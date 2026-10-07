"""
CloudWise Waste Detection Service

Main orchestration service for AWS waste detection. Coordinates all resource-specific
detectors and provides a unified API for waste detection across AWS accounts.

Features:
- CloudWatch-based detection (enabled by default for all tiers)
- Dynamic pricing via AWS Pricing API
- Configurable thresholds per account
- Caching with 24-hour TTL
- AI-enhanced insights (via integration with AI Copilot)
- Service-based filtering (only run detectors for services with actual resources)
- Modular detector architecture via mixins

Supported Services (38 detector methods organized into 7 categories):
- Compute: EC2, Lambda, ECS/Fargate, SageMaker, WorkSpaces, Lightsail, Elastic Beanstalk
- Storage: EBS, S3, EFS, FSx, ECR, Backup
- Databases: RDS, DynamoDB, ElastiCache, Redshift, OpenSearch, Neptune, DocumentDB, Timestream, QLDB
- Networking: EIP, NAT Gateway, Load Balancer, CloudFront, Route 53, Global Accelerator
- Analytics/ML: EMR, Kinesis, Glue
- Integration: API Gateway, AppSync, Step Functions, MSK, MQ, Transfer Family
- Management: CloudWatch, Secrets Manager, KMS

Removed detectors (per WASTE_DETECTOR_AUDIT.md):
- Oversized EC2/RDS (50% savings assumption was arbitrary)
- Previous Gen EC2 (10-20% estimate varies widely)
- Multi-AZ Non-Prod RDS (name heuristic is unreliable)
"""

import logging
import os
import sys
import threading
import time
import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Coroutine, Dict, List, Optional, Set, Tuple

import boto3
from botocore.config import Config

from cloudwise_scan_core.models import (
    WasteItem,
    WasteDetectionSettings,
    WasteDetectionResult,
    WasteType,
    ResourceType,
    ConfidenceLevel,
    generate_deterministic_id,
    GOVERNANCE_WASTE_TYPES,
    COMMITMENT_WASTE_TYPES,
)
from cloudwise_scan_core.cloudwatch_metrics_service import (
    get_cloudwatch_metrics_service,
)
from cloudwise_scan_core.aws_pricing_service import (
    get_pricing_service,
)
from cloudwise_scan_core.data_providers import (
    WasteDataProvider,
    OnlineDataProvider,
    OfflineDataProvider,
)

# Import detector mixins

logger = logging.getLogger(__name__)

# Default boto3 client configuration for all AWS API calls
DEFAULT_BOTO_CONFIG = Config(
    read_timeout=30,
    connect_timeout=10,
    retries={'max_attempts': 3, 'mode': 'adaptive'}
)

# Service-to-detector mapping for intelligent filtering
# Keys are AWS service names as they appear in Cost Explorer / CUR data
SERVICE_TO_DETECTORS: Dict[str, List[str]] = {
    # EC2 variants
    'AmazonEC2': ['ec2', 'ebs', 'network', 'compute_optimizer'],
    'Amazon Elastic Compute Cloud': ['ec2', 'ebs', 'network', 'compute_optimizer'],
    'Amazon Elastic Compute Cloud - Compute': ['ec2', 'compute_optimizer'],
    'EC2 - Other': ['ec2', 'ebs', 'network'],
    # CLO-463: some CUR exports name EBS directly instead of folding it into
    # the 'EC2 - Other' bucket above. Unproven against a live bill (our own
    # accounts' EBS spend lands in 'EC2 - Other'), and kept anyway because a
    # missing key silently disables a detector while a spare key costs nothing.
    'Amazon Elastic Block Store': ['ebs'],
    # RDS
    'AmazonRDS': ['rds', 'compute_optimizer', 'aurora'],
    'Amazon Relational Database Service': ['rds', 'compute_optimizer', 'aurora'],
    # S3
    'AmazonS3': ['s3'],
    'Amazon Simple Storage Service': ['s3'],
    # DynamoDB
    'AmazonDynamoDB': ['dynamodb'],
    'Amazon DynamoDB': ['dynamodb'],
    # ElastiCache
    'AmazonElastiCache': ['elasticache'],
    'Amazon ElastiCache': ['elasticache'],
    # Lambda
    'AWSLambda': ['lambda', 'compute_optimizer'],
    'AWS Lambda': ['lambda', 'compute_optimizer'],
    # ECS/EKS
    'AmazonECS': ['ecs'],
    'Amazon Elastic Container Service': ['ecs'],
    'AmazonEKS': ['ecs', 'eks_extended_support'],
    'Amazon Elastic Kubernetes Service': ['ecs', 'eks_extended_support'],
    # CLO-463: EKS's pre-2018 name. Not folklore — the AWS Price List API
    # returned exactly this string for ServiceCode=AmazonEKS on 2026-09-20, so
    # AWS's own surfaces still emit it. `eks_extended_support` is reachable
    # ONLY through an EKS name and is not in ALWAYS_RUN_DETECTORS, so a miss
    # here is a detector that never runs on any scheduled scan.
    'Amazon Elastic Container Service for Kubernetes': ['ecs', 'eks_extended_support'],
    # SageMaker
    'AmazonSageMaker': ['sagemaker'],
    'Amazon SageMaker': ['sagemaker'],
    # Kinesis
    'AmazonKinesis': ['kinesis'],
    'Amazon Kinesis': ['kinesis'],
    # CLO-528: Firehose bills under its own product name (Price List API,
    # ServiceCode=AmazonKinesisFirehose, servicename 'Amazon Kinesis Firehose',
    # checked 2026-10-01). The kinesis detector also runs kinesis_firehose_idle,
    # so without these keys an account whose only Kinesis-family spend is
    # Firehose CUR-skipped the detector on every scheduled scan.
    'AmazonKinesisFirehose': ['kinesis'],
    'Amazon Kinesis Firehose': ['kinesis'],
    # MSK
    'AmazonMSK': ['msk'],
    'Amazon Managed Streaming for Apache Kafka': ['msk'],
    # Redshift
    'AmazonRedshift': ['redshift'],
    'Amazon Redshift': ['redshift'],
    # OpenSearch
    'AmazonOpenSearchService': ['opensearch'],
    'Amazon OpenSearch Service': ['opensearch'],
    'AmazonES': ['opensearch'],
    # CLO-463: the pre-2021 name. Long-lived accounts and historical CE data
    # still carry it; the service was renamed, the bills were not rewritten.
    'Amazon Elasticsearch Service': ['opensearch'],
    # CloudWatch
    'AmazonCloudWatch': ['cloudwatch', 'cloudwatch_dashboard'],
    # Secrets Manager
    'AWSSecretsManager': ['secrets_manager'],
    'AWS Secrets Manager': ['secrets_manager'],
    # KMS
    'AWSKMS': ['kms'],
    'AWS Key Management Service': ['kms'],
    # EMR
    'AmazonEMR': ['emr'],
    'Amazon EMR': ['emr'],
    # CLO-589: the billing name Cost Explorer has historically used for EMR
    # and the Price List service code. Unverified from the session that added
    # them (no AWS access); exact-match keys, so adding them cannot deselect
    # anything. The wave-8a scan's cur_skipped / CLO-465 WARNING settles it.
    'Amazon Elastic MapReduce': ['emr'],
    'ElasticMapReduce': ['emr'],
    # Glue
    'AWSGlue': ['glue'],
    'AWS Glue': ['glue'],
    # EFS
    'AmazonEFS': ['efs'],
    'Amazon Elastic File System': ['efs'],
    # FSx
    'AmazonFSx': ['fsx'],
    'Amazon FSx': ['fsx'],
    # ECR
    'AmazonECR': ['ecr'],
    'Amazon EC2 Container Registry (ECR)': ['ecr'],
    # API Gateway
    'AmazonAPIGateway': ['api_gateway'],
    'Amazon API Gateway': ['api_gateway'],
    # CloudFront
    'AmazonCloudFront': ['cloudfront'],
    'Amazon CloudFront': ['cloudfront'],
    # Route 53
    'AmazonRoute53': ['route53', 'orphaned_dns'],
    'Amazon Route 53': ['route53', 'orphaned_dns'],
    # Transfer Family
    'AWSTransfer': ['transfer_family'],
    'AWS Transfer Family': ['transfer_family'],
    # Step Functions
    'AWSStepFunctions': ['step_functions'],
    'AWS Step Functions': ['step_functions'],
    # AppSync
    'AWSAppSync': ['appsync'],
    'AWS AppSync': ['appsync'],
    # MQ
    'AmazonMQ': ['mq'],
    'Amazon MQ': ['mq'],
    # Neptune
    'AmazonNeptune': ['neptune'],
    'Amazon Neptune': ['neptune'],
    # DocumentDB
    'AmazonDocDB': ['documentdb'],
    'Amazon DocumentDB': ['documentdb'],
    # CLO-435, 2026-09-18: the product name CUR and Cost Explorer ACTUALLY
    # deliver. Neither key above ever matches it, and the lookup is exact, so on
    # every scheduled (CUR-filtered) scan the documentdb detector was CUR-skipped
    # even on accounts whose cost data lists DocumentDB — proven on the fixture
    # account, whose EMF read `DetectorId=documentdb, DetectorSkippedCURFilter=1`
    # with two DocumentDB rows in resource-costs-daily. That made idle_documentdb,
    # overprovisioned_documentdb and the old-snapshot check dead a THIRD way,
    # after CLO-169 (a missing provider method) and CLO-447 (Sum over a
    # Count/Second rate). Same class as the Session 10 spaced-name bug for Route 53.
    'Amazon DocumentDB (with MongoDB compatibility)': ['documentdb'],
    # WorkSpaces
    'AmazonWorkSpaces': ['workspaces'],
    'Amazon WorkSpaces': ['workspaces'],
    # Lightsail
    'AmazonLightsail': ['lightsail'],
    'Amazon Lightsail': ['lightsail'],
    # Elastic Beanstalk
    'AWSElasticBeanstalk': ['elastic_beanstalk'],
    'AWS Elastic Beanstalk': ['elastic_beanstalk'],
    # Global Accelerator
    'AWSGlobalAccelerator': ['global_accelerator'],
    'AWS Global Accelerator': ['global_accelerator'],
    # Backup
    'AWSBackup': ['backup'],
    'AWS Backup': ['backup'],
    # CloudTrail
    'AWSCloudTrail': ['cloudtrail'],
    'AWS CloudTrail': ['cloudtrail'],
    # ELB (load balancers - common in cost data)
    'Elastic Load Balancing': ['network'],
    'Amazon Elastic Load Balancing': ['network'],
    # VPC
    'Amazon Virtual Private Cloud': ['network', 'vpc_endpoint'],
}

# Detectors that should ALWAYS run regardless of service filter
ALWAYS_RUN_DETECTORS: Set[str] = {
    'network',  # EIPs, NAT Gateways often missed in CUR
    'ebs',      # Unattached volumes may not show as separate service
    's3',       # Buckets without lifecycle policies - common issue even with low current cost
    # savings_opportunities and commitment are intentionally kept here so they run in us-east-1
    # even for service-filtered scans.  GLOBAL_SERVICE_DETECTORS then removes them from
    # non-us-east-1 regions, achieving the "account-level once per scan" effect.
    'savings_opportunities',  # CE GetReservation* — global API, runs once in us-east-1
    'commitment',             # CE GetReservationUtilization etc. — global API, runs once in us-east-1
    'sagemaker',  # Notebooks/endpoints may exist without CUR cost history (newly created, stopped)
    'glue',     # Dev endpoints cost $1,606/month and may not appear in CUR immediately
    'lightsail',  # Static IPs, unused disks, old snapshots often forgotten and not in CUR
    'backup',   # Backup costs may not appear as distinct service in CUR
    'fsx',      # FSx filesystems are expensive and may not appear in CUR immediately
    'step_functions',  # Retry storms and high transition density waste CloudWatch-only metrics
    'security_posture',  # Security posture checks should always run regardless of cost data
    'vpc_endpoint',  # Interface endpoints cost $7.30/AZ/month and may not show in CUR
    'orphaned_dns',  # Security hygiene — dangling DNS records are a takeover risk
    'cloudwatch_dashboard',  # Dashboards beyond free tier cost $3/each, often forgotten
    # CLO-515: Elastic Beanstalk has no charge of its own (customers pay for
    # the EC2, ELB and RDS underneath), so no cost row ever says "AWS Elastic
    # Beanstalk" and the CUR keys above never select it: the detector never ran
    # on a scheduled scan. Cost of always running it: one DescribeEnvironments
    # per region when there is no environment (the configuration read is
    # skipped), plus the orphaned-RDS sweep's DescribeDBInstances pages (tags
    # come in the response). All free control-plane calls, no CloudWatch
    # unless a candidate exists.
    'elastic_beanstalk',
}

# Mapping from detector key to method name
DETECTOR_METHODS: Dict[str, str] = {
    # Compute
    'ec2': '_detect_ec2_waste',
    'lambda': '_detect_lambda_waste',
    'ecs': '_detect_ecs_waste',
    'eks_extended_support': '_detect_eks_extended_support',
    'sagemaker': '_detect_sagemaker_waste',
    'workspaces': '_detect_workspaces_waste',
    'lightsail': '_detect_lightsail_waste',
    'elastic_beanstalk': '_detect_elastic_beanstalk_waste',
    # Storage
    'ebs': '_detect_ebs_waste',
    's3': '_detect_s3_waste',
    'efs': '_detect_efs_waste',
    'fsx': '_detect_fsx_waste',
    'ecr': '_detect_ecr_waste',
    'backup': '_detect_backup_waste',
    # Database
    'rds': '_detect_rds_waste',
    'aurora': '_detect_aurora_waste',
    'dynamodb': '_detect_dynamodb_waste',
    'elasticache': '_detect_elasticache_waste',
    'redshift': '_detect_redshift_waste',
    'opensearch': '_detect_opensearch_waste',
    'neptune': '_detect_neptune_waste',
    'documentdb': '_detect_documentdb_waste',
    # Network
    'network': '_detect_network_waste',
    'cloudfront': '_detect_cloudfront_waste',
    'route53': '_detect_route53_waste',
    'global_accelerator': '_detect_global_accelerator_waste',
    # Analytics
    'emr': '_detect_emr_deep_waste',
    'kinesis': '_detect_kinesis_waste',
    'glue': '_detect_glue_waste',
    # Integration
    'api_gateway': '_detect_api_gateway_waste',
    'msk': '_detect_msk_waste',
    'mq': '_detect_mq_waste',
    'step_functions': '_detect_step_functions_waste',
    'appsync': '_detect_appsync_waste',
    'transfer_family': '_detect_transfer_family_waste',
    # Management
    'cloudwatch': '_detect_cloudwatch_waste',
    'secrets_manager': '_detect_secrets_manager_waste',
    'kms': '_detect_kms_waste',
    'cloudtrail': '_detect_cloudtrail_waste',
    # Security Posture
    'security_posture': '_detect_security_posture_waste',
    # Optimizer (AWS Compute Optimizer - ML-backed rightsizing)
    'compute_optimizer': '_detect_compute_optimizer_waste',
    # Savings Opportunities (RI/Savings Plans from Cost Explorer)
    'savings_opportunities': '_detect_savings_opportunities',
    # Additional standalone detectors
    'vpc_endpoint': '_detect_vpc_endpoint_waste',
    'orphaned_dns': '_detect_orphaned_dns_waste',
    'cloudwatch_dashboard': '_detect_cloudwatch_dashboard_waste',
    # Commitment risk detectors (commitment.py)
    'commitment': '_detect_commitment_waste',
}

# Global service detectors (only run when region == us-east-1).
# CE-backed account-level detectors belong here: RI/SP data is global (no region dimension).
# Running them in every region multiplies CE API calls by the region count (10x).
GLOBAL_SERVICE_DETECTORS: Set[str] = {
    'cloudfront', 'route53', 'global_accelerator',
    'savings_opportunities',  # CE GetReservationRecommendation — global API, runs once in us-east-1
    'commitment',             # CE GetReservationUtilization etc. — global API, runs once in us-east-1
    'orphaned_dns',           # Route 53 is global — running per-region emitted the same
                              # dangling record once per scanned region (17× duplicates)
}


# CLO-465: CUR service names we deliberately have no detector for.
#
# `_get_active_detectors` selects detectors by EXACT key, so a name that is not
# in SERVICE_TO_DETECTORS selects nothing, records DetectorSkippedCURFilter=1,
# and is indistinguishable from "this account does not use that service". That
# silent miss is how `documentdb` stayed dead until #1410 mapped the spaced CUR
# product name, and CLO-464 measured what it costs: two days reading a working
# detector as dead.
#
# The fix is not a longer map — it is making a miss loud. Anything NOT in this
# allowlist and NOT in SERVICE_TO_DETECTORS now produces a WARNING, so the next
# AWS rename arrives as a log line instead of as a detector that quietly stops.
# Keep this list honest: it means "we looked, and there is no detector", never
# "we have not got round to it".
#
# Seeded from the 2026-09-20 audit (54 live names across staging accounts, 31
# Cost Explorer dimension values, the Price List API for all 37 API-style keys).
NO_DETECTOR_SERVICES: Set[str] = {
    # Billing artefacts, not services anyone can waste money on directly.
    'Tax',
    'AWS Cost Explorer',
    'AWS Data Transfer',
    'Amazon Registrar',
    'AWS Skill Builder Individual',
    'Contact Center Telecommunications (service sold by AMCS, LLC)',
    'CloudFront Flat-Rate Plans',
    # Real services with no detector today. Adding one here is a decision that
    # we do not detect waste for it, not a note that we might later.
    'Amazon Simple Queue Service',
    'Amazon Simple Notification Service',
    'Amazon Simple Email Service',
    'Amazon Cognito',
    'Amazon GuardDuty',
    'Amazon Connect',
    'Amazon Location Service',
    'Amazon Glacier',
    'AWS Security Hub',
    'AWS Config',
    'AWS WAF',
    'AWS X-Ray',
    'AWS CloudFormation',
    'AWS Certificate Manager',
    'AWS Service Catalog',
    'AWS Amplify',
    'AWS App Runner',
    'AWS CloudShell',
    # CLO-528: the other Kinesis family members (Price List API servicename,
    # 2026-10-01). No detector reads Kinesis Video Streams or Kinesis Data
    # Analytics / Managed Service for Apache Flink resources.
    'Amazon Kinesis Video Streams',
    'Amazon Kinesis Analytics',
}

# Allowlisted by SHAPE rather than by name, because the set is unbounded.
# Cost Explorer emits one service name per Bedrock model — "Claude Sonnet 4.6
# (Amazon Bedrock Edition)" and so on — and a new one appears whenever a model
# ships. Listing them literally would warn on every new model forever.
NO_DETECTOR_SERVICE_SUFFIXES: Tuple[str, ...] = (
    '(Amazon Bedrock Edition)',
)


def is_expected_unmapped_service(service_name: str) -> bool:
    """Whether a CUR service name having no detector is expected, not a gap."""
    if service_name in NO_DETECTOR_SERVICES:
        return True
    return any(service_name.endswith(suffix) for suffix in NO_DETECTOR_SERVICE_SUFFIXES)

# CLO-234: trailing window of CUR data used to reconcile claimed savings
# against actual billed cost. 30 days matches the monthly basis of
# ``WasteItem.monthly_savings`` and gives enough distinct usage dates to
# clear ``billed_cost.DEFAULT_MIN_DAYS_COVERED`` on any established resource.
RECONCILIATION_WINDOW_DAYS = 30


# CLO-191: process-wide, bounded thread pool that every detector invocation
# runs its (blocking) boto3 work through — see ``_run_detector_coroutine_sync``
# and ``WasteDetectionService._run_detector_with_timeout`` below. Module-level
# (not per-instance) so multiple ``WasteDetectionService`` instances in the
# same process (tests, or a backend worker handling several accounts) share
# one bounded pool instead of each spinning up its own — the failure mode
# this guards against is unbounded thread creation across ~190 detectors x
# 17 regions. Sized to ``WasteDetectionService.MAX_CONCURRENT_API_CALLS`` (10)
# since that semaphore already caps how many detectors run concurrently per
# scan; the pool can never see more concurrent submissions than that.
_detector_thread_pool: Optional[ThreadPoolExecutor] = None
_detector_thread_pool_lock = threading.Lock()

# Each detector-executor worker thread gets exactly one persistent event
# loop, created lazily on that thread's first submitted detector and reused
# for every subsequent one (ThreadPoolExecutor threads are long-lived and
# reused across submissions, not spawned per task). Reusing the loop avoids
# paying ``asyncio.new_event_loop()``/teardown overhead on every single
# detector call — with a 10-worker pool servicing dozens of detectors per
# scan, that's the difference between ~10 loop lifetimes and one per call.
_thread_local = threading.local()


def _get_detector_thread_pool() -> ThreadPoolExecutor:
    """Lazily create (once) the shared executor detector work runs on."""
    global _detector_thread_pool
    if _detector_thread_pool is None:
        with _detector_thread_pool_lock:
            if _detector_thread_pool is None:
                _detector_thread_pool = ThreadPoolExecutor(
                    max_workers=WasteDetectionServiceBase.MAX_CONCURRENT_API_CALLS,
                    thread_name_prefix="cw-scan-detector",
                )
    return _detector_thread_pool


# CLO-493: detector method name -> its DETECTOR_METHODS key, so the provider
# path (detect_waste_with_provider) names a failed detector as online does.
_DETECTOR_KEY_BY_METHOD: Dict[str, str] = {}
for _key, _method in DETECTOR_METHODS.items():
    _DETECTOR_KEY_BY_METHOD.setdefault(_method, _key)


def _detector_label(method_name: str) -> str:
    """``_detect_ec2_waste`` -> ``EC2``; an unregistered method keeps its name."""
    key = _DETECTOR_KEY_BY_METHOD.get(method_name)
    if key:
        return key.upper()
    return method_name or "DETECTOR"


def _run_detector_coroutine_sync(coro: Coroutine) -> Any:
    """Execute a detector coroutine to completion on this worker thread's
    persistent event loop.

    CLO-191: every ``OnlineDataProvider.get_*`` method a detector calls makes
    a synchronous boto3 call inside an ``async def`` with no real internal
    ``await`` (see the module docstring in ``data_providers/online.py``) —
    so a detector coroutine is, in practice, 100% blocking work with an
    ``async``/``await`` costume on it. Prior to this fix that blocking work
    ran directly on the shared scan event loop (via a plain ``await``),
    which starved every other detector's task for the full duration of the
    call — including the one detector (lightsail, pre-CLO-185) that used
    real async waits, whose own wall-clock timeout then fired as a victim
    of its blocking neighbors, not its own work.

    Running the coroutine on a dedicated worker thread (submitted through
    ``loop.run_in_executor``) moves that blocking work off the shared loop
    entirely: the loop only awaits a ``concurrent.futures`` future, which is
    a real suspension point, so it stays free to schedule every other
    detector's task. Each worker thread keeps its own event loop alive for
    its lifetime (rather than a fresh ``asyncio.new_event_loop()`` per call)
    — cheaper per call, and just as safe, since a ``ThreadPoolExecutor``
    worker thread never runs more than one submitted item at a time.
    """
    loop = getattr(_thread_local, "loop", None)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _thread_local.loop = loop
    return loop.run_until_complete(coro)


class CircuitBreakerError(Exception):
    """Raised when the circuit breaker is open and blocking calls."""
    pass


class CircuitBreaker:
    """
    Simple circuit breaker pattern implementation for AWS API calls.
    
    When a detector experiences too many failures, the circuit opens and
    subsequent calls fail fast, preventing cascade failures.
    """
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._failures = 0
        self._last_failure_time: Optional[float] = None
        self._is_open = False
        self._lock = asyncio.Lock()
    
    async def call(self, func, *args, **kwargs):
        """Execute a function through the circuit breaker."""
        async with self._lock:
            if self._is_open:
                if time.time() - self._last_failure_time >= self._recovery_timeout:
                    logger.info("Circuit breaker in half-open state, allowing test call")
                    self._is_open = False
                else:
                    raise CircuitBreakerError(
                        f"Circuit is open. Retry after {self._recovery_timeout - (time.time() - self._last_failure_time):.1f}s"
                    )
        
        try:
            result = await func(*args, **kwargs)
            async with self._lock:
                self._failures = 0
            return result
        except Exception as e:
            async with self._lock:
                self._failures += 1
                if self._failures >= self._failure_threshold:
                    self._is_open = True
                    self._last_failure_time = time.time()
                    logger.warning(
                        f"Circuit breaker opened after {self._failures} failures. "
                        f"Will recover in {self._recovery_timeout}s"
                    )
            raise
    
    @property
    def is_open(self) -> bool:
        return self._is_open
    
    @property
    def failure_count(self) -> int:
        return self._failures
    
    def reset(self):
        self._failures = 0
        self._is_open = False
        self._last_failure_time = None


def _append_permission_missing(result: "WasteDetectionResult", detector: str, action: str) -> None:
    """CLO-368: append a ``{"detector", "action"}`` entry to
    ``WasteDetectionResult.permission_missing``, deduplicated.

    Kept separate from ``permission_errors`` (a list of human-readable
    strings, CLO-176) — this is the compact, structured shape CLO-354 reads
    to write ``permission_missing`` onto the account row so the UI can tell
    the customer which role-template permissions are missing.
    """
    entry = {"detector": detector, "action": action}
    if entry not in result.permission_missing:
        result.permission_missing.append(entry)


def _attach_provider_permission_errors(payload: Dict[str, Any], data_provider) -> Dict[str, Any]:
    """CLO-176: fold any access-denied/unauthorized failures the
    ``OnlineDataProvider`` recorded (via its ``_service_call`` guard, or the
    inline ``_is_access_denied`` checks in its other ``get_*`` methods) into
    this detector invocation's result payload.

    This works regardless of whether the detector itself let the
    provider's re-raised ``ClientError`` propagate, or caught it in its own
    broad ``except Exception`` (e.g. ``security.py:_detect_unencrypted_efs``
    and ``storage.py:_detect_efs_waste`` both do) — the provider instance is
    created fresh per detector call in ``_run_detector_with_timeout`` and
    its ``permission_errors`` list is populated the moment the guard sees
    the error, before any detector-level except block runs. ``detect_waste``
    reads ``provider_permission_errors`` off this payload and folds it into
    ``WasteDetectionResult.permission_errors``.
    """
    provider_errors = getattr(data_provider, 'permission_errors', None) if data_provider is not None else None
    if provider_errors:
        payload['provider_permission_errors'] = list(provider_errors)
    # CLO-368: count of previously-silent errors this provider instance
    # swallowed via ``_warn_swallowed`` (best-effort/secondary fetches that
    # don't fail the detector). Folded into the ``DetectorErrors`` EMF
    # field so a detector that "succeeded" but had internal failures is no
    # longer indistinguishable from one that had none.
    swallowed = getattr(data_provider, 'swallowed_error_count', 0) if data_provider is not None else 0
    if swallowed:
        payload['provider_swallowed_error_count'] = int(swallowed)
    # CLO-375: free AWS inputs the account hasn't enabled (Compute Optimizer
    # not opted in). Folded into ``WasteDetectionResult.coverage_notes``.
    coverage_notes = getattr(data_provider, 'coverage_notes', None) if data_provider is not None else None
    if coverage_notes:
        payload['provider_coverage_notes'] = list(coverage_notes)
    # CLO-479: partial-data notes (e.g. Lambda functions whose metrics could
    # not be fetched). Folded into ``WasteDetectionResult.warnings``.
    data_warnings = getattr(data_provider, 'data_warnings', None) if data_provider is not None else None
    if data_warnings:
        payload['provider_data_warnings'] = list(data_warnings)
    return payload


class WasteDetectionServiceBase:
    """
    Main service for comprehensive AWS waste detection.
    
    This service orchestrates waste detection across multiple AWS resource types,
    using CloudWatch metrics for accurate utilization analysis and dynamic pricing
    from the AWS Pricing API.
    
    Features:
    - Rate limiting via semaphore (max 10 concurrent AWS API calls)
    - Service-based filtering to only run relevant detectors
    - Detector-level timeouts (15s per detector to fit within API Gateway's 29s limit)
    - Modular architecture with detector mixins
    - AWS Compute Optimizer integration for ML-backed rightsizing
    - RI/Savings Plans recommendations from Cost Explorer
    """

    # CLO-562: the registry is read from the class, not module globals, so an
    # assembly with a subset of the detector mixins (the open core's
    # ``OpenWasteDetectionService``) can narrow it. The hosted
    # ``WasteDetectionService`` (``hosted_service.py``) keeps these full sets.
    DETECTOR_METHODS: Dict[str, str] = DETECTOR_METHODS
    ALWAYS_RUN_DETECTORS: Set[str] = ALWAYS_RUN_DETECTORS
    GLOBAL_SERVICE_DETECTORS: Set[str] = GLOBAL_SERVICE_DETECTORS
    SERVICE_TO_DETECTORS: Dict[str, List[str]] = SERVICE_TO_DETECTORS
    
    MAX_CONCURRENT_API_CALLS = 10
    # Reduced from 120s to 15s to fit within API Gateway's 29s timeout limit
    # Multiple detectors run in parallel, but the total request must complete < 29s
    # With 15s per detector, even slow detectors won't block the entire scan
    DETECTOR_TIMEOUT_SECONDS = 15
    # CLO-178: composite detectors fan out over many resources/sub-detectors
    # (lightsail runs 7 sub-detectors serially; s3 makes ~6 API + up to 7
    # CloudWatch calls per bucket; security_posture re-reads five providers)
    # and regularly exceed the 15s cap on real accounts — each breach counted
    # as a circuit-breaker failure and blacked the detector out for an hour.
    # Runtimes WITHOUT the API Gateway 29s constraint (the region scanner,
    # Lambda timeout 600s) opt in to a longer cap for these detectors via
    # the DETECTOR_TIMEOUT_HEAVY_SECONDS env var; unset/0 keeps 15s
    # everywhere else (backend API path unchanged).
    # CLO-478: lambda joined after production us-east-1 reached 43.3s against
    # the 45s default (32.3s → 35.4s → 43.3s over 09-25..27). It makes two
    # serial GetMetricStatistics calls per function; the real fix is batching.
    HEAVY_DETECTORS = frozenset({"s3", "security_posture", "lightsail", "lambda"})
    
    def __init__(self, aws_factory=None, cloudwatch_service=None, pricing_service=None, cache_service=None):
        """
        Initialize the waste detection service.
        
        Args:
            aws_factory: AWS service factory for creating clients
            cloudwatch_service: CloudWatch metrics service
            pricing_service: AWS Pricing service for dynamic pricing
            cache_service: Cache service for storing results
        """
        # aws_factory is retained for backward compat with the FastAPI backend
        # but scan-core never calls into it (boto3 clients are built from
        # per-scan customer creds). When unset, we leave it as None rather
        # than importing app.core.aws_service_factory, keeping scan-core
        # runtime-agnostic (see SCAN-PIPELINE-SCALING-SPEC.md §6.5).
        self.aws_factory = aws_factory
        self.cloudwatch_service = cloudwatch_service or get_cloudwatch_metrics_service()
        self.pricing_service = pricing_service or get_pricing_service()

        # cache_service is used for run-level memoisation of scan payloads
        # (keyed by user_id + cache_key). The FastAPI backend injects its
        # Redis-backed impl; other runtimes (Lambda, ECS worker, CLI) get
        # a no-op in-package default that always misses and accepts writes
        # silently. This preserves correctness (cache is a perf hint, not a
        # source of truth) without forcing a hard dependency on app.*.
        if cache_service is None:
            from .cache import NoOpCacheService
            cache_service = NoOpCacheService()
        self.cache_service = cache_service
        
        # Rate limiting semaphore to prevent AWS API throttling.
        # Created per running event loop via _get_api_semaphore(), never
        # here: this service is a process-wide singleton
        # (get_waste_detection_service) but the Lambda handler runs each
        # invocation on a fresh event loop, and an asyncio.Semaphore binds
        # itself to whichever loop first makes it WAIT (contended acquire).
        # A semaphore carried across invocations then raises "is bound to a
        # different event loop" on the next contended acquire — detectors
        # silently return zero findings. Contention only became routine with
        # CLO-191 (detector tasks now genuinely suspend, so all of them
        # reach the semaphore together), which is how this surfaced.
        self._api_semaphore: Optional[asyncio.Semaphore] = None
        self._api_semaphore_loop: Optional[asyncio.AbstractEventLoop] = None

        # Circuit breaker for AWS API resilience
        self._circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        
        logger.info("Waste Detection Service initialized with modular detector architecture")
    
    def _get_api_semaphore(self) -> asyncio.Semaphore:
        """Return the rate-limiting semaphore for the *current* event loop.

        Recreated whenever the running loop changes (Lambda: one fresh loop
        per invocation on a warm container; the backend's single long-lived
        loop reuses the same instance every call). Loop-change detection is
        identity-based and cheap; recreating on a new loop is always safe
        because a previous loop's scan has fully completed before its loop
        is closed, so no acquirer of the old semaphore can still be running.
        """
        loop = asyncio.get_running_loop()
        if self._api_semaphore is None or self._api_semaphore_loop is not loop:
            self._api_semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_API_CALLS)
            self._api_semaphore_loop = loop
        return self._api_semaphore

    def _create_client(self, service_name: str, creds: Dict[str, str], region_override: str = None) -> Any:
        """Create a boto3 client with standard configuration."""
        return boto3.client(
            service_name,
            aws_access_key_id=creds['access_key_id'],
            aws_secret_access_key=creds['secret_access_key'],
            aws_session_token=creds.get('session_token'),
            region_name=region_override or creds['region'],
            config=DEFAULT_BOTO_CONFIG
        )
    
    async def detect_waste(
        self,
        user_id: str,
        account_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        session_token: str = None,
        settings: WasteDetectionSettings = None,
        force_refresh: bool = False,
        enabled_services: List[str] = None,
        customer_tier: str = None,
    ) -> WasteDetectionResult:
        """
        Run comprehensive waste detection for an AWS account.
        
        Args:
            user_id: CloudWise user ID (for caching)
            account_id: AWS account ID
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region to scan
            session_token: Optional session token for assumed roles
            settings: Detection settings (uses defaults if not provided)
            force_refresh: Skip cache and force fresh scan
            enabled_services: List of AWS service names to scan (e.g., ['AmazonEC2', 'AmazonRDS']).
                            If None, all detectors are run.
            customer_tier: Subscription tier of the account's owner
                            (``free`` / ``shield`` / ``agentic`` / ``compliance``).
                            When provided, detectors outside the tier's
                            allowed set are filtered out before execution
                            (Phase 5 §3.7). Unknown / missing tier falls
                            back to the Free tier set as a cost fail-safe.
            
        Returns:
            WasteDetectionResult with all findings
        """
        settings = settings or WasteDetectionSettings.get_defaults()
        result = WasteDetectionResult(
            account_id=account_id,
            region=region,
            settings=settings,
        )
        
        # Check cache first
        if not force_refresh:
            cached = await self._get_cached_result(user_id, account_id, region)
            if cached:
                logger.warning(f"Using cached waste detection for account {account_id} (from DynamoDB)")
                return cached
            else:
                logger.warning(f"No valid cache found for account {account_id}, will run fresh scan")
        else:
            logger.warning(f"force_refresh=True, bypassing cache for account {account_id}")
        
        try:
            # CLO-358: one dict shared by every detector's fresh
            # OnlineDataProvider for the duration of THIS detect_waste()
            # call only — created fresh per call, so it never leaks a
            # cached breakdown into a later scan of a different account or
            # region. Without it, rds and aurora (and any other pair asking
            # for the same (service_keys, days)) each pay for their own
            # identical, customer-billed ce:GetCostAndUsage call.
            extended_support_cache: Dict[Any, Any] = {}
            creds = {
                'access_key_id': access_key_id,
                'secret_access_key': secret_access_key,
                'region': region,
                'session_token': session_token,
                'account_id': account_id,  # AWS account ID for caching
                'customer_tier': customer_tier,  # Phase 5 §3.7 — threaded into EMF
                'extended_support_cache': extended_support_cache,  # CLO-358
            }
            
            is_global_scan_region = (region == 'us-east-1')
            active_detector_keys = self._get_active_detectors(enabled_services, is_global_scan_region)

            # Phase 5 §3.7 / §3.8 — apply tier routing *after* CUR filtering
            # so the metric attribution is unambiguous: a detector dropped
            # by CUR is counted as ``DetectorSkippedCURFilter``, while a
            # detector dropped purely for tier reasons is counted as
            # ``DetectorSkippedTierFilter``. Both emit a zero-duration
            # EMF record so dashboards can graph per-scan skip counts.
            full_registry = set(self.DETECTOR_METHODS.keys())
            if not is_global_scan_region:
                full_registry -= self.GLOBAL_SERVICE_DETECTORS
            cur_filtered_set = set(active_detector_keys)
            skipped_by_cur = full_registry - cur_filtered_set

            skipped_by_tier: set = set()
            if customer_tier:
                from .tier_routing import Tier, resolve_detector_set
                try:
                    tier_enum = Tier(customer_tier)
                except ValueError:
                    # Unknown tier → Free (fail-safe on cost).
                    tier_enum = Tier.FREE
                tier_allowed = resolve_detector_set(tier_enum, cur_filtered_set)
                skipped_by_tier = cur_filtered_set - tier_allowed
                active_detector_keys = list(tier_allowed)

            self._emit_skip_metrics(
                skipped_by_cur=skipped_by_cur,
                skipped_by_tier=skipped_by_tier,
                account_id=account_id,
                region=region,
                customer_tier=customer_tier,
            )

            # CLO-217: previously skipped_by_tier/skipped_by_cur only fed the
            # EMF metrics above and were then discarded — the persisted scan
            # row had no record that anything was withheld. Carry them onto
            # the result the same way CLO-193 carries detector-exception
            # warnings, so a downgraded customer's missing detectors are
            # never indistinguishable from "this account has no waste here".
            result.tier_skipped = sorted(skipped_by_tier)
            result.cur_skipped = sorted(skipped_by_cur)

            logger.warning(f"Starting waste detection scan for account {account_id} in {region} with {len(active_detector_keys)} detectors")
            
            # Build detector tasks
            detector_tasks = []
            detector_names = []
            global_service_detector_indices = set()
            
            for detector_key in active_detector_keys:
                method_name = self.DETECTOR_METHODS.get(detector_key)
                if method_name and hasattr(self, method_name):
                    method = getattr(self, method_name)
                    detector_tasks.append(
                        self._run_detector_with_timeout(method, detector_key, creds, settings)
                    )
                    detector_names.append(detector_key.upper())
                    if detector_key in self.GLOBAL_SERVICE_DETECTORS:
                        global_service_detector_indices.add(len(detector_tasks) - 1)
            
            # Run all detectors in parallel
            detector_results = await asyncio.gather(*detector_tasks, return_exceptions=True)
            
            # Collect results
            staged_items: List[WasteItem] = []
            for i, detector_result in enumerate(detector_results):
                detector_name = detector_names[i] if i < len(detector_names) else f"Detector_{i}"
                if isinstance(detector_result, Exception):
                    error_msg = f"{detector_name} detector error: {str(detector_result)}"
                    logger.error(error_msg)
                    result.errors.append(error_msg)
                    # Check if this is an AccessDenied error at gather level
                    error_str = str(detector_result)
                    if 'AccessDenied' in error_str or 'AccessDeniedException' in error_str:
                        result.permission_errors.append(detector_name)
                        _append_permission_missing(
                            result, detector_name, detector_result.__class__.__name__,
                        )
                elif isinstance(detector_result, dict):
                    # New return format: {'items': [...], 'permission_error': detector_name or None}
                    items = detector_result.get('items', [])
                    permission_error = detector_result.get('permission_error')

                    # CLO-176: prefer the richer, resource-level detail the
                    # OnlineDataProvider recorded (via _service_call /
                    # _is_access_denied) over the generic detector-name
                    # entry below — this surfaces even when the detector's
                    # own except block swallowed the provider's re-raised
                    # ClientError (e.g. security.py:_detect_unencrypted_efs,
                    # storage.py:_detect_efs_waste), since the provider is
                    # created fresh per detector call and records the
                    # failure the moment it happens, before any detector-
                    # level except runs.
                    provider_permission_errors = detector_result.get('provider_permission_errors') or []
                    if provider_permission_errors:
                        for err in provider_permission_errors:
                            result.permission_errors.append(
                                f"{detector_name}: {err.get('resource')} needs "
                                f"{err.get('permission')} ({err.get('error_code')})"
                            )
                            # CLO-368: structured {detector, action} view of the
                            # same failure for the account row / UI.
                            _append_permission_missing(
                                result, detector_name, err.get('permission') or 'unknown',
                            )
                    elif permission_error:
                        result.permission_errors.append(permission_error)
                        _append_permission_missing(
                            result,
                            permission_error,
                            detector_result.get('permission_missing_action') or 'unknown',
                        )

                    # CLO-375: a free AWS input this account hasn't enabled.
                    # Not an error (the scan still succeeded), but carried to
                    # the account row so it never reads as "no waste".
                    for note in detector_result.get('provider_coverage_notes') or []:
                        if note not in result.coverage_notes:
                            result.coverage_notes.append(note)

                    # CLO-479: the detector ran, but part of its input is
                    # missing (e.g. Lambda functions whose CloudWatch metrics
                    # failed to load). Those findings are MISSING, not zero.
                    for warning in detector_result.get('provider_data_warnings') or []:
                        if warning not in result.warnings:
                            result.warnings.append(warning)

                    # CLO-178: a circuit-open skip means this detector's
                    # findings are MISSING from this scan, not zero. Surface
                    # it on the result (→ region-scanner response warnings /
                    # SFN summary) instead of leaving it metrics-and-logs
                    # only, where whole categories vanished without a trace.
                    if detector_result.get('circuit_open_skip'):
                        result.warnings.append(
                            f"{detector_name}: detector skipped — circuit breaker open "
                            f"after recent failures/timeouts; findings for this service "
                            f"are missing from this scan, not zero"
                        )

                    # CLO-185: a detector that dies with asyncio.TimeoutError
                    # previously left the persisted scan record clean — the
                    # timeout only hit EMF metrics + a log WARNING. Surface
                    # it the same way CLO-178 surfaced circuit-open skips,
                    # so a timed-out detector's missing findings aren't
                    # silently indistinguishable from "this account has zero
                    # resources of this type".
                    if detector_result.get('timeout_skip'):
                        budget = detector_result.get('timeout_budget_seconds')
                        budget_str = f"{budget}s" if budget is not None else "its budget"
                        result.warnings.append(
                            f"Detector {detector_name} timed out after {budget_str} "
                            f"in {region} — its findings are MISSING from this scan, "
                            f"not zero"
                        )

                    # CLO-193: an unhandled generic exception in a detector
                    # previously only hit EMF metrics + a log.error line —
                    # the persisted SCAN# row looked clean while findings
                    # were silently missing. Surface it the same way
                    # CLO-178/CLO-185 surfaced circuit-open skips / timeouts.
                    detector_error = detector_result.get('detector_error')
                    if detector_error:
                        err_class = detector_error.get('error_class', 'Exception')
                        err_message = detector_error.get('message', '')
                        result.warnings.append(
                            f"Detector {detector_name} failed "
                            f"({err_class}: {err_message}) — findings from this "
                            f"detector are MISSING from this scan, not zero"
                        )

                    item_region = 'global' if i in global_service_detector_indices else region

                    # CLO-234: stage, don't filter. The savings floor moved
                    # below the reconciliation pass so it gates the reconciled
                    # figure rather than the list-price one.
                    for item in items:
                        staged_items.append(
                            self._stage_item(
                                item, account_id=account_id, item_region=item_region
                            )
                        )
                elif isinstance(detector_result, list):
                    # Legacy support for direct list returns (e.g., from tests or other callers)
                    item_region = 'global' if i in global_service_detector_indices else region

                    for item in detector_result:
                        staged_items.append(
                            self._stage_item(
                                item, account_id=account_id, item_region=item_region
                            )
                        )

            self._reconcile_and_collect(
                staged_items,
                result,
                settings,
                user_id=user_id,
                account_id=account_id,
            )

            result.complete()
            result.success = len(result.errors) == 0
            
            # Cache the result
            await self._cache_result(user_id, account_id, region, result)
            
            logger.info(
                f"Waste detection complete for {account_id}: "
                f"found {result.waste_items_found} items, "
                f"${result.total_monthly_savings:.2f}/month savings"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Waste detection failed for account {account_id}: {e}")
            result.success = False
            result.errors.append(str(e))
            result.complete()
            return result
    
    async def detect_waste_with_provider(
        self,
        data_provider: WasteDataProvider,
        settings: WasteDetectionSettings = None,
        account_id: str = None,
        is_global_scan_region: bool = True,
        user_id: str = None,
    ) -> WasteDetectionResult:
        """
        Run waste detection using a DataProvider.
        
        This method enables the SAME detection logic to work with both:
        - OnlineDataProvider: Live AWS API calls (online mode)
        - OfflineDataProvider: Parsed JSON exports (offline mode)
        
        KEY BENEFIT: One codebase for all ~92 waste types. Adding new waste
        types only requires updating this method, and both modes benefit.
        
        Args:
            data_provider: WasteDataProvider instance (Online or Offline)
            settings: Detection settings (uses defaults if not provided)
            account_id: AWS account ID (extracted from provider if not specified)
            is_global_scan_region: If False, skip global service detectors
                (CloudFront, Route53, Global Accelerator) to avoid duplicates
                in multi-region scans. Default True for backward compatibility.
            user_id: CloudWise user id, required to reconcile savings against
                billed cost (CLO-234) — the CUR partition key is
                ``USER#{user_id}#ACCT#{account_id}``. Optional: when absent
                (e.g. air-gapped uploads) every finding is labelled
                ``unreconciled_no_cur`` and keeps its list-price estimate,
                rather than silently presenting it as reconciled.

        Returns:
            WasteDetectionResult with all findings
            
        Example (Online Mode):
            provider = OnlineDataProvider(access_key, secret_key, region)
            result = await service.detect_waste_with_provider(provider)
            
        Example (Offline Mode - Lambda):
            provider = OfflineDataProvider(export_data)
            result = await service.detect_waste_with_provider(provider)
        """
        settings = settings or WasteDetectionSettings.get_defaults()
        
        # Get account_id from provider if not specified
        if account_id is None:
            if hasattr(data_provider, '_account_id'):
                account_id = data_provider._account_id
            else:
                account_id = "unknown"
        
        result = WasteDetectionResult(
            account_id=account_id,
            region=data_provider.region,
            settings=settings,
        )
        
        try:
            logger.info(
                f"Starting unified waste detection with {data_provider.provider_type} provider "
                f"for region {data_provider.region}"
            )
            
            # Run all detector categories using the mixin methods
            # These methods now use DataProvider, enabling TRUE online-offline parity
            detector_tasks = [
                # Compute detectors (compute.py)
                self._detect_ec2_waste(data_provider, settings),
                self._detect_lambda_waste(data_provider, settings),
                self._detect_ecs_waste(data_provider, settings),
                self._detect_eks_extended_support(data_provider, settings),
                self._detect_sagemaker_waste(data_provider, settings),
                self._detect_workspaces_waste(data_provider, settings),
                self._detect_lightsail_waste(data_provider, settings),
                self._detect_elastic_beanstalk_waste(data_provider, settings),
                # Storage detectors (storage.py)
                self._detect_ebs_waste(data_provider, settings),
                self._detect_s3_waste(data_provider, settings),
                self._detect_efs_waste(data_provider, settings),
                self._detect_fsx_waste(data_provider, settings),
                self._detect_ecr_waste(data_provider, settings),
                self._detect_backup_waste(data_provider, settings),
                # Database detectors (database.py)
                self._detect_rds_waste(data_provider, settings),
                self._detect_aurora_waste(data_provider, settings),
                self._detect_dynamodb_waste(data_provider, settings),
                self._detect_elasticache_waste(data_provider, settings),
                self._detect_redshift_waste(data_provider, settings),
                self._detect_opensearch_waste(data_provider, settings),
                self._detect_neptune_waste(data_provider, settings),
                self._detect_documentdb_waste(data_provider, settings),
                # Network detectors (network.py)
                self._detect_network_waste(data_provider, settings),
                self._detect_vpc_endpoint_waste(data_provider, settings),
                # NOTE (CLO-174): _detect_orphaned_dns_waste is intentionally
                # EXCLUDED from the offline path. It cross-references Route 53
                # records against a *live* route53 client and self-guards with
                # `if data_provider.provider_type == 'offline': return []`, so it
                # can never emit findings on a CUR/offline upload. Adding it would
                # only enqueue a no-op task. Re-add here if the detector ever
                # gains an offline (export-based) code path.
                # Analytics detectors (analytics.py)
                self._detect_emr_deep_waste(data_provider, settings),
                self._detect_kinesis_waste(data_provider, settings),
                self._detect_glue_waste(data_provider, settings),
                # Integration detectors (integration.py)
                self._detect_api_gateway_waste(data_provider, settings),
                self._detect_msk_waste(data_provider, settings),
                self._detect_mq_waste(data_provider, settings),
                self._detect_step_functions_waste(data_provider, settings),
                self._detect_appsync_waste(data_provider, settings),
                self._detect_transfer_family_waste(data_provider, settings),
                # Management detectors (management.py)
                self._detect_cloudwatch_waste(data_provider, settings),
                self._detect_secrets_manager_waste(data_provider, settings),
                self._detect_kms_waste(data_provider, settings),
                self._detect_cloudtrail_waste(data_provider, settings),
                self._detect_cloudwatch_dashboard_waste(data_provider, settings),
                # Security posture detectors (security.py) — advisory ($0) findings.
                # All checks read describe-style resource attributes (encryption,
                # deletion protection, public access, backup coverage) that the
                # offline provider parses directly from the CUR/export JSON, so
                # they run identically online and offline. (CLO-174)
                self._detect_security_posture_waste(data_provider, settings),
                # Optimizer (optimizer.py) - Online only
                self._detect_compute_optimizer_waste(data_provider, settings),
                # Savings recommendations (savings.py) - Online only
                self._detect_savings_opportunities(data_provider, settings),
                # Commitment risk detectors (commitment.py)
                self._detect_commitment_waste(data_provider, settings),
            ]
            
            # Global service detectors: only run on the primary scan region
            # to avoid duplicate findings in multi-region scans
            if is_global_scan_region:
                detector_tasks.extend([
                    self._detect_cloudfront_waste(data_provider, settings),
                    self._detect_route53_waste(data_provider, settings),
                    self._detect_global_accelerator_waste(data_provider, settings),
                ])
            else:
                logger.info(
                    f"Skipping global service detectors for non-primary region "
                    f"{data_provider.region}"
                )
            
            # CLO-493: name each task by its detector (the DETECTOR_METHODS
            # key, as the online path does), read before gather consumes them.
            detector_names = [
                _detector_label(getattr(task, '__name__', '')) for task in detector_tasks
            ]

            # Run all detectors in parallel
            detector_results = await asyncio.gather(*detector_tasks, return_exceptions=True)
            
            # Collect results
            staged_items: List[WasteItem] = []
            for i, detector_result in enumerate(detector_results):
                if isinstance(detector_result, Exception):
                    detector_name = detector_names[i] if i < len(detector_names) else f"DETECTOR_{i}"
                    self._record_provider_detector_error(
                        result, data_provider, detector_name, detector_result, account_id,
                    )
                elif isinstance(detector_result, list):
                    # CLO-234: stage first — the savings floor is applied to the
                    # reconciled figure inside _reconcile_and_collect. Staging
                    # also regenerates the deterministic ID now that
                    # region/account are set (they were empty at __post_init__).
                    for item in detector_result:
                        staged_items.append(
                            self._stage_item(
                                item,
                                account_id=account_id,
                                item_region=data_provider.region,
                            )
                        )

            self._reconcile_and_collect(
                staged_items,
                result,
                settings,
                user_id=user_id,
                account_id=account_id,
            )

            # CLO-485: the provider's "MISSING, not zero" notes (idle verdicts
            # withheld for missing data) reach the result here as they do in
            # detect_waste. This is the air-gapped upload's path.
            provider_warnings = getattr(data_provider, 'data_warnings', None)
            for warning in provider_warnings if isinstance(provider_warnings, list) else []:
                if warning not in result.warnings:
                    result.warnings.append(warning)

            result.complete()
            result.success = len(result.errors) == 0
            
            logger.info(
                f"Unified waste detection complete: "
                f"found {result.waste_items_found} items, "
                f"${result.total_monthly_savings:.2f}/month savings"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Unified waste detection failed: {e}")
            result.success = False
            result.errors.append(str(e))
            result.complete()
            return result
    
    @staticmethod
    def _record_provider_detector_error(
        result: WasteDetectionResult,
        data_provider: WasteDataProvider,
        detector_name: str,
        error: BaseException,
        account_id: Optional[str],
    ) -> None:
        """CLO-493: a detector that raised on the provider path (the
        Air-Gapped upload) is counted and surfaced the way
        ``_run_detector_with_timeout`` does it online (CLO-193).

        It used to land only in ``result.errors`` as ``Detector <index>
        error``, which the upload never showed or counted, so a detector that
        crashed on every upload (idle EC2's ``avg_cpu`` AttributeError) looked
        like "no findings". Now it gets:

        * a named ``result.errors`` entry and an ERROR log;
        * a ``result.warnings`` note, which the upload stores as
          ``scan_warnings``: the detector's findings are MISSING, not zero;
        * one ``DetectorMetricEvent`` with ``errors=1`` through the
          configured emitter, so it counts in ``DetectorErrors`` wherever an
          emitter is wired (the backend wires none today: a no-op there).
        """
        from cloudwise_scan_core.config import get_metrics_emitter_provider
        from cloudwise_scan_core.metrics import DetectorMetricEvent

        error_class = error.__class__.__name__
        message = str(error)
        error_msg = f"{detector_name} detector error: {error_class}: {message}"
        logger.error(
            "Detector %s failed on the %s provider in %s: %s: %s",
            detector_name, getattr(data_provider, 'provider_type', '?'),
            getattr(data_provider, 'region', '?'), error_class, message,
        )
        result.errors.append(error_msg)
        warning = (
            f"Detector {detector_name} failed ({error_class}: {message[:200]}) — "
            f"findings from this detector are MISSING from this scan, not zero"
        )
        if warning not in result.warnings:
            result.warnings.append(warning)

        try:
            emitter = get_metrics_emitter_provider()()
            if emitter is not None:
                emitter.emit(DetectorMetricEvent(
                    environment=os.environ.get("ENVIRONMENT")
                    or os.environ.get("CLOUDWISE_ENVIRONMENT", "unknown"),
                    detector_id=detector_name,
                    region=getattr(data_provider, 'region', '') or '',
                    duration_ms=0,
                    findings_count=0,
                    errors=1,
                    account_id=account_id,
                    success=False,
                    error_class=error_class,
                    extras={'provider_type': getattr(data_provider, 'provider_type', None)},
                ))
        except Exception:  # noqa: BLE001 — metrics never fail a scan
            logger.debug("metrics emitter raised; ignoring", exc_info=True)

    # =========================================================================
    # Helper methods for pricing estimates
    # =========================================================================
    
    def _estimate_ec2_monthly_cost(self, instance_type: str) -> float:
        """Estimate monthly cost for an EC2 instance type."""
        cost_map = {
            't2.micro': 8.47, 't2.small': 16.79, 't2.medium': 33.87,
            't3.micro': 7.59, 't3.small': 15.18, 't3.medium': 30.37,
            'm5.large': 70.08, 'm5.xlarge': 140.16, 'm5.2xlarge': 280.32,
            'm6i.large': 70.08, 'm6i.xlarge': 140.16, 'm6i.2xlarge': 280.32,
        }
        return cost_map.get(instance_type, 73.0)  # Default ~$73/month
    
    def _estimate_ebs_monthly_cost(self, size_gb: int, volume_type: str) -> float:
        """Estimate monthly cost for an EBS volume."""
        cost_per_gb = {
            'gp2': 0.10, 'gp3': 0.08,
            'io1': 0.125, 'io2': 0.125,
            'st1': 0.045, 'sc1': 0.015,
            'standard': 0.05,
        }
        return size_gb * cost_per_gb.get(volume_type, 0.10)
    
    def _estimate_rds_monthly_cost(self, db_class: str, multi_az: bool) -> float:
        """Estimate monthly cost for an RDS instance."""
        base_costs = {
            'db.t3.micro': 12.41, 'db.t3.small': 24.82, 'db.t3.medium': 49.64,
            'db.m5.large': 124.83, 'db.m5.xlarge': 249.66,
            'db.r5.large': 175.20, 'db.r5.xlarge': 350.40,
        }
        cost = base_costs.get(db_class, 150.0)
        if multi_az:
            cost *= 2
        return cost
    
    def _estimate_redshift_hourly_cost(self, node_type: str) -> float:
        """Estimate Redshift hourly cost."""
        costs = {
            'dc2.large': 0.25, 'dc2.8xlarge': 4.80,
            'ra3.xlplus': 1.086, 'ra3.4xlarge': 3.26, 'ra3.16xlarge': 13.04,
        }
        return costs.get(node_type, 1.0)
    
    def _estimate_sagemaker_notebook_cost(self, instance_type: str) -> float:
        """Estimate SageMaker notebook hourly cost."""
        return self.pricing_service.FALLBACK_SAGEMAKER_PRICING.get(instance_type, 0.10)
    
    def _get_active_detectors(self, enabled_services: List[str], is_global_scan_region: bool) -> List[str]:
        """Determine which detectors to run based on enabled services."""
        if enabled_services is None:
            all_detectors = set(self.DETECTOR_METHODS.keys())
            if not is_global_scan_region:
                all_detectors -= self.GLOBAL_SERVICE_DETECTORS
            return list(all_detectors)
        
        active_detectors = set(self.ALWAYS_RUN_DETECTORS)

        # CLO-465: a name that maps to nothing selects nothing, silently. Collect
        # the ones we cannot explain and say so once, rather than leaving the next
        # AWS rename to look exactly like an account that stopped using a service.
        unmapped: List[str] = []
        for service in enabled_services:
            detector_keys = self.SERVICE_TO_DETECTORS.get(service, [])
            if not detector_keys and not is_expected_unmapped_service(service):
                unmapped.append(service)
            active_detectors.update(detector_keys)

        if unmapped:
            # One line per scan of one account/region, listing every unexplained
            # name: the fixture account alone scans 17 regions, so a line per
            # name per region would bury the fact it is reporting. WARNING, not
            # INFO — the production API Lambda drops every INFO line (CLO-326),
            # and a grep that returns nothing must not be a false zero.
            logger.warning(
                "%d CUR service name(s) map to no detector and are not on the "
                "no-detector allowlist: %s. Either AWS renamed a service (add the name "
                "to SERVICE_TO_DETECTORS) or we genuinely do not detect it (add it to "
                "NO_DETECTOR_SERVICES). Until then any detector behind that name is "
                "silently skipped on every scheduled scan (CLO-465).",
                len(unmapped), ", ".join(sorted(unmapped)),
            )
        
        if not is_global_scan_region:
            active_detectors -= self.GLOBAL_SERVICE_DETECTORS
        else:
            # CUR/Cost Explorer deliver the spaced product names ("Amazon
            # CloudFront"); the compact API-style names only appear in older
            # exports. Both must match — with only the compact forms this
            # check was dead code on the CUR path, so the global-detector
            # bulk-add never triggered (waste-audit Session 10).
            global_services_in_cost = any(
                service in enabled_services
                for service in [
                    'AmazonCloudFront', 'Amazon CloudFront',
                    'AmazonRoute53', 'Amazon Route 53',
                    'AWSGlobalAccelerator', 'AWS Global Accelerator',
                ]
            )
            if global_services_in_cost:
                active_detectors.update(self.GLOBAL_SERVICE_DETECTORS)
        
        logger.info(f"Service-filtered scan: {len(active_detectors)} detectors for {len(enabled_services)} services")
        return list(active_detectors)

    @staticmethod
    def _stage_item(item: WasteItem, *, account_id: str, item_region: str) -> WasteItem:
        """Attach scan identity to a detector's item and give it a stable id.

        Extracted from the three collection loops so staging happens before the
        savings floor rather than inside it (CLO-234) — the floor now runs
        against the *reconciled* figure, which cannot be known until every
        item is in hand and one batched CUR read has been issued.
        """
        item.account_id = account_id
        item.region = item_region
        waste_type_str = (
            item.waste_type.value
            if isinstance(item.waste_type, WasteType)
            else item.waste_type
        )
        item.id = generate_deterministic_id(
            resource_id=item.resource_id,
            waste_type=waste_type_str,
            region=item.region,
            account_id=item.account_id,
        )
        return item

    def _reconcile_and_collect(
        self,
        staged: List[WasteItem],
        result: WasteDetectionResult,
        settings: WasteDetectionSettings,
        *,
        user_id: Optional[str],
        account_id: str,
    ) -> None:
        """Reconcile staged findings against billed cost, then apply the floor.

        CLO-234. Every figure a detector produces is list-price arithmetic; this
        is where it gets checked against what AWS actually charged. Ordering is
        deliberate and load-bearing:

        1. reconcile — one batched CUR read for the whole finding set,
        2. *then* apply ``min_waste_threshold_usd``.

        Doing it the other way round would filter on a number we already know
        to be wrong, and would let a finding that reconciles to $0 survive
        purely because its list price cleared the bar.

        Every failure mode degrades to "keep the estimate, label it" — never to
        a confident-looking zero. See ``billed_cost.reconcile_savings``.

        CLO-376: commitment findings (``COMMITMENT_WASTE_TYPES`` — RI/SP
        purchase recommendations and existing-commitment risk) never enter
        the per-resource CUR match above. Their ``resource_id`` is a label
        or an RI/SP entity id, never a resource the CUR bills line items
        against, so matching them against ``lookup`` always misses and reads
        as "AWS bills $0 for this" on any account with resource-level CUR —
        silently zeroing and dropping a real recommendation. They go through
        ``billed_cost.reconcile_commitment_savings`` instead, capped against
        whatever aggregate covering spend the detector itself computed.

        Two known costs, accepted for now rather than hidden:
        - This runs synchronously on the event loop and the adapter's DynamoDB
          query is blocking. It happens once per scan, after every detector has
          already returned, so it extends the tail rather than starving
          in-flight work — but it does not go through the bounded pool that
          ``_run_detector_coroutine_sync`` uses. Revisit if CUR partitions grow.
        - The region scanner runs per region while this query is per ACCOUNT,
          so an N-region account issues N identical reads per cycle. Correct
          but redundant; hoisting the lookup to the fan-out parent would fix it.
        """
        from cloudwise_scan_core.billed_cost import (
            ReconciliationStatus,
            reconcile_commitment_savings,
            reconcile_savings,
        )
        from cloudwise_scan_core.config import get_billed_cost_provider

        lookup = None
        if staged and user_id:
            # Best-effort: a broken or unconfigured lookup must never take a
            # scan down, and must never silently zero a finding either — a
            # None lookup yields UNRECONCILED_NO_CUR for every item.
            try:
                port = get_billed_cost_provider()()
                if port is not None:
                    end_date = datetime.now(timezone.utc).date()
                    start_date = end_date - timedelta(
                        days=RECONCILIATION_WINDOW_DAYS
                    )
                    lookup = port.get_billed_costs(
                        user_id=user_id,
                        account_id=account_id,
                        resource_ids=[i.resource_id for i in staged],
                        start_date=start_date,
                        end_date=end_date,
                    )
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    f"Billed-cost lookup failed for account {account_id}: {exc}. "
                    f"Findings will report list-price estimates, labelled "
                    f"'{ReconciliationStatus.UNRECONCILED_NO_CUR}'."
                )
                lookup = None

        for item in staged:
            estimate = item.monthly_savings

            if item.waste_type in COMMITMENT_WASTE_TYPES:
                # CLO-376: RI/SP purchase recommendations and existing-
                # commitment findings name a label ("Savings Plan", an
                # instance type) or an RI/SP entity id, never a resource the
                # CUR bills line items against. Matching them against the
                # per-resource CUR index always misses and reads as "AWS
                # bills $0 for this" on any account with resource-level CUR —
                # silently zeroing and dropping the finding. Cap against the
                # detector's own aggregate covering spend instead.
                outcome = reconcile_commitment_savings(
                    estimated_savings=estimate,
                    covering_monthly_spend=(
                        item.metadata.get("covering_monthly_spend")
                        if isinstance(item.metadata, dict)
                        else None
                    ),
                )
            else:
                outcome = reconcile_savings(
                    estimated_savings=estimate,
                    resource_id=item.resource_id,
                    lookup=lookup,
                )

            item.estimated_savings_list_price = estimate
            item.monthly_savings = outcome.monthly_savings
            item.reconciliation_status = outcome.reconciliation_status
            item.billed_cost_observed = outcome.billed_cost_observed
            item.cost_basis = outcome.cost_basis

            result.reconciliation_counts[outcome.reconciliation_status] = (
                result.reconciliation_counts.get(outcome.reconciliation_status, 0)
                + 1
            )

            if (
                item.monthly_savings >= settings.min_waste_threshold_usd
                or item.waste_type in GOVERNANCE_WASTE_TYPES
            ):
                result.waste_items.append(item)
            else:
                # Correct, but visible: reconciling a finding down below the
                # floor removes it from the scan. Record it so a shrunken
                # finding count is explainable rather than mysterious.
                # The governance bypass above decides persistence only; the
                # reconciled figure stands for governance types too (CLO-448).
                result.reconciled_below_threshold += 1
                # CLO-430: keep the item, not just the tally. The region
                # scanner writes these to `below_floor.jsonl.gz` beside
                # `findings.jsonl.gz`, and the union of the two is the L2
                # oracle (ADR 0002). Nothing persisted or customer-facing
                # reads this list — it exists so validation can distinguish a
                # detector that stayed silent from one that fired and was
                # floored. Appending after the counter keeps the two in step.
                result.below_floor_items.append(item)

        if result.reconciled_below_threshold:
            logger.info(
                f"Reconciliation dropped {result.reconciled_below_threshold} "
                f"finding(s) below the ${settings.min_waste_threshold_usd} floor "
                f"for account {account_id} — savings were list-price only"
            )

    def _emit_skip_metrics(
        self,
        *,
        skipped_by_cur: set,
        skipped_by_tier: set,
        account_id: str,
        region: str,
        customer_tier: Optional[str],
    ) -> None:
        """Emit a zero-duration EMF record for each skipped detector.

        Phase 5 §3.8 — observability for pre-execution drops. Metric
        emission is best-effort; any failure is logged at DEBUG and
        swallowed so skipping remains side-effect-free.
        """
        if not skipped_by_cur and not skipped_by_tier:
            return
        from cloudwise_scan_core.config import get_metrics_emitter_provider
        from cloudwise_scan_core.metrics import DetectorMetricEvent

        emitter = get_metrics_emitter_provider()()
        if emitter is None:
            return
        environment = os.environ.get("ENVIRONMENT") or os.environ.get(
            "CLOUDWISE_ENVIRONMENT", "unknown"
        )

        def _emit(detector_id: str, *, cur: int, tier: int) -> None:
            try:
                emitter.emit(
                    DetectorMetricEvent(
                        environment=environment,
                        detector_id=detector_id,
                        region=region,
                        duration_ms=0,
                        findings_count=0,
                        account_id=account_id,
                        scan_tier=customer_tier,
                        success=True,
                        skipped_cur_filter=cur,
                        skipped_tier_filter=tier,
                    )
                )
            except Exception:  # noqa: BLE001 — metrics never fail a scan
                logger.debug("skip-metric emit failed", exc_info=True)

        for det in skipped_by_cur:
            _emit(det, cur=1, tier=0)
        for det in skipped_by_tier:
            _emit(det, cur=0, tier=1)
    
    async def _run_detector_with_timeout(
        self,
        detector_method,
        detector_name: str,
        creds: Dict[str, str],
        settings: WasteDetectionSettings,
        data_provider: WasteDataProvider = None,
    ) -> Dict[str, Any]:
        """
        Run a detector with circuit breaker, timeout, and rate limiting.
        
        Uses the DataProvider pattern for true online/offline parity.
        All detectors now accept a data_provider instead of raw creds.
        
        Phase 4 (§3.6, §4.1): consults the per-(account, detector)
        DynamoDB circuit breaker before invoking the detector, and emits
        one EMF record per invocation via the configured MetricsEmitter.
        Both are pure observability / resilience concerns and MUST NOT
        change detector outputs on the happy path.
        
        Returns:
            Dict with 'items' (List[WasteItem]) and optionally 'permission_error' (str)
            if an AccessDenied error occurred.
        """
        # Lazy-import the DI accessors so unit tests that stub providers
        # via ``reset_providers_for_tests`` + ``configure_providers`` see
        # the overrides on every call (module globals are already resolved
        # by the time we get here, but the accessors read fresh).
        from cloudwise_scan_core.config import (
            get_circuit_breaker_provider,
            get_metrics_emitter_provider,
        )
        from cloudwise_scan_core.metrics import (
            DetectorMetricEvent,
            is_throttle_error,
        )

        account_id = (creds or {}).get("account_id") or ""
        region = (creds or {}).get("region") or ""
        # CLO-358: shared dict from detect_waste(), passed through to the
        # fresh OnlineDataProvider built below so every detector in this
        # scan reuses the same extended-support CE query cache.
        extended_support_cache = (creds or {}).get("extended_support_cache")
        environment = os.environ.get("ENVIRONMENT") or os.environ.get(
            "CLOUDWISE_ENVIRONMENT", "unknown"
        )
        run_id = (creds or {}).get("run_id")
        customer_tier = (creds or {}).get("customer_tier")

        # CLO-178: scope the breaker per region. The daily pipeline fans out
        # one regional scan per Lambda invoke in parallel (17 regions); with
        # an account-level key they all share one reserve budget
        # (in_flight < threshold), so a detector still running in `threshold`
        # regions was silently skipped in every other region —
        # nondeterministic coverage loss that hit us-east-1 (the slowest,
        # resource-bearing region) hardest. Region scoping keeps the
        # breaker's protection (repeat offenders still trip, per region)
        # without cross-region blanking.
        breaker_scope = f"{detector_name}@{region}" if region else detector_name

        # CLO-178: longer cap for known-heavy detectors, opt-in per runtime
        # (see HEAVY_DETECTORS). Env read at call time so tests and the
        # region-scanner adapter can set it without rewiring the service.
        detector_timeout: float = self.DETECTOR_TIMEOUT_SECONDS
        # CLO-478: the 15s default exists for the API path (API Gateway's 29s
        # limit). The region scanner has a 600s Lambda and runs detectors
        # concurrently, so it raises the default for EVERY detector via
        # DETECTOR_TIMEOUT_DEFAULT_SECONDS — the HEAVY allowlist alone had
        # fallen behind (lambda and step_functions timed out at 15s on real
        # accounts, losing their findings for that scan). Unset/0/invalid keeps
        # 15s, so the backend API path is unchanged.
        try:
            default_override = float(os.environ.get("DETECTOR_TIMEOUT_DEFAULT_SECONDS") or 0)
        except ValueError:
            default_override = 0
        if default_override > 0:
            detector_timeout = default_override
        if detector_name in self.HEAVY_DETECTORS:
            try:
                heavy = float(os.environ.get("DETECTOR_TIMEOUT_HEAVY_SECONDS") or 0)
            except ValueError:
                heavy = 0
            if heavy > 0:
                # Never SHORTER than the general cap: a heavy detector must not
                # get less time than an ordinary one if the envs are mis-set.
                detector_timeout = max(detector_timeout, heavy)

        breaker = get_circuit_breaker_provider()()
        emitter = get_metrics_emitter_provider()()

        def _emit(event: "DetectorMetricEvent") -> None:
            if emitter is None:
                return
            try:
                emitter.emit(event)
            except Exception:  # noqa: BLE001 — metrics never fail a scan
                logger.debug("metrics emitter raised; ignoring", exc_info=True)

        # Short-circuit if the breaker is open for this (account, detector).
        #
        # Phase 4.x (issue #318): prefer the atomic reserve-before-call
        # path when the breaker backend exposes it. Under parallel region
        # fan-out N concurrent scanners can each see ``is_open=False``
        # (no failure committed yet) and each eat the full per-detector
        # timeout before the N-th failure finally trips the circuit —
        # with a reservation counter ``fail_count + in_flight >= threshold``
        # rejects calls once enough are in flight, even when no failure
        # has committed yet. Backends that don't implement ``try_reserve``
        # (e.g. external mocks) fall back to the legacy ``is_open`` read.
        reserved = False
        # CLO-360: set on the happy path so the ``finally`` block below can
        # fold ``record_success`` into ``release_reservation``'s write
        # instead of paying for a second one.
        detector_succeeded = False
        try_reserve = getattr(breaker, "try_reserve", None) if breaker is not None else None
        if breaker is not None and account_id:
            try:
                if try_reserve is not None:
                    reservation = try_reserve(
                        account_id=account_id, detector_id=breaker_scope
                    )
                    granted = bool(getattr(reservation, "granted", True))
                else:
                    granted = not breaker.is_open(
                        account_id=account_id, detector_id=breaker_scope
                    )
                if not granted:
                    logger.warning(
                        "detector %s skipped — circuit open for account=%s region=%s",
                        detector_name,
                        account_id,
                        region,
                    )
                    _emit(
                        DetectorMetricEvent(
                            environment=environment,
                            detector_id=detector_name,
                            region=region,
                            duration_ms=0,
                            findings_count=0,
                            circuit_open=1,
                            account_id=account_id,
                            run_id=run_id,
                            scan_tier=customer_tier,
                            success=False,
                        )
                    )
                    # CLO-178: mark the skip so detect_waste can surface it
                    # in result.warnings — previously a circuit-open skip was
                    # invisible outside metrics/logs and whole categories
                    # vanished from a day's scan with no user-facing trace.
                    return {
                        "items": [],
                        "permission_error": None,
                        "circuit_open_skip": True,
                    }
                reserved = try_reserve is not None
            except Exception:  # noqa: BLE001 — breaker fails open
                logger.debug("circuit breaker reserve raised; ignoring", exc_info=True)

        start = time.monotonic()
        try:
            if self._circuit_breaker.is_open:
                logger.warning(f"Detector {detector_name} skipped - circuit breaker is open")
                return {'items': [], 'permission_error': None, 'circuit_open_skip': True}
            
            # Create OnlineDataProvider if not provided
            # This enables true online/offline parity - same detectors work for both
            if data_provider is None:
                data_provider = OnlineDataProvider(
                    access_key_id=creds['access_key_id'],
                    secret_access_key=creds['secret_access_key'],
                    region=creds['region'],
                    session_token=creds.get('session_token'),
                    account_id=creds.get('account_id'),
                    extended_support_cache=extended_support_cache,  # CLO-358
                )
            
            async with self._get_api_semaphore():
                async def run_with_circuit():
                    # CLO-191: hand the detector's coroutine to the shared
                    # executor pool instead of awaiting it in place — see
                    # ``_run_detector_coroutine_sync`` for why (blocking
                    # boto3 calls with an async costume) and why this keeps
                    # ``asyncio.wait_for``'s timeout meaningful: a
                    # ``run_in_executor`` future is a real suspension point,
                    # so ``wait_for`` cancels it (and returns) at exactly
                    # ``detector_timeout`` — it does not wait for the
                    # underlying thread to finish, matching today's "the
                    # timeout stops waiting; it cannot force-kill the work"
                    # semantics.
                    loop = asyncio.get_running_loop()
                    coro = detector_method(data_provider, settings)
                    return await asyncio.wait_for(
                        loop.run_in_executor(
                            _get_detector_thread_pool(),
                            _run_detector_coroutine_sync,
                            coro,
                        ),
                        timeout=detector_timeout
                    )

                items = await self._circuit_breaker.call(run_with_circuit)
                duration_ms = int((time.monotonic() - start) * 1000)
                findings_count = len(items) if isinstance(items, list) else 0
                # CLO-368: a detector that completed normally may still have
                # swallowed one or more secondary/best-effort failures deep
                # inside the data provider (``_warn_swallowed``). Fold that
                # count into ``DetectorErrors`` here — this is the only EMF
                # event emitted for a successful invocation, so it is the
                # only place this can land. ``success`` stays True: a
                # swallowed sub-error is not a detector failure and must not
                # change what existing dashboards mean by "success".
                swallowed_errors = getattr(data_provider, 'swallowed_error_count', 0)
                _emit(
                    DetectorMetricEvent(
                        environment=environment,
                        detector_id=detector_name,
                        region=region,
                        duration_ms=duration_ms,
                        findings_count=findings_count,
                        errors=swallowed_errors,
                        account_id=account_id,
                        run_id=run_id,
                        scan_tier=customer_tier,
                        success=True,
                    )
                )
                detector_succeeded = True
                if breaker is not None and account_id and not reserved:
                    # CLO-360: when a reservation is in play, the
                    # ``finally`` block's release_reservation(success=True)
                    # call folds this exact clear into that SAME write
                    # instead of paying for a second one. Only call
                    # record_success standalone here when there's no
                    # release to merge it into (the breaker doesn't
                    # support try_reserve at all).
                    try:
                        breaker.record_success(
                            account_id=account_id,
                            detector_id=breaker_scope,
                        )
                    except Exception:  # noqa: BLE001
                        logger.debug(
                            "circuit breaker record_success raised; ignoring",
                            exc_info=True,
                        )
                return _attach_provider_permission_errors(
                    {'items': items, 'permission_error': None}, data_provider
                )

        except CircuitBreakerError as e:
            logger.warning(f"Detector {detector_name} blocked by circuit breaker: {e}")
            _emit(
                DetectorMetricEvent(
                    environment=environment,
                    detector_id=detector_name,
                    region=region,
                    duration_ms=int((time.monotonic() - start) * 1000),
                    findings_count=0,
                    circuit_open=1,
                    account_id=account_id,
                    run_id=run_id,
                    scan_tier=customer_tier,
                    success=False,
                    error_class="CircuitBreakerError",
                )
            )
            return _attach_provider_permission_errors(
                {'items': [], 'permission_error': None, 'circuit_open_skip': True},
                data_provider,
            )
        except asyncio.TimeoutError:
            logger.warning(f"Detector {detector_name} timed out after {detector_timeout}s")
            _emit(
                DetectorMetricEvent(
                    environment=environment,
                    detector_id=detector_name,
                    region=region,
                    duration_ms=int((time.monotonic() - start) * 1000),
                    findings_count=0,
                    timeouts=1,
                    errors=1,
                    account_id=account_id,
                    run_id=run_id,
                    scan_tier=customer_tier,
                    success=False,
                    error_class="TimeoutError",
                )
            )
            if breaker is not None and account_id:
                try:
                    breaker.record_failure(
                        account_id=account_id,
                        detector_id=breaker_scope,
                        error_class="TimeoutError",
                    )
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "circuit breaker record_failure raised; ignoring",
                        exc_info=True,
                    )
            # CLO-185: a detector timeout means this detector's findings are
            # MISSING from this scan, not zero — mirror the CLO-178
            # circuit_open_skip treatment so detect_waste can surface it in
            # result.warnings instead of it only being visible in EMF
            # metrics + this log line.
            return _attach_provider_permission_errors(
                {
                    'items': [],
                    'permission_error': None,
                    'timeout_skip': True,
                    'timeout_budget_seconds': detector_timeout,
                },
                data_provider,
            )
        except Exception as e:
            error_str = str(e)
            duration_ms = int((time.monotonic() - start) * 1000)
            throttled = is_throttle_error(e)
            error_class = e.__class__.__name__
            # AccessDenied is an expected steady-state signal (customer
            # permissions), not a breaker-worthy transient fault. Record
            # it as a separate metric so dashboards can distinguish.
            if 'AccessDenied' in error_str or 'AccessDeniedException' in error_str:
                logger.warning(f"Detector {detector_name} AccessDenied - user needs to update CloudFormation: {e}")
                _emit(
                    DetectorMetricEvent(
                        environment=environment,
                        detector_id=detector_name,
                        region=region,
                        duration_ms=duration_ms,
                        findings_count=0,
                        access_denied=1,
                        account_id=account_id,
                        run_id=run_id,
                        scan_tier=customer_tier,
                        success=False,
                        error_class=error_class,
                    )
                )
                # CLO-368: best-effort IAM action for permission_missing —
                # botocore ClientError carries the API operation name it
                # attempted; anything else falls back to the error class so
                # the account row still has *something* actionable.
                permission_action = getattr(e, 'operation_name', None) or error_class
                return _attach_provider_permission_errors(
                    {
                        'items': [],
                        'permission_error': detector_name,
                        'permission_missing_action': permission_action,
                    },
                    data_provider,
                )
            logger.error(f"Detector {detector_name} failed: {e}")
            _emit(
                DetectorMetricEvent(
                    environment=environment,
                    detector_id=detector_name,
                    region=region,
                    duration_ms=duration_ms,
                    findings_count=0,
                    errors=1,
                    api_throttles=1 if throttled else 0,
                    account_id=account_id,
                    run_id=run_id,
                    scan_tier=customer_tier,
                    success=False,
                    error_class=error_class,
                )
            )
            if breaker is not None and account_id:
                try:
                    breaker.record_failure(
                        account_id=account_id,
                        detector_id=breaker_scope,
                        error_class=error_class,
                    )
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "circuit breaker record_failure raised; ignoring",
                        exc_info=True,
                    )
            # CLO-193: an unhandled detector exception previously vanished
            # into EMF metrics + a single log.error line — the persisted
            # SCAN# row looked clean while this detector's findings were
            # silently missing (real incident: 2026-07-16 staging scan had
            # 13+ detector invocations fail with RuntimeError, all invisible
            # in scan rows). Mirror the CLO-178/CLO-185 timeout_skip
            # plumbing so detect_waste can surface it in result.warnings.
            return _attach_provider_permission_errors(
                {
                    'items': [],
                    'permission_error': None,
                    'detector_error': {
                        'detector': detector_name,
                        'error_class': error_class,
                        'message': error_str[:200],
                    },
                },
                data_provider,
            )
        finally:
            # Always release a granted reservation so the in_flight
            # counter decays even on success, access-denied, timeout, or
            # unexpected error paths. Best-effort; breaker swallows its
            # own errors.
            #
            # CLO-360: pass success=detector_succeeded so an adapter that
            # supports it (DynamoDBCircuitBreaker) folds record_success's
            # write into this one instead of paying for two. A breaker
            # whose release_reservation doesn't accept `success` (an
            # older adapter, or a test double) raises TypeError on the
            # unexpected kwarg; fall back to the original two-call shape
            # rather than lose the success recording or crash the
            # finally block.
            if reserved and breaker is not None and account_id:
                release = getattr(breaker, "release_reservation", None)
                if release is not None:
                    try:
                        release(
                            account_id=account_id,
                            detector_id=breaker_scope,
                            success=detector_succeeded,
                        )
                    except TypeError:
                        try:
                            release(account_id=account_id, detector_id=breaker_scope)
                        except Exception:  # noqa: BLE001
                            logger.debug(
                                "circuit breaker release_reservation raised; ignoring",
                                exc_info=True,
                            )
                        if detector_succeeded:
                            try:
                                breaker.record_success(
                                    account_id=account_id,
                                    detector_id=breaker_scope,
                                )
                            except Exception:  # noqa: BLE001
                                logger.debug(
                                    "circuit breaker record_success raised; ignoring",
                                    exc_info=True,
                                )
                    except Exception:  # noqa: BLE001
                        logger.debug(
                            "circuit breaker release_reservation raised; ignoring",
                            exc_info=True,
                        )
    
    async def _get_cached_result(
        self,
        user_id: str,
        account_id: str,
        region: str,
    ) -> Optional[WasteDetectionResult]:
        """Get cached waste detection result if valid."""
        try:
            cache_key = f"waste_detection:{account_id}:{region}"
            cached = await self.cache_service.get_cached_data(user_id, cache_key)
            
            if cached and isinstance(cached, dict):
                # Cache service wraps data: {"data": <original>, "cached_at": ..., "cache_key": ...}
                # Extract the inner data envelope first
                cache_envelope = cached.get('data', cached)  # fall back to cached itself for compat
                cached_at = cached.get('cached_at') or cache_envelope.get('cached_at')
                if cached_at:
                    cached_time = datetime.fromisoformat(cached_at.replace('Z', '+00:00'))
                    if cached_time.tzinfo is None:
                        cached_time = cached_time.replace(tzinfo=timezone.utc)
                    
                    age = datetime.now(timezone.utc) - cached_time
                    if age < timedelta(hours=24):
                        result_data = cache_envelope.get('result', {})
                        result = WasteDetectionResult(
                            account_id=result_data.get('account_id', account_id),
                            region=result_data.get('region', region),
                        )
                        result.waste_items = [
                            WasteItem.from_dict(item) 
                            for item in result_data.get('waste_items', [])
                        ]
                        result.total_monthly_savings = result_data.get('total_monthly_savings', 0)
                        result.success = result_data.get('success', True)
                        result.waste_items_found = len(result.waste_items)
                        
                        return result
            
            return None
            
        except Exception as e:
            logger.warning(f"Error reading cache: {e}")
            return None
    
    async def _cache_result(
        self,
        user_id: str,
        account_id: str,
        region: str,
        result: WasteDetectionResult,
    ):
        """Cache waste detection result."""
        try:
            cache_key = f"waste_detection:{account_id}:{region}"
            cache_data = {
                'cached_at': datetime.now(timezone.utc).isoformat(),
                'result': result.to_dict(),
            }
            await self.cache_service.set_cache_data(user_id, cache_key, cache_data, ttl_hours=24)
            logger.debug(f"Cached waste detection result for {account_id}:{region}")
        except Exception as e:
            logger.warning(f"Error caching result: {e}")


# Singleton instance
_waste_detection_service: Optional["WasteDetectionService"] = None


def get_waste_detection_service() -> "WasteDetectionService":
    """Get or create the waste detection service singleton."""
    global _waste_detection_service
    if _waste_detection_service is None:
        # Through the module, not a direct import, so that
        # patch("...waste_detection_service.WasteDetectionService") still
        # reaches the singleton as it did when the class was defined here.
        service_cls = getattr(sys.modules[__name__], "WasteDetectionService")
        _waste_detection_service = service_cls()
    return _waste_detection_service


def __getattr__(name):
    # CLO-562: the full service (every detector mixin, open and closed) lives in
    # ``hosted_service.py`` so that this module, the orchestration base, imports
    # no closed detector. Resolved lazily to keep the old import path working.
    if name == "WasteDetectionService":
        from cloudwise_scan_core.hosted_service import WasteDetectionService

        return WasteDetectionService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
