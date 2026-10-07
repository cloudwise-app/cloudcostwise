"""
Online Waste Data Provider

This implementation uses live boto3 AWS API calls to fetch resource data
and CloudWatch metrics. This is the default provider for connected AWS accounts.
"""

import logging
import math
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

from cloudwise_scan_core.data_providers.base import WasteDataProvider
from cloudwise_scan_core.data_providers.missing_data import (
    KINESIS_EFO_NOTE_EVIDENCE,
    KINESIS_EFO_NOTE_SERVICE,
    KINESIS_EFO_NOTE_VERDICT,
    MissingDataNotesMixin,
)
from cloudwise_scan_core.cloudwatch_metrics_service import MSKMetrics, MQMetrics
from cloudwise_scan_core.metric_window import (
    _as_utc,
    drop_pre_creation_datapoints,
    metric_start_time,
)
from cloudwise_scan_core.cpu_sizing import (
    CPU_PERCENTILE,
    MIN_CPU_COVERAGE,
    CpuSizingThresholds,
    cpu_is_low_enough,
    ec2_cpu_is_idle,
    has_min_coverage,
    is_as_old_as_window,
    nearest_rank_percentile,
    summarize_ecs_utilization,
    summarize_hourly_cpu,
)
from cloudwise_scan_core.data_providers.models import (
    CounterRead,
    EC2InstanceData,
    EC2MetricsData,
    EBSVolumeData,
    EBSIopsPeakData,
    EBSSnapshotData,
    ElasticIPData,
    RDSInstanceData,
    RDSMetricsData,
    RDSSnapshotData,
    LambdaFunctionData,
    LambdaMetricsData,
    LambdaProvisionedConcurrencyData,
    NATGatewayData,
    NATGatewayMetricsData,
    S3BucketData,
    S3CostBreakdown,
    ExtendedSupportCostData,
    EFSFilesystemData,
    ECRRepositoryData,
    LoadBalancerData,
    LoadBalancerMetricsData,
    Route53ZoneData,
    DynamoDBTableData,
    DynamoDBMetricsData,
    ElastiCacheClusterData,
    ElastiCacheMetricsData,
    ElastiCacheRequestVolumeData,
    RedshiftClusterData,
    RedshiftMetricsData,
    RedshiftCostData,
    OpenSearchDomainData,
    OpenSearchMetricsData,
    CloudWatchLogGroupData,
    KMSKeyData,
    SecretsManagerSecretData,
    SageMakerNotebookData,
    SageMakerEndpointData,
    SageMakerMetricsData,
    KinesisStreamData,
    KinesisMetricsData,
    KinesisConsumerData,
    KinesisFirehoseData,
    KinesisFirehoseMetricsData,
    AMIData,
    MSKClusterData,
    BackupRecoveryPointData,
    BackupPlanData,
    BackupSelectionData,
    BackupCopyJobSummary,
    DocumentDBClusterData,
    DocumentDBSnapshotData,
    DocumentDBMetricsData,
    FSxFilesystemData,
    FSxMetricsData,
    FSxBackupData,
    fsx_filesystem_config,
    recovery_point_plan_id,
    fsx_hourly_peak_bytes,
    StepFunctionExecutionSummaryData,
    StepFunctionRetryMetricsData,
    StepFunctionTransitionMetricsData,
    EKSClusterData,
    AuroraClusterData,
    AuroraClusterInstanceRef,
    AuroraIOMetricsData,
    NeptuneClusterData,
    NeptuneClusterInstanceRef,
    NeptuneSnapshotData,
    NeptuneMetricsData,
    MQBrokerData,
    LightsailInstanceData,
    LightsailStaticIpData,
    LightsailDiskData,
    LightsailSnapshotData,
    LightsailLoadBalancerData,
    LightsailDatabaseData,
    LightsailMetricsData,
    EMRClusterData,
    EMRInstanceGroupData,
    EMRStepSummaryData,
    EMRMetricsData,
    WorkspaceData,
    WorkspaceConnectionData,
    WorkspacePoolData,
    WorkspaceMetricsData,
    BeanstalkEnvironmentData,
    BeanstalkConfigData,
    BeanstalkMetricsData,
    ApiGatewayRestApiData,
    beanstalk_rds_marks,
    GlobalAcceleratorData,
)

logger = logging.getLogger(__name__)

# CLO-513: ListMultipartUploads pages read per bucket (1,000 uploads each).
S3_MULTIPART_MAX_PAGES = 5

# CLO-527 item 5: DescribeVolumes pages (500 is the API's MaxResults ceiling).
# 40 pages = 20,000 volumes per region; past that the rest are MISSING and
# noted, and the orphaned-snapshot verdict (which needs the WHOLE volume
# list) is withheld.
EBS_VOLUMES_PAGE_SIZE = 500
EBS_VOLUMES_MAX_PAGES = 40

# CLO-527 item 5: DescribeTargetGroups pages per load balancer (400 is the
# API's PageSize ceiling). An ALB holds at most 100 target groups (ELB quota
# "Target groups per Application Load Balancer"), so one page is the whole
# answer in practice; the bound only stops a runaway Marker loop.
TARGET_GROUPS_PAGE_SIZE = 400
TARGET_GROUPS_MAX_PAGES = 5

# CLO-532 item 2: DescribeLoadBalancers pages (elbv2 and classic ELB; 400 is
# both APIs' PageSize ceiling). 5 pages = 2,000 load balancers per API per
# region, far above the default quotas (50 ALBs, 50 NLBs, 20 CLBs); past
# that the rest are not judged and get_load_balancers reports the list as
# incomplete (orphaned_dns_record then withholds its ELB-CNAME verdicts).
LOAD_BALANCERS_PAGE_SIZE = 400
LOAD_BALANCERS_MAX_PAGES = 5

# CLO-535 item 3: DescribeDBInstances pages at the API's default MaxRecords
# (100; the parameter is not sent, so the first call matches the recorded
# unpaged one). 20 pages = 2,000 instances per region, far above the default
# quota of 40 DB instances; past that the rest are not judged and
# get_rds_instances reports the list as incomplete.
RDS_INSTANCES_MAX_PAGES = 20


def _describe_target_groups_bounded(elbv2, load_balancer_arn: str) -> Tuple[List[Dict[str, Any]], bool]:
    """A load balancer's target groups, following NextMarker for at most
    TARGET_GROUPS_MAX_PAGES pages. Returns (groups, complete); complete is
    False when the bound stopped the read. ClientError propagates."""
    groups: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {'LoadBalancerArn': load_balancer_arn, 'PageSize': TARGET_GROUPS_PAGE_SIZE}
    for _ in range(TARGET_GROUPS_MAX_PAGES):
        page = elbv2.describe_target_groups(**kwargs)
        groups.extend(page.get('TargetGroups', []) or [])
        marker = page.get('NextMarker')
        if not marker:
            return groups, True
        kwargs = {**kwargs, 'Marker': marker}
    return groups, False


def _describe_load_balancers_bounded(client, result_key: str) -> Tuple[List[Dict[str, Any]], bool]:
    """Every page of an elbv2 or classic ELB DescribeLoadBalancers (both page
    with PageSize/Marker/NextMarker), for at most LOAD_BALANCERS_MAX_PAGES
    pages. Returns (load_balancers, complete); complete is False when the
    bound stopped the read. ClientError propagates."""
    lbs: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {'PageSize': LOAD_BALANCERS_PAGE_SIZE}
    for _ in range(LOAD_BALANCERS_MAX_PAGES):
        page = client.describe_load_balancers(**kwargs)
        lbs.extend(page.get(result_key, []) or [])
        marker = page.get('NextMarker')
        if not marker:
            return lbs, True
        kwargs = {**kwargs, 'Marker': marker}
    return lbs, False


def _list_incomplete_multipart_uploads(s3, bucket_name: str) -> List[Dict[str, Any]]:
    """A bucket's incomplete multipart uploads, following IsTruncated for at
    most S3_MULTIPART_MAX_PAGES pages (CLO-513 review: only the first page
    was read). ClientError propagates to the caller."""
    uploads: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {'Bucket': bucket_name}
    for _ in range(S3_MULTIPART_MAX_PAGES):
        page = s3.list_multipart_uploads(**kwargs)
        uploads.extend(page.get('Uploads', []) or [])
        if not page.get('IsTruncated'):
            break
        kwargs = {
            'Bucket': bucket_name,
            'KeyMarker': page.get('NextKeyMarker', ''),
            'UploadIdMarker': page.get('NextUploadIdMarker', ''),
        }
    return uploads

# CLO-479: Lambda metrics come from batched GetMetricData. Each function
# needs three queries (Invocations Sum, Duration Average, Duration Maximum)
# and one call accepts at most 500 queries, so 166 functions per call.
_LAMBDA_METRIC_QUERIES: Tuple[Tuple[str, str, str], ...] = (
    ('inv', 'Invocations', 'Sum'),
    ('davg', 'Duration', 'Average'),
    ('dmax', 'Duration', 'Maximum'),
)
_METRIC_DATA_MAX_QUERIES_PER_CALL = 500
_LAMBDA_FUNCTIONS_PER_METRIC_DATA_CALL = _METRIC_DATA_MAX_QUERIES_PER_CALL // len(_LAMBDA_METRIC_QUERIES)

# CLO-499: idle_ec2's hourly CPU comes from batched GetMetricData too. Each
# instance needs two queries (CPUUtilization Average and Maximum), so 250
# instances per request. A response carries at most 100,800 datapoints, so a
# full 250-instance chunk (168,000 hourly datapoints over 14 days) arrives in
# two NextToken pages: 500 instances cost 4 requests instead of 500.
_EC2_CPU_METRIC_QUERIES: Tuple[Tuple[str, str], ...] = (
    ('cavg', 'Average'),
    ('cmax', 'Maximum'),
)
_EC2_INSTANCES_PER_METRIC_DATA_CALL = _METRIC_DATA_MAX_QUERIES_PER_CALL // len(_EC2_CPU_METRIC_QUERIES)

# CLO-549: AWS/Kafka publishes broker metrics per broker ("Cluster Name" +
# "Broker ID", DEFAULT monitoring level). Five queries per broker, so 100
# brokers per GetMetricData request; a 7-day hourly window is 168 datapoints
# per query (84,000 for a full chunk, one page). A cluster costs one request.
_MSK_BROKER_METRICS: Tuple[Tuple[str, str], ...] = (
    ('msg', 'MessagesInPerSec'),
    ('bin', 'BytesInPerSec'),
    ('bout', 'BytesOutPerSec'),
    ('cusr', 'CpuUser'),
    ('csys', 'CpuSystem'),
)
# One query is kept for the broker-id probe (get_msk_metrics).
_MSK_BROKERS_PER_METRIC_DATA_CALL = (_METRIC_DATA_MAX_QUERIES_PER_CALL - 1) // len(_MSK_BROKER_METRICS)
# A broker's series must reach this close to the window's end: a broker
# removed during the window leaves a stale series, which is MISSING.
_MSK_FRESH_HOURS = 3


# CLO-524/CLO-506: share of a window a Beanstalk or WorkSpaces measurement
# must cover before a verdict is drawn from it (#1535's 75% rule).
BEANSTALK_MIN_COVERAGE = 0.75
WORKSPACES_MIN_COVERAGE = 0.75

# CLO-516: over_provisioned_iops reads each candidate volume's one-minute
# VolumeReadOps + VolumeWriteOps through one metric-math expression
# ((r+w)/PERIOD(r), the per-minute IOPS) per volume; only the expression's
# values come back (20,160 per volume for 14 days). One GetMetricData response
# holds at most 100,800 datapoints, and every NextToken page is billed for all
# the metrics requested again, so a batch is sized to fit ONE page (5 volumes
# at 14 days) and the deadline is checked before every request. Cost: two
# metrics per volume ($0.01 per 1,000 metrics), about $0.00002 per volume per
# scan; a request takes well under a second.
_EBS_IOPS_PERIOD_SECONDS = 60
_METRIC_DATA_MAX_DATAPOINTS_PER_PAGE = 100_800


def _ebs_volumes_per_metric_data_call(days: int) -> int:
    per_volume = max(1, int(days * 86400 / _EBS_IOPS_PERIOD_SECONDS))
    return max(1, min(_METRIC_DATA_MAX_QUERIES_PER_CALL // 3,
                      _METRIC_DATA_MAX_DATAPOINTS_PER_PAGE // per_volume))


# Share of the window's minutes the series must cover before a peak counts as
# measured (#1479's 75% rule). EBS publishes one-minute data for every
# attached volume.
EBS_IOPS_MIN_COVERAGE = 0.75

# CLO-481: provisioned-concurrency (PC) lookups for the lambda detector.
#
# ListProvisionedConcurrencyConfigs is per function, and the detector used to
# make one call per function, serially (~150-300 ms each). Two levers:
#
# 1. Prune. PC can't be configured on $LATEST, and an alias pointing at
#    $LATEST is rejected too ("Provisioned Concurrency Configs cannot be
#    applied to unpublished function versions"), so a function with no
#    published version can't have PC. ListFunctions(FunctionVersion=ALL)
#    lists every published version, 50 entries a page, so one walk finds the
#    functions that have one. The walk is capped at one page per
#    ``_LAMBDA_VERSION_WALK_FUNCTIONS_PER_PAGE_BUDGET`` functions: a region
#    whose functions carry many versions (Serverless Framework publishes one
#    per deploy by default) would otherwise make the walk dearer than the
#    lookups it saves. Past the cap, or on any walk error, every function is
#    looked up: pruning never assumes "no PC" from missing data.
#
# 2. Bound the rest. The remaining lookups run on a small, per-call thread
#    pool. Lambda's control-plane quota is 15 requests/s per account and
#    region, across ALL control-plane APIs, cannot be raised, and is shared
#    with the customer's own deploys. So the pool is capped by RATE, not only
#    by width: 8 workers at 150-300 ms would try 27-53 requests/s. 10/s
#    leaves a third of the quota to the customer; 4 workers at 150-300 ms
#    can reach it. The client's adaptive retry mode still backs off on a
#    throttle.
#
# Ceiling: with no published versions, a region needs 2 x ceil(n/50)
# ListFunctions pages and no lookups. With every function versioned, the
# walk gives up after ceil(n/8) pages and n lookups run at 10/s: about
# 300 functions in the 45s default cap, 600 in the 90s heavy cap.
_LAMBDA_PC_LOOKUP_WORKERS = 4
_LAMBDA_PC_LOOKUP_MAX_RPS = 10.0
_LAMBDA_VERSION_WALK_FUNCTIONS_PER_PAGE_BUDGET = 8

# CLO-516: a log group's last activity, per group, from its newest stream.
#
# DescribeLogGroups has no lastEventTimestamp (the wire response carries none;
# only log streams do), so old_log_group never fired and empty_log_group
# measured "days empty" from the group's creation. The fix is one
# DescribeLogStreams(orderBy=LastEventTime, descending, limit=1) per group,
# and only for groups the cheap DescribeLogGroups filters already made
# candidates (the detector picks them), never for every group in the region.
#
# DescribeLogStreams' quota is 25 requests/s per account and region, shared
# with the customer's own tooling, so the lookups are capped by rate as the
# Lambda PC lookups are: 4 workers, 10/s. The adaptive retry mode still backs
# off on a throttle. At 10/s a 15s API-path detector gets through roughly 70
# candidates and the region scanner's 45s default about 250; the rest are
# reported MISSING in data_warnings and not flagged.
_LOG_ACTIVITY_LOOKUP_WORKERS = 4
_LOG_ACTIVITY_LOOKUP_MAX_RPS = 10.0

# CLO-577: AWS/AppSync does not publish CacheHitCount/CacheMissCount under
# the GraphQLAPIId dimension (or under any dimension) — confirmed against
# docs.aws.amazon.com/appsync/latest/devguide/monitoring.html. The only
# documented cache metrics are the Enhanced CacheHit/CacheMiss, keyed by
# API_Id + Resolver. See get_appsync_metrics for the full story.
_APPSYNC_CACHE_METRICS_NOT_PUBLISHED = frozenset({'CacheHitCount', 'CacheMissCount'})


class _RateLimiter:
    """Spaces calls at least ``1 / rate`` seconds apart across threads."""

    def __init__(self, rate_per_second: float):
        self._interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if not self._interval:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self._interval
        wait = slot - now
        if wait > 0:
            time.sleep(wait)


def _lambda_function_name(entry: Dict[str, Any]) -> str:
    """Unqualified function name of a ListFunctions entry. A published
    version's entry carries a qualified ARN (``...:function:name:3``); take
    the name from the ARN when it has one, so version entries and the
    $LATEST entry agree."""
    parts = (entry.get('FunctionArn') or '').split(':')
    if len(parts) >= 7 and parts[5] == 'function' and parts[6]:
        return parts[6]
    return entry.get('FunctionName', '')


DEFAULT_BOTO_CONFIG = Config(
    read_timeout=30,
    connect_timeout=10,
    retries={'max_attempts': 3, 'mode': 'adaptive'}
)

# Lightsail is only deployed to a subset of AWS regions (see
# https://docs.aws.amazon.com/general/latest/gr/lightsail.html). Unlike other
# regional services that fail fast with a ClientError when called from an
# unsupported region (see MSK/MQ "not available in this region" handling
# below), Lightsail API calls from unsupported regions were burning through
# the full per-detector timeout budget every scan (the original #725 hang).
# Skip the call outright for regions Lightsail doesn't support instead of
# hitting the API.
#
# Lightsail's boto3 calls are made synchronously, directly inside these
# ``async def`` methods, exactly like every other provider method in this
# file (see ``get_ec2_instances`` for the house style) — no method in this
# file routes its own boto3 calls through an executor/``asyncio.wait_for``
# wrapper at the provider layer. CLO-185: making Lightsail the one
# truly-async detector on the shared scan event loop backfired — every
# other detector's blocking boto3 calls starved that loop, so Lightsail's
# own wall-clock detector timeout (in waste_detection_service.py) fired as
# a victim of *other* detectors' calls even when Lightsail itself had
# nothing slow to do. CLO-191 fixed the starvation at its source: every
# detector invocation (this method included) now runs on its own worker
# thread via ``WasteDetectionService._run_detector_with_timeout``, so no
# detector's blocking calls can starve another's — the region gate above
# remains valuable independently, since it avoids paying for a slow/hanging
# call at all in regions Lightsail doesn't support, and
# ``DEFAULT_BOTO_CONFIG`` bounds a genuinely slow call in a supported region
# (30s read timeout).
LIGHTSAIL_SUPPORTED_REGIONS = frozenset({
    'us-east-1', 'us-east-2', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
    'ap-south-1',
    'ca-central-1',
})


# Error codes AWS returns when the caller lacks (or is explicitly denied) a
# permission — as opposed to a transient/unexpected failure. Silently
# returning an empty/default result for an access-denied error is
# indistinguishable from "this account genuinely has zero resources of this
# type", which creates an account-wide blind spot for any detector relying
# on the data (see CLO-172, which fixed this for ``get_efs_filesystems``
# alone; CLO-176 generalizes the fix via ``_service_call`` below).
ACCESS_DENIED_ERROR_CODES = frozenset({
    'AccessDenied',
    'AccessDeniedException',
    'UnauthorizedOperation',
    'UnauthorizedAccess',
    'UnauthorizedException',
    'AuthorizationError',
})

# DocumentDB idle/overprovisioned thresholds (CLO-447).
#
# AWS/DocDB's ReadIOPS and WriteIOPS report a Count/Second RATE, not a
# running total — CloudWatch's own unit for both is "Count/Second". Summing
# that rate over a multi-day window (the CLO-169 implementation) inflates a
# steady background rate into a huge, meaningless number: a real, never-
# connected db.t3.medium cluster held WriteIOPS at a steady 5.1-5.2/s with
# DatabaseConnections at 0, and summing 5.15/s over a 7-day window of
# 1-minute datapoints gives ~5.15 x 10,080 = ~52,000 — permanently defeating
# both the `== 0` idle gate and the `< 100` overprovisioned gate. The fix is
# to read the Average of the rate (matching the CPUUtilization query already
# below) and compare it against a rate threshold instead.
#
# DatabaseConnections is summed the same (wrong) way pre-fix: it is a gauge
# (a point-in-time count), not a delta counter, so summing point samples
# over the window is equally meaningless — it only *looked* correct for the
# idle gate because a sum of all-zero samples is still zero.
DOCDB_IDLE_COMBINED_IOPS_THRESHOLD = 10.0  # Count/Second, read + write avg
#
# CLO-455: the CPU gates. Both read the hourly (Period=3600) CPUUtilization
# datapoints over the detector's window (7 days).
#
# - avg_cpu: the mean of the hourly Averages must be under 20%. An idle
#   db.t3.medium is not near 0%: the recorded cwfx-idle-documentdb (CLO-460
#   recording, 2026-09-19) held 13.8-14.6% an hour with no clients, and its
#   window mean including boot was ~15%. 20% sits above that baseline. It was
#   not re-derived per instance class; that needs measurements we do not have.
# - p95_cpu: the 95th percentile (nearest rank) of the hourly Averages must be
#   under 40%. In words: at least 95% of the hours in the window averaged under
#   40% CPU. This replaced `max_cpu < 40`, where max_cpu was the MAXIMUM of
#   every hourly Maximum in the window: cluster boot alone hits 52-64%
#   (measured, CLO-435), so one boot hour, or one nightly batch job, vetoed the
#   detector for the whole window. Rightsizing is a claim about sustained
#   utilisation; a single hour cannot make or break it, but load in more than
#   5% of hours (8+ hours of 168) still vetoes.
# - p95_max_cpu: the 95th percentile of the hourly MAXIMUMS must be under 50%
#   (Neptune's CPU_MAX_THRESHOLD). This is the burst guard the hourly Averages
#   lose. It matters more than it looks: these metrics are read on the
#   DBClusterIdentifier dimension, which aggregates the cluster's instances, so
#   a cluster Average dilutes a hot primary with idle replicas, while the
#   cluster Maximum still shows the hot instance's peak. A primary peaking at or
#   above 50% in more than 5% of hours vetoes, however idle its replicas.
#   max_cpu (the window's single highest reading) is still read and reported;
#   it no longer gates.
# - coverage: at least 75% of the window's hours must have a CPU datapoint (126
#   of 168 for 7 days). A percentile over a few hours says nothing about a
#   week: sliced to its first 4 hours, the recorded fresh cluster (boot hour
#   averaging 32.19%) would pass both percentile gates. Zero datapoints (a
#   stopped cluster, missing metrics) vetoes for the same reason. The detector
#   additionally requires the cluster itself to be as old as the window
#   (CLO-233's minimum-age rule), because a reused DBClusterIdentifier inherits
#   the deleted cluster's datapoints (CLO-457) and can satisfy coverage while
#   being brand new.
#
# CLO-480: the CPU half of this rule now lives in cloudwise_scan_core.cpu_sizing,
# shared with oversized_neptune and oversized_opensearch so the three cannot
# drift. These constants are DocumentDB's thresholds for it, unchanged.
DOCDB_OVERPROVISIONED_AVG_CPU_THRESHOLD = 20.0  # percent, mean of hourly Averages
DOCDB_OVERPROVISIONED_P95_CPU_THRESHOLD = 40.0  # percent, p95 of hourly Averages
DOCDB_OVERPROVISIONED_P95_MAX_CPU_THRESHOLD = 50.0  # percent, p95 of hourly Maximums
DOCDB_OVERPROVISIONED_CPU_PERCENTILE = CPU_PERCENTILE  # 95.0
DOCDB_OVERPROVISIONED_MIN_CPU_COVERAGE = MIN_CPU_COVERAGE  # 0.75, fraction of the window's hours
DOCDB_OVERPROVISIONED_AVG_CONNECTIONS_THRESHOLD = 50.0
DOCDB_OVERPROVISIONED_COMBINED_IOPS_THRESHOLD = 100.0  # Count/Second, read + write avg
DOCDB_OVERPROVISIONED_CPU_THRESHOLDS = CpuSizingThresholds(
    avg_threshold=DOCDB_OVERPROVISIONED_AVG_CPU_THRESHOLD,
    p95_avg_threshold=DOCDB_OVERPROVISIONED_P95_CPU_THRESHOLD,
    p95_max_threshold=DOCDB_OVERPROVISIONED_P95_MAX_CPU_THRESHOLD,
    percentile=DOCDB_OVERPROVISIONED_CPU_PERCENTILE,
    min_coverage=DOCDB_OVERPROVISIONED_MIN_CPU_COVERAGE,
)

# Kept under its old name: it moved to cpu_sizing (CLO-480).
_nearest_rank_percentile = nearest_rank_percentile


class _ServiceCallGuard:
    """Shared context manager for every ``OnlineDataProvider.get_*`` method
    (CLO-176; generalizes the pattern CLO-172 established one-off for
    ``get_efs_filesystems``).

    Wraps the AWS API-fetch portion of a ``get_*`` method so that:

    - an access-denied/unauthorized ``ClientError`` is logged with a
      distinct, actionable WARNING (account, region, permission, resource),
      recorded onto ``provider.permission_errors`` so a scan-level caller
      can surface it, and RE-RAISED — a scan role missing a permission must
      never be indistinguishable from "this account has zero resources".
    - a non-auth ``ClientError``/``BotoCoreError`` (throttling, transient
      network errors, etc.) is logged and swallowed, preserving today's
      graceful-degradation behavior: control returns to the statement right
      after the ``with`` block, so the caller's pre-initialized default
      (usually ``[]``/``{}``/``None``) is what gets returned.
    - anything that isn't an AWS API error (a bug, a ``KeyError``, ...)
      is left completely alone and propagates normally.

    Usage::

        async def get_ec2_instances(self):
            instances = []
            with self._service_call("EC2 instances", "ec2:DescribeInstances"):
                ec2 = self._get_client('ec2')
                ...
                instances.append(...)
            return instances

    Or, for methods that return directly from inside the guarded block
    (no separate default-initialized variable)::

        def get_ecs_clusters(self):
            with self._service_call("ECS clusters", "ecs:DescribeClusters"):
                ecs = self._get_client('ecs')
                ...
                return all_clusters
            return []
    """

    def __init__(
        self,
        provider: "OnlineDataProvider",
        resource: str,
        permission: str,
        record: bool = True,
    ):
        self._provider = provider
        self._resource = resource
        self._permission = permission
        self._record = record

    def __enter__(self) -> "_ServiceCallGuard":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is None:
            return False
        if not issubclass(exc_type, (ClientError, BotoCoreError)):
            return False  # not an AWS API error — let it propagate untouched

        provider = self._provider
        error_code = ''
        if isinstance(exc_val, ClientError):
            error_code = exc_val.response.get('Error', {}).get('Code', '')

        if error_code in ACCESS_DENIED_ERROR_CODES:
            # Do NOT conflate "permission denied" with "no resources of this
            # type" — log distinctly, record it, and re-raise so this is
            # visible as a scan-level failure rather than silently
            # masquerading as an empty (but successful) result.
            if self._record:
                provider._record_permission_error(
                    resource=self._resource,
                    permission=self._permission,
                    error=exc_val,
                )
            provider._warn_access_denied(self._resource, self._permission, exc_val)
            return False  # re-raise — never masquerade as an empty result

        logger.warning(
            "Error fetching %s for account=%s region=%s (non-permission "
            "error, returning empty/default result): %s",
            self._resource, provider._account_id, provider._region, exc_val,
        )
        return True  # suppress — caller's pre-initialized default is returned


def docdb_connections_cover_idle_window(datapoints: int, window_days: int) -> bool:
    """idle_documentdb's coverage gate (CLO-457, 2026-09-28): hourly
    DatabaseConnections must cover 75% of the window (#1479's rule). Named so
    the recorded contract can lift exactly this gate (EXPECTED.json
    ``replay_verdict_change.vetoed_by``)."""
    return has_min_coverage(datapoints, window_days)


def parse_lambda_timestamp(value: Any) -> Optional[datetime]:
    """CLO-528: Lambda's ``LastModified`` as an aware datetime, or None.

    The Lambda API model declares it ``string`` (ISO-8601 with a ``+0000``
    offset), so botocore returns text where every other service's timestamp
    is a datetime. Left as text, ``is_as_old_as_window`` reads it as an
    unknown age (old), and the unused_lambda age gate would never hold."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    for fmt in ('%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z'):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    try:
        parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class OnlineDataProvider(MissingDataNotesMixin, WasteDataProvider):
    """
    Online data provider using live AWS API calls.
    
    This provider fetches data directly from AWS using boto3 clients,
    supporting real-time waste detection for connected accounts.
    """
    
    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        session_token: Optional[str] = None,
        account_id: Optional[str] = None,
        extended_support_cache: Optional[
            Dict[Tuple[str, Tuple[str, ...], int], Dict[str, ExtendedSupportCostData]]
        ] = None,
    ):
        """
        Initialize the online data provider.

        Args:
            access_key_id: AWS access key ID
            secret_access_key: AWS secret access key
            region: AWS region to query
            session_token: Optional session token for assumed roles
            account_id: Optional AWS account ID for logging
            extended_support_cache: Optional dict shared across every
                ``OnlineDataProvider`` instance created during one scan
                (CLO-358). ``waste_detection_service._run_detector_with_timeout``
                builds a fresh provider per detector, so without a caller-supplied,
                shared dict here each detector would get its own private cache and
                the rds/aurora extended-support query would still run twice. Pass
                the same dict into every provider built for one scan; leave it
                None for a standalone provider (a private, per-instance cache
                still avoids repeat calls made by the same detector).
        """
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._region = region
        self._session_token = session_token
        self._account_id = account_id or "unknown"
        self._extended_support_cache: Dict[
            Tuple[str, Tuple[str, ...], int], Dict[str, ExtendedSupportCostData]
        ] = extended_support_cache if extended_support_cache is not None else {}

        # Client cache for reuse
        self._clients: Dict[str, Any] = {}

        # Accumulates access-denied/unauthorized failures raised by
        # ``_service_call`` (CLO-176). A missing IAM permission must never be
        # indistinguishable from "this account has zero resources of this
        # type" — the orchestrator (``waste_detection_service.detect_waste``)
        # reads this list after the scan and folds it into
        # ``WasteDetectionResult.permission_errors`` so the failure is
        # actually surfaced instead of silently producing zero findings.
        self.permission_errors: List[Dict[str, Any]] = []

        # CLO-368: every previously-silent ``except ...: pass`` in this file
        # now routes through ``_warn_swallowed`` below. ``swallowed_error_count``
        # feeds the existing ``DetectorErrors`` EMF field (waste_detection_
        # service._run_detector_with_timeout reads it back off this instance
        # before emitting) and ``_warned_swallowed`` dedupes repeated
        # failures of the same (context, error class) within one provider
        # instance — the provider is constructed fresh per detector
        # invocation per region, so this caps log volume to one WARNING per
        # detector per region per scan even when the failing call sits
        # inside a per-resource loop (e.g. one CloudWatch call per SageMaker
        # endpoint).
        self.swallowed_error_count: int = 0
        self._warned_swallowed: set = set()
        # CLO-493: LaunchTime per instance, recorded by get_ec2_instances so
        # get_ec2_metrics can skip the MISSING note for an instance younger
        # than the idle window (the detector calls both on this instance).
        self._ec2_launch_times: Dict[str, Any] = {}

        # CLO-375: a free AWS input the account has not enabled (Compute
        # Optimizer not opted in, or still activating). Not a failure and
        # not a missing permission, so it goes neither in
        # ``permission_errors`` nor in the scan's errors, but it must never
        # read as "no waste" either. Each entry is ``{"source", "state"}``;
        # ``_attach_provider_permission_errors`` carries the list to the
        # account row the same way it carries ``permission_errors``.
        self.coverage_notes: List[Dict[str, str]] = []

        # CLO-479: partial-data notes for the scan result's ``warnings``
        # ("MISSING, not zero"), e.g. Lambda functions whose CloudWatch
        # metrics could not be fetched. ``_attach_provider_permission_errors``
        # carries them to ``WasteDetectionResult.warnings``.
        self.data_warnings: List[str] = []

    @property
    def provider_type(self) -> str:
        return "online"
    
    @property
    def region(self) -> str:
        return self._region
    
    @property
    def supports_cloudwatch(self) -> bool:
        return True

    def _aws_account_id(self) -> Optional[str]:
        """The scanned account's 12-digit AWS account ID, or None.

        ``self._account_id`` is NOT reliably the AWS ID: in production the
        Step Functions scan and the API's sync path pass CloudWise's own
        account UUID there (the AWS ID travels separately as
        ``aws_account_id``), and it defaults to "unknown". Anything that uses
        the account as an AWS value (a CloudWatch dimension, an ARN
        comparison) must use this instead. ``_account_id`` is used only when
        it is a 12-digit ID; otherwise one sts:GetCallerIdentity call (no IAM
        permission needed) is made and cached for the provider's life. A
        failed call is cached as None, and callers must then skip whatever
        needed the ID rather than guess."""
        if not hasattr(self, '_aws_account_id_cache'):
            account = self._account_id if isinstance(self._account_id, str) else ''
            if re.fullmatch(r'\d{12}', account or ''):
                self._aws_account_id_cache = account
            else:
                try:
                    identity = self._get_client('sts').get_caller_identity()
                    resolved = str(identity.get('Account') or '')
                    self._aws_account_id_cache = resolved if re.fullmatch(r'\d{12}', resolved) else None
                except Exception as e:  # noqa: BLE001 - any failure means "unknown"
                    logger.warning(
                        "Could not resolve the AWS account ID (sts:GetCallerIdentity) "
                        "for region=%s: %s", self._region, e,
                    )
                    self._aws_account_id_cache = None
        return self._aws_account_id_cache

    def _aws_account_id_from_sts(self) -> Optional[str]:
        """The AWS account the scan's credentials ACTUALLY belong to, or None.

        CLO-505: strict variant for tenant-isolation keys (the RI/SP savings
        cache). Unlike ``_aws_account_id`` it never trusts ``_account_id``:
        it always asks sts:GetCallerIdentity with the scan's own (assumed-role)
        credentials, once per provider. A 12-digit ``_account_id`` that
        disagrees is logged and ignored. A failed or malformed answer is
        cached as None, and callers must skip rather than guess.
        ``_aws_account_id`` is unchanged for its other callers."""
        if not hasattr(self, '_aws_account_id_sts_cache'):
            resolved: Optional[str] = None
            try:
                identity = self._get_client('sts').get_caller_identity()
                account = str(identity.get('Account') or '')
                resolved = account if re.fullmatch(r'\d{12}', account) else None
                if resolved is None:
                    logger.warning(
                        "sts:GetCallerIdentity returned no valid account for region=%s",
                        self._region,
                    )
            except Exception as e:  # noqa: BLE001 - any failure means "unknown"
                logger.warning(
                    "Could not resolve the AWS account ID (sts:GetCallerIdentity) "
                    "for region=%s: %s", self._region, e,
                )
            claimed = self._account_id if isinstance(self._account_id, str) else ''
            if resolved and re.fullmatch(r'\d{12}', claimed or '') and claimed != resolved:
                logger.warning(
                    "Provider account_id %s does not match the credentials' account %s "
                    "(sts:GetCallerIdentity); using the STS account",
                    claimed, resolved,
                )
            self._aws_account_id_sts_cache = resolved
        return self._aws_account_id_sts_cache

    def _get_client(self, service_name: str, region: Optional[str] = None):
        """Get or create a boto3 client for the given service.
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 's3', 'cloudfront')
            region: Optional region override. If not specified, uses provider's region.
                   Useful for global services like CloudFront that always use us-east-1.
        """
        # Use a cache key that includes region for region-specific clients
        effective_region = region or self._region
        cache_key = f"{service_name}:{effective_region}"
        
        if cache_key not in self._clients:
            self._clients[cache_key] = boto3.client(
                service_name,
                aws_access_key_id=self._access_key_id,
                aws_secret_access_key=self._secret_access_key,
                region_name=effective_region,
                aws_session_token=self._session_token,
                config=DEFAULT_BOTO_CONFIG,
            )
        return self._clients[cache_key]

    def _service_call(
        self, resource: str, permission: str, record: bool = True,
    ) -> _ServiceCallGuard:
        """Context manager shared by every ``get_*`` method (CLO-176).

        See ``_ServiceCallGuard`` for the full contract. ``resource`` is a
        short human-readable description used in log lines (e.g. "EC2
        instances"); ``permission`` is the best-effort IAM action string
        (e.g. "ec2:DescribeInstances") named in the warning so an operator
        knows exactly what to grant. ``record=False`` is used internally by
        ``_paginate`` to avoid double-recording the same failure once for
        the pagination call and again for the outer ``get_*`` method that
        wraps it.
        """
        return _ServiceCallGuard(self, resource, permission, record=record)

    def _record_permission_error(
        self, resource: str, permission: str, error: ClientError,
    ) -> None:
        """Accumulate a permission failure so a scan-level caller can fold
        it into ``WasteDetectionResult.permission_errors`` (CLO-176).

        ``waste_detection_service._run_detector_with_timeout`` creates a
        fresh ``OnlineDataProvider`` per detector invocation and reads this
        list right after calling the detector — regardless of whether the
        detector itself let the re-raised ``ClientError`` propagate or
        caught it in a broad ``except Exception`` — so this is the
        mechanism that lets a permission failure surface even for detectors
        that were never touched by this change.
        """
        error_code = ''
        if isinstance(error, ClientError):
            error_code = error.response.get('Error', {}).get('Code', '')
        self.permission_errors.append({
            'resource': resource,
            'permission': permission,
            'error_code': error_code,
            'account_id': self._account_id,
            'region': self._region,
            'message': str(error),
        })

    def _record_coverage_note(self, source: str, state: str) -> None:
        """CLO-375: record that ``source`` (e.g. ``compute_optimizer``) is not
        available to this scan for a reason the customer can fix, deduplicated.
        ``state`` is ``not_enrolled`` or ``pending``."""
        note = {'source': source, 'state': state}
        if note not in self.coverage_notes:
            self.coverage_notes.append(note)

    def _is_access_denied(self, error: Exception) -> bool:
        """Whether an exception is a ``ClientError`` whose AWS error code
        indicates a permission problem rather than a transient/unexpected
        failure. Safe to call with any exception type (e.g. inside a broad
        ``except Exception as e:`` handler) — returns False for anything
        that isn't a ``ClientError``."""
        if not isinstance(error, ClientError):
            return False
        return error.response.get('Error', {}).get('Code', '') in ACCESS_DENIED_ERROR_CODES

    def _warn_access_denied(self, resource: str, permission: str, error: Exception) -> None:
        """Shared WARNING format for an access-denied/unauthorized
        ``ClientError`` (CLO-176) — used both by ``_service_call``'s
        context-manager guard and by ``get_*`` methods that inline the
        ``_is_access_denied`` check directly inside their existing except
        block (see the module docstring / CLO-176 PR body for why not every
        method was converted to the ``with self._service_call(...)`` form)."""
        error_code = ''
        if isinstance(error, ClientError):
            error_code = error.response.get('Error', {}).get('Code', '')
        logger.warning(
            "%s permission check failed for account=%s region=%s: %s "
            "calling %s. Findings dependent on %s will be MISSING, not "
            "zero, until the CloudWise IAM role grants this permission. "
            "Underlying error: %s",
            resource, self._account_id, self._region,
            error_code, permission, resource, error,
        )

    def _warn_swallowed(self, context: str, permission: str, error: Exception) -> None:
        """Replace a silent ``except ...: pass`` (CLO-368) with a WARNING and
        a counted, classified record — while preserving the existing
        behaviour that a secondary/best-effort fetch failing never fails the
        whole ``get_*`` method (the caller's pre-initialized default is
        still what gets returned).

        ``context`` is a short, generic description of what was being
        fetched (e.g. "SageMaker endpoint CPU utilization") — never a
        specific resource name/ARN beyond an id already used elsewhere in
        this file's logging. ``permission`` is the best-effort IAM action.

        Access-denied errors are folded into the existing
        ``permission_errors`` mechanism (CLO-176) so they reach
        ``WasteDetectionResult.permission_missing`` (CLO-368) the same way
        a primary ``_service_call`` failure does. Every call increments
        ``swallowed_error_count``, which feeds the ``DetectorErrors`` EMF
        field. Repeats of the same (context, error class) on this provider
        instance are counted but not re-logged, since the provider is
        constructed fresh per detector invocation per region — this is the
        "one WARNING per detector per region per scan" the CLO-368 cost
        note requires, not a general-purpose log throttle.
        """
        self.swallowed_error_count += 1
        error_class = error.__class__.__name__
        # For a botocore ClientError, "ClientError" alone is true of nearly
        # every AWS API failure and tells an operator nothing — fold in the
        # AWS error code (e.g. "ThrottlingException") so the WARNING is
        # actually actionable. Non-ClientError exceptions (a bug, a
        # KeyError, ...) just use the plain class name.
        aws_error_code = ''
        if isinstance(error, ClientError):
            aws_error_code = error.response.get('Error', {}).get('Code', '')
        error_label = f"{error_class}:{aws_error_code}" if aws_error_code else error_class
        dedupe_key = (context, error_label)
        already_warned = dedupe_key in self._warned_swallowed
        self._warned_swallowed.add(dedupe_key)

        if self._is_access_denied(error):
            self._record_permission_error(resource=context, permission=permission, error=error)
            if not already_warned:
                self._warn_access_denied(context, permission, error)
            return

        if already_warned:
            return
        logger.warning(
            "Error fetching %s for account=%s region=%s (%s): swallowing, "
            "continuing scan",
            context, self._account_id, self._region, error_label,
        )

    def _paginate(self, client, method_name: str, result_key: str, **kwargs) -> List[Any]:
        """Helper to paginate boto3 API calls.

        Shares the CLO-176 permission-error guard: an access-denied error
        here means every ``get_*`` caller relying on this pagination
        silently got an empty list. ``record=False`` because every current
        caller already wraps this in its own ``_service_call`` (or will
        after CLO-176's migration), which records the failure once at the
        outer, more descriptive level; recording here too would duplicate
        the same root-cause failure in ``permission_errors``.
        """
        results = []
        try:
            service = getattr(getattr(client, 'meta', None), 'service_model', None)
            service_name = getattr(service, 'service_name', None) or 'aws'
        except Exception:  # noqa: BLE001 — best-effort label for logging only
            service_name = 'aws'
        action = ''.join(part.capitalize() for part in method_name.split('_'))
        with self._service_call(f"{method_name} (paginated)", f"{service_name}:{action}", record=False):
            paginator = client.get_paginator(method_name)
            for page in paginator.paginate(**kwargs):
                results.extend(page.get(result_key, []))
        return results
    
    def _get_tag_value(self, tags: List[Dict], key: str) -> Optional[str]:
        """Extract a tag value from AWS tags list."""
        for tag in tags or []:
            if tag.get('Key') == key:
                return tag.get('Value')
        return None
    
    def _tags_to_dict(self, tags: List[Dict]) -> Dict[str, str]:
        """Convert AWS tags list to dict."""
        return {tag.get('Key'): tag.get('Value') for tag in tags or [] if tag.get('Key')}

    def _is_lightsail_region_supported(self) -> bool:
        """Whether Lightsail is available in this provider's region.

        Lightsail is only deployed to a subset of AWS regions. Calling it
        from an unsupported region doesn't fail fast, so we check the known
        region list up front rather than paying for a slow/hanging API call
        (see ``LIGHTSAIL_SUPPORTED_REGIONS`` for the rationale).
        """
        return self._region in LIGHTSAIL_SUPPORTED_REGIONS

    # =========================================================================
    # EC2 / Compute
    # =========================================================================
    
    async def get_ec2_instances(self) -> List[EC2InstanceData]:
        """Get all EC2 instances in the region.

        Sets ``self.ec2_instances_complete`` (CLO-535 item 1): True only when
        the one DescribeInstances call succeeded and returned no NextToken.
        A failed read or a further page leaves it False, so a verdict that
        needs the WHOLE list (orphaned_dns_record's A records: "no instance
        has this public IP") is withheld. The call is not paged here: paging
        would grow every EC2-fed Fix This set, which needs its own review.
        """
        instances = []
        self.ec2_instances_complete = False
        try:
            ec2 = self._get_client('ec2')
            response = ec2.describe_instances()
            if response.get('NextToken'):
                self._warn_once(
                    f"ec2: DescribeInstances in {self._region} returned more than one page; only the "
                    "first is read. orphaned_dns_record's A-record check is withheld for the "
                    "account: MISSING, not orphaned"
                )
            
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId', '')
                    tags = instance.get('Tags', [])
                    self.__dict__.setdefault('_ec2_launch_times', {})[instance_id] = instance.get('LaunchTime')
                    
                    instances.append(EC2InstanceData(
                        instance_id=instance_id,
                        instance_type=instance.get('InstanceType', ''),
                        state=instance.get('State', {}).get('Name', ''),
                        region=self._region,
                        name=self._get_tag_value(tags, 'Name'),
                        launch_time=instance.get('LaunchTime'),
                        platform=instance.get('Platform'),
                        tags=self._tags_to_dict(tags),
                        block_device_mappings=instance.get('BlockDeviceMappings', []),
                        vpc_id=instance.get('VpcId'),
                        subnet_id=instance.get('SubnetId'),
                        public_ip=instance.get('PublicIpAddress') or None,
                    ))
            self.ec2_instances_complete = not response.get('NextToken')
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="EC2 Instances", permission="ec2:DescribeInstances", error=e,
                )
                self._warn_access_denied("EC2 Instances", "ec2:DescribeInstances", e)
                raise
            logger.error(f"Error fetching EC2 instances: {e}")
        
        return instances
    
    async def get_ec2_metrics(
        self,
        instance_ids: List[str],
        days: int = 14,
        idle_threshold: float = 5.0,
        oversized_threshold: float = 40.0,
    ) -> Dict[str, EC2MetricsData]:
        """Get CloudWatch metrics for EC2 instances.

        CLO-493, in CLO-485's shape (#1479): the idle verdict reads HOURLY
        ``CPUUtilization`` (Average + Maximum) covering 75% of the window (252
        of 336 hours), and ``cpu_sizing.ec2_cpu_is_idle``'s peak guard. An
        instance with fewer datapoints, or whose read failed, is left OUT of
        the map and noted MISSING in ``data_warnings``; a failed read also
        goes through ``_warn_swallowed``. It used to get a default
        ``cpu_avg=0.0`` entry, and one daily datapoint with a low mean was
        enough for an idle verdict.

        CLO-499: one batched ``GetMetricData`` request per
        ``_EC2_INSTANCES_PER_METRIC_DATA_CALL`` instances (plus NextToken
        pages) instead of one ``GetMetricStatistics`` call per instance. The
        queries ask for the same statistics, window and period, the hourly
        series are joined back into GetMetricStatistics-shaped datapoints,
        and ``_ec2_metrics_from_datapoints`` turns them into the verdict for
        both paths, so every ``EC2MetricsData`` field keeps its meaning.

        Fail-closed: an instance whose Average and Maximum series disagree on
        their hours, or whose query did not end ``Complete``, is MISSING. A
        failed request makes its whole chunk MISSING. If the role lacks
        ``cloudwatch:GetMetricData`` (stacks older than the Dec 2025
        template), the old per-instance ``GetMetricStatistics`` path runs for
        the instances not yet read.
        """
        metrics: Dict[str, EC2MetricsData] = {}

        if not instance_ids:
            return metrics

        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)

            chunk_size = _EC2_INSTANCES_PER_METRIC_DATA_CALL
            for chunk_start in range(0, len(instance_ids), chunk_size):
                chunk = instance_ids[chunk_start:chunk_start + chunk_size]
                try:
                    series, failed = self._fetch_ec2_cpu_batch(cloudwatch, chunk, start_time, end_time)
                except ClientError as e:
                    if self._is_access_denied(e):
                        logger.warning(
                            "cloudwatch:GetMetricData denied for EC2 metrics in %s (%s); "
                            "falling back to per-instance GetMetricStatistics",
                            self._region, e.response.get('Error', {}).get('Code', ''),
                        )
                        self._get_ec2_metrics_per_instance(
                            cloudwatch, instance_ids[chunk_start:], start_time, end_time,
                            days, idle_threshold, oversized_threshold, metrics,
                        )
                        break
                    # Counted once in DetectorErrors; every instance in the
                    # chunk is MISSING, not 0% CPU.
                    self._warn_swallowed("EC2 Metrics (batched)", "cloudwatch:GetMetricData", e)
                    for instance_id in chunk:
                        self._note_idle_verdict_missing(
                            'ec2', instance_id, f"read failed ({self._error_label(e)})",
                        )
                    continue
                except Exception as e:  # noqa: BLE001 — e.g. a botocore ReadTimeoutError
                    # A transport failure on a large response: stop here (more
                    # chunks could run past the detector cap) and note every
                    # instance not yet read as MISSING, not silently absent.
                    self._warn_swallowed("EC2 Metrics (batched)", "cloudwatch:GetMetricData", e)
                    for instance_id in instance_ids[chunk_start:]:
                        self._note_idle_verdict_missing(
                            'ec2', instance_id, f"read failed ({self._error_label(e)})",
                        )
                    break

                if failed:
                    self.swallowed_error_count += 1
                    logger.warning(
                        "EC2 CPUUtilization unusable for %d of %d instances in account=%s region=%s "
                        "(%s); their idle verdicts are MISSING, not zero",
                        len(failed), len(chunk), self._account_id, self._region,
                        ', '.join(sorted(set(failed.values()))),
                    )
                for instance_id in chunk:
                    if instance_id in failed:
                        self._note_idle_verdict_missing(
                            'ec2', instance_id, f"read failed ({failed[instance_id]})",
                        )
                        continue
                    self._ec2_metrics_from_datapoints(
                        instance_id, series.get(instance_id, []), days,
                        idle_threshold, oversized_threshold, metrics,
                    )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="EC2 Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("EC2 Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching EC2 metrics: {e}")

        return metrics

    def _fetch_ec2_cpu_batch(
        self,
        cloudwatch,
        instance_ids: List[str],
        start_time: datetime,
        end_time: datetime,
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
        """CLO-499: hourly CPUUtilization Average and Maximum for up to
        ``_EC2_INSTANCES_PER_METRIC_DATA_CALL`` instances in one
        ``GetMetricData`` request (plus NextToken pages).

        Returns ``(series, failed)``: ``series`` maps an instance to
        GetMetricStatistics-shaped datapoints (``Timestamp``, ``Average``,
        ``Maximum``) in ascending time; ``failed`` maps an instance whose
        data can't be trusted to a reason. Query Ids are positional
        (``cavg_3``) because Ids must match ``^[a-z][a-zA-Z0-9_]*$``. A
        ``ClientError`` propagates to the caller.
        """
        queries = []
        for idx, instance_id in enumerate(instance_ids):
            dimensions = [{'Name': 'InstanceId', 'Value': instance_id}]
            for prefix, stat in _EC2_CPU_METRIC_QUERIES:
                queries.append({
                    'Id': f'{prefix}_{idx}',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/EC2',
                            'MetricName': 'CPUUtilization',
                            'Dimensions': dimensions,
                        },
                        'Period': 3600,  # hourly, as GetMetricStatistics used
                        'Stat': stat,
                    },
                    'ReturnData': True,
                })

        points: Dict[str, Dict[Any, float]] = {q['Id']: {} for q in queries}
        status: Dict[str, str] = {}
        next_token: Optional[str] = None
        while True:
            request: Dict[str, Any] = {
                'MetricDataQueries': queries,
                'StartTime': start_time,
                'EndTime': end_time,
                'ScanBy': 'TimestampAscending',
            }
            if next_token:
                request['NextToken'] = next_token
            response = cloudwatch.get_metric_data(**request)
            next_token = response.get('NextToken')
            for result in response.get('MetricDataResults', []):
                query_id = result.get('Id')
                if query_id not in points:
                    continue
                for ts, value in zip(result.get('Timestamps', []), result.get('Values', [])):
                    points[query_id][ts] = value
                code = result.get('StatusCode', 'Complete')
                # A failed query stays failed. PartialData only counts on
                # the last page: before it, it just means "see NextToken".
                if code in ('InternalError', 'Forbidden') or (code != 'Complete' and not next_token):
                    status.setdefault(query_id, code)
            if not next_token:
                break

        series: Dict[str, List[Dict[str, Any]]] = {}
        failed: Dict[str, str] = {}
        for idx, instance_id in enumerate(instance_ids):
            avg_id, max_id = (f'{prefix}_{idx}' for prefix, _ in _EC2_CPU_METRIC_QUERIES)
            bad = sorted({status.get(i, 'Complete') for i in (avg_id, max_id)} - {'Complete'})
            if bad:
                failed[instance_id] = f"GetMetricData status {'/'.join(bad)}"
                continue
            averages, maximums = points[avg_id], points[max_id]
            if set(averages) != set(maximums):
                # summarize_hourly_cpu reads a missing Maximum as 0, which
                # would weaken the peak guard: MISSING instead.
                failed[instance_id] = "GetMetricData Average/Maximum hours differ"
                continue
            series[instance_id] = [
                {'Timestamp': ts, 'Average': averages[ts], 'Maximum': maximums[ts]}
                for ts in sorted(averages)
            ]
        return series, failed

    def _get_ec2_metrics_per_instance(
        self,
        cloudwatch,
        instance_ids: List[str],
        start_time: datetime,
        end_time: datetime,
        days: int,
        idle_threshold: float,
        oversized_threshold: float,
        metrics: Dict[str, EC2MetricsData],
    ) -> None:
        """Pre-CLO-499 path: one ``GetMetricStatistics`` call per instance.

        Kept only as the fallback for roles without
        ``cloudwatch:GetMetricData``. Fills ``metrics`` in place."""
        for instance_id in instance_ids:
            try:
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,  # hourly: 336 datapoints for 14 days, one call
                    Statistics=['Average', 'Maximum'],
                )
                self._ec2_metrics_from_datapoints(
                    instance_id, response.get('Datapoints', []), days,
                    idle_threshold, oversized_threshold, metrics,
                )
            except ClientError as e:
                # Counted in DetectorErrors; AccessDenied becomes
                # permission_missing (CLO-368).
                self._warn_swallowed(
                    "EC2 Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e,
                )
                self._note_idle_verdict_missing(
                    'ec2', instance_id, f"read failed ({self._error_label(e)})",
                )

    def _ec2_metrics_from_datapoints(
        self,
        instance_id: str,
        datapoints: List[Dict[str, Any]],
        days: int,
        idle_threshold: float,
        oversized_threshold: float,
        metrics: Dict[str, EC2MetricsData],
    ) -> None:
        """The CLO-493 verdict from hourly Average+Maximum datapoints, shared
        by the batched and per-instance paths (CLO-499)."""
        if not has_min_coverage(len(datapoints), days, 3600):
            # No or sparse data: MISSING, not 0% CPU. A new
            # instance (younger than the window) gets no note.
            if is_as_old_as_window(getattr(self, '_ec2_launch_times', {}).get(instance_id), days):
                self._note_idle_verdict_missing(
                    'ec2', instance_id,
                    "no CPUUtilization datapoints" if not datapoints
                    else "CPUUtilization under 75% coverage",
                )
            return
        cpu = summarize_hourly_cpu(datapoints)

        metrics[instance_id] = EC2MetricsData(
            instance_id=instance_id,
            cpu_avg=round(cpu.avg_cpu, 2),
            cpu_max=round(cpu.max_cpu, 2),
            period_days=days,
            is_idle=ec2_cpu_is_idle(
                cpu.avg_cpu, cpu.p95_cpu, cpu.p95_max_cpu, cpu.max_cpu, idle_threshold,
            ),
            is_oversized=cpu.avg_cpu < oversized_threshold and cpu.avg_cpu >= idle_threshold,
            cpu_datapoints=cpu.datapoints,
            cpu_p95=round(cpu.p95_cpu, 2),
            cpu_p95_max=round(cpu.p95_max_cpu, 2),
        )
    
    # =========================================================================
    # EBS / Storage
    # =========================================================================
    
    async def get_ebs_volumes(self) -> List[EBSVolumeData]:
        """Get all EBS volumes in the region (CLO-527 item 5: DescribeVolumes
        pages, bounded by EBS_VOLUMES_MAX_PAGES).

        Sets ``self.ebs_volumes_complete``: True only when every page was
        read. A capped or failed read leaves it False, so a verdict that
        needs the WHOLE list (orphaned_ebs_snapshot: "its volume no longer
        exists") is withheld instead of reading an unseen volume as deleted.
        """
        volumes = []
        self.ebs_volumes_complete = False
        try:
            ec2 = self._get_client('ec2')
            next_token: Optional[str] = None
            for _ in range(EBS_VOLUMES_MAX_PAGES):
                kwargs: Dict[str, Any] = {'MaxResults': EBS_VOLUMES_PAGE_SIZE}
                if next_token:
                    kwargs['NextToken'] = next_token
                response = ec2.describe_volumes(**kwargs)
                volumes.extend(self._ebs_volume_from(v) for v in response.get('Volumes', []))
                next_token = response.get('NextToken')
                if not next_token:
                    self.ebs_volumes_complete = True
                    break
            else:
                self._warn_once(
                    f"ebs: more than {len(volumes)} EBS volumes in {self._region}; DescribeVolumes "
                    f"stopped at {EBS_VOLUMES_MAX_PAGES} pages. Volumes past that are not judged and "
                    "orphaned_ebs_snapshot is withheld for the region: MISSING, not zero"
                )
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="EBS Volumes", permission="ec2:DescribeVolumes", error=e,
                )
                self._warn_access_denied("EBS Volumes", "ec2:DescribeVolumes", e)
                raise
            logger.error(f"Error fetching EBS volumes: {e}")
            self._warn_once(
                f"ebs: DescribeVolumes failed in {self._region} "
                f"({e.response.get('Error', {}).get('Code', 'ClientError')}); EBS volume checks and "
                "orphaned_ebs_snapshot are MISSING for the region, not zero"
            )

        return volumes

    def _warn_once(self, message: str) -> None:
        """Append a scan warning unless this provider already holds it: several
        detectors read the same list (get_ebs_volumes from storage, compute
        and security), and a customer should see each gap once."""
        if message not in self.data_warnings:
            self.data_warnings.append(message)

    def _ebs_volume_from(self, volume: Dict[str, Any]) -> EBSVolumeData:
        return EBSVolumeData(
            volume_id=volume.get('VolumeId', ''),
            volume_type=volume.get('VolumeType', ''),
            size_gb=volume.get('Size', 0),
            state=volume.get('State', ''),
            region=self._region,
            iops=volume.get('Iops'),
            throughput=volume.get('Throughput'),
            create_time=volume.get('CreateTime'),
            attachments=volume.get('Attachments', []),
            encrypted=volume.get('Encrypted', False),
            tags=self._tags_to_dict(volume.get('Tags', [])),
        )

    async def get_ebs_iops_peaks(
        self,
        volume_ids: List[str],
        days: int = 14,
        deadline: Optional[float] = None,
    ) -> Dict[str, EBSIopsPeakData]:
        """CLO-516: peak one-minute IOPS per volume over the last ``days``.

        Batched ``GetMetricData``, one page per request (see
        ``_ebs_volumes_per_metric_data_call``), in the caller's order (the
        detector puts the most expensive volumes first, so a spent budget
        drops the cheapest).
        A volume whose series is unreadable or under 75% of the window's
        minutes is left out and noted MISSING in ``data_warnings``; after an
        AccessDenied no further batch is attempted."""
        result: Dict[str, EBSIopsPeakData] = {}
        if not volume_ids:
            return result
        reasons: Dict[str, str] = {}
        end_time = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        start_time = end_time - timedelta(days=days)
        expected = int(days * 86400 / _EBS_IOPS_PERIOD_SECONDS)
        cloudwatch = self._get_client('cloudwatch')
        denied = False
        per_call = _ebs_volumes_per_metric_data_call(days)
        for offset in range(0, len(volume_ids), per_call):
            batch = volume_ids[offset:offset + per_call]
            if denied:
                for volume_id in batch:
                    reasons[volume_id] = 'read failed (AccessDenied)'
                continue
            if deadline is not None and time.monotonic() > deadline:
                for volume_id in batch:
                    reasons[volume_id] = 'time budget spent'
                continue
            try:
                values, failed = self._fetch_ebs_iops_batch(cloudwatch, batch, start_time, end_time)
            except Exception as e:  # noqa: BLE001 - every failure is MISSING, never zero
                if self._is_access_denied(e):
                    denied = True
                    self._record_permission_error(
                        resource="EBS IOPS metrics", permission="cloudwatch:GetMetricData", error=e,
                    )
                    self._warn_access_denied("EBS IOPS metrics", "cloudwatch:GetMetricData", e)
                else:
                    self._warn_swallowed("EBS IOPS metrics", "cloudwatch:GetMetricData", e)
                code = ''
                if isinstance(e, ClientError):
                    code = e.response.get('Error', {}).get('Code', '')
                label = f"read failed ({code or e.__class__.__name__})"
                for volume_id in batch:
                    reasons[volume_id] = label
                continue
            for volume_id in batch:
                if volume_id in failed:
                    reasons[volume_id] = failed[volume_id]
                    continue
                series = values.get(volume_id, [])
                if len(series) < expected * EBS_IOPS_MIN_COVERAGE:
                    reasons[volume_id] = (
                        'no datapoints' if not series else 'under 75% coverage'
                    )
                    continue
                result[volume_id] = EBSIopsPeakData(
                    volume_id=volume_id,
                    peak_iops=max(series),
                    datapoints=len(series),
                    expected_datapoints=expected,
                    window_days=days,
                    period_seconds=_EBS_IOPS_PERIOD_SECONDS,
                )
        for volume_id, reason in reasons.items():
            self._note_idle_verdict_missing(
                'ebs', volume_id, reason,
                verdict='over-provisioned IOPS', evidence='one-minute IOPS metrics',
            )
        return result

    def _fetch_ebs_iops_batch(
        self,
        cloudwatch,
        volume_ids: List[str],
        start_time: datetime,
        end_time: datetime,
    ) -> Tuple[Dict[str, List[float]], Dict[str, str]]:
        """One ``GetMetricData`` request (plus NextToken pages) for up to
        ``_ebs_volumes_per_metric_data_call(days)`` volumes. Returns
        ``(values, failed)``: per-minute IOPS per volume, and the volumes
        whose query did not complete. A ``ClientError`` propagates."""
        queries: List[Dict[str, Any]] = []
        for idx, volume_id in enumerate(volume_ids):
            dimensions = [{'Name': 'VolumeId', 'Value': volume_id}]
            for prefix, metric in (('r', 'VolumeReadOps'), ('w', 'VolumeWriteOps')):
                queries.append({
                    'Id': f'{prefix}_{idx}',
                    'MetricStat': {
                        'Metric': {'Namespace': 'AWS/EBS', 'MetricName': metric, 'Dimensions': dimensions},
                        'Period': _EBS_IOPS_PERIOD_SECONDS,
                        'Stat': 'Sum',
                    },
                    'ReturnData': False,
                })
            queries.append({
                'Id': f'iops_{idx}',
                # Operations per second for each minute.
                'Expression': f'(r_{idx} + w_{idx}) / PERIOD(r_{idx})',
                'ReturnData': True,
            })
        values: Dict[str, List[float]] = {}
        status: Dict[str, str] = {}
        by_query = {f'iops_{idx}': volume_id for idx, volume_id in enumerate(volume_ids)}
        next_token: Optional[str] = None
        while True:
            request: Dict[str, Any] = {
                'MetricDataQueries': queries,
                'StartTime': start_time,
                'EndTime': end_time,
                'ScanBy': 'TimestampAscending',
            }
            if next_token:
                request['NextToken'] = next_token
            response = cloudwatch.get_metric_data(**request)
            next_token = response.get('NextToken')
            for res in response.get('MetricDataResults', []):
                volume_id = by_query.get(res.get('Id'))
                if volume_id is None:
                    continue
                values.setdefault(volume_id, []).extend(
                    float(v) for v in res.get('Values', []) if v is not None
                )
                code = res.get('StatusCode', 'Complete')
                if code in ('InternalError', 'Forbidden') or (code != 'Complete' and not next_token):
                    status.setdefault(volume_id, code)
            if not next_token:
                break
        failed = {v: f"GetMetricData status {code}" for v, code in status.items()}
        return values, failed

    async def get_ebs_snapshots(
        self,
        owner_ids: Optional[List[str]] = None,
        age_threshold_days: int = 90,
    ) -> List[EBSSnapshotData]:
        """Get EBS snapshots in the region."""
        snapshots = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=age_threshold_days)
        
        try:
            ec2 = self._get_client('ec2')
            filters = []
            if owner_ids is None:
                owner_ids = ['self']
            
            response = ec2.describe_snapshots(OwnerIds=owner_ids)
            
            for snapshot in response.get('Snapshots', []):
                start_time = snapshot.get('StartTime')
                age_days = 0
                if start_time:
                    age_days = (datetime.now(timezone.utc) - start_time).days
                
                # Only include snapshots older than threshold
                if age_days >= age_threshold_days:
                    snapshots.append(EBSSnapshotData(
                        snapshot_id=snapshot.get('SnapshotId', ''),
                        volume_id=snapshot.get('VolumeId'),
                        volume_size_gb=snapshot.get('VolumeSize', 0),
                        state=snapshot.get('State', ''),
                        region=self._region,
                        start_time=start_time,
                        description=snapshot.get('Description'),
                        encrypted=snapshot.get('Encrypted', False),
                        tags=self._tags_to_dict(snapshot.get('Tags', [])),
                        age_days=age_days,
                    ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="EBS Snapshots", permission="ec2:DescribeSnapshots", error=e,
                )
                self._warn_access_denied("EBS Snapshots", "ec2:DescribeSnapshots", e)
                raise
            logger.error(f"Error fetching EBS snapshots: {e}")
        
        return snapshots
    
    async def get_elastic_ips(self) -> List[ElasticIPData]:
        """Get all Elastic IPs in the region.

        Sets ``self.elastic_ips_complete`` (CLO-535 item 1): DescribeAddresses
        has no pagination, so the list is whole exactly when the call
        succeeded. A failed read leaves it False and orphaned_dns_record
        withholds its A-record verdicts.
        """
        eips = []
        self.elastic_ips_complete = False
        try:
            ec2 = self._get_client('ec2')
            response = ec2.describe_addresses()
            
            for address in response.get('Addresses', []):
                instance_id = address.get('InstanceId')
                network_interface_id = address.get('NetworkInterfaceId')
                
                eips.append(ElasticIPData(
                    allocation_id=address.get('AllocationId', ''),
                    public_ip=address.get('PublicIp', ''),
                    region=self._region,
                    instance_id=instance_id,
                    network_interface_id=network_interface_id,
                    is_attached=bool(instance_id or network_interface_id),
                    domain=address.get('Domain', 'vpc'),
                    tags=self._tags_to_dict(address.get('Tags', [])),
                ))
            self.elastic_ips_complete = True
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Elastic Ips", permission="ec2:DescribeAddresses", error=e,
                )
                self._warn_access_denied("Elastic Ips", "ec2:DescribeAddresses", e)
                raise
            logger.error(f"Error fetching Elastic IPs: {e}")
        
        return eips
    
    # =========================================================================
    # RDS / Databases
    # =========================================================================
    
    async def get_rds_instances(self) -> List[RDSInstanceData]:
        """Get all RDS instances in the region (CLO-535 item 3: every
        DescribeDBInstances page, bounded by RDS_INSTANCES_MAX_PAGES).

        The first call has no parameters and later ones add only ``Marker``
        (what botocore's paginator sends), at the API's default 100 records
        per page. Sets ``self.rds_instances_complete``: True only when every
        page was read. A capped or failed read leaves it False; a verdict
        that needs the WHOLE list must be withheld then (none reads it
        today: every RDS-list verdict is per-instance evidence).
        """
        instances = []
        self.rds_instances_complete = False
        rows: List[Dict[str, Any]] = []
        try:
            rds = self._get_client('rds')
            kwargs: Dict[str, Any] = {}
            for _ in range(RDS_INSTANCES_MAX_PAGES):
                response = rds.describe_db_instances(**kwargs)
                rows.extend(response.get('DBInstances', []) or [])
                marker = response.get('Marker')
                if not marker:
                    self.rds_instances_complete = True
                    break
                kwargs = {'Marker': marker}
            else:
                self._warn_once(
                    f"rds: more than {len(rows)} RDS instances in {self._region}; DescribeDBInstances "
                    f"stopped at {RDS_INSTANCES_MAX_PAGES} pages. Instances past that are not judged: "
                    "MISSING, not zero"
                )
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="RDS Instances", permission="rds:DescribeDbInstances", error=e,
                )
                self._warn_access_denied("RDS Instances", "rds:DescribeDbInstances", e)
                raise
            # A later page's failure keeps the pages already read (each
            # verdict on them is per-instance evidence); the list stays
            # incomplete.
            logger.error(f"Error fetching RDS instances: {e}")

        for db in rows:
            instances.append(RDSInstanceData(
                db_instance_id=db.get('DBInstanceIdentifier', ''),
                db_instance_class=db.get('DBInstanceClass', ''),
                engine=db.get('Engine', ''),
                engine_version=db.get('EngineVersion', ''),
                status=db.get('DBInstanceStatus', ''),
                region=self._region,
                multi_az=db.get('MultiAZ', False),
                storage_type=db.get('StorageType', 'gp2'),
                allocated_storage_gb=db.get('AllocatedStorage', 0),
                iops=db.get('Iops'),
                publicly_accessible=db.get('PubliclyAccessible', False),
                storage_encrypted=db.get('StorageEncrypted', False),
                deletion_protection=db.get('DeletionProtection', False),
                endpoint=db.get('Endpoint', {}).get('Address'),
                tags=self._tags_to_dict(db.get('TagList', [])),
                db_instance_arn=db.get('DBInstanceArn', ''),
                backup_retention_period=db.get('BackupRetentionPeriod', 0),
                instance_create_time=db.get('InstanceCreateTime'),
            ))
        return instances
    
    async def get_rds_metrics(
        self,
        db_instance_ids: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
        include_cpu: bool = False,
    ) -> Dict[str, RDSMetricsData]:
        """Get CloudWatch metrics for RDS instances.

        CLO-457: DBInstanceIdentifier is a name. With an instance's creation
        time in ``create_times``, its read starts at the creation time and
        drops datapoints from before it (see metric_window), so an instance
        recreated under a reused identifier is judged on its own days only.

        CLO-485: with ``include_cpu``, the instance's hourly CPUUtilization
        (Average and Maximum) is read too and fills ``cpu_avg``, ``cpu_max``
        and ``cpu_datapoints``. Before this, nothing ever read CPU here, so
        the Aurora sizing detectors' CPU gates compared a constant 0.0. It is
        opt-in because ``idle_rds`` gates on connections only and runs over
        every instance."""
        metrics = {}
        
        if not db_instance_ids:
            return metrics
        
        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            
            for db_id in db_instance_ids:
                created = (create_times or {}).get(db_id)
                start_time = metric_start_time(end_time, days, created)
                try:
                    # Get DatabaseConnections metric
                    response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='DatabaseConnections',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average', 'Maximum'],
                    )
                    
                    datapoints = drop_pre_creation_datapoints(
                        response.get('Datapoints', []), created, 86400,
                    )
                    if datapoints:
                        conn_avg = sum(dp['Average'] for dp in datapoints) / len(datapoints)
                        conn_max = max(dp['Maximum'] for dp in datapoints)
                        
                        metrics[db_id] = RDSMetricsData(
                            db_instance_id=db_id,
                            connections_avg=round(conn_avg, 2),
                            connections_max=round(conn_max, 2),
                            period_days=days,
                            is_idle=conn_avg == 0,
                            connections_datapoints=len(datapoints),
                        )
                    else:
                        metrics[db_id] = RDSMetricsData(
                            db_instance_id=db_id,
                            period_days=days,
                            connections_datapoints=0,
                        )

                    if include_cpu:
                        # CLO-485: hourly, on the instance's own dimension,
                        # like DocumentDB/Neptune's CPU reads (cpu_sizing).
                        # 30 days of hours is 720 datapoints, under the
                        # 1,440-per-call limit.
                        cpu_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/RDS',
                            MetricName='CPUUtilization',
                            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,
                            Statistics=['Average', 'Maximum'],
                        )
                        cpu = summarize_hourly_cpu(drop_pre_creation_datapoints(
                            cpu_response.get('Datapoints', []), created, 3600,
                        ))
                        entry = metrics[db_id]
                        entry.cpu_avg = round(cpu.avg_cpu, 2)
                        entry.cpu_max = round(cpu.max_cpu, 2)
                        entry.cpu_datapoints = cpu.datapoints
                except ClientError as e:
                    if self._is_access_denied(e):
                        self._record_permission_error(
                            resource="RDS Metrics (per-resource)", permission="cloudwatch:GetMetricStatistics", error=e,
                        )
                        self._warn_access_denied("RDS Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e)
                    # CLO-506: counted (DetectorErrors), one WARNING per
                    # region, not one line per instance.
                    self._warn_swallowed("RDS metrics (per-resource)", "cloudwatch:GetMetricStatistics", e)
                    # CLO-485: when CPU was asked for and the read failed, say
                    # so (0 datapoints), so a CPU gate vetoes rather than
                    # reading the default 0.0 as an idle CPU.
                    metrics[db_id] = RDSMetricsData(
                        db_instance_id=db_id, period_days=days,
                        cpu_datapoints=0 if include_cpu else None,
                    )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="RDS Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("RDS Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching RDS metrics: {e}")
        
        return metrics
    
    async def get_rds_snapshots(
        self,
        snapshot_type: str = "manual",
        age_threshold_days: int = 90,
    ) -> List[RDSSnapshotData]:
        """Get RDS snapshots in the region."""
        snapshots = []
        
        try:
            rds = self._get_client('rds')
            response = rds.describe_db_snapshots(SnapshotType=snapshot_type)
            
            for snapshot in response.get('DBSnapshots', []):
                create_time = snapshot.get('SnapshotCreateTime')
                age_days = 0
                if create_time:
                    age_days = (datetime.now(timezone.utc) - create_time).days
                
                if age_days >= age_threshold_days:
                    snapshots.append(RDSSnapshotData(
                        snapshot_id=snapshot.get('DBSnapshotIdentifier', ''),
                        db_instance_id=snapshot.get('DBInstanceIdentifier'),
                        snapshot_type=snapshot.get('SnapshotType', 'manual'),
                        status=snapshot.get('Status', ''),
                        region=self._region,
                        allocated_storage_gb=snapshot.get('AllocatedStorage', 0),
                        create_time=create_time,
                        encrypted=snapshot.get('Encrypted', False),
                        engine=snapshot.get('Engine'),
                        age_days=age_days,
                    ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="RDS Snapshots", permission="rds:DescribeDbSnapshots", error=e,
                )
                self._warn_access_denied("RDS Snapshots", "rds:DescribeDbSnapshots", e)
                raise
            logger.error(f"Error fetching RDS snapshots: {e}")
        
        return snapshots
    
    # =========================================================================
    # Lambda / Serverless
    # =========================================================================
    
    async def get_lambda_functions(self) -> List[LambdaFunctionData]:
        """Get all Lambda functions in the region."""
        functions = []
        try:
            lambda_client = self._get_client('lambda')
            all_functions = self._paginate(lambda_client, 'list_functions', 'Functions')
            
            for func in all_functions:
                functions.append(LambdaFunctionData(
                    function_name=func.get('FunctionName', ''),
                    function_arn=func.get('FunctionArn', ''),
                    runtime=func.get('Runtime', 'unknown'),
                    memory_mb=func.get('MemorySize', 128),
                    timeout_seconds=func.get('Timeout', 3),
                    region=self._region,
                    code_size_bytes=func.get('CodeSize', 0),
                    # CLO-528: botocore types LastModified as a STRING
                    # ('2026-09-30T12:34:56.000+0000'), not a datetime.
                    last_modified=parse_lambda_timestamp(func.get('LastModified')),
                    handler=func.get('Handler'),
                    description=func.get('Description'),
                    architecture=func.get('Architectures', ['x86_64'])[0],
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lambda Functions", permission="lambda:ListFunctions", error=e,
                )
                self._warn_access_denied("Lambda Functions", "lambda:ListFunctions", e)
                raise
            logger.error(f"Error fetching Lambda functions: {e}")
        
        return functions
    
    async def get_lambda_metrics(
        self,
        function_names: List[str],
        days: int = 30,
    ) -> Dict[str, LambdaMetricsData]:
        """Get CloudWatch metrics for Lambda functions.

        CLO-479: one batched ``GetMetricData`` call per
        ``_LAMBDA_FUNCTIONS_PER_METRIC_DATA_CALL`` functions (plus NextToken
        pages) instead of two ``GetMetricStatistics`` calls per function.
        The queries ask for the same statistics over the same window and
        period as before (Invocations Sum, Duration Average and Maximum,
        daily buckets), and the aggregation below is the same, so every
        ``LambdaMetricsData`` field keeps its meaning.

        The boto3 call is made directly, like every other provider method:
        since CLO-191 the detector runner executes each detector coroutine
        on its own worker thread (``_run_detector_with_timeout``), so it no
        longer blocks the shared scan loop, and CLO-185 removed the last
        per-provider executor wrapper on purpose.

        A function whose metrics could not be fetched (a failed batch, a
        failed query status, a failed fallback call, or an exception that
        stops the fetch) is left OUT of the returned map: its metrics are
        MISSING, not zero. Before CLO-479 it got an empty
        ``LambdaMetricsData``, whose ``invocations_total=0`` the detector
        read as a HIGH-confidence ``unused_lambda``. ``_detect_lambda_waste``
        already skips every metric-based check for an absent entry. The
        functions left out are logged once at WARNING, counted in
        ``swallowed_error_count`` and noted in ``data_warnings``.

        If the role lacks ``cloudwatch:GetMetricData`` (stacks older than
        the Dec 2025 template), the old per-function ``GetMetricStatistics``
        path runs instead.
        """
        metrics: Dict[str, LambdaMetricsData] = {}
        failure_reasons: Dict[str, int] = {}
        
        if not function_names:
            return metrics
        
        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            chunk_size = _LAMBDA_FUNCTIONS_PER_METRIC_DATA_CALL
            for chunk_start in range(0, len(function_names), chunk_size):
                chunk = function_names[chunk_start:chunk_start + chunk_size]
                try:
                    self._fetch_lambda_metrics_batch(
                        cloudwatch, chunk, start_time, end_time, days, metrics, failure_reasons,
                    )
                except ClientError as e:
                    if self._is_access_denied(e):
                        logger.warning(
                            "cloudwatch:GetMetricData denied for Lambda metrics in %s (%s); "
                            "falling back to per-function GetMetricStatistics",
                            self._region, e.response.get('Error', {}).get('Code', ''),
                        )
                        remaining = function_names[chunk_start:]
                        self._get_lambda_metrics_per_function(
                            cloudwatch, remaining, start_time, end_time, days, metrics,
                            failure_reasons,
                        )
                        break
                    label = f"GetMetricData:{e.response.get('Error', {}).get('Code', '') or 'ClientError'}"
                    failure_reasons[label] = failure_reasons.get(label, 0) + len(chunk)
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lambda Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Lambda Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching Lambda metrics: {e}")
            failure_reasons[e.__class__.__name__] = failure_reasons.get(e.__class__.__name__, 0) + 1

        self._note_missing_lambda_metrics(function_names, metrics, failure_reasons)
        return metrics

    @staticmethod
    def _error_label(error: Exception) -> str:
        """``ClientError:Throttling``-style label, as ``_warn_swallowed`` logs it."""
        if isinstance(error, ClientError):
            code = error.response.get('Error', {}).get('Code', '')
            if code:
                return f"{error.__class__.__name__}:{code}"
        return error.__class__.__name__

    def _note_missing_lambda_metrics(
        self,
        function_names: List[str],
        metrics: Dict[str, LambdaMetricsData],
        failure_reasons: Dict[str, int],
    ) -> None:
        """CLO-479: one WARNING, one ``DetectorErrors`` count and one
        ``data_warnings`` note for every function left out of ``metrics``."""
        missing = [name for name in function_names if name not in metrics]
        if not missing:
            return
        reasons = ', '.join(f"{label} x{count}" for label, count in sorted(failure_reasons.items())) or 'unknown'
        logger.warning(
            "Lambda metrics unavailable for %d of %d functions in account=%s region=%s (%s); "
            "their invocation- and duration-based findings are MISSING from this scan, not zero",
            len(missing), len(function_names), self._account_id, self._region, reasons,
        )
        self.swallowed_error_count += 1
        self.data_warnings.append(
            f"lambda: CloudWatch metrics unavailable for {len(missing)} of {len(function_names)} "
            f"functions in {self._region}; their unused/over-provisioned/timeout/ARM64 findings "
            f"are MISSING from this scan, not zero"
        )

    def _fetch_lambda_metrics_batch(
        self,
        cloudwatch,
        function_names: List[str],
        start_time: datetime,
        end_time: datetime,
        days: int,
        metrics: Dict[str, LambdaMetricsData],
        failure_reasons: Dict[str, int],
    ) -> None:
        """Fill ``metrics`` for up to ``_LAMBDA_FUNCTIONS_PER_METRIC_DATA_CALL``
        functions with one ``GetMetricData`` request (plus NextToken pages).

        Query Ids must match ``^[a-z][a-zA-Z0-9_]*$`` and function names can
        contain hyphens, so Ids are positional (``inv_3``) and mapped back.
        A ``ClientError`` propagates to the caller, which decides between the
        empty-entry path and the GetMetricStatistics fallback.
        """
        queries = []
        for idx, func_name in enumerate(function_names):
            dimensions = [{'Name': 'FunctionName', 'Value': func_name}]
            for prefix, metric_name, stat in _LAMBDA_METRIC_QUERIES:
                queries.append({
                    'Id': f'{prefix}_{idx}',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/Lambda',
                            'MetricName': metric_name,
                            'Dimensions': dimensions,
                        },
                        'Period': 86400,  # Daily buckets, as GetMetricStatistics used
                        'Stat': stat,
                    },
                    'ReturnData': True,
                })

        values: Dict[str, List[float]] = {q['Id']: [] for q in queries}
        failed_ids: Dict[str, str] = {}
        next_token: Optional[str] = None
        while True:
            request: Dict[str, Any] = {
                'MetricDataQueries': queries,
                'StartTime': start_time,
                'EndTime': end_time,
                'ScanBy': 'TimestampAscending',
            }
            if next_token:
                request['NextToken'] = next_token
            response = cloudwatch.get_metric_data(**request)
            for result in response.get('MetricDataResults', []):
                query_id = result.get('Id')
                if query_id not in values:
                    continue
                values[query_id].extend(result.get('Values', []))
                status = result.get('StatusCode')
                if status in ('InternalError', 'Forbidden'):
                    failed_ids[query_id] = status
            next_token = response.get('NextToken')
            if not next_token:
                break

        for idx, func_name in enumerate(function_names):
            ids = [f'{prefix}_{idx}' for prefix, _, _ in _LAMBDA_METRIC_QUERIES]
            failed = sorted({failed_ids[i] for i in ids if i in failed_ids})
            if failed:
                # Left out of ``metrics``: MISSING, not zero (see get_lambda_metrics).
                label = f"GetMetricData status {'/'.join(failed)}"
                failure_reasons[label] = failure_reasons.get(label, 0) + 1
                continue

            inv_values, avg_values, max_values = (values[i] for i in ids)
            total_invocations = sum(inv_values)
            # Same aggregation as the GetMetricStatistics path: the mean of
            # the daily Averages and the max of the daily Maximums.
            duration_avg = 0.0
            duration_max = 0.0
            if avg_values:
                duration_avg = sum(avg_values) / len(avg_values)
            if max_values:
                duration_max = max(max_values)

            metrics[func_name] = LambdaMetricsData(
                function_name=func_name,
                invocations_total=int(total_invocations),
                duration_avg_ms=round(duration_avg, 2),
                duration_max_ms=round(duration_max, 2),
                period_days=days,
                is_unused=total_invocations == 0,
            )

    def _get_lambda_metrics_per_function(
        self,
        cloudwatch,
        function_names: List[str],
        start_time: datetime,
        end_time: datetime,
        days: int,
        metrics: Dict[str, LambdaMetricsData],
        failure_reasons: Dict[str, int],
    ) -> None:
        """Pre-CLO-479 path: two ``GetMetricStatistics`` calls per function.

        Kept only as the fallback for roles without
        ``cloudwatch:GetMetricData``. Fills ``metrics`` in place so a
        non-``ClientError`` exception still leaves earlier functions' results
        for the caller, as the old inline loop did. A function whose calls
        fail is left out of ``metrics`` (MISSING, not zero) rather than
        given an empty entry.
        """
        for func_name in function_names:
            try:
                # Get Invocations metric
                response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Invocations',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # Daily buckets, summed below
                    Statistics=['Sum'],
                )
                
                datapoints = response.get('Datapoints', [])
                total_invocations = sum(dp.get('Sum', 0) for dp in datapoints)
                
                # Get Duration metric
                dur_response = cloudwatch.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Duration',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # Daily buckets, aggregated below
                    Statistics=['Average', 'Maximum'],
                )
                
                dur_datapoints = dur_response.get('Datapoints', [])
                duration_avg = 0.0
                duration_max = 0.0
                if dur_datapoints:
                    duration_avg = sum(dp.get('Average', 0) for dp in dur_datapoints) / len(dur_datapoints)
                    duration_max = max(dp.get('Maximum', 0) for dp in dur_datapoints)
                
                metrics[func_name] = LambdaMetricsData(
                    function_name=func_name,
                    invocations_total=int(total_invocations),
                    duration_avg_ms=round(duration_avg, 2),
                    duration_max_ms=round(duration_max, 2),
                    period_days=days,
                    is_unused=total_invocations == 0,
                )
            except ClientError as e:
                if self._is_access_denied(e):
                    self._record_permission_error(
                        resource="Lambda Metrics (per-resource)", permission="cloudwatch:GetMetricStatistics", error=e,
                    )
                    self._warn_access_denied("Lambda Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e)
                label = f"GetMetricStatistics:{e.response.get('Error', {}).get('Code', '') or 'ClientError'}"
                failure_reasons[label] = failure_reasons.get(label, 0) + 1
    
    async def get_lambda_provisioned_concurrency(
        self, function_name: str
    ) -> List[LambdaProvisionedConcurrencyData]:
        """Get Provisioned Concurrency configs from live AWS API."""
        configs = []
        try:
            lambda_client = self._get_client('lambda')
            configs = self._list_pc_configs(lambda_client, function_name)
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lambda Provisioned Concurrency", permission="lambda:ListProvisionedConcurrencyConfigs", error=e,
                )
                self._warn_access_denied("Lambda Provisioned Concurrency", "lambda:ListProvisionedConcurrencyConfigs", e)
                raise
            logger.warning(f"Error fetching PC configs for {function_name}: {e}")
        
        return configs

    async def get_lambda_provisioned_concurrency_bulk(
        self, function_names: List[str]
    ) -> Dict[str, List[LambdaProvisionedConcurrencyData]]:
        """PC configs for many functions (CLO-481). See the comment above
        ``_LAMBDA_PC_LOOKUP_WORKERS`` for why it prunes and then runs a
        rate-capped pool.

        Every function in the returned map was either looked up, or ruled
        out because the ALL-versions walk saw only its $LATEST entry. A
        function whose lookup failed is left OUT of the map: its PC is
        MISSING, not "none", and the detector skips its idle-PC check. The
        functions left out get one WARNING, one ``swallowed_error_count``
        and one ``data_warnings`` note, as ``get_lambda_metrics`` does
        (CLO-479). An AccessDenied is recorded once as ``permission_missing``
        and stops further lookups: the rest would be denied too.
        """
        names = list(dict.fromkeys(function_names))
        result: Dict[str, List[LambdaProvisionedConcurrencyData]] = {}
        failure_reasons: Dict[str, int] = {}
        if not names:
            return result

        limiter = _RateLimiter(_LAMBDA_PC_LOOKUP_MAX_RPS)
        try:
            lambda_client = self._get_client('lambda')
            to_look_up = self._lambda_functions_that_may_have_pc(lambda_client, names, limiter)
            looked_up = set(to_look_up)
            for name in names:
                if name not in looked_up:
                    result[name] = []
            if to_look_up:
                cloudwatch = self._get_client('cloudwatch')
                self._look_up_pc_configs(
                    lambda_client, cloudwatch, to_look_up, limiter, result, failure_reasons,
                )
        except Exception as e:
            label = e.__class__.__name__
            failure_reasons[label] = failure_reasons.get(label, 0) + 1
            logger.error(f"Error fetching Lambda provisioned concurrency: {e}")

        self._note_missing_lambda_pc(names, result, failure_reasons)
        return result

    def _lambda_functions_that_may_have_pc(
        self, lambda_client, names: List[str], limiter: _RateLimiter,
    ) -> List[str]:
        """The functions in ``names`` that need a PC lookup, in order.

        Walks ListFunctions(FunctionVersion=ALL). A function is ruled out
        only if the walk saw its $LATEST entry and no published version.
        A function the walk never saw is kept. If the walk fails or passes
        its page budget, every function is kept."""
        page_budget = max(2, math.ceil(len(names) / _LAMBDA_VERSION_WALK_FUNCTIONS_PER_PAGE_BUDGET))
        seen_latest: set = set()
        versioned: set = set()
        kwargs: Dict[str, Any] = {'FunctionVersion': 'ALL'}
        pages = 0
        try:
            while True:
                if pages >= page_budget:
                    logger.info(
                        "Lambda version walk in %s passed its %d-page budget; "
                        "looking up provisioned concurrency for all %d functions",
                        self._region, page_budget, len(names),
                    )
                    return names
                limiter.acquire()
                response = lambda_client.list_functions(**kwargs)
                pages += 1
                for entry in response.get('Functions') or []:
                    name = _lambda_function_name(entry)
                    if entry.get('Version') == '$LATEST':
                        seen_latest.add(name)
                    else:
                        # A published version, or an entry with no Version
                        # at all: either way, don't rule the function out.
                        versioned.add(name)
                marker = response.get('NextMarker')
                if not marker:
                    break
                kwargs['Marker'] = marker
        except Exception as e:
            logger.info(
                "Lambda version walk failed in %s (%s); looking up provisioned "
                "concurrency for all %d functions",
                self._region, e.__class__.__name__, len(names),
            )
            return names
        return [n for n in names if n in versioned or n not in seen_latest]

    def _look_up_pc_configs(
        self,
        lambda_client,
        cloudwatch,
        names: List[str],
        limiter: _RateLimiter,
        result: Dict[str, List[LambdaProvisionedConcurrencyData]],
        failure_reasons: Dict[str, int],
    ) -> None:
        """Run ``_list_pc_configs`` for ``names`` on a bounded pool.

        Workers only call AWS through the two clients made up front (the
        client cache isn't locked) and return their outcome. ``result``,
        ``failure_reasons`` and the permission record are written here, on
        the calling thread."""
        denied = threading.Event()
        skipped = object()

        def work(name: str):
            if denied.is_set():
                return name, None, skipped
            limiter.acquire()
            try:
                return name, self._list_pc_configs(lambda_client, name, cloudwatch), None
            except Exception as e:  # noqa: BLE001 - reported on the calling thread
                if self._is_access_denied(e):
                    denied.set()
                return name, None, e

        workers = max(1, min(_LAMBDA_PC_LOOKUP_WORKERS, len(names)))
        permission_recorded = False
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cw-lambda-pc") as pool:
            for name, configs, error in pool.map(work, names):
                if error is None:
                    result[name] = configs
                    continue
                if error is skipped:
                    label = 'skipped after AccessDenied'
                elif isinstance(error, ClientError):
                    code = error.response.get('Error', {}).get('Code', '') or 'ClientError'
                    label = f"ListProvisionedConcurrencyConfigs:{code}"
                    if self._is_access_denied(error) and not permission_recorded:
                        permission_recorded = True
                        self._record_permission_error(
                            resource="Lambda Provisioned Concurrency",
                            permission="lambda:ListProvisionedConcurrencyConfigs",
                            error=error,
                        )
                        self._warn_access_denied(
                            "Lambda Provisioned Concurrency",
                            "lambda:ListProvisionedConcurrencyConfigs",
                            error,
                        )
                else:
                    label = error.__class__.__name__
                failure_reasons[label] = failure_reasons.get(label, 0) + 1

    def _note_missing_lambda_pc(
        self,
        function_names: List[str],
        result: Dict[str, List[LambdaProvisionedConcurrencyData]],
        failure_reasons: Dict[str, int],
    ) -> None:
        """CLO-481: one WARNING, one ``DetectorErrors`` count and one
        ``data_warnings`` note for every function left out of ``result``."""
        missing = [name for name in function_names if name not in result]
        if not missing:
            return
        reasons = ', '.join(f"{label} x{count}" for label, count in sorted(failure_reasons.items())) or 'unknown'
        logger.warning(
            "Lambda provisioned concurrency unavailable for %d of %d functions in account=%s region=%s (%s); "
            "their idle-provisioned-concurrency findings are MISSING from this scan, not zero",
            len(missing), len(function_names), self._account_id, self._region, reasons,
        )
        self.swallowed_error_count += 1
        self.data_warnings.append(
            f"lambda: provisioned concurrency unavailable for {len(missing)} of {len(function_names)} "
            f"functions in {self._region}; their idle provisioned concurrency findings "
            f"are MISSING from this scan, not zero"
        )

    def _list_pc_configs(
        self, lambda_client, function_name: str, cloudwatch=None,
    ) -> List[LambdaProvisionedConcurrencyData]:
        """One ListProvisionedConcurrencyConfigs call, plus the utilization
        read for each config. Raises on a failed Lambda call."""
        configs = []
        response = lambda_client.list_provisioned_concurrency_configs(
            FunctionName=function_name
        )
        
        for pc in response.get('ProvisionedConcurrencyConfigs', []):
            qualifier = pc.get('FunctionArn', '').split(':')[-1]
            allocated = pc.get('AllocatedProvisionedConcurrentExecutions', 0)
            
            # Get utilization metric from CloudWatch
            avg_util = self._pc_utilization(function_name, qualifier, cloudwatch)
            
            configs.append(LambdaProvisionedConcurrencyData(
                function_name=function_name,
                function_qualifier=qualifier,
                requested_provisioned_concurrent_executions=pc.get(
                    'RequestedProvisionedConcurrentExecutions', 0
                ),
                allocated_provisioned_concurrent_executions=allocated,
                status=pc.get('Status', 'UNKNOWN'),
                avg_utilization_pct=avg_util,
            ))
        return configs

    async def _get_pc_utilization(
        self, function_name: str, qualifier: str
    ) -> Optional[float]:
        """Get average ProvisionedConcurrencyUtilization from CloudWatch."""
        return self._pc_utilization(function_name, qualifier)

    def _pc_utilization(
        self, function_name: str, qualifier: str, cloudwatch=None,
    ) -> Optional[float]:
        """Average ProvisionedConcurrencyUtilization over 14 days, as a
        percentage, or None when there is no data or the read fails."""
        try:
            if cloudwatch is None:
                cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=14)
            
            response = cloudwatch.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='ProvisionedConcurrencyUtilization',
                Dimensions=[
                    {'Name': 'FunctionName', 'Value': function_name},
                    {'Name': 'Resource', 'Value': f"{function_name}:{qualifier}"},
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,  # Daily buckets
                Statistics=['Average'],
            )
            
            datapoints = response.get('Datapoints', [])
            if datapoints:
                # Returned as a fraction 0.0–1.0, convert to percentage
                avg_util = sum(dp.get('Average', 0) for dp in datapoints) / len(datapoints)
                return round(avg_util * 100, 2)
        except Exception as e:
            logger.debug(f"Could not get PC utilization for {function_name}: {e}")
        
        return None
    
    # =========================================================================
    # Network
    # =========================================================================
    
    async def get_nat_gateways(self) -> List[NATGatewayData]:
        """Get all NAT Gateways in the region."""
        gateways = []
        try:
            ec2 = self._get_client('ec2')
            response = ec2.describe_nat_gateways()
            
            for nat in response.get('NatGateways', []):
                gateways.append(NATGatewayData(
                    nat_gateway_id=nat.get('NatGatewayId', ''),
                    state=nat.get('State', ''),
                    vpc_id=nat.get('VpcId', ''),
                    subnet_id=nat.get('SubnetId', ''),
                    region=self._region,
                    create_time=nat.get('CreateTime'),
                    connectivity_type=nat.get('ConnectivityType', 'public'),
                    tags=self._tags_to_dict(nat.get('Tags', [])),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="NAT Gateways", permission="ec2:DescribeNatGateways", error=e,
                )
                self._warn_access_denied("NAT Gateways", "ec2:DescribeNatGateways", e)
                raise
            logger.error(f"Error fetching NAT Gateways: {e}")
        
        return gateways
    
    async def get_nat_gateway_metrics(
        self,
        nat_gateway_ids: List[str],
        days: int = 7,
    ) -> Dict[str, NATGatewayMetricsData]:
        """Get CloudWatch metrics for NAT Gateways.

        CLO-589: an empty BytesOutToDestination series (no datapoints at all,
        not a published 0) is MISSING: noted and left out of the map, so the
        detector withholds idle_nat_gateway. It used to sum to 0 and read as
        idle. A failed read is noted the same way."""
        metrics = {}
        
        if not nat_gateway_ids:
            return metrics
        
        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            for nat_id in nat_gateway_ids:
                try:
                    response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/NATGateway',
                        MetricName='BytesOutToDestination',
                        Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Sum'],
                    )
                    
                    datapoints = response.get('Datapoints', [])
                    if not datapoints:
                        self._note_idle_verdict_missing('nat gateway', nat_id, "no datapoints")
                        continue
                    bytes_out = sum(dp.get('Sum', 0) for dp in datapoints)
                    
                    metrics[nat_id] = NATGatewayMetricsData(
                        nat_gateway_id=nat_id,
                        bytes_out_total=bytes_out,
                        period_days=days,
                        is_idle=bytes_out == 0,
                    )
                except ClientError as e:
                    if self._is_access_denied(e):
                        self._record_permission_error(
                            resource="NAT Gateway Metrics (per-resource)", permission="cloudwatch:GetMetricStatistics", error=e,
                        )
                        self._warn_access_denied("NAT Gateway Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e)
                    logger.warning(f"Error fetching NAT Gateway metrics for {nat_id}: {e}")
                    self._note_idle_verdict_missing(
                        'nat gateway', nat_id, f"read failed ({self._error_label(e)})",
                    )
                    metrics[nat_id] = NATGatewayMetricsData(nat_gateway_id=nat_id, period_days=days)
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="NAT Gateway Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("NAT Gateway Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching NAT Gateway metrics: {e}")
            for nat_id in nat_gateway_ids:
                if nat_id not in metrics:
                    self._note_idle_verdict_missing(
                        'nat gateway', nat_id, f"read failed ({self._error_label(e)})",
                    )
        
        return metrics
    
    async def get_load_balancers(self) -> List[LoadBalancerData]:
        """Get all Load Balancers in the region (ALB, NLB, Gateway, Classic).

        CLO-532 item 2: both DescribeLoadBalancers reads page (bounded by
        LOAD_BALANCERS_MAX_PAGES). Sets ``self.load_balancers_complete``: True
        only when every page of both reads came back, so a verdict that needs
        the WHOLE list (orphaned_dns_record: "no load balancer has this DNS
        name") is withheld instead of reading an unseen LB as deleted. Each
        LB's ``target_health_known`` says whether its health was read.
        """
        load_balancers = []
        elbv2_complete = False
        classic_complete = False
        self.load_balancers_complete = False
        try:
            elbv2 = self._get_client('elbv2')
            elbv2_lbs, elbv2_complete = _describe_load_balancers_bounded(elbv2, 'LoadBalancers')
            if not elbv2_complete:
                self._warn_once(
                    f"elbv2: more than {len(elbv2_lbs)} load balancers in {self._region}; "
                    f"DescribeLoadBalancers stopped at {LOAD_BALANCERS_MAX_PAGES} pages. Load balancers "
                    "past that are not judged and orphaned_dns_record's load-balancer check is withheld: "
                    "MISSING, not zero"
                )

            for lb in elbv2_lbs:
                lb_arn = lb.get('LoadBalancerArn', '')

                # Get target health count
                healthy_count = 0
                unhealthy_count = 0
                health_known = True
                try:
                    # CLO-527 item 5: every page of the LB's target groups.
                    target_groups, tg_complete = _describe_target_groups_bounded(elbv2, lb_arn)
                    if not tg_complete:
                        health_known = False
                        self._warn_once(
                            f"elbv2: {lb.get('LoadBalancerName', lb_arn)} in {self._region} has more than "
                            f"{len(target_groups)} target groups; target health past that is not counted"
                        )
                    for tg in target_groups:
                        tg_arn = tg.get('TargetGroupArn')
                        if tg_arn:
                            health_response = elbv2.describe_target_health(TargetGroupArn=tg_arn)
                            for target in health_response.get('TargetHealthDescriptions', []):
                                state = target.get('TargetHealth', {}).get('State', '')
                                if state == 'healthy':
                                    healthy_count += 1
                                else:
                                    unhealthy_count += 1
                except ClientError as e:
                    # CLO-532 item 2: an unread count is not "no healthy targets".
                    health_known = False
                    self._warn_swallowed(
                        "ALB/NLB target health", "elasticloadbalancing:DescribeTargetHealth", e,
                    )

                load_balancers.append(LoadBalancerData(
                    load_balancer_arn=lb_arn,
                    load_balancer_name=lb.get('LoadBalancerName', ''),
                    type=lb.get('Type', 'application'),
                    scheme=lb.get('Scheme', 'internet-facing'),
                    state=lb.get('State', {}).get('Code', 'unknown'),
                    region=self._region,
                    vpc_id=lb.get('VpcId'),
                    dns_name=lb.get('DNSName'),
                    created_time=lb.get('CreatedTime'),
                    healthy_target_count=healthy_count,
                    unhealthy_target_count=unhealthy_count,
                    target_health_known=health_known,
                ))
        except ClientError as e:
            elbv2_complete = False
            logger.error(f"Error fetching Load Balancers: {e}")
            self._warn_once(
                f"elbv2: DescribeLoadBalancers failed in {self._region} "
                f"({e.response.get('Error', {}).get('Code', 'ClientError')}); ALB/NLB checks and "
                "orphaned_dns_record's load-balancer check are MISSING for the region, not zero"
            )

        # Also fetch Classic Load Balancers (v1 API)
        try:
            elb_classic = self._get_client('elb')
            classic_lbs, classic_complete = _describe_load_balancers_bounded(
                elb_classic, 'LoadBalancerDescriptions',
            )
            if not classic_complete:
                self._warn_once(
                    f"elb: more than {len(classic_lbs)} Classic Load Balancers in {self._region}; "
                    f"DescribeLoadBalancers stopped at {LOAD_BALANCERS_MAX_PAGES} pages. Load balancers "
                    "past that are not judged and orphaned_dns_record's load-balancer check is withheld: "
                    "MISSING, not zero"
                )

            for clb in classic_lbs:
                clb_name = clb.get('LoadBalancerName', '')
                # Classic LBs report instance health directly
                healthy_count = 0
                unhealthy_count = 0
                health_known = True
                try:
                    health_response = elb_classic.describe_instance_health(
                        LoadBalancerName=clb_name
                    )
                    for instance in health_response.get('InstanceStates', []):
                        if instance.get('State') == 'InService':
                            healthy_count += 1
                        else:
                            unhealthy_count += 1
                except ClientError as e:
                    health_known = False
                    self._warn_swallowed(
                        "Classic ELB instance health", "elasticloadbalancing:DescribeInstanceHealth", e,
                    )

                load_balancers.append(LoadBalancerData(
                    load_balancer_arn=clb.get('DNSName', ''),  # CLBs don't have ARNs in v1
                    load_balancer_name=clb_name,
                    type='classic',
                    scheme=clb.get('Scheme', 'internet-facing'),
                    state='active',  # CLBs don't have a state field
                    region=self._region,
                    vpc_id=clb.get('VPCId'),
                    dns_name=clb.get('DNSName'),
                    created_time=clb.get('CreatedTime'),
                    healthy_target_count=healthy_count,
                    unhealthy_target_count=unhealthy_count,
                    target_health_known=health_known,
                ))
        except Exception as e:
            classic_complete = False
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Load Balancers", permission="elb:DescribeLoadBalancers", error=e,
                )
                self._warn_access_denied("Load Balancers", "elb:DescribeLoadBalancers", e)
                raise
            logger.warning(f"Error fetching Classic LBs: {e}")
            self._warn_once(
                f"elb: DescribeLoadBalancers failed in {self._region} ({e.__class__.__name__}); "
                "Classic Load Balancer checks and orphaned_dns_record's load-balancer check are "
                "MISSING for the region, not zero"
            )

        self.load_balancers_complete = elbv2_complete and classic_complete
        return load_balancers
    
    async def get_load_balancer_metrics(
        self,
        load_balancer_arns: List[str],
        days: int = 7,
    ) -> Dict[str, LoadBalancerMetricsData]:
        """Get CloudWatch metrics for Load Balancers (ALB + NLB)."""
        metrics = {}
        
        if not load_balancer_arns:
            return metrics
        
        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            for lb_arn in load_balancer_arns:
                # Extract load balancer name from ARN for CloudWatch dimension
                # ARN format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
                try:
                    lb_dimension = '/'.join(lb_arn.split('/')[-3:])

                    # Determine namespace based on LB type (app/* = ALB, net/* = NLB)
                    if lb_dimension.startswith('app/'):
                        namespace = 'AWS/ApplicationELB'
                    elif lb_dimension.startswith('net/'):
                        namespace = 'AWS/NetworkELB'
                    else:
                        namespace = 'AWS/ApplicationELB'

                    if lb_dimension.startswith('net/'):
                        # CLO-516: NLBs publish no RequestCount, so the old read
                        # always summed to 0 and every NLB with a healthy target
                        # was flagged low-traffic. Their traffic metric is
                        # NewFlowCount, which AWS reports even when it is zero:
                        # no datapoints at all is MISSING, not idle.
                        flow_response = cloudwatch.get_metric_statistics(
                            Namespace=namespace,
                            MetricName='NewFlowCount',
                            Dimensions=[{'Name': 'LoadBalancer', 'Value': lb_dimension}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400 * days,
                            Statistics=['Sum'],
                        )
                        flow_datapoints = flow_response.get('Datapoints', [])
                        if not flow_datapoints:
                            self._note_idle_verdict_missing(
                                'elbv2', lb_dimension, 'no NewFlowCount datapoints',
                                evidence='load balancer traffic metrics',
                            )
                            continue
                        flows = int(sum(dp.get('Sum', 0) for dp in flow_datapoints))
                        metrics[lb_arn] = LoadBalancerMetricsData(
                            load_balancer_arn=lb_arn,
                            request_count_total=0,
                            new_flow_count_total=flows,
                            period_days=days,
                            is_idle=flows == 0,
                        )
                        continue

                    response = cloudwatch.get_metric_statistics(
                        Namespace=namespace,
                        MetricName='RequestCount',
                        Dimensions=[{'Name': 'LoadBalancer', 'Value': lb_dimension}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Sum'],
                    )

                    # An ALB publishes RequestCount only when requests flow, so
                    # an empty series here is a measured zero.
                    datapoints = response.get('Datapoints', [])
                    request_count = sum(dp.get('Sum', 0) for dp in datapoints)

                    # Fetch ConsumedLCUs for ALBs (LCU cost analysis)
                    consumed_lcus_avg = None
                    if lb_dimension.startswith('app/'):
                        try:
                            # ConsumedLCUs is a billing metric published in 60-second
                            # intervals, where each datapoint is the LCU-hours accrued
                            # during that minute. AWS pins this on the sibling
                            # ReservedLCUs: "if 500 LCUs are reserved for an hour, the
                            # per-minute metric will be 8.33 LCUs" (500/60), and "the
                            # total ReservedLCUs over any period is the amount of LCUs
                            # you will be charged for". So `Sum` over a window is that
                            # window's LCU-hours, already aggregated across LB nodes.
                            #
                            # `Average` is Sum/SampleCount over per-minute, per-node
                            # samples — not LCUs per hour, and not comparable to the
                            # hourly LCU rate it gets multiplied by downstream. Using it
                            # understated LCU cost by roughly two orders of magnitude,
                            # so expensive ALBs slipped under the gate (CLO-228).
                            lcu_response = cloudwatch.get_metric_statistics(
                                Namespace='AWS/ApplicationELB',
                                MetricName='ConsumedLCUs',
                                Dimensions=[{'Name': 'LoadBalancer', 'Value': lb_dimension}],
                                StartTime=start_time,
                                EndTime=end_time,
                                Period=86400,  # 1-day granularity
                                Statistics=['Sum'],
                            )
                            lcu_datapoints = lcu_response.get('Datapoints', [])
                            if lcu_datapoints:
                                # Total LCU-hours ÷ window hours = average LCUs per hour,
                                # which is what the hourly LCU rate must multiply.
                                # Divide by the full window, not len(datapoints):
                                # CloudWatch drops periods with no traffic, and a quiet
                                # day is a genuine zero.
                                total_lcu_hours = sum(dp.get('Sum', 0.0) for dp in lcu_datapoints)
                                window_hours = days * 24
                                consumed_lcus_avg = (
                                    total_lcu_hours / window_hours if window_hours else None
                                )
                        except Exception as e:
                            logger.warning(f"Error fetching LCU metrics for {lb_arn}: {e}")
                    
                    metrics[lb_arn] = LoadBalancerMetricsData(
                        load_balancer_arn=lb_arn,
                        request_count_total=int(request_count),
                        consumed_lcus_avg=consumed_lcus_avg,
                        period_days=days,
                        is_idle=request_count == 0,
                    )
                except Exception as e:
                    if self._is_access_denied(e):
                        self._record_permission_error(
                            resource="Load Balancer Metrics (per-resource)", permission="cloudwatch:GetMetricStatistics", error=e,
                        )
                        self._warn_access_denied("Load Balancer Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e)
                    else:
                        self._warn_swallowed(
                            "Load Balancer Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e,
                        )
                    # CLO-516: a failed read is MISSING. It used to store a
                    # default model whose request_count_total of 0 read as an
                    # idle load balancer.
                    self._note_idle_verdict_missing(
                        'elbv2', lb_arn.split('/')[-2] if '/' in lb_arn else lb_arn,
                        f"read failed ({e.__class__.__name__})",
                        evidence='load balancer traffic metrics',
                    )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Load Balancer Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Load Balancer Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching Load Balancer metrics: {e}")
        
        return metrics
    
    # =========================================================================
    # S3
    # =========================================================================
    
    async def get_s3_buckets(self) -> List[S3BucketData]:
        """Get all S3 buckets with lifecycle policy info and CloudWatch size metrics."""
        buckets = []
        try:
            s3 = self._get_client('s3')
            response = s3.list_buckets()
            
            now = datetime.now(timezone.utc)
            
            # Storage types to query for size breakdown
            _STORAGE_TYPES = [
                'StandardStorage', 'IntelligentTieringStorage', 'StandardIAStorage',
                'OneZoneIAStorage', 'GlacierStorage', 'GlacierInstantRetrievalStorage',
                'DeepArchiveStorage',
            ]
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket.get('Name', '')
                
                # Get bucket region
                bucket_region = None
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location.get('LocationConstraint') or 'us-east-1'
                except ClientError as e:
                    self._warn_swallowed("S3 bucket location", "s3:GetBucketLocation", e)
                
                # Check lifecycle policy. CLO-551: NoSuchLifecycleConfiguration
                # is AWS's real "no policy" answer; any other failure
                # (AccessDenied, a bucket policy deny, throttling) is None
                # (MISSING), so no_lifecycle_policy is withheld and
                # s3_wrong_storage_class / s3_rapid_growth, which a lifecycle
                # rule suppresses, are withheld too. A denial reaches
                # permission_missing through _warn_swallowed.
                has_lifecycle: Optional[bool] = False
                lifecycle_rules = []
                try:
                    lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                    lifecycle_rules = lifecycle.get('Rules', [])
                    has_lifecycle = len(lifecycle_rules) > 0
                except (ClientError, BotoCoreError) as e:
                    code = e.response.get('Error', {}).get('Code', '') if isinstance(e, ClientError) else ''
                    if code != 'NoSuchLifecycleConfiguration':
                        has_lifecycle = None
                        self._warn_swallowed(
                            "S3 bucket lifecycle configuration", "s3:GetLifecycleConfiguration", e,
                        )
                
                # Check for incomplete multipart uploads
                incomplete_count = 0
                incomplete_initiated: Optional[List[datetime]] = None
                try:
                    upload_list = _list_incomplete_multipart_uploads(s3, bucket_name)
                    incomplete_count = len(upload_list)
                    # CLO-513: keep each upload's start time so only stale
                    # uploads are flagged, never one still in progress.
                    incomplete_initiated = [
                        u['Initiated'] for u in upload_list
                        if isinstance(u, dict) and isinstance(u.get('Initiated'), datetime)
                    ]
                except ClientError as e:
                    self._warn_swallowed("S3 incomplete multipart uploads", "s3:ListMultipartUploads", e)
                
                # ── CloudWatch S3 metrics ──
                storage_breakdown: Dict[str, int] = {}
                total_size = 0
                object_count = 0
                size_previous = 0
                growth_pct = 0.0
                has_intelligent_tiering = False
                cloudwatch = None

                try:
                    # Use the bucket's region for CloudWatch queries
                    cw_region = bucket_region or self._region
                    cloudwatch = self._get_client('cloudwatch', region=cw_region)
                    
                    # Current size by storage class
                    for storage_type in _STORAGE_TYPES:
                        try:
                            size_resp = cloudwatch.get_metric_statistics(
                                Namespace='AWS/S3',
                                MetricName='BucketSizeBytes',
                                Dimensions=[
                                    {'Name': 'BucketName', 'Value': bucket_name},
                                    {'Name': 'StorageType', 'Value': storage_type},
                                ],
                                StartTime=now - timedelta(days=2),
                                EndTime=now,
                                Period=86400,
                                Statistics=['Average'],
                            )
                            datapoints = size_resp.get('Datapoints', [])
                            if datapoints:
                                # Use most recent datapoint
                                latest = max(datapoints, key=lambda dp: dp.get('Timestamp', now))
                                size = int(latest.get('Average', 0))
                                if size > 0:
                                    storage_breakdown[storage_type] = size
                                    total_size += size
                                    if storage_type == 'IntelligentTieringStorage':
                                        has_intelligent_tiering = True
                        except (ClientError, BotoCoreError) as e:
                            self._warn_swallowed(
                                "S3 bucket size by storage class", "cloudwatch:GetMetricStatistics", e,
                            )
                    
                    # Object count (AllStorageTypes)
                    try:
                        count_resp = cloudwatch.get_metric_statistics(
                            Namespace='AWS/S3',
                            MetricName='NumberOfObjects',
                            Dimensions=[
                                {'Name': 'BucketName', 'Value': bucket_name},
                                {'Name': 'StorageType', 'Value': 'AllStorageTypes'},
                            ],
                            StartTime=now - timedelta(days=2),
                            EndTime=now,
                            Period=86400,
                            Statistics=['Average'],
                        )
                        count_dps = count_resp.get('Datapoints', [])
                        if count_dps:
                            latest = max(count_dps, key=lambda dp: dp.get('Timestamp', now))
                            object_count = int(latest.get('Average', 0))
                    except (ClientError, BotoCoreError) as e:
                        self._warn_swallowed(
                            "S3 bucket object count", "cloudwatch:GetMetricStatistics", e,
                        )
                    
                    # Historical size for growth (30 days ago, Standard only)
                    if total_size > 0:
                        try:
                            hist_resp = cloudwatch.get_metric_statistics(
                                Namespace='AWS/S3',
                                MetricName='BucketSizeBytes',
                                Dimensions=[
                                    {'Name': 'BucketName', 'Value': bucket_name},
                                    {'Name': 'StorageType', 'Value': 'StandardStorage'},
                                ],
                                StartTime=now - timedelta(days=32),
                                EndTime=now - timedelta(days=28),
                                Period=86400,
                                Statistics=['Average'],
                            )
                            hist_dps = hist_resp.get('Datapoints', [])
                            if hist_dps:
                                latest = max(hist_dps, key=lambda dp: dp.get('Timestamp', now))
                                size_previous = int(latest.get('Average', 0))
                                if size_previous > 0:
                                    growth_pct = round(
                                        ((total_size - size_previous) / size_previous) * 100, 1
                                    )
                        except (ClientError, BotoCoreError) as e:
                            self._warn_swallowed(
                                "S3 bucket historical size", "cloudwatch:GetMetricStatistics", e,
                            )
                except (ClientError, BotoCoreError) as e:
                    logger.debug(f"CloudWatch S3 metrics unavailable for {bucket_name}: {e}")
                
                # CLO-488: a CloudWatch size above zero is observed contents.
                # Zero (no datapoints) is not: S3 publishes no storage
                # datapoints for an empty bucket, so only the listing below
                # can say the bucket is empty.
                contents_observed = total_size > 0

                # ── Fallback: S3 API when CloudWatch has no data ──
                # CloudWatch publishes BucketSizeBytes once daily; newly-created
                # buckets won't have datapoints for up to 24-48 hours. Use
                # list_objects_v2 to get real-time size and storage class info.
                if total_size == 0:
                    try:
                        # Use a regional S3 client so ListObjectsV2 works for
                        # buckets outside the provider's default region.
                        regional_s3 = self._get_client('s3', region=bucket_region) if bucket_region else s3
                        paginator = regional_s3.get_paginator('list_objects_v2')
                        fallback_breakdown: Dict[str, int] = {}
                        fallback_count = 0
                        fallback_total = 0
                        _SC_TO_CW = {
                            'STANDARD': 'StandardStorage',
                            'INTELLIGENT_TIERING': 'IntelligentTieringStorage',
                            'STANDARD_IA': 'StandardIAStorage',
                            'ONEZONE_IA': 'OneZoneIAStorage',
                            'GLACIER': 'GlacierStorage',
                            'GLACIER_INSTANT_RETRIEVAL': 'GlacierInstantRetrievalStorage',
                            'DEEP_ARCHIVE': 'DeepArchiveStorage',
                        }
                        for page in paginator.paginate(Bucket=bucket_name):
                            for obj in page.get('Contents', []):
                                obj_size = obj.get('Size', 0)
                                sc = obj.get('StorageClass', 'STANDARD')
                                cw_name = _SC_TO_CW.get(sc, 'StandardStorage')
                                fallback_breakdown[cw_name] = fallback_breakdown.get(cw_name, 0) + obj_size
                                fallback_total += obj_size
                                fallback_count += 1
                        # A full (paginated) ListObjectsV2 listing is authoritative —
                        # it always reflects the bucket's true, current contents, unlike
                        # CloudWatch's once-daily storage metrics. In particular,
                        # NumberOfObjects can report a stale non-zero value (e.g. from
                        # zero-byte placeholder keys, or objects deleted after the last
                        # publish) even though BucketSizeBytes has already dropped to
                        # zero for every storage class. Trust the listing unconditionally
                        # — including when it confirms the bucket is truly empty — so a
                        # stale CloudWatch object count can never mask an empty bucket.
                        storage_breakdown = fallback_breakdown
                        total_size = fallback_total
                        object_count = fallback_count
                        has_intelligent_tiering = 'IntelligentTieringStorage' in fallback_breakdown
                        contents_observed = True
                        if fallback_total > 0:
                            logger.info(
                                f"S3 fallback: {bucket_name} — {fallback_total / (1024**3):.1f} GB, "
                                f"{fallback_count} objects (CloudWatch data not yet available)"
                            )
                    except (ClientError, BotoCoreError) as e:
                        # CLO-488: CloudWatch had no size and the listing
                        # failed, so the contents are unknown. The zero
                        # defaults used to read as an empty bucket. Every
                        # region's scan lists every bucket; only the
                        # bucket's own region judges it, so only that one
                        # counts and notes the failure.
                        if (bucket_region or 'us-east-1') == self._region:
                            self._warn_swallowed(
                                "S3 bucket object listing", "s3:ListBucket", e,
                            )
                            if object_count == 0:
                                self._note_idle_verdict_missing(
                                    's3', bucket_name, f"listing failed ({self._error_label(e)})",
                                    verdict="empty-bucket", evidence="object listings",
                                )
                        else:
                            logger.debug(f"S3 list_objects_v2 fallback failed for {bucket_name}: {e}")

                # CLO-385: for a bucket that is currently empty AND has an
                # enabled lifecycle expiration rule, check whether it held
                # objects recently — evidence it's a self-clearing upload
                # bucket the s3_empty_bucket detector should not flag,
                # rather than an orphaned one. Only queried for this narrow
                # case, to avoid a second CloudWatch call per bucket.
                # NumberOfObjects is a daily gauge, so Maximum over the
                # window is the honest statistic — Average would smear a
                # one-day spike toward zero, and Sum is meaningless for a
                # gauge (see the CloudWatch Average/sum-type trap notes).
                recent_max_objects = None
                has_expiration_rule = any(
                    rule.get('Status') == 'Enabled' and 'Expiration' in rule
                    for rule in lifecycle_rules
                )
                # CLO-551: also when the lifecycle read failed (None): an
                # expiration rule cannot be ruled out, so the evidence is read.
                if (cloudwatch is not None and total_size == 0 and object_count == 0
                        and (has_expiration_rule or has_lifecycle is None)):
                    try:
                        recent_resp = cloudwatch.get_metric_statistics(
                            Namespace='AWS/S3',
                            MetricName='NumberOfObjects',
                            Dimensions=[
                                {'Name': 'BucketName', 'Value': bucket_name},
                                {'Name': 'StorageType', 'Value': 'AllStorageTypes'},
                            ],
                            StartTime=now - timedelta(days=35),
                            EndTime=now,
                            Period=86400,
                            Statistics=['Maximum'],
                        )
                        recent_dps = recent_resp.get('Datapoints', [])
                        if recent_dps:
                            recent_max_objects = int(max(dp.get('Maximum', 0) for dp in recent_dps))
                    except (ClientError, BotoCoreError) as e:
                        self._warn_swallowed(
                            "S3 bucket recent max object count", "cloudwatch:GetMetricStatistics", e,
                        )

                # Check default encryption
                default_encryption_enabled = True  # AWS default since Jan 2023
                encryption_algorithm = None
                try:
                    enc_resp = s3.get_bucket_encryption(Bucket=bucket_name)
                    enc_config = enc_resp.get('ServerSideEncryptionConfiguration', {})
                    rules = enc_config.get('Rules', []) if isinstance(enc_config, dict) else []
                    if rules and isinstance(rules, list) and len(rules) > 0:
                        default_rule = rules[0]
                        if isinstance(default_rule, dict):
                            encryption_algorithm = default_rule.get(
                                'ApplyServerSideEncryptionByDefault', {}
                            ).get('SSEAlgorithm')
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        default_encryption_enabled = False
                
                buckets.append(S3BucketData(
                    bucket_name=bucket_name,
                    region=bucket_region,
                    creation_date=bucket.get('CreationDate'),
                    has_lifecycle_policy=has_lifecycle,
                    lifecycle_rules=lifecycle_rules,
                    has_incomplete_multipart=incomplete_count > 0,
                    incomplete_multipart_count=incomplete_count,
                    incomplete_multipart_initiated=incomplete_initiated,
                    total_size_bytes=total_size,
                    object_count=object_count,
                    storage_class_breakdown=storage_breakdown,
                    has_intelligent_tiering=has_intelligent_tiering,
                    size_previous_bytes=size_previous,
                    size_growth_pct_30d=growth_pct,
                    default_encryption_enabled=default_encryption_enabled,
                    encryption_algorithm=encryption_algorithm,
                    recent_max_object_count=recent_max_objects,
                    contents_observed=contents_observed,
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="S3 Buckets", permission="s3:ListBuckets", error=e,
                )
                self._warn_access_denied("S3 Buckets", "s3:ListBuckets", e)
                raise
            logger.error(f"Error fetching S3 buckets: {e}")
        
        return buckets
    
    async def get_s3_cost_breakdown(self) -> Dict[str, S3CostBreakdown]:
        """Query Cost Explorer for per-bucket S3 cost breakdown by usage type.

        Note: Cost Explorer does not support RESOURCE_ID for S3.
        Per-bucket granularity requires CUR (Cost and Usage Reports) via
        Athena, which is not yet integrated.  Until CUR support is added
        this method returns an empty dict so the downstream detector
        gracefully produces no waste items rather than crashing with a
        ValidationException or generating misleading aggregate data.
        """
        logger.info(
            "S3 per-bucket cost breakdown skipped: "
            "requires CUR/Athena integration (not yet available)"
        )
        return {}

    async def get_extended_support_cost_breakdown(
        self,
        service_keys: Optional[List[str]] = None,
        days: int = 30,
    ) -> Dict[str, ExtendedSupportCostData]:
        """Query Cost Explorer for extended support surcharge totals.

        Returns service-level totals keyed by normalized service key.

        CLO-358: memoized per (account, service_keys, days) for the life of
        this provider (see ``extended_support_cache`` on ``__init__``) so
        callers that ask for the identical breakdown more than once during
        one scan — today that's the ``rds`` and ``aurora`` detectors, both
        requesting ``service_keys=['rds'], days=30`` — issue one billed
        ``ce:GetCostAndUsage`` call instead of one each.
        """
        cache_key = (self._account_id, tuple(sorted(service_keys or [])), days)
        cached = self._extended_support_cache.get(cache_key)
        if cached is not None:
            return cached

        breakdowns: Dict[str, ExtendedSupportCostData] = {}

        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        try:
            ce = self._get_client('ce', region='us-east-1')
            response = ce.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.date().isoformat(),
                    'End': end_date.date().isoformat(),
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                Filter={
                    'Or': [
                        {'Dimensions': {'Key': 'USAGE_TYPE', 'MatchOptions': ['CONTAINS'], 'Values': ['ExtendedSupport']}},
                        {'Dimensions': {'Key': 'USAGE_TYPE', 'MatchOptions': ['CONTAINS'], 'Values': ['Extended Support']}},
                        {'Dimensions': {'Key': 'USAGE_TYPE', 'MatchOptions': ['CONTAINS'], 'Values': ['LegacySupport']}},
                        {'Dimensions': {'Key': 'USAGE_TYPE', 'MatchOptions': ['CONTAINS'], 'Values': ['Legacy Support']}},
                    ]
                },
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                    {'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'},
                ],
            )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Extended Support Cost Breakdown", permission="ce:GetCostAndUsage", error=e,
                )
                self._warn_access_denied("Extended Support Cost Breakdown", "ce:GetCostAndUsage", e)
                raise
            logger.debug(f"Extended support cost breakdown unavailable: {e}")
            return breakdowns

        service_map = {
            'Amazon Relational Database Service': 'rds',
            'AmazonRDS': 'rds',
            'Amazon ElastiCache': 'elasticache',
            'AmazonElastiCache': 'elasticache',
            'Amazon Elastic Kubernetes Service': 'eks',
            'AmazonEKS': 'eks',
            'Amazon OpenSearch Service': 'opensearch',
            'AmazonOpenSearchService': 'opensearch',
            'Amazon DocumentDB': 'documentdb',
            'AmazonDocDB': 'documentdb',
        }

        for result in response.get('ResultsByTime', []):
            for group in result.get('Groups', []):
                keys = group.get('Keys', [])
                if len(keys) < 2:
                    continue

                service_name = keys[0]
                usage_type = keys[1]
                normalized = service_map.get(service_name)
                if not normalized:
                    continue
                if service_keys and normalized not in service_keys:
                    continue

                amount = float(group.get('Metrics', {}).get('UnblendedCost', {}).get('Amount', 0.0))
                if amount <= 0:
                    continue

                if normalized not in breakdowns:
                    breakdowns[normalized] = ExtendedSupportCostData(
                        service_key=normalized,
                        amount_usd=0.0,
                        days=days,
                        billing_source='cost_explorer',
                    )

                breakdowns[normalized].amount_usd += amount
                breakdowns[normalized].usage_types.append(usage_type)

        # Cache only a successful response — a transient CE failure above
        # returns early without reaching here, so it is never memoized as a
        # false "no extended support cost" for the rest of the scan.
        self._extended_support_cache[cache_key] = breakdowns
        return breakdowns
    
    # =========================================================================
    # EFS
    # =========================================================================

    async def get_efs_filesystems(self) -> List[EFSFilesystemData]:
        """Get all EFS filesystems in the region.

        Raises:
            ClientError: if the call fails with an access-denied/unauthorized
                error code (via ``_service_call`` — see CLO-176). This is
                intentional — the scan role is missing
                ``elasticfilesystem:DescribeFileSystems`` (or similar), and a
                bare ``[]`` return would be indistinguishable from a genuinely
                empty account, silently blinding any detector (e.g.
                ``unencrypted_efs_filesystem``) that relies on this data.
                Callers that want graceful degradation for a single detector
                without failing the whole scan should catch this explicitly
                (see ``_run_detector_with_timeout``'s permission_error
                handling) rather than relying on this method to swallow it.
        """
        filesystems = []
        with self._service_call("EFS filesystems", "elasticfilesystem:DescribeFileSystems"):
            efs = self._get_client('efs')
            paginator = efs.get_paginator('describe_file_systems')

            for page in paginator.paginate():
                for fs in page.get('FileSystems', []):
                    fs_id = fs.get('FileSystemId', '')

                    # Check mount targets
                    mount_target_count = 0
                    try:
                        mt_response = efs.describe_mount_targets(FileSystemId=fs_id)
                        mount_target_count = len(mt_response.get('MountTargets', []))
                    except ClientError as e:
                        self._warn_swallowed(
                            "EFS mount targets", "elasticfilesystem:DescribeMountTargets", e,
                        )

                    # Get name from tags
                    name = None
                    for tag in fs.get('Tags', []):
                        if tag.get('Key') == 'Name':
                            name = tag.get('Value')
                            break

                    # Get lifecycle policies
                    # CLO-516: a failed read is None (MISSING), not [] ("no
                    # policy"), so no_lifecycle_efs cannot fire on it.
                    lifecycle_policies: Optional[List[Dict[str, str]]] = []
                    try:
                        lc_response = efs.describe_lifecycle_configuration(FileSystemId=fs_id)
                        lifecycle_policies = lc_response.get('LifecyclePolicies', [])
                    except ClientError as e:
                        lifecycle_policies = None
                        self._warn_swallowed(
                            "EFS lifecycle policies", "elasticfilesystem:DescribeLifecycleConfiguration", e,
                        )
                        code = e.response.get('Error', {}).get('Code', '') or 'ClientError'
                        self._note_idle_verdict_missing(
                            'efs', fs_id, f"read failed ({code})",
                            verdict='no-lifecycle-policy', evidence='lifecycle configurations',
                        )

                    filesystems.append(EFSFilesystemData(
                        filesystem_id=fs_id,
                        region=self._region,
                        name=name,
                        lifecycle_state=fs.get('LifeCycleState', 'available'),
                        size_bytes=fs.get('SizeInBytes', {}).get('Value', 0),
                        has_mount_targets=mount_target_count > 0,
                        mount_target_count=mount_target_count,
                        performance_mode=fs.get('PerformanceMode', 'generalPurpose'),
                        throughput_mode=fs.get('ThroughputMode', 'bursting'),
                        encrypted=fs.get('Encrypted', False),
                        creation_time=fs.get('CreationTime'),
                        lifecycle_policies=lifecycle_policies,
                        tags={tag.get('Key'): tag.get('Value') for tag in fs.get('Tags', [])},
                    ))

        return filesystems
    
    # =========================================================================
    # ECR
    # =========================================================================
    
    async def get_ecr_repositories(self) -> List[ECRRepositoryData]:
        """Get all ECR repositories in the region."""
        repositories = []
        try:
            ecr = self._get_client('ecr')
            
            # List all repositories
            repo_list = self._paginate(ecr, 'describe_repositories', 'repositories')
            
            for repo in repo_list:
                repo_name = repo.get('repositoryName', '')
                repo_arn = repo.get('repositoryArn', '')
                repo_uri = repo.get('repositoryUri', '')
                
                # Check for lifecycle policy. CLO-551:
                # LifecyclePolicyNotFoundException is AWS's real "no policy"
                # answer; any other failure is None (MISSING), so
                # ecr_no_lifecycle_policy is withheld. A denial reaches
                # permission_missing through _warn_swallowed.
                has_lifecycle_policy: Optional[bool] = False
                try:
                    ecr.get_lifecycle_policy(repositoryName=repo_name)
                    has_lifecycle_policy = True
                except (ClientError, BotoCoreError) as e:
                    code = e.response.get('Error', {}).get('Code', '') if isinstance(e, ClientError) else ''
                    if code != 'LifecyclePolicyNotFoundException':
                        has_lifecycle_policy = None
                        self._warn_swallowed(
                            "ECR repository lifecycle policy", "ecr:GetLifecyclePolicy", e,
                        )
                
                # Get image details
                image_count = 0
                total_size_bytes = 0
                untagged_count = 0
                untagged_size_bytes = 0
                old_image_count = 0
                old_images_size_bytes = 0
                
                try:
                    images = self._paginate(ecr, 'describe_images', 'imageDetails', repositoryName=repo_name)
                    image_count = len(images)
                    
                    from datetime import datetime, timezone, timedelta
                    cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)
                    
                    for image in images:
                        size = image.get('imageSizeInBytes', 0)
                        total_size_bytes += size
                        
                        # Check for untagged images
                        if not image.get('imageTags'):
                            untagged_count += 1
                            untagged_size_bytes += size
                        
                        # Check for old images (>90 days)
                        pushed_at = image.get('imagePushedAt')
                        if pushed_at and pushed_at < cutoff_date:
                            old_image_count += 1
                            old_images_size_bytes += size
                            
                except ClientError as e:
                    logger.warning(f"Error getting images for {repo_name}: {e}")
                
                repositories.append(ECRRepositoryData(
                    repository_name=repo_name,
                    repository_arn=repo_arn,
                    repository_uri=repo_uri,
                    region=self._region,
                    created_at=repo.get('createdAt'),
                    image_count=image_count,
                    total_size_gb=total_size_bytes / (1024 ** 3),
                    has_lifecycle_policy=has_lifecycle_policy,
                    untagged_image_count=untagged_count,
                    untagged_images_size_gb=untagged_size_bytes / (1024 ** 3),
                    old_image_count=old_image_count,
                    old_images_size_gb=old_images_size_bytes / (1024 ** 3),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="ECR Repositories", permission="ecr:DescribeRepositories", error=e,
                )
                self._warn_access_denied("ECR Repositories", "ecr:DescribeRepositories", e)
                raise
            logger.warning(f"Error fetching ECR repositories: {e}")
        
        return repositories
    
    # =========================================================================
    # Route 53
    # =========================================================================
    
    async def get_route53_zones(self) -> List[Route53ZoneData]:
        """Get all Route 53 hosted zones."""
        zones = []
        try:
            route53 = self._get_client('route53')
            response = route53.list_hosted_zones()
            
            for zone in response.get('HostedZones', []):
                zone_id = zone.get('Id', '').replace('/hostedzone/', '')
                
                zones.append(Route53ZoneData(
                    zone_id=zone_id,
                    zone_name=zone.get('Name', ''),
                    record_set_count=zone.get('ResourceRecordSetCount', 0),
                    is_private=zone.get('Config', {}).get('PrivateZone', False),
                    comment=zone.get('Config', {}).get('Comment'),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Route53 Zones", permission="route53:ListHostedZones", error=e,
                )
                self._warn_access_denied("Route53 Zones", "route53:ListHostedZones", e)
                raise
            logger.error(f"Error fetching Route 53 zones: {e}")
        
        return zones

    async def get_vpc_endpoints(self) -> List["VPCEndpointData"]:
        """Get all VPC endpoints in the region."""
        from cloudwise_scan_core.data_providers.models import VPCEndpointData
        endpoints = []
        try:
            ec2 = self._get_client('ec2')
            paginator = ec2.get_paginator('describe_vpc_endpoints')
            for page in paginator.paginate():
                for ep in page.get('VpcEndpoints', []):
                    endpoints.append(VPCEndpointData(
                        endpoint_id=ep.get('VpcEndpointId', ''),
                        service_name=ep.get('ServiceName', ''),
                        endpoint_type=ep.get('VpcEndpointType', 'Interface'),
                        state=ep.get('State', 'available'),
                        vpc_id=ep.get('VpcId', ''),
                        region=self._region,
                        creation_time=ep.get('CreationTimestamp'),
                        subnet_ids=ep.get('SubnetIds', []),
                        network_interface_ids=ep.get('NetworkInterfaceIds', []),
                        tags={t.get('Key'): t.get('Value') for t in ep.get('Tags', [])},
                    ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="VPC Endpoints", permission="ec2:DescribeVpcEndpoints", error=e,
                )
                self._warn_access_denied("VPC Endpoints", "ec2:DescribeVpcEndpoints", e)
                raise
            logger.warning(f"Error fetching VPC endpoints: {e}")
        return endpoints

    # GetMetricData takes at most 500 queries per request; one per endpoint.
    _VPCE_METRIC_BATCH = 500
    # CLO-533: the exact dimension set PrivateLink publishes BytesProcessed
    # under, per endpoint (a per-subnet series adds "Subnet Id").
    _VPCE_DIMENSION_NAMES = frozenset({'VPC Id', 'VPC Endpoint Id', 'Endpoint Type', 'Service Name'})
    # CLO-533: ListMetrics pages read for the dimension-sanity guard (500
    # metrics per page). Any one matching series ends the read.
    _VPCE_LIST_METRICS_MAX_PAGES = 5

    def _vpce_series_identity_confirmed(self, cloudwatch) -> bool:
        """CLO-533 dimension-sanity guard: True when ListMetrics shows a
        BytesProcessed series in AWS/PrivateLinkEndpoints under EXACTLY the
        4-dimension set this provider queries, for any endpoint in the
        region. That proves the query shape matches what AWS publishes here,
        so an empty Complete series is the endpoint's own silence, not the
        CLO-528 wrong-dimension bug. Bounded pages; a failed read is False
        (the caller keeps the endpoints MISSING)."""
        cached = getattr(self, '_vpce_identity_confirmed', None)
        if cached is not None:
            return cached
        confirmed = False
        try:
            kwargs: Dict[str, Any] = {
                'Namespace': 'AWS/PrivateLinkEndpoints',
                'MetricName': 'BytesProcessed',
                'Dimensions': [{'Name': 'VPC Endpoint Id'}],
            }
            for _ in range(self._VPCE_LIST_METRICS_MAX_PAGES):
                page = cloudwatch.list_metrics(**kwargs)
                for metric in page.get('Metrics', []) or []:
                    names = {d.get('Name') for d in metric.get('Dimensions', []) or []}
                    if names == self._VPCE_DIMENSION_NAMES:
                        confirmed = True
                        break
                token = page.get('NextToken')
                if confirmed or not token:
                    break
                kwargs = {**kwargs, 'NextToken': token}
        except (ClientError, BotoCoreError) as e:
            # Monitoring template 1.29.0 grants cloudwatch:ListMetrics; an
            # older stack is denied it. The denial is recorded (once: the
            # answer is cached per provider) so permission_missing carries it
            # and the account gets the CLO-534 targeted notice. Either way the
            # guard fails and the empty-series endpoints stay MISSING (noted
            # per endpoint): the verdict is unchanged.
            if self._is_access_denied(e):
                logger.info(
                    "vpc-endpoint: cloudwatch:ListMetrics denied in %s; empty BytesProcessed "
                    "series are judged only on same-request evidence", self._region,
                )
                self._record_permission_error(
                    resource="VPC endpoint BytesProcessed series check",
                    permission="cloudwatch:ListMetrics", error=e,
                )
            else:
                self._warn_swallowed(
                    "VPC endpoint BytesProcessed series check", "cloudwatch:ListMetrics", e,
                )
            confirmed = False
        self._vpce_identity_confirmed = confirmed
        return confirmed

    async def get_vpc_endpoint_bytes_processed(
        self,
        endpoints: List["VPCEndpointData"],
        days: int = 14,
    ) -> Optional[Dict[str, float]]:
        """CLO-528: see WasteDataProvider.get_vpc_endpoint_bytes_processed.

        PrivateLink publishes BytesProcessed ONLY under the full dimension
        set: (VPC Id, VPC Endpoint Id, Endpoint Type, Service Name) for the
        endpoint, plus one series per subnet that adds Subnet Id.
        CloudWatch matches dimensions exactly, so the pre-fix query on
        ``VPC Endpoint Id`` alone matched no series, returned no datapoints,
        and summed to 0: every interface endpoint read as idle (verified on
        the fixture account, 2026-10-01: 302,981 bytes under the 4-dimension
        set, ``[]`` under the 1-dimension one). This reads the per-endpoint
        series, daily Sums, in batched GetMetricData requests. Datapoints
        from before the endpoint existed are dropped (CLO-457).

        CLO-533: an idle endpoint publishes NO datapoints at all (measured on
        the wave-4 fixture, 2026-10-02), so "no datapoints" alone is not
        evidence either way. It counts as 0 bytes only when ALL hold:
          - the endpoint is at least ``days`` old (known creation time);
          - its query's final StatusCode is Complete (a PartialData,
            InternalError or Forbidden result, an Id missing from the
            response, or a failed request is MISSING);
          - the dimension-sanity guard passes: another endpoint in the same
            GetMetricData request returned datapoints, or ListMetrics shows
            the exact 4-dimension series for some endpoint in the region.
        Otherwise it stays MISSING."""
        totals: Dict[str, float] = {}
        if not endpoints:
            return totals

        queries_for: List[Tuple["VPCEndpointData", Dict[str, Any]]] = []
        for ep in endpoints:
            dims = [
                ('VPC Id', ep.vpc_id),
                ('VPC Endpoint Id', ep.endpoint_id),
                ('Endpoint Type', ep.endpoint_type),
                ('Service Name', ep.service_name),
            ]
            if not all(value for _, value in dims):
                self._note_idle_verdict_missing(
                    'vpc-endpoint', ep.endpoint_id or '?', "metric dimensions unknown",
                    evidence='BytesProcessed datapoints',
                )
                continue
            queries_for.append((ep, {
                'Namespace': 'AWS/PrivateLinkEndpoints',
                'MetricName': 'BytesProcessed',
                'Dimensions': [{'Name': n, 'Value': v} for n, v in dims],
            }))

        cloudwatch = self._get_client('cloudwatch')
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)

        for offset in range(0, len(queries_for), self._VPCE_METRIC_BATCH):
            batch = queries_for[offset:offset + self._VPCE_METRIC_BATCH]
            by_query = {f'vpce{idx}': ep for idx, (ep, _) in enumerate(batch)}
            queries = [
                {
                    'Id': f'vpce{idx}',
                    'MetricStat': {'Metric': metric, 'Period': 86400, 'Stat': 'Sum'},
                    'ReturnData': True,
                }
                for idx, (_, metric) in enumerate(batch)
            ]
            series: Dict[str, List[Dict[str, Any]]] = {}
            # CLO-533: each query's StatusCode on the last page it appeared
            # on (PartialData means more pages follow).
            status: Dict[str, str] = {}
            try:
                next_token: Optional[str] = None
                while True:
                    request: Dict[str, Any] = {
                        'MetricDataQueries': queries,
                        'StartTime': start_time,
                        'EndTime': end_time,
                    }
                    if next_token:
                        request['NextToken'] = next_token
                    response = cloudwatch.get_metric_data(**request)
                    for res in response.get('MetricDataResults', []):
                        ep = by_query.get(res.get('Id'))
                        if ep is None:
                            continue
                        status[ep.endpoint_id] = res.get('StatusCode') or ''
                        points = series.setdefault(ep.endpoint_id, [])
                        for ts, value in zip(res.get('Timestamps', []), res.get('Values', [])):
                            if value is not None:
                                points.append({'Timestamp': ts, 'Sum': float(value)})
                    next_token = response.get('NextToken')
                    if not next_token:
                        break
            except (ClientError, BotoCoreError) as e:
                if self._is_access_denied(e):
                    self._record_permission_error(
                        resource="VPC Endpoint Metrics",
                        permission="cloudwatch:GetMetricData", error=e,
                    )
                self._warn_swallowed(
                    "VPC endpoint BytesProcessed", "cloudwatch:GetMetricData", e,
                )
                for ep in by_query.values():
                    self._note_idle_verdict_missing(
                        'vpc-endpoint', ep.endpoint_id, f"read failed ({self._error_label(e)})",
                        evidence='BytesProcessed datapoints',
                    )
                continue

            # Same-request evidence for the guard: some endpoint's series came
            # back with datapoints under the exact query shape.
            batch_has_datapoints = any(series.get(ep.endpoint_id) for ep in by_query.values())

            for ep in by_query.values():
                final_status = status.get(ep.endpoint_id)
                if final_status != 'Complete':
                    self._note_idle_verdict_missing(
                        'vpc-endpoint', ep.endpoint_id,
                        f"read incomplete ({final_status or 'no result'})",
                        evidence='BytesProcessed datapoints',
                    )
                    continue
                points = drop_pre_creation_datapoints(
                    series.get(ep.endpoint_id, []), ep.creation_time, 86400,
                )
                total = float(sum(p.get('Sum', 0) for p in points))
                if not points:
                    # CLO-533: a Complete, empty series from an endpoint old
                    # enough for the window, with the series identity
                    # confirmed, is an idle endpoint's silence: 0 bytes.
                    # Only for Interface endpoints, the type the wave-4
                    # fixture measured; GatewayLoadBalancer, Resource and
                    # ServiceNetwork endpoints stay MISSING.
                    if ep.endpoint_type != 'Interface':
                        self._note_idle_verdict_missing(
                            'vpc-endpoint', ep.endpoint_id,
                            f"no datapoints ({ep.endpoint_type} endpoint, no-data rule unvalidated)",
                            evidence='BytesProcessed datapoints',
                        )
                        continue
                    if ep.creation_time is None or not is_as_old_as_window(ep.creation_time, days):
                        self._note_idle_verdict_missing(
                            'vpc-endpoint', ep.endpoint_id, "no datapoints (age unknown or under window)",
                            evidence='BytesProcessed datapoints',
                        )
                        continue
                    if not (batch_has_datapoints or self._vpce_series_identity_confirmed(cloudwatch)):
                        self._note_idle_verdict_missing(
                            'vpc-endpoint', ep.endpoint_id,
                            "no datapoints (series identity unconfirmed)",
                            evidence='BytesProcessed datapoints',
                        )
                        continue
                    totals[ep.endpoint_id] = 0.0
                    continue
                if total == 0 and not has_min_coverage(len(points), days, 86400):
                    # Traffic anywhere in the series is a measurement on its
                    # own; an idle claim needs the window covered.
                    self._note_idle_verdict_missing(
                        'vpc-endpoint', ep.endpoint_id, "under 75% coverage",
                        evidence='BytesProcessed datapoints',
                    )
                    continue
                totals[ep.endpoint_id] = total
        return totals
    
    # =========================================================================
    # DynamoDB
    # =========================================================================
    
    async def get_dynamodb_tables(self) -> List[DynamoDBTableData]:
        """Get all DynamoDB tables in the region."""
        tables = []
        try:
            dynamodb = self._get_client('dynamodb')
            table_names = self._paginate(dynamodb, 'list_tables', 'TableNames')
            
            for table_name in table_names:
                try:
                    response = dynamodb.describe_table(TableName=table_name)
                    table = response.get('Table', {})
                    
                    # Check for autoscaling. CLO-551: a failed read is None
                    # (MISSING), not False ("no auto scaling"), so
                    # dynamodb_no_autoscaling is withheld for the table; a
                    # denial still reaches permission_missing through
                    # _warn_swallowed.
                    has_autoscaling: Optional[bool] = False
                    try:
                        autoscaling = self._get_client('application-autoscaling')
                        scalable_targets = autoscaling.describe_scalable_targets(
                            ServiceNamespace='dynamodb',
                            ResourceIds=[f"table/{table_name}"]
                        )
                        has_autoscaling = len(scalable_targets.get('ScalableTargets', [])) > 0
                    except (ClientError, BotoCoreError) as e:
                        has_autoscaling = None
                        self._warn_swallowed(
                            "DynamoDB autoscaling targets",
                            "application-autoscaling:DescribeScalableTargets",
                            e,
                        )
                    
                    billing_mode = table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                    provisioned = table.get('ProvisionedThroughput', {})

                    # CLO-384: PITR status isn't on describe-table's
                    # response — it needs a separate, best-effort call. Not
                    # in the monitoring role template as of 1.24.0
                    # (missing: dynamodb:DescribeContinuousBackups). Stays
                    # None (unknown, never "off") on any failure so the
                    # backup-coverage detector can downgrade instead of
                    # asserting no coverage.
                    pitr_enabled = None
                    try:
                        backups = dynamodb.describe_continuous_backups(TableName=table_name)
                        pitr_status = (
                            backups.get('ContinuousBackupsDescription', {})
                            .get('PointInTimeRecoveryDescription', {})
                            .get('PointInTimeRecoveryStatus')
                        )
                        if pitr_status:
                            pitr_enabled = pitr_status == 'ENABLED'
                    except ClientError as e:
                        self._warn_swallowed(
                            "DynamoDB point-in-time recovery status",
                            "dynamodb:DescribeContinuousBackups",
                            e,
                        )

                    tables.append(DynamoDBTableData(
                        table_name=table_name,
                        table_arn=table.get('TableArn', ''),
                        region=self._region,
                        billing_mode=billing_mode,
                        status=table.get('TableStatus', ''),
                        provisioned_read_capacity=provisioned.get('ReadCapacityUnits', 0),
                        provisioned_write_capacity=provisioned.get('WriteCapacityUnits', 0),
                        has_autoscaling=has_autoscaling,
                        item_count=table.get('ItemCount', 0),
                        size_bytes=table.get('TableSizeBytes', 0),
                        deletion_protection=table.get('DeletionProtectionEnabled', False),
                        point_in_time_recovery_enabled=pitr_enabled,
                        created_time=table.get('CreationDateTime'),
                    ))
                except ClientError as e:
                    logger.warning(f"Error describing DynamoDB table {table_name}: {e}")
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="DynamoDB Tables", permission="dynamodb:ListTables", error=e,
                )
                self._warn_access_denied("DynamoDB Tables", "dynamodb:ListTables", e)
                raise
            logger.error(f"Error fetching DynamoDB tables: {e}")
        
        return tables
    
    async def get_dynamodb_metrics(
        self,
        table_names: List[str],
        days: int = 14,
    ) -> Dict[str, DynamoDBMetricsData]:
        """Get CloudWatch metrics for DynamoDB tables."""
        metrics = {}
        
        if not table_names:
            return metrics
        
        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Consumed*CapacityUnits are sum-type metrics: over any period, `Sum` is the
            # total capacity units consumed and `SampleCount` is the number of *requests*
            # — so CloudWatch's `Average` is units-per-request, which is unrelated to a
            # rate (verified against a live table: Sum 236 / SampleCount 1655 = Average
            # 0.1426, with SampleCount exceeding the 1440 minutes in the day). Provisioned
            # RCU/WCU are units *per second*, so the only correct comparison basis is
            # Sum over the whole window divided by the window length in seconds (CLO-227).
            window_seconds = days * 86400

            for table_name in table_names:
                try:
                    # Get consumed read capacity
                    read_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/DynamoDB',
                        MetricName='ConsumedReadCapacityUnits',
                        Dimensions=[{'Name': 'TableName', 'Value': table_name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Sum'],
                    )

                    # Sum every returned datapoint and divide by the full window, not by
                    # len(datapoints): CloudWatch omits periods with no requests, and a
                    # day with no traffic is a genuine zero that must drag the rate down.
                    read_total = sum(dp.get('Sum', 0.0) for dp in read_response.get('Datapoints', []))
                    read_rate = read_total / window_seconds if window_seconds else 0.0

                    # Get consumed write capacity
                    write_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/DynamoDB',
                        MetricName='ConsumedWriteCapacityUnits',
                        Dimensions=[{'Name': 'TableName', 'Value': table_name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Sum'],
                    )

                    write_total = sum(dp.get('Sum', 0.0) for dp in write_response.get('Datapoints', []))
                    write_rate = write_total / window_seconds if window_seconds else 0.0

                    metrics[table_name] = DynamoDBMetricsData(
                        table_name=table_name,
                        # Deliberately unrounded — a real per-second rate is often far
                        # below 0.01 (a table doing 236 reads/day is 0.0027 RCU/s), and
                        # rounding it to 2dp would collapse it to exactly 0.0 and trip
                        # the idle-table branch at HIGH confidence.
                        consumed_read_capacity_avg=read_rate,
                        consumed_write_capacity_avg=write_rate,
                        period_days=days,
                        # Idleness is decided on the raw totals, never on the rate, so
                        # float precision can never manufacture an idle table.
                        is_idle=read_total == 0 and write_total == 0,
                    )
                except ClientError as e:
                    if self._is_access_denied(e):
                        self._record_permission_error(
                            resource="DynamoDB Metrics (per-resource)", permission="cloudwatch:GetMetricStatistics", error=e,
                        )
                        self._warn_access_denied("DynamoDB Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e)
                    # CLO-485: a failed read is MISSING, not zero. It used to
                    # store a default DynamoDBMetricsData whose 0.0/0.0
                    # consumed capacity read as an idle table (the detector
                    # gates on the rates). Leave the table out of the map;
                    # the detector skips a table with no metrics.
                    self._warn_swallowed(
                        "DynamoDB Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e,
                    )
                    self._note_idle_verdict_missing(
                        'dynamodb', table_name, f"read failed ({self._error_label(e)})",
                    )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="DynamoDB Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("DynamoDB Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching DynamoDB metrics: {e}")
        
        return metrics
    
    # =========================================================================
    # ElastiCache
    # =========================================================================
    
    async def get_elasticache_clusters(self) -> List[ElastiCacheClusterData]:
        """Get all ElastiCache clusters including replication group topology and tags."""
        clusters = []
        try:
            elasticache = self._get_client('elasticache')
            response = elasticache.describe_cache_clusters(ShowCacheNodeInfo=True)

            # Fetch replication groups for topology info
            replication_groups = {}
            try:
                rg_response = elasticache.describe_replication_groups()
                for rg in rg_response.get('ReplicationGroups', []):
                    replication_groups[rg['ReplicationGroupId']] = rg
            except Exception as e:
                self._warn_swallowed(
                    "ElastiCache replication groups", "elasticache:DescribeReplicationGroups", e,
                )

            for cluster in response.get('CacheClusters', []):
                cluster_id = cluster.get('CacheClusterId', '')
                rg_id = cluster.get('ReplicationGroupId')

                # Fetch tags
                tags = {}
                try:
                    arn = cluster.get('ARN', '')
                    if arn:
                        tag_response = elasticache.list_tags_for_resource(ResourceName=arn)
                        tags = {t['Key']: t['Value'] for t in tag_response.get('TagList', [])}
                except Exception as e:
                    self._warn_swallowed(
                        "ElastiCache resource tags", "elasticache:ListTagsForResource", e,
                    )

                # Parse replication group topology
                num_shards = 1
                replicas_per_shard = 0
                multi_az = False
                auto_failover = 'disabled'

                # CLO-584: DataTiering is a ReplicationGroup field, never a
                # CacheCluster one (DescribeCacheClusters' CacheCluster shape
                # has no DataTiering member at all), so reading it off
                # ``cluster`` always defaulted to 'disabled' -- the data
                # tiering detector's own "already tiered" guard never
                # fired. Read it off the replication group, the same lookup
                # already used for shard/replica/Multi-AZ topology.
                data_tiering_enabled = False
                if rg_id and rg_id in replication_groups:
                    rg = replication_groups[rg_id]
                    node_groups = rg.get('NodeGroups', [])
                    num_shards = len(node_groups) if node_groups else 1
                    if node_groups:
                        replicas_per_shard = max(len(node_groups[0].get('NodeGroupMembers', [])) - 1, 0)
                    multi_az = rg.get('MultiAZ', 'disabled') == 'enabled'
                    auto_failover = rg.get('AutomaticFailover', 'disabled')
                    data_tiering_enabled = rg.get('DataTiering', 'disabled') == 'enabled'

                clusters.append(ElastiCacheClusterData(
                    cluster_id=cluster_id,
                    engine=cluster.get('Engine', ''),
                    engine_version=cluster.get('EngineVersion', ''),
                    node_type=cluster.get('CacheNodeType', ''),
                    num_nodes=cluster.get('NumCacheNodes', 1),
                    status=cluster.get('CacheClusterStatus', ''),
                    region=self._region,
                    created_time=cluster.get('CacheClusterCreateTime'),
                    tags=tags,
                    replication_group_id=rg_id,
                    num_shards=num_shards,
                    replicas_per_shard=replicas_per_shard,
                    multi_az_enabled=multi_az,
                    automatic_failover=auto_failover,
                    data_tiering_enabled=data_tiering_enabled,
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="ElastiCache Clusters", permission="elasticache:DescribeCacheClusters", error=e,
                )
                self._warn_access_denied("ElastiCache Clusters", "elasticache:DescribeCacheClusters", e)
                raise
            logger.error(f"Error fetching ElastiCache clusters: {e}")
        
        return clusters
    
    async def get_elasticache_metrics(
        self,
        cluster_ids: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
        idle_window_days: Optional[int] = None,
    ) -> Dict[str, ElastiCacheMetricsData]:
        """Get CloudWatch metrics for ElastiCache clusters.

        CLO-485: ``is_idle`` needs the daily CurrConnections series to cover
        75% of ``idle_window_days`` (``days`` when not given), and never zero
        datapoints. The idle detector passes ``idle_window_days``; only then
        is a withheld idle verdict noted in ``data_warnings``.

        CLO-457: CacheClusterId is a name. With a cluster's creation time in
        ``create_times`` (CacheClusterCreateTime), every read starts at the
        creation time and drops datapoints from before it (see
        metric_window), so a cluster recreated under a reused id is judged on
        its own days only."""
        metrics = {}
        
        if not cluster_ids:
            return metrics
        
        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            
            for cluster_id in cluster_ids:
                created = (create_times or {}).get(cluster_id)
                start_time = metric_start_time(end_time, days, created)

                def _own(resp, _created=created) -> list:
                    return drop_pre_creation_datapoints(
                        resp.get('Datapoints', []), _created, 86400,
                    )

                try:
                    # CacheHits
                    hits_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ElastiCache',
                        MetricName='CacheHits',
                        Dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average'],
                    )
                    hits_dps = _own(hits_resp)
                    cache_hits_avg = sum(dp['Average'] for dp in hits_dps) / len(hits_dps) if hits_dps else 0

                    # CurrConnections (avg + max)
                    conn_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ElastiCache',
                        MetricName='CurrConnections',
                        Dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average', 'Maximum'],
                    )
                    conn_dps = _own(conn_resp)
                    conn_avg = sum(dp['Average'] for dp in conn_dps) / len(conn_dps) if conn_dps else 0
                    conn_max = max((dp['Maximum'] for dp in conn_dps), default=0)
                    # Compute std dev of daily averages for connection variance
                    conn_std = 0.0
                    if len(conn_dps) > 1:
                        conn_values = [dp['Average'] for dp in conn_dps]
                        conn_mean = sum(conn_values) / len(conn_values)
                        conn_std = (sum((v - conn_mean) ** 2 for v in conn_values) / len(conn_values)) ** 0.5

                    # CPUUtilization (avg + max)
                    cpu_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ElastiCache',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average', 'Maximum'],
                    )
                    cpu_dps = _own(cpu_resp)
                    cpu_avg = sum(dp['Average'] for dp in cpu_dps) / len(cpu_dps) if cpu_dps else 0
                    cpu_max = max((dp['Maximum'] for dp in cpu_dps), default=0)

                    # DatabaseMemoryUsagePercentage
                    mem_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ElastiCache',
                        MetricName='DatabaseMemoryUsagePercentage',
                        Dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average'],
                    )
                    mem_dps = _own(mem_resp)
                    mem_pct = sum(dp['Average'] for dp in mem_dps) / len(mem_dps) if mem_dps else 0

                    # BytesUsedForCache
                    bytes_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ElastiCache',
                        MetricName='BytesUsedForCache',
                        Dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average'],
                    )
                    bytes_dps = _own(bytes_resp)
                    bytes_used = sum(dp['Average'] for dp in bytes_dps) / len(bytes_dps) if bytes_dps else 0

                    # CLO-485: "0 connections" must be measured, not
                    # defaulted. An empty or sparse CurrConnections series
                    # (a new region, a metrics outage) averages to 0 above;
                    # it is only idle with the coverage #1452 set for
                    # DocumentDB: 75% of the window's daily datapoints, and
                    # never zero.
                    claim_days = idle_window_days or days
                    conn_covered = has_min_coverage(len(conn_dps), claim_days, 86400)
                    # A cluster younger than the window is not called idle
                    # anyway (the detector's age guard), so its short series
                    # is expected, not missing.
                    if (idle_window_days and conn_avg == 0 and not conn_covered
                            and is_as_old_as_window(created, claim_days)):
                        self._note_idle_verdict_missing(
                            'elasticache', cluster_id,
                            "no CurrConnections datapoints" if not conn_dps
                            else "CurrConnections under 75% coverage",
                        )

                    metrics[cluster_id] = ElastiCacheMetricsData(
                        cluster_id=cluster_id,
                        cache_hits_avg=round(cache_hits_avg, 2),
                        # CLO-584: deliberately unrounded -- a brief handful
                        # of connections over 7 days can average well under
                        # 0.01, and rounding to 2dp would collapse it to
                        # exactly 0.0, which makes oversized_elasticache's
                        # own ``current_connections_avg > 0`` gate
                        # unreachable (``is_idle`` above already reads the
                        # raw, unrounded ``conn_avg``, so it is unaffected).
                        # The std stays unrounded with it: the serverless
                        # detector divides one by the other (cv = std/avg),
                        # and a 2dp std over a full-precision avg read a
                        # true cv of 1.5 (avg 0.004, std 0.006) as 2.5.
                        current_connections_avg=conn_avg,
                        current_connections_max=round(conn_max, 2),
                        current_connections_std=conn_std,
                        cpu_utilization_avg=round(cpu_avg, 2),
                        cpu_utilization_max=round(cpu_max, 2),
                        database_memory_usage_pct=round(mem_pct, 2),
                        bytes_used_for_cache=round(bytes_used, 2),
                        period_days=days,
                        is_idle=conn_covered and conn_avg == 0,
                        connection_datapoints=len(conn_dps),
                        cpu_datapoints=len(cpu_dps),
                        # CLO-572: the oversized memory gate's coverage count.
                        memory_datapoints=len(mem_dps),
                    )
                except ClientError as e:
                    # CLO-485: a failed read is MISSING, not zero. It used to
                    # store a default ElastiCacheMetricsData, whose 0.0
                    # connections read as an idle cluster. Leave the cluster
                    # out of the map instead; every ElastiCache detector
                    # already skips a cluster with no metrics.
                    self._warn_swallowed(
                        "ElastiCache Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e,
                    )
                    self._note_idle_verdict_missing(
                        'elasticache', cluster_id, f"read failed ({self._error_label(e)})",
                    )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="ElastiCache Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("ElastiCache Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching ElastiCache metrics: {e}")

        return metrics

    # CLO-508: ElastiCache request-volume metrics, (query suffix, MetricName).
    _EC_VOLUME_METRICS = (
        ('cmd', 'ProcessedCommands'),
        ('get', 'GetTypeCmds'),
        ('set', 'SetTypeCmds'),
        ('nin', 'NetworkBytesIn'),
        ('nout', 'NetworkBytesOut'),
    )
    # 5 queries per node; GetMetricData takes at most 500 per request.
    _EC_VOLUME_BATCH = 100

    async def get_elasticache_request_volume(
        self,
        cluster_ids: List[str],
        days: int = 30,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, ElastiCacheRequestVolumeData]:
        """CLO-508: see WasteDataProvider.get_elasticache_request_volume.

        Daily Sums of ProcessedCommands (falling back to GetTypeCmds +
        SetTypeCmds when the node publishes none), NetworkBytesIn and
        NetworkBytesOut on CacheClusterId, for every requested node in
        batched GetMetricData requests (5 metrics x up to 100 nodes each),
        not one GetMetricStatistics call per metric per node. Datapoints from
        before a node's creation time are dropped (CLO-457). A node whose
        command series covers under 75% of the window's days, or whose read
        fails, is left out (MISSING) and noted."""
        volumes: Dict[str, ElastiCacheRequestVolumeData] = {}
        if not cluster_ids:
            return volumes

        cloudwatch = self._get_client('cloudwatch')
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        ids = list(dict.fromkeys(cluster_ids))

        for offset in range(0, len(ids), self._EC_VOLUME_BATCH):
            batch = ids[offset:offset + self._EC_VOLUME_BATCH]
            queries = []
            by_query: Dict[str, Tuple[str, str]] = {}
            for idx, cluster_id in enumerate(batch):
                for suffix, metric in self._EC_VOLUME_METRICS:
                    qid = f'ec{idx}_{suffix}'
                    by_query[qid] = (cluster_id, suffix)
                    queries.append({
                        'Id': qid,
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/ElastiCache',
                                'MetricName': metric,
                                'Dimensions': [{'Name': 'CacheClusterId', 'Value': cluster_id}],
                            },
                            'Period': 86400,
                            'Stat': 'Sum',
                        },
                        'ReturnData': True,
                    })

            series: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
            try:
                next_token: Optional[str] = None
                while True:
                    request: Dict[str, Any] = {
                        'MetricDataQueries': queries,
                        'StartTime': start_time,
                        'EndTime': end_time,
                    }
                    if next_token:
                        request['NextToken'] = next_token
                    response = cloudwatch.get_metric_data(**request)
                    for res in response.get('MetricDataResults', []):
                        key = by_query.get(res.get('Id'))
                        if key is None:
                            continue
                        points = series.setdefault(key, [])
                        for ts, value in zip(res.get('Timestamps', []), res.get('Values', [])):
                            if value is not None:
                                points.append({'Timestamp': ts, 'Sum': float(value)})
                    next_token = response.get('NextToken')
                    if not next_token:
                        break
            except (ClientError, BotoCoreError) as e:
                if self._is_access_denied(e):
                    self._record_permission_error(
                        resource="ElastiCache Request Metrics",
                        permission="cloudwatch:GetMetricData", error=e,
                    )
                self._warn_swallowed(
                    "ElastiCache request metrics", "cloudwatch:GetMetricData", e,
                )
                for cluster_id in batch:
                    self._note_idle_verdict_missing(
                        'elasticache-serverless', cluster_id, f"read failed ({self._error_label(e)})",
                        verdict='serverless-estimate', evidence='command counts',
                    )
                continue

            for cluster_id in batch:
                created = (create_times or {}).get(cluster_id)

                def _own(suffix: str, _id=cluster_id, _created=created) -> List[Dict[str, Any]]:
                    return drop_pre_creation_datapoints(series.get((_id, suffix), []), _created, 86400)

                def _total(points: List[Dict[str, Any]]) -> float:
                    return float(sum(p.get('Sum', 0) for p in points))

                command_metric = 'ProcessedCommands'
                command_dps = _own('cmd')
                if command_dps:
                    commands = _total(command_dps)
                else:
                    command_metric = 'GetTypeCmds+SetTypeCmds'
                    get_dps, set_dps = _own('get'), _own('set')
                    command_dps = get_dps if len(get_dps) >= len(set_dps) else set_dps
                    commands = _total(get_dps) + _total(set_dps)
                if not has_min_coverage(len(command_dps), days, 86400):
                    self._note_idle_verdict_missing(
                        'elasticache-serverless', cluster_id,
                        "no command-count datapoints" if not command_dps
                        else "command counts under 75% coverage",
                        verdict='serverless-estimate', evidence='command counts',
                    )
                    continue
                volumes[cluster_id] = ElastiCacheRequestVolumeData(
                    cluster_id=cluster_id,
                    commands_total=commands,
                    network_bytes_total=_total(_own('nin')) + _total(_own('nout')),
                    period_days=days,
                    command_metric=command_metric,
                )
        return volumes

    # =========================================================================
    # Redshift
    # =========================================================================
    
    async def get_redshift_clusters(self) -> List[RedshiftClusterData]:
        """Get all Redshift clusters in the region."""
        clusters = []
        try:
            redshift = self._get_client('redshift')
            response = redshift.describe_clusters()
            
            # Fetch scheduled actions to determine pause schedules
            scheduled_actions = {}
            try:
                sa_response = redshift.describe_scheduled_actions()
                for action in sa_response.get('ScheduledActions', []):
                    target = action.get('TargetAction', {})
                    pause = target.get('PauseCluster', {})
                    resume = target.get('ResumeCluster', {})
                    cluster_id = pause.get('ClusterIdentifier') or resume.get('ClusterIdentifier')
                    if cluster_id:
                        scheduled_actions[cluster_id] = True
            except ClientError as e:
                self._warn_swallowed(
                    "Redshift scheduled actions", "redshift:DescribeScheduledActions", e,
                )
            
            for cluster in response.get('Clusters', []):
                cluster_id = cluster.get('ClusterIdentifier', '')
                clusters.append(RedshiftClusterData(
                    cluster_id=cluster_id,
                    node_type=cluster.get('NodeType', ''),
                    num_nodes=cluster.get('NumberOfNodes', 1),
                    status=cluster.get('ClusterStatus', ''),
                    region=self._region,
                    database_name=cluster.get('DBName'),
                    endpoint=cluster.get('Endpoint', {}).get('Address'),
                    encrypted=cluster.get('Encrypted', False),
                    created_time=cluster.get('ClusterCreateTime'),
                    has_pause_schedule=scheduled_actions.get(cluster_id, False),
                    is_paused=cluster.get('ClusterStatus', '').lower() == 'paused',
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Redshift Clusters", permission="redshift:DescribeClusters", error=e,
                )
                self._warn_access_denied("Redshift Clusters", "redshift:DescribeClusters", e)
                raise
            logger.error(f"Error fetching Redshift clusters: {e}")
        
        return clusters
    
    async def get_redshift_metrics(
        self,
        cluster_ids: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
        idle_window_days: Optional[int] = None,
    ) -> Dict[str, RedshiftMetricsData]:
        """Get CloudWatch metrics for Redshift clusters.

        CLO-457: ClusterIdentifier is a name. With a cluster's creation time
        in ``create_times`` (ClusterCreateTime), every read starts at the
        creation time and drops datapoints from before it (see
        metric_window), so a cluster recreated under a reused identifier is
        judged on its own hours and days only.

        CLO-485: ``is_idle`` needs the hourly DatabaseConnections series to
        cover at least 75% of the idle claim window (``idle_window_days``,
        the detector's redshift_idle_days; ``days`` when not given). Hours
        from before that window do not count toward it."""
        metrics = {}
        claim_days = idle_window_days or days
        
        if not cluster_ids:
            return metrics
        
        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            
            for cluster_id in cluster_ids:
                created = (create_times or {}).get(cluster_id)
                start_time = metric_start_time(end_time, days, created)

                def _own(resp, period=86400, _created=created) -> list:
                    return drop_pre_creation_datapoints(
                        resp.get('Datapoints', []), _created, period,
                    )

                try:
                    # Fetch DatabaseConnections (daily)
                    conn_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Redshift',
                        MetricName='DatabaseConnections',
                        Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average'],
                    )
                    
                    conn_datapoints = _own(conn_response)
                    conn_avg = sum(dp['Average'] for dp in conn_datapoints) / len(conn_datapoints) if conn_datapoints else 0
                    
                    # Fetch CPUUtilization (daily)
                    cpu_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Redshift',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Average'],
                    )
                    
                    cpu_datapoints = _own(cpu_response)
                    cpu_avg = sum(dp['Average'] for dp in cpu_datapoints) / len(cpu_datapoints) if cpu_datapoints else 0
                    
                    # Fetch hourly DatabaseConnections for zero-connection hours analysis
                    hourly_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Redshift',
                        MetricName='DatabaseConnections',
                        Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average'],
                    )
                    
                    hourly_datapoints = _own(hourly_response, 3600)
                    total_hours = len(hourly_datapoints)
                    # Hours inside the claim window (a bucket straddling its
                    # start counts, as metric_window counts a straddling
                    # creation bucket).
                    claim_hours = len(drop_pre_creation_datapoints(
                        hourly_datapoints, end_time - timedelta(days=claim_days), 3600,
                    ))
                    zero_hours = sum(1 for dp in hourly_datapoints if dp['Average'] == 0)
                    zero_pct = (zero_hours / total_hours * 100) if total_hours > 0 else 0
                    
                    # Fetch WLM metrics for over-provisioned detection
                    wlm_queue_avg = 0.0
                    wlm_wait_avg = 0.0
                    wlm_running_avg = 0.0
                    wlm_running_max = 0.0
                    try:
                        # WLM Queue Length
                        wlm_queue_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/Redshift',
                            MetricName='WLMQueueLength',
                            Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=['Average'],
                        )
                        wlm_queue_dps = _own(wlm_queue_response)
                        wlm_queue_avg = sum(dp['Average'] for dp in wlm_queue_dps) / len(wlm_queue_dps) if wlm_queue_dps else 0.0
                        
                        # WLM Queue Wait Time
                        wlm_wait_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/Redshift',
                            MetricName='WLMQueueWaitTime',
                            Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=['Average'],
                        )
                        wlm_wait_dps = _own(wlm_wait_response)
                        wlm_wait_avg = sum(dp['Average'] for dp in wlm_wait_dps) / len(wlm_wait_dps) if wlm_wait_dps else 0.0
                        
                        # WLM Running Queries
                        wlm_running_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/Redshift',
                            MetricName='WLMRunningQueries',
                            Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=['Average', 'Maximum'],
                        )
                        wlm_running_dps = _own(wlm_running_response)
                        wlm_running_avg = sum(dp['Average'] for dp in wlm_running_dps) / len(wlm_running_dps) if wlm_running_dps else 0.0
                        wlm_running_max = max((dp['Maximum'] for dp in wlm_running_dps), default=0.0)
                    except ClientError as e:
                        logger.debug(f"Could not fetch WLM metrics for {cluster_id}: {e}")
                    
                    # Concurrency Scaling metrics (Detector 6)
                    cs_seconds_avg = 0.0
                    cs_seconds_total = 0.0
                    cs_active_avg = 0.0
                    cs_active_max = 0.0
                    try:
                        # ConcurrencyScalingSeconds — total per day
                        cs_seconds_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/Redshift',
                            MetricName='ConcurrencyScalingSeconds',
                            Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=['Sum'],
                        )
                        cs_daily_sums = [dp['Sum'] for dp in _own(cs_seconds_response)]
                        cs_seconds_total = sum(cs_daily_sums)
                        cs_seconds_avg = cs_seconds_total / max(len(cs_daily_sums), 1)

                        # ConcurrencyScalingActiveClusters
                        cs_active_response = cloudwatch.get_metric_statistics(
                            Namespace='AWS/Redshift',
                            MetricName='ConcurrencyScalingActiveClusters',
                            Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=['Average', 'Maximum'],
                        )
                        cs_active_dps = _own(cs_active_response)
                        cs_active_avg = sum(dp['Average'] for dp in cs_active_dps) / len(cs_active_dps) if cs_active_dps else 0.0
                        cs_active_max = max((dp['Maximum'] for dp in cs_active_dps), default=0.0)
                    except ClientError as e:
                        logger.debug(f"Could not fetch Concurrency Scaling metrics for {cluster_id}: {e}")
                    
                    # CLO-485: "0 connections for N days" must be measured,
                    # not defaulted. An empty or sparse series (a new region,
                    # a metrics outage, a paused cluster, which publishes no
                    # metrics) averages to 0 above; it is idle only with 75%
                    # of the claim window's hours observed (#1452's coverage
                    # rule), and never with zero.
                    conn_covered = bool(conn_datapoints) and has_min_coverage(
                        claim_hours, claim_days, 3600,
                    )
                    if (conn_avg == 0 and not conn_covered
                            and is_as_old_as_window(created, claim_days)):
                        self._note_idle_verdict_missing(
                            'redshift', cluster_id,
                            "no DatabaseConnections datapoints" if not claim_hours
                            else "DatabaseConnections under 75% coverage",
                        )

                    metrics[cluster_id] = RedshiftMetricsData(
                        cluster_id=cluster_id,
                        database_connections_avg=round(conn_avg, 2),
                        cpu_utilization_avg=round(cpu_avg, 2),
                        period_days=days,
                        is_idle=conn_covered and conn_avg == 0,
                        connection_hours_in_idle_window=claim_hours,
                        zero_connection_hours_pct=round(zero_pct, 1),
                        wlm_queue_length_avg=round(wlm_queue_avg, 2),
                        wlm_queue_wait_time_avg=round(wlm_wait_avg, 2),
                        wlm_running_queries_avg=round(wlm_running_avg, 2),
                        wlm_running_queries_max=round(wlm_running_max, 2),
                        concurrency_scaling_seconds_avg=round(cs_seconds_avg, 2),
                        concurrency_scaling_seconds_total=round(cs_seconds_total, 2),
                        concurrency_scaling_active_clusters_avg=round(cs_active_avg, 2),
                        concurrency_scaling_active_clusters_max=round(cs_active_max, 2),
                    )
                except ClientError as e:
                    # CLO-485: a failed read is MISSING, not zero: leave the
                    # cluster out of the map (every Redshift sub-detector
                    # skips a cluster with no metrics) instead of storing a
                    # default model whose zeros other gates could misread.
                    self._warn_swallowed(
                        "Redshift Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e,
                    )
                    self._note_idle_verdict_missing(
                        'redshift', cluster_id, f"read failed ({self._error_label(e)})",
                    )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Redshift Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Redshift Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching Redshift metrics: {e}")
        
        return metrics
    
    async def get_redshift_cost_breakdown(
        self,
        cluster_ids: List[str],
    ) -> Dict[str, RedshiftCostData]:
        """Get Cost Explorer data for Redshift clusters (Spectrum vs compute)."""
        costs: Dict[str, RedshiftCostData] = {}
        
        if not cluster_ids:
            return costs
        
        try:
            ce = self._get_client('ce')
            end_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            start_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%d')
            
            # Get Redshift compute costs
            try:
                compute_response = ce.get_cost_and_usage(
                    TimePeriod={'Start': start_date, 'End': end_date},
                    Granularity='MONTHLY',
                    Filter={
                        'Dimensions': {
                            'Key': 'SERVICE',
                            'Values': ['Amazon Redshift'],
                        }
                    },
                    Metrics=['UnblendedCost'],
                )
                
                total_redshift = 0
                for result in compute_response.get('ResultsByTime', []):
                    total_redshift += float(result.get('Total', {}).get('UnblendedCost', {}).get('Amount', 0))
            except ClientError:
                total_redshift = 0
            
            # Get Redshift Spectrum costs
            try:
                spectrum_response = ce.get_cost_and_usage(
                    TimePeriod={'Start': start_date, 'End': end_date},
                    Granularity='MONTHLY',
                    Filter={
                        'And': [
                            {'Dimensions': {'Key': 'SERVICE', 'Values': ['Amazon Redshift']}},
                            {'Dimensions': {'Key': 'USAGE_TYPE', 'MatchOptions': ['CONTAINS'], 'Values': ['Spectrum']}},
                        ]
                    },
                    Metrics=['UnblendedCost'],
                )
                
                total_spectrum = 0
                for result in spectrum_response.get('ResultsByTime', []):
                    total_spectrum += float(result.get('Total', {}).get('UnblendedCost', {}).get('Amount', 0))
            except ClientError:
                total_spectrum = 0
            
            compute_cost = total_redshift - total_spectrum
            spectrum_ratio = (total_spectrum / compute_cost * 100) if compute_cost > 0 else 0
            
            # Distribute evenly across clusters (best effort without per-cluster tags)
            num_clusters = max(len(cluster_ids), 1)
            for cluster_id in cluster_ids:
                costs[cluster_id] = RedshiftCostData(
                    cluster_id=cluster_id,
                    compute_cost_monthly=round(compute_cost / num_clusters, 2),
                    spectrum_cost_monthly=round(total_spectrum / num_clusters, 2),
                    total_cost_monthly=round(total_redshift / num_clusters, 2),
                    spectrum_cost_ratio=round(spectrum_ratio, 1),
                )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Redshift Cost Breakdown", permission="ce:GetCostAndUsage", error=e,
                )
                self._warn_access_denied("Redshift Cost Breakdown", "ce:GetCostAndUsage", e)
                raise
            logger.error(f"Error fetching Redshift cost breakdown: {e}")
        
        return costs
    
    # =========================================================================
    # OpenSearch
    # =========================================================================
    
    async def get_opensearch_domains(self) -> List[OpenSearchDomainData]:
        """Get all OpenSearch domains in the region."""
        domains = []
        try:
            opensearch = self._get_client('opensearch')
            list_response = opensearch.list_domain_names()
            
            for domain_info in list_response.get('DomainNames', []):
                domain_name = domain_info.get('DomainName', '')
                try:
                    response = opensearch.describe_domain(DomainName=domain_name)
                    domain = response.get('DomainStatus', {})
                    
                    cluster_config = domain.get('ClusterConfig', {})
                    ebs_options = domain.get('EBSOptions', {})
                    
                    domains.append(OpenSearchDomainData(
                        domain_name=domain_name,
                        domain_arn=domain.get('ARN', ''),
                        instance_type=cluster_config.get('InstanceType', ''),
                        instance_count=cluster_config.get('InstanceCount', 1),
                        status='available' if not domain.get('Processing', True) else 'processing',
                        region=self._region,
                        engine_version=domain.get('EngineVersion', ''),
                        endpoint=domain.get('Endpoint'),
                        created=domain.get('Created'),
                        encrypted=domain.get('EncryptionAtRestOptions', {}).get('Enabled', False),
                        ebs_enabled=ebs_options.get('EBSEnabled', False),
                        ebs_volume_type=ebs_options.get('VolumeType', ''),
                        ebs_volume_size_gb=ebs_options.get('VolumeSize', 0),
                        deleted=bool(domain.get('Deleted', False)),
                    ))
                except ClientError as e:
                    logger.warning(f"Error describing OpenSearch domain {domain_name}: {e}")
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="OpenSearch Domains", permission="opensearch:ListDomainNames", error=e,
                )
                self._warn_access_denied("OpenSearch Domains", "opensearch:ListDomainNames", e)
                raise
            logger.error(f"Error fetching OpenSearch domains: {e}")
        
        return domains
    
    async def get_opensearch_metrics(
        self,
        domain_names: List[str],
        days: int = 14,
    ) -> Dict[str, OpenSearchMetricsData]:
        """Get CloudWatch metrics for OpenSearch domains.

        Review of #1535: the ClientId dimension is the 12-digit AWS account
        ID (``_aws_account_id``). It used to be ``self._account_id``, which
        in production is CloudWise's account UUID, so every read returned no
        datapoints and ``is_idle`` (0 searches) was True for every domain.
        Now:
        - an unresolvable account ID reads nothing: every domain is left out
          of the map and noted MISSING;
        - SearchRate and IndexingRate are read as DAILY series; their
          datapoint counts are reported, and ``is_idle`` needs SearchRate to
          cover 75% of the window's days (fewer is MISSING and noted, never
          idle);
        - a failed read leaves the domain out (MISSING, noted) instead of an
          all-zero model."""
        metrics = {}

        if not domain_names:
            return metrics

        client_id = self._aws_account_id()
        if not client_id:
            for domain_name in domain_names:
                self._note_idle_verdict_missing(
                    'opensearch', domain_name, "AWS account ID unresolved (ClientId)",
                )
            return metrics

        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            period = 86400  # 1-day granularity

            for domain_name in domain_names:
                try:
                    dims = [
                        {'Name': 'DomainName', 'Value': domain_name},
                        {'Name': 'ClientId', 'Value': client_id},
                    ]

                    # SearchRate, daily Sums: their count is the coverage
                    search_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ES', MetricName='SearchRate',
                        Dimensions=dims, StartTime=start_time, EndTime=end_time,
                        Period=period, Statistics=['Sum'],
                    )
                    search_dps = search_resp.get('Datapoints', [])
                    search_total = sum(dp.get('Sum', 0) for dp in search_dps)
                    search_covered = has_min_coverage(len(search_dps), days, period)
                    if not search_covered:
                        self._note_idle_verdict_missing(
                            'opensearch', domain_name,
                            "no SearchRate datapoints" if not search_dps
                            else "SearchRate under 75% coverage",
                        )

                    # IndexingRate, daily Averages
                    idx_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ES', MetricName='IndexingRate',
                        Dimensions=dims, StartTime=start_time, EndTime=end_time,
                        Period=period, Statistics=['Average'],
                    )
                    idx_avg = 0.0
                    idx_dps = idx_resp.get('Datapoints', [])
                    if idx_dps:
                        idx_avg = sum(dp.get('Average', 0) for dp in idx_dps) / len(idx_dps)
                    
                    # CPUUtilization (avg + max), HOURLY since CLO-480. It was
                    # daily (Period=86400) and the gate was the window max of
                    # the daily Maximums, so one spike vetoed the whole window.
                    # The shared rule (cpu_sizing) needs hourly datapoints for
                    # its percentiles and coverage: 168 for 7 days, well under
                    # GetMetricStatistics' 1,440-datapoint limit. On the
                    # DomainName/ClientId dimensions the Average is across data
                    # nodes and the Maximum is the busiest node.
                    cpu_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ES', MetricName='CPUUtilization',
                        Dimensions=dims, StartTime=start_time, EndTime=end_time,
                        Period=3600, Statistics=['Average', 'Maximum'],
                    )
                    cpu = summarize_hourly_cpu(cpu_resp.get('Datapoints', []))
                    cpu_avg, cpu_max = cpu.avg_cpu, cpu.max_cpu
                    
                    # JVMMemoryPressure (average)
                    jvm_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ES', MetricName='JVMMemoryPressure',
                        Dimensions=dims, StartTime=start_time, EndTime=end_time,
                        Period=86400 * days, Statistics=['Average'],
                    )
                    jvm_avg = 0.0
                    jvm_dps = jvm_resp.get('Datapoints', [])
                    if jvm_dps:
                        jvm_avg = sum(dp.get('Average', 0) for dp in jvm_dps) / len(jvm_dps)
                    
                    # FreeStorageSpace (average per day for trend)
                    fs_resp = cloudwatch.get_metric_statistics(
                        Namespace='AWS/ES', MetricName='FreeStorageSpace',
                        Dimensions=dims, StartTime=start_time, EndTime=end_time,
                        Period=period, Statistics=['Average'],
                    )
                    fs_avg = 0.0
                    fs_dps = fs_resp.get('Datapoints', [])
                    storage_growth_rate = 0.0
                    if fs_dps:
                        fs_avg = sum(dp.get('Average', 0) for dp in fs_dps) / len(fs_dps)
                        # FreeStorageSpace is in MB — compute growth from trend
                        if len(fs_dps) >= 2:
                            sorted_dps = sorted(fs_dps, key=lambda d: d['Timestamp'])
                            first_free_mb = sorted_dps[0].get('Average', 0)
                            last_free_mb = sorted_dps[-1].get('Average', 0)
                            delta_days = (sorted_dps[-1]['Timestamp'] - sorted_dps[0]['Timestamp']).total_seconds() / 86400
                            if delta_days > 0:
                                # Decreasing free space = positive growth
                                storage_growth_rate = (first_free_mb - last_free_mb) / 1024 / delta_days  # GB/day
                    
                    metrics[domain_name] = OpenSearchMetricsData(
                        domain_name=domain_name,
                        search_requests_total=int(search_total),
                        indexing_rate_avg=idx_avg,
                        cpu_utilization_avg=cpu_avg,
                        cpu_utilization_max=cpu_max,
                        cpu_p95=cpu.p95_cpu,
                        cpu_p95_max=cpu.p95_max_cpu,
                        cpu_datapoints=cpu.datapoints,
                        jvm_memory_pressure_avg=jvm_avg,
                        free_storage_space_avg=fs_avg,
                        storage_growth_rate_gb_per_day=max(storage_growth_rate, 0.0),
                        period_days=days,
                        is_idle=search_covered and search_total == 0,
                        search_datapoints=len(search_dps),
                        indexing_datapoints=len(idx_dps),
                    )
                except ClientError as e:
                    if self._is_access_denied(e):
                        self._record_permission_error(
                            resource="OpenSearch Metrics (per-resource)", permission="cloudwatch:GetMetricStatistics", error=e,
                        )
                        self._warn_access_denied("OpenSearch Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e)
                    logger.warning(f"Error fetching OpenSearch metrics for {domain_name}: {e}")
                    # A failed read is MISSING, not an all-zero (idle) model.
                    self._note_idle_verdict_missing(
                        'opensearch', domain_name, f"read failed ({self._error_label(e)})",
                    )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="OpenSearch Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("OpenSearch Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching OpenSearch metrics: {e}")
        
        return metrics
    
    # =========================================================================
    # CloudWatch Logs
    # =========================================================================
    
    async def get_cloudwatch_log_groups(self) -> List[CloudWatchLogGroupData]:
        """Get all CloudWatch Log Groups in the region.

        ``last_event_time`` is left None: DescribeLogGroups has no
        ``lastEventTimestamp`` (CLO-516, confirmed on the wire). Last
        activity comes from ``get_cloudwatch_log_group_last_activity``, for
        the candidates that need it."""
        log_groups = []
        try:
            logs = self._get_client('logs')
            all_groups = self._paginate(logs, 'describe_log_groups', 'logGroups')
            
            for group in all_groups:
                creation_time = group.get('creationTime')
                log_groups.append(CloudWatchLogGroupData(
                    log_group_name=group.get('logGroupName', ''),
                    region=self._region,
                    stored_bytes=group.get('storedBytes', 0),
                    retention_days=group.get('retentionInDays'),
                    creation_time=datetime.fromtimestamp(creation_time / 1000, tz=timezone.utc) if creation_time else None,
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="CloudWatch Log Groups", permission="logs:DescribeLogGroups", error=e,
                )
                self._warn_access_denied("CloudWatch Log Groups", "logs:DescribeLogGroups", e)
                raise
            logger.error(f"Error fetching CloudWatch log groups: {e}")
        
        return log_groups

    @staticmethod
    def _stream_last_activity(streams: List[Dict[str, Any]]) -> Optional[datetime]:
        """Latest of lastEventTimestamp / lastIngestionTime / creationTime
        across ``streams`` (epoch ms), or None when there are none.

        lastEventTimestamp is eventually consistent (AWS: usually within an
        hour of ingestion), so lastIngestionTime and the stream's own
        creation count too: any of them is evidence of activity, and taking
        the latest can only make a group look MORE recently active."""
        latest = None
        for stream in streams:
            for key in ('lastEventTimestamp', 'lastIngestionTime', 'creationTime'):
                value = stream.get(key)
                if value and (latest is None or value > latest):
                    latest = value
        if latest is None:
            return None
        return datetime.fromtimestamp(latest / 1000, tz=timezone.utc)

    async def get_cloudwatch_log_group_last_activity(
        self,
        log_group_names: List[str],
        deadline: Optional[float] = None,
    ) -> Dict[str, Optional[datetime]]:
        """CLO-516: last activity per group from its newest log stream.

        One ``DescribeLogStreams(orderBy=LastEventTime, descending=True,
        limit=1)`` per name, on a bounded, rate-limited pool (see
        ``_LOG_ACTIVITY_LOOKUP_WORKERS``). A group with no stream maps to
        None (it never received an event). A lookup that fails (throttled
        past the retries, AccessDenied, group deleted mid-scan) or that would
        start after ``deadline`` leaves the name OUT of the map, and every
        name left out is noted once in ``data_warnings``: MISSING, not zero.
        After an AccessDenied, no further lookup is made."""
        result: Dict[str, Optional[datetime]] = {}
        if not log_group_names:
            return result
        reasons: Dict[str, str] = {}
        try:
            logs = self._get_client('logs')
        except Exception as e:  # noqa: BLE001 - every name becomes MISSING
            reasons = {name: e.__class__.__name__ for name in log_group_names}
            self._note_missing_log_activity(reasons)
            return result

        limiter = _RateLimiter(_LOG_ACTIVITY_LOOKUP_MAX_RPS)
        denied = threading.Event()
        skipped_denied = object()
        skipped_budget = object()

        def work(name: str):
            if denied.is_set():
                return name, None, skipped_denied
            if deadline is not None and time.monotonic() >= deadline:
                return name, None, skipped_budget
            limiter.acquire()
            if deadline is not None and time.monotonic() >= deadline:
                return name, None, skipped_budget
            try:
                response = logs.describe_log_streams(
                    logGroupName=name,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=1,
                )
                return name, self._stream_last_activity(response.get('logStreams') or []), None
            except Exception as e:  # noqa: BLE001 - reported on the calling thread
                if self._is_access_denied(e):
                    denied.set()
                return name, None, e

        workers = max(1, min(_LOG_ACTIVITY_LOOKUP_WORKERS, len(log_group_names)))
        permission_recorded = False
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cw-log-activity") as pool:
            for name, activity, error in pool.map(work, log_group_names):
                if error is None:
                    result[name] = activity
                    continue
                if error is skipped_denied:
                    label = 'skipped after AccessDenied'
                elif error is skipped_budget:
                    label = 'time budget spent'
                elif isinstance(error, ClientError):
                    code = error.response.get('Error', {}).get('Code', '') or 'ClientError'
                    label = f"DescribeLogStreams:{code}"
                    if self._is_access_denied(error) and not permission_recorded:
                        permission_recorded = True
                        self._record_permission_error(
                            resource="CloudWatch Log Streams",
                            permission="logs:DescribeLogStreams",
                            error=error,
                        )
                        self._warn_access_denied(
                            "CloudWatch Log Streams", "logs:DescribeLogStreams", error,
                        )
                else:
                    label = error.__class__.__name__
                reasons[name] = label

        self._note_missing_log_activity(reasons)
        return result

    def _note_missing_log_activity(self, reasons: Dict[str, str]) -> None:
        """One aggregated ``data_warnings`` note (and one WARNING log) for
        the groups whose activity could not be read, ``{name: reason}``. A
        failed read also counts toward ``DetectorErrors``; a lookup skipped
        for time does not, because nothing failed."""
        if not reasons:
            return
        if any(label != 'time budget spent' for label in reasons.values()):
            self.swallowed_error_count += 1
        for name, label in reasons.items():
            self._note_idle_verdict_missing(
                'cloudwatch_logs', name, label,
                verdict='empty/stale log group', evidence='log stream activity reads',
            )

    async def get_cloudwatch_dashboards(self) -> List["CloudWatchDashboardData"]:
        """Get all CloudWatch Dashboards in the region."""
        from cloudwise_scan_core.data_providers.models import CloudWatchDashboardData
        dashboards = []
        try:
            cw = self._get_client('cloudwatch')
            response = cw.list_dashboards()
            for entry in response.get('DashboardEntries', []):
                dashboards.append(CloudWatchDashboardData(
                    dashboard_name=entry.get('DashboardName', ''),
                    dashboard_arn=entry.get('DashboardArn', ''),
                    region=self._region,
                    last_modified=entry.get('LastModified'),
                    size_bytes=entry.get('Size', 0),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="CloudWatch Dashboards", permission="cloudwatch:ListDashboards", error=e,
                )
                self._warn_access_denied("CloudWatch Dashboards", "cloudwatch:ListDashboards", e)
                raise
            logger.warning(f"Error fetching CloudWatch dashboards: {e}")
        return dashboards
    
    # =========================================================================
    # KMS
    # =========================================================================
    
    async def get_kms_keys(self) -> List[KMSKeyData]:
        """Get all customer-managed KMS keys in the region."""
        keys = []
        try:
            kms = self._get_client('kms')
            response = kms.list_keys()
            
            for key_entry in response.get('Keys', []):
                key_id = key_entry.get('KeyId', '')
                try:
                    key_info = kms.describe_key(KeyId=key_id)
                    metadata = key_info.get('KeyMetadata', {})
                    
                    # Skip AWS managed keys
                    if metadata.get('KeyManager') != 'CUSTOMER':
                        continue
                    
                    # CLO-368: this was a dead try/except (the try body was
                    # a bare `pass` — nothing here can ever raise
                    # ClientError). Removed rather than converted; there was
                    # nothing being swallowed. See report for justification.
                    # Note: computing this would need CloudTrail lookups,
                    # which would be slower; left unset for now.
                    days_since_last_use = None

                    keys.append(KMSKeyData(
                        key_id=key_id,
                        key_arn=metadata.get('Arn', ''),
                        key_state=metadata.get('KeyState', ''),
                        key_usage=metadata.get('KeyUsage', ''),
                        region=self._region,
                        description=metadata.get('Description'),
                        creation_date=metadata.get('CreationDate'),
                        enabled=metadata.get('Enabled', True),
                        days_since_last_use=days_since_last_use,
                    ))
                except ClientError as e:
                    logger.warning(f"Error describing KMS key {key_id}: {e}")
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="KMS Keys", permission="kms:ListKeys", error=e,
                )
                self._warn_access_denied("KMS Keys", "kms:ListKeys", e)
                raise
            logger.error(f"Error fetching KMS keys: {e}")
        
        return keys
    
    # =========================================================================
    # Secrets Manager
    # =========================================================================
    
    async def get_secrets(self) -> List[SecretsManagerSecretData]:
        """Get all Secrets Manager secrets in the region."""
        secrets = []
        try:
            secretsmanager = self._get_client('secretsmanager')
            all_secrets = self._paginate(secretsmanager, 'list_secrets', 'SecretList')
            
            for secret in all_secrets:
                last_accessed = secret.get('LastAccessedDate')
                days_since_access = None
                if last_accessed:
                    days_since_access = (datetime.now(timezone.utc) - last_accessed).days
                
                secrets.append(SecretsManagerSecretData(
                    secret_id=secret.get('ARN', ''),
                    secret_arn=secret.get('ARN', ''),
                    name=secret.get('Name', ''),
                    region=self._region,
                    description=secret.get('Description'),
                    created_date=secret.get('CreatedDate'),
                    last_accessed_date=last_accessed,
                    last_rotated_date=secret.get('LastRotatedDate'),
                    days_since_last_access=days_since_access,
                    rotation_enabled=secret.get('RotationEnabled', False),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Secrets", permission="secretsmanager:ListSecrets", error=e,
                )
                self._warn_access_denied("Secrets", "secretsmanager:ListSecrets", e)
                raise
            logger.error(f"Error fetching Secrets Manager secrets: {e}")
        
        return secrets
    
    # =========================================================================
    # SageMaker
    # =========================================================================
    
    async def get_sagemaker_notebooks(self) -> List[SageMakerNotebookData]:
        """Get all SageMaker notebook instances in the region.
        
        Uses ListNotebookInstances for basic info, then DescribeNotebookInstance
        for each to get VolumeSizeInGB (not returned by the List API).
        """
        notebooks = []
        try:
            sagemaker = self._get_client('sagemaker')
            response = sagemaker.list_notebook_instances()
            
            for notebook in response.get('NotebookInstances', []):
                name = notebook.get('NotebookInstanceName', '')
                
                # DescribeNotebookInstance is needed for VolumeSizeInGB
                # which the List API does not return
                volume_size_gb = 0
                try:
                    detail = sagemaker.describe_notebook_instance(
                        NotebookInstanceName=name
                    )
                    volume_size_gb = detail.get('VolumeSizeInGB', 0)
                except Exception as e:
                    logger.debug(f"Could not describe notebook {name}: {e}")
                
                notebooks.append(SageMakerNotebookData(
                    notebook_name=name,
                    notebook_arn=notebook.get('NotebookInstanceArn', ''),
                    instance_type=notebook.get('InstanceType', ''),
                    status=notebook.get('NotebookInstanceStatus', ''),
                    region=self._region,
                    creation_time=notebook.get('CreationTime'),
                    last_modified_time=notebook.get('LastModifiedTime'),
                    volume_size_gb=volume_size_gb,
                    url=notebook.get('Url'),
                ))
            
            logger.warning(f"SageMaker: found {len(notebooks)} notebooks in {self._region}")
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="SageMaker Notebooks", permission="sagemaker:ListNotebookInstances", error=e,
                )
                self._warn_access_denied("SageMaker Notebooks", "sagemaker:ListNotebookInstances", e)
                raise
            logger.error(f"Error fetching SageMaker notebooks: {e}")
        
        return notebooks
    
    async def get_sagemaker_endpoints(self) -> List[SageMakerEndpointData]:
        """Get all SageMaker endpoints in the region with instance details."""
        endpoints = []
        try:
            sagemaker = self._get_client('sagemaker')
            response = sagemaker.list_endpoints()
            
            for endpoint in response.get('Endpoints', []):
                # Describe each endpoint for instance_type and instance_count
                instance_type = None
                instance_count = 1
                try:
                    detail = sagemaker.describe_endpoint(
                        EndpointName=endpoint['EndpointName']
                    )
                    config_name = detail.get('EndpointConfigName')
                    if config_name:
                        config = sagemaker.describe_endpoint_config(
                            EndpointConfigName=config_name
                        )
                        variants = config.get('ProductionVariants', [])
                        if variants:
                            instance_type = variants[0].get('InstanceType')
                            instance_count = variants[0].get('InitialInstanceCount', 1)
                except Exception as e:
                    logger.debug(f"Could not describe endpoint {endpoint.get('EndpointName')}: {e}")
                
                endpoints.append(SageMakerEndpointData(
                    endpoint_name=endpoint.get('EndpointName', ''),
                    endpoint_arn=endpoint.get('EndpointArn', ''),
                    status=endpoint.get('EndpointStatus', ''),
                    region=self._region,
                    creation_time=endpoint.get('CreationTime'),
                    last_modified_time=endpoint.get('LastModifiedTime'),
                    instance_type=instance_type,
                    instance_count=instance_count,
                ))
            logger.warning(f"SageMaker: found {len(endpoints)} endpoints in {self._region}")
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="SageMaker Endpoints", permission="sagemaker:ListEndpoints", error=e,
                )
                self._warn_access_denied("SageMaker Endpoints", "sagemaker:ListEndpoints", e)
                raise
            logger.error(f"Error fetching SageMaker endpoints: {e}")
        
        return endpoints
    
    async def get_sagemaker_metrics(
        self,
        endpoint_names: List[str],
        days: int = 7,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, SageMakerMetricsData]:
        """Get CloudWatch metrics for SageMaker endpoints (Invocations, CPU, Memory).

        CLO-457: EndpointName is a name. With an endpoint's CreationTime in
        ``create_times``, every read starts at the creation time and drops
        datapoints from before it (see metric_window). The Invocations Sum is
        one window-long datapoint, so the start time is its only defence."""
        metrics = {}
        
        if not endpoint_names:
            return metrics
        
        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            
            for endpoint_name in endpoint_names:
                created = (create_times or {}).get(endpoint_name)
                start_time = metric_start_time(end_time, days, created)
                try:
                    # Invocations (AWS/SageMaker namespace)
                    inv_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/SageMaker',
                        MetricName='Invocations',
                        Dimensions=[
                            {'Name': 'EndpointName', 'Value': endpoint_name},
                            {'Name': 'VariantName', 'Value': 'AllTraffic'},
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Sum'],
                    )
                    inv_datapoints = drop_pre_creation_datapoints(
                        inv_response.get('Datapoints', []), created, 86400 * days,
                    )
                    total_invocations = sum(dp.get('Sum', 0) for dp in inv_datapoints)
                    
                    # CPU Utilization (/aws/sagemaker/Endpoints namespace — Container Insights)
                    cpu_avg = 0.0
                    try:
                        cpu_response = cloudwatch.get_metric_statistics(
                            Namespace='/aws/sagemaker/Endpoints',
                            MetricName='CPUUtilization',
                            Dimensions=[
                                {'Name': 'EndpointName', 'Value': endpoint_name},
                                {'Name': 'VariantName', 'Value': 'AllTraffic'},
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=['Average'],
                        )
                        cpu_datapoints = drop_pre_creation_datapoints(
                            cpu_response.get('Datapoints', []), created, 86400,
                        )
                        if cpu_datapoints:
                            cpu_avg = sum(dp.get('Average', 0) for dp in cpu_datapoints) / len(cpu_datapoints)
                    except Exception as e:
                        self._warn_swallowed(
                            "SageMaker endpoint CPU utilization", "cloudwatch:GetMetricStatistics", e,
                        )
                    
                    # Memory Utilization (/aws/sagemaker/Endpoints namespace — Container Insights)
                    mem_avg = 0.0
                    try:
                        mem_response = cloudwatch.get_metric_statistics(
                            Namespace='/aws/sagemaker/Endpoints',
                            MetricName='MemoryUtilization',
                            Dimensions=[
                                {'Name': 'EndpointName', 'Value': endpoint_name},
                                {'Name': 'VariantName', 'Value': 'AllTraffic'},
                            ],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400,
                            Statistics=['Average'],
                        )
                        mem_datapoints = drop_pre_creation_datapoints(
                            mem_response.get('Datapoints', []), created, 86400,
                        )
                        if mem_datapoints:
                            mem_avg = sum(dp.get('Average', 0) for dp in mem_datapoints) / len(mem_datapoints)
                    except Exception as e:
                        self._warn_swallowed(
                            "SageMaker endpoint memory utilization", "cloudwatch:GetMetricStatistics", e,
                        )
                    
                    metrics[endpoint_name] = SageMakerMetricsData(
                        endpoint_name=endpoint_name,
                        invocations_total=int(total_invocations),
                        invocations_avg=total_invocations / max(days, 1),
                        cpu_utilization_avg=cpu_avg,
                        memory_utilization_avg=mem_avg,
                        period_days=days,
                        is_idle=total_invocations == 0,
                    )
                except ClientError as e:
                    self._warn_swallowed(
                        "SageMaker Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e,
                    )
                    # CLO-485: a failed read is MISSING, not zero. The default
                    # model's invocations_total=0 read as an idle endpoint.
                    self._note_idle_verdict_missing(
                        'sagemaker', endpoint_name, f"read failed ({self._error_label(e)})",
                    )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="SageMaker Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("SageMaker Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching SageMaker metrics: {e}")
        
        return metrics
    
    # =========================================================================
    # Kinesis
    # =========================================================================
    
    async def get_kinesis_streams(self) -> List[KinesisStreamData]:
        """Get all Kinesis streams in the region."""
        streams = []
        try:
            kinesis = self._get_client('kinesis')
            response = kinesis.list_streams()
            
            for stream_name in response.get('StreamNames', []):
                try:
                    desc_response = kinesis.describe_stream_summary(StreamName=stream_name)
                    summary = desc_response.get('StreamDescriptionSummary', {})
                    
                    streams.append(KinesisStreamData(
                        stream_name=stream_name,
                        stream_arn=summary.get('StreamARN', ''),
                        status=summary.get('StreamStatus', ''),
                        region=self._region,
                        shard_count=summary.get('OpenShardCount', 1),
                        retention_period_hours=summary.get('RetentionPeriodHours', 24),
                        encryption_type=summary.get('EncryptionType'),
                        created_time=summary.get('StreamCreationTimestamp'),
                    ))
                except ClientError as e:
                    logger.warning(f"Error describing Kinesis stream {stream_name}: {e}")
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Kinesis Streams", permission="kinesis:ListStreams", error=e,
                )
                self._warn_access_denied("Kinesis Streams", "kinesis:ListStreams", e)
                raise
            logger.error(f"Error fetching Kinesis streams: {e}")
        
        return streams
    
    async def get_kinesis_metrics(
        self,
        stream_names: List[str],
        days: int = 7,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, KinesisMetricsData]:
        """Get CloudWatch metrics for Kinesis streams.

        CLO-457: StreamName is a name. With a stream's
        StreamCreationTimestamp in ``create_times``, every read starts at the
        creation time and drops datapoints from before it (see
        metric_window). The record Sums are one window-long datapoint, so the
        start time is their only defence."""
        metrics = {}
        
        if not stream_names:
            return metrics
        
        try:
            cloudwatch = self._get_client('cloudwatch')
            kinesis = self._get_client('kinesis')
            end_time = datetime.now(timezone.utc)

            for stream_name in stream_names:
                created = (create_times or {}).get(stream_name)
                start_time = metric_start_time(end_time, days, created)
                try:
                    # Stream mode (PROVISIONED vs ON_DEMAND) — required by the
                    # kinesis_on_demand_downgrade detector, which only fires on
                    # ON_DEMAND streams. Defaults to PROVISIONED if unavailable.
                    stream_mode = 'PROVISIONED'
                    try:
                        summary = kinesis.describe_stream_summary(
                            StreamName=stream_name
                        ).get('StreamDescriptionSummary', {})
                        stream_mode = summary.get('StreamModeDetails', {}).get('StreamMode', 'PROVISIONED')
                    except ClientError as e:
                        logger.warning(f"Error describing Kinesis stream mode for {stream_name}: {e}")

                    # IncomingRecords (total)
                    response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Kinesis',
                        MetricName='IncomingRecords',
                        Dimensions=[{'Name': 'StreamName', 'Value': stream_name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Sum'],
                    )
                    
                    datapoints = drop_pre_creation_datapoints(
                        response.get('Datapoints', []), created, 86400 * days,
                    )
                    incoming_records = sum(dp.get('Sum', 0) for dp in datapoints)

                    # IncomingBytes (daily breakdown for CV calculation)
                    bytes_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Kinesis',
                        MetricName='IncomingBytes',
                        Dimensions=[{'Name': 'StreamName', 'Value': stream_name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400,
                        Statistics=['Sum'],
                    )
                    sorted_bytes = sorted(
                        drop_pre_creation_datapoints(bytes_response.get('Datapoints', []), created, 86400),
                        key=lambda x: x['Timestamp'],
                    )
                    daily_bytes = [dp.get('Sum', 0) for dp in sorted_bytes]
                    total_bytes = sum(daily_bytes)

                    # GetRecords.Records (consumer activity detection)
                    get_records_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/Kinesis',
                        MetricName='GetRecords.Records',
                        Dimensions=[{'Name': 'StreamName', 'Value': stream_name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Sum'],
                    )
                    get_records_total = sum(dp.get('Sum', 0) for dp in drop_pre_creation_datapoints(
                        get_records_response.get('Datapoints', []), created, 86400 * days,
                    ))

                    metrics[stream_name] = KinesisMetricsData(
                        stream_name=stream_name,
                        incoming_records_total=int(incoming_records),
                        incoming_bytes_total=int(total_bytes),
                        incoming_bytes_daily=daily_bytes if daily_bytes else None,
                        get_records_total=int(get_records_total),
                        period_days=days,
                        is_idle=incoming_records == 0,
                        stream_mode=stream_mode,
                    )
                except ClientError as e:
                    self._warn_swallowed(
                        "Kinesis Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e,
                    )
                    # CLO-485: a failed read is MISSING, not zero. The default
                    # model's 0 records read as an idle stream (and 0 reads as
                    # extended-retention waste). The detector skips a stream
                    # with no metrics.
                    self._note_idle_verdict_missing(
                        'kinesis', stream_name, f"read failed ({self._error_label(e)})",
                    )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Kinesis Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Kinesis Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching Kinesis metrics: {e}")
        
        return metrics

    async def get_kinesis_consumers(self, stream_arn: str) -> List[KinesisConsumerData]:
        """Get enhanced fan-out consumers for a Kinesis stream."""
        consumers = []
        try:
            kinesis = self._get_client('kinesis')
            response = kinesis.list_stream_consumers(StreamARN=stream_arn)
            for c in response.get('Consumers', []):
                consumers.append(KinesisConsumerData(
                    consumer_name=c['ConsumerName'],
                    consumer_arn=c['ConsumerARN'],
                    stream_arn=stream_arn,
                    consumer_status=c.get('ConsumerStatus', ''),
                    consumer_creation_timestamp=c.get('ConsumerCreationTimestamp'),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Kinesis Consumers", permission="kinesis:ListStreamConsumers", error=e,
                )
                self._warn_access_denied("Kinesis Consumers", "kinesis:ListStreamConsumers", e)
                raise
            logger.warning(f"Error listing Kinesis consumers: {e}")
        return consumers

    async def get_kinesis_consumer_metrics(
        self,
        stream_name: str,
        consumer_name: str,
        days: int = 14,
        consumer_create_time: Optional[datetime] = None,
    ) -> Optional[KinesisMetricsData]:
        """Get CloudWatch metrics for a specific enhanced fan-out consumer.

        CLO-485: None when the read fails (MISSING, not zero), instead of a
        default model whose 0 reads made the consumer look idle.

        CLO-457: with ``consumer_create_time`` the read starts at the
        consumer's creation (StreamName and ConsumerName are both names).

        CLO-589: an enhanced fan-out consumer never calls GetRecords (botocore:
        GetRecordsInput is ShardIterator/Limit/StreamARN, no consumer; records
        are pushed over SubscribeToShard), so the old GetRecords.Records read
        by ConsumerName was always empty and every consumer read as idle. The
        read is now SubscribeToShardEvent.Records (StreamName, ConsumerName).
        That name is not in botocore and could not be checked against the AWS
        docs from the session that wrote this, so an EMPTY series is MISSING
        (noted, None), never zero reads: if the name were wrong the detector
        goes quiet instead of firing on every consumer. Only a published
        series that sums to 0 is idle."""
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = metric_start_time(end_time, days, consumer_create_time)

            response = cw.get_metric_statistics(
                Namespace='AWS/Kinesis',
                MetricName='SubscribeToShardEvent.Records',
                Dimensions=[
                    {'Name': 'StreamName', 'Value': stream_name},
                    {'Name': 'ConsumerName', 'Value': consumer_name},
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400 * days,
                Statistics=['Sum'],
            )
            datapoints = drop_pre_creation_datapoints(
                response.get('Datapoints', []), consumer_create_time, 86400 * days,
            )
            if not datapoints:
                self._note_idle_verdict_missing(
                    'kinesis', f"{stream_name}/{consumer_name}", "no datapoints",
                )
                return None
            records = sum(dp.get('Sum', 0) for dp in datapoints)
            return KinesisMetricsData(
                stream_name=stream_name,
                get_records_total=int(records),
                period_days=days,
                is_idle=records == 0,
            )
        except Exception as e:
            self._warn_swallowed("Kinesis Consumer Metrics", "cloudwatch:GetMetricStatistics", e)
            self._note_idle_verdict_missing(
                'kinesis', f"{stream_name}/{consumer_name}", f"read failed ({self._error_label(e)})",
            )
            return None

    # CLO-589 follow-up: ListMetrics pages read per consumer (500 metrics per
    # page; a consumer has a handful). Running out of pages is MISSING.
    _KINESIS_CONSUMER_LIST_METRICS_MAX_PAGES = 10

    async def get_kinesis_consumer_subscribed(
        self, stream_name: str, consumer_name: str,
    ) -> Optional[bool]:
        """CLO-589 follow-up (PR #1654 review HIGH 1): see
        WasteDataProvider.get_kinesis_consumer_subscribed.

        One ListMetrics read in AWS/Kinesis filtered on BOTH StreamName and
        ConsumerName, paged to the end, no MetricName and no RecentlyActive
        filter (ListMetrics then covers the past two weeks). Any series
        returned counts as subscribed; AWS publishes only SubscribeToShard*
        under that pair, and SubscribeToShard.Success at least once every 5
        minutes while a subscription lives, so counting any of them is the
        conservative superset. False only on a complete, successful answer
        with none. A failed, denied or truncated read is None, noted.
        Monitoring template 1.29.0 grants cloudwatch:ListMetrics, so a
        denial (an older stack) is noted per consumer AND recorded once per
        provider as a permission error, which is what puts the account in
        line for the CLO-534 targeted notice (same as the CLO-533 VPC
        endpoint guard). The verdict stays None either way."""
        resource_id = f"{stream_name}/{consumer_name}"
        try:
            cw = self._get_client('cloudwatch')
            kwargs: Dict[str, Any] = {
                'Namespace': 'AWS/Kinesis',
                'Dimensions': [
                    {'Name': 'StreamName', 'Value': stream_name},
                    {'Name': 'ConsumerName', 'Value': consumer_name},
                ],
            }
            for _ in range(self._KINESIS_CONSUMER_LIST_METRICS_MAX_PAGES):
                page = cw.list_metrics(**kwargs)
                # The filter ran server-side: any series returned is one
                # under this (StreamName, ConsumerName), so it counts.
                if page.get('Metrics'):
                    return True
                token = page.get('NextToken')
                if not token:
                    return False
                kwargs = {**kwargs, 'NextToken': token}
            reason = 'ListMetrics answer truncated'
        except Exception as e:
            if self._is_access_denied(e):
                logger.info(
                    "kinesis: cloudwatch:ListMetrics denied in %s; enhanced fan-out "
                    "consumers cannot be judged and are withheld", self._region,
                )
                reason = 'cloudwatch:ListMetrics denied'
                # Once per provider: permission_missing dedupes, but the
                # human-readable permission_errors list does not, and every
                # consumer in the region would be denied the same way.
                if not getattr(self, '_kinesis_list_metrics_denial_recorded', False):
                    self._kinesis_list_metrics_denial_recorded = True
                    self._record_permission_error(
                        resource="Kinesis consumer subscription check",
                        permission="cloudwatch:ListMetrics", error=e,
                    )
            else:
                self._warn_swallowed("Kinesis consumer subscription check", "cloudwatch:ListMetrics", e)
                reason = f"ListMetrics read failed ({self._error_label(e)})"
        self._note_idle_verdict_missing(
            KINESIS_EFO_NOTE_SERVICE, resource_id, reason,
            verdict=KINESIS_EFO_NOTE_VERDICT, evidence=KINESIS_EFO_NOTE_EVIDENCE,
        )
        return None

    async def get_firehose_delivery_streams(self) -> List[KinesisFirehoseData]:
        """Get all Kinesis Data Firehose delivery streams."""
        streams = []
        try:
            firehose = self._get_client('firehose')
            response = firehose.list_delivery_streams()
            for name in response.get('DeliveryStreamNames', []):
                try:
                    desc = firehose.describe_delivery_stream(DeliveryStreamName=name)
                    ds = desc.get('DeliveryStreamDescription', {})
                    has_lambda = False
                    for dest in ds.get('Destinations', []):
                        for key in dest:
                            if isinstance(dest[key], dict):
                                proc = dest[key].get('ProcessingConfiguration', {})
                                if proc.get('Enabled'):
                                    has_lambda = True
                                    break

                    streams.append(KinesisFirehoseData(
                        delivery_stream_name=name,
                        delivery_stream_arn=ds.get('DeliveryStreamARN', ''),
                        delivery_stream_status=ds.get('DeliveryStreamStatus', ''),
                        delivery_stream_type=ds.get('DeliveryStreamType', ''),
                        source_stream_arn=ds.get('Source', {}).get('KinesisStreamSourceDescription', {}).get('KinesisStreamARN'),
                        has_lambda_transform=has_lambda,
                        destination_type=ds.get('Destinations', [{}])[0].get('DestinationId', ''),
                        region=self._region,
                        create_time=ds.get('CreateTimestamp'),  # CLO-457
                    ))
                except ClientError as e:
                    logger.warning(f"Error describing Firehose stream {name}: {e}")
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Firehose Delivery Streams", permission="firehose:ListDeliveryStreams", error=e,
                )
                self._warn_access_denied("Firehose Delivery Streams", "firehose:ListDeliveryStreams", e)
                raise
            logger.error(f"Error listing Firehose delivery streams: {e}")
        return streams

    async def get_firehose_metrics(
        self,
        delivery_stream_names: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, KinesisFirehoseMetricsData]:
        """Get CloudWatch metrics for Firehose delivery streams.

        CLO-457: DeliveryStreamName is a reusable name. With a stream's
        CreateTimestamp in ``create_times``, its reads start at it. Each Sum
        is ONE window-long datapoint, so the start time is the only defence
        (there is no per-day timestamp to filter on); the idle detector also
        requires a stream as old as the window."""
        metrics = {}
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)

            for name in delivery_stream_names:
                created = (create_times or {}).get(name)
                start_time = metric_start_time(end_time, days, created)
                try:
                    response = cw.get_metric_statistics(
                        Namespace='AWS/Firehose',
                        MetricName='IncomingRecords',
                        Dimensions=[{'Name': 'DeliveryStreamName', 'Value': name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Sum'],
                    )
                    records = sum(dp.get('Sum', 0) for dp in response.get('Datapoints', []))

                    bytes_response = cw.get_metric_statistics(
                        Namespace='AWS/Firehose',
                        MetricName='IncomingBytes',
                        Dimensions=[{'Name': 'DeliveryStreamName', 'Value': name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Sum'],
                    )
                    total_bytes = sum(dp.get('Sum', 0) for dp in bytes_response.get('Datapoints', []))

                    metrics[name] = KinesisFirehoseMetricsData(
                        delivery_stream_name=name,
                        incoming_records_total=int(records),
                        incoming_bytes_total=int(total_bytes),
                        period_days=days,
                        is_idle=records == 0 and total_bytes == 0,
                    )
                except ClientError as e:
                    if self._is_access_denied(e):
                        self._record_permission_error(
                            resource="Firehose Metrics (per-resource)", permission="cloudwatch:GetMetricStatistics", error=e,
                        )
                        self._warn_access_denied("Firehose Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e)
                    logger.warning(f"Error fetching Firehose metrics for {name}: {e}")
                    metrics[name] = KinesisFirehoseMetricsData(delivery_stream_name=name, period_days=days)
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Firehose Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Firehose Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching Firehose metrics: {e}")
        return metrics

    # =========================================================================
    # MSK
    # =========================================================================

    async def get_msk_clusters(self) -> List[MSKClusterData]:
        """Get MSK clusters from the AWS API."""
        clusters = []
        try:
            msk = self._get_client('kafka')
            response = msk.list_clusters()

            for c in response.get('ClusterInfoList', []):
                clusters.append(MSKClusterData(
                    cluster_name=c.get('ClusterName', ''),
                    cluster_arn=c.get('ClusterArn', ''),
                    # CLO-549: None when absent (no 3-broker guess); the
                    # per-broker metric read then withholds its verdicts.
                    broker_count=c.get('NumberOfBrokerNodes'),
                    instance_type=c.get('BrokerNodeGroupInfo', {}).get(
                        'InstanceType', 'kafka.m5.large'
                    ),
                    cluster_type=c.get('ClusterType', 'PROVISIONED'),
                    state=c.get('State', 'ACTIVE'),
                    tags=c.get('Tags', {}),
                    creation_time=c.get('CreationTime'),  # CLO-457
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="MSK Clusters", permission="kafka:ListClusters", error=e,
                )
                self._warn_access_denied("MSK Clusters", "kafka:ListClusters", e)
                raise
            logger.error(f"Error fetching MSK clusters: {e}")
        except Exception as e:
            logger.debug(f"MSK not available in this region: {e}")

        return clusters

    def _fetch_msk_broker_batch(
        self,
        cloudwatch,
        cluster_name: str,
        broker_ids: List[str],
        probe_broker_id: Optional[str],
        start_time: datetime,
        end_time: datetime,
    ) -> Tuple[Dict[Tuple[str, str], List[Dict[str, Any]]], Dict[Tuple[str, str], str]]:
        """CLO-549: hourly Average of every ``_MSK_BROKER_METRICS`` metric for
        up to ``_MSK_BROKERS_PER_METRIC_DATA_CALL`` brokers of one cluster in
        one ``GetMetricData`` request (plus NextToken pages).

        AWS/Kafka publishes these metrics per broker, with the dimensions
        "Cluster Name" + "Broker ID" (DEFAULT monitoring level, free); a
        "Cluster Name"-only query matches no series. ``probe_broker_id`` adds
        one MessagesInPerSec query for the broker id just past the reported
        count (see ``get_msk_metrics``).

        Returns ``(series, failed)``, both keyed by ``(broker_id,
        metric_name)``: ``series`` holds GetMetricStatistics-shaped
        datapoints (``Timestamp``, ``Average``) in ascending time; ``failed``
        maps a query whose data cannot be trusted to its status. Query Ids
        are positional (``msg_3``). A ``ClientError`` propagates.
        """
        targets: List[Tuple[str, str, str]] = []  # (query id, broker id, metric)
        for idx, broker_id in enumerate(broker_ids):
            for prefix, metric_name in _MSK_BROKER_METRICS:
                targets.append((f'{prefix}_{idx}', broker_id, metric_name))
        if probe_broker_id is not None:
            targets.append(('probe', probe_broker_id, 'MessagesInPerSec'))

        queries = [{
            'Id': query_id,
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/Kafka',
                    'MetricName': metric_name,
                    'Dimensions': [
                        {'Name': 'Cluster Name', 'Value': cluster_name},
                        {'Name': 'Broker ID', 'Value': broker_id},
                    ],
                },
                'Period': 3600,  # hourly, as GetMetricStatistics used
                'Stat': 'Average',
            },
            'ReturnData': True,
        } for query_id, broker_id, metric_name in targets]

        points: Dict[str, Dict[Any, float]] = {q['Id']: {} for q in queries}
        status: Dict[str, str] = {}
        next_token: Optional[str] = None
        while True:
            request: Dict[str, Any] = {
                'MetricDataQueries': queries,
                'StartTime': start_time,
                'EndTime': end_time,
                'ScanBy': 'TimestampAscending',
            }
            if next_token:
                request['NextToken'] = next_token
            response = cloudwatch.get_metric_data(**request)
            next_token = response.get('NextToken')
            for result in response.get('MetricDataResults', []):
                query_id = result.get('Id')
                if query_id not in points:
                    continue
                for ts, value in zip(result.get('Timestamps', []), result.get('Values', [])):
                    points[query_id][ts] = value
                code = result.get('StatusCode', 'Complete')
                # As the EC2 batch (CLO-499): a failed query stays failed;
                # PartialData only counts on the last page.
                if code in ('InternalError', 'Forbidden') or (code != 'Complete' and not next_token):
                    status.setdefault(query_id, code)
            if not next_token:
                break

        series: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        failed: Dict[Tuple[str, str], str] = {}
        for query_id, broker_id, metric_name in targets:
            key = (broker_id, metric_name)
            if query_id in status:
                failed[key] = status[query_id]
                continue
            series[key] = [
                {'Timestamp': ts, 'Average': points[query_id][ts]}
                for ts in sorted(points[query_id])
            ]
        return series, failed

    async def get_msk_metrics(
        self,
        cluster_name: str,
        days: int = 7,
        created: Optional[datetime] = None,
        broker_count: Optional[int] = None,
    ) -> Optional[MSKMetrics]:
        """Get CloudWatch metrics for an MSK cluster, read per broker.

        Args:
            cluster_name: MSK cluster name
            days: Number of days to analyse (default 7)
            created: the cluster's CreationTime (CLO-457). "Cluster Name" is
                a reusable name, so every read starts at it and drops hourly
                datapoints from before it (see metric_window).
            broker_count: ListClusters' NumberOfBrokerNodes (CLO-549).

        CLO-549: AWS/Kafka publishes MessagesInPerSec, BytesInPerSec,
        BytesOutPerSec, CpuUser and CpuSystem per broker ("Cluster Name" +
        "Broker ID", DEFAULT monitoring level, Standard and Express brokers
        alike). The old "Cluster Name"-only query matched no series, so both
        MSK checks never fired. The brokers are read as ids "1".."N" from
        NumberOfBrokerNodes (MSK numbers brokers from 1), because the scan
        role grants kafka:ListClusters but not kafka:ListNodes. These guards
        turn most wrong guesses into a withheld verdict:

        * every broker 1..N must have its own datapoints for a metric, the
          latest within ``_MSK_FRESH_HOURS`` of the window's end, or the
          metric is MISSING for the cluster (a broker id that does not exist,
          or a broker removed during the window, leaves an empty or stale
          series);
        * broker N+1 is probed (one MessagesInPerSec query): if it published
          anything in the window, the count is not the cluster's whole set
          of brokers and the traffic verdict is MISSING.

        Known gap (a wrong guess is NOT always withheld): live ids that are
        not 1..N, with the ids in 1..N removed less than
        ``_MSK_FRESH_HOURS`` before the scan and broker N+1 silent all
        window. E.g. live brokers {1, 2, 6, 7}, NumberOfBrokerNodes 4,
        brokers 3 and 4 removed an hour ago, broker 5 gone before the
        window: 3 and 4 still look fresh, 6 and 7 are never read, and the
        probe (5) is silent, so busy brokers 6 and 7 are missed. Broker
        removal is rare and recent; kafka:ListNodes would close the gap but
        needs a new template permission.

        Aggregation: traffic is the SUM across brokers of each broker's mean;
        CPU is the MAX across brokers of each broker's mean CpuUser +
        CpuSystem (AWS's sizing guidance reads total CPU as user + system),
        reported in ``cpu_user``. ``cpu_datapoints`` is the fewest CPU hours
        of any broker, and 0 when any broker's CPU is MISSING.

        A series left empty (nothing published, or all of it a deleted
        namesake's) is MISSING, never idle: with MessagesInPerSec or
        BytesInPerSec unmeasured on any broker this returns None (noted).
        Idle also needs BytesOutPerSec measured and zero on every broker (a
        consumer-only cluster is in use); unmeasured BytesOut returns None.
        BytesInPerSec is published only once a topic exists, so a cluster
        that never had a topic is withheld too, not called idle. Unmeasured
        BytesOutPerSec returns None for both verdicts (oversized would read
        it as network headroom), and unmeasured CPU gives
        ``cpu_datapoints`` 0, which vetoes oversized.

        Returns:
            MSKMetrics object with utilisation data, or None on error or
            when traffic was not measured
        """
        if isinstance(broker_count, bool) or not isinstance(broker_count, int) or broker_count < 1:
            self._note_idle_verdict_missing(
                'msk', cluster_name, 'broker count unknown', evidence='per-broker traffic metrics',
            )
            return None

        broker_ids = [str(i) for i in range(1, broker_count + 1)]
        probe_id = str(broker_count + 1)
        series: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        failed: Dict[Tuple[str, str], str] = {}
        try:
            cloudwatch = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = metric_start_time(end_time, days, created)
            for chunk_start in range(0, len(broker_ids), _MSK_BROKERS_PER_METRIC_DATA_CALL):
                chunk = broker_ids[chunk_start:chunk_start + _MSK_BROKERS_PER_METRIC_DATA_CALL]
                is_last = chunk_start + _MSK_BROKERS_PER_METRIC_DATA_CALL >= len(broker_ids)
                chunk_series, chunk_failed = self._fetch_msk_broker_batch(
                    cloudwatch, cluster_name, chunk, probe_id if is_last else None,
                    start_time, end_time,
                )
                series.update(chunk_series)
                failed.update(chunk_failed)
        except Exception as e:  # noqa: BLE001 — MISSING, never idle
            self._warn_swallowed("MSK Metrics", "cloudwatch:GetMetricData", e)
            self._note_idle_verdict_missing(
                'msk', cluster_name, f"read failed ({self._error_label(e)})",
                evidence='per-broker traffic metrics',
            )
            logger.error(f"Error getting metrics for MSK {cluster_name}: {e}")
            return None

        fresh_after = end_time - timedelta(hours=_MSK_FRESH_HOURS)

        def _own(broker_id: str, metric_name: str) -> Optional[List[Dict[str, Any]]]:
            """The broker's own, fresh datapoints, or None when MISSING."""
            if (broker_id, metric_name) in failed:
                return None
            dps = drop_pre_creation_datapoints(
                series.get((broker_id, metric_name), []), created, 3600,
            )
            if not dps:
                return None
            latest = max(
                (ts for ts in (_as_utc(d.get('Timestamp')) for d in dps) if ts is not None),
                default=None,
            )
            if latest is None or latest < fresh_after:
                return None
            return list(dps)

        def _mean(dps: List[Dict[str, Any]]) -> float:
            return sum(d.get('Average', 0) for d in dps) / len(dps)

        def _per_broker(metric_name: str) -> Tuple[Optional[Dict[str, float]], str]:
            """Each broker's mean, or (None, why) when any broker is MISSING."""
            means: Dict[str, float] = {}
            for broker_id in broker_ids:
                dps = _own(broker_id, metric_name)
                if dps is not None:
                    means[broker_id] = _mean(dps)
            if len(means) == len(broker_ids):
                return means, ''
            bad = sorted({failed[(b, metric_name)] for b in broker_ids if (b, metric_name) in failed})
            if bad:
                return None, f"read failed (GetMetricData status {'/'.join(bad)})"
            if not means:
                return None, 'no datapoints'
            return None, f"partial broker coverage ({len(means)} of {len(broker_ids)} brokers)"

        msg_means, msg_why = _per_broker('MessagesInPerSec')
        bin_means, bin_why = _per_broker('BytesInPerSec')
        if msg_means is None or bin_means is None:
            # CLO-457/CLO-549: unmeasured traffic, on any broker, is MISSING.
            # Both verdicts need it (idle reads it as zero, oversized as
            # network headroom).
            self._note_idle_verdict_missing(
                'msk', cluster_name, msg_why or bin_why, evidence='per-broker traffic metrics',
            )
            return None

        probe = series.get((probe_id, 'MessagesInPerSec'), [])
        probe = drop_pre_creation_datapoints(probe, created, 3600)
        if probe or (probe_id, 'MessagesInPerSec') in failed:
            # A broker past NumberOfBrokerNodes published (or could not be
            # ruled out): brokers 1..N are not the whole cluster.
            self._note_idle_verdict_missing(
                'msk', cluster_name, 'broker ids beyond the reported count',
                evidence='per-broker traffic metrics',
            )
            return None

        messages_in = sum(msg_means.values())
        bytes_in = sum(bin_means.values())
        bout_means, bout_why = _per_broker('BytesOutPerSec')
        if bout_means is None:
            # Both verdicts need BytesOut: a consumer-only cluster (no
            # inbound, consumers still reading) is NOT idle, and oversized
            # would read it as network headroom. Unmeasured is MISSING.
            self._note_idle_verdict_missing(
                'msk', cluster_name, bout_why,
                verdict='idle' if messages_in == 0 and bytes_in == 0 else 'oversized',
                evidence='per-broker BytesOutPerSec',
            )
            return None
        bytes_out = sum(bout_means.values())
        # Idle needs no inbound AND no outbound traffic on any broker.
        is_idle = messages_in == 0 and bytes_in == 0 and bytes_out == 0

        # CPU: per broker, the hours with both CpuUser and CpuSystem; the
        # cluster's figure is the busiest broker's mean user + system.
        cpu_by_broker: Dict[str, float] = {}
        cpu_hours: List[int] = []
        for broker_id in broker_ids:
            user = _own(broker_id, 'CpuUser')
            system = _own(broker_id, 'CpuSystem')
            if user is None or system is None:
                continue
            system_by_ts = {d.get('Timestamp'): d.get('Average', 0) for d in system}
            totals = [
                d.get('Average', 0) + system_by_ts[d.get('Timestamp')]
                for d in user if d.get('Timestamp') in system_by_ts
            ]
            if not totals:
                continue
            cpu_by_broker[broker_id] = sum(totals) / len(totals)
            cpu_hours.append(len(totals))
        cpu_measured = len(cpu_by_broker) == len(broker_ids)
        cpu_total = max(cpu_by_broker.values()) if cpu_measured else 0.0
        cpu_datapoints = min(cpu_hours) if cpu_measured else 0
        if not cpu_measured and not is_idle:
            self._note_idle_verdict_missing(
                'msk', cluster_name, 'no datapoints' if not cpu_by_broker else
                f"partial broker coverage ({len(cpu_by_broker)} of {len(broker_ids)} brokers)",
                verdict='oversized', evidence='per-broker CPU metrics',
            )

        return MSKMetrics(
            messages_in_per_sec=round(messages_in, 2),
            bytes_in_per_sec=round(bytes_in, 2),
            bytes_out_per_sec=round(bytes_out, 2),
            cpu_user=round(cpu_total, 2),
            period_days=days,
            is_idle=is_idle,
            cpu_datapoints=cpu_datapoints,
        )

    # =========================================================================
    # AMIs
    # =========================================================================

    async def get_amis(self) -> List[AMIData]:
        """Get AMIs owned by the account in this region."""
        amis = []
        try:
            ec2 = self._get_client('ec2')
            response = ec2.describe_images(Owners=['self'])

            for image in response.get('Images', []):
                creation_date = None
                if image.get('CreationDate'):
                    creation_date = datetime.fromisoformat(
                        image['CreationDate'].replace('Z', '+00:00')
                    )

                amis.append(AMIData(
                    image_id=image.get('ImageId', ''),
                    name=image.get('Name'),
                    state=image.get('State', ''),
                    region=self._region,
                    creation_date=creation_date,
                    description=image.get('Description'),
                    tags=self._tags_to_dict(image.get('Tags', [])),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="AMIs", permission="ec2:DescribeImages", error=e,
                )
                self._warn_access_denied("AMIs", "ec2:DescribeImages", e)
                raise
            logger.error(f"Error fetching AMIs: {e}")

        return amis

    # =========================================================================
    # ECS / Fargate
    # =========================================================================

    def get_ecs_clusters(self) -> List[Dict[str, Any]]:
        """Get all ECS clusters via boto3."""
        try:
            ecs = self._get_client('ecs')
            cluster_arns = []
            paginator = ecs.get_paginator('list_clusters')
            for page in paginator.paginate():
                cluster_arns.extend(page.get('clusterArns', []))

            if not cluster_arns:
                return []

            all_clusters = []
            for i in range(0, len(cluster_arns), 100):
                batch = cluster_arns[i:i + 100]
                response = ecs.describe_clusters(
                    clusters=batch,
                    include=['ATTACHMENTS', 'SETTINGS', 'STATISTICS']
                )
                all_clusters.extend(response.get('clusters', []))
            return all_clusters
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="ECS Clusters", permission="ecs:ListClusters", error=e,
                )
                self._warn_access_denied("ECS Clusters", "ecs:ListClusters", e)
                raise
            logger.debug(f"Failed to get ECS clusters: {e}")
            return []

    def get_ecs_services(self, cluster_arn: str) -> List[Dict[str, Any]]:
        """Get ECS services for a cluster via boto3.

        CLO-551: a failed list-services used to return [] (a cluster with
        no services, so ecs_container_insights_waste read it as small and
        idle), a failed describe-services batch dropped the services read
        before it, and a denial raised, which aborted every ECS check in the
        region. Now the services read are returned and
        :meth:`ecs_services_unread` says the list is incomplete; a denial is
        still recorded as a permission error."""
        unread: Dict[str, str] = self.__dict__.setdefault('_ecs_services_unread', {})
        unread.pop(cluster_arn, None)
        try:
            ecs = self._get_client('ecs')
            service_arns = []
            paginator = ecs.get_paginator('list_services')
            for page in paginator.paginate(cluster=cluster_arn, maxResults=100):
                service_arns.extend(page.get('serviceArns', []))
        except Exception as e:
            unread[cluster_arn] = 'service list not read'
            self._warn_swallowed("ECS services", "ecs:ListServices", e)
            return []

        all_services = []
        for i in range(0, len(service_arns), 10):
            batch = service_arns[i:i + 10]
            try:
                response = ecs.describe_services(cluster=cluster_arn, services=batch)
            except Exception as e:
                unread[cluster_arn] = 'service descriptions not read'
                self._warn_swallowed("ECS service descriptions", "ecs:DescribeServices", e)
                continue
            all_services.extend(response.get('services', []))
        return all_services

    def get_ecs_task_definition(self, task_definition_arn: str) -> Optional[Dict[str, Any]]:
        """Get task definition via boto3."""
        try:
            ecs = self._get_client('ecs')
            response = ecs.describe_task_definition(taskDefinition=task_definition_arn)
            return response.get('taskDefinition', {})
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="ECS Task Definition", permission="ecs:DescribeTaskDefinition", error=e,
                )
                self._warn_access_denied("ECS Task Definition", "ecs:DescribeTaskDefinition", e)
                raise
            return None

    def get_ecs_metrics(
        self, cluster_name: str, service_name: str,
        metric_name: str, days: int = 7,
    ) -> Optional[Dict[str, float]]:
        """Get ECS service CloudWatch metrics: ``{'average', 'maximum'}``
        over the window, or None (MISSING).

        CLO-546: hourly datapoints (Period=3600), the mean of the hourly
        Averages and the max of the hourly Maximums, and only when they cover
        75% of the window (CLO-485's ``has_min_coverage``). A single
        window-long datapoint hid how much of the window had samples (a
        service whose samples all fall in one day read as a 7-day max), and
        ``datapoints[0]`` relied on an ordering CloudWatch does not promise.
        Under-covered or empty is MISSING, noted, never a utilization."""
        try:
            cw = self._get_client('cloudwatch')
            now = datetime.now(timezone.utc)
            response = cw.get_metric_statistics(
                Namespace='AWS/ECS',
                MetricName=metric_name,
                Dimensions=[
                    {'Name': 'ClusterName', 'Value': cluster_name},
                    {'Name': 'ServiceName', 'Value': service_name},
                ],
                StartTime=now - timedelta(days=days),
                EndTime=now,
                Period=3600,
                Statistics=['Average', 'Maximum'],
            )
            datapoints = response.get('Datapoints', [])
            if not has_min_coverage(len(datapoints), days, 3600):
                self._note_idle_verdict_missing(
                    'ecs', f"{cluster_name}/{service_name}",
                    f"{metric_name} under 75% hourly coverage ({len(datapoints)} datapoints)",
                    verdict='oversized', evidence='hourly utilization metrics',
                )
                return None
            return summarize_ecs_utilization(datapoints)
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="ECS Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("ECS Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.debug(f"Failed to get ECS metric {metric_name} for {cluster_name}/{service_name}: {e}")
            return None

    def get_ecs_autoscaling_targets(self, cluster_name: str) -> Optional[List[Dict[str, Any]]]:
        """Application Auto Scaling targets for ECS services in a cluster, or
        None when the read failed (MISSING).

        CLO-550: a failed read used to return [] (no service scaled, so every
        service with 2+ tasks was flagged ecs_no_autoscaling), and a denied
        one raised, which aborted every ECS check in the region. Both now
        return None; the detector withholds ecs_no_autoscaling for the
        cluster only. A denial is still recorded as a permission error."""
        try:
            autoscaling = self._get_client('application-autoscaling')
            response = autoscaling.describe_scalable_targets(
                ServiceNamespace='ecs'
            )
            return [
                t for t in response.get('ScalableTargets', [])
                if f'service/{cluster_name}/' in t.get('ResourceId', '')
            ]
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="ECS Autoscaling Targets", permission="application-autoscaling:DescribeScalableTargets", error=e,
                )
                self._warn_access_denied("ECS Autoscaling Targets", "application-autoscaling:DescribeScalableTargets", e)
            else:
                logger.warning(f"Failed to get ECS auto-scaling targets for {cluster_name}: {e}")
            return None

    def get_ecs_container_insights_status(self, cluster_name: str) -> bool:
        """Check if Container Insights is enabled via cluster settings."""
        clusters = self.get_ecs_clusters()
        for cluster in clusters:
            if cluster.get('clusterName') == cluster_name:
                for setting in cluster.get('settings', []):
                    if (setting.get('name') == 'containerInsights' and
                            setting.get('value') == 'enabled'):
                        return True
        return False

    def get_eks_clusters(self) -> List[EKSClusterData]:
        """Get all EKS clusters with version metadata."""
        clusters: List[EKSClusterData] = []
        try:
            eks = self._get_client('eks')
            names: List[str] = []
            paginator = eks.get_paginator('list_clusters')
            for page in paginator.paginate():
                names.extend(page.get('clusters', []))

            for cluster_name in names:
                try:
                    response = eks.describe_cluster(name=cluster_name)
                    cluster = response.get('cluster', {})
                    clusters.append(EKSClusterData(
                        cluster_name=cluster.get('name', cluster_name),
                        version=cluster.get('version', ''),
                        status=cluster.get('status', 'UNKNOWN'),
                        region=self._region,
                        platform_version=cluster.get('platformVersion', ''),
                        cluster_arn=cluster.get('arn', ''),
                        created_at=cluster.get('createdAt'),
                    ))
                except Exception as e:
                    logger.debug(f"Failed to describe EKS cluster {cluster_name}: {e}")
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="EKS Clusters", permission="eks:ListClusters", error=e,
                )
                self._warn_access_denied("EKS Clusters", "eks:ListClusters", e)
                raise
            logger.debug(f"Failed to list EKS clusters: {e}")

        return clusters

    # =========================================================================
    # Glue
    # =========================================================================

    def get_glue_jobs(self) -> List[Dict[str, Any]]:
        """Get all Glue ETL jobs."""
        try:
            glue = self._get_client('glue')
            jobs = []
            paginator = glue.get_paginator('get_jobs')
            for page in paginator.paginate():
                jobs.extend(page.get('Jobs', []))
            return jobs
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Glue Jobs", permission="glue:GetJobs", error=e,
                )
                self._warn_access_denied("Glue Jobs", "glue:GetJobs", e)
                raise
            logger.debug(f"Failed to get Glue jobs: {e}")
            return []

    def get_glue_job_runs(self, job_name: str, max_results: int = 10) -> Optional[List[Dict[str, Any]]]:
        """Recent runs of a Glue job, or None when the read failed (MISSING).

        CLO-551: a failed read used to return [] ("never ran", which flags
        old_glue_job, glue_job_missing_timeout, failed_glue_job_retry and
        oversized_glue_job on config alone), and a denied one raised, which
        aborted the timeout / retry / oversized checks for every job in the
        region. Both now return None; the detectors withhold that job's
        run-history verdicts. A denial is still recorded as a permission
        error."""
        try:
            glue = self._get_client('glue')
            response = glue.get_job_runs(JobName=job_name, MaxResults=max_results)
            runs = response.get('JobRuns')
            return runs if isinstance(runs, list) else None
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Glue Job Runs", permission="glue:GetJobRuns", error=e,
                )
                self._warn_access_denied("Glue Job Runs", "glue:GetJobRuns", e)
            else:
                logger.warning(f"Failed to get runs for Glue job {job_name}: {e}")
            return None

    def get_glue_crawlers(self) -> List[Dict[str, Any]]:
        """Get all Glue crawlers."""
        try:
            glue = self._get_client('glue')
            crawlers = []
            paginator = glue.get_paginator('get_crawlers')
            for page in paginator.paginate():
                crawlers.extend(page.get('Crawlers', []))
            return crawlers
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Glue Crawlers", permission="glue:GetCrawlers", error=e,
                )
                self._warn_access_denied("Glue Crawlers", "glue:GetCrawlers", e)
                raise
            logger.debug(f"Failed to get Glue crawlers: {e}")
            return []

    def get_glue_catalog_stats(self) -> Optional[Dict[str, Any]]:
        """Get Data Catalog object counts."""
        try:
            glue = self._get_client('glue')

            # Count databases
            databases = []
            paginator = glue.get_paginator('get_databases')
            for page in paginator.paginate():
                databases.extend(page.get('DatabaseList', []))

            # Count tables across all databases
            total_tables = 0
            total_table_versions = 0
            total_partitions = 0

            for db in databases:
                db_name = db['Name']
                try:
                    table_paginator = glue.get_paginator('get_tables')
                    for page in table_paginator.paginate(DatabaseName=db_name):
                        tables = page.get('TableList', [])
                        total_tables += len(tables)

                        # Sample table versions (first 10 tables per DB)
                        for table in tables[:10]:
                            try:
                                versions = glue.get_table_versions(
                                    DatabaseName=db_name,
                                    TableName=table['Name'],
                                    MaxResults=100
                                )
                                total_table_versions += len(versions.get('TableVersions', []))
                            except Exception as e:
                                self._warn_swallowed(
                                    "Glue table versions", "glue:GetTableVersions", e,
                                )
                except Exception as e:
                    self._warn_swallowed("Glue tables for database", "glue:GetTables", e)

            total_objects = len(databases) + total_tables + total_table_versions + total_partitions

            return {
                'databases': len(databases),
                'tables': total_tables,
                'table_versions': total_table_versions,
                'partitions': total_partitions,
                'total_objects': total_objects,
            }
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Glue Catalog Stats", permission="glue:GetDatabases", error=e,
                )
                self._warn_access_denied("Glue Catalog Stats", "glue:GetDatabases", e)
                raise
            logger.debug(f"Failed to get Glue catalog stats: {e}")
            return None

    def get_glue_metrics(self, job_name: str, metric_name: str, days: int = 14) -> Optional[float]:
        """Average of a Glue job's gauge metric over ``days``, as published
        (e.g. glue.ALL.jvm.heap.usage is a 0-1 fraction), or None when
        there is no datapoint (MISSING; Glue job metrics are opt-in).

        CLO-547: Glue job metrics are published per JobName, JobRunId (a run
        id, or ``ALL`` for the aggregate across runs) and Type. CloudWatch
        matches dimensions exactly, so a query without JobRunId matched no
        series and the heap read was always empty."""
        try:
            cw = self._get_client('cloudwatch')
            now = datetime.now(timezone.utc)

            response = cw.get_metric_statistics(
                Namespace='Glue',
                MetricName=metric_name,
                Dimensions=[
                    {'Name': 'JobName', 'Value': job_name},
                    {'Name': 'JobRunId', 'Value': 'ALL'},
                    {'Name': 'Type', 'Value': 'gauge'},
                ],
                StartTime=now - timedelta(days=days),
                EndTime=now,
                Period=86400,
                Statistics=['Average'],
            )

            datapoints = response.get('Datapoints', [])
            if not datapoints:
                return None

            return sum(dp.get('Average', 0) for dp in datapoints) / len(datapoints)
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Glue Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Glue Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.debug(f"Failed to get Glue metric {metric_name} for {job_name}: {e}")
            return None

    # =========================================================================
    # Transfer Family
    # =========================================================================

    def get_transfer_servers(self) -> List[Dict[str, Any]]:
        """Get all Transfer Family servers with enriched details."""
        try:
            transfer = self._get_client('transfer')
            servers = transfer.list_servers().get('Servers', [])
            enriched = []
            for server in servers:
                server_id = server['ServerId']
                try:
                    details = transfer.describe_server(ServerId=server_id).get('Server', {})
                    enriched.append(details)
                except Exception:
                    enriched.append(server)
            return enriched
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Transfer Servers", permission="transfer:ListServers", error=e,
                )
                self._warn_access_denied("Transfer Servers", "transfer:ListServers", e)
                raise
            logger.debug(f"Failed to get Transfer servers: {e}")
            return []

    def get_transfer_server_users(self, server_id: str) -> Optional[List[Dict[str, Any]]]:
        """Users of a Transfer Family server (the first page is enough to
        tell "none" from "some"), or None when the read failed (MISSING).

        CLO-550: a failed read used to return [] ("no users", so the server
        was flagged idle_transfer_server), and a denied one raised, which
        aborted the Transfer detector for every server and web app in the
        region. Both now return None, and the detector withholds that
        server's no-users verdict and notes it. A denial is still recorded
        as a permission error."""
        try:
            transfer = self._get_client('transfer')
            users = transfer.list_users(ServerId=server_id).get('Users')
            return users if isinstance(users, list) else None
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Transfer Server Users", permission="transfer:ListUsers", error=e,
                )
                self._warn_access_denied("Transfer Server Users", "transfer:ListUsers", e)
            else:
                logger.warning(f"Failed to list users for Transfer server {server_id}: {e}")
            return None

    def get_transfer_web_apps(self) -> List[Dict[str, Any]]:
        """Get all Transfer Family Web Apps with enriched details."""
        try:
            transfer = self._get_client('transfer')
            web_apps = transfer.list_web_apps().get('WebApps', [])
            enriched = []
            for app in web_apps:
                app_id = app.get('WebAppId', '')
                try:
                    details = transfer.describe_web_app(WebAppId=app_id).get('WebApp', {})
                    enriched.append(details)
                except Exception:
                    enriched.append(app)
            return enriched
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Transfer Web Apps", permission="transfer:ListWebApps", error=e,
                )
                self._warn_access_denied("Transfer Web Apps", "transfer:ListWebApps", e)
                raise
            logger.debug(f"Failed to get Transfer web apps: {e}")
            return []

    def get_transfer_metrics(
        self, server_id: str, metric_name: str, days: int = 30,
        protocol: Optional[str] = None
    ) -> CounterRead:
        """The Sum of an AWS/Transfer counter for a server (optionally one
        protocol) over ``days``, as a :class:`CounterRead`."""
        dimensions = [{'Name': 'ServerId', 'Value': server_id}]
        if protocol:
            dimensions.append({'Name': 'Protocol', 'Value': protocol})
        return self._read_transfer_counter(
            dimensions, metric_name, days, "Transfer Metrics",
            f"{server_id}/{protocol}" if protocol else server_id,
        )

    def get_transfer_web_app_metrics(
        self, web_app_id: str, metric_name: str, days: int = 30
    ) -> CounterRead:
        """The Sum of an AWS/Transfer counter for a web app over ``days``,
        as a :class:`CounterRead`."""
        return self._read_transfer_counter(
            [{'Name': 'WebAppId', 'Value': web_app_id}], metric_name, days,
            "Transfer Web App Metrics", web_app_id,
        )

    def _read_transfer_counter(
        self, dimensions: List[Dict[str, str]], metric_name: str, days: int,
        resource: str, resource_id: str,
    ) -> CounterRead:
        """CLO-546 follow-up, CLO-485's counter rule. AWS/Transfer FilesIn,
        FilesOut and ActiveSessions publish only when something happens, so
        a quiet server or web app has NO datapoints: a successful read with
        an empty series is EMPTY (a measured zero, subject to the detector's
        age gate), not MISSING. A read that raises (access denied,
        throttling, anything) is MISSING with the reason, never zero."""
        try:
            cw = self._get_client('cloudwatch')
            now = datetime.now(timezone.utc)
            response = cw.get_metric_statistics(
                Namespace='AWS/Transfer',
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=now - timedelta(days=days),
                EndTime=now,
                Period=86400,
                Statistics=['Sum'],
            )
            return CounterRead.from_datapoints(response.get('Datapoints', []))
        except Exception as e:  # noqa: BLE001 - any failure is MISSING, never zero
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource=resource, permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied(resource, "cloudwatch:GetMetricStatistics", e)
            logger.debug(f"Failed to get {resource} {metric_name} for {resource_id}: {e}")
            code = e.response.get('Error', {}).get('Code', '') if isinstance(e, ClientError) else ''
            return CounterRead.missing(
                f"{metric_name} read failed ({type(e).__name__}{':' + code if code else ''})"
            )

    # =========================================================================
    # AWS Backup
    # =========================================================================

    async def get_backup_recovery_points(self) -> List[BackupRecoveryPointData]:
        """Get all recovery points across backup vaults.

        CLO-551: a vault whose recovery points could not be listed (a vault
        access policy deny, throttling) used to be skipped at debug level,
        so a resource backed up only into that vault read as "not backed
        up" (resource_without_backup_coverage). The partial list is still
        returned for the checks over the recovery points it holds, and
        :meth:`backup_recovery_points_unread` says it is incomplete; a
        denial is recorded as a permission error."""
        recovery_points: List[BackupRecoveryPointData] = []
        self._backup_recovery_points_unread = None
        try:
            backup = self._get_client('backup')
            now = datetime.now(timezone.utc)

            # List all vaults. One page; a further page is unread vaults, so
            # the recovery-point list is then incomplete.
            vaults_response = backup.list_backup_vaults()
            vaults = vaults_response.get('BackupVaultList', [])
            if vaults_response.get('NextToken'):
                self._backup_recovery_points_unread = 'vault list truncated'

            for vault in vaults:
                vault_name = vault.get('BackupVaultName', '')
                vault_arn = vault.get('BackupVaultArn', '')
                try:
                    paginator = backup.get_paginator('list_recovery_points_by_backup_vault')
                    for page in paginator.paginate(BackupVaultName=vault_name):
                        for rp in page.get('RecoveryPoints', []):
                            creation = rp.get('CreationDate')
                            age_days = (now - creation).days if creation else 0
                            recovery_points.append(BackupRecoveryPointData(
                                recovery_point_arn=rp.get('RecoveryPointArn', ''),
                                backup_vault_name=vault_name,
                                backup_vault_arn=vault_arn,
                                resource_arn=rp.get('ResourceArn', ''),
                                resource_type=rp.get('ResourceType', ''),
                                status=rp.get('Status', 'COMPLETED'),
                                creation_date=creation,
                                completion_date=rp.get('CompletionDate'),
                                backup_size_bytes=rp.get('BackupSizeInBytes'),
                                lifecycle=rp.get('Lifecycle'),
                                is_encrypted=rp.get('IsEncrypted', False),
                                # CLO-514: the plan id is under CreatedBy.
                                backup_plan_id=recovery_point_plan_id(rp),
                                age_days=age_days,
                                is_parent=rp.get('IsParent', False),
                                parent_recovery_point_arn=rp.get('ParentRecoveryPointArn'),
                            ))
                except Exception as e:
                    self._backup_recovery_points_unread = 'vault recovery-point read failed'
                    self._warn_swallowed(
                        "Backup vault recovery points", "backup:ListRecoveryPointsByBackupVault", e,
                    )

            logger.info(f"Backup: Found {len(recovery_points)} recovery points across {len(vaults)} vaults")
            return recovery_points
        except Exception as e:
            self._backup_recovery_points_unread = 'vault list not read'
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Backup Recovery Points", permission="backup:ListRecoveryPointsByBackupVault", error=e,
                )
                self._warn_access_denied("Backup Recovery Points", "backup:ListRecoveryPointsByBackupVault", e)
                raise
            logger.warning(f"Failed to get backup recovery points: {e}")
            return []

    async def get_backup_plans(self) -> List[BackupPlanData]:
        """Get all backup plans with rules."""
        plans: List[BackupPlanData] = []
        try:
            backup = self._get_client('backup')
            list_response = backup.list_backup_plans()

            for plan_meta in list_response.get('BackupPlansList', []):
                plan_id = plan_meta.get('BackupPlanId', '')
                try:
                    detail = backup.get_backup_plan(BackupPlanId=plan_id)
                    plan_body = detail.get('BackupPlan', {})
                    plans.append(BackupPlanData(
                        backup_plan_id=plan_id,
                        backup_plan_name=plan_body.get('BackupPlanName', ''),
                        backup_plan_arn=plan_meta.get('BackupPlanArn', ''),
                        version_id=plan_meta.get('VersionId'),
                        creation_date=plan_meta.get('CreationDate'),
                        last_execution_date=plan_meta.get('LastExecutionDate'),
                        rules=plan_body.get('Rules', []),
                    ))
                except Exception as e:
                    logger.debug(f"Failed to get backup plan {plan_id}: {e}")

            logger.info(f"Backup: Found {len(plans)} backup plans")
            return plans
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Backup Plans", permission="backup:ListBackupPlans", error=e,
                )
                self._warn_access_denied("Backup Plans", "backup:ListBackupPlans", e)
                raise
            logger.debug(f"Failed to get backup plans: {e}")
            return []

    async def get_backup_selections(self, plan_id: str) -> List[BackupSelectionData]:
        """Get backup selections for a specific plan."""
        selections: List[BackupSelectionData] = []
        try:
            backup = self._get_client('backup')
            list_response = backup.list_backup_selections(BackupPlanId=plan_id)

            for sel_meta in list_response.get('BackupSelectionsList', []):
                sel_id = sel_meta.get('SelectionId', '')
                try:
                    detail = backup.get_backup_selection(
                        BackupPlanId=plan_id, SelectionId=sel_id
                    )
                    sel = detail.get('BackupSelection', {})
                    selections.append(BackupSelectionData(
                        selection_id=sel_id,
                        selection_name=sel.get('SelectionName', ''),
                        backup_plan_id=plan_id,
                        iam_role_arn=sel.get('IamRoleArn', ''),
                        resources=sel.get('Resources', []),
                        list_of_tags=sel.get('ListOfTags', []),
                        conditions=sel.get('Conditions'),
                        not_resources=sel.get('NotResources', []),
                    ))
                except Exception as e:
                    logger.debug(f"Failed to get backup selection {sel_id}: {e}")

            return selections
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Backup Selections", permission="backup:ListBackupSelections", error=e,
                )
                self._warn_access_denied("Backup Selections", "backup:ListBackupSelections", e)
                raise
            logger.debug(f"Failed to list backup selections for plan {plan_id}: {e}")
            return []

    async def get_backup_copy_jobs(self, days: int = 90) -> List[BackupCopyJobSummary]:
        """Get copy job summaries for the specified lookback period."""
        jobs: List[BackupCopyJobSummary] = []
        try:
            backup = self._get_client('backup')
            now = datetime.now(timezone.utc)
            created_after = now - timedelta(days=days)

            paginator = backup.get_paginator('list_copy_jobs')
            for page in paginator.paginate(
                ByCreatedAfter=created_after,
                ByState='COMPLETED',
            ):
                for job in page.get('CopyJobs', []):
                    jobs.append(BackupCopyJobSummary(
                        source_backup_vault_arn=job.get('SourceBackupVaultArn', ''),
                        destination_backup_vault_arn=job.get('DestinationBackupVaultArn', ''),
                        resource_type=job.get('ResourceType', ''),
                        state=job.get('State', 'COMPLETED'),
                        creation_date=job.get('CreationDate'),
                        backup_size_bytes=job.get('BackupSizeInBytes'),
                    ))

            logger.info(f"Backup: Found {len(jobs)} copy jobs in last {days} days")
            return jobs
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Backup Copy Jobs", permission="backup:ListCopyJobs", error=e,
                )
                self._warn_access_denied("Backup Copy Jobs", "backup:ListCopyJobs", e)
                raise
            logger.debug(f"Failed to get backup copy jobs: {e}")
            return []

    # CLO-589 follow-up (PR #1654 review MEDIUM 3): ListBackupVaults'
    # ByVaultType values in botocore 1.40.21. The model does not say which
    # types the unfiltered call returns, so every type is listed explicitly.
    # The live client's model is preferred (a newer botocore may add a type);
    # this is the fallback when it cannot be read.
    _BACKUP_VAULT_TYPES = (
        'BACKUP_VAULT', 'LOGICALLY_AIR_GAPPED_BACKUP_VAULT', 'RESTORE_ACCESS_BACKUP_VAULT',
    )

    def _backup_vault_types(self, backup) -> Tuple[str, ...]:
        try:
            shape = backup.meta.service_model.operation_model('ListBackupVaults').input_shape
            enum = list(shape.members['ByVaultType'].enum)
        except Exception:
            enum = []
        if not enum or not all(isinstance(v, str) for v in enum):
            return self._BACKUP_VAULT_TYPES
        return tuple(dict.fromkeys([*enum, *self._BACKUP_VAULT_TYPES]))

    def _own_backup_vault_arns(self, region: str) -> Tuple[set, Optional[str]]:
        """Every vault ARN ListBackupVaults reports in ``region``: the
        unfiltered answer plus one paged read per ByVaultType. Returns the
        union and None when every read completed, or the union so far and the
        first failure's reason. Cached per Region for the provider's life."""
        cache: Dict[str, Tuple[set, Optional[str]]] = self.__dict__.setdefault('_backup_vault_arns_by_region', {})
        if region in cache:
            return cache[region]
        arns: set = set()
        reason: Optional[str] = None
        try:
            backup = self._get_client('backup', region=region)
        except Exception as e:
            self._warn_swallowed("Backup Vaults", "backup:ListBackupVaults", e)
            cache[region] = (arns, f"read failed ({self._error_label(e)})")
            return cache[region]
        filters: List[Dict[str, str]] = [{}]
        filters += [{'ByVaultType': t} for t in self._backup_vault_types(backup)]
        for kwargs in filters:
            try:
                for page in backup.get_paginator('list_backup_vaults').paginate(**kwargs):
                    arns.update(
                        v.get('BackupVaultArn') for v in page.get('BackupVaultList', []) or []
                        if isinstance(v, dict)
                    )
            except Exception as e:
                self._warn_swallowed("Backup Vaults", "backup:ListBackupVaults", e)
                if reason is None:
                    label = kwargs.get('ByVaultType', 'unfiltered')
                    reason = f"read failed ({label}: {self._error_label(e)})"
        cache[region] = (arns, reason)
        return cache[region]

    async def backup_vault_exists(self, vault_arn: str) -> Optional[bool]:
        """CLO-589: look the vault up with ListBackupVaults in its own Region.

        ListBackupVaults is already in the monitoring role (DescribeBackupVault
        is not). It only lists the caller's own vaults, so a vault in another
        account cannot be judged: None, noted.

        CLO-589 follow-up (PR #1654 review MEDIUM 3): the unfiltered answer
        may leave out a logically air-gapped or restore-access vault (the
        model does not say), and absent from it used to read as False, a
        silent withhold. Now True when ANY read lists the vault; False only
        when the unfiltered read and one read per ByVaultType ALL completed
        without it; otherwise None, noted. Cached per Region and per ARN."""
        cache: Dict[str, Optional[bool]] = self.__dict__.setdefault('_backup_vault_exists', {})
        if vault_arn in cache:
            return cache[vault_arn]
        result: Optional[bool] = None
        reason = None
        parts = vault_arn.split(':')
        own_account = self._aws_account_id()
        if len(parts) < 7 or parts[2] != 'backup' or parts[5] != 'backup-vault':
            reason = 'vault ARN unparseable'
        elif own_account is None:
            reason = 'scanned account ID unknown'
        elif parts[4] != own_account:
            reason = 'destination vault in another account'
        else:
            arns, failure = self._own_backup_vault_arns(parts[3])
            if vault_arn in arns:
                result = True
            elif failure is None:
                result = False
            else:
                reason = failure
        if reason:
            self._note_idle_verdict_missing(
                'backup', vault_arn, reason,
                verdict='copy-policy-overreach', evidence='destination vault reads',
            )
        cache[vault_arn] = result
        return result

    # =========================================================================
    # DocumentDB
    # =========================================================================

    async def get_documentdb_clusters(self) -> List[DocumentDBClusterData]:
        """Get all DocumentDB clusters."""
        clusters: List[DocumentDBClusterData] = []
        try:
            docdb = self._get_client('docdb')
            paginator = docdb.get_paginator('describe_db_clusters')
            for page in paginator.paginate():
                for c in page.get('DBClusters', []):
                    if c.get('Engine') != 'docdb':
                        continue
                    members = c.get('DBClusterMembers', [])
                    # Determine instance class from first member if available
                    instance_class = ''
                    if members:
                        try:
                            inst_resp = docdb.describe_db_instances(
                                DBInstanceIdentifier=members[0].get('DBInstanceIdentifier', '')
                            )
                            inst_list = inst_resp.get('DBInstances', [])
                            if inst_list:
                                instance_class = inst_list[0].get('DBInstanceClass', '')
                        except Exception as e:
                            self._warn_swallowed(
                                "DocumentDB instance class lookup", "docdb:DescribeDBInstances", e,
                            )
                    tag_list = c.get('TagList', [])
                    tags = {t['Key']: t['Value'] for t in tag_list if 'Key' in t and 'Value' in t}
                    clusters.append(DocumentDBClusterData(
                        cluster_identifier=c['DBClusterIdentifier'],
                        status=c.get('Status', 'available'),
                        engine=c.get('Engine', 'docdb'),
                        engine_version=c.get('EngineVersion', ''),
                        db_cluster_members=members,
                        instance_class=instance_class,
                        num_instances=len(members),
                        storage_encrypted=c.get('StorageEncrypted', False),
                        deletion_protection=c.get('DeletionProtection', False),
                        tags=tags,
                        cluster_create_time=c.get('ClusterCreateTime'),
                    ))

            logger.info(f"DocumentDB: Found {len(clusters)} clusters")
            return clusters
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="DocumentDB Clusters", permission="docdb:DescribeDbClusters", error=e,
                )
                self._warn_access_denied("DocumentDB Clusters", "docdb:DescribeDbClusters", e)
                raise
            logger.debug(f"Failed to get DocumentDB clusters: {e}")
            return []

    async def get_documentdb_snapshots(self, snapshot_type: str = "manual") -> List[DocumentDBSnapshotData]:
        """Get DocumentDB cluster snapshots."""
        snapshots: List[DocumentDBSnapshotData] = []
        try:
            docdb = self._get_client('docdb')
            now = datetime.now(timezone.utc)
            paginator = docdb.get_paginator('describe_db_cluster_snapshots')
            kwargs = {'SnapshotType': snapshot_type} if snapshot_type else {}
            for page in paginator.paginate(**kwargs):
                for s in page.get('DBClusterSnapshots', []):
                    if s.get('Engine') != 'docdb':
                        continue
                    created = s.get('SnapshotCreateTime')
                    age_days = (now - created).days if created else 0
                    # Get tags
                    tags = {}
                    snap_arn = s.get('DBClusterSnapshotArn', '')
                    if snap_arn:
                        try:
                            tag_resp = docdb.list_tags_for_resource(ResourceName=snap_arn)
                            for t in tag_resp.get('TagList', []):
                                if 'Key' in t and 'Value' in t:
                                    tags[t['Key']] = t['Value']
                        except Exception as e:
                            self._warn_swallowed(
                                "DocumentDB snapshot tags", "docdb:ListTagsForResource", e,
                            )
                    snapshots.append(DocumentDBSnapshotData(
                        snapshot_identifier=s['DBClusterSnapshotIdentifier'],
                        cluster_identifier=s.get('DBClusterIdentifier', ''),
                        status=s.get('Status', 'available'),
                        snapshot_type=s.get('SnapshotType', 'manual'),
                        engine=s.get('Engine', 'docdb'),
                        engine_version=s.get('EngineVersion', ''),
                        snapshot_create_time=created,
                        storage_encrypted=s.get('StorageEncrypted', False),
                        allocated_storage=s.get('AllocatedStorage', 0),
                        age_days=age_days,
                        tags=tags,
                    ))

            logger.info(f"DocumentDB: Found {len(snapshots)} {snapshot_type} snapshots")
            return snapshots
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="DocumentDB Snapshots", permission="docdb:DescribeDbClusterSnapshots", error=e,
                )
                self._warn_access_denied("DocumentDB Snapshots", "docdb:DescribeDbClusterSnapshots", e)
                raise
            logger.debug(f"Failed to get DocumentDB snapshots: {e}")
            return []

    async def get_documentdb_cluster_metrics(
        self, cluster_id: str, days: int = 14, cluster_create_time: Optional[datetime] = None,
    ) -> Optional[DocumentDBMetricsData]:
        """Get CloudWatch metrics for a DocumentDB cluster.

        Queries the AWS/DocDB namespace directly (dimension DBClusterIdentifier).
        Connections, IOPS and CPU are all read as an Average across hourly
        datapoints (CLO-447). ReadIOPS/WriteIOPS are a Count/Second RATE, and
        DatabaseConnections is a gauge — Sum-ing either over a multi-day window
        (the prior behaviour) produces a meaningless number, not a real total;
        see DOCDB_IDLE_COMBINED_IOPS_THRESHOLD above for the measured evidence.

        CLO-457: with ``cluster_create_time``, every read starts at the
        creation time and drops datapoints from before it, so a cluster
        recreated under a reused DBClusterIdentifier is judged on its own
        hours only (see metric_window). Coverage is still measured against
        the full ``days`` window.
        """
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = metric_start_time(end_time, days, cluster_create_time)

            def _own(resp) -> list:
                return drop_pre_creation_datapoints(
                    resp.get('Datapoints', []), cluster_create_time, 3600,
                )

            datapoint_counts: Dict[str, int] = {}

            def _avg(metric_name: str) -> float:
                resp = cw.get_metric_statistics(
                    Namespace='AWS/DocDB',
                    MetricName=metric_name,
                    Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average'],
                )
                dps = _own(resp)
                datapoint_counts[metric_name] = len(dps)
                return sum(dp.get('Average', 0.0) for dp in dps) / len(dps) if dps else 0.0

            cpu_resp = cw.get_metric_statistics(
                Namespace='AWS/DocDB',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average', 'Maximum'],
            )
            cpu_dps = _own(cpu_resp)
            # The shared rule (cpu_sizing, CLO-455/CLO-480). max_cpu is
            # reported only: it used to gate, and one boot hour vetoed the
            # detector for the whole window (CLO-455).
            cpu = summarize_hourly_cpu(cpu_dps, DOCDB_OVERPROVISIONED_CPU_PERCENTILE)

            connections = _avg('DatabaseConnections')
            read_iops = _avg('ReadIOPS')
            write_iops = _avg('WriteIOPS')

            # CLO-485: DatabaseConnections is a gauge, published every period
            # while the cluster runs, so an EMPTY series is missing data, not
            # zero connections. CLO-457 (2026-09-28): "0 connections for N
            # days" also needs the series to cover 75% of the N-day window
            # (126 of 168 hours for 7), the rule #1479 gave idle_elasticache
            # and idle_redshift. Zero datapoints never passes. The recorded
            # 09-19 contract (44 of 168 hours, 1.8 days old) no longer reads
            # idle; see docs/decisions/2026-09-28-idle-documentdb-age-guard.md.
            conn_count = datapoint_counts.get('DatabaseConnections', 0)
            conn_observed = conn_count > 0
            conn_covered = docdb_connections_cover_idle_window(conn_count, days)
            idle_shaped = (
                conn_observed
                and connections == 0
                and (read_iops + write_iops) < DOCDB_IDLE_COMBINED_IOPS_THRESHOLD
            )
            is_idle = idle_shaped and conn_covered
            # A cluster younger than the window is not called idle anyway
            # (the detector's age guard), so its short series is expected,
            # not missing.
            if (not conn_covered and (idle_shaped or not conn_observed)
                    and is_as_old_as_window(cluster_create_time, days)):
                self._note_idle_verdict_missing(
                    'documentdb', cluster_id,
                    "no DatabaseConnections datapoints" if not conn_observed
                    else "DatabaseConnections under 75% coverage",
                )
            is_overprovisioned = (
                # Defers on the idle SHAPE, not on the coverage-gated
                # verdict: a zero-connection cluster whose series is too
                # sparse to be called idle is MISSING, not a rightsizing
                # candidate (the sibling-deferral rule #1479 set for Redshift).
                not idle_shaped
                and conn_observed  # CLO-485: a missing series is not "< 1 connection"
                and cpu_is_low_enough(
                    cpu.avg_cpu, cpu.p95_cpu, cpu.p95_max_cpu, cpu.datapoints,
                    days, DOCDB_OVERPROVISIONED_CPU_THRESHOLDS,
                )
                and connections < DOCDB_OVERPROVISIONED_AVG_CONNECTIONS_THRESHOLD
                and (read_iops + write_iops) < DOCDB_OVERPROVISIONED_COMBINED_IOPS_THRESHOLD
            )
            return DocumentDBMetricsData(
                cluster_identifier=cluster_id,
                database_connections=connections,
                read_iops=read_iops,
                write_iops=write_iops,
                avg_cpu=round(cpu.avg_cpu, 2),
                max_cpu=round(cpu.max_cpu, 2),
                p95_cpu=round(cpu.p95_cpu, 2),
                p95_max_cpu=round(cpu.p95_max_cpu, 2),
                cpu_datapoints=cpu.datapoints,
                period_days=days,
                is_idle=is_idle,
                is_overprovisioned=is_overprovisioned,
            )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="DocumentDB Cluster Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("DocumentDB Cluster Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.debug(f"Failed to get DocumentDB metrics for {cluster_id}: {e}")
            return None

    # =========================================================================
    # FSx
    # =========================================================================

    async def get_fsx_filesystems(self) -> List[FSxFilesystemData]:
        """Get all FSx filesystems."""
        filesystems: List[FSxFilesystemData] = []
        try:
            fsx = self._get_client('fsx')
            paginator = fsx.get_paginator('describe_file_systems')
            for page in paginator.paginate():
                for fs in page.get('FileSystems', []):
                    tag_list = fs.get('Tags', [])
                    tags = {t['Key']: t['Value'] for t in tag_list if 'Key' in t and 'Value' in t}
                    # Throughput, deployment type and Lustre per-unit
                    # throughput live in the type's configuration block.
                    fstype = fs.get('FileSystemType', '')
                    config = fsx_filesystem_config(fs)
                    creation_time = fs.get('CreationTime')
                    filesystems.append(FSxFilesystemData(
                        filesystem_id=fs['FileSystemId'],
                        filesystem_type=fstype,
                        lifecycle=fs.get('Lifecycle', 'AVAILABLE'),
                        storage_capacity_gb=fs.get('StorageCapacity', 0),
                        storage_type=fs.get('StorageType', 'SSD'),
                        throughput_capacity_mbps=config['throughput_capacity_mbps'],
                        deployment_type=config['deployment_type'],
                        per_unit_storage_throughput=config['per_unit_storage_throughput'],
                        creation_time=creation_time,
                        tags=tags,
                    ))
            logger.info(f"FSx: Found {len(filesystems)} filesystems")
            return filesystems
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="FSx Filesystems", permission="fsx:DescribeFileSystems", error=e,
                )
                self._warn_access_denied("FSx Filesystems", "fsx:DescribeFileSystems", e)
                raise
            logger.debug(f"Failed to get FSx filesystems: {e}")
            return []

    async def get_fsx_backups(self) -> List[FSxBackupData]:
        """Get FSx backups."""
        backups: List[FSxBackupData] = []
        try:
            fsx = self._get_client('fsx')
            now = datetime.now(timezone.utc)
            paginator = fsx.get_paginator('describe_backups')
            for page in paginator.paginate():
                for b in page.get('Backups', []):
                    created = b.get('CreationTime')
                    age_days = (now - created).days if created else 0
                    fs_info = b.get('FileSystem', {})
                    tag_list = b.get('Tags', [])
                    tags = {t['Key']: t['Value'] for t in tag_list if 'Key' in t and 'Value' in t}
                    backups.append(FSxBackupData(
                        backup_id=b['BackupId'],
                        filesystem_id=fs_info.get('FileSystemId', ''),
                        filesystem_type=fs_info.get('FileSystemType', ''),
                        lifecycle=b.get('Lifecycle', 'AVAILABLE'),
                        backup_type=b.get('Type', 'USER_INITIATED'),
                        creation_time=created,
                        age_days=age_days,
                        tags=tags,
                        size_bytes=b.get('SizeInBytes'),
                    ))
            logger.info(f"FSx: Found {len(backups)} backups")
            return backups
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="FSx Backups", permission="fsx:DescribeBackups", error=e,
                )
                self._warn_access_denied("FSx Backups", "fsx:DescribeBackups", e)
                raise
            logger.debug(f"Failed to get FSx backups: {e}")
            return []

    async def get_fsx_filesystem_metrics(
        self, filesystem_id: str, days: int = 7, filesystem_type: Optional[str] = None,
    ) -> Optional[FSxMetricsData]:
        """Get CloudWatch metrics for an FSx filesystem."""
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            period = 86400 * days  # Single datapoint for the whole period

            def _get_metric(metric_name, stat='Average', extra_dims=()):
                # CLO-540: one datapoint per metric (Period = the window);
                # an empty series is MISSING (None), never 0.
                resp = cw.get_metric_statistics(
                    Namespace='AWS/FSx',
                    MetricName=metric_name,
                    Dimensions=[{'Name': 'FileSystemId', 'Value': filesystem_id}, *extra_dims],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=period,
                    Statistics=[stat],
                )
                values = [d[stat] for d in resp.get('Datapoints', []) or [] if d.get(stat) is not None]
                if not values:
                    return None
                return max(values) if stat == 'Maximum' else sum(values) / len(values)

            def _hourly(metric_name):
                # CLO-512: hourly sums (<= 24 x days datapoints, one call),
                # so the busiest hour is visible, not only the total.
                resp = cw.get_metric_statistics(
                    Namespace='AWS/FSx',
                    MetricName=metric_name,
                    Dimensions=[{'Name': 'FileSystemId', 'Value': filesystem_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Sum'],
                )
                return resp.get('Datapoints', []) or []

            read_points = _hourly('DataReadBytes')
            write_points = _hourly('DataWriteBytes')
            if not read_points and not write_points:
                # CLO-512 review: no datapoints is MISSING, not zero I/O.
                self._note_idle_verdict_missing(
                    'fsx', filesystem_id, 'no datapoints',
                    evidence='DataReadBytes/DataWriteBytes datapoints',
                )
                return None
            read_bytes = int(sum(d.get('Sum', 0) for d in read_points))
            write_bytes = int(sum(d.get('Sum', 0) for d in write_points))
            free_storage = self._fsx_free_storage_gb(filesystem_id, filesystem_type, _get_metric)

            is_idle = (read_bytes + write_bytes) == 0

            return FSxMetricsData(
                filesystem_id=filesystem_id,
                data_read_bytes=read_bytes,
                data_write_bytes=write_bytes,
                free_storage_capacity_gb=free_storage,
                period_days=days,
                is_idle=is_idle,
                peak_hourly_bytes=fsx_hourly_peak_bytes(read_points + write_points),
            )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="FSx Filesystem Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("FSx Filesystem Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.debug(f"Failed to get FSx metrics for {filesystem_id}: {e}")
            return None

    # CLO-540: where each FSx type publishes its storage capacity, verified
    # against the AWS docs (2026-10-03) and, for OpenZFS, list-metrics on a
    # live file system:
    #   WINDOWS  FreeStorageCapacity {FileSystemId}, bytes, Average.
    #   OPENZFS  no FreeStorageCapacity. StorageCapacity and
    #            UsedStorageCapacity {FileSystemId}, bytes: free = capacity - used.
    #   ONTAP    no FreeStorageCapacity. The SSD (primary) tier, which is what
    #            StorageCapacity in DescribeFileSystems provisions:
    #            StorageCapacity {FileSystemId, StorageTier=SSD, DataType=All}
    #            (Maximum is its only statistic) minus StorageUsed with the
    #            same dimensions. FileSystemId-only StorageUsed spans both
    #            tiers, so it would overstate use of the SSD tier.
    #   LUSTRE   FreeDataStorageCapacity exists only per storage target
    #            {FileSystemId, StorageTargetId}; no file-system series. Not
    #            read: MISSING, with a note.
    _FSX_ONTAP_SSD_DIMS = (
        {'Name': 'StorageTier', 'Value': 'SSD'},
        {'Name': 'DataType', 'Value': 'All'},
    )

    def _fsx_free_storage_gb(self, filesystem_id: str, filesystem_type: Optional[str], get_metric) -> Optional[float]:
        """Free storage in GiB, or None (MISSING, noted in data_warnings).

        At most two GetMetricStatistics calls, one datapoint each. A failed
        read withholds the oversized verdict only; the idle and throughput
        verdicts already read stand."""
        fstype = (filesystem_type or '').upper()
        try:
            if fstype == 'OPENZFS':
                capacity = get_metric('StorageCapacity', 'Average')
                used = get_metric('UsedStorageCapacity', 'Average') if capacity is not None else None
                free_bytes = None if capacity is None or used is None else max(capacity - used, 0.0)
                reason = 'no StorageCapacity/UsedStorageCapacity datapoints'
            elif fstype == 'ONTAP':
                capacity = get_metric('StorageCapacity', 'Maximum', self._FSX_ONTAP_SSD_DIMS)
                used = (get_metric('StorageUsed', 'Average', self._FSX_ONTAP_SSD_DIMS)
                        if capacity is not None else None)
                free_bytes = None if capacity is None or used is None else max(capacity - used, 0.0)
                reason = 'no SSD-tier StorageCapacity/StorageUsed datapoints'
            elif fstype == 'LUSTRE':
                free_bytes = None
                reason = 'Lustre publishes free capacity per storage target only'
            else:
                # WINDOWS (and a type this code does not know yet).
                free_bytes = get_metric('FreeStorageCapacity', 'Average')
                reason = 'no FreeStorageCapacity datapoints'
        except Exception as e:  # noqa: BLE001 - MISSING for this verdict only
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="FSx Storage Capacity Metrics",
                    permission="cloudwatch:GetMetricStatistics", error=e,
                )
            free_bytes = None
            reason = f'read failed ({e.__class__.__name__})'
        if free_bytes is None:
            self._note_idle_verdict_missing(
                'fsx storage', filesystem_id, reason,
                verdict='oversized', evidence='storage capacity metrics',
            )
            return None
        return free_bytes / (1024 ** 3)

    # =========================================================================
    # Step Functions
    # =========================================================================

    @staticmethod
    def _cw_state_transitions(cw, state_machine_arn, start_time, end_time, period) -> int:
        """Total state transitions consumed by a state machine over the window.

        Step Functions does not publish a plain ``StateTransition`` count metric.
        Per-state-machine transition consumption is exposed by the *Service Metrics*
        group as ``ConsumedCapacity`` in the ``AWS/States`` namespace, filtered by the
        dimension pair ``ServiceMetric=StateTransition`` + ``StateMachineArn`` (verified
        against the Step Functions CloudWatch metrics docs, 2026-07). Sum over the
        window yields the total transitions consumed.
        """
        try:
            resp = cw.get_metric_statistics(
                Namespace='AWS/States',
                MetricName='ConsumedCapacity',
                Dimensions=[
                    {'Name': 'ServiceMetric', 'Value': 'StateTransition'},
                    {'Name': 'StateMachineArn', 'Value': state_machine_arn},
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=period,
                Statistics=['Sum'],
            )
            return int(sum(d.get('Sum', 0) for d in resp.get('Datapoints', [])))
        except Exception as e:
            logger.debug(f"Failed to get SFN state-transition metric for {state_machine_arn}: {e}")
            return 0

    async def get_step_function_state_machines(self) -> List[Dict[str, Any]]:
        """Get all Step Functions state machines."""
        machines: List[Dict[str, Any]] = []
        try:
            sfn = self._get_client('stepfunctions')
            paginator = sfn.get_paginator('list_state_machines')
            for page in paginator.paginate():
                for sm in page.get('stateMachines', []):
                    # ListStateMachines already returns the authoritative `type`
                    # (STANDARD/EXPRESS). Do NOT re-derive it via
                    # DescribeStateMachine: the monitoring role does not grant
                    # states:DescribeStateMachine, and falling back to STANDARD
                    # on failure mislabels EXPRESS machines, which then hit the
                    # unsupported ListExecutions path and become undetectable
                    # (idle_state_machine can never fire for them).
                    sm.setdefault('type', 'STANDARD')
                    machines.append(sm)
            logger.info(f"StepFunctions: Found {len(machines)} state machines")
            return machines
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Step Function State Machines", permission="stepfunctions:ListStateMachines", error=e,
                )
                self._warn_access_denied("Step Function State Machines", "stepfunctions:ListStateMachines", e)
                raise
            logger.debug(f"Failed to get Step Functions state machines: {e}")
            return []

    async def get_step_function_execution_summary(
        self, state_machine_arn: str, days: int = 14, sm_type: str = 'STANDARD'
    ) -> Optional[StepFunctionExecutionSummaryData]:
        """Get execution summary for a state machine over a window.

        EXPRESS workflows do not support ``ListExecutions`` (it raises
        ``StateMachineTypeNotSupported``), so their execution history is instead
        derived from the CloudWatch execution metrics (ExecutionsStarted/Succeeded/
        Failed/TimedOut/Aborted), which ARE emitted for Express with the
        StateMachineArn dimension. Without this, idle_state_machine could never
        flag an unused EXPRESS machine.
        """
        try:
            if sm_type == 'EXPRESS':
                return self._express_execution_summary_from_cw(state_machine_arn, days)

            sfn = self._get_client('stepfunctions')
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(days=days)
            counts = {'SUCCEEDED': 0, 'FAILED': 0, 'TIMED_OUT': 0, 'ABORTED': 0, 'RUNNING': 0}

            # One unfiltered listing, not one per status, and it STOPS at the
            # window's edge. ListExecutions returns the most recent execution
            # first (documented), so the first execution older than `cutoff`
            # means every remaining one is older too.
            #
            # The previous version made five calls (one per statusFilter), each
            # paging up to 1,000 executions and filtering by date client-side,
            # so its cost grew with a machine's whole execution history rather
            # than with the window. On 2026-09-19 that pushed the step_functions
            # detector past its 15s budget on the fixture account (8 machines,
            # ~500 executions) and it emitted nothing — the same wall any
            # customer with busy state machines would hit on every scan.
            # The counts are unchanged; tests pin equality with the old result.
            paginator = sfn.get_paginator('list_executions')
            done = False
            for page in paginator.paginate(
                stateMachineArn=state_machine_arn,
                PaginationConfig={'MaxItems': 5000},
            ):
                for ex in page.get('executions', []):
                    start = ex.get('startDate')
                    if start and start < cutoff:
                        done = True
                        break
                    status = ex.get('status')
                    if status in counts:
                        counts[status] += 1
                if done:
                    break

            total = sum(counts.values())
            return StepFunctionExecutionSummaryData(
                state_machine_arn=state_machine_arn,
                total_executions=total,
                succeeded=counts['SUCCEEDED'],
                failed=counts['FAILED'],
                timed_out=counts['TIMED_OUT'],
                aborted=counts['ABORTED'],
                running=counts['RUNNING'],
                period_days=days,
            )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Step Function Execution Summary", permission="stepfunctions:ListExecutions", error=e,
                )
                self._warn_access_denied("Step Function Execution Summary", "stepfunctions:ListExecutions", e)
                raise
            logger.debug(f"Failed to get SFN execution summary for {state_machine_arn}: {e}")
            return None

    def _express_execution_summary_from_cw(
        self, state_machine_arn: str, days: int
    ) -> Optional[StepFunctionExecutionSummaryData]:
        """Build an execution summary for an EXPRESS workflow from CloudWatch."""
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            period = 86400 * days
            dim = [{'Name': 'StateMachineArn', 'Value': state_machine_arn}]

            def _sum(metric_name):
                resp = cw.get_metric_statistics(
                    Namespace='AWS/States',
                    MetricName=metric_name,
                    Dimensions=dim,
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=period,
                    Statistics=['Sum'],
                )
                return int(sum(d.get('Sum', 0) for d in resp.get('Datapoints', [])))

            started = _sum('ExecutionsStarted')
            succeeded = _sum('ExecutionsSucceeded')
            failed = _sum('ExecutionsFailed')
            timed_out = _sum('ExecutionsTimedOut')
            aborted = _sum('ExecutionsAborted')
            # Express runs are short-lived; treat any not-yet-terminal starts as running.
            running = max(0, started - succeeded - failed - timed_out - aborted)
            total = max(started, succeeded + failed + timed_out + aborted)

            return StepFunctionExecutionSummaryData(
                state_machine_arn=state_machine_arn,
                total_executions=total,
                succeeded=succeeded,
                failed=failed,
                timed_out=timed_out,
                aborted=aborted,
                running=running,
                period_days=days,
            )
        except Exception as e:
            logger.debug(f"Failed to get Express SFN summary for {state_machine_arn}: {e}")
            return None

    async def get_step_function_retry_metrics(
        self, state_machine_arn: str, days: int = 14
    ) -> Optional[StepFunctionRetryMetricsData]:
        """Get retry and failure metrics from CloudWatch."""
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            period = 86400 * days

            dim = [{'Name': 'StateMachineArn', 'Value': state_machine_arn}]

            def _cw_sum(metric_name):
                resp = cw.get_metric_statistics(
                    Namespace='AWS/States',
                    MetricName=metric_name,
                    Dimensions=dim,
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=period,
                    Statistics=['Sum'],
                )
                return int(sum(d.get('Sum', 0) for d in resp.get('Datapoints', [])))

            executions_started = _cw_sum('ExecutionsStarted')
            executions_failed = _cw_sum('ExecutionsFailed')
            executions_timed_out = _cw_sum('ExecutionsTimedOut')
            # State transitions per state machine are exposed via the Service Metrics
            # group as ConsumedCapacity filtered by ServiceMetric=StateTransition +
            # StateMachineArn — there is NO plain AWS/States "StateTransition" count
            # metric (the previous code read a nonexistent metric → always 0).
            total_transitions = self._cw_state_transitions(
                cw, state_machine_arn, start_time, end_time, period
            )
            executions_succeeded = _cw_sum('ExecutionsSucceeded')

            # Estimate retry transitions: failed+timedout executions still consume transitions
            # Retry ratio = (transitions from failed runs) / total transitions
            total_exec = executions_started if executions_started > 0 else 1
            failure_rate = (executions_failed + executions_timed_out) / total_exec
            # Estimate retry transitions proportional to failure share
            estimated_retry = int(total_transitions * failure_rate) if total_transitions > 0 else 0
            retry_ratio = estimated_retry / total_transitions if total_transitions > 0 else 0.0

            return StepFunctionRetryMetricsData(
                state_machine_arn=state_machine_arn,
                total_transitions=total_transitions,
                estimated_retry_transitions=estimated_retry,
                retry_ratio=retry_ratio,
                failure_rate=failure_rate,
                period_days=days,
            )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Step Function Retry Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Step Function Retry Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.debug(f"Failed to get SFN retry metrics for {state_machine_arn}: {e}")
            return None

    async def get_step_function_transition_metrics(
        self, state_machine_arn: str, days: int = 14
    ) -> Optional[StepFunctionTransitionMetricsData]:
        """Get transition density and duration metrics from CloudWatch."""
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            period = 86400 * days

            dim = [{'Name': 'StateMachineArn', 'Value': state_machine_arn}]

            def _cw_stat(metric_name, stat='Sum'):
                resp = cw.get_metric_statistics(
                    Namespace='AWS/States',
                    MetricName=metric_name,
                    Dimensions=dim,
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=period,
                    Statistics=[stat],
                )
                dps = resp.get('Datapoints', [])
                if not dps:
                    return 0.0
                if stat == 'Sum':
                    return sum(d.get(stat, 0) for d in dps)
                return max(d.get(stat, 0) for d in dps)

            # See _cw_state_transitions: transitions come from the ConsumedCapacity
            # Service Metric (ServiceMetric=StateTransition), not a bare metric name.
            total_transitions = self._cw_state_transitions(
                cw, state_machine_arn, start_time, end_time, period
            )
            succeeded = int(_cw_stat('ExecutionsSucceeded', 'Sum'))
            started = int(_cw_stat('ExecutionsStarted', 'Sum'))

            # Duration metrics (primarily useful for Express workflows)
            avg_duration = _cw_stat('ExecutionTime', 'Average')
            p95_duration = _cw_stat('ExecutionTime', 'Maximum')  # Approximation of p95

            avg_transitions_per_success = (
                total_transitions / succeeded if succeeded > 0 else 0.0
            )

            # Estimate monthly execution rate
            daily_rate = started / days if days > 0 else 0
            monthly_estimate = int(daily_rate * 30)

            return StepFunctionTransitionMetricsData(
                state_machine_arn=state_machine_arn,
                total_transitions=total_transitions,
                successful_executions=succeeded,
                avg_transitions_per_success=avg_transitions_per_success,
                p95_duration_ms=p95_duration,
                avg_duration_ms=avg_duration,
                monthly_execution_estimate=monthly_estimate,
                period_days=days,
            )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Step Function Transition Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Step Function Transition Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.debug(f"Failed to get SFN transition metrics for {state_machine_arn}: {e}")
            return None

    # =========================================================================
    # AppSync
    # =========================================================================

    async def get_appsync_apis(self) -> List[Dict[str, Any]]:
        """List all AppSync GraphQL APIs."""
        try:
            client = self._get_client('appsync')
            apis = []
            response = client.list_graphql_apis()
            apis.extend(response.get('graphqlApis', []))
            while response.get('nextToken'):
                response = client.list_graphql_apis(
                    nextToken=response['nextToken']
                )
                apis.extend(response.get('graphqlApis', []))
            return apis
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="AppSync Apis", permission="appsync:ListGraphqlApis", error=e,
                )
                self._warn_access_denied("AppSync Apis", "appsync:ListGraphqlApis", e)
                raise
            logger.debug(f"Failed to list AppSync APIs: {e}")
            return []

    async def get_appsync_api_cache(self, api_id: str) -> Optional[Dict[str, Any]]:
        """Get cache configuration for an AppSync API."""
        try:
            client = self._get_client('appsync')
            response = client.get_api_cache(apiId=api_id)
            return response.get('apiCache')
        except Exception as e:
            # NotFoundException means no cache — not an error
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="AppSync Api Cache", permission="appsync:GetApiCache", error=e,
                )
                self._warn_access_denied("AppSync Api Cache", "appsync:GetApiCache", e)
                raise
            error_code = getattr(getattr(e, 'response', {}), 'get', lambda *a: None)
            if hasattr(e, 'response') and e.response.get('Error', {}).get('Code') == 'NotFoundException':
                return None
            logger.debug(f"Failed to get AppSync cache for {api_id}: {e}")
            return None

    async def get_appsync_metrics(
        self, api_id: str, metric_name: str,
        days: int = 14, statistic: str = 'Sum'
    ) -> Optional[float]:
        """Get aggregated CloudWatch metric for an AppSync API.

        CLO-485: None when the read fails. It used to return 0.0, which the
        unused-API, idle-cache and idle-subscription gates read as no traffic.
        An empty series is still 0 for a real counter (e.g. Latency
        SampleCount), published only when there is traffic.

        CLO-577: `CacheHitCount`/`CacheMissCount` under `AWS/AppSync` keyed by
        `GraphQLAPIId` are not metrics AWS publishes at all (confirmed against
        docs.aws.amazon.com/appsync/latest/devguide/monitoring.html). The only
        documented cache metrics are the Enhanced (paid) `CacheHit`/`CacheMiss`,
        keyed by `API_Id` + `Resolver`, emitted only when per-resolver enhanced
        metrics are turned on. `GetMetricStatistics` on the bogus name/dimension
        pair still succeeds with an empty `Datapoints`, which this method used
        to sum to 0.0 — read by `_detect_appsync_idle_cache` as "zero cache
        traffic" and turned into a HIGH-confidence false positive on every
        AVAILABLE cache. Withhold instead of querying a metric that cannot
        exist. Reading the real per-resolver `CacheHit`/`CacheMiss` needs
        `cloudwatch:ListMetrics` (or `appsync:ListResolvers`) to find the
        Resolver dimension values. `cloudwise-cur-setup-template.yaml` grants
        `cloudwatch:ListMetrics` since 1.29.0, but no reader is built on it
        yet: a per-resolver CacheHit/CacheMiss read is new verdict logic, a
        follow-up (docs/reviews/template-1-29.md)."""
        if metric_name in _APPSYNC_CACHE_METRICS_NOT_PUBLISHED:
            self._note_idle_verdict_missing(
                'appsync_idle_cache', api_id,
                'cache hit/miss metric not published by AWS (CLO-577)',
            )
            return None
        try:
            cw = self._get_client('cloudwatch')
            response = cw.get_metric_statistics(
                Namespace='AWS/AppSync',
                MetricName=metric_name,
                Dimensions=[{'Name': 'GraphQLAPIId', 'Value': api_id}],
                StartTime=datetime.now(timezone.utc) - timedelta(days=days),
                EndTime=datetime.now(timezone.utc),
                Period=86400 * days,
                Statistics=[statistic]
            )
            return sum(
                dp.get(statistic, 0)
                for dp in response.get('Datapoints', [])
            )
        except Exception as e:
            self._warn_swallowed("AppSync Metrics", "cloudwatch:GetMetricStatistics", e)
            self._note_idle_verdict_missing(
                'appsync', api_id, f"read failed ({self._error_label(e)})",
            )
            return None

    # =========================================================================
    # Aurora
    # =========================================================================

    async def get_aurora_clusters(self) -> List[AuroraClusterData]:
        """Get all Aurora clusters in the region."""
        clusters: List[AuroraClusterData] = []
        try:
            rds = self._get_client('rds')
            paginator = rds.get_paginator('describe_db_clusters')

            # Build a lookup of instance classes from existing RDS instances
            instance_class_map: Dict[str, str] = {}
            # CLO-457: each member's InstanceCreateTime, from the same call.
            instance_created_map: Dict[str, Any] = {}
            try:
                inst_paginator = rds.get_paginator('describe_db_instances')
                for page in inst_paginator.paginate():
                    for inst in page.get('DBInstances', []):
                        instance_class_map[inst.get('DBInstanceIdentifier', '')] = inst.get('DBInstanceClass', '')
                        instance_created_map[inst.get('DBInstanceIdentifier', '')] = inst.get('InstanceCreateTime')
            except Exception as e:
                self._warn_swallowed(
                    "Aurora instance class lookup", "rds:DescribeDBInstances", e,
                )

            for page in paginator.paginate():
                for cluster in page.get('DBClusters', []):
                    engine = cluster.get('Engine', '')
                    if not engine.startswith('aurora'):
                        continue

                    instances = []
                    for member in cluster.get('DBClusterMembers', []):
                        inst_id = member.get('DBInstanceIdentifier', '')
                        inst_class = instance_class_map.get(inst_id, '')
                        instances.append(AuroraClusterInstanceRef(
                            db_instance_id=inst_id,
                            db_instance_class=inst_class,
                            is_writer=member.get('IsClusterWriter', False),
                            instance_create_time=instance_created_map.get(inst_id),
                        ))

                    sv2_config = cluster.get('ServerlessV2ScalingConfiguration')

                    clusters.append(AuroraClusterData(
                        cluster_id=cluster.get('DBClusterIdentifier', ''),
                        engine=engine,
                        engine_version=cluster.get('EngineVersion', ''),
                        engine_mode=cluster.get('EngineMode', 'provisioned'),
                        storage_type=cluster.get('StorageType', 'aurora'),
                        status=cluster.get('Status', ''),
                        region=self._region,
                        instances=instances,
                        serverless_v2_config=sv2_config,
                        is_global_secondary=bool(
                            cluster.get('ReplicationSourceIdentifier')
                        ),
                        tags=self._tags_to_dict(cluster.get('TagList', [])),
                        cluster_create_time=cluster.get('ClusterCreateTime'),
                    ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Aurora Clusters", permission="rds:DescribeDbClusters", error=e,
                )
                self._warn_access_denied("Aurora Clusters", "rds:DescribeDbClusters", e)
                raise
            logger.error(f"Error fetching Aurora clusters: {e}")

        return clusters

    async def get_aurora_io_metrics(
        self, cluster_id: str, days: int = 30, cluster_create_time: Optional[datetime] = None,
    ) -> Optional[AuroraIOMetricsData]:
        """Get I/O and storage metrics from CloudWatch for an Aurora cluster.

        CLO-457: with ``cluster_create_time``, every read starts at the
        creation time and drops daily datapoints from before it, so a cluster
        recreated under a reused DBClusterIdentifier is not charged its
        predecessor's I/Os (see metric_window)."""
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = metric_start_time(end_time, days, cluster_create_time)

            def _own(resp) -> list:
                return drop_pre_creation_datapoints(
                    resp.get('Datapoints', []), cluster_create_time, 86400,
                )

            # Read I/Os
            read_resp = cw.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName='VolumeReadIOPs',
                Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            read_sum = sum(dp.get('Sum', 0) for dp in _own(read_resp))

            # Write I/Os
            write_resp = cw.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName='VolumeWriteIOPs',
                Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            write_sum = sum(dp.get('Sum', 0) for dp in _own(write_resp))

            # Storage used
            storage_resp = cw.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName='VolumeBytesUsed',
                Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Average']
            )
            datapoints = _own(storage_resp)
            storage_avg = (
                sum(dp.get('Average', 0) for dp in datapoints)
                / max(len(datapoints), 1)
            )

            return AuroraIOMetricsData(
                cluster_id=cluster_id,
                volume_read_iops_sum=read_sum,
                volume_write_iops_sum=write_sum,
                volume_bytes_used_avg=storage_avg,
                period_days=days,
            )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Aurora Io Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Aurora Io Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.debug(f"Failed to get Aurora I/O metrics for {cluster_id}: {e}")
            return None

    # ─── Neptune ──────────────────────────────────────────────────────

    async def get_neptune_clusters(self) -> List[NeptuneClusterData]:
        """Get all Neptune clusters in the region."""
        clusters = []
        try:
            neptune = self._get_client('neptune')
            response = neptune.describe_db_clusters()

            for cluster in response.get('DBClusters', []):
                if cluster.get('Engine') != 'neptune':
                    continue

                instances = []
                for member in cluster.get('DBClusterMembers', []):
                    inst_id = member.get('DBInstanceIdentifier', '')
                    try:
                        inst_resp = neptune.describe_db_instances(
                            DBInstanceIdentifier=inst_id
                        )
                        inst_data = inst_resp.get('DBInstances', [{}])[0]
                        inst_class = inst_data.get('DBInstanceClass', '')
                    except ClientError:
                        inst_class = 'unknown'

                    instances.append(NeptuneClusterInstanceRef(
                        db_instance_id=inst_id,
                        db_instance_class=inst_class,
                        is_writer=member.get('IsClusterWriter', False),
                    ))

                sv2_config = cluster.get('ServerlessV2ScalingConfiguration')
                engine_mode = 'serverless' if sv2_config else 'provisioned'

                clusters.append(NeptuneClusterData(
                    cluster_id=cluster.get('DBClusterIdentifier', ''),
                    engine='neptune',
                    engine_version=cluster.get('EngineVersion', ''),
                    engine_mode=engine_mode,
                    status=cluster.get('Status', ''),
                    region=self._region,
                    instances=instances,
                    serverless_v2_config=sv2_config,
                    tags=self._tags_to_dict(cluster.get('TagList', [])),
                    cluster_create_time=cluster.get('ClusterCreateTime'),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Neptune Clusters", permission="neptune:DescribeDbClusters", error=e,
                )
                self._warn_access_denied("Neptune Clusters", "neptune:DescribeDbClusters", e)
                raise
            logger.error(f"Error fetching Neptune clusters: {e}")

        return clusters

    async def get_neptune_snapshots(
        self, snapshot_type: str = 'manual', age_threshold_days: int = 90
    ) -> List[NeptuneSnapshotData]:
        """Get Neptune cluster snapshots matching criteria."""
        snapshots = []
        try:
            neptune = self._get_client('neptune')
            now = datetime.now(timezone.utc)
            threshold = now - timedelta(days=age_threshold_days)

            response = neptune.describe_db_cluster_snapshots(
                SnapshotType=snapshot_type,
                IncludeShared=False,
            )

            for snap in response.get('DBClusterSnapshots', []):
                if snap.get('Engine') != 'neptune':
                    continue

                create_time = snap.get('SnapshotCreateTime')
                if not create_time:
                    continue

                if create_time > threshold:
                    continue  # Too recent

                age_days = (now - create_time).days

                snapshots.append(NeptuneSnapshotData(
                    snapshot_id=snap.get('DBClusterSnapshotIdentifier', ''),
                    cluster_id=snap.get('DBClusterIdentifier', ''),
                    snapshot_type=snap.get('SnapshotType', 'manual'),
                    status=snap.get('Status', ''),
                    engine='neptune',
                    allocated_storage_gb=snap.get('AllocatedStorage', 0),
                    create_time=create_time,
                    age_days=age_days,
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Neptune Snapshots", permission="neptune:DescribeDbClusterSnapshots", error=e,
                )
                self._warn_access_denied("Neptune Snapshots", "neptune:DescribeDbClusterSnapshots", e)
                raise
            logger.error(f"Error fetching Neptune snapshots: {e}")

        return snapshots

    async def get_neptune_cluster_metrics(
        self, cluster_id: str, days: int = 14, cluster_create_time: Optional[datetime] = None,
    ) -> Optional[NeptuneMetricsData]:
        """Get CloudWatch metrics for a Neptune cluster.

        CLO-457: with ``cluster_create_time``, every read starts at the
        creation time (the request Sums are one window-long datapoint, so the
        start time is their only defence) and hourly CPU datapoints from
        before it are dropped. See metric_window."""
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = metric_start_time(end_time, days, cluster_create_time)

            # Gremlin requests
            gremlin_resp = cw.get_metric_statistics(
                Namespace='AWS/Neptune',
                MetricName='GremlinRequestsPerSec',
                Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                StartTime=start_time, EndTime=end_time,
                Period=86400 * days, Statistics=['Sum']
            )
            # CLO-584: kept as a float. A lightly used cluster's
            # GremlinRequestsPerSec Sum over the whole window can be well
            # under 1 (e.g. ~0.12 requests/sec), and wrapping it in int()
            # truncated it to 0 -- indistinguishable from true zero traffic,
            # so idle_neptune fired on a cluster that was actually in use.
            gremlin_requests = sum(
                dp.get('Sum', 0) for dp in drop_pre_creation_datapoints(
                    gremlin_resp.get('Datapoints', []), cluster_create_time, 86400 * days,
                )
            )

            # SPARQL requests
            sparql_resp = cw.get_metric_statistics(
                Namespace='AWS/Neptune',
                MetricName='SparqlRequestsPerSec',
                Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                StartTime=start_time, EndTime=end_time,
                Period=86400 * days, Statistics=['Sum']
            )
            # CLO-584: same truncation risk as gremlin_requests above.
            sparql_requests = sum(
                dp.get('Sum', 0) for dp in drop_pre_creation_datapoints(
                    sparql_resp.get('Datapoints', []), cluster_create_time, 86400 * days,
                )
            )

            # CPU utilization
            cpu_resp = cw.get_metric_statistics(
                Namespace='AWS/Neptune',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                StartTime=start_time, EndTime=end_time,
                Period=3600, Statistics=['Average', 'Maximum']
            )
            # The shared CPU rule's inputs (cpu_sizing, CLO-480): the window
            # maximum is reported only; the percentiles and coverage gate.
            cpu = summarize_hourly_cpu(drop_pre_creation_datapoints(
                cpu_resp.get('Datapoints', []), cluster_create_time, 3600,
            ))

            return NeptuneMetricsData(
                cluster_id=cluster_id,
                gremlin_requests=gremlin_requests,
                sparql_requests=sparql_requests,
                avg_cpu=round(cpu.avg_cpu, 2),
                max_cpu=round(cpu.max_cpu, 2),
                p95_cpu=round(cpu.p95_cpu, 2),
                p95_max_cpu=round(cpu.p95_max_cpu, 2),
                cpu_datapoints=cpu.datapoints,
                period_days=days,
                is_idle=(gremlin_requests + sparql_requests) == 0,
            )
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Neptune Cluster Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("Neptune Cluster Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.debug(f"Failed to get Neptune metrics for {cluster_id}: {e}")
            return None

    # =========================================================================
    # Amazon MQ
    # =========================================================================

    async def get_mq_brokers(self) -> List[MQBrokerData]:
        """Get all Amazon MQ brokers in the region."""
        brokers = []
        try:
            mq = self._get_client('mq')
            response = mq.list_brokers()

            for summary in response.get('BrokerSummaries', []):
                brokers.append(MQBrokerData(
                    broker_id=summary.get('BrokerId', ''),
                    broker_name=summary.get('BrokerName', ''),
                    engine_type=summary.get('EngineType', 'ACTIVEMQ'),
                    host_instance_type=summary.get('HostInstanceType', 'mq.m5.large'),
                    deployment_mode=summary.get('DeploymentMode', 'SINGLE_INSTANCE'),
                    broker_state=summary.get('BrokerState', ''),
                    region=self._region,
                    created=summary.get('Created'),  # CLO-457
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="MQ Brokers", permission="mq:ListBrokers", error=e,
                )
                self._warn_access_denied("MQ Brokers", "mq:ListBrokers", e)
                raise
            logger.error(f"Error fetching MQ brokers: {e}")
        except Exception as e:
            logger.debug(f"MQ not available in this region: {e}")

        return brokers

    async def get_mq_metrics(
        self, broker_id: str, days: int = 14, broker: Optional[MQBrokerData] = None,
    ) -> Optional[MQMetrics]:
        """CloudWatch activity and CPU for an Amazon MQ broker (CLO-516).

        AWS/AmazonMQ's ``Broker`` dimension is the broker NAME. ActiveMQ
        publishes per instance as ``<name>-1`` (and ``<name>-2`` for an
        active/standby pair) with TotalMessageCount / TotalConsumerCount /
        TotalProducerCount / CpuUtilization; RabbitMQ publishes broker-level
        ``<name>`` with MessageCount / ConsumerCount / ConnectionCount /
        SystemCpuUtilization. The old read used the broker ID, got no
        datapoints, and every broker read as idle at 0% CPU.

        Hourly Maximum for the activity gauges (an Average floored by int()
        hid occasional consumers), hourly Average for CPU. A series under 75%
        of the window's hours is MISSING: an unmeasured broker is never idle
        and its CPU is None, never 0%. Returns None when nothing could be
        measured. One GetMetricData request per broker, cached for the
        provider's lifetime (the idle and oversized checks share it)."""
        cache: Dict[Tuple[str, int], Optional[MQMetrics]] = self.__dict__.setdefault('_mq_metrics_cache', {})
        if (broker_id, days) in cache:
            return cache[(broker_id, days)]
        if broker is None or not broker.broker_name:
            self._note_idle_verdict_missing(
                'mq', broker_id, 'broker name unknown', evidence='broker activity metrics',
            )
            cache[(broker_id, days)] = None
            return None

        if (broker.engine_type or '').upper() == 'RABBITMQ':
            instances = [broker.broker_name]
            activity = (('msg', 'MessageCount'), ('con', 'ConsumerCount'), ('pro', 'ConnectionCount'))
            cpu_metric = 'SystemCpuUtilization'
        else:
            suffixes = ['-1', '-2'] if broker.deployment_mode == 'ACTIVE_STANDBY_MULTI_AZ' else ['-1']
            instances = [f'{broker.broker_name}{suffix}' for suffix in suffixes]
            activity = (('msg', 'TotalMessageCount'), ('con', 'TotalConsumerCount'), ('pro', 'TotalProducerCount'))
            cpu_metric = 'CpuUtilization'

        queries: List[Dict[str, Any]] = []
        for i, instance in enumerate(instances):
            dims = [{'Name': 'Broker', 'Value': instance}]
            for key, metric in activity + (('cpu', cpu_metric),):
                queries.append({
                    'Id': f'{key}_{i}',
                    'MetricStat': {
                        'Metric': {'Namespace': 'AWS/AmazonMQ', 'MetricName': metric, 'Dimensions': dims},
                        'Period': 3600,
                        'Stat': 'Average' if key == 'cpu' else 'Maximum',
                    },
                    'ReturnData': True,
                })

        end_time = datetime.now(timezone.utc)
        # CLO-457: the Broker dimension is a reusable NAME. Start at the
        # broker's creation and drop hours that ended before it; the 75%
        # coverage below still counts against the FULL window, so a broker
        # recreated under a reused name is MISSING until it has 75% of the
        # window's hours of its own, never idle on a predecessor's.
        created = getattr(broker, 'created', None)
        start_time = metric_start_time(end_time, days, created)
        points: Dict[str, Dict[Any, float]] = {'msg': {}, 'con': {}, 'pro': {}, 'cpu': {}}
        try:
            cw = self._get_client('cloudwatch')
            next_token: Optional[str] = None
            while True:
                request: Dict[str, Any] = {
                    'MetricDataQueries': queries, 'StartTime': start_time, 'EndTime': end_time,
                    'ScanBy': 'TimestampAscending',
                }
                if next_token:
                    request['NextToken'] = next_token
                response = cw.get_metric_data(**request)
                next_token = response.get('NextToken')
                for res in response.get('MetricDataResults', []):
                    key = (res.get('Id') or '').split('_', 1)[0]
                    if key not in points:
                        continue
                    for ts, value in zip(res.get('Timestamps', []), res.get('Values', [])):
                        if value is None:
                            continue
                        if not drop_pre_creation_datapoints([{'Timestamp': ts}], created, 3600):
                            continue  # CLO-457: a deleted namesake's hour
                        # Per hour, the busiest instance (the standby of a
                        # pair publishes little or nothing).
                        prior = points[key].get(ts)
                        points[key][ts] = value if prior is None else max(prior, value)
                if not next_token:
                    break
        except Exception as e:  # noqa: BLE001 - a failed read is MISSING, never idle
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="MQ Metrics", permission="cloudwatch:GetMetricData", error=e,
                )
                self._warn_access_denied("MQ Metrics", "cloudwatch:GetMetricData", e)
            else:
                self._warn_swallowed("MQ Metrics", "cloudwatch:GetMetricData", e)
            code = e.response.get('Error', {}).get('Code', '') if isinstance(e, ClientError) else ''
            self._note_idle_verdict_missing(
                'mq', broker_id, f"read failed ({code or e.__class__.__name__})",
                evidence='broker activity metrics',
            )
            cache[(broker_id, days)] = None
            return None

        needed = days * 24 * 0.75
        activity_ok = all(len(points[key]) >= needed for key in ('msg', 'con', 'pro'))
        cpu_ok = len(points['cpu']) >= needed
        if not activity_ok:
            missing = [key for key in ('msg', 'con', 'pro') if len(points[key]) < needed]
            reason = 'no datapoints' if all(not points[k] for k in missing) else 'under 75% coverage'
            self._note_idle_verdict_missing('mq', broker_id, reason, evidence='broker activity metrics')
        if not cpu_ok:
            self._note_idle_verdict_missing(
                'mq', broker_id, 'no datapoints' if not points['cpu'] else 'under 75% coverage',
                verdict='oversized', evidence='broker CPU metrics',
            )
        if not activity_ok and not cpu_ok:
            cache[(broker_id, days)] = None
            return None

        def _peak(key: str) -> int:
            return int(math.ceil(max(points[key].values()))) if points[key] else 0

        messages, consumers, producers = _peak('msg'), _peak('con'), _peak('pro')
        cpu = (
            round(sum(points['cpu'].values()) / len(points['cpu']), 2) if cpu_ok else None
        )
        metrics = MQMetrics(
            total_message_count=messages,
            total_consumer_count=consumers,
            total_producer_count=producers,
            cpu_utilization=cpu,
            period_days=days,
            is_idle=activity_ok and messages == 0 and consumers == 0 and producers == 0,
        )
        cache[(broker_id, days)] = metrics
        return metrics

    # ─── Lightsail ────────────────────────────────────────────────

    async def get_lightsail_instances(self) -> List[LightsailInstanceData]:
        """Get all Lightsail instances in the region."""
        if not self._is_lightsail_region_supported():
            logger.debug(f"Lightsail not available in region {self._region}, skipping")
            return []
        try:
            ls = self._get_client('lightsail')
            response = ls.get_instances()
            instances = response.get('instances', [])
            return [LightsailInstanceData(
                name=i['name'],
                state=i.get('state', {}).get('name', 'unknown'),
                bundle_id=i.get('bundleId', ''),
                blueprint_id=i.get('blueprintId', ''),
                ip_address=i.get('publicIpAddress'),
                is_static_ip=i.get('isStaticIp', False),
                region=self._region,
            ) for i in instances]
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lightsail Instances", permission="lightsail:GetInstances", error=e,
                )
                self._warn_access_denied("Lightsail Instances", "lightsail:GetInstances", e)
                raise
            logger.error(f"Error fetching Lightsail instances: {e}")
            return []

    async def get_lightsail_static_ips(self) -> List[LightsailStaticIpData]:
        """Get all Lightsail static IPs in the region."""
        if not self._is_lightsail_region_supported():
            logger.debug(f"Lightsail not available in region {self._region}, skipping")
            return []
        try:
            ls = self._get_client('lightsail')
            response = ls.get_static_ips()
            ips = response.get('staticIps', [])
            return [LightsailStaticIpData(
                name=ip['name'],
                ip_address=ip.get('ipAddress', ''),
                is_attached=ip.get('isAttached', False),
                attached_to=ip.get('attachedTo'),
                region=self._region,
            ) for ip in ips]
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lightsail Static Ips", permission="lightsail:GetStaticIps", error=e,
                )
                self._warn_access_denied("Lightsail Static Ips", "lightsail:GetStaticIps", e)
                raise
            logger.error(f"Error fetching Lightsail static IPs: {e}")
            return []

    async def get_lightsail_disks(self) -> List[LightsailDiskData]:
        """Get all Lightsail additional block storage disks."""
        if not self._is_lightsail_region_supported():
            logger.debug(f"Lightsail not available in region {self._region}, skipping")
            return []
        try:
            ls = self._get_client('lightsail')
            response = ls.get_disks()
            disks = response.get('disks', [])
            return [LightsailDiskData(
                name=d['name'],
                size_in_gb=d.get('sizeInGb', 0),
                state=d.get('state', 'unknown'),
                is_attached=d.get('isAttached', False),
                attached_to=d.get('attachedTo'),
                path=d.get('path'),
                region=self._region,
            ) for d in disks]
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lightsail Disks", permission="lightsail:GetDisks", error=e,
                )
                self._warn_access_denied("Lightsail Disks", "lightsail:GetDisks", e)
                raise
            logger.error(f"Error fetching Lightsail disks: {e}")
            return []

    async def get_lightsail_snapshots(self) -> List[LightsailSnapshotData]:
        """Get all Lightsail instance snapshots."""
        if not self._is_lightsail_region_supported():
            logger.debug(f"Lightsail not available in region {self._region}, skipping")
            return []
        try:
            ls = self._get_client('lightsail')
            response = ls.get_instance_snapshots()
            snaps = response.get('instanceSnapshots', [])
            return [LightsailSnapshotData(
                name=s['name'],
                size_in_gb=s.get('sizeInGb', 0),
                created_at=s.get('createdAt', datetime.min),
                from_instance_name=s.get('fromInstanceName'),
                is_from_auto_snapshot=s.get('isFromAutoSnapshot', False),
                region=self._region,
            ) for s in snaps]
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lightsail Snapshots", permission="lightsail:GetInstanceSnapshots", error=e,
                )
                self._warn_access_denied("Lightsail Snapshots", "lightsail:GetInstanceSnapshots", e)
                raise
            logger.error(f"Error fetching Lightsail snapshots: {e}")
            return []

    async def get_lightsail_load_balancers(self) -> List[LightsailLoadBalancerData]:
        """Get all Lightsail load balancers."""
        if not self._is_lightsail_region_supported():
            logger.debug(f"Lightsail not available in region {self._region}, skipping")
            return []
        try:
            ls = self._get_client('lightsail')
            response = ls.get_load_balancers()
            lbs = response.get('loadBalancers', [])
            return [LightsailLoadBalancerData(
                name=lb['name'],
                dns_name=lb.get('dnsName', ''),
                instance_port=lb.get('instancePort', 80),
                health_check_path=lb.get('healthCheckPath', '/'),
                instance_health_summary=lb.get('instanceHealthSummary', []),
                tls_certificate_summaries=lb.get('tlsCertificateSummaries', []),
                region=self._region,
            ) for lb in lbs]
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lightsail Load Balancers", permission="lightsail:GetLoadBalancers", error=e,
                )
                self._warn_access_denied("Lightsail Load Balancers", "lightsail:GetLoadBalancers", e)
                raise
            logger.error(f"Error fetching Lightsail load balancers: {e}")
            return []

    async def get_lightsail_databases(self) -> List[LightsailDatabaseData]:
        """Get all Lightsail managed databases."""
        if not self._is_lightsail_region_supported():
            logger.debug(f"Lightsail not available in region {self._region}, skipping")
            return []
        try:
            ls = self._get_client('lightsail')
            response = ls.get_relational_databases()
            dbs = response.get('relationalDatabases', [])
            return [LightsailDatabaseData(
                name=db['name'],
                state=db.get('state', 'unknown'),
                engine=db.get('engine', ''),
                engine_version=db.get('engineVersion', ''),
                bundle_id=db.get('relationalDatabaseBundleId', ''),
                master_database_name=db.get('masterDatabaseName', ''),
                secondary_availability_zone=db.get('secondaryAvailabilityZone'),
                region=self._region,
            ) for db in dbs]
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lightsail Databases", permission="lightsail:GetRelationalDatabases", error=e,
                )
                self._warn_access_denied("Lightsail Databases", "lightsail:GetRelationalDatabases", e)
                raise
            logger.error(f"Error fetching Lightsail databases: {e}")
            return []

    async def get_lightsail_metrics(
        self, resource_name: str, resource_type: str = 'instance'
    ) -> LightsailMetricsData:
        """Get CloudWatch metrics for a Lightsail resource."""
        if not self._is_lightsail_region_supported():
            logger.debug(f"Lightsail not available in region {self._region}, skipping")
            return LightsailMetricsData(resource_name=resource_name)
        try:
            ls = self._get_client('lightsail')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=14)

            if resource_type == 'instance':
                response = ls.get_instance_metric_data(
                    instanceName=resource_name,
                    metricName='CPUUtilization',
                    startTime=start_time,
                    endTime=end_time,
                    period=3600,
                    statistics=['Average'],
                    unit='Percent',
                )
                # CLO-506: count the hours that carry a value, against the
                # 14 x 24 read, so the detector can gate on coverage.
                cpu_data = [d for d in response.get('metricData', []) if d.get('average') is not None]
                avg_cpu = sum(d['average'] for d in cpu_data) / len(cpu_data) if cpu_data else None
                max_cpu = max((d['average'] for d in cpu_data), default=None)
                return LightsailMetricsData(
                    resource_name=resource_name,
                    avg_cpu=avg_cpu,
                    max_cpu=max_cpu,
                    cpu_datapoints=len(cpu_data),
                    cpu_window_hours=14 * 24,
                )
            elif resource_type == 'database':
                cpu_response = ls.get_relational_database_metric_data(
                    relationalDatabaseName=resource_name,
                    metricName='CPUUtilization',
                    startTime=start_time,
                    endTime=end_time,
                    period=3600,
                    statistics=['Average'],
                    unit='Percent',
                )
                cpu_data = cpu_response.get('metricData', [])
                conn_response = ls.get_relational_database_metric_data(
                    relationalDatabaseName=resource_name,
                    metricName='DatabaseConnections',
                    startTime=start_time,
                    endTime=end_time,
                    period=3600,
                    statistics=['Average'],
                    unit='Count',
                )
                conn_data = conn_response.get('metricData', [])
                # CLO-540: a datapoint without a value is skipped, and an
                # empty series is MISSING (None, noted), never zero use.
                cpu_values = [d['average'] for d in cpu_data if d.get('average') is not None]
                conn_values = [d['average'] for d in conn_data if d.get('average') is not None]
                avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else None
                avg_conn = sum(conn_values) / len(conn_values) if conn_values else None
                if avg_cpu is None or avg_conn is None:
                    self._note_idle_verdict_missing(
                        'lightsail database', resource_name, 'no datapoints',
                        evidence='CPUUtilization/DatabaseConnections datapoints',
                    )
                return LightsailMetricsData(
                    resource_name=resource_name,
                    avg_cpu=avg_cpu,
                    avg_connections=avg_conn,
                )
            return LightsailMetricsData(resource_name=resource_name)
        except Exception as e:
            # CLO-540: record the action this branch actually called, so a
            # denied database read targets the GetRelationalDatabaseMetricData
            # notice (template_versions.optional_updates_for), not the
            # instance one.
            permission = (
                "lightsail:GetRelationalDatabaseMetricData" if resource_type == 'database'
                else "lightsail:GetInstanceMetricData"
            )
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Lightsail Metrics", permission=permission, error=e,
                )
                self._warn_access_denied("Lightsail Metrics", permission, e)
            if resource_type == 'database':
                self._note_idle_verdict_missing(
                    'lightsail database', resource_name, f'read failed ({e.__class__.__name__})',
                    evidence='CPUUtilization/DatabaseConnections datapoints',
                )
            logger.error(f"Error fetching Lightsail metrics for {resource_name}: {e}")
            return LightsailMetricsData(resource_name=resource_name)

    # =========================================================================
    # EMR / Analytics
    # =========================================================================

    async def get_emr_clusters(self) -> List[EMRClusterData]:
        """Get all active EMR clusters."""
        clusters = []
        try:
            emr = self._get_client('emr')
            # CLO-578: ListClusters paginates (Marker/50-per-page); a single
            # call silently missed every cluster beyond the first page.
            paginator = emr.get_paginator('list_clusters')
            raw_clusters = []
            for page in paginator.paginate(ClusterStates=['WAITING', 'RUNNING']):
                raw_clusters.extend(page.get('Clusters', []))
            for c in raw_clusters:
                cluster_id = c['Id']
                try:
                    details = emr.describe_cluster(ClusterId=cluster_id).get('Cluster', {})
                    timeline = details.get('Status', {}).get('Timeline', {})
                    ig_response = emr.list_instance_groups(ClusterId=cluster_id)
                    instance_groups_raw = ig_response.get('InstanceGroups', [])

                    total_instances = sum(
                        ig.get('RunningInstanceCount', 0) for ig in instance_groups_raw
                    )

                    master_type = ''
                    for ig in instance_groups_raw:
                        if ig.get('InstanceGroupType') == 'MASTER':
                            master_type = ig.get('InstanceType', '')
                            break

                    # CLO-574: the Cluster shape has no AutoTerminationPolicy or
                    # KeepJobFlowAliveWhenNoSteps member -- it has AutoTerminate
                    # (true = the cluster terminates itself after its steps
                    # finish, so it never needs an idle auto-termination policy)
                    # and TerminationProtected. keep_alive is the complement.
                    auto_terminate = details.get('AutoTerminate')
                    keep_alive = (not auto_terminate) if auto_terminate is not None else True

                    # Mirror the detector's own age gate (analytics.py
                    # ~hours_running > 24) here: a cluster younger than 24h is
                    # never a candidate for this finding, so don't spend the
                    # extra API call or raise a MISSING note for it either.
                    ref_time = timeline.get('ReadyDateTime') or timeline.get('CreationDateTime')
                    if ref_time is not None and ref_time.tzinfo is None:
                        ref_time = ref_time.replace(tzinfo=timezone.utc)
                    old_enough = bool(
                        ref_time and (datetime.now(timezone.utc) - ref_time) > timedelta(hours=24)
                    )

                    auto_termination_policy = None
                    auto_termination_unknown = True
                    if keep_alive and old_enough:
                        # Only clusters that don't self-terminate AND are old
                        # enough to be a candidate are worth the extra call;
                        # skip it (and any MISSING note) for the rest.
                        try:
                            policy_resp = emr.get_auto_termination_policy(ClusterId=cluster_id)
                        except Exception as policy_err:  # noqa: BLE001 -- any
                            # failed read (ClientError or a transport failure)
                            # withholds the finding; it must never be read as
                            # "confirmed no policy".
                            self._warn_swallowed(
                                "EMR Auto-Termination Policy",
                                "elasticmapreduce:GetAutoTerminationPolicy",
                                policy_err,
                            )
                            self._note_idle_verdict_missing(
                                'emr auto-termination', cluster_id,
                                f"read failed ({self._error_label(policy_err)})",
                                verdict='auto-termination',
                                evidence='GetAutoTerminationPolicy',
                            )
                        else:
                            # A successful call with no AutoTerminationPolicy key
                            # is the "no policy set" response implied by the
                            # botocore model (no modeled errors for this
                            # operation; AutoTerminationPolicy is an optional
                            # output member) -- distinct from the except above.
                            auto_termination_policy = policy_resp.get('AutoTerminationPolicy')
                            auto_termination_unknown = False

                    clusters.append(EMRClusterData(
                        cluster_id=cluster_id,
                        cluster_name=c.get('Name', cluster_id),
                        state=c.get('Status', {}).get('State', ''),
                        cluster_arn=details.get('ClusterArn', ''),
                        region=self._region,
                        release_label=details.get('ReleaseLabel', ''),
                        auto_termination_policy=auto_termination_policy,
                        auto_termination_unknown=auto_termination_unknown,
                        keep_alive=keep_alive,
                        ready_datetime=timeline.get('ReadyDateTime'),
                        created_datetime=timeline.get('CreationDateTime'),
                        instance_groups=[{
                            'InstanceGroupType': ig.get('InstanceGroupType'),
                            'InstanceType': ig.get('InstanceType'),
                            'RunningInstanceCount': ig.get('RunningInstanceCount', 0),
                            'Market': ig.get('Market', 'ON_DEMAND'),
                            'InstanceGroupId': ig.get('Id'),
                        } for ig in instance_groups_raw],
                        total_instances=total_instances,
                        master_instance_type=master_type,
                        tags={t['Key']: t['Value'] for t in details.get('Tags', [])},
                    ))
                except ClientError as e:
                    logger.warning(f"Error describing EMR cluster {cluster_id}: {e}")
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="EMR Clusters", permission="emr:ListClusters", error=e,
                )
                self._warn_access_denied("EMR Clusters", "emr:ListClusters", e)
                raise
            logger.error(f"Error listing EMR clusters: {e}")
        return clusters

    async def get_emr_instance_groups(self, cluster_id: str) -> List[EMRInstanceGroupData]:
        """Get instance groups for an EMR cluster."""
        groups = []
        try:
            emr = self._get_client('emr')
            response = emr.list_instance_groups(ClusterId=cluster_id)
            for ig in response.get('InstanceGroups', []):
                ebs_config = None
                ebs_volumes = ig.get('EbsBlockDevices', [])
                if ebs_volumes:
                    vol = ebs_volumes[0].get('VolumeSpecification', {})
                    ebs_config = {
                        'VolumeType': vol.get('VolumeType', 'gp3'),
                        'SizeInGB': vol.get('SizeInGB', 32),
                        'VolumesPerInstance': len(ebs_volumes),
                    }
                groups.append(EMRInstanceGroupData(
                    instance_group_id=ig.get('Id', ''),
                    instance_group_type=ig.get('InstanceGroupType', ''),
                    instance_type=ig.get('InstanceType', ''),
                    market=ig.get('Market', 'ON_DEMAND'),
                    running_instance_count=ig.get('RunningInstanceCount', 0),
                    requested_instance_count=ig.get('RequestedInstanceCount', 0),
                    ebs_config=ebs_config,
                    status=ig.get('Status', {}).get('State', ''),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="EMR Instance Groups", permission="emr:ListInstanceGroups", error=e,
                )
                self._warn_access_denied("EMR Instance Groups", "emr:ListInstanceGroups", e)
                raise
            logger.warning(f"Error listing EMR instance groups for {cluster_id}: {e}")
        return groups

    async def get_emr_step_summary(self, cluster_id: str) -> EMRStepSummaryData:
        """Get step execution summary for an EMR cluster."""
        try:
            emr = self._get_client('emr')
            steps = emr.list_steps(ClusterId=cluster_id).get('Steps', [])

            completed = [s for s in steps if s.get('Status', {}).get('State') == 'COMPLETED']
            running = [s for s in steps if s.get('Status', {}).get('State') == 'RUNNING']
            pending = [s for s in steps if s.get('Status', {}).get('State') == 'PENDING']

            last_end = None
            if completed:
                end_times = [
                    s.get('Status', {}).get('Timeline', {}).get('EndDateTime')
                    for s in completed if s.get('Status', {}).get('Timeline', {}).get('EndDateTime')
                ]
                if end_times:
                    last_end = max(end_times)

            return EMRStepSummaryData(
                cluster_id=cluster_id,
                total_steps=len(steps),
                completed_steps=len(completed),
                last_step_end_time=last_end,
                running_steps=len(running),
                pending_steps=len(pending),
            )
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="EMR Step Summary", permission="emr:ListSteps", error=e,
                )
                self._warn_access_denied("EMR Step Summary", "emr:ListSteps", e)
                raise
            logger.warning(f"Error listing EMR steps for {cluster_id}: {e}")
            return EMRStepSummaryData(cluster_id=cluster_id)

    async def get_emr_metrics(
        self,
        cluster_ids: List[str],
        days: int = 14,
    ) -> Dict[str, EMRMetricsData]:
        """Get CloudWatch metrics for EMR clusters."""
        metrics = {}
        try:
            cw = self._get_client('cloudwatch')
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)

            for cluster_id in cluster_ids:
                try:
                    idle_response = cw.get_metric_statistics(
                        Namespace='AWS/ElasticMapReduce',
                        MetricName='IsIdle',
                        Dimensions=[{'Name': 'JobFlowId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Average'],
                    )
                    is_idle_avg = sum(
                        dp.get('Average', 0) for dp in idle_response.get('Datapoints', [])
                    ) / max(len(idle_response.get('Datapoints', [])), 1)

                    yarn_response = cw.get_metric_statistics(
                        Namespace='AWS/ElasticMapReduce',
                        MetricName='YARNMemoryAvailablePercentage',
                        Dimensions=[{'Name': 'JobFlowId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Average'],
                    )
                    yarn_avail = sum(
                        dp.get('Average', 0) for dp in yarn_response.get('Datapoints', [])
                    ) / max(len(yarn_response.get('Datapoints', [])), 1)

                    apps_response = cw.get_metric_statistics(
                        Namespace='AWS/ElasticMapReduce',
                        MetricName='AppsRunning',
                        Dimensions=[{'Name': 'JobFlowId', 'Value': cluster_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,
                        Statistics=['Average'],
                    )
                    apps_avg = sum(
                        dp.get('Average', 0) for dp in apps_response.get('Datapoints', [])
                    ) / max(len(apps_response.get('Datapoints', [])), 1)

                    metrics[cluster_id] = EMRMetricsData(
                        cluster_id=cluster_id,
                        is_idle=is_idle_avg > 0.5,
                        yarn_memory_available_pct=yarn_avail,
                        apps_running_avg=apps_avg,
                        period_days=days,
                    )
                except ClientError as e:
                    if self._is_access_denied(e):
                        self._record_permission_error(
                            resource="EMR Metrics (per-resource)", permission="cloudwatch:GetMetricStatistics", error=e,
                        )
                        self._warn_access_denied("EMR Metrics (per-resource)", "cloudwatch:GetMetricStatistics", e)
                    logger.warning(f"Error fetching EMR metrics for {cluster_id}: {e}")
                    metrics[cluster_id] = EMRMetricsData(cluster_id=cluster_id, period_days=days)
        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="EMR Metrics", permission="cloudwatch:GetMetricStatistics", error=e,
                )
                self._warn_access_denied("EMR Metrics", "cloudwatch:GetMetricStatistics", e)
            logger.error(f"Error fetching EMR metrics: {e}")
        return metrics

    # =========================================================================
    # WorkSpaces
    # =========================================================================

    async def get_workspaces(self) -> List[WorkspaceData]:
        """Get all WorkSpaces via live API."""
        results = []
        try:
            ws = self._get_client('workspaces')
            response = ws.describe_workspaces()
            for w in response.get('Workspaces', []):
                props = w.get('WorkspaceProperties', {})
                bundle_id = w.get('BundleId', '')
                compute_type = props.get('ComputeTypeName', 'STANDARD')
                results.append(WorkspaceData(
                    workspace_id=w.get('WorkspaceId', ''),
                    bundle_id=bundle_id,
                    state=w.get('State', 'UNKNOWN'),
                    running_mode=props.get('RunningMode', 'ALWAYS_ON'),
                    compute_type=compute_type,
                    operating_system=w.get('OperatingSystemName', ''),
                    region=self._region,
                    tags={t['Key']: t['Value'] for t in w.get('Tags', []) if isinstance(t, dict)},
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="WorkSpaces", permission="workspaces:DescribeWorkspaces", error=e,
                )
                self._warn_access_denied("WorkSpaces", "workspaces:DescribeWorkspaces", e)
                raise
            logger.error(f"Error listing WorkSpaces: {e}")
        return results

    async def get_workspaces_connection_status(self, workspace_ids: List[str]) -> List[WorkspaceConnectionData]:
        """Get connection status for WorkSpaces via live API."""
        results = []
        try:
            ws = self._get_client('workspaces')
            # API accepts up to 25 workspace IDs per call
            for i in range(0, len(workspace_ids), 25):
                batch = workspace_ids[i:i + 25]
                response = ws.describe_workspaces_connection_status(WorkspaceIds=batch)
                for c in response.get('WorkspacesConnectionStatus', []):
                    last_ts = c.get('LastKnownUserConnectionTimestamp')
                    if last_ts and isinstance(last_ts, str):
                        try:
                            last_ts = datetime.fromisoformat(last_ts.replace('Z', '+00:00'))
                        except (ValueError, TypeError):
                            last_ts = None
                    results.append(WorkspaceConnectionData(
                        workspace_id=c.get('WorkspaceId', ''),
                        connection_state=c.get('ConnectionState', ''),
                        last_known_user_connection_timestamp=last_ts,
                    ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="WorkSpaces Connection Status", permission="workspaces:DescribeWorkspacesConnectionStatus", error=e,
                )
                self._warn_access_denied("WorkSpaces Connection Status", "workspaces:DescribeWorkspacesConnectionStatus", e)
                raise
            logger.error(f"Error fetching WorkSpaces connection status: {e}")
        return results

    async def get_workspaces_pools(self) -> List[WorkspacePoolData]:
        """Get WorkSpaces Pools via live API."""
        results = []
        try:
            ws = self._get_client('workspaces')
            response = ws.describe_workspaces_pools()
            for p in response.get('WorkspacesPools', []):
                capacity = p.get('Capacity', {})
                results.append(WorkspacePoolData(
                    pool_id=p.get('PoolId', ''),
                    pool_name=p.get('PoolName', p.get('PoolId', '')),
                    state=p.get('State', ''),
                    desired_user_sessions=capacity.get('DesiredUserSessions', 0),
                    running_user_sessions=capacity.get('RunningUserSessions', 0) if capacity else 0,
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="WorkSpaces Pools", permission="workspaces:DescribeWorkspacesPools", error=e,
                )
                self._warn_access_denied("WorkSpaces Pools", "workspaces:DescribeWorkspacesPools", e)
                raise
            logger.error(f"Error listing WorkSpaces Pools: {e}")
        return results

    async def get_workspaces_metrics(
        self,
        workspace_ids: List[str],
        days: int = 14,
    ) -> Dict[str, WorkspaceMetricsData]:
        """CloudWatch metrics for WorkSpaces, in batched GetMetricData requests.

        CLO-506: oversized_workspace never looked at the WorkSpace's load: it
        fired for every downgradeable WorkSpace with 7 days of session data.
        This now also reads AWS/WorkSpaces CPUUsage and MemoryUsage (hourly
        Maximum) and sets ``cpu_peak_p95`` (p95 of the hourly peaks) and
        ``memory_peak_max`` only when both series cover 75% of the window's
        days (``utilization_days``); otherwise they stay None and the
        oversized verdict is MISSING. Four queries per WorkSpace replace two
        GetMetricStatistics calls per WorkSpace. A failed read leaves the
        WorkSpaces out of the map (MISSING) and notes them."""
        metrics: Dict[str, WorkspaceMetricsData] = {}
        ids = list(dict.fromkeys(workspace_ids or []))
        if not ids:
            return metrics
        series_spec = (
            ('ses', 'UserSessionsCount', 86400, 'Maximum'),
            ('con', 'UserConnected', 86400, 'Sum'),
            ('cpu', 'CPUUsage', 3600, 'Maximum'),
            ('mem', 'MemoryUsage', 3600, 'Maximum'),
        )
        queries = [{
            'Id': f'{prefix}{idx}',
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/WorkSpaces',
                    'MetricName': metric,
                    'Dimensions': [{'Name': 'WorkspaceId', 'Value': wid}],
                },
                'Period': period,
                'Stat': stat,
            },
            'ReturnData': True,
        } for idx, wid in enumerate(ids) for prefix, metric, period, stat in series_spec]
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        try:
            points, failed = self._run_metric_data_queries(
                self._get_client('cloudwatch'), queries, start_time, end_time,
            )
        except Exception as e:  # noqa: BLE001 - any failure is MISSING, never zero
            self._warn_swallowed("WorkSpaces metrics", "cloudwatch:GetMetricData", e)
            for wid in ids:
                self._note_idle_verdict_missing(
                    'workspaces', wid, f"read failed ({self._error_label(e)})",
                    verdict='oversized', evidence='CPU and memory metrics',
                )
            return metrics

        need_days = math.ceil(days * WORKSPACES_MIN_COVERAGE)
        for idx, wid in enumerate(ids):
            qids = {prefix: f'{prefix}{idx}' for prefix, _, _, _ in series_spec}
            bad = sorted({failed[q] for q in qids.values() if q in failed})
            if bad:
                self._note_idle_verdict_missing(
                    'workspaces', wid, f"GetMetricData status {'/'.join(bad)}",
                    verdict='oversized', evidence='CPU and memory metrics',
                )
                continue
            sessions = [points[qids['ses']][ts] for ts in sorted(points[qids['ses']])]
            connected = [points[qids['con']][ts] for ts in sorted(points[qids['con']])]
            cpu, mem = points[qids['cpu']], points[qids['mem']]
            cpu_days = {ts.date() for ts in cpu}
            mem_days = {ts.date() for ts in mem}
            utilization_days = len(cpu_days & mem_days)
            entry = WorkspaceMetricsData(
                workspace_id=wid,
                user_sessions_max_daily=sessions,
                user_connected_sum_daily=connected,
                period_days=days,
                observation_days=len(sessions),
                utilization_days=utilization_days,
            )
            if utilization_days >= need_days and cpu and mem:
                entry.cpu_peak_p95 = round(nearest_rank_percentile(list(cpu.values()), 95.0), 2)
                entry.memory_peak_max = round(max(mem.values()), 2)
            metrics[wid] = entry
        return metrics

    # =========================================================================
    # Elastic Beanstalk / Compute
    # =========================================================================

    @staticmethod
    def _describe_all_beanstalk_environments(eb) -> List[Dict[str, Any]]:
        """Every page of DescribeEnvironments (CLO-515: it is paginated by
        NextToken, and the detector now runs in every region of every scan)."""
        environments: List[Dict[str, Any]] = []
        kwargs: Dict[str, Any] = {'IncludeDeleted': False}
        while True:
            response = eb.describe_environments(**kwargs)
            environments.extend(response.get('Environments', []))
            token = response.get('NextToken')
            if not token:
                return environments
            kwargs['NextToken'] = token

    async def get_beanstalk_environments(self) -> List[BeanstalkEnvironmentData]:
        """Get all active Elastic Beanstalk environments."""
        environments = []
        try:
            eb = self._get_client('elasticbeanstalk')
            for env in self._describe_all_beanstalk_environments(eb):
                environments.append(BeanstalkEnvironmentData(
                    environment_id=env.get('EnvironmentId', ''),
                    environment_name=env.get('EnvironmentName', ''),
                    application_name=env.get('ApplicationName', ''),
                    status=env.get('Status', ''),
                    health=env.get('Health', ''),
                    health_status=env.get('HealthStatus', ''),
                    tier=env.get('Tier', {}).get('Name', 'WebServer'),
                    platform_arn=env.get('PlatformArn', ''),
                    version_label=env.get('VersionLabel', ''),
                    cname=env.get('CNAME', ''),
                    date_created=env.get('DateCreated'),
                    date_updated=env.get('DateUpdated'),
                    endpoint_url=env.get('EndpointURL', ''),
                    solution_stack_name=env.get('SolutionStackName', ''),
                ))
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Beanstalk Environments", permission="elasticbeanstalk:DescribeEnvironments", error=e,
                )
                self._warn_access_denied("Beanstalk Environments", "elasticbeanstalk:DescribeEnvironments", e)
                raise
            # CLO-515: re-raise, never return []. The orphaned-RDS check reads
            # "environment not in this list" as "environment gone", so an empty
            # list from a throttled read would call every Beanstalk database
            # orphaned. The detector records it (_warn_swallowed) and judges
            # nothing in this region: MISSING, not zero.
            logger.warning(
                "Beanstalk DescribeEnvironments failed in %s (%s); environments are MISSING for this scan",
                self._region, e.response.get('Error', {}).get('Code', type(e).__name__),
            )
            raise
        return environments

    async def get_beanstalk_configurations(self) -> Dict[str, BeanstalkConfigData]:
        """Get configuration settings for all Beanstalk environments."""
        configs = {}
        try:
            eb = self._get_client('elasticbeanstalk')
            envs = self._describe_all_beanstalk_environments(eb)

            for env in envs:
                env_id = env.get('EnvironmentId', '')
                env_name = env.get('EnvironmentName', '')
                app_name = env.get('ApplicationName', '')

                try:
                    settings = eb.describe_configuration_settings(
                        ApplicationName=app_name,
                        EnvironmentName=env_name,
                    ).get('ConfigurationSettings', [{}])[0]

                    options = {
                        (opt.get('Namespace', ''), opt.get('OptionName', '')): opt.get('Value', '')
                        for opt in settings.get('OptionSettings', [])
                    }

                    configs[env_id] = BeanstalkConfigData(
                        environment_id=env_id,
                        instance_type=options.get(
                            ('aws:autoscaling:launchconfiguration', 'InstanceType'), 't3.micro'
                        ),
                        environment_type=options.get(
                            ('aws:elasticbeanstalk:environment', 'EnvironmentType'), 'SingleInstance'
                        ),
                        load_balancer_type=options.get(
                            ('aws:elasticbeanstalk:environment', 'LoadBalancerType'), ''
                        ),
                        min_size=int(options.get(
                            ('aws:autoscaling:asg', 'MinSize'), '1'
                        )),
                        max_size=int(options.get(
                            ('aws:autoscaling:asg', 'MaxSize'), '1'
                        )),
                        rds_endpoint=options.get(
                            ('aws:rds:dbinstance', 'DBEngine'), ''
                        ),
                    )
                except ClientError as e:
                    logger.warning(f"Error describing config for {env_name}: {e}")
                    configs[env_id] = BeanstalkConfigData(environment_id=env_id)
        except ClientError as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Beanstalk Configurations", permission="elasticbeanstalk:DescribeEnvironments", error=e,
                )
                self._warn_access_denied("Beanstalk Configurations", "elasticbeanstalk:DescribeEnvironments", e)
                raise
            logger.error(f"Error listing Beanstalk environments for config: {e}")
        return configs

    # CLO-524: bounds for the per-region Beanstalk reads.
    _BEANSTALK_MAX_ENVIRONMENTS = 200
    _BEANSTALK_MAX_INSTANCES = 400

    async def get_beanstalk_metrics(
        self,
        environment_names: List[str],
        days: int = 14,
        endpoint_urls: Optional[Dict[str, str]] = None,
    ) -> Dict[str, BeanstalkMetricsData]:
        """CLO-524: request volume and CPU for Beanstalk environments.

        The old read asked AWS/ElasticBeanstalk for RequestCount (Beanstalk
        publishes no such metric) and AWS/EC2 for CPUUtilization on an
        EnvironmentName dimension (AWS/EC2 has none), so both always came
        back empty and neither beanstalk_idle_traffic nor
        beanstalk_over_provisioned could fire. Now, using only reads the
        monitoring role grants:

        - Instances: ec2:DescribeInstances filtered on the
          ``elasticbeanstalk:environment-name`` tag Beanstalk puts on every
          instance it launches (running instances only).
        - Load balancer: the environment's EndpointURL is its load
          balancer's DNS name; matched against elbv2/elb
          DescribeLoadBalancers. A network load balancer publishes no
          RequestCount, so it falls through to enhanced health.
        - One batched GetMetricData pass: hourly AWS/EC2 CPUUtilization per
          instance; daily RequestCount on the ALB (or Classic ELB) with
          HealthyHostCount on the same load balancer as proof the dimension
          is right and the load balancer reported all window (RequestCount
          is a counter, empty when there is no traffic, so on its own an
          empty series can't be told from a wrong dimension); and daily
          ApplicationRequestsTotal, which enhanced health publishes only
          when it is configured.

        request_count_14d is the load balancer's total when HealthyHostCount
        covers 75% of the window's days, else enhanced health's total when
        it covers 75%, else -1 (MISSING). avg_cpu_14d is the mean of the
        hourly per-environment CPU averages when 75% of the window's hours
        carry CPU, else -1. A failed read leaves the affected fields -1 with
        ``missing_reason`` set; nothing is ever read as zero."""
        metrics: Dict[str, BeanstalkMetricsData] = {}
        names = list(dict.fromkeys(environment_names or []))
        if not names:
            return metrics
        over_cap = names[self._BEANSTALK_MAX_ENVIRONMENTS:]
        names = names[:self._BEANSTALK_MAX_ENVIRONMENTS]
        for name in over_cap:
            metrics[name] = BeanstalkMetricsData(
                environment_name=name, period_days=days, missing_reason='over the per-region read cap',
            )
        for name in names:
            metrics[name] = BeanstalkMetricsData(environment_name=name, period_days=days)

        # ── Instances by tag ──
        instances_by_env: Dict[str, List[str]] = {}
        instances_read = True
        try:
            ec2 = self._get_client('ec2')
            for offset in range(0, len(names), 200):
                filters = [
                    {'Name': 'tag:elasticbeanstalk:environment-name', 'Values': names[offset:offset + 200]},
                    {'Name': 'instance-state-name', 'Values': ['running']},
                ]
                for page in ec2.get_paginator('describe_instances').paginate(Filters=filters):
                    for reservation in page.get('Reservations', []):
                        for inst in reservation.get('Instances', []):
                            env = self._get_tag_value(inst.get('Tags', []), 'elasticbeanstalk:environment-name')
                            if env in metrics:
                                instances_by_env.setdefault(env, []).append(inst.get('InstanceId', ''))
        except Exception as e:  # noqa: BLE001 - any failure is MISSING, never zero
            self._warn_swallowed("Beanstalk environment instances", "ec2:DescribeInstances", e)
            instances_read = False
        instance_budget = self._BEANSTALK_MAX_INSTANCES
        for name in names:
            ids = instances_by_env.get(name, [])
            if len(ids) > instance_budget:
                metrics[name].missing_reason = 'instances over the per-region read cap'
                ids = []
            instance_budget -= len(ids)
            metrics[name].instance_ids = ids

        # ── Load balancers by DNS name ──
        lb_by_env: Dict[str, Tuple[str, str, List[str]]] = {}  # name -> (kind, dimension, target groups)
        wanted = {
            name: (url or '').strip().lower().rstrip('.').split('://')[-1]
            for name, url in (endpoint_urls or {}).items() if name in names and url
        }
        if any('.elb.' in host for host in wanted.values()):
            try:
                elbv2 = self._get_client('elbv2')
                v2_by_dns = {
                    (lb.get('DNSName') or '').lower(): lb
                    for page in elbv2.get_paginator('describe_load_balancers').paginate()
                    for lb in page.get('LoadBalancers', [])
                }
                classic_by_dns: Dict[str, Dict[str, Any]] = {}
                if any(host not in v2_by_dns for host in wanted.values() if '.elb.' in host):
                    elb = self._get_client('elb')
                    classic_by_dns = {
                        (lb.get('DNSName') or '').lower(): lb
                        for page in elb.get_paginator('describe_load_balancers').paginate()
                        for lb in page.get('LoadBalancerDescriptions', [])
                    }
                for name, host in wanted.items():
                    lb = v2_by_dns.get(host)
                    if lb is not None:
                        arn = lb.get('LoadBalancerArn', '')
                        if lb.get('Type') == 'application' and 'loadbalancer/' in arn:
                            # CLO-527 item 5: every page. A capped read
                            # would sum RequestCount over some groups only,
                            # so the environment's traffic is MISSING then.
                            groups, tg_complete = _describe_target_groups_bounded(elbv2, arn)
                            if not tg_complete:
                                metrics[name].missing_reason = metrics[name].missing_reason or (
                                    "load balancer has more target groups than the bounded read covers"
                                )
                                continue
                            tg_dims = [
                                g.get('TargetGroupArn', '').split(':')[-1]
                                for g in groups if g.get('TargetGroupArn')
                            ]
                            lb_by_env[name] = ('alb', arn.split('loadbalancer/', 1)[1], tg_dims)
                        else:
                            metrics[name].missing_reason = metrics[name].missing_reason or (
                                f"{lb.get('Type') or 'unknown'} load balancer publishes no RequestCount"
                            )
                        continue
                    classic = classic_by_dns.get(host)
                    if classic is not None:
                        lb_by_env[name] = ('elb', classic.get('LoadBalancerName', ''), [])
            except Exception as e:  # noqa: BLE001 - any failure is MISSING, never zero
                self._warn_swallowed("Beanstalk load balancers", "elasticloadbalancing:DescribeLoadBalancers", e)
                lb_by_env = {}

        # ── One batched GetMetricData pass ──
        queries: List[Dict[str, Any]] = []
        roles: Dict[str, Tuple[str, str]] = {}  # query id -> (environment, role)

        def _q(env_name, role, namespace, metric, dims, period, stat):
            qid = f'eb{len(queries)}'
            roles[qid] = (env_name, role)
            queries.append({
                'Id': qid,
                'MetricStat': {
                    'Metric': {'Namespace': namespace, 'MetricName': metric, 'Dimensions': dims},
                    'Period': period,
                    'Stat': stat,
                },
                'ReturnData': True,
            })

        for name in names:
            for instance_id in metrics[name].instance_ids:
                _q(name, 'cpu', 'AWS/EC2', 'CPUUtilization',
                   [{'Name': 'InstanceId', 'Value': instance_id}], 3600, 'Average')
            lb = lb_by_env.get(name)
            if lb and lb[0] == 'alb':
                _q(name, 'requests', 'AWS/ApplicationELB', 'RequestCount',
                   [{'Name': 'LoadBalancer', 'Value': lb[1]}], 86400, 'Sum')
                for tg in lb[2]:
                    _q(name, 'liveness', 'AWS/ApplicationELB', 'HealthyHostCount',
                       [{'Name': 'TargetGroup', 'Value': tg}, {'Name': 'LoadBalancer', 'Value': lb[1]}],
                       86400, 'Average')
            elif lb and lb[0] == 'elb':
                _q(name, 'requests', 'AWS/ELB', 'RequestCount',
                   [{'Name': 'LoadBalancerName', 'Value': lb[1]}], 86400, 'Sum')
                _q(name, 'liveness', 'AWS/ELB', 'HealthyHostCount',
                   [{'Name': 'LoadBalancerName', 'Value': lb[1]}], 86400, 'Average')
            _q(name, 'app_requests', 'AWS/ElasticBeanstalk', 'ApplicationRequestsTotal',
               [{'Name': 'EnvironmentName', 'Value': name}], 86400, 'Sum')

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        try:
            points, failed = self._run_metric_data_queries(
                self._get_client('cloudwatch'), queries, start_time, end_time,
            )
        except Exception as e:  # noqa: BLE001 - any failure is MISSING, never zero
            self._warn_swallowed("Beanstalk metrics", "cloudwatch:GetMetricData", e)
            for name in names:
                metrics[name].missing_reason = f"read failed ({self._error_label(e)})"
            return metrics

        need_days = math.ceil(days * BEANSTALK_MIN_COVERAGE)
        need_hours = math.ceil(days * 24 * BEANSTALK_MIN_COVERAGE)
        by_env: Dict[str, Dict[str, List[str]]] = {}
        for qid, (env_name, role) in roles.items():
            by_env.setdefault(env_name, {}).setdefault(role, []).append(qid)

        def _days_with_data(qids):
            return {ts.date() if hasattr(ts, 'date') else ts for q in qids for ts in points[q]}

        for name in names:
            entry = metrics[name]
            env_q = by_env.get(name, {})
            bad = sorted({failed[q] for qs in env_q.values() for q in qs if q in failed})
            if bad:
                entry.missing_reason = f"GetMetricData status {'/'.join(bad)}"
                continue

            # Requests: the load balancer first, proven live by HealthyHostCount.
            lb = lb_by_env.get(name)
            live_days = len(_days_with_data(env_q.get('liveness', [])))
            if lb and live_days >= need_days:
                entry.request_count_14d = int(sum(v for q in env_q.get('requests', []) for v in points[q].values()))
                entry.request_source = lb[0]
                entry.request_coverage_days = live_days
                entry.load_balancer = lb[1]
            else:
                app_q = env_q.get('app_requests', [])
                app_days = len(_days_with_data(app_q))
                if app_days >= need_days:
                    entry.request_count_14d = int(sum(v for q in app_q for v in points[q].values()))
                    entry.request_source = 'enhanced_health'
                    entry.request_coverage_days = app_days
                elif not entry.missing_reason:
                    entry.missing_reason = (
                        f"load balancer reported {live_days} of {days} days" if lb
                        else 'no load balancer RequestCount or enhanced-health metrics'
                    )

            # CPU: hourly environment mean across its instances.
            hourly: Dict[Any, List[float]] = {}
            for q in env_q.get('cpu', []):
                for ts, value in points[q].items():
                    hourly.setdefault(ts, []).append(value)
            entry.cpu_coverage_hours = len(hourly)
            if len(hourly) >= need_hours:
                entry.avg_cpu_14d = round(sum(sum(v) / len(v) for v in hourly.values()) / len(hourly), 2)
            elif not entry.missing_reason:
                entry.missing_reason = (
                    'no running instances found by tag' if not entry.instance_ids and instances_read
                    else 'instance read failed' if not instances_read
                    else f"CPU for {len(hourly)} of {days * 24} hours"
                )
        return metrics

    async def get_beanstalk_rds_instances(self) -> Optional[List[RDSInstanceData]]:
        """CLO-506: see WasteDataProvider.get_beanstalk_rds_instances.

        Every DescribeDBInstances page, in its own read (this sweep predates
        CLO-535's bounded paging of ``get_rds_instances``, and any failure
        here is MISSING for the sweep alone). Tags come from each instance's
        TagList, no per-instance ListTagsForResource."""
        try:
            rds = self._get_client('rds')
            rows = [
                db
                for page in rds.get_paginator('describe_db_instances').paginate()
                for db in page.get('DBInstances', [])
            ]
        except Exception as e:  # noqa: BLE001 - any failure is MISSING, never zero
            self._warn_swallowed("Beanstalk orphaned-RDS sweep", "rds:DescribeDBInstances", e)
            return None
        instances: List[RDSInstanceData] = []
        for db in rows:
            tags = self._tags_to_dict(db.get('TagList', []))
            if not beanstalk_rds_marks(tags):
                continue
            instances.append(RDSInstanceData(
                db_instance_id=db.get('DBInstanceIdentifier', ''),
                db_instance_class=db.get('DBInstanceClass', ''),
                engine=db.get('Engine', ''),
                engine_version=db.get('EngineVersion', ''),
                status=db.get('DBInstanceStatus', ''),
                region=self._region,
                multi_az=db.get('MultiAZ', False),
                storage_type=db.get('StorageType', 'gp2'),
                allocated_storage_gb=db.get('AllocatedStorage', 0),
                iops=db.get('Iops'),
                tags=tags,
                db_instance_arn=db.get('DBInstanceArn', ''),
                instance_create_time=db.get('InstanceCreateTime'),
            ))
        return instances

    # =========================================================================
    # Batched CloudWatch reads (CLO-506/507/524)
    # =========================================================================

    # GetMetricData accepts at most 500 queries per request.
    _METRIC_DATA_MAX_QUERIES = 500

    def _run_metric_data_queries(
        self,
        cloudwatch,
        queries: List[Dict[str, Any]],
        start_time: datetime,
        end_time: datetime,
    ) -> Tuple[Dict[str, Dict[Any, float]], Dict[str, str]]:
        """Run ``queries`` through GetMetricData, 500 per request, following
        NextToken pages. Returns ``(points, failed)``: ``points`` maps a
        query Id to {timestamp: value}; ``failed`` maps a query Id whose
        result did not end ``Complete`` to its status (its data can't be
        trusted: MISSING). A ClientError/BotoCoreError propagates; the caller
        decides what is MISSING."""
        points: Dict[str, Dict[Any, float]] = {q['Id']: {} for q in queries}
        failed: Dict[str, str] = {}
        for offset in range(0, len(queries), self._METRIC_DATA_MAX_QUERIES):
            chunk = queries[offset:offset + self._METRIC_DATA_MAX_QUERIES]
            next_token: Optional[str] = None
            while True:
                request: Dict[str, Any] = {
                    'MetricDataQueries': chunk,
                    'StartTime': start_time,
                    'EndTime': end_time,
                    'ScanBy': 'TimestampAscending',
                }
                if next_token:
                    request['NextToken'] = next_token
                response = cloudwatch.get_metric_data(**request)
                next_token = response.get('NextToken')
                for result in response.get('MetricDataResults', []):
                    query_id = result.get('Id')
                    if query_id not in points:
                        continue
                    for ts, value in zip(result.get('Timestamps', []), result.get('Values', [])):
                        if value is not None:
                            points[query_id][ts] = float(value)
                    code = result.get('StatusCode', 'Complete')
                    # PartialData before the last page only means "see NextToken".
                    if code in ('InternalError', 'Forbidden') or (code != 'Complete' and not next_token):
                        failed.setdefault(query_id, code)
                if not next_token:
                    break
        return points, failed

    # =========================================================================
    # API Gateway (CLO-507)
    # =========================================================================

    # GetRestApis returns at most 500 per page; the default regional quota
    # is 600 REST APIs, so two pages cover a normal account.
    _APIGW_PAGE_SIZE = 500
    _APIGW_MAX_PAGES = 4

    async def get_api_gateway_rest_apis(self) -> Optional[List[ApiGatewayRestApiData]]:
        """CLO-507: every REST API (GetRestApis pages, bounded). The detector
        read only the first page of the default 25 before. Past the bound
        the rest are MISSING and noted."""
        apis: List[ApiGatewayRestApiData] = []
        try:
            apigw = self._get_client('apigateway')
            position: Optional[str] = None
            for _ in range(self._APIGW_MAX_PAGES):
                kwargs: Dict[str, Any] = {'limit': self._APIGW_PAGE_SIZE}
                if position:
                    kwargs['position'] = position
                response = apigw.get_rest_apis(**kwargs)
                for api in response.get('items', []):
                    apis.append(ApiGatewayRestApiData(
                        api_id=api.get('id', ''),
                        name=api.get('name', '') or api.get('id', ''),
                        created_date=api.get('createdDate'),
                        endpoint_types=list((api.get('endpointConfiguration') or {}).get('types') or []),
                    ))
                position = response.get('position')
                if not position:
                    break
            else:
                if position:
                    self.data_warnings.append(
                        f"apigateway: more than {len(apis)} REST APIs in {self._region}; the rest "
                        f"were not read and their unused_api_gateway verdicts are MISSING, not zero"
                    )
        except Exception as e:  # noqa: BLE001 - any failure is MISSING, never zero
            self._warn_swallowed("API Gateway REST APIs", "apigateway:GET", e)
            return None
        return apis

    async def get_api_gateway_request_counts(
        self, apis: List[ApiGatewayRestApiData], days: int = 30,
    ) -> Dict[str, float]:
        """CLO-507: see WasteDataProvider.get_api_gateway_request_counts.
        One GetMetricData query per API (daily Sum of Count on ApiName), in
        batched requests; replaces one GetMetricStatistics call per API."""
        counts: Dict[str, float] = {}
        if not apis:
            return counts
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        queries = [{
            'Id': f'apic{idx}',
            'MetricStat': {
                'Metric': {
                    'Namespace': 'AWS/ApiGateway',
                    'MetricName': 'Count',
                    'Dimensions': [{'Name': 'ApiName', 'Value': api.name}],
                },
                'Period': 86400,
                'Stat': 'Sum',
            },
            'ReturnData': True,
        } for idx, api in enumerate(apis)]
        try:
            points, failed = self._run_metric_data_queries(
                self._get_client('cloudwatch'), queries, start_time, end_time,
            )
        except Exception as e:  # noqa: BLE001 - any failure is MISSING, never zero
            self._warn_swallowed("API Gateway request counts", "cloudwatch:GetMetricData", e)
            for api in apis:
                self._note_idle_verdict_missing(
                    'apigateway', api.api_id, f"read failed ({self._error_label(e)})",
                    verdict='unused', evidence='request counts',
                )
            return counts
        for idx, api in enumerate(apis):
            qid = f'apic{idx}'
            if qid in failed:
                self._note_idle_verdict_missing(
                    'apigateway', api.api_id, f"GetMetricData status {failed[qid]}",
                    verdict='unused', evidence='request counts',
                )
                continue
            datapoints = drop_pre_creation_datapoints(
                [{'Timestamp': ts, 'Sum': v} for ts, v in points[qid].items()],
                api.created_date, 86400,
            )
            # Count is a counter: no datapoint means no request (CLO-485).
            counts[api.api_id] = float(sum(dp['Sum'] for dp in datapoints))
        return counts

    async def get_api_gateway_cache_enabled(self, api_id: str) -> Optional[bool]:
        try:
            stages = self._get_client('apigateway').get_stages(restApiId=api_id).get('item', [])
        except Exception as e:  # noqa: BLE001 - any failure is MISSING, never zero
            self._warn_swallowed("API Gateway stages", "apigateway:GET", e)
            return None
        return any(bool(s.get('cacheClusterEnabled')) for s in stages)

    # =========================================================================
    # SageMaker notebook activity (CLO-510)
    # =========================================================================

    # One DescribeLogStreams call per candidate notebook; past this many
    # candidates in a region the rest are MISSING and noted.
    _SAGEMAKER_LOG_READS_MAX = 50
    _SAGEMAKER_NOTEBOOK_LOG_GROUP = '/aws/sagemaker/NotebookInstances'

    async def get_sagemaker_notebook_last_activity(
        self, notebook_names: List[str],
    ) -> Dict[str, Optional[datetime]]:
        """CLO-510: see WasteDataProvider.get_sagemaker_notebook_last_activity.
        Reads ``lastEventTimestamp`` (epoch ms) of ``<name>/jupyter.log``
        with logs:DescribeLogStreams, which the monitoring role grants."""
        activity: Dict[str, Optional[datetime]] = {}
        if not notebook_names:
            return activity
        try:
            logs = self._get_client('logs')
        except Exception as e:  # noqa: BLE001 - client construction failure: MISSING
            self._warn_swallowed("SageMaker notebook Jupyter logs", "logs:DescribeLogStreams", e)
            logs = None
        for idx, name in enumerate(notebook_names):
            if logs is None or idx >= self._SAGEMAKER_LOG_READS_MAX:
                self._note_idle_verdict_missing(
                    'sagemaker-notebook', name,
                    "not read (read cap)" if logs is not None else "read failed",
                    evidence='Jupyter server logs',
                )
                continue
            stream_name = f'{name}/jupyter.log'
            try:
                response = logs.describe_log_streams(
                    logGroupName=self._SAGEMAKER_NOTEBOOK_LOG_GROUP,
                    logStreamNamePrefix=stream_name,
                )
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                    # No log group: the region's notebooks ship no Jupyter
                    # logs (e.g. a VPC with no route to CloudWatch Logs), so
                    # silence proves nothing.
                    self._note_idle_verdict_missing(
                        'sagemaker-notebook', name, "no Jupyter log group",
                        evidence='Jupyter server logs',
                    )
                    continue
                self._warn_swallowed("SageMaker notebook Jupyter logs", "logs:DescribeLogStreams", e)
                self._note_idle_verdict_missing(
                    'sagemaker-notebook', name, f"read failed ({self._error_label(e)})",
                    evidence='Jupyter server logs',
                )
                continue
            except BotoCoreError as e:
                self._warn_swallowed("SageMaker notebook Jupyter logs", "logs:DescribeLogStreams", e)
                self._note_idle_verdict_missing(
                    'sagemaker-notebook', name, f"read failed ({self._error_label(e)})",
                    evidence='Jupyter server logs',
                )
                continue
            stream = next(
                (s for s in response.get('logStreams', []) if s.get('logStreamName') == stream_name),
                None,
            )
            last_ms = (stream or {}).get('lastEventTimestamp') or (stream or {}).get('lastIngestionTime')
            if not last_ms:
                # No stream (or no event in it): the notebook's logs may
                # never reach CloudWatch, so this is MISSING, not idle.
                self._note_idle_verdict_missing(
                    'sagemaker-notebook', name, "no Jupyter log stream",
                    evidence='Jupyter server logs',
                )
                continue
            activity[name] = datetime.fromtimestamp(last_ms / 1000, tz=timezone.utc)
        return activity

    # =========================================================================
    # Global Accelerator / Network
    # =========================================================================

    async def get_global_accelerator_resources(self) -> List[GlobalAcceleratorData]:
        """Fetch Global Accelerator data from live AWS APIs."""
        results = []
        try:
            # Global Accelerator API is always us-west-2
            ga = self._get_client('globalaccelerator', region='us-west-2')
            accelerators = ga.list_accelerators().get('Accelerators', [])

            for acc in accelerators:
                arn = acc['AcceleratorArn']
                listeners = ga.list_listeners(AcceleratorArn=arn).get('Listeners', [])

                all_endpoint_groups = []
                has_endpoints = False
                for listener in listeners:
                    egs = ga.list_endpoint_groups(
                        ListenerArn=listener['ListenerArn']
                    ).get('EndpointGroups', [])
                    all_endpoint_groups.extend(egs)
                    for eg in egs:
                        if eg.get('EndpointDescriptions', []):
                            has_endpoints = True

                # CloudWatch metrics for idle detection
                processed_in = 0.0
                processed_out = 0.0
                try:
                    cw = self._get_client('cloudwatch', region='us-west-2')
                    end_time = datetime.now(timezone.utc)
                    start_time = end_time - timedelta(days=30)

                    for metric_name in ['ProcessedBytesIn', 'ProcessedBytesOut']:
                        response = cw.get_metric_statistics(
                            Namespace='AWS/GlobalAccelerator',
                            MetricName=metric_name,
                            Dimensions=[{'Name': 'Accelerator', 'Value': arn}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=86400 * 30,
                            Statistics=['Sum'],
                        )
                        datapoints = response.get('Datapoints', [])
                        total = sum(dp['Sum'] for dp in datapoints)
                        if metric_name == 'ProcessedBytesIn':
                            processed_in = total
                        else:
                            processed_out = total
                except Exception as e:
                    self._warn_swallowed(
                        "Global Accelerator processed bytes", "cloudwatch:GetMetricStatistics", e,
                    )
                    # CLO-485: a failed read is MISSING, not zero bytes. It
                    # used to leave both sums at 0.0, which the idle gate read
                    # as an accelerator with no traffic.
                    processed_in = None
                    processed_out = None
                    self._note_idle_verdict_missing(
                        'globalaccelerator', acc.get('Name') or arn,
                        f"read failed ({self._error_label(e)})",
                    )

                ip_sets = acc.get('IpSets', [])
                ip_addresses = []
                if ip_sets:
                    ip_addresses = [ip.get('IpAddress', '') for ip in ip_sets[0].get('IpAddresses', [])]

                results.append(GlobalAcceleratorData(
                    name=acc['Name'],
                    arn=arn,
                    status=acc.get('Status', ''),
                    enabled=acc.get('Enabled', True),
                    ip_addresses=ip_addresses,
                    dns_name=acc.get('DnsName', ''),
                    created_time=str(acc.get('CreatedTime', '')),
                    listeners=[{
                        'ListenerArn': l['ListenerArn'],
                        'PortRanges': l.get('PortRanges', []),
                        'Protocol': l.get('Protocol', ''),
                    } for l in listeners],
                    endpoint_groups=[{
                        'EndpointGroupArn': eg['EndpointGroupArn'],
                        'EndpointDescriptions': eg.get('EndpointDescriptions', []),
                    } for eg in all_endpoint_groups],
                    has_endpoints=has_endpoints,
                    processed_bytes_in_sum=processed_in,
                    processed_bytes_out_sum=processed_out,
                ))

        except Exception as e:
            if self._is_access_denied(e):
                self._record_permission_error(
                    resource="Global Accelerator Resources", permission="globalaccelerator:ListAccelerators", error=e,
                )
                self._warn_access_denied("Global Accelerator Resources", "globalaccelerator:ListAccelerators", e)
                raise
            logger.debug(f"Global Accelerator data fetch error: {e}")

        return results
