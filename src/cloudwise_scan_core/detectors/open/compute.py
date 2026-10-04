"""Open-core part of ``detectors/compute.py`` (FSL-1.1-ALv2).

The service entrypoints in ``FREE_TIER_DETECTORS`` and every method they call.
``ComputeDetectorsMixin`` in ``detectors/compute.py`` subclasses this mixin and adds the
closed detectors. Moved verbatim from ``detectors/compute.py`` (CLO-562).
"""

import logging
import math
import re
import uuid
from datetime import date, datetime, timezone
from typing import Dict, Any, List, TYPE_CHECKING
from cloudwise_scan_core.models import WasteItem, WasteDetectionSettings, WasteType, ResourceType, ConfidenceLevel, get_ebs_monthly_cost, get_ec2_monthly_cost, _region_price_multiplier
from cloudwise_scan_core.aws_pricing_service import lightsail_bundle_monthly_price
from cloudwise_scan_core.cpu_sizing import EC2_IDLE_MAX_CPU_THRESHOLD, EC2_IDLE_P95_AVG_CPU_THRESHOLD, EC2_IDLE_P95_MAX_CPU_THRESHOLD, is_as_old_as_window
if TYPE_CHECKING:
    from cloudwise_scan_core.data_providers.base import WasteDataProvider

logger = logging.getLogger(__name__)

# CLO-493: instances another service owns. idle_ec2 never judges them:
# stopping an Auto Scaling member gets it replaced (the ASG's desired count
# is the lever), stopping an EKS node breaks its cluster's capacity, and a
# Beanstalk member is already covered, environment-wide, by idle_beanstalk.
# CLO-499: an EMR node is covered cluster-wide by idle_emr_cluster (judging
# it here double-counts), and a Spot Fleet or EC2 Fleet member is replaced by
# its fleet when stopped (the fleet's target capacity is the lever). All
# three keys start with "aws:", so they survive the export's --anonymize.
_EC2_MANAGED_TAG_KEYS = {
    'aws:autoscaling:groupName': 'Auto Scaling group',
    'eks:cluster-name': 'EKS cluster',
    'aws:eks:cluster-name': 'EKS cluster',
    'elasticbeanstalk:environment-name': 'Elastic Beanstalk environment',
    'aws:elasticmapreduce:job-flow-id': 'EMR cluster',
    'aws:ec2spot:fleet-request-id': 'Spot Fleet',
    'aws:ec2:fleet-id': 'EC2 Fleet',
}


_EC2_MANAGED_TAG_PREFIXES = {
    'kubernetes.io/cluster/': 'Kubernetes cluster',
}


# The export's --anonymize hashes every tag key that does not start with
# "aws:" into tag_<hex>, so eks:cluster-name, kubernetes.io/cluster/* and
# elasticbeanstalk:environment-name cannot be read in such an export.
# CLO-499: the pseudonym's exact shapes, from cloudwise-export.sh's history:
# tag_ + 8 hex (before 2026-02-02), 12 hex (until #837, script 1.10.x) and
# 16 hex (HASH_HEX_LENGTH, script 1.11.0+). Only an Air-Gapped export can
# carry them; online, tag keys are the customer's own (e.g. tag_20240101) and
# are never read as anonymized.
_EC2_ANONYMIZED_TAG_KEY_RE = re.compile(r'^tag_(?:[0-9a-f]{8}|[0-9a-f]{12}|[0-9a-f]{16})$')


# EC2's instance-state names. Anything else (an anonymized export's hashed
# state) is unreadable.
_EC2_INSTANCE_STATES = frozenset({
    'pending', 'running', 'shutting-down', 'terminated', 'stopping', 'stopped',
})


def _ec2_managed_by(tags: Dict[str, str]) -> "str | None":
    """The service that owns this instance, from its tags, or None."""
    for key in tags or {}:
        if key in _EC2_MANAGED_TAG_KEYS:
            return _EC2_MANAGED_TAG_KEYS[key]
        for prefix, owner in _EC2_MANAGED_TAG_PREFIXES.items():
            if key.startswith(prefix):
                return owner
    return None


def _ec2_tags_anonymized(tags: Dict[str, str]) -> bool:
    return any(_EC2_ANONYMIZED_TAG_KEY_RE.match(key or '') for key in tags or {})


# Share of a window's datapoints an idle (or utilization) verdict needs, as in
# #1535's OpenSearch fix and CLO-485.
_MIN_COVERAGE = 0.75


# CLO-528: unused_lambda's window and minimum age (ledger aging_d: 30).
UNUSED_LAMBDA_MIN_AGE_DAYS = 30


def lightsail_cpu_covers_window(metrics) -> bool:
    """CLO-506: whether a Lightsail instance's hourly CPU series covers 75%
    of the hours it was read over. Unknown counts are not coverage."""
    points = getattr(metrics, 'cpu_datapoints', None)
    window = getattr(metrics, 'cpu_window_hours', None)
    if not points or not window:
        return False
    return points >= math.ceil(window * _MIN_COVERAGE)



class OpenComputeDetectorsMixin:
    """Open detectors from ``ComputeDetectorsMixin``."""

    # CLO-507: Lambda's runtime deprecation dates, from AWS's "Lambda
    # runtimes" page (Supported and Deprecated tables, read 2026-10-01). A
    # runtime is flagged once today >= its deprecation date, so a scheduled
    # deprecation (python3.10 on 2026-10-31, dotnet8 on 2026-11-10, ...)
    # starts firing on its own instead of waiting for someone to edit a list.
    # The old hand-kept list ("as of February 2026") missed nodejs18.x,
    # nodejs20.x, python3.9, ruby3.2, provided and provided.al2, and gave
    # wrong dates for several. Targets are the newest runtime of the family
    # that is not scheduled for deprecation before 2028.
    LAMBDA_RUNTIME_DEPRECATIONS: Dict[str, tuple] = {
        # Deprecated
        'provided.al2': (date(2026, 7, 31), 'provided.al2023'),
        'nodejs20.x': (date(2026, 4, 30), 'nodejs24.x'),
        'ruby3.2': (date(2026, 3, 31), 'ruby3.4'),
        'python3.9': (date(2025, 12, 15), 'python3.13'),
        'nodejs18.x': (date(2025, 9, 1), 'nodejs24.x'),
        'dotnet6': (date(2024, 12, 20), 'dotnet10'),
        'python3.8': (date(2024, 10, 14), 'python3.13'),
        'nodejs16.x': (date(2024, 6, 12), 'nodejs24.x'),
        'dotnet7': (date(2024, 5, 14), 'dotnet10'),
        'java8': (date(2024, 1, 8), 'java21'),
        'go1.x': (date(2024, 1, 8), 'provided.al2023'),
        'provided': (date(2024, 1, 8), 'provided.al2023'),
        'ruby2.7': (date(2023, 12, 7), 'ruby3.4'),
        'nodejs14.x': (date(2023, 12, 4), 'nodejs24.x'),
        'python3.7': (date(2023, 12, 4), 'python3.13'),
        'dotnetcore3.1': (date(2023, 4, 3), 'dotnet10'),
        'nodejs12.x': (date(2023, 3, 31), 'nodejs24.x'),
        'python3.6': (date(2022, 7, 18), 'python3.13'),
        'dotnet5.0': (date(2022, 5, 10), 'dotnet10'),
        'dotnetcore2.1': (date(2022, 1, 5), 'dotnet10'),
        'nodejs10.x': (date(2021, 7, 30), 'nodejs24.x'),
        'ruby2.5': (date(2021, 7, 30), 'ruby3.4'),
        'python2.7': (date(2021, 7, 15), 'python3.13'),
        'nodejs8.10': (date(2020, 3, 6), 'nodejs24.x'),
        'nodejs6.10': (date(2019, 8, 12), 'nodejs24.x'),
        'nodejs4.3': (date(2020, 3, 5), 'nodejs24.x'),
        'nodejs4.3-edge': (date(2020, 3, 5), 'nodejs24.x'),
        'dotnetcore2.0': (date(2019, 5, 30), 'dotnet10'),
        'dotnetcore1.0': (date(2019, 6, 27), 'dotnet10'),
        'nodejs': (date(2016, 8, 30), 'nodejs24.x'),
        # Supported today, deprecation scheduled
        'python3.10': (date(2026, 10, 31), 'python3.13'),
        'dotnet8': (date(2026, 11, 10), 'dotnet10'),
        'dotnet9': (date(2026, 11, 10), 'dotnet10'),
        'ruby3.3': (date(2027, 3, 31), 'ruby3.4'),
        'nodejs22.x': (date(2027, 4, 30), 'nodejs24.x'),
        'python3.11': (date(2027, 6, 30), 'python3.13'),
        'java17': (date(2027, 6, 30), 'java21'),
        'java11': (date(2027, 6, 30), 'java21'),
        'java8.al2': (date(2027, 6, 30), 'java21'),
    }

    async def _detect_ec2_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect EC2-related waste using DataProvider.
        
        Works for both online and offline modes via the DataProvider abstraction.
        
        Detectors (with Confidence Levels):
        
        1. IDLE_EC2 (MEDIUM confidence, CLO-493)
           - Detection: hourly CloudWatch CPUUtilization over 14 days (7 in
             an Air-Gapped export) with 75% coverage: mean < 5%, and the
             peak guard in cpu_sizing.ec2_cpu_is_idle. Instances owned by an
             ASG, EKS, Beanstalk, EMR, Spot Fleet or EC2 Fleet are skipped;
             the instance must be as old
             as the window.
           - Savings: Full instance compute cost (the fix is to stop it)
           - AWS Source: CloudWatch metrics, EC2 Pricing API
           
        2. STOPPED_EC2_WITH_EBS (MEDIUM confidence)
           - Detection: Instance state = stopped with BlockDeviceMappings
           - Savings: EBS storage costs (calculated from actual volume sizes)
        """
        waste_items = []
        
        try:
            # Get instances from data provider (works for both online/offline!)
            instances = await data_provider.get_ec2_instances()
            
            if not instances:
                logger.debug("No EC2 instances found")
                return waste_items
            
            # CLO-493: running instances idle_ec2 may judge. Instances another
            # service owns (ASG, EKS, Beanstalk, EMR, Spot Fleet, EC2 Fleet)
            # are skipped. When an Air-Gapped export's --anonymize hashed the
            # tag keys, ownership can't be read: the verdict is MISSING, not
            # "unmanaged" (CLO-499: offline only).
            running_instance_ids = []
            note = getattr(data_provider, '_note_idle_verdict_missing', None)
            for i in instances:
                if i.state not in _EC2_INSTANCE_STATES:
                    # The export's --anonymize (through script 1.14.0) hashes
                    # State.Name ("running" -> res_<hex>): the instance can't
                    # be judged, which is MISSING, not "not running".
                    if callable(note):
                        note('ec2', i.instance_id, "instance state not readable in export")
                    continue
                if i.state != 'running' or _ec2_managed_by(i.tags):
                    continue
                if data_provider.provider_type == 'offline' and _ec2_tags_anonymized(i.tags):
                    if callable(note):
                        note('ec2', i.instance_id, "managed-by tags anonymized in export")
                    continue
                running_instance_ids.append(i.instance_id)
            
            metrics_map = {}
            # CLO-493: an air-gapped export with no metric files at all reads
            # supports_cloudwatch False. Ask the offline provider anyway (it
            # costs nothing): it notes each running instance's missing CPU as
            # MISSING instead of the idle check silently not running.
            wants_metrics = data_provider.supports_cloudwatch or data_provider.provider_type == 'offline'
            if running_instance_ids and settings.cloudwatch_enabled and wants_metrics:
                metrics_map = await data_provider.get_ec2_metrics(
                    instance_ids=running_instance_ids,
                    days=settings.ec2_idle_days,
                    idle_threshold=settings.ec2_idle_cpu_threshold,
                    oversized_threshold=settings.ec2_oversized_cpu_threshold,
                )
            
            volumes_by_id = None  # read once, only if a stopped instance needs it
            for instance in instances:
                # Skip terminated instances
                if instance.state == 'terminated':
                    continue
                
                instance_name = instance.name or instance.instance_id
                
                # Get pricing
                try:
                    pricing = await self.pricing_service.get_ec2_price(
                        instance.instance_type, data_provider.region
                    )
                    monthly_cost = pricing.monthly_estimate
                except Exception:
                    # CLO-359: region-scaled even on this last-resort path.
                    monthly_cost = get_ec2_monthly_cost(
                        instance.instance_type, data_provider.region
                    )
                
                # Check 1: Stopped instances with EBS
                if instance.state == 'stopped':
                    volume_count = len(instance.block_device_mappings or [])
                    if volume_count > 0:
                        # CLO-506: priced from the attached volumes' real
                        # size and type (DescribeVolumes), region-scaled. It
                        # was a flat $2 per volume. A volume the scan could
                        # not read is MISSING: no finding, and a note.
                        if volumes_by_id is None:
                            volumes_by_id = await self._ebs_volumes_by_id(data_provider)
                        priced = self._price_stopped_instance_volumes(
                            instance, volumes_by_id, data_provider.region,
                        )
                        if priced is None:
                            self._note_missing(
                                data_provider, 'ec2-stopped', instance.instance_id,
                                'attached volume not readable', verdict='storage-cost',
                                evidence='attached EBS volume sizes',
                            )
                            continue
                        estimated_cost, volume_lines, kept_on_terminate = priced
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=instance.instance_id,
                            resource_type=ResourceType.EC2_INSTANCE,
                            waste_type=WasteType.STOPPED_EC2_WITH_EBS,
                            title="Stopped Instance with EBS Storage",
                            description=f"Instance '{instance_name}' ({instance.instance_type}) is stopped but has {volume_count} EBS volume(s) incurring storage charges.",
                            monthly_savings=estimated_cost,
                            confidence=ConfidenceLevel.MEDIUM,
                            action="Delete instance and its volumes if no longer needed, or create an AMI and terminate.",
                            action_command=f"aws ec2 terminate-instances --instance-ids {instance.instance_id}",
                            explanation={
                                'detection': f'Instance state is "stopped" with {volume_count} EBS volume(s) still attached',
                                'threshold': 'Any stopped instance with attached EBS volumes',
                                'pricing': (
                                    f'${estimated_cost:.2f}/month EBS storage: ' + '; '.join(volume_lines)
                                ),
                                'why_waste': f'Stopped instances don\'t incur compute charges, but their EBS volumes continue to accumulate storage costs. This instance may have been stopped temporarily and forgotten.',
                                'risk': (
                                    'Create an AMI before terminating if you may need this instance again. Verify no important data exists only on these volumes.'
                                    + (
                                        f' Terminating does NOT delete {", ".join(kept_on_terminate)} '
                                        f'(DeleteOnTermination is off): delete those separately once reviewed.'
                                        if kept_on_terminate else ''
                                    )
                                ),
                            },
                            metadata={
                                'instance_type': instance.instance_type,
                                'instance_name': instance_name,
                                'state': instance.state,
                                'ebs_volumes': volume_count,
                                'ebs_monthly_cost': round(estimated_cost, 2),
                                'volumes_kept_on_terminate': kept_on_terminate,
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
                    continue
                
                if instance.state != 'running':
                    continue
                
                # Check 2: Idle instances (requires CloudWatch metrics)
                # CLO-493: the model's fields are cpu_avg/cpu_max. This read
                # avg_cpu/max_cpu, so every idle instance raised
                # AttributeError and took the detector's other findings
                # (stopped_ec2_with_ebs included) down with it, online and
                # offline. The metadata keys stay avg_cpu/max_cpu: they are
                # the finding's stored shape.
                #
                # CLO-493: the claim is "idle over the window", so the instance
                # must have existed for all of it (CLO-233's minimum-age rule;
                # LaunchTime resets on every start, so a recently restarted
                # instance waits a full window too). Unknown age counts as old.
                metrics = metrics_map.get(instance.instance_id)
                if (metrics and metrics.is_idle
                        and instance.instance_id in running_instance_ids
                        and is_as_old_as_window(instance.launch_time, metrics.period_days)):
                    avg_cpu = metrics.cpu_avg
                    max_cpu = metrics.cpu_max
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=instance.instance_id,
                        resource_type=ResourceType.EC2_INSTANCE,
                        waste_type=WasteType.IDLE_EC2,
                        title="Idle EC2 Instance",
                        description=f"Instance '{instance_name}' ({instance.instance_type}) has averaged only {avg_cpu:.1f}% CPU over {metrics.period_days} days.",
                        monthly_savings=monthly_cost,
                        confidence=ConfidenceLevel.MEDIUM,  # CLO-493: L0 only; see ledger
                        action="Stop or terminate this instance if not needed.",
                        action_command=f"aws ec2 stop-instances --instance-ids {instance.instance_id}",
                        explanation={
                            'detection': f'CloudWatch CPUUtilization averaged {avg_cpu:.1f}% (peak {max_cpu:.1f}%) over {metrics.period_days} days',
                            'threshold': (
                                f'< {settings.ec2_idle_cpu_threshold:g}% average CPU over {metrics.period_days} days, '
                                f'p95 of hourly averages < {EC2_IDLE_P95_AVG_CPU_THRESHOLD:g}%, '
                                f'p95 of hourly peaks < {EC2_IDLE_P95_MAX_CPU_THRESHOLD:g}%, '
                                f'no hourly peak >= {EC2_IDLE_MAX_CPU_THRESHOLD:g}%; '
                                f'not part of an Auto Scaling group, EKS or EMR cluster, Beanstalk environment, Spot Fleet or EC2 Fleet'
                            ),
                            'pricing': f'{instance.instance_type}: ${monthly_cost:.2f}/month (on-demand)',
                            'why_waste': f'This instance has been nearly idle for {metrics.period_days} days. At {avg_cpu:.1f}% average CPU, it is not running meaningful workloads.',
                            'risk': 'Verify no scheduled batch jobs or intermittent workloads before stopping. Check CloudTrail for recent SSH/SSM sessions.',
                        },
                        metadata={
                            'instance_type': instance.instance_type,
                            'instance_name': instance_name,
                            'avg_cpu': avg_cpu,
                            'max_cpu': max_cpu,
                            'p95_cpu': metrics.cpu_p95,
                            'p95_max_cpu': metrics.cpu_p95_max,
                            'cpu_datapoints': metrics.cpu_datapoints,
                            'analysis_days': metrics.period_days,
                            'current_monthly_cost': monthly_cost,
                            'detection_mode': data_provider.provider_type,
                            'cloudwatch_verified': True,
                        }
                    ))

            logger.info(f"EC2 detector found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"Error in EC2 waste detection: {e}")
            raise
    @staticmethod
    def _note_missing(data_provider, service, resource_id, reason, verdict='idle', evidence='activity metrics'):
        """MISSING note through the provider's aggregated channel (CLO-485);
        a test double without it is skipped."""
        note = getattr(data_provider, '_note_idle_verdict_missing', None)
        if callable(note):
            note(service, resource_id, reason, verdict=verdict, evidence=evidence)
    @staticmethod
    async def _ebs_volumes_by_id(data_provider) -> Dict[str, Any]:
        """Every EBS volume in the region by id; {} when the read fails (each
        stopped instance's cost is then MISSING, not $0)."""
        try:
            return {v.volume_id: v for v in await data_provider.get_ebs_volumes()}
        except Exception as e:  # noqa: BLE001 - MISSING, noted per instance
            logger.warning("stopped_ec2_with_ebs: EBS volume read failed (%s)", type(e).__name__)
            return {}
    @staticmethod
    def _price_stopped_instance_volumes(instance, volumes_by_id, region):
        """``(monthly cost, per-volume lines, volume ids kept on terminate)``
        for a stopped instance's attached EBS volumes, or None when any
        attached volume is not in ``volumes_by_id`` (MISSING, not $0).

        Storage at the region-scaled per-GB rate plus io1/io2 provisioned
        IOPS (``get_ebs_monthly_cost``); gp3 IOPS/throughput above the free
        baseline is not counted, so the figure can understate, never
        overstate."""
        total = 0.0
        lines: List[str] = []
        kept: List[str] = []
        for mapping in instance.block_device_mappings or []:
            ebs = (mapping or {}).get('Ebs') or {}
            volume_id = ebs.get('VolumeId')
            volume = volumes_by_id.get(volume_id) if volume_id else None
            if volume is None:
                return None
            cost = get_ebs_monthly_cost(
                volume.volume_type, volume.size_gb, iops=volume.iops or 0, region=region,
            )
            total += cost
            lines.append(f'{volume_id} {volume.size_gb} GB {volume.volume_type} ${cost:.2f}')
            if ebs.get('DeleteOnTermination') is False:
                kept.append(volume_id)
        return total, lines, kept
    # ── Lambda constants ────────────────────────────────────────────────
    # ARM64-compatible runtimes (natively supported by AWS Graviton2)
    ARM64_COMPATIBLE_RUNTIMES = {
        'python3.9', 'python3.10', 'python3.11', 'python3.12', 'python3.13',
        'nodejs16.x', 'nodejs18.x', 'nodejs20.x', 'nodejs22.x',
        'java11', 'java17', 'java21',
        'dotnet6', 'dotnet8',
        'ruby3.2', 'ruby3.3',
        'provided.al2', 'provided.al2023',
    }
    @classmethod
    def _lambda_runtime_eol_message(cls, runtime: str, today: "date | None" = None) -> "str | None":
        """The EOL message for a runtime already past its deprecation date, else None."""
        entry = cls.LAMBDA_RUNTIME_DEPRECATIONS.get(runtime or '')
        if not entry:
            return None
        deprecated_on, target = entry
        if (today or date.today()) < deprecated_on:
            return None
        if runtime == 'go1.x':
            return f'EOL {deprecated_on.isoformat()}. Use {target} with a Go native binary.'
        return f'EOL {deprecated_on.isoformat()}. Migrate to {target}.'
    # CLO-506: excessive-timeout recommendation = 3x the longest observed
    # invocation, never under 10 seconds.
    LAMBDA_TIMEOUT_MAX_MULTIPLIER = 3
    LAMBDA_TIMEOUT_FLOOR_SECONDS = 10
    # Minimum monthly cost threshold for ARM64 migration flagging
    ARM64_MIN_MONTHLY_COST = 1.0
    async def _detect_lambda_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect Lambda-related waste using DataProvider.
        
        Detectors:
        1. UNUSED_LAMBDA - 0 invocations in 30 days
        2. OVER_PROVISIONED_LAMBDA - High memory with low utilization
        3. LAMBDA_PROVISIONED_CONCURRENCY_IDLE - PC utilization < 10% for 14 days
        4. LAMBDA_EXCESSIVE_TIMEOUT - Timeout >= 10x average duration
        5. LAMBDA_ARM64_MIGRATION - x86_64 with ARM64-compatible runtime
        6. LAMBDA_OLD_RUNTIME - Deprecated/EOL runtime
        """
        waste_items = []
        
        try:
            # Get functions from data provider
            functions = await data_provider.get_lambda_functions()
            
            if not functions:
                logger.debug("No Lambda functions found")
                return waste_items
            
            # Get metrics for all functions (if CloudWatch available)
            function_names = [f.function_name for f in functions]
            metrics_map = {}
            if function_names and settings.cloudwatch_enabled and data_provider.supports_cloudwatch:
                metrics_map = await data_provider.get_lambda_metrics(
                    function_names=function_names,
                    days=30,
                )

            # CLO-481: every function's PC configs up front, in one pruned,
            # bounded pass, instead of one serial lookup per function in the
            # loop below. A function absent from the map had a failed lookup:
            # its PC is MISSING, not "none", and check 3 skips it.
            pc_map = await self._lambda_provisioned_concurrency_map(
                data_provider, function_names,
            )
            
            for func in functions:
                func_name = func.function_name
                memory_mb = func.memory_mb
                code_size_gb = func.code_size_bytes / (1024 ** 3) if func.code_size_bytes else 0
                
                metrics = metrics_map.get(func_name)
                
                if metrics:
                    # Check 1: Unused functions (0 invocations)
                    # CLO-528: the ledger's 30-day aging (CLO-233's minimum-age
                    # rule). A function deployed or updated inside the window
                    # has had no chance to be invoked across all of it, so it
                    # is not judged; it also does not fall through to the
                    # memory check (no invocations, nothing to size).
                    # ListFunctions has no creation date: LastModified (the
                    # last code or configuration update) is the closest
                    # timestamp, and it errs towards not flagging. Unknown
                    # LastModified counts as old, like every other age gate.
                    if metrics.invocations_total == 0:
                        if is_as_old_as_window(func.last_modified, UNUSED_LAMBDA_MIN_AGE_DAYS):
                            monthly_savings = max(0.01, code_size_gb * 0.08)
                        
                            waste_items.append(WasteItem(
                                id=str(uuid.uuid4()),
                                resource_id=func_name,
                                resource_type=ResourceType.LAMBDA_FUNCTION,
                                waste_type=WasteType.UNUSED_LAMBDA,
                                title="Unused Lambda Function",
                                description=f"Function '{func_name}' has had 0 invocations in 30 days.",
                                monthly_savings=monthly_savings,
                                confidence=ConfidenceLevel.HIGH,
                                action="Delete this function if it's no longer needed.",
                                action_command=f"aws lambda delete-function --function-name {func_name}",
                                explanation={
                                    'detection': f'CloudWatch Invocations metric = 0 over the past 30 days',
                                    'threshold': '0 invocations in 30 days',
                                    'pricing': f'Storage cost: {code_size_gb:.4f} GB × $0.08/GB = ${monthly_savings:.2f}/month',
                                    'why_waste': f'This function has not been invoked in 30 days. It may be leftover from a decommissioned feature or a one-time migration.',
                                    'risk': 'Check if this function is triggered by scheduled events, S3 notifications, or other async invocations before deleting.',
                                },
                                metadata={
                                    'function_name': func_name,
                                    'memory_mb': memory_mb,
                                    'runtime': func.runtime or 'unknown',
                                    'days_without_invocation': 30,
                                    'detection_mode': data_provider.provider_type,
                                }
                            ))
                    
                    # Check 2: Over-provisioned memory
                    elif metrics.duration_avg_ms and memory_mb >= 512:
                        avg_duration_sec = metrics.duration_avg_ms / 1000
                        if avg_duration_sec < 0.5:
                            current_gb_sec = (memory_mb / 1024) * avg_duration_sec * metrics.invocations_total
                            new_gb_sec = (memory_mb / 2 / 1024) * avg_duration_sec * metrics.invocations_total
                            savings = (current_gb_sec - new_gb_sec) * 0.0000166667
                            
                            if savings >= settings.min_waste_threshold_usd:
                                waste_items.append(WasteItem(
                                    id=str(uuid.uuid4()),
                                    resource_id=func_name,
                                    resource_type=ResourceType.LAMBDA_FUNCTION,
                                    waste_type=WasteType.OVER_PROVISIONED_LAMBDA,
                                    title="Over-Provisioned Lambda Memory",
                                    description=f"Function '{func_name}' has {memory_mb}MB memory but averages {metrics.duration_avg_ms:.0f}ms duration.",
                                    monthly_savings=savings,
                                    confidence=ConfidenceLevel.MEDIUM,
                                    action=f"Reduce memory allocation to {memory_mb // 2}MB.",
                                    explanation={
                                        'detection': f'Function has {memory_mb}MB memory allocated but completes in {metrics.duration_avg_ms:.0f}ms on average',
                                        'threshold': f'>= 512MB memory with < 500ms average duration',
                                        'pricing': f'Current: {memory_mb}MB → Recommended: {memory_mb // 2}MB. Saves ~${savings:.4f}/month based on {metrics.invocations_total:,} invocations',
                                        'why_waste': f'Fast-executing functions with high memory allocation are paying for unused capacity. Lambda charges per GB-second, so halving memory halves cost.',
                                        'risk': 'Lambda CPU scales proportionally with memory. Reducing memory may increase duration. Test with AWS Lambda Power Tuning before applying.',
                                    },
                                    metadata={
                                        'function_name': func_name,
                                        'current_memory_mb': memory_mb,
                                        'avg_duration_ms': metrics.duration_avg_ms,
                                        'detection_mode': data_provider.provider_type,
                                    }
                                ))
                    
                    # Check 4: Excessive timeout
                    # CLO-506: the recommendation used to be 3x the AVERAGE
                    # duration, which can sit below the longest observed
                    # invocation, so the one-click fix would start timing out
                    # real work. It is now 3x the observed MAXIMUM (what the
                    # risk text always told the customer to do), and a
                    # function whose maximum is unknown, or whose safe timeout
                    # is not below the current one, is not flagged.
                    max_duration_sec = (metrics.duration_max_ms or 0) / 1000
                    recommended_timeout = max(
                        self.LAMBDA_TIMEOUT_FLOOR_SECONDS,
                        math.ceil(max_duration_sec * self.LAMBDA_TIMEOUT_MAX_MULTIPLIER),
                    )
                    if (
                        metrics.duration_avg_ms > 0
                        and max_duration_sec > 0
                        and metrics.invocations_total > 100
                        and func.timeout_seconds >= 60
                        and recommended_timeout < func.timeout_seconds
                    ):
                        avg_duration_sec = metrics.duration_avg_ms / 1000
                        timeout_ratio = func.timeout_seconds / avg_duration_sec

                        if timeout_ratio >= 10:
                            # Per-stuck-invocation cost (running at full timeout vs recommended)
                            waste_per_stuck = (
                                (func.timeout_seconds - recommended_timeout)
                                * (memory_mb / 1024)
                                * 0.0000166667
                            )
                            # Monthly exposure: per-stuck cost × invocations × 1% stuck rate
                            # Minimum $0.01 — this is primarily a risk/best-practice finding
                            stuck_rate = 0.01
                            monthly_exposure = waste_per_stuck * metrics.invocations_total * stuck_rate
                            monthly_savings = max(0.01, round(monthly_exposure, 2))
                            
                            waste_items.append(WasteItem(
                                id=str(uuid.uuid4()),
                                resource_id=func_name,
                                resource_type=ResourceType.LAMBDA_FUNCTION,
                                waste_type=WasteType.LAMBDA_EXCESSIVE_TIMEOUT,
                                title="Excessive Lambda Timeout",
                                description=(
                                    f"Function '{func_name}' has a {func.timeout_seconds}s timeout "
                                    f"but averages only {metrics.duration_avg_ms:.0f}ms "
                                    f"({timeout_ratio:.0f}× ratio). "
                                    f"Recommended: {recommended_timeout}s."
                                ),
                                monthly_savings=monthly_savings,
                                confidence=ConfidenceLevel.MEDIUM,
                                action=(
                                    f"Reduce timeout from {func.timeout_seconds}s to "
                                    f"{recommended_timeout}s (3× the longest observed invocation)."
                                ),
                                action_command=(
                                    f"aws lambda update-function-configuration "
                                    f"--function-name {func_name} "
                                    f"--timeout {recommended_timeout}"
                                ),
                                explanation={
                                    'detection': f'Timeout is {func.timeout_seconds}s but average execution is {metrics.duration_avg_ms:.0f}ms ({timeout_ratio:.0f}× ratio)',
                                    'threshold': 'Timeout ≥ 10× average duration and ≥ 60s, and 3× the longest observed invocation is below the current timeout',
                                    'pricing': f'Risk exposure: ${monthly_savings:.2f}/month if 1% of invocations hang to full timeout',
                                    'why_waste': f'An excessive timeout means a stuck invocation burns Lambda compute for {func.timeout_seconds}s instead of failing fast. This is a cost-risk and operational-reliability finding.',
                                    'risk': (
                                        f'The longest invocation in the last 30 days took {metrics.duration_max_ms:.0f}ms; '
                                        f'the recommended {recommended_timeout}s is at least 3× that. Rarer, longer '
                                        f'invocations outside this window would fail at the new timeout.'
                                    ),
                                },
                                metadata={
                                    'function_name': func_name,
                                    'current_timeout_seconds': func.timeout_seconds,
                                    'avg_duration_ms': metrics.duration_avg_ms,
                                    'max_duration_ms': metrics.duration_max_ms,
                                    'timeout_ratio': round(timeout_ratio, 1),
                                    'recommended_timeout_seconds': recommended_timeout,
                                    'invocations_total': metrics.invocations_total,
                                    'detection_mode': data_provider.provider_type,
                                },
                            ))
                    
                    # Check 5: ARM64 migration candidate
                    if (
                        func.architecture == 'x86_64'
                        and func.runtime in self.ARM64_COMPATIBLE_RUNTIMES
                        and metrics.invocations_total > 0
                    ):
                        avg_duration_sec = metrics.duration_avg_ms / 1000
                        monthly_gb_seconds = (
                            metrics.invocations_total
                            * avg_duration_sec
                            * (memory_mb / 1024)
                        )
                        current_monthly_cost = monthly_gb_seconds * 0.0000166667
                        arm64_monthly_cost = monthly_gb_seconds * 0.0000133334
                        arm64_savings = current_monthly_cost - arm64_monthly_cost
                        
                        if current_monthly_cost >= self.ARM64_MIN_MONTHLY_COST:
                            waste_items.append(WasteItem(
                                id=str(uuid.uuid4()),
                                resource_id=func_name,
                                resource_type=ResourceType.LAMBDA_FUNCTION,
                                waste_type=WasteType.LAMBDA_ARM64_MIGRATION,
                                title="ARM64 Migration Candidate",
                                description=(
                                    f"Function '{func_name}' runs on x86_64 with runtime "
                                    f"'{func.runtime}' (ARM64-compatible). Current compute cost: "
                                    f"${current_monthly_cost:.2f}/month. "
                                    f"ARM64 would save ${arm64_savings:.2f}/month (20%)."
                                ),
                                monthly_savings=arm64_savings,
                                confidence=ConfidenceLevel.LOW,
                                action=(
                                    f"Switch architecture from x86_64 to arm64. "
                                    f"Test with your existing test suite first — most "
                                    f"{func.runtime} code works without changes."
                                ),
                                action_command=(
                                    f"aws lambda update-function-configuration "
                                    f"--function-name {func_name} --architectures arm64"
                                ),
                                explanation={
                                    'detection': f'Function runs on x86_64 with ARM64-compatible runtime {func.runtime}',
                                    'threshold': f'x86_64 architecture with ARM64-compatible runtime and ≥ ${self.ARM64_MIN_MONTHLY_COST:.2f}/month compute cost',
                                    'pricing': f'x86_64: ${current_monthly_cost:.2f}/month → ARM64: ${arm64_monthly_cost:.2f}/month (20% savings)',
                                    'why_waste': f'AWS Graviton2 (ARM64) processors offer 20% lower cost per GB-second. Runtime {func.runtime} is fully compatible with ARM64.',
                                    'risk': 'Most code works without changes. Test your function with ARM64 architecture in a staging environment first. Native compiled dependencies may need recompilation.',
                                },
                                metadata={
                                    'function_name': func_name,
                                    'current_architecture': 'x86_64',
                                    'runtime': func.runtime,
                                    'current_monthly_cost': round(current_monthly_cost, 2),
                                    'arm64_monthly_cost': round(arm64_monthly_cost, 2),
                                    'savings_pct': 20,
                                    'monthly_gb_seconds': round(monthly_gb_seconds, 2),
                                    'invocations_total': metrics.invocations_total,
                                    'detection_mode': data_provider.provider_type,
                                },
                            ))
                
                # Check 6: Deprecated runtime (no metrics needed)
                eol_message = self._lambda_runtime_eol_message(func.runtime)
                if eol_message:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=func_name,
                        resource_type=ResourceType.LAMBDA_FUNCTION,
                        waste_type=WasteType.LAMBDA_OLD_RUNTIME,
                        title="Deprecated Lambda Runtime",
                        description=(
                            f"Function '{func_name}' uses deprecated runtime "
                            f"'{func.runtime}'. {eol_message}"
                        ),
                        monthly_savings=0.01,
                        confidence=ConfidenceLevel.LOW,
                        action=f"Update the runtime. {eol_message}",
                        explanation={
                            'detection': f'Function uses deprecated runtime {func.runtime}',
                            'threshold': 'Runtime is past AWS end-of-life date',
                            'pricing': '$0.01/month (hygiene finding — no direct cost savings)',
                            'why_waste': f'Deprecated runtimes no longer receive security patches from AWS. {eol_message}',
                            'risk': 'Runtime migration may require code changes. Test thoroughly in a staging environment. Check for deprecated API usage in your function code.',
                        },
                        metadata={
                            'function_name': func_name,
                            'current_runtime': func.runtime,
                            'eol_info': eol_message,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
                
                # Check 3: Idle Provisioned Concurrency
                try:
                    pc_configs = pc_map.get(func_name)
                    if pc_configs is None:
                        pc_configs = []  # lookup failed: MISSING, not "no PC"
                    
                    for pc in pc_configs:
                        if pc.status != 'READY':
                            continue
                        
                        allocated_units = pc.allocated_provisioned_concurrent_executions
                        memory_gb = memory_mb / 1024
                        
                        # Full monthly cost of this PC allocation
                        monthly_pc_cost = (
                            allocated_units * memory_gb * 2_592_000 * 0.0000041667
                        )
                        
                        utilization_pct = pc.avg_utilization_pct
                        
                        if utilization_pct is None:
                            # No utilization data — if function has zero invocations, 100% wasted
                            if metrics and metrics.invocations_total == 0:
                                utilization_pct = 0.0
                            else:
                                continue  # Can't determine — skip
                        
                        if utilization_pct >= 10.0:
                            continue  # Reasonably utilized
                        
                        wasted_fraction = 1.0 - (utilization_pct / 100.0)
                        monthly_savings = monthly_pc_cost * wasted_fraction
                        
                        if monthly_savings < settings.min_waste_threshold_usd:
                            continue
                        
                        qualifier = pc.function_qualifier or 'N/A'
                        
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=func_name,
                            resource_type=ResourceType.LAMBDA_FUNCTION,
                            waste_type=WasteType.LAMBDA_PROVISIONED_CONCURRENCY_IDLE,
                            title="Idle Provisioned Concurrency",
                            description=(
                                f"Function '{func_name}' (qualifier: {qualifier}) has "
                                f"{allocated_units} Provisioned Concurrency units at "
                                f"{utilization_pct:.1f}% utilization. Monthly PC cost: "
                                f"${monthly_pc_cost:.2f}, wasted: ${monthly_savings:.2f}."
                            ),
                            monthly_savings=monthly_savings,
                            confidence=ConfidenceLevel.HIGH,
                            action=(
                                f"Remove or reduce Provisioned Concurrency. Current: "
                                f"{allocated_units} units. Recommended: "
                                f"{max(1, int(allocated_units * utilization_pct / 100))} "
                                f"units (based on peak utilization)."
                            ),
                            action_command=(
                                f"aws lambda delete-provisioned-concurrency-config "
                                f"--function-name {func_name} --qualifier {qualifier}"
                            ),
                            explanation={
                                'detection': f'Provisioned Concurrency utilization is {utilization_pct:.1f}% for qualifier {qualifier}',
                                'threshold': '< 10% average utilization',
                                'pricing': f'PC allocation: ${monthly_pc_cost:.2f}/month. Wasted portion ({wasted_fraction*100:.0f}%): ${monthly_savings:.2f}/month',
                                'why_waste': f'Provisioned Concurrency keeps {allocated_units} function instances warm 24/7 but only {utilization_pct:.1f}% are used on average. The rest are idle but still billed.',
                                'risk': 'Removing PC may cause cold start latency for the first invocations. Check if the function serves latency-sensitive traffic before removing.',
                            },
                            metadata={
                                'function_name': func_name,
                                'qualifier': qualifier,
                                'allocated_units': allocated_units,
                                'avg_utilization_pct': utilization_pct,
                                'memory_mb': memory_mb,
                                'monthly_pc_cost': round(monthly_pc_cost, 2),
                                'wasted_fraction': round(wasted_fraction, 3),
                                'detection_mode': data_provider.provider_type,
                            },
                        ))
                except Exception as e:
                    logger.debug(f"Could not check PC for {func_name}: {e}")
            
            logger.info(f"Lambda detector found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"Error in Lambda waste detection: {e}")
            raise
    @staticmethod
    async def _lambda_provisioned_concurrency_map(
        data_provider: "WasteDataProvider",
        function_names: List[str],
    ) -> Dict[str, list]:
        """PC configs by function name; a failed lookup is left out.

        Providers built on ``WasteDataProvider`` answer in one bulk call.
        A provider without the bulk method (a duck-typed test double) is
        asked one function at a time, exactly as before CLO-481."""
        bulk = getattr(data_provider, 'get_lambda_provisioned_concurrency_bulk', None)
        if bulk is not None:
            try:
                return await bulk(function_names)
            except Exception as e:
                # As before CLO-481, a PC failure never costs the other
                # lambda checks: every function's PC is MISSING instead.
                logger.warning(f"Lambda provisioned concurrency lookup failed: {e}")
                return {}
        pc_map: Dict[str, list] = {}
        for name in function_names:
            try:
                pc_map[name] = await data_provider.get_lambda_provisioned_concurrency(name)
            except Exception as e:
                logger.debug(f"Could not check PC for {name}: {e}")
        return pc_map
    # Previous-generation SageMaker instance prefixes
    # Only families where the current-gen equivalent is genuinely cheaper.
    # ml.t2 → ml.t3 costs MORE in SageMaker; ml.r4 → ml.r5 is same price;
    # ml.p2 → ml.p3 is 3.4× more expensive.  Those are excluded.
    PREVIOUS_GEN_SAGEMAKER_PREFIXES = (
        "ml.m4.",  # → ml.m5  (18-20% cheaper)
        "ml.c4.",  # → ml.c5  (25-27% cheaper)
    )
    # Upgrade mapping: old_type → (new_type, new_hourly_price)
    SAGEMAKER_UPGRADE_MAP = {
        "ml.m4.xlarge":  ("ml.m5.xlarge",  0.23),
        "ml.m4.2xlarge": ("ml.m5.2xlarge", 0.461),
        "ml.m4.4xlarge": ("ml.m5.4xlarge", 0.922),
        "ml.c4.xlarge":  ("ml.c5.xlarge",  0.204),
        "ml.c4.2xlarge": ("ml.c5.2xlarge", 0.408),
    }
    # CLO-510: SageMaker notebook instance ML storage, us-east-1 $/GB-month.
    SAGEMAKER_NOTEBOOK_STORAGE_PER_GB = 0.14
    def _sagemaker_notebook_storage_rate(self, region: str) -> float:
        return self.SAGEMAKER_NOTEBOOK_STORAGE_PER_GB * _region_price_multiplier(region)
    async def _detect_sagemaker_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect SageMaker waste: idle notebooks/endpoints, oversized, stopped storage, previous-gen."""
        waste_items = []
        
        try:
            # Get SageMaker resources from data provider
            notebooks = await data_provider.get_sagemaker_notebooks()
            endpoints = await data_provider.get_sagemaker_endpoints()
            
            # ── Idle Notebooks ──────────────────────────────────────────
            # CLO-510: LastModifiedTime alone was the idleness signal, but it
            # changes on configuration edits and start/stop, not on use: a
            # notebook started weeks ago and used every day was "idle". It
            # now also needs the notebook's Jupyter server log
            # (/aws/sagemaker/NotebookInstances, <name>/jupyter.log, which
            # records kernel, session and save activity) to have no event in
            # the window. No readable log (read failed, no log stream, or an
            # Air-Gapped export) is MISSING, noted, never idle.
            now = datetime.now(timezone.utc)
            idle_days = settings.sagemaker_notebook_idle_days
            candidates = [
                nb for nb in notebooks
                if nb.status == 'InService' and nb.last_modified_time
                and (now - nb.last_modified_time).days > idle_days
            ]
            activity: Dict[str, Any] = {}
            if candidates:
                try:
                    activity = await data_provider.get_sagemaker_notebook_last_activity(
                        [nb.notebook_name for nb in candidates]
                    )
                except Exception as e:  # noqa: BLE001 - MISSING for every candidate
                    logger.warning("idle_sagemaker_notebook: activity read failed (%s)", type(e).__name__)
                    for nb in candidates:
                        self._note_missing(
                            data_provider, 'sagemaker-notebook', nb.notebook_name, 'read failed',
                            evidence='Jupyter server logs',
                        )
            for nb in candidates:
                last_activity = activity.get(nb.notebook_name)
                if last_activity is None:
                    continue  # MISSING, noted by the provider
                if last_activity.tzinfo is None:
                    last_activity = last_activity.replace(tzinfo=timezone.utc)
                days_since_activity = (now - last_activity).days
                if days_since_activity <= idle_days:
                    continue
                days_idle = min(days_since_activity, (now - nb.last_modified_time).days)
                hourly = self.pricing_service.FALLBACK_SAGEMAKER_PRICING.get(
                    nb.instance_type, 0.10
                )
                cost = hourly * 730
                waste_items.append(WasteItem(
                    id=str(uuid.uuid4()),
                    resource_id=nb.notebook_name,
                    resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
                    waste_type=WasteType.IDLE_SAGEMAKER_NOTEBOOK,
                    title="Idle SageMaker Notebook",
                    description=(
                        f"Notebook '{nb.notebook_name}' ({nb.instance_type}) has been running with no "
                        f"Jupyter activity for {days_idle} days."
                    ),
                    monthly_savings=cost,
                    confidence=ConfidenceLevel.MEDIUM,
                    action="Stop this notebook instance.",
                    action_command=f"aws sagemaker stop-notebook-instance --notebook-instance-name {nb.notebook_name}",
                    explanation={
                        'detection': (
                            f'InService and not started or modified for {(now - nb.last_modified_time).days} days; '
                            f'its Jupyter server log has no event for {days_since_activity} days'
                        ),
                        'threshold': (
                            f'> {idle_days} days since the last start or modification AND '
                            f'> {idle_days} days since the last Jupyter server log event'
                        ),
                        'pricing': f'{nb.instance_type} running 24/7: ${cost:.2f}/month (${hourly:.3f}/hr × 730 hrs)',
                        'why_waste': f'SageMaker notebooks charge per hour while InService regardless of whether you are using them. This one has had no Jupyter activity for {days_idle} days.',
                        'risk': (
                            'Stopping preserves the ML storage volume and data, and the notebook can be restarted. '
                            'A long-running job in a kernel that logs nothing would be interrupted; check before stopping.'
                        ),
                    },
                    metadata={
                        'instance_type': nb.instance_type,
                        'days_idle': days_idle,
                        'last_jupyter_activity': last_activity.isoformat(),
                        'detection_mode': data_provider.provider_type,
                    }
                ))
            
            # ── Stopped Notebook Storage ────────────────────────────────
            for nb in notebooks:
                if nb.status == 'Stopped' and nb.volume_size_gb > 0:
                    days_stopped = 0
                    if nb.last_modified_time:
                        days_stopped = (datetime.now(timezone.utc) - nb.last_modified_time).days
                    
                    if days_stopped < 7:
                        continue  # Recently stopped — skip
                    
                    # CLO-510: notebook volumes bill as SageMaker "Notebook
                    # Instance ML storage", not EBS: $0.14/GB-month in
                    # us-east-1 (Price List, USE1-Notebk:VolumeUsage.gp2,
                    # 2026-10-01). It was $0.116, an EBS-like rate. Other
                    # regions are scaled by the shared multiplier, which
                    # understates and never overstates the regions checked
                    # (eu-west-1 $0.154, ap-southeast-2 $0.168, sa-east-1
                    # $0.266).
                    ml_storage_rate = self._sagemaker_notebook_storage_rate(data_provider.region)
                    storage_cost = nb.volume_size_gb * ml_storage_rate
                    
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=nb.notebook_name,
                        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
                        waste_type=WasteType.STOPPED_SAGEMAKER_NOTEBOOK_STORAGE,
                        title="Stopped Notebook with EBS Storage",
                        description=(
                            f"Notebook '{nb.notebook_name}' has been Stopped for "
                            f"{days_stopped} days but retains a {nb.volume_size_gb} GB "
                            f"ML storage volume costing ${storage_cost:.2f}/month."
                        ),
                        monthly_savings=storage_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete this notebook instance to remove the attached EBS volume.",
                        action_command=f"aws sagemaker delete-notebook-instance --notebook-instance-name {nb.notebook_name}",
                        explanation={
                            'detection': f'Notebook has been in Stopped state for {days_stopped} days with a {nb.volume_size_gb}GB EBS volume attached',
                            'threshold': '> 7 days stopped with attached storage',
                            'pricing': (
                                f'{nb.volume_size_gb}GB × ${ml_storage_rate:.3f}/GB-month '
                                f'(SageMaker notebook ML storage) = ${storage_cost:.2f}/month'
                            ),
                            'why_waste': f'Even though the notebook instance is stopped (no compute charges), the attached EBS volume continues to incur storage costs.',
                            'risk': 'Deleting the notebook instance permanently removes the EBS volume and any data on it. Back up important notebooks to S3 first.',
                        },
                        metadata={
                            'notebook_name': nb.notebook_name,
                            'instance_type': nb.instance_type,
                            'volume_size_gb': nb.volume_size_gb,
                            'days_stopped': days_stopped,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
            
            # ── Previous-Gen Notebooks ──────────────────────────────────
            for nb in notebooks:
                if nb.status not in ('Deleting', 'Failed') and nb.instance_type and \
                   nb.instance_type.startswith(self.PREVIOUS_GEN_SAGEMAKER_PREFIXES):
                    current_hourly = self.pricing_service.FALLBACK_SAGEMAKER_PRICING.get(
                        nb.instance_type, 0.10
                    )
                    upgrade_target, upgrade_hourly = self.SAGEMAKER_UPGRADE_MAP.get(
                        nb.instance_type, (None, current_hourly)
                    )
                    savings = (current_hourly - upgrade_hourly) * 730
                    if savings < 0.01:
                        continue  # No cost benefit — skip
                    
                    desc = (
                        f"Notebook '{nb.notebook_name}' uses {nb.instance_type} "
                        f"(previous generation). Upgrade to {upgrade_target or 'current gen'} "
                        f"for ~${savings:.0f}/month savings."
                    )
                    
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=nb.notebook_name,
                        resource_type=ResourceType.SAGEMAKER_NOTEBOOK,
                        waste_type=WasteType.PREVIOUS_GEN_SAGEMAKER_INSTANCE,
                        title="Previous-Gen SageMaker Instance",
                        description=desc,
                        monthly_savings=savings,
                        confidence=ConfidenceLevel.HIGH,
                        action=f"Migrate to {upgrade_target or 'current-gen equivalent'}.",
                        action_command=(
                            f"aws sagemaker update-notebook-instance "
                            f"--notebook-instance-name {nb.notebook_name} "
                            f"--instance-type {upgrade_target}"
                        ) if upgrade_target else None,
                        explanation={
                            'detection': f'Instance type {nb.instance_type} is a previous-generation family',
                            'threshold': 'Using ml.m4.* or ml.c4.* instance families',
                            'pricing': f'{nb.instance_type} (${current_hourly:.3f}/hr) → {upgrade_target or "current-gen"} (${upgrade_hourly:.3f}/hr) = ${savings:.0f}/month savings',
                            'why_waste': f'Current-generation instances (ml.m5/ml.c5) offer better performance at 18-27% lower cost on the same workloads.',
                            'risk': 'The notebook must be stopped before changing instance type. Verify your ML frameworks are compatible with the new instance family.',
                        },
                        metadata={
                            'resource_name': nb.notebook_name,
                            'current_instance_type': nb.instance_type,
                            'recommended_instance_type': upgrade_target,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
            
            # ── Endpoint Detectors (idle, oversized, previous-gen) ──────
            metrics_map = {}
            if endpoints and settings.cloudwatch_enabled and data_provider.supports_cloudwatch:
                endpoint_names = [e.endpoint_name for e in endpoints if e.status == 'InService']
                if endpoint_names:
                    metrics_map = await data_provider.get_sagemaker_metrics(
                        endpoint_names=endpoint_names,
                        days=settings.sagemaker_endpoint_idle_days,
                        # CLO-457: EndpointName is a name; only each
                        # endpoint's own datapoints, not a deleted namesake's.
                        create_times={
                            e.endpoint_name: getattr(e, 'creation_time', None) for e in endpoints
                        },
                    )
            
            for endpoint in endpoints:
                if endpoint.status != 'InService':
                    continue
                
                metrics = metrics_map.get(endpoint.endpoint_name)
                hourly = self.pricing_service.FALLBACK_SAGEMAKER_PRICING.get(
                    endpoint.instance_type or "ml.t3.medium", 0.10
                )
                monthly_cost = hourly * 730 * (endpoint.instance_count or 1)
                
                # ── Idle Endpoint ───────────────────────────────────────
                # CLO-233's minimum-age rule (CLO-457): "0 invocations in N
                # days" needs an endpoint that existed for all N days. A
                # younger one (including one recreated under a reused name,
                # now judged on its own days only) is not called idle on
                # partial data. Unknown creation time counts as old.
                # CLO-485: the provider's verdict, not a 0 default. A failed
                # read (online) or a missing export entry (offline) used to
                # arrive as a default model with invocations_total=0.
                if metrics and metrics.is_idle and is_as_old_as_window(
                    getattr(endpoint, 'creation_time', None), settings.sagemaker_endpoint_idle_days,
                ):
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=endpoint.endpoint_name,
                        resource_type=ResourceType.SAGEMAKER_ENDPOINT,
                        waste_type=WasteType.IDLE_SAGEMAKER_ENDPOINT,
                        title="Idle SageMaker Endpoint",
                        description=(
                            f"Endpoint '{endpoint.endpoint_name}' "
                            f"({endpoint.instance_type or 'unknown'} × {endpoint.instance_count}) "
                            f"has had 0 invocations in {metrics.period_days} days."
                        ),
                        monthly_savings=monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete this endpoint.",
                        action_command=f"aws sagemaker delete-endpoint --endpoint-name {endpoint.endpoint_name}",
                        explanation={
                            'detection': f'Endpoint has received 0 invocations over {metrics.period_days} days of monitoring',
                            'threshold': '0 invocations over the monitoring period',
                            'pricing': f'{endpoint.instance_type or "unknown"} × {endpoint.instance_count} instance(s) = ${monthly_cost:.2f}/month',
                            'why_waste': f'SageMaker endpoints charge per instance-hour 24/7, even with zero inference requests. This endpoint has been idle for {metrics.period_days} days.',
                            'risk': 'Deleting the endpoint does not delete the model or endpoint configuration. You can recreate it if needed.',
                        },
                        metadata={
                            'endpoint_name': endpoint.endpoint_name,
                            'instance_type': endpoint.instance_type,
                            'instance_count': endpoint.instance_count,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                
                # ── Oversized Endpoint ──────────────────────────────────
                OVERSIZED_CPU_THRESHOLD = 20.0
                OVERSIZED_MEM_THRESHOLD = 20.0
                MIN_INVOCATIONS = 100
                
                if metrics and metrics.invocations_total >= MIN_INVOCATIONS:
                    if (metrics.cpu_utilization_avg > 0 and
                        metrics.cpu_utilization_avg < OVERSIZED_CPU_THRESHOLD and
                        metrics.memory_utilization_avg > 0 and
                        metrics.memory_utilization_avg < OVERSIZED_MEM_THRESHOLD):
                        
                        estimated_savings = monthly_cost * 0.40  # Conservative 40% savings
                        
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=endpoint.endpoint_name,
                            resource_type=ResourceType.SAGEMAKER_ENDPOINT,
                            waste_type=WasteType.OVERSIZED_SAGEMAKER_ENDPOINT,
                            title="Oversized SageMaker Endpoint",
                            description=(
                                f"Endpoint '{endpoint.endpoint_name}' "
                                f"({endpoint.instance_type or 'unknown'} × "
                                f"{endpoint.instance_count}) has avg CPU "
                                f"{metrics.cpu_utilization_avg:.1f}% and Memory "
                                f"{metrics.memory_utilization_avg:.1f}% over "
                                f"{metrics.period_days}d — consider downsizing."
                            ),
                            monthly_savings=estimated_savings,
                            confidence=ConfidenceLevel.MEDIUM,
                            action="Right-size this endpoint to a smaller instance type.",
                            action_command=(
                                f"aws sagemaker update-endpoint "
                                f"--endpoint-name {endpoint.endpoint_name} "
                                f"--endpoint-config-name <new-config>"
                            ),
                            explanation={
                                'detection': f'Average CPU {metrics.cpu_utilization_avg:.1f}% and Memory {metrics.memory_utilization_avg:.1f}% over {metrics.period_days} days with {metrics.invocations_total} invocations',
                                'threshold': f'CPU < {OVERSIZED_CPU_THRESHOLD}% and Memory < {OVERSIZED_MEM_THRESHOLD}% with ≥ {MIN_INVOCATIONS} invocations',
                                'pricing': f'Current: ${monthly_cost:.2f}/month. Estimated 40% savings: ${estimated_savings:.2f}/month',
                                'why_waste': f'Both CPU and memory are under-utilized, indicating the endpoint is over-provisioned for its actual inference workload.',
                                'risk': 'Create a new endpoint configuration with a smaller instance type and test with realistic traffic before switching. Use SageMaker Inference Recommender for data-driven sizing.',
                            },
                            metadata={
                                'endpoint_name': endpoint.endpoint_name,
                                'instance_type': endpoint.instance_type,
                                'instance_count': endpoint.instance_count,
                                'cpu_avg': metrics.cpu_utilization_avg,
                                'memory_avg': metrics.memory_utilization_avg,
                                'invocations_total': metrics.invocations_total,
                                'detection_mode': data_provider.provider_type,
                            },
                        ))
                
                # ── Previous-Gen Endpoint ───────────────────────────────
                if endpoint.instance_type and \
                   endpoint.instance_type.startswith(self.PREVIOUS_GEN_SAGEMAKER_PREFIXES):
                    current_hourly = self.pricing_service.FALLBACK_SAGEMAKER_PRICING.get(
                        endpoint.instance_type, 0.10
                    )
                    upgrade_target, upgrade_hourly = self.SAGEMAKER_UPGRADE_MAP.get(
                        endpoint.instance_type, (None, current_hourly)
                    )
                    savings = (current_hourly - upgrade_hourly) * 730 * (endpoint.instance_count or 1)
                    if savings < 0.01:
                        continue  # No cost benefit — skip
                    
                    desc = (
                        f"Endpoint '{endpoint.endpoint_name}' uses {endpoint.instance_type} "
                        f"(previous generation). Upgrade to {upgrade_target or 'current gen'} "
                        f"for ~${savings:.0f}/month savings."
                    )
                    
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=endpoint.endpoint_name,
                        resource_type=ResourceType.SAGEMAKER_ENDPOINT,
                        waste_type=WasteType.PREVIOUS_GEN_SAGEMAKER_INSTANCE,
                        title="Previous-Gen SageMaker Instance",
                        description=desc,
                        monthly_savings=savings,
                        confidence=ConfidenceLevel.HIGH,
                        action=f"Migrate to {upgrade_target or 'current-gen equivalent'}.",
                        action_command=None,
                        explanation={
                            'detection': f'Endpoint instance type {endpoint.instance_type} is a previous-generation family',
                            'threshold': 'Using ml.m4.* or ml.c4.* instance families',
                            'pricing': f'{endpoint.instance_type} (${current_hourly:.3f}/hr) → {upgrade_target or "current-gen"} (${upgrade_hourly:.3f}/hr) × {endpoint.instance_count or 1} instances = ${savings:.0f}/month savings',
                            'why_waste': f'Current-generation instances offer better performance per dollar. Upgrading {endpoint.instance_count or 1} instance(s) saves ~${savings:.0f}/month.',
                            'risk': 'Requires creating a new endpoint configuration and updating the endpoint. Brief downtime during the update unless using blue/green deployment.',
                        },
                        metadata={
                            'resource_name': endpoint.endpoint_name,
                            'current_instance_type': endpoint.instance_type,
                            'recommended_instance_type': upgrade_target,
                            'instance_count': endpoint.instance_count,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
            
            return waste_items
            
        except Exception as e:
            logger.debug(f"SageMaker detection error: {e}")
            return waste_items
    # CLO-506: (target vCPU / current vCPU, target memory / current memory)
    # for each single-step downgrade, from the WorkSpaces bundle specs:
    # PowerPro 8 vCPU/32 GiB, Power 4/16, Performance 2/7.5, Standard 2/4
    # (the smaller of its 4 and 8 GiB variants), GraphicsPro 16/122,
    # Graphics 8/15.
    WORKSPACES_DOWNGRADE_CAPACITY = {
        'POWERPRO': (4 / 8, 16 / 32),
        'POWER': (2 / 4, 7.5 / 16),
        'PERFORMANCE': (2 / 2, 4 / 7.5),
        'GRAPHICSPRO': (8 / 16, 15 / 122),
    }
    # Peak load must fit within this share of the smaller bundle.
    WORKSPACES_TARGET_FIT = 0.7
    async def _detect_workspaces_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect WorkSpaces waste — orchestrator for idle, autostop, oversized, pool, and license detectors."""
        waste_items = []
        
        try:
            # ── Shared data: all WorkSpaces ───────────────────────────
            workspaces = await data_provider.get_workspaces()

            # ── Bundle pricing maps ───────────────────────────────────
            price_map = {
                'VALUE': 21, 'STANDARD': 35, 'PERFORMANCE': 60,
                'POWER': 78, 'POWERPRO': 127, 'GRAPHICS': 50, 'GRAPHICSPRO': 85
            }
            autostop_hourly_rates = {
                'VALUE': 0.17, 'STANDARD': 0.40, 'PERFORMANCE': 0.57,
                'POWER': 0.82, 'POWERPRO': 1.53, 'GRAPHICS': 1.75, 'GRAPHICSPRO': 3.18
            }
            autostop_base = 7.25
            downgrade_map = {
                'POWERPRO': 'POWER',
                'POWER': 'PERFORMANCE',
                'PERFORMANCE': 'STANDARD',
                'GRAPHICSPRO': 'GRAPHICS',
            }

            # Enrich compute types from bundles if online
            bundle_compute_types: Dict[str, str] = {}
            if data_provider.provider_type == 'online' and hasattr(data_provider, '_get_client'):
                try:
                    ws_client = data_provider._get_client('workspaces')
                    bundles = ws_client.describe_workspace_bundles().get('Bundles', [])
                    for b in bundles:
                        bundle_compute_types[b.get('BundleId', '')] = b.get('ComputeType', {}).get('Name', 'STANDARD')
                except Exception as e:
                    if hasattr(data_provider, '_warn_swallowed'):
                        data_provider._warn_swallowed(
                            "WorkSpaces bundle compute types", "workspaces:DescribeWorkspaceBundles", e,
                        )
                    else:
                        logger.warning(
                            "idle_workspace: WorkSpaces bundle lookup failed (%s), continuing scan",
                            e.__class__.__name__,
                        )

            # ── Detectors A+B: Idle + AutoStop (need connection status) ──
            available_ws = [w for w in workspaces if w.state == 'AVAILABLE']
            if available_ws:
                ws_ids = [w.workspace_id for w in available_ws]
                conn_status = await data_provider.get_workspaces_connection_status(ws_ids)
                conn_map = {c.workspace_id: c for c in conn_status}

                for w in available_ws:
                    conn = conn_map.get(w.workspace_id)
                    if not conn or conn.connection_state != 'DISCONNECTED':
                        continue
                    if not conn.last_known_user_connection_timestamp:
                        continue

                    last_ts = conn.last_known_user_connection_timestamp
                    if last_ts.tzinfo is None:
                        last_ts = last_ts.replace(tzinfo=timezone.utc)
                    days_idle = (datetime.now(timezone.utc) - last_ts).days

                    compute_type = w.compute_type or bundle_compute_types.get(w.bundle_id, 'STANDARD')
                    monthly_cost = price_map.get(compute_type, 35)

                    # ── Detector A: Idle WorkSpace (>30 days disconnected) ──
                    if days_idle > 30:
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=w.workspace_id,
                            resource_type=ResourceType.WORKSPACE,
                            waste_type=WasteType.IDLE_WORKSPACE,
                            title="Idle WorkSpace",
                            description=f"WorkSpace '{w.workspace_id}' hasn't been used in {days_idle} days.",
                            monthly_savings=monthly_cost,
                            confidence=ConfidenceLevel.HIGH,
                            action="Terminate this WorkSpace.",
                            action_command=f"aws workspaces terminate-workspaces --terminate-workspace-requests WorkspaceId={w.workspace_id}",
                            explanation={
                                'detection': f'WorkSpace has been disconnected for {days_idle} days with no user connections',
                                'threshold': '> 30 days since last user connection',
                                'pricing': f'Monthly AlwaysOn fee: ${monthly_cost:.0f}/month',
                                'why_waste': f'This WorkSpace has had no user login for {days_idle} days. The monthly subscription continues regardless of usage.',
                                'risk': 'Terminating a WorkSpace permanently deletes user data on the root and user volumes. Ensure the user no longer needs access or back up data first.',
                            },
                            metadata={
                                'workspace_id': w.workspace_id,
                                'days_idle': days_idle,
                                'detection_mode': data_provider.provider_type,
                            }
                        ))

                    # ── Detector B: AutoStop Opportunity (AlwaysOn low-usage) ──
                    elif days_idle > 7 and w.running_mode == 'ALWAYS_ON':
                        hourly_rate = autostop_hourly_rates.get(compute_type, 0.40)
                        estimated_usage_hours = 20
                        estimated_autostop_cost = autostop_base + (hourly_rate * estimated_usage_hours)
                        savings = monthly_cost - estimated_autostop_cost
                        break_even_hours = (monthly_cost - autostop_base) / hourly_rate if hourly_rate > 0 else 0

                        if savings >= max(settings.min_waste_threshold_usd, 10):
                            waste_items.append(WasteItem(
                                id=str(uuid.uuid4()),
                                resource_id=w.workspace_id,
                                resource_type=ResourceType.WORKSPACE,
                                waste_type=WasteType.WORKSPACES_AUTOSTOP_OPPORTUNITY,
                                title="WorkSpaces AutoStop Opportunity",
                                description=(
                                    f"WorkSpace '{w.workspace_id}' ({compute_type}) is AlwaysOn but "
                                    f"only used occasionally (last connection {days_idle} days ago). "
                                    f"Switching to AutoStop billing could save ~${savings:.0f}/month."
                                ),
                                monthly_savings=savings,
                                confidence=ConfidenceLevel.HIGH,
                                action="Switch from AlwaysOn to AutoStop billing mode.",
                                action_command=(
                                    f"aws workspaces modify-workspace-properties --workspace-id {w.workspace_id} "
                                    f"--workspace-properties RunningMode=AUTO_STOP,RunningModeAutoStopTimeoutInMinutes=60"
                                ),
                                explanation={
                                    'detection': (
                                        f'WorkSpace is in AlwaysOn mode but last user connection was {days_idle} days ago. '
                                        f'Compute type: {compute_type}.'
                                    ),
                                    'threshold': 'AlwaysOn WorkSpaces with > 7 days since last connection and savings >= $10/month',
                                    'pricing': (
                                        f'AlwaysOn: ${monthly_cost:.0f}/month. '
                                        f'AutoStop (est. {estimated_usage_hours}hrs/month): ${estimated_autostop_cost:.0f}/month. '
                                        f'Break-even: {break_even_hours:.0f} hours/month. '
                                        f'Savings: ~${savings:.0f}/month.'
                                    ),
                                    'why_waste': (
                                        'AlwaysOn billing charges a flat monthly rate regardless of usage hours. '
                                        'For infrequent users, AutoStop billing (hourly rate + small base) is significantly cheaper.'
                                    ),
                                    'risk': (
                                        'AutoStop WorkSpaces shut down after idle timeout (1-3 hours). '
                                        'Boot time is ~1-2 minutes. User data is preserved. '
                                        'This change is fully reversible.'
                                    ),
                                },
                                metadata={
                                    'workspace_id': w.workspace_id,
                                    'bundle_id': w.bundle_id,
                                    'running_mode': w.running_mode,
                                    'usage_hours_30d': estimated_usage_hours,
                                    'estimated_always_on_cost': monthly_cost,
                                    'estimated_autostop_cost': round(estimated_autostop_cost, 2),
                                    'break_even_hours': round(break_even_hours, 0),
                                    'compute_type': compute_type,
                                    'days_since_connection': days_idle,
                                    'detection_mode': data_provider.provider_type,
                                }
                            ))

            # ── Detector C: Oversized WorkSpace (bundle rightsizing) ──
            # Needs CloudWatch UserSessionsCount metrics
            candidates = [
                w for w in available_ws
                if downgrade_map.get(w.compute_type or bundle_compute_types.get(w.bundle_id, 'STANDARD'))
            ]
            if candidates:
                candidate_ids = [w.workspace_id for w in candidates]
                ws_metrics = await data_provider.get_workspaces_metrics(candidate_ids)

                for w in candidates:
                    compute_type = w.compute_type or bundle_compute_types.get(w.bundle_id, 'STANDARD')
                    target_type = downgrade_map.get(compute_type)
                    if not target_type:
                        continue

                    current_price = price_map.get(compute_type, 35)
                    target_price = price_map.get(target_type, 35)
                    potential_savings = current_price - target_price

                    if potential_savings < max(settings.min_waste_threshold_usd, 15):
                        continue

                    # CLO-506: the WorkSpace's own peak load must fit the
                    # smaller bundle. It used to fire for every
                    # downgradeable WorkSpace with 7 days of session data,
                    # without looking at CPU or memory at all. p95 of the
                    # hourly CPU peaks and the highest hourly memory peak
                    # must each stay under 70% of what the target bundle
                    # has (scaled by the target/current vCPU and memory
                    # ratio), over 75% of the window's days. Unmeasured
                    # load is MISSING, noted.
                    m = ws_metrics.get(w.workspace_id)
                    if not m or m.cpu_peak_p95 is None or m.memory_peak_max is None:
                        self._note_missing(
                            data_provider, 'workspaces', w.workspace_id,
                            'no CPU/memory coverage' if m else 'not read',
                            verdict='oversized', evidence='CPU and memory metrics',
                        )
                        continue
                    cpu_ratio, mem_ratio = self.WORKSPACES_DOWNGRADE_CAPACITY[compute_type]
                    cpu_limit = self.WORKSPACES_TARGET_FIT * cpu_ratio * 100
                    mem_limit = self.WORKSPACES_TARGET_FIT * mem_ratio * 100
                    if m.cpu_peak_p95 > cpu_limit or m.memory_peak_max > mem_limit:
                        continue

                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=w.workspace_id,
                        resource_type=ResourceType.WORKSPACE,
                        waste_type=WasteType.OVERSIZED_WORKSPACE,
                        title="Oversized WorkSpace",
                        description=(
                            f"WorkSpace '{w.workspace_id}' is running {compute_type} bundle but usage patterns "
                            f"suggest {target_type} would be sufficient. "
                            f"Downgrading could save ~${potential_savings:.0f}/month."
                        ),
                        monthly_savings=potential_savings,
                        confidence=ConfidenceLevel.MEDIUM,
                        action=f"Consider downgrading from {compute_type} to {target_type} bundle.",
                        action_command=(
                            f"aws workspaces modify-workspace-properties --workspace-id {w.workspace_id} "
                            f"--workspace-properties ComputeTypeName={target_type}"
                        ),
                        explanation={
                            'detection': (
                                f'WorkSpace has a {compute_type} bundle; over {m.utilization_days} days its CPU peaks '
                                f'(p95 of hourly maxima) were {m.cpu_peak_p95:.0f}% and its memory peaked at '
                                f'{m.memory_peak_max:.0f}%. Candidate downgrade to {target_type} within the same OS family.'
                            ),
                            'threshold': (
                                f'Peak CPU under {cpu_limit:.0f}% and peak memory under {mem_limit:.0f}% of this bundle '
                                f'(70% of {target_type}\'s capacity), measured on 75% of the last '
                                f'{m.period_days} days, with >= $15/month savings potential'
                            ),
                            'pricing': (
                                f'Current ({compute_type}): ${current_price:.0f}/month. '
                                f'Recommended ({target_type}): ${target_price:.0f}/month. '
                                f'Savings: ~${potential_savings:.0f}/month.'
                            ),
                            'why_waste': (
                                'Higher-tier bundles include more vCPUs and memory than the workload requires. '
                                'Rightsizing to a smaller bundle reduces cost without impacting typical usage patterns.'
                            ),
                            'risk': (
                                'Sizing errors can degrade developer or analyst productivity. '
                                'Validate application requirements with the desktop owner before changing. '
                                'This recommendation uses conservative single-step downgrade mapping.'
                            ),
                        },
                        metadata={
                            'workspace_id': w.workspace_id,
                            'current_bundle': compute_type,
                            'recommended_bundle': target_type,
                            'observation_days': m.observation_days,
                            'utilization_days': m.utilization_days,
                            'cpu_peak_p95': m.cpu_peak_p95,
                            'memory_peak_max': m.memory_peak_max,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))

            # ── Detector D: Pool Overprovisioned Capacity ──
            try:
                pools = await data_provider.get_workspaces_pools()
                for pool in pools:
                    desired = pool.desired_user_sessions
                    running = pool.running_user_sessions

                    if desired <= 0:
                        continue

                    excess = desired - running
                    utilization_pct = (running / desired * 100) if desired > 0 else 0

                    if utilization_pct > 75 or excess < 2:
                        continue

                    excess_monthly_cost = excess * 35
                    if excess_monthly_cost < max(settings.min_waste_threshold_usd, 25):
                        continue

                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=pool.pool_id,
                        resource_type=ResourceType.WORKSPACE,
                        waste_type=WasteType.WORKSPACES_POOL_OVERPROVISIONED_CAPACITY,
                        title="WorkSpaces Pool Overprovisioned Capacity",
                        description=(
                            f"WorkSpaces Pool '{pool.pool_name}' has {desired} configured sessions "
                            f"but only {running} in use ({utilization_pct:.0f}% utilization). "
                            f"Reducing excess capacity could save ~${excess_monthly_cost:.0f}/month."
                        ),
                        monthly_savings=excess_monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action=f"Reduce pool capacity from {desired} to {running + max(1, running // 4)} sessions.",
                        action_command=f"# Review and adjust pool '{pool.pool_name}' capacity in the AWS Console",
                        explanation={
                            'detection': (
                                f'Pool has {desired} desired sessions but only {running} active '
                                f'({utilization_pct:.0f}% utilization). Excess: {excess} idle slots.'
                            ),
                            'threshold': 'Pool utilization < 75% with excess capacity > 25% above p95 sustained usage',
                            'pricing': f'Estimated excess cost: ~${excess_monthly_cost:.0f}/month ({excess} unused slots)',
                            'why_waste': (
                                'WorkSpaces Pools charge for provisioned capacity regardless of session usage. '
                                'Excess buffer above peak demand wastes recurring hourly/stopped-instance charges.'
                            ),
                            'risk': (
                                'Reducing capacity too aggressively may cause session launch delays during peak hours. '
                                'Keep a safety margin above p95 sustained concurrent sessions. '
                                'Account for seasonality and known peak events.'
                            ),
                        },
                        metadata={
                            'pool_id': pool.pool_id,
                            'pool_name': pool.pool_name,
                            'configured_capacity': desired,
                            'active_sessions': running,
                            'utilization_pct': round(utilization_pct, 1),
                            'excess_slots': excess,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
            except Exception as e:
                logger.debug(f"WorkSpaces pool detection error: {e}")

            # ── Detector E: Windows License Optimization ──
            windows_included_count = 0
            for w in workspaces:
                if w.state != 'AVAILABLE':
                    continue
                if w.operating_system in ('WINDOWS', '') and 'byol' not in w.bundle_id.lower():
                    windows_included_count += 1

            if windows_included_count >= 5:
                license_savings_per_desktop = 4
                total_license_savings = windows_included_count * license_savings_per_desktop

                if total_license_savings >= settings.min_waste_threshold_usd:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=f"workspaces-windows-license-{windows_included_count}",
                        resource_type=ResourceType.WORKSPACE,
                        waste_type=WasteType.WORKSPACES_WINDOWS_LICENSE_OPTIMIZATION,
                        title="WorkSpaces Windows License Optimization",
                        description=(
                            f"{windows_included_count} WorkSpaces are running Windows with included licenses. "
                            f"Organizations with existing Microsoft licensing agreements may save "
                            f"~${total_license_savings:.0f}/month by switching to BYOL or Linux alternatives."
                        ),
                        monthly_savings=total_license_savings,
                        confidence=ConfidenceLevel.MEDIUM,
                        action="Review licensing posture and evaluate BYOL eligibility or Linux alternatives.",
                        action_command="# Review BYOL eligibility at https://docs.aws.amazon.com/workspaces/latest/adminguide/byol-windows-images.html",
                        explanation={
                            'detection': (
                                f'Found {windows_included_count} WorkSpaces using Windows license-included bundles. '
                                f'Organizations with Microsoft Volume Licensing or Software Assurance may qualify for BYOL savings.'
                            ),
                            'threshold': '>= 5 Windows license-included WorkSpaces',
                            'pricing': (
                                f'Estimated license delta: ~${license_savings_per_desktop}/month per desktop. '
                                f'Total potential savings: ~${total_license_savings:.0f}/month for {windows_included_count} desktops.'
                            ),
                            'why_waste': (
                                'AWS-included Windows licenses carry a per-desktop premium. '
                                'Organizations with existing Microsoft licensing agreements can bring their own licenses (BYOL) '
                                'or migrate eligible users to Amazon Linux WorkSpaces to eliminate this premium.'
                            ),
                            'risk': (
                                'DISCLAIMER: This is an advisory finding. BYOL eligibility depends on your Microsoft licensing terms. '
                                'Verify licensing compliance with your Microsoft representative before making changes. '
                                'Pilot migration on a non-critical user group before broad rollout.'
                            ),
                        },
                        metadata={
                            'windows_license_included_count': windows_included_count,
                            'estimated_savings_per_desktop': license_savings_per_desktop,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))

            return waste_items

        except Exception as e:
            logger.debug(f"WorkSpaces detection error: {e}")
            return waste_items
    LIGHTSAIL_DB_PRICING = {
        'micro_2_0': 15.00,   # 1 vCPU, 1 GB RAM, 40 GB SSD
        'small_2_0': 30.00,   # 1 vCPU, 2 GB RAM, 80 GB SSD
        'medium_2_0': 60.00,  # 2 vCPU, 4 GB RAM, 120 GB SSD
        'large_2_0': 115.00,  # 2 vCPU, 8 GB RAM, 240 GB SSD
    }
    async def _detect_lightsail_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect all Lightsail waste — orchestrator for 6 sub-detectors."""
        waste_items = []

        # Run all sub-detectors concurrently
        import asyncio
        results = await asyncio.gather(
            self._detect_lightsail_idle_instances(data_provider, settings),
            self._detect_lightsail_unattached_static_ips(data_provider, settings),
            self._detect_lightsail_unattached_disks(data_provider, settings),
            self._detect_lightsail_old_snapshots(data_provider, settings),
            self._detect_lightsail_idle_load_balancers(data_provider, settings),
            self._detect_lightsail_idle_databases(data_provider, settings),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, list):
                waste_items.extend(result)
            elif isinstance(result, Exception):
                logger.debug(f"Lightsail sub-detector error: {result}")

        return waste_items
    async def _detect_lightsail_idle_instances(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect stopped or idle Lightsail instances using DataProvider."""
        waste_items = []
        try:
            instances = await data_provider.get_lightsail_instances()
            for inst in instances:
                name = inst.name
                bundle = inst.bundle_id
                state = inst.state

                # CLO-506: the bundle id is parsed token by token. The
                # substring match this replaces priced xlarge/2xlarge as
                # "large" (dict order) and anything unknown at $3.50. An
                # unknown bundle is MISSING now, never a guessed price.
                monthly_cost = lightsail_bundle_monthly_price(bundle)
                if monthly_cost is None:
                    if state in ('stopped', 'running'):
                        self._note_missing(
                            data_provider, 'lightsail', name, f'unknown bundle {bundle}',
                            verdict='idle', evidence='bundle prices',
                        )
                    continue

                if state == 'stopped':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=name,
                        resource_type=ResourceType.LIGHTSAIL_INSTANCE,
                        waste_type=WasteType.IDLE_LIGHTSAIL,
                        title="Stopped Lightsail Instance",
                        description=f"Lightsail instance '{name}' ({bundle}) is stopped but still incurs charges.",
                        monthly_savings=monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete this instance.",
                        action_command=f"aws lightsail delete-instance --instance-name {name}",
                        explanation={
                            'detection': 'Lightsail instance is in stopped state',
                            'threshold': 'Instance state == stopped',
                            'pricing': f'Bundle {bundle}: ${monthly_cost:.2f}/month (charged even while stopped)',
                            'why_waste': 'Unlike EC2, Lightsail instances are billed at a flat monthly rate regardless of whether they are running or stopped.',
                            'risk': 'Deleting a Lightsail instance permanently removes it and its data. Create a snapshot first if you need to preserve the data.',
                        },
                        metadata={
                            'instance_name': name,
                            'bundle_id': bundle,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                elif state == 'running':
                    # Check CPU metrics for idle running instances
                    try:
                        metrics = await data_provider.get_lightsail_metrics(name, 'instance')
                        # CLO-506: an idle verdict needs hourly CPU for 75%
                        # of the window. A sparse or missing series is
                        # MISSING (noted), not idle.
                        covered = lightsail_cpu_covers_window(metrics)
                        if metrics.avg_cpu is not None and not covered:
                            self._note_missing(
                                data_provider, 'lightsail', name, 'under 75% coverage',
                            )
                        elif metrics.avg_cpu is None:
                            self._note_missing(data_provider, 'lightsail', name, 'no datapoints')
                        if covered and metrics.avg_cpu < 5.0:
                            waste_items.append(WasteItem(
                                id=str(uuid.uuid4()),
                                resource_id=name,
                                resource_type=ResourceType.LIGHTSAIL_INSTANCE,
                                waste_type=WasteType.IDLE_LIGHTSAIL,
                                title="Idle Lightsail Instance",
                                description=f"Lightsail instance '{name}' ({bundle}) has avg CPU {metrics.avg_cpu:.1f}% over 14 days.",
                                monthly_savings=monthly_cost,
                                confidence=ConfidenceLevel.HIGH,
                                action="Stop or delete this instance.",
                                action_command=f"aws lightsail stop-instance --instance-name {name}",
                                explanation={
                                    'detection': f'CPU avg {metrics.avg_cpu:.1f}% over 14 days',
                                    'threshold': 'CPU avg < 5% for 14 days',
                                    'pricing': f'Bundle {bundle}: ${monthly_cost:.2f}/month',
                                    'why_waste': 'Instance shows near-zero CPU utilization, suggesting it is not serving any workload.',
                                    'risk': 'Stopping preserves the instance; deleting is permanent. Create a snapshot first if needed.',
                                },
                                metadata={
                                    'instance_name': name,
                                    'bundle_id': bundle,
                                    'avg_cpu': metrics.avg_cpu,
                                    'detection_mode': data_provider.provider_type,
                                }
                            ))
                    except Exception as e:
                        if hasattr(data_provider, '_warn_swallowed'):
                            data_provider._warn_swallowed(
                                "Lightsail instance metrics", "lightsail:GetInstanceMetricData", e,
                            )
                        else:
                            logger.warning(
                                "idle_lightsail: metrics fetch failed for an instance (%s), "
                                "skipping idle-running detection for it",
                                e.__class__.__name__,
                            )

            return waste_items
        except Exception as e:
            logger.debug(f"Lightsail instance detection error: {e}")
            return waste_items
    async def _detect_lightsail_unattached_static_ips(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect unattached Lightsail static IPs."""
        waste_items = []
        try:
            static_ips = await data_provider.get_lightsail_static_ips()
            for ip in static_ips:
                if not ip.is_attached:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=ip.name,
                        resource_type=ResourceType.LIGHTSAIL_STATIC_IP,
                        waste_type=WasteType.LIGHTSAIL_UNATTACHED_STATIC_IP,
                        title="Unattached Lightsail Static IP",
                        description=f"Static IP '{ip.name}' is not attached to any instance. Unattached IPs cost $0.005/hr (~$3.65/month).",
                        monthly_savings=3.65,
                        confidence=ConfidenceLevel.HIGH,
                        action="Release this static IP.",
                        action_command=f"aws lightsail release-static-ip --static-ip-name {ip.name}",
                        explanation={
                            'detection': 'Static IP is not attached to any Lightsail instance',
                            'threshold': 'isAttached == false',
                            'pricing': '$0.005/hr (~$3.65/month) when unattached, free when attached',
                            'why_waste': 'AWS charges for Lightsail static IPs that are not attached to a running instance. This is similar to unattached Elastic IPs in EC2.',
                            'risk': 'Releasing a static IP deallocates it permanently. The same IP address cannot be recovered.',
                        },
                        metadata={
                            'ip_address': ip.ip_address,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
            return waste_items
        except Exception as e:
            logger.debug(f"Lightsail static IP detection error: {e}")
            return waste_items
    async def _detect_lightsail_unattached_disks(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect unattached Lightsail disks."""
        waste_items = []
        try:
            disks = await data_provider.get_lightsail_disks()
            for disk in disks:
                if not disk.is_attached:
                    monthly = disk.size_in_gb * 0.10
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=disk.name,
                        resource_type=ResourceType.LIGHTSAIL_DISK,
                        waste_type=WasteType.LIGHTSAIL_UNATTACHED_DISK,
                        title="Unattached Lightsail Disk",
                        description=f"Disk '{disk.name}' ({disk.size_in_gb}GB) is not attached to any instance. Costs ${monthly:.2f}/month.",
                        monthly_savings=monthly,
                        confidence=ConfidenceLevel.HIGH,
                        action="Create a snapshot (if needed) and delete this disk.",
                        action_command=f"aws lightsail delete-disk --disk-name {disk.name}",
                        explanation={
                            'detection': 'Lightsail additional disk is not attached to any instance',
                            'threshold': 'isAttached == false',
                            'pricing': f'{disk.size_in_gb} GB × $0.10/GB/month = ${monthly:.2f}/month',
                            'why_waste': 'Lightsail block storage disks are charged at $0.10/GB/month regardless of attachment status. Detached disks often remain after instance deletion.',
                            'risk': 'Deleting a disk permanently removes all data. Create a disk snapshot first if you need to preserve the data.',
                        },
                        metadata={
                            'size_in_gb': disk.size_in_gb,
                            'state': disk.state,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
            return waste_items
        except Exception as e:
            logger.debug(f"Lightsail disk detection error: {e}")
            return waste_items
    async def _detect_lightsail_old_snapshots(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect old Lightsail instance snapshots (>90 days)."""
        waste_items = []
        try:
            snapshots = await data_provider.get_lightsail_snapshots()
            now = datetime.now(timezone.utc)
            for snap in snapshots:
                # Skip auto-snapshots (managed lifecycle)
                if snap.is_from_auto_snapshot:
                    continue

                created = snap.created_at
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (now - created).days

                if age_days > 90:
                    monthly = snap.size_in_gb * 0.05
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=snap.name,
                        resource_type=ResourceType.LIGHTSAIL_SNAPSHOT,
                        waste_type=WasteType.LIGHTSAIL_OLD_SNAPSHOT,
                        title="Old Lightsail Instance Snapshot",
                        description=f"Snapshot '{snap.name}' is {age_days} days old ({snap.size_in_gb}GB). Costs ${monthly:.2f}/month in storage.",
                        monthly_savings=monthly,
                        confidence=ConfidenceLevel.MEDIUM,
                        action="Delete this snapshot if no longer needed for recovery.",
                        action_command=f"aws lightsail delete-instance-snapshot --instance-snapshot-name {snap.name}",
                        explanation={
                            'detection': f'Lightsail instance snapshot is {age_days} days old',
                            'threshold': 'Snapshot age > 90 days',
                            'pricing': f'{snap.size_in_gb} GB × $0.05/GB/month = ${monthly:.2f}/month',
                            'why_waste': 'Old instance snapshots accumulate storage charges at $0.05/GB/month. Snapshots older than 90 days are rarely used for disaster recovery.',
                            'risk': 'Deleting a snapshot is irreversible. Verify you do not need this snapshot for recovery before deletion.',
                        },
                        metadata={
                            'age_days': age_days,
                            'size_in_gb': snap.size_in_gb,
                            'from_instance': snap.from_instance_name,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
            return waste_items
        except Exception as e:
            logger.debug(f"Lightsail snapshot detection error: {e}")
            return waste_items
    async def _detect_lightsail_idle_load_balancers(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect idle Lightsail load balancers (no healthy targets)."""
        waste_items = []
        try:
            load_balancers = await data_provider.get_lightsail_load_balancers()
            for lb in load_balancers:
                health_summary = lb.instance_health_summary
                # Flag if no instances or all instances are unhealthy
                healthy_count = sum(
                    1 for h in health_summary
                    if h.get('instanceHealth') == 'healthy'
                )
                if healthy_count == 0:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=lb.name,
                        resource_type=ResourceType.LIGHTSAIL_LOAD_BALANCER,
                        waste_type=WasteType.LIGHTSAIL_IDLE_LOAD_BALANCER,
                        title="Idle Lightsail Load Balancer",
                        description=f"Load balancer '{lb.name}' has no healthy registered instances. Costs $18.00/month.",
                        monthly_savings=18.00,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete this load balancer if no longer needed.",
                        action_command=f"aws lightsail delete-load-balancer --load-balancer-name {lb.name}",
                        explanation={
                            'detection': 'Lightsail load balancer has no healthy registered instances',
                            'threshold': 'Zero healthy instances in health summary',
                            'pricing': '$18.00/month flat rate regardless of traffic',
                            'why_waste': 'Lightsail load balancers are charged a flat $18/month fee. A load balancer with zero healthy targets is not routing any traffic but still incurring the full charge.',
                            'risk': 'Deleting a load balancer removes its DNS name and TLS certificate bindings. Ensure no DNS records point to this load balancer before deletion.',
                        },
                        metadata={
                            'dns_name': lb.dns_name,
                            'instance_port': lb.instance_port,
                            'total_instances': len(health_summary),
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
            return waste_items
        except Exception as e:
            logger.debug(f"Lightsail load balancer detection error: {e}")
            return waste_items
    async def _detect_lightsail_idle_databases(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect idle or stopped Lightsail managed databases."""
        waste_items = []
        try:
            databases = await data_provider.get_lightsail_databases()
            for db in databases:
                bundle = db.bundle_id
                bundle_lower = bundle.lower()
                monthly_cost = 15.00  # Default to micro
                for key, price in self.LIGHTSAIL_DB_PRICING.items():
                    if key in bundle_lower:
                        monthly_cost = price
                        break

                # HA doubles the price
                if db.secondary_availability_zone:
                    monthly_cost *= 2

                if db.state == 'stopped':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=db.name,
                        resource_type=ResourceType.LIGHTSAIL_DATABASE,
                        waste_type=WasteType.LIGHTSAIL_IDLE_DATABASE,
                        title="Stopped Lightsail Database",
                        description=f"Database '{db.name}' ({bundle}) is stopped but still billed at ${monthly_cost:.2f}/month.",
                        monthly_savings=monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete this database if no longer needed. Create a snapshot first.",
                        action_command=f"aws lightsail delete-relational-database --relational-database-name {db.name}",
                        explanation={
                            'detection': 'Lightsail managed database is in stopped state',
                            'threshold': 'Database state == stopped',
                            'pricing': f'Bundle {bundle}: ${monthly_cost:.2f}/month (charged even while stopped)',
                            'why_waste': 'Like Lightsail instances, managed databases are billed at a flat monthly rate regardless of state. Stopped databases still incur the full charge.',
                            'risk': 'Deleting a database permanently removes all data. Create a final snapshot first.',
                        },
                        metadata={
                            'engine': db.engine,
                            'bundle_id': bundle,
                            'is_ha': db.secondary_availability_zone is not None,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                elif db.state == 'available':
                    # Check metrics for idle running database
                    try:
                        metrics = await data_provider.get_lightsail_metrics(db.name, 'database')
                        if (metrics.avg_cpu is not None and metrics.avg_cpu < 5.0
                                and metrics.avg_connections is not None and metrics.avg_connections < 1.0):
                            waste_items.append(WasteItem(
                                id=str(uuid.uuid4()),
                                resource_id=db.name,
                                resource_type=ResourceType.LIGHTSAIL_DATABASE,
                                waste_type=WasteType.LIGHTSAIL_IDLE_DATABASE,
                                title="Idle Lightsail Database",
                                description=f"Database '{db.name}' ({bundle}) has <5% CPU and <1 connection for 14 days.",
                                monthly_savings=monthly_cost,
                                confidence=ConfidenceLevel.HIGH,
                                action="Stop or delete this database.",
                                action_command=f"aws lightsail delete-relational-database --relational-database-name {db.name}",
                                explanation={
                                    'detection': f'CPU avg {metrics.avg_cpu:.1f}% and {metrics.avg_connections:.1f} avg connections over 14 days',
                                    'threshold': 'CPU avg < 5% AND connections avg < 1 for 14 days',
                                    'pricing': f'Bundle {bundle}: ${monthly_cost:.2f}/month',
                                    'why_waste': 'Database shows near-zero utilization, suggesting no application is actively using it.',
                                    'risk': 'Stopping a database preserves data but pauses it for up to 7 days (auto-restarts after). Deleting is permanent.',
                                },
                                metadata={
                                    'engine': db.engine,
                                    'bundle_id': bundle,
                                    'avg_cpu': metrics.avg_cpu,
                                    'avg_connections': metrics.avg_connections,
                                    'is_ha': db.secondary_availability_zone is not None,
                                    'detection_mode': data_provider.provider_type,
                                }
                            ))
                    except Exception as e:
                        if hasattr(data_provider, '_warn_swallowed'):
                            data_provider._warn_swallowed(
                                "Lightsail database metrics", "lightsail:GetRelationalDatabaseMetricData", e,
                            )
                        else:
                            logger.warning(
                                "idle_lightsail: metrics fetch failed for a database (%s), "
                                "skipping idle-running detection for it",
                                e.__class__.__name__,
                            )

            return waste_items
        except Exception as e:
            logger.debug(f"Lightsail database detection error: {e}")
            return waste_items
