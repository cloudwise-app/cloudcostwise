"""Open-core part of ``detectors/storage.py`` (FSL-1.1-ALv2).

The service entrypoints in ``FREE_TIER_DETECTORS`` and every method they call.
``StorageDetectorsMixin`` in ``detectors/storage.py`` subclasses this mixin and adds the
closed detectors. Moved verbatim from ``detectors/storage.py`` (CLO-562).
"""

import logging
import math
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, TYPE_CHECKING
from cloudwise_scan_core.models import WasteItem, WasteDetectionSettings, WasteType, ResourceType, ConfidenceLevel, get_ebs_monthly_cost, _region_price_multiplier, S3_STANDARD_PER_GB, S3_IT_MONITORING_PER_1K
if TYPE_CHECKING:
    from cloudwise_scan_core.data_providers.base import WasteDataProvider

logger = logging.getLogger(__name__)

# CLO-516: over_provisioned_iops. Provisioned-IOPS list prices (us-east-1,
# per IOPS-month). gp3 includes 3,000 IOPS free; io1 bills every IOPS; io2
# bills in tiers (first 32,000, 32,001-64,000, above 64,000).
OVER_PROVISIONED_IOPS_DAYS = 14


GP3_FREE_IOPS = 3000


GP3_IOPS_PRICE = 0.005


IO1_IOPS_PRICE = 0.065


IO2_IOPS_TIERS = ((32000, 0.065), (64000, 0.0455), (None, 0.032))


# The lowest IOPS a volume may be set to: gp3's included 3,000, io1/io2's 100.
MIN_PROVISIONED_IOPS = {'gp3': GP3_FREE_IOPS, 'io1': 100, 'io2': 100}


# Flag only when the measured one-minute peak is under half the provisioned
# IOPS, and recommend the peak plus 30% headroom.
IOPS_PEAK_SHARE_GATE = 0.50


IOPS_HEADROOM = 1.30


# CLO-514: gp2_migration. gp2 delivers 3 IOPS per GiB (100 minimum, 16,000
# maximum) and, at 334 GiB and above, 250 MiB/s without burst credits. gp3
# includes 3,000 IOPS and 125 MiB/s; anything above is billed. A migration
# that keeps the volume's gp2 baseline pays for that difference.
GP3_FREE_THROUGHPUT_MIBPS = 125


GP3_THROUGHPUT_PRICE = 0.04          # per MiB/s-month above 125


GP2_MAX_IOPS = 16000


GP2_FULL_THROUGHPUT_MIN_GIB = 334


GP2_FULL_THROUGHPUT_MIBPS = 250


def gp2_baseline(size_gb: int) -> tuple:
    """(IOPS, MiB/s) a gp2 volume of ``size_gb`` delivers without burst
    credits, floored at gp3's included 3,000 IOPS / 125 MiB/s, i.e. the gp3
    settings that keep the volume's performance."""
    size = max(int(size_gb or 0), 0)
    iops = max(GP3_FREE_IOPS, min(GP2_MAX_IOPS, 3 * size))
    throughput = (
        GP2_FULL_THROUGHPUT_MIBPS if size >= GP2_FULL_THROUGHPUT_MIN_GIB
        else GP3_FREE_THROUGHPUT_MIBPS
    )
    return iops, throughput


# CLO-513: an incomplete multipart upload younger than this may still be in
# progress. AWS's own lifecycle guidance aborts after 7 days.
INCOMPLETE_MULTIPART_MIN_AGE_DAYS = 7


def provisioned_iops_monthly_cost(volume_type: str, iops: int) -> float:
    """Monthly list price of ``iops`` provisioned IOPS on ``volume_type``."""
    iops = max(int(iops or 0), 0)
    if volume_type == 'gp3':
        return max(iops - GP3_FREE_IOPS, 0) * GP3_IOPS_PRICE
    if volume_type == 'io1':
        return iops * IO1_IOPS_PRICE
    if volume_type == 'io2':
        cost, floor = 0.0, 0
        for ceiling, price in IO2_IOPS_TIERS:
            top = iops if ceiling is None else min(iops, ceiling)
            if top > floor:
                cost += (top - floor) * price
            if ceiling is None or iops <= ceiling:
                break
            floor = ceiling
        return cost
    return 0.0


def min_provisioned_iops(volume) -> int:
    """The lowest IOPS ``volume`` can be set to. io1/io2: 100. gp3: the
    included 3,000, or more when its provisioned throughput needs it (AWS
    requires at least 1 IOPS per 0.25 MiB/s, so 1,000 MiB/s needs 4,000)."""
    floor = MIN_PROVISIONED_IOPS[volume.volume_type]
    if volume.volume_type == 'gp3':
        throughput = getattr(volume, 'throughput', None) or 0
        try:
            floor = max(floor, int(math.ceil(float(throughput) * 4)))
        except (TypeError, ValueError):
            pass
    return floor


def _iops_read_deadline(started: float) -> float:
    from cloudwise_scan_core.detectors.open.management import _log_activity_deadline
    # Same timeout source as the log-group lookups; same 60% share.
    return _log_activity_deadline(started)


# Bound at import, so a test that patches this module's ``datetime`` to freeze
# ``now()`` does not break the isinstance checks below.
_DATETIME = datetime


def _attached_since(volume) -> Optional[datetime]:
    """When the volume's current attachment began (latest AttachTime), else
    its creation time, else None. EBS publishes metrics only while a volume
    is attached, so the IOPS window must lie inside the attachment."""
    latest = None
    for attachment in getattr(volume, 'attachments', None) or []:
        value = attachment.get('AttachTime') if isinstance(attachment, dict) else None
        if isinstance(value, str):
            try:
                value = _DATETIME.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                value = None
        if isinstance(value, _DATETIME):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            if latest is None or value > latest:
                latest = value
    if latest is not None:
        return latest
    created = getattr(volume, 'create_time', None)
    if isinstance(created, _DATETIME) and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return created if isinstance(created, _DATETIME) else None



class OpenStorageDetectorsMixin:
    """Open detectors from ``StorageDetectorsMixin``."""

    async def _detect_ebs_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect EBS-related waste using DataProvider.
        
        Detectors:
        1. UNATTACHED_EBS - Volumes not attached to any instance
        2. GP2_MIGRATION - gp2 volumes that could be migrated to gp3
        3. OLD_EBS_SNAPSHOT - Snapshots older than threshold
        4. ORPHANED_EBS_SNAPSHOT - Snapshots whose source volume no longer exists
        5. AMI_ORPHANED_SNAPSHOT - Snapshots backing deregistered AMIs
        
        Dedup priority: AMI orphan > volume orphan > old snapshot
        """
        waste_items = []
        
        # Regex for AMI-backing snapshots created by CreateImage
        AMI_SNAPSHOT_PATTERN = re.compile(
            r'Created by CreateImage\(i-[a-f0-9]+\) for (ami-[a-f0-9]+)'
        )
        
        started = time.monotonic()
        try:
            # Get volumes from data provider (works for both online/offline!)
            volumes = await data_provider.get_ebs_volumes()
            existing_volume_ids = {v.volume_id for v in volumes}
            # CLO-527 item 5: "its volume no longer exists" needs the WHOLE
            # volume list. A capped or failed DescribeVolumes read (the online
            # provider notes it) would read every unseen volume as deleted,
            # so Check 4 is withheld then. The offline export is whole.
            volume_list_complete = getattr(data_provider, 'ebs_volumes_complete', True) is not False
            
            for volume in volumes:
                volume_name = volume.tags.get('Name', volume.volume_id)
                # CLO-359: region-scaled — this table is us-east-1 flat rates
                # otherwise, so an unattached volume outside us-east-1 always
                # understated its saving.
                monthly_cost = get_ebs_monthly_cost(
                    volume.volume_type, volume.size_gb, region=data_provider.region
                )
                
                # Check 1: Unattached volumes
                if volume.state == 'available':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=volume.volume_id,
                        resource_type=ResourceType.EBS_VOLUME,
                        waste_type=WasteType.UNATTACHED_EBS,
                        title=f"Unattached EBS Volume ({volume.size_gb}GB {volume.volume_type})",
                        description=f"Volume '{volume_name}' is not attached to any instance.",
                        monthly_savings=monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete this volume if no longer needed.",
                        action_command=f"aws ec2 delete-volume --volume-id {volume.volume_id}",
                        explanation={
                            'detection': f'EBS volume state is "available" (not attached to any EC2 instance)',
                            'threshold': 'Volume not attached to any instance',
                            'pricing': (
                                f'{volume.volume_type}: {volume.size_gb} GB × '
                                f'${get_ebs_monthly_cost(volume.volume_type, 1, region=data_provider.region):.3f}/GB '
                                f'= ${monthly_cost:.2f}/month'
                            ),
                            'why_waste': f'This volume is not attached to any instance. It was likely left behind after an instance was terminated or a snapshot was restored.',
                            'risk': 'Verify no data on this volume is needed before deleting. Consider creating a snapshot first as a safety net.',
                        },
                        metadata={
                            'volume_name': volume_name,
                            'size_gb': volume.size_gb,
                            'volume_type': volume.volume_type,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                
                # Check 2: gp2 → gp3 migration opportunities
                if volume.volume_type == 'gp2':
                    # CLO-359: region-scaled — EBS_PRICING is flat us-east-1
                    # rates, so this saving was always understated outside
                    # us-east-1 (the gp2/gp3 delta scales with the region
                    # multiplier just like the absolute price does).
                    gp2_cost = get_ebs_monthly_cost(
                        'gp2', volume.size_gb, region=data_provider.region
                    )
                    gp3_cost = get_ebs_monthly_cost(
                        'gp3', volume.size_gb, region=data_provider.region
                    )
                    gp2_rate_per_gb = get_ebs_monthly_cost(
                        'gp2', 1, region=data_provider.region
                    )
                    gp3_rate_per_gb = get_ebs_monthly_cost(
                        'gp3', 1, region=data_provider.region
                    )
                    # CLO-514: gp3 includes 3,000 IOPS and 125 MiB/s. A gp2
                    # volume above 1,000 GiB delivers more IOPS (3 per GiB)
                    # and one of 334 GiB or more 250 MiB/s, so a migration
                    # that keeps its performance provisions the difference,
                    # and that cost comes off the per-GB saving.
                    mult = _region_price_multiplier(data_provider.region)
                    target_iops, target_throughput = gp2_baseline(volume.size_gb)
                    extra_iops_cost = (
                        provisioned_iops_monthly_cost('gp3', target_iops) * mult
                    )
                    extra_throughput_cost = (
                        max(target_throughput - GP3_FREE_THROUGHPUT_MIBPS, 0)
                        * GP3_THROUGHPUT_PRICE * mult
                    )
                    gp3_cost += extra_iops_cost + extra_throughput_cost
                    savings = gp2_cost - gp3_cost
                    keeps_baseline = (
                        target_iops > GP3_FREE_IOPS
                        or target_throughput > GP3_FREE_THROUGHPUT_MIBPS
                    )
                    modify_command = (
                        f"aws ec2 modify-volume --volume-id {volume.volume_id} --volume-type gp3"
                    )
                    if keeps_baseline:
                        modify_command += (
                            f" --iops {target_iops} --throughput {target_throughput}"
                        )
                    pricing = (
                        f'gp2: {volume.size_gb} GB × ${gp2_rate_per_gb:.3f}/GB = ${gp2_cost:.2f}/mo → '
                        f'gp3: {volume.size_gb} GB × ${gp3_rate_per_gb:.3f}/GB'
                    )
                    if keeps_baseline:
                        pricing += (
                            f' + {max(target_iops - GP3_FREE_IOPS, 0):,} IOPS above the included 3,000'
                            f' (${extra_iops_cost:.2f}) + {max(target_throughput - GP3_FREE_THROUGHPUT_MIBPS, 0)} MiB/s'
                            f' above the included 125 (${extra_throughput_cost:.2f}) to keep gp2\'s'
                            f' {target_iops:,} IOPS / {target_throughput} MiB/s baseline'
                        )
                    pricing += f' = ${gp3_cost:.2f}/mo'

                    if savings >= settings.min_waste_threshold_usd:
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=volume.volume_id,
                            resource_type=ResourceType.EBS_VOLUME,
                            waste_type=WasteType.GP2_MIGRATION,
                            title=f"gp2 → gp3 Migration Opportunity",
                            description=f"Volume '{volume_name}' ({volume.size_gb}GB) can save ${savings:.2f}/month by migrating to gp3.",
                            monthly_savings=savings,
                            confidence=ConfidenceLevel.HIGH,
                            action=(
                                f"Modify volume type from gp2 to gp3 with {target_iops:,} IOPS and "
                                f"{target_throughput} MiB/s to keep gp2's baseline. No downtime required."
                                if keeps_baseline else
                                "Modify volume type from gp2 to gp3. No downtime required."
                            ),
                            action_command=modify_command,
                            explanation={
                                'detection': f'Volume type is gp2. gp3 provides the same baseline performance at lower cost.',
                                'threshold': 'All gp2 volumes are candidates for gp3 migration',
                                'pricing': pricing,
                                'why_waste': f'gp3 is the successor to gp2 with 20% lower cost per GB. This migration requires no downtime and is fully reversible.',
                                'risk': (
                                    'Migration is non-disruptive. Volume remains available during modification. '
                                    + (
                                        f'Set gp3 to {target_iops:,} IOPS and {target_throughput} MiB/s: '
                                        f'gp3 defaults (3,000 IOPS, 125 MiB/s) are below this volume\'s gp2 baseline.'
                                        if keeps_baseline else
                                        'gp3 defaults (3,000 IOPS, 125 MiB/s) meet or exceed this volume\'s gp2 baseline.'
                                    )
                                ),
                            },
                            metadata={
                                'volume_name': volume_name,
                                'size_gb': volume.size_gb,
                                'current_type': 'gp2',
                                'recommended_type': 'gp3',
                                'recommended_iops': target_iops,
                                'recommended_throughput': target_throughput,
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
                

            # Fetch ALL snapshots for orphan detection (age_threshold_days=0)
            all_snapshots = await data_provider.get_ebs_snapshots(age_threshold_days=0)
            
            # Fetch AMIs for AMI orphan detection
            amis = await data_provider.get_amis()
            registered_ami_ids = {ami.image_id for ami in amis}
            
            # Track snapshot IDs flagged by higher-priority detectors to avoid duplicates
            orphaned_snapshot_ids = set()
            ami_orphaned_snapshot_ids = set()
            
            # Check 5: AMI Orphaned Snapshots (highest priority among snapshot checks)
            for snapshot in all_snapshots:
                match = AMI_SNAPSHOT_PATTERN.search(snapshot.description or '')
                if match:
                    ami_id = match.group(1)
                    if ami_id not in registered_ami_ids:
                        age_days = snapshot.age_days if snapshot.age_days else (
                            (datetime.now(timezone.utc) - snapshot.start_time).days if snapshot.start_time else 0
                        )
                        monthly_cost = snapshot.volume_size_gb * 0.05
                        
                        ami_orphaned_snapshot_ids.add(snapshot.snapshot_id)
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=snapshot.snapshot_id,
                            resource_type=ResourceType.EBS_SNAPSHOT,
                            waste_type=WasteType.AMI_ORPHANED_SNAPSHOT,
                            title=f"AMI Orphaned Snapshot ({snapshot.volume_size_gb}GB)",
                            description=(
                                f"Snapshot '{snapshot.snapshot_id}' ({snapshot.volume_size_gb}GB, {age_days} days old) "
                                f"was created for AMI {ami_id} which has been deregistered. "
                                f"The backing AMI no longer exists — this snapshot is no longer serving its original purpose."
                            ),
                            monthly_savings=monthly_cost,
                            confidence=ConfidenceLevel.HIGH,
                            action=(
                                "Delete this snapshot if the deregistered AMI is no longer needed. "
                                "Verify no other AMIs or launch templates reference this snapshot."
                            ),
                            action_command=f"aws ec2 delete-snapshot --snapshot-id {snapshot.snapshot_id}",
                            explanation={
                                'detection': f'Snapshot was created by CreateImage for AMI {ami_id}, which has been deregistered',
                                'threshold': 'AMI backing this snapshot no longer exists',
                                'pricing': f'{snapshot.volume_size_gb} GB × $0.05/GB = ${monthly_cost:.2f}/month',
                                'why_waste': f'This snapshot was created to back AMI {ami_id}, which has since been deregistered. The snapshot no longer serves its original purpose.',
                                'risk': 'Verify no launch templates or Auto Scaling groups reference this snapshot. Check if any other AMIs share this snapshot.',
                            },
                            metadata={
                                'snapshot_name': snapshot.description or snapshot.snapshot_id,
                                'volume_size_gb': snapshot.volume_size_gb,
                                'age_days': age_days,
                                'deregistered_ami_id': ami_id,
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
            
            # Check 4: Orphaned EBS Snapshots (source volume deleted)
            for snapshot in (all_snapshots if volume_list_complete else []):
                # Skip if already flagged as AMI orphan (higher priority)
                if snapshot.snapshot_id in ami_orphaned_snapshot_ids:
                    continue
                
                if snapshot.volume_id and snapshot.volume_id not in existing_volume_ids:
                    age_days = snapshot.age_days if snapshot.age_days else (
                        (datetime.now(timezone.utc) - snapshot.start_time).days if snapshot.start_time else 0
                    )
                    monthly_cost = snapshot.volume_size_gb * 0.05
                    snapshot_name = snapshot.description or snapshot.snapshot_id
                    
                    orphaned_snapshot_ids.add(snapshot.snapshot_id)
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=snapshot.snapshot_id,
                        resource_type=ResourceType.EBS_SNAPSHOT,
                        waste_type=WasteType.ORPHANED_EBS_SNAPSHOT,
                        title=f"Orphaned EBS Snapshot ({snapshot.volume_size_gb}GB)",
                        description=(
                            f"Snapshot '{snapshot_name}' ({snapshot.volume_size_gb}GB, {age_days} days old) "
                            f"references deleted volume {snapshot.volume_id}. "
                            f"The source volume no longer exists — this snapshot cannot be used for incremental recovery."
                        ),
                        monthly_savings=monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete this orphaned snapshot if no longer needed for standalone restore.",
                        action_command=f"aws ec2 delete-snapshot --snapshot-id {snapshot.snapshot_id}",
                        explanation={
                            'detection': f'Source volume {snapshot.volume_id} no longer exists. Snapshot is {age_days} days old.',
                            'threshold': 'Source EBS volume has been deleted',
                            'pricing': f'{snapshot.volume_size_gb} GB × $0.05/GB = ${monthly_cost:.2f}/month',
                            'why_waste': f'This snapshot references volume {snapshot.volume_id} which has been deleted. Incremental snapshot chains are broken — this snapshot is now a standalone copy.',
                            'risk': 'This may still contain data needed for compliance or disaster recovery. Verify before deleting.',
                        },
                        metadata={
                            'snapshot_name': snapshot_name,
                            'volume_size_gb': snapshot.volume_size_gb,
                            'age_days': age_days,
                            'deleted_volume_id': snapshot.volume_id,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
            
            # Check 3: Old snapshots (skip those already flagged as orphaned)
            snapshots = await data_provider.get_ebs_snapshots(age_threshold_days=settings.snapshot_age_days)
            
            for snapshot in snapshots:
                # Skip if already flagged by orphan detectors
                if snapshot.snapshot_id in orphaned_snapshot_ids or snapshot.snapshot_id in ami_orphaned_snapshot_ids:
                    continue
                
                age_days = snapshot.age_days if snapshot.age_days else (
                    (datetime.now(timezone.utc) - snapshot.start_time).days if snapshot.start_time else 0
                )
                monthly_cost = snapshot.volume_size_gb * 0.05
                
                snapshot_name = snapshot.description or snapshot.snapshot_id
                
                waste_items.append(WasteItem(
                    id=str(uuid.uuid4()),
                    resource_id=snapshot.snapshot_id,
                    resource_type=ResourceType.EBS_SNAPSHOT,
                    waste_type=WasteType.OLD_EBS_SNAPSHOT,
                    title=f"Old EBS Snapshot ({age_days} days)",
                    description=f"Snapshot '{snapshot_name}' ({snapshot.volume_size_gb}GB) is {age_days} days old.",
                    monthly_savings=monthly_cost,
                    confidence=ConfidenceLevel.MEDIUM,
                    action="Delete this snapshot if no longer needed.",
                    action_command=f"aws ec2 delete-snapshot --snapshot-id {snapshot.snapshot_id}",
                    explanation={
                        'detection': f'Snapshot is {age_days} days old, exceeding the {settings.snapshot_age_days}-day retention threshold',
                        'threshold': f'> {settings.snapshot_age_days} days old',
                        'pricing': f'{snapshot.volume_size_gb} GB × $0.05/GB = ${monthly_cost:.2f}/month',
                        'why_waste': f'Old snapshots accumulate silently. At {age_days} days old, this snapshot likely represents a point-in-time backup that is no longer relevant.',
                        'risk': 'Verify this snapshot is not the only backup for critical data. Check if any AMIs reference this snapshot before deleting.',
                    },
                    metadata={
                        'snapshot_name': snapshot_name,
                        'volume_size_gb': snapshot.volume_size_gb,
                        'age_days': age_days,
                        'detection_mode': data_provider.provider_type,
                    }
                ))
            
            # Check 3: Over-provisioned IOPS (CLO-516). Runs LAST, so its
            # budgeted metric reads can never starve the volume and snapshot
            # checks above. It used to import a model and call a provider
            # method that did not exist, swallowed at DEBUG, so it never fired.
            waste_items.extend(
                await self._detect_over_provisioned_iops(volumes, data_provider, settings, started)
            )

            logger.info(f"EBS detector found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"Error in EBS waste detection: {e}")
            raise
    GB = 1_073_741_824  # bytes per GiB
    # Bucket name patterns to skip for empty-bucket detection (infrastructure buckets)
    _S3_INFRA_PATTERNS = [
        'cdk-', 'cdktoolkit', 'cf-templates', 'cloudformation',
        'aws-sam-', 'aws-codestar', 'codepipeline', 'codebuild',
        'elasticbeanstalk', 'sagemaker',
        '-logs', '-logging', '-trail', '-audit',
    ]
    async def _detect_s3_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        S3 waste orchestrator — calls sub-detectors for each bucket.
        
        Detectors:
        1. INCOMPLETE_MULTIPART – Old incomplete multipart uploads
        2. NO_LIFECYCLE_POLICY – Large buckets without lifecycle policies (re-enabled with size filter)
        3. S3_RAPID_GROWTH – Buckets growing abnormally fast
        4. S3_WRONG_STORAGE_CLASS – Standard storage that should be Intelligent-Tiering
        5. S3_EMPTY_BUCKET – Empty buckets (hygiene)
        6. S3_HIGH_REQUEST_AND_TRANSFER_COST – Non-storage costs dominate (CUR-based)
        """
        waste_items = []
        
        try:
            buckets = await data_provider.get_s3_buckets()
            
            for bucket in buckets:
                # CRITICAL: Filter by region — S3 buckets are global but we scan per-region
                if bucket.region and bucket.region != data_provider.region:
                    continue
                
                # Run sub-detectors per bucket
                waste_items.extend(self._detect_s3_incomplete_multipart(bucket, settings))
                if bucket.has_lifecycle_policy is None:
                    # CLO-551: the lifecycle configuration is MISSING (the
                    # read failed with an error other than
                    # NoSuchLifecycleConfiguration, or an export that cannot
                    # tell such a failure from "no policy"). "No policy" is
                    # not known, and neither is whether a rule already
                    # expires or transitions the objects, which suppresses
                    # s3_rapid_growth and s3_wrong_storage_class: all three
                    # are withheld for this bucket and noted.
                    note = getattr(data_provider, '_note_idle_verdict_missing', None)
                    if callable(note):
                        note('s3 lifecycle', bucket.bucket_name, 'lifecycle configuration not read',
                             verdict='no-lifecycle-policy',
                             evidence='lifecycle configurations (s3:GetLifecycleConfiguration)')
                    waste_items.extend(self._detect_s3_empty_bucket(bucket, settings))
                    continue
                no_lifecycle = self._detect_s3_no_lifecycle(bucket, settings)
                wrong_class = self._detect_s3_wrong_storage_class(bucket, settings)
                if no_lifecycle and wrong_class:
                    # CLO-513: both estimate the same move of Standard bytes
                    # to cheaper classes; count it once, on wrong_storage_class.
                    for item in no_lifecycle:
                        item.monthly_savings = 0.0
                        item.metadata['estimated_savings_usd'] = 0.0
                        item.metadata['savings_counted_in'] = WasteType.S3_WRONG_STORAGE_CLASS.value
                        item.explanation['pricing'] += (
                            ' Counted once, in this bucket\'s S3 Wrong Storage Class finding; shown as $0 here.'
                        )
                waste_items.extend(no_lifecycle)
                waste_items.extend(self._detect_s3_rapid_growth(bucket, settings))
                waste_items.extend(wrong_class)
                waste_items.extend(self._detect_s3_empty_bucket(bucket, settings))
            
            # Detector 6: CUR-based cost breakdown (one CE call for all buckets)
            waste_items.extend(
                await self._detect_s3_high_request_and_transfer_cost(
                    data_provider, settings
                )
            )
            
            logger.info(f"S3 detector found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"Error in S3 waste detection: {e}")
            raise
    def _detect_s3_incomplete_multipart(
        self,
        bucket,
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """Detect stale incomplete multipart uploads in an S3 bucket.

        CLO-513: the saving used to be ``count x 0.05 GB``, a made-up size.
        The bytes an upload's parts hold are only readable with ListParts,
        which needs s3:ListMultipartUploadParts, a permission the scan role
        does not have; so the size is reported as not measured ($0) rather
        than guessed. An upload is flagged only once it is older than
        INCOMPLETE_MULTIPART_MIN_AGE_DAYS: a younger one may still be in
        progress, and aborting it would break a live transfer.
        """
        if not bucket.incomplete_multipart_count or bucket.incomplete_multipart_count <= 0:
            return []

        initiated = getattr(bucket, 'incomplete_multipart_initiated', None)
        if initiated is None:
            # No upload dates (an export made before they were kept): the
            # age cannot be checked, so nothing is flagged.
            return []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=INCOMPLETE_MULTIPART_MIN_AGE_DAYS)
        stale = []
        for value in initiated:
            if isinstance(value, _DATETIME) and value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            if isinstance(value, _DATETIME) and value <= cutoff:
                stale.append(value)
        if not stale:
            return []
        oldest_days = (now - min(stale)).days
        sampled = len(initiated) < bucket.incomplete_multipart_count

        return [WasteItem(
            id=str(uuid.uuid4()),
            resource_id=bucket.bucket_name,
            resource_type=ResourceType.S3_BUCKET,
            waste_type=WasteType.INCOMPLETE_MULTIPART,
            title="Incomplete Multipart Uploads",
            description=(
                f"Bucket '{bucket.bucket_name}' has {len(stale)} incomplete multipart "
                f"upload{'s' if len(stale) != 1 else ''} older than "
                f"{INCOMPLETE_MULTIPART_MIN_AGE_DAYS} days (oldest: {oldest_days} days)."
            ),
            monthly_savings=0.0,
            confidence=ConfidenceLevel.HIGH,
            action=(
                "Abort the stale multipart uploads, and add a lifecycle rule "
                "(AbortIncompleteMultipartUpload after 7 days) so new ones are cleaned up."
            ),
            explanation={
                'detection': (
                    f'{len(stale)} of the bucket\'s {bucket.incomplete_multipart_count}'
                    f'{" listed" if sampled else ""} incomplete multipart uploads were started more than '
                    f'{INCOMPLETE_MULTIPART_MIN_AGE_DAYS} days ago'
                ),
                'threshold': f'Incomplete multipart uploads older than {INCOMPLETE_MULTIPART_MIN_AGE_DAYS} days',
                'pricing': (
                    'Uploaded parts are billed as S3 storage until the upload is aborted, but their size is '
                    'not measured: reading it needs s3:ListMultipartUploadParts, which the CloudWise scan '
                    'role does not have. Saving shown as $0; the S3 Storage Lens "incomplete multipart '
                    'upload bytes" metric shows the real figure.'
                ),
                'why_waste': f'Incomplete multipart uploads consume storage but are not usable. They are typically left behind by failed or interrupted uploads.',
                'risk': 'Aborting a stale upload is safe; uploads under 7 days old are not flagged, since they may still be in progress. A lifecycle rule prevents future accumulation.',
            },
            metadata={
                'bucket_name': bucket.bucket_name,
                'incomplete_uploads': bucket.incomplete_multipart_count,
                'stale_uploads': len(stale),
                'oldest_upload_age_days': oldest_days,
                'size_measured': False,
                'detection_mode': getattr(self, '_provider_type', 'unknown'),
            }
        )]
    def _detect_s3_no_lifecycle(
        self,
        bucket,
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect large S3 buckets without lifecycle policies.
        
        Re-enabled with size-based filtering — only flags buckets > s3_lifecycle_min_size_gb.
        """
        if bucket.has_lifecycle_policy:
            return []
        
        # Size-based filtering: only flag buckets above the threshold
        min_size_bytes = int(settings.s3_lifecycle_min_size_gb * self.GB)
        if bucket.total_size_bytes < min_size_bytes:
            return []
        
        size_gb = bucket.total_size_bytes / self.GB
        # CLO-513: the saving used to be the bucket's whole storage bill, as
        # if a lifecycle rule deleted everything. A rule moves older objects
        # to cheaper classes, so the saving is the same share of S3 Standard
        # storage s3_wrong_storage_class estimates (s3_tiering_savings_pct),
        # on the Standard bytes only (other classes are already cheaper).
        breakdown = bucket.storage_class_breakdown or {}
        standard_bytes = (
            breakdown.get('StandardStorage', 0) if breakdown else bucket.total_size_bytes
        )
        standard_gb = standard_bytes / self.GB
        monthly_cost = standard_gb * S3_STANDARD_PER_GB
        savings_pct = settings.s3_tiering_savings_pct / 100.0
        estimated_savings = monthly_cost * savings_pct

        if estimated_savings < settings.min_waste_threshold_usd:
            return []

        return [WasteItem(
            id=str(uuid.uuid4()),
            resource_id=bucket.bucket_name,
            resource_type=ResourceType.S3_BUCKET,
            waste_type=WasteType.NO_LIFECYCLE_POLICY,
            title="S3 Bucket Without Lifecycle Policy",
            description=(
                f"Bucket '{bucket.bucket_name}' ({size_gb:.1f} GB) has no lifecycle policy. "
                f"Without lifecycle rules, objects accumulate indefinitely."
            ),
            monthly_savings=estimated_savings,
            confidence=ConfidenceLevel.MEDIUM,
            action=(
                f"Add lifecycle rules to transition old objects to cheaper storage classes "
                f"or expire them. Current S3 Standard cost: ${monthly_cost:.2f}/month."
            ),
            explanation={
                'detection': f'Bucket has no S3 Lifecycle Configuration and is {size_gb:.1f} GB ({bucket.object_count:,} objects)',
                'threshold': f'> {settings.s3_lifecycle_min_size_gb} GB with no lifecycle rules',
                'pricing': (
                    f'S3 Standard: {standard_gb:.1f} GB × ${S3_STANDARD_PER_GB:.4f}/GB = ${monthly_cost:.2f}/month. '
                    f'Estimated saving from transitioning older objects: {settings.s3_tiering_savings_pct:.0f}% '
                    f'= ${estimated_savings:.2f}/month (the real share depends on object age and access).'
                ),
                'why_waste': f'Without lifecycle policies, objects remain in S3 Standard indefinitely. Older objects that are rarely accessed could be automatically transitioned to cheaper tiers.',
                'risk': 'Adding lifecycle rules is non-destructive. Start with transition rules (Standard → IA after 90 days) before adding expiration rules.',
            },
            metadata={
                'bucket_name': bucket.bucket_name,
                'total_size_gb': round(size_gb, 2),
                'standard_size_gb': round(standard_gb, 2),
                'object_count': bucket.object_count,
                'monthly_cost_usd': round(monthly_cost, 2),
                'estimated_savings_usd': round(estimated_savings, 2),
            }
        )]
    def _detect_s3_rapid_growth(
        self,
        bucket,
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect S3 buckets with abnormal growth patterns.
        
        Criteria (ALL must be true):
          1. Bucket has size metrics available (CloudWatch BucketSizeBytes)
          2. Current size > s3_growth_min_size_gb (default 1 GB)
          3. 30-day growth rate > s3_growth_threshold_pct (default 100%)
          4. Absolute growth > s3_growth_min_absolute_gb (default 10 GB)
          5. No lifecycle policy with expiration rules present
        """
        # Require size metrics
        if bucket.total_size_bytes <= 0 or bucket.size_previous_bytes <= 0:
            return []
        
        # Minimum current size
        min_size_bytes = int(settings.s3_growth_min_size_gb * self.GB)
        if bucket.total_size_bytes < min_size_bytes:
            return []
        
        # Check growth rate
        growth_pct = bucket.size_growth_pct_30d
        if growth_pct < settings.s3_growth_threshold_pct:
            return []
        
        # Check absolute growth
        growth_bytes = bucket.total_size_bytes - bucket.size_previous_bytes
        min_absolute_bytes = int(settings.s3_growth_min_absolute_gb * self.GB)
        if growth_bytes < min_absolute_bytes:
            return []
        
        # Skip if bucket has expiration rules (actively managed)
        has_expiration = any(
            'Expiration' in rule
            for rule in bucket.lifecycle_rules
        )
        if has_expiration:
            return []
        
        curr_gb = bucket.total_size_bytes / self.GB
        prev_gb = bucket.size_previous_bytes / self.GB
        growth_gb = growth_bytes / self.GB
        current_cost = curr_gb * S3_STANDARD_PER_GB
        projected_growth_cost = growth_gb * S3_STANDARD_PER_GB
        
        return [WasteItem(
            id=str(uuid.uuid4()),
            resource_id=bucket.bucket_name,
            resource_type=ResourceType.S3_BUCKET,
            waste_type=WasteType.S3_RAPID_GROWTH,
            title="S3 Rapid Growth Anomaly",
            description=(
                f"S3 bucket '{bucket.bucket_name}' grew {growth_pct:.0f}% in 30 days "
                f"({prev_gb:.1f} GB → {curr_gb:.1f} GB). "
                f"Investigate source of growth. Consider adding lifecycle rules "
                f"to expire old objects or transition to cheaper storage classes."
            ),
            monthly_savings=projected_growth_cost,
            confidence=ConfidenceLevel.LOW,
            action=(
                f"S3 bucket '{bucket.bucket_name}' grew {growth_pct:.0f}% in 30 days "
                f"({prev_gb:.1f} GB → {curr_gb:.1f} GB). "
                f"Investigate source of growth. Consider adding lifecycle rules "
                f"to expire old objects or transition to cheaper storage classes."
            ),
            explanation={
                'detection': f'Bucket grew {growth_pct:.0f}% in 30 days ({prev_gb:.1f} GB → {curr_gb:.1f} GB, +{growth_gb:.1f} GB)',
                'threshold': f'> {settings.s3_growth_threshold_pct}% growth in 30 days with > {settings.s3_growth_min_absolute_gb} GB absolute increase',
                'pricing': f'Growth adds ~${projected_growth_cost:.2f}/month in storage costs. At this rate, costs will double in ~{30/max(growth_pct, 1)*100:.0f} days.',
                'why_waste': f'Abnormal growth often indicates runaway logging, build artifacts, or misconfigured data pipelines. Without lifecycle rules, this growth continues unchecked.',
                'risk': 'Investigate the source of growth before adding lifecycle rules. Use S3 Storage Lens or S3 Inventory to identify which prefixes are growing.',
            },
            metadata={
                'bucket_name': bucket.bucket_name,
                'current_size_gb': round(curr_gb, 2),
                'previous_size_gb': round(prev_gb, 2),
                'growth_pct_30d': growth_pct,
                'growth_gb_30d': round(growth_gb, 2),
                'has_lifecycle_policy': bucket.has_lifecycle_policy,
                'has_expiration_rules': has_expiration,
                'storage_class': 'StandardStorage',
                'projected_monthly_increase_usd': round(projected_growth_cost, 2),
            }
        )]
    def _detect_s3_wrong_storage_class(
        self,
        bucket,
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect S3 buckets where Standard storage should be Intelligent-Tiering.
        
        Criteria (ALL must be true):
          1. Bucket has size metrics available
          2. StandardStorage bytes > s3_tiering_min_size_gb (default 50 GB)
          3. StandardStorage is > 90% of total bucket size
          4. Bucket does NOT already have Intelligent-Tiering
          5. Bucket does NOT have lifecycle rules transitioning to cheaper classes
          6. Monthly storage cost >= min_waste_threshold_usd
        """
        if bucket.total_size_bytes <= 0:
            return []
        
        standard_bytes = bucket.storage_class_breakdown.get('StandardStorage', 0)
        if standard_bytes <= 0:
            return []
        
        # Minimum Standard size threshold
        min_tiering_bytes = int(settings.s3_tiering_min_size_gb * self.GB)
        if standard_bytes < min_tiering_bytes:
            return []
        
        # Must be primarily Standard (> 90%)
        standard_pct = round((standard_bytes / bucket.total_size_bytes) * 100, 1)
        if standard_pct < 90.0:
            return []
        
        # Skip if already using Intelligent-Tiering
        if bucket.has_intelligent_tiering:
            return []
        
        # Skip if lifecycle already transitions to cheaper classes
        _TIERING_CLASSES = {
            'INTELLIGENT_TIERING', 'STANDARD_IA', 'ONEZONE_IA',
            'GLACIER', 'GLACIER_IR', 'DEEP_ARCHIVE',
        }
        has_tiering_transitions = any(
            any(
                t.get('StorageClass', '') in _TIERING_CLASSES
                for t in rule.get('Transitions', [])
            )
            for rule in bucket.lifecycle_rules
        )
        if has_tiering_transitions:
            return []
        
        std_gb = standard_bytes / self.GB
        standard_cost = std_gb * S3_STANDARD_PER_GB
        savings_pct = settings.s3_tiering_savings_pct / 100.0
        estimated_savings = standard_cost * savings_pct
        monitoring_fee = round(bucket.object_count / 1000 * S3_IT_MONITORING_PER_1K, 2)
        
        if standard_cost < settings.min_waste_threshold_usd:
            return []
        
        return [WasteItem(
            id=str(uuid.uuid4()),
            resource_id=bucket.bucket_name,
            resource_type=ResourceType.S3_BUCKET,
            waste_type=WasteType.S3_WRONG_STORAGE_CLASS,
            title="S3 Wrong Storage Class",
            description=(
                f"S3 bucket '{bucket.bucket_name}' has {std_gb:.1f} GB in Standard storage "
                f"(${standard_cost:.2f}/month) with no Intelligent-Tiering configuration. "
                f"Enable S3 Intelligent-Tiering to automatically move infrequently-accessed "
                f"objects to cheaper tiers. Estimated savings: ${estimated_savings:.2f}/month "
                f"({settings.s3_tiering_savings_pct:.0f}%). "
                f"No retrieval fees, no access pattern analysis required."
            ),
            monthly_savings=estimated_savings,
            confidence=ConfidenceLevel.LOW,
            action=(
                f"S3 bucket '{bucket.bucket_name}' has {std_gb:.1f} GB in Standard storage "
                f"(${standard_cost:.2f}/month) with no Intelligent-Tiering configuration. "
                f"Enable S3 Intelligent-Tiering to automatically move infrequently-accessed "
                f"objects to cheaper tiers. Estimated savings: ${estimated_savings:.2f}/month "
                f"({settings.s3_tiering_savings_pct:.0f}%). "
                f"No retrieval fees, no access pattern analysis required."
            ),
            explanation={
                'detection': f'{std_gb:.1f} GB ({standard_pct}%) of bucket storage is in Standard class with no Intelligent-Tiering',
                'threshold': f'> {settings.s3_tiering_min_size_gb} GB in Standard with no tiering configuration',
                'pricing': f'Standard: ${standard_cost:.2f}/month. IT monitoring fee: ${monitoring_fee:.2f}/month. Net savings: ~${estimated_savings:.2f}/month ({settings.s3_tiering_savings_pct:.0f}%)',
                'why_waste': f'S3 Intelligent-Tiering automatically moves infrequently accessed objects to lower-cost tiers with no retrieval fees. Without it, all objects stay in the most expensive tier.',
                'risk': f'Intelligent-Tiering has a small per-object monitoring fee (${S3_IT_MONITORING_PER_1K:.4f} per 1,000 objects). Best suited for buckets with unpredictable access patterns.',
            },
            metadata={
                'bucket_name': bucket.bucket_name,
                'standard_size_gb': round(std_gb, 2),
                'total_size_gb': round(bucket.total_size_bytes / self.GB, 2),
                'standard_pct': standard_pct,
                'object_count': bucket.object_count,
                'current_monthly_cost_usd': round(standard_cost, 2),
                'estimated_savings_usd': round(estimated_savings, 2),
                'recommended_class': 'S3 Intelligent-Tiering',
                'monitoring_fee_monthly': monitoring_fee,
                'has_lifecycle_policy': bucket.has_lifecycle_policy,
                'has_tiering_transitions': has_tiering_transitions,
            }
        )]
    def _detect_s3_empty_bucket(
        self,
        bucket,
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect empty S3 buckets (hygiene detector).

        Criteria (ALL must be true):
          1. The provider observed the contents (CLO-488) and they are
             empty: total_size_bytes == 0 AND object_count == 0
          2. Bucket created more than 30 days ago (a known creation date)
          3. Not a known infrastructure bucket (CDK, CloudFormation, etc.)
          4. Not a bucket a lifecycle expiration rule clears by design,
             with evidence it was recently used (CLO-385)
        """
        # Must be empty
        if bucket.total_size_bytes > 0 or bucket.object_count > 0:
            return []

        # CLO-488: zero size and count are only evidence when the provider
        # observed the contents. Missing size or count data is MISSING, not
        # empty; the provider notes it in data_warnings. Before this, an
        # air-gapped upload reported every bucket in the export as empty.
        if not bucket.contents_observed:
            return []

        # Must be older than 30 days. CLO-488: an unknown creation date is
        # not old enough; it used to skip the age guard (age_days = 0), and
        # pre-1.13.0 air-gapped exports carry no CreationDate.
        if not bucket.creation_date:
            return []
        age_days = (datetime.now(timezone.utc) - bucket.creation_date).days
        if age_days < 30:
            return []

        # Skip infrastructure buckets
        bucket_lower = bucket.bucket_name.lower()
        for pattern in self._S3_INFRA_PATTERNS:
            if pattern in bucket_lower:
                return []

        # CLO-385 (METHOD.md pinned decision 4): a bucket a workload writes
        # to and a lifecycle expiration rule then clears is in use, even
        # though it's empty at scan time. Suppress rather than downgrade —
        # METHOD.md's rubric calls this fp_not_waste outright, not
        # uncertain, so leaving it flagged at any confidence would still be
        # wrong. `recent_max_object_count` is only populated (online mode)
        # when the bucket is currently empty and has an enabled expiration
        # rule, so a positive count here is real evidence of recent use.
        has_expiration_rule = any(
            rule.get('Status') == 'Enabled' and 'Expiration' in rule
            for rule in bucket.lifecycle_rules
        )
        # CLO-551: a bucket whose lifecycle read failed (None) may have such a
        # rule; with the same evidence of recent use it is suppressed too.
        may_expire = has_expiration_rule or bucket.has_lifecycle_policy is None
        if may_expire and (bucket.recent_max_object_count or 0) > 0:
            return []

        return [WasteItem(
            id=str(uuid.uuid4()),
            resource_id=bucket.bucket_name,
            resource_type=ResourceType.S3_BUCKET,
            waste_type=WasteType.S3_EMPTY_BUCKET,
            title="Empty S3 Bucket",
            description=(
                f"S3 bucket '{bucket.bucket_name}' has been empty for {age_days} days. "
                f"Consider deleting it to reduce console clutter and simplify IAM policies."
            ),
            monthly_savings=0.0,
            confidence=ConfidenceLevel.LOW,
            action=(
                f"S3 bucket '{bucket.bucket_name}' has been empty for {age_days} days. "
                f"Consider deleting it to reduce console clutter and simplify IAM policies."
            ),
            explanation={
                'detection': f'Bucket has 0 objects and 0 bytes. Created {age_days} days ago.',
                'threshold': 'Empty for > 30 days and not an infrastructure bucket',
                'pricing': 'Empty buckets incur no storage cost, but clutter your account and IAM policies.',
                'why_waste': f'This bucket has been empty for {age_days} days. It may have been created for testing or by a deployment tool and never used.',
                'risk': 'Verify no applications or scripts reference this bucket name before deleting. S3 bucket names are globally unique — once deleted, the name may be claimed by someone else.',
            },
            metadata={
                'bucket_name': bucket.bucket_name,
                'created_date': bucket.creation_date.isoformat() if bucket.creation_date else None,
                'age_days': age_days,
                'versioning_enabled': bucket.versioning_enabled,
            }
        )]
    async def _detect_s3_high_request_and_transfer_cost(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect S3 buckets where non-storage costs (transfer + API requests)
        dominate storage costs.

        Data source: CUR / Cost Explorer (not CloudWatch).

        Criteria (ALL must be true):
          1. Bucket has CUR cost data for the last 30 days
          2. Total S3 cost > s3_request_transfer_min_cost_usd (default $10)
          3. Non-storage / storage ratio > s3_request_transfer_ratio_threshold (default 1.0)
          4. Non-storage cost > s3_request_transfer_min_nonstorage_usd (default $5)
        """
        waste_items: List[WasteItem] = []

        try:
            breakdowns = await data_provider.get_s3_cost_breakdown()
        except Exception as e:
            logger.warning(f"S3 cost breakdown unavailable: {e}")
            return waste_items

        for bucket_name, bd in breakdowns.items():
            # Skip infrastructure buckets
            bucket_lower = bucket_name.lower()
            if any(p in bucket_lower for p in self._S3_INFRA_PATTERNS):
                continue

            # Criterion 1: must have meaningful total cost
            if bd.total_cost < settings.s3_request_transfer_min_cost_usd:
                continue

            # Criterion 2: non-storage must meet minimum
            if bd.non_storage_cost < settings.s3_request_transfer_min_nonstorage_usd:
                continue

            # Criterion 3: non-storage / storage ratio check
            storage = max(bd.storage_cost, 0.01)  # avoid division by zero
            ratio = bd.non_storage_cost / storage
            if ratio < settings.s3_request_transfer_ratio_threshold:
                continue

            # Build tailored recommendation
            dominant = bd.dominant_non_storage_category
            suggested_action, recommendations = self._s3_cost_recommendations(
                bucket_name, bd, dominant, ratio
            )

            waste_items.append(WasteItem(
                id=str(uuid.uuid4()),
                resource_id=bucket_name,
                resource_type=ResourceType.S3_BUCKET,
                waste_type=WasteType.S3_HIGH_REQUEST_AND_TRANSFER_COST,
                title="S3 High Request & Transfer Cost",
                description=suggested_action,
                monthly_savings=0.0,  # Cannot estimate without architectural changes
                confidence=ConfidenceLevel.LOW,
                action=suggested_action,
                explanation={
                    'detection': f'Non-storage costs (${bd.non_storage_cost:.2f}) are {ratio:.1f}× storage costs (${bd.storage_cost:.2f})',
                    'threshold': f'Non-storage/storage ratio > {settings.s3_request_transfer_ratio_threshold} with non-storage > ${settings.s3_request_transfer_min_nonstorage_usd}',
                    'pricing': f'Total: ${bd.total_cost:.2f}/month. Storage: ${bd.storage_cost:.2f}. Transfer: ${bd.transfer_out_cost + bd.transfer_regional_cost + bd.transfer_cross_region_cost:.2f}. Requests: ${bd.request_tier1_cost + bd.request_tier2_cost:.2f}.',
                    'why_waste': f'Dominant cost driver is {dominant.replace("_", " ")}. Architectural changes (CDN, caching, VPC endpoints) can significantly reduce these costs.',
                    'risk': 'Savings require architectural changes. Recommendations are listed in metadata. Evaluate each based on your access patterns.',
                },
                metadata={
                    'bucket_name': bucket_name,
                    'storage_cost_usd': round(bd.storage_cost, 2),
                    'transfer_out_cost_usd': round(bd.transfer_out_cost, 2),
                    'transfer_regional_cost_usd': round(bd.transfer_regional_cost, 2),
                    'transfer_cross_region_cost_usd': round(bd.transfer_cross_region_cost, 2),
                    'request_tier1_cost_usd': round(bd.request_tier1_cost, 2),
                    'request_tier2_cost_usd': round(bd.request_tier2_cost, 2),
                    'other_cost_usd': round(bd.other_cost, 2),
                    'total_cost_usd': round(bd.total_cost, 2),
                    'non_storage_cost_usd': round(bd.non_storage_cost, 2),
                    'non_storage_ratio': round(ratio, 2),
                    'dominant_cost_driver': dominant,
                    'recommendations': recommendations,
                },
            ))

        return waste_items
    @staticmethod
    def _s3_cost_recommendations(
        bucket_name: str,
        bd: Any,
        dominant: str,
        ratio: float,
    ) -> tuple:
        """Return (suggested_action, recommendations_list) based on dominant cost driver."""
        if dominant == 'data_transfer_out':
            action = (
                f"S3 bucket '{bucket_name}' has ${bd.transfer_out_cost:.2f}/month in internet "
                f"egress vs. ${bd.storage_cost:.2f}/month in storage ({ratio:.0f}\u00d7 storage "
                f"cost). Consider CloudFront, VPC endpoints, or S3 Select to reduce transfer."
            )
            recs = [
                "Put CloudFront in front of this bucket — reduces egress cost by ~15-50%",
                "Use VPC endpoints for EC2/Lambda consumers (eliminates egress for in-VPC traffic)",
                "Use S3 Select to transfer only needed rows/columns from structured data",
                "Enable S3 Transfer Acceleration for large uploads from distant clients",
                "Review application: are consumers downloading full objects when they need subsets?",
            ]
        elif dominant == 'api_requests':
            action = (
                f"S3 bucket '{bucket_name}' has ${bd.request_cost:.2f}/month in API requests "
                f"vs. ${bd.storage_cost:.2f}/month in storage ({ratio:.0f}\u00d7 storage cost). "
                f"Consider caching, batching, or S3 Event Notifications to reduce API calls."
            )
            recs = [
                "Cache frequently-accessed objects at the application layer (Redis, local disk)",
                "Use S3 Select instead of GetObject for structured data (CSV, JSON, Parquet)",
                "Batch small object reads — consider combining objects or using S3 Inventory",
                "For LIST-heavy workloads, cache directory listings instead of re-listing",
                "Replace polling patterns with S3 Event Notifications or EventBridge",
            ]
        elif dominant == 'cross_region_transfer':
            action = (
                f"S3 bucket '{bucket_name}' has ${bd.transfer_cross_region_cost:.2f}/month in "
                f"cross-region transfer vs. ${bd.storage_cost:.2f}/month in storage "
                f"({ratio:.0f}\u00d7 storage cost). Consider S3 Cross-Region Replication "
                f"or Multi-Region Access Points."
            )
            recs = [
                "Replicate bucket to the consuming region (S3 Cross-Region Replication)",
                "Use S3 Multi-Region Access Points to auto-route reads to nearest replica",
                "Move compute (Lambda, EC2) to the same region as the bucket",
            ]
        else:  # regional_transfer
            action = (
                f"S3 bucket '{bucket_name}' has ${bd.transfer_regional_cost:.2f}/month in "
                f"regional/cross-AZ transfer vs. ${bd.storage_cost:.2f}/month in storage "
                f"({ratio:.0f}\u00d7 storage cost). Consider VPC endpoints or co-locating "
                f"compute with the bucket."
            )
            recs = [
                "Use VPC Gateway Endpoints for S3 (free, eliminates cross-AZ NAT charges)",
                "Co-locate compute in the same AZ as the data when possible",
                "Review NAT Gateway data processing charges — VPC endpoints bypass NAT",
            ]
        return action, recs
    async def _detect_over_provisioned_iops(
        self,
        volumes,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
        started: float,
    ) -> List[WasteItem]:
        """CLO-516: in-use io1/io2/gp3 volumes whose measured one-minute peak
        IOPS over 14 days is under half of what they pay for.

        Candidates: provisioned IOPS above the type's minimum (gp3's free
        3,000; io1/io2's 100), attached for the whole window (younger
        attachments are skipped without a note). Their peaks come from one
        batched provider read; a volume the provider could not measure is
        MISSING (noted there), never read as idle."""
        waste_items: List[WasteItem] = []
        if not settings.cloudwatch_enabled:
            return waste_items
        days = OVER_PROVISIONED_IOPS_DAYS
        now = datetime.now(timezone.utc)
        candidates = []
        for volume in volumes:
            if volume.state != 'in-use' or volume.volume_type not in MIN_PROVISIONED_IOPS:
                continue
            provisioned = int(getattr(volume, 'iops', None) or 0)
            # Nothing to release when the volume already sits at its floor
            # (gp3: its throughput can pin IOPS above the free 3,000).
            if provisioned <= min_provisioned_iops(volume):
                continue
            since = _attached_since(volume)
            if since is not None and since > now - timedelta(days=days):
                continue  # attached for less than the window: too young to judge
            candidates.append(volume)
        if not candidates:
            return waste_items
        # Most expensive provisioned IOPS first: a spent time budget drops the
        # cheapest volumes (noted MISSING), not the ones that matter.
        candidates.sort(
            key=lambda v: provisioned_iops_monthly_cost(v.volume_type, int(v.iops)), reverse=True,
        )

        # Offline: an export without the IOPS capture reads supports_cloudwatch
        # False; ask anyway so each candidate is noted MISSING, not skipped.
        if not (data_provider.supports_cloudwatch or data_provider.provider_type == 'offline'):
            return waste_items
        peaks = await data_provider.get_ebs_iops_peaks(
            volume_ids=[v.volume_id for v in candidates],
            days=days,
            deadline=_iops_read_deadline(started),
        )

        for volume in candidates:
            peak = peaks.get(volume.volume_id)
            if peak is None:
                continue  # MISSING: the provider noted it
            provisioned = int(volume.iops)
            peak_iops = float(peak.peak_iops)
            if peak_iops >= provisioned * IOPS_PEAK_SHARE_GATE:
                continue
            floor = min_provisioned_iops(volume)
            target = max(int(math.ceil(peak_iops * IOPS_HEADROOM)), floor)
            if target >= provisioned:
                continue
            current_cost = provisioned_iops_monthly_cost(volume.volume_type, provisioned)
            target_cost = provisioned_iops_monthly_cost(volume.volume_type, target)
            savings = round(current_cost - target_cost, 2)
            if savings <= 0 or savings < settings.min_waste_threshold_usd:
                continue
            volume_name = (getattr(volume, 'tags', None) or {}).get('Name', volume.volume_id)
            window_label = f"{peak.window_days:g}-day"
            unused = provisioned - target
            waste_items.append(WasteItem(
                id=str(uuid.uuid4()),
                resource_id=volume.volume_id,
                resource_type=ResourceType.EBS_VOLUME,
                waste_type=WasteType.OVER_PROVISIONED_IOPS,
                title=f"Over-Provisioned EBS IOPS ({volume.volume_type})",
                description=(
                    f"Volume '{volume_name}' ({volume.volume_type}, {volume.size_gb}GB) "
                    f"has {provisioned:,} provisioned IOPS but its peak one-minute usage "
                    f"was {peak_iops:,.0f} IOPS ({window_label}). {unused:,} IOPS could be released."
                ),
                monthly_savings=savings,
                confidence=ConfidenceLevel.MEDIUM,
                action=(
                    f"Review, then reduce IOPS from {provisioned:,} to {target:,} "
                    f"(peak + 30% headroom, never below this volume's minimum of {floor:,})."
                ),
                action_command=(
                    f"aws ec2 modify-volume --volume-id {volume.volume_id} --iops {target}"
                ),
                explanation={
                    'detection': (
                        f'Volume has {provisioned:,} provisioned IOPS; its highest one-minute IOPS '
                        f'(VolumeReadOps + VolumeWriteOps per second) over {window_label} was '
                        f'{peak_iops:,.0f} ({peak_iops / provisioned * 100:.0f}% of provisioned), '
                        f'from {peak.datapoints:,} of {peak.expected_datapoints:,} minutes.'
                    ),
                    'threshold': 'Peak one-minute IOPS under 50% of provisioned over 14 days, volume attached for the whole window',
                    'pricing': (
                        f'{volume.volume_type} provisioned IOPS: ${current_cost:.2f}/month at {provisioned:,} IOPS '
                        f'vs ${target_cost:.2f}/month at {target:,} IOPS (list price, us-east-1'
                        f'{"; 3,000 IOPS included free" if volume.volume_type == "gp3" else ""}).'
                    ),
                    'why_waste': (
                        'Provisioned IOPS are charged whether used or not. '
                        'This volume never used half of its provisioned IOPS in the window.'
                    ),
                    'risk': (
                        'IOPS modification is online, but a volume can be modified only once '
                        'every 6 hours. A one-minute peak can hide shorter bursts, and monthly '
                        'jobs outside the window are not seen. Monitor after the change.'
                    ),
                },
                metadata={
                    'volume_name': volume_name,
                    'volume_type': volume.volume_type,
                    'size_gb': volume.size_gb,
                    'provisioned_iops': provisioned,
                    'peak_iops': round(peak_iops),
                    'recommended_iops': target,
                    'min_iops': floor,
                    'wasted_iops': unused,
                    'iops_datapoints': peak.datapoints,
                    'iops_expected_datapoints': peak.expected_datapoints,
                    'detection_mode': data_provider.provider_type,
                },
            ))
        return waste_items
    async def _detect_efs_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """Detect idle EFS filesystems without mount targets using DataProvider."""
        waste_items = []
        
        try:
            # Get EFS filesystems from data provider
            filesystems = await data_provider.get_efs_filesystems()
            
            for fs in filesystems:
                size_gb = (fs.size_bytes or 0) / (1024 ** 3)
                monthly_cost = size_gb * 0.30
                
                if not fs.has_mount_targets and monthly_cost >= settings.min_waste_threshold_usd:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=fs.filesystem_id,
                        resource_type=ResourceType.EFS_FILESYSTEM,
                        waste_type=WasteType.IDLE_EFS,
                        title="EFS Without Mount Targets",
                        description=f"EFS '{fs.name or fs.filesystem_id}' ({size_gb:.1f}GB) has no mount targets.",
                        monthly_savings=monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete this filesystem.",
                        action_command=f"aws efs delete-file-system --file-system-id {fs.filesystem_id}",
                        explanation={
                            'detection': f'EFS filesystem has no mount targets (not mounted anywhere)',
                            'threshold': 'Zero mount targets with size > $0 cost',
                            'pricing': f'{size_gb:.1f} GB × $0.30/GB/month = ${monthly_cost:.2f}/month',
                            'why_waste': f'Without mount targets, no EC2 instance or container can access this filesystem. It\'s paying for storage that cannot be read or written.',
                            'risk': 'Verify the filesystem is not in the process of being set up. Back up data with AWS Backup or DataSync before deleting.',
                        },
                        metadata={
                            'filesystem_id': fs.filesystem_id,
                            'size_gb': round(size_gb, 2),
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                
                # Detector 2: No lifecycle policy (EFS without IA transition)
                # CLO-516: AWS returns one dict per rule, e.g.
                # [{'TransitionToIA': 'AFTER_30_DAYS'}, {'TransitionToPrimaryStorageClass':
                # 'AFTER_1_ACCESS'}]. The old test looked for the KEY name inside the
                # VALUE ('TransitionToIA' in 'AFTER_30_DAYS'), which is always False,
                # so every file system of 1 GB or more fired, IA policy or not.
                # None means the configuration could not be read: MISSING (the
                # provider noted it), not "no policy".
                lifecycle_policies = getattr(fs, 'lifecycle_policies', None)
                if lifecycle_policies is None:
                    continue
                has_ia_transition = any(
                    # TransitionToArchive tiers cold data too; a
                    # TransitionToPrimaryStorageClass rule alone moves nothing.
                    isinstance(p, dict) and (p.get('TransitionToIA') or p.get('TransitionToArchive'))
                    for p in lifecycle_policies
                )

                if not has_ia_transition and size_gb >= 1.0:
                    # EFS Standard = $0.30/GB/month, IA = $0.025/GB/month
                    # Typical IA-eligible data: ~80% of files older than 30 days
                    ia_eligible_pct = 0.80
                    standard_cost = size_gb * 0.30
                    ia_cost = size_gb * ia_eligible_pct * 0.025 + size_gb * (1 - ia_eligible_pct) * 0.30
                    estimated_savings = standard_cost - ia_cost
                    
                    if estimated_savings >= settings.min_waste_threshold_usd:
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=fs.filesystem_id,
                            resource_type=ResourceType.EFS_FILESYSTEM,
                            waste_type=WasteType.NO_LIFECYCLE_EFS,
                            title="EFS Without Lifecycle Policy",
                            description=(
                                f"EFS '{fs.name or fs.filesystem_id}' ({size_gb:.1f}GB) has no lifecycle policy. "
                                f"Enabling Infrequent Access tiering could save ~${estimated_savings:.2f}/month."
                            ),
                            monthly_savings=estimated_savings,
                            confidence=ConfidenceLevel.MEDIUM,
                            action="Enable lifecycle policy to transition infrequently accessed files to IA storage.",
                            action_command=(
                                f"aws efs put-lifecycle-configuration --file-system-id {fs.filesystem_id} "
                                f"--lifecycle-policies TransitionToIA=AFTER_30_DAYS TransitionToPrimaryStorageClass=AFTER_1_ACCESS"
                            ),
                            explanation={
                                'detection': f'EFS filesystem has no lifecycle policy configured. All {size_gb:.1f} GB stored at Standard tier pricing.',
                                'threshold': 'EFS filesystems ≥ 1 GB without lifecycle policy',
                                'pricing': (
                                    f'Standard: {size_gb:.1f} GB × $0.30/GB = ${standard_cost:.2f}/month. '
                                    f'With IA (~80% eligible): ${ia_cost:.2f}/month. '
                                    f'Savings: ${estimated_savings:.2f}/month.'
                                ),
                                'why_waste': (
                                    'EFS Standard costs $0.30/GB/month vs $0.025/GB/month for Infrequent Access. '
                                    'Without a lifecycle policy, all data stays in Standard regardless of access patterns.'
                                ),
                                'risk': (
                                    'IA has a per-access read charge of $0.01/GB. '
                                    'Files accessed frequently will cost more in IA. '
                                    'Use TransitionToPrimaryStorageClass=AFTER_1_ACCESS for automatic promotion.'
                                ),
                            },
                            metadata={
                                'filesystem_id': fs.filesystem_id,
                                'size_gb': round(size_gb, 2),
                                'standard_cost': round(standard_cost, 2),
                                'estimated_ia_cost': round(ia_cost, 2),
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
            
            return waste_items
            
        except Exception as e:
            logger.debug(f"EFS detection error: {e}")
            return waste_items
    async def _detect_ecr_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """
        Detect ECR-related waste using DataProvider.
        
        Detectors:
        1. ECR_NO_LIFECYCLE_POLICY - Repositories without lifecycle policies
        2. OLD_ECR_IMAGES - Repositories with old/untagged images (>0.5GB)
        """
        waste_items = []
        
        try:
            # Get ECR repositories from data provider
            repositories = await data_provider.get_ecr_repositories()
            logger.info(f"ECR waste detection: Checking {len(repositories)} repositories")
            
            for repo in repositories:
                logger.debug(f"ECR repo '{repo.repository_name}': images={repo.image_count}, "
                           f"size_gb={repo.total_size_gb:.2f}, lifecycle={repo.has_lifecycle_policy}, "
                           f"untagged={repo.untagged_image_count}, old={repo.old_image_count}")
                
                # Detector 1: No lifecycle policy (with images). CLO-551:
                # None means the lifecycle-policy read is MISSING (failed
                # with an error other than LifecyclePolicyNotFoundException,
                # or an export that cannot tell such a failure from "no
                # policy"): withheld and noted, never "no policy".
                if repo.has_lifecycle_policy is None:
                    if repo.image_count > 0:
                        note = getattr(data_provider, '_note_idle_verdict_missing', None)
                        if callable(note):
                            note('ecr lifecycle', repo.repository_name, 'lifecycle policy not read',
                                 verdict='no-lifecycle-policy',
                                 evidence='lifecycle policies (ecr:GetLifecyclePolicy)')
                elif not repo.has_lifecycle_policy and repo.image_count > 0:
                    # CLO-514: the saving used to be a flat 50% of the
                    # repository's storage, and the old/untagged checks below
                    # counted the same images again. A lifecycle policy
                    # removes the old and untagged images; their measured size
                    # is the saving, and when Detector 2 or 3 reports them on
                    # this repository, the dollars stay there and this
                    # finding shows $0 (ECR_NO_LIFECYCLE_POLICY is a
                    # governance type, so it is still reported).
                    claimable_gb = (repo.untagged_images_size_gb or 0) + (repo.old_images_size_gb or 0)
                    claimed_elsewhere = claimable_gb > 0.5 or (
                        (repo.untagged_image_count or 0) > 0
                        and (repo.untagged_images_size_gb or 0) > 0.1
                    )
                    estimated_savings = 0.0 if claimed_elsewhere else claimable_gb * 0.10
                    if claimed_elsewhere:
                        savings_note = (
                            f'{claimable_gb:.2f} GB of old/untagged images × $0.10/GB-month = '
                            f'${claimable_gb * 0.10:.2f}/month, counted once in this repository\'s '
                            f'old/untagged image finding; $0 here.'
                        )
                    else:
                        savings_note = (
                            f'{claimable_gb:.2f} GB of old/untagged images × $0.10/GB-month = '
                            f'${estimated_savings:.2f}/month today; the policy stops new ones accumulating.'
                        )

                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=repo.repository_name,
                        resource_type=ResourceType.ECR_REPOSITORY,
                        waste_type=WasteType.ECR_NO_LIFECYCLE_POLICY,
                        title="ECR Repository Without Lifecycle Policy",
                        description=f"Repository '{repo.repository_name}' ({repo.image_count} images, {repo.total_size_gb:.2f}GB) has no lifecycle policy.",
                        monthly_savings=estimated_savings,
                        confidence=ConfidenceLevel.MEDIUM,
                        action="Add a lifecycle policy to automatically clean old images.",
                        action_command=f"aws ecr put-lifecycle-policy --repository-name {repo.repository_name} --lifecycle-policy-text '{{\"rules\":[{{\"rulePriority\":1,\"description\":\"Keep only last 10 images\",\"selection\":{{\"tagStatus\":\"any\",\"countType\":\"imageCountMoreThan\",\"countNumber\":10}},\"action\":{{\"type\":\"expire\"}}}}]}}'",
                        explanation={
                            'detection': f'Repository has {repo.image_count} images ({repo.total_size_gb:.2f} GB) with no lifecycle policy',
                            'threshold': 'Any repository with images and no lifecycle policy',
                            'pricing': savings_note,
                            'why_waste': f'Without a lifecycle policy, old and unused container images accumulate indefinitely, consuming ECR storage.',
                            'risk': 'Review how many image versions your deployment process needs before setting the policy. Keep at least the last N images needed for rollback.',
                        },
                        metadata={
                            'repo_name': repo.repository_name,
                            'image_count': repo.image_count,
                            'total_size_gb': round(repo.total_size_gb, 2),
                            'old_untagged_size_gb': round(claimable_gb, 2),
                            'savings_counted_elsewhere': claimed_elsewhere,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                
                # Detector 2: Old/untagged images
                total_waste_gb = (repo.untagged_images_size_gb or 0) + (repo.old_images_size_gb or 0)
                
                if total_waste_gb > 0.5:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=repo.repository_name,
                        resource_type=ResourceType.ECR_REPOSITORY,
                        waste_type=WasteType.OLD_ECR_IMAGES,
                        title="Old/Untagged ECR Images",
                        description=f"Repository '{repo.repository_name}' has {repo.untagged_image_count or 0} untagged and {repo.old_image_count or 0} old images ({total_waste_gb:.1f}GB).",
                        monthly_savings=total_waste_gb * 0.10,
                        confidence=ConfidenceLevel.MEDIUM,
                        action="Delete old images or set up lifecycle policy.",
                        explanation={
                            'detection': f'{repo.untagged_image_count or 0} untagged and {repo.old_image_count or 0} old images totaling {total_waste_gb:.1f} GB',
                            'threshold': '> 0.5 GB of old/untagged images',
                            'pricing': f'{total_waste_gb:.1f} GB × $0.10/GB/month = ${total_waste_gb * 0.10:.2f}/month',
                            'why_waste': f'Untagged images are typically superseded builds. Old images beyond your rollback window serve no purpose.',
                            'risk': 'Verify no running tasks reference these images. Keep the latest tagged images needed for production and rollback.',
                        },
                        metadata={
                            'untagged_count': repo.untagged_image_count or 0,
                            'old_count': repo.old_image_count or 0,
                            'waste_size_gb': round(total_waste_gb, 2),
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                
                # Detector 3: Untagged ECR images (specifically targets untagged image waste)
                untagged_count = repo.untagged_image_count or 0
                untagged_size_gb = repo.untagged_images_size_gb or 0
                
                if untagged_count > 0 and untagged_size_gb > 0.1 and total_waste_gb <= 0.5:
                    # Only fire when OLD_ECR_IMAGES didn't fire (dedup)
                    monthly_cost = untagged_size_gb * 0.10
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=repo.repository_name,
                        resource_type=ResourceType.ECR_REPOSITORY,
                        waste_type=WasteType.UNTAGGED_ECR_IMAGES,
                        title="Untagged ECR Images",
                        description=(
                            f"Repository '{repo.repository_name}' has {untagged_count} untagged images "
                            f"({untagged_size_gb:.2f}GB). These are typically orphaned build artifacts."
                        ),
                        monthly_savings=monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete untagged images or add a lifecycle policy to expire them automatically.",
                        action_command=(
                            f"aws ecr batch-delete-image --repository-name {repo.repository_name} "
                            f"--image-ids \"$(aws ecr list-images --repository-name {repo.repository_name} "
                            f"--filter tagStatus=UNTAGGED --query 'imageIds[*]' --output json)\""
                        ),
                        explanation={
                            'detection': f'{untagged_count} images without any tag in repository \'{repo.repository_name}\' ({untagged_size_gb:.2f} GB)',
                            'threshold': '> 0 untagged images with > 0.1 GB total size',
                            'pricing': f'{untagged_size_gb:.2f} GB × $0.10/GB/month = ${monthly_cost:.2f}/month',
                            'why_waste': (
                                'Untagged images are created when a new image is pushed with the same tag, '
                                'replacing the old manifest. The old image loses its tag but remains stored. '
                                'These orphaned layers accumulate and increase storage costs.'
                            ),
                            'risk': (
                                'Untagged images cannot be pulled by tag. They are only referenced by digest. '
                                'Verify no Fargate tasks or Kubernetes pods reference images by SHA digest before deleting.'
                            ),
                        },
                        metadata={
                            'repo_name': repo.repository_name,
                            'untagged_count': untagged_count,
                            'untagged_size_gb': round(untagged_size_gb, 2),
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
            
            logger.info(f"ECR waste detection: Found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"ECR detection error: {e}", exc_info=True)
            return waste_items
