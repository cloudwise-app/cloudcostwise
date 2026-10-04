"""
Security Posture Detectors

Detects security misconfigurations across AWS resources:
- Unencrypted resources (EBS, RDS, EFS, OpenSearch, DocumentDB, S3)
- Missing deletion protection (RDS, DynamoDB)
- Publicly accessible databases (RDS)
- Resources without backup coverage

These are advisory-only findings with $0 savings — they surface compliance
and reliability risks rather than cost waste.
"""

import logging
import uuid
from typing import Dict, List, TYPE_CHECKING

from cloudwise_scan_core.models import (
    WasteItem,
    WasteType,
    ResourceType,
    ConfidenceLevel,
    WasteDetectionSettings,
)

if TYPE_CHECKING:
    from cloudwise_scan_core.data_providers import WasteDataProvider

logger = logging.getLogger(__name__)

# CLO-531: engines whose deletion protection lives on the DB cluster, not the
# instance, although DescribeDBInstances lists their members.
_CLUSTER_PROTECTED_ENGINES = frozenset({'docdb', 'neptune'})
# CLO-532 item 1: Aurora members too ("aurora", "aurora-mysql",
# "aurora-postgresql"). ModifyDBInstance's DeletionProtection "doesn't apply
# to Amazon Aurora DB instances"; Aurora sets it with ModifyDBCluster.
_CLUSTER_PROTECTED_ENGINE_PREFIXES = ('aurora',)


def instance_flag_is_deletion_control(engine: str) -> bool:
    """CLO-531 gate: whether a DB instance's own DeletionProtection flag is
    the control rds_no_deletion_protection judges. False for DocumentDB,
    Neptune and Aurora (aurora-*) members, whose protection is set on the
    cluster (ModifyDBCluster). The contract replay lifts this gate by name
    (tests/recordings/VERDICT_CHANGES.json)."""
    key = (engine or '').strip().lower()
    return key not in _CLUSTER_PROTECTED_ENGINES and not key.startswith(_CLUSTER_PROTECTED_ENGINE_PREFIXES)


class SecurityPostureDetectorsMixin:
    """Mixin providing security posture detectors."""

    async def _detect_security_posture_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect security posture issues across all resource types.

        All findings are advisory ($0 savings) and bypass the
        min_waste_threshold_usd filter via GOVERNANCE_WASTE_TYPES.
        """
        waste_items: List[WasteItem] = []

        try:
            # ── Encryption detectors ──
            await self._detect_unencrypted_ebs(data_provider, waste_items)
            await self._detect_unencrypted_rds(data_provider, waste_items)
            await self._detect_unencrypted_efs(data_provider, waste_items)
            await self._detect_opensearch_no_encryption(data_provider, waste_items)
            await self._detect_unencrypted_documentdb(data_provider, waste_items)
            await self._detect_s3_no_encryption(data_provider, waste_items)

            # ── Deletion protection detectors ──
            await self._detect_rds_no_deletion_protection(data_provider, waste_items)
            await self._detect_dynamodb_no_deletion_protection(data_provider, waste_items)

            # ── Public access detectors ──
            await self._detect_rds_publicly_accessible(data_provider, waste_items)

            # ── Backup coverage detector ──
            await self._detect_resources_without_backup(data_provider, waste_items)

        except Exception as e:
            logger.error(f"Error in security posture detection: {e}")
            raise

        return waste_items

    # ─── Encryption Detectors ─────────────────────────────────────────────

    async def _detect_unencrypted_ebs(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """Flag EBS volumes where encrypted == False."""
        try:
            volumes = await data_provider.get_ebs_volumes()
            for vol in volumes:
                if not vol.encrypted and vol.state == 'in-use':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=vol.volume_id,
                        resource_type=ResourceType.EBS_VOLUME,
                        waste_type=WasteType.UNENCRYPTED_EBS_VOLUME,
                        title="Unencrypted EBS Volume",
                        description=(
                            f"EBS volume '{vol.volume_id}' ({vol.volume_type}, "
                            f"{vol.size_gb} GB) is not encrypted at rest."
                        ),
                        monthly_savings=0.0,
                        confidence=ConfidenceLevel.HIGH,
                        action="Create an encrypted snapshot, copy it, and replace the volume.",
                        action_command=f"aws ec2 create-snapshot --volume-id {vol.volume_id} --description 'Encrypt migration'",
                        explanation={
                            'detection': f'EBS volume {vol.volume_id} has encrypted=False.',
                            'threshold': 'All EBS volumes should be encrypted at rest.',
                            'compliance': 'SOC 2 CC6.1, CC6.7 — data classification and protection.',
                            'why_flagged': 'Unencrypted volumes expose data if disks are physically compromised or snapshots are shared.',
                            'risk': 'Encryption migration requires snapshot→copy→swap and brief downtime.',
                        },
                        metadata={
                            'volume_type': vol.volume_type,
                            'size_gb': vol.size_gb,
                            'state': vol.state,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.warning(f"Error checking EBS encryption: {e}")

    async def _detect_unencrypted_rds(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """Flag RDS instances where storage_encrypted == False."""
        try:
            instances = await data_provider.get_rds_instances()
            for inst in instances:
                if not inst.storage_encrypted and inst.status == 'available':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=inst.db_instance_id,
                        resource_type=ResourceType.RDS_INSTANCE,
                        waste_type=WasteType.UNENCRYPTED_RDS_INSTANCE,
                        title="Unencrypted RDS Instance",
                        description=(
                            f"RDS instance '{inst.db_instance_id}' ({inst.engine} "
                            f"{inst.db_instance_class}) does not have storage encryption enabled."
                        ),
                        monthly_savings=0.0,
                        confidence=ConfidenceLevel.HIGH,
                        action="Create encrypted snapshot, restore with encryption, swap DNS endpoint.",
                        explanation={
                            'detection': f'RDS instance {inst.db_instance_id} has StorageEncrypted=False.',
                            'threshold': 'All RDS instances should have encryption at rest enabled.',
                            'compliance': 'SOC 2 CC6.1, HIPAA §164.312(a)(2)(iv) — encryption of data at rest.',
                            'why_flagged': 'Unencrypted database storage exposes sensitive data if underlying disks are compromised.',
                            'risk': 'Encryption cannot be enabled in-place. Requires snapshot→restore with encryption→DNS swap.',
                        },
                        metadata={
                            'engine': inst.engine,
                            'instance_class': inst.db_instance_class,
                            'multi_az': inst.multi_az,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.warning(f"Error checking RDS encryption: {e}")

    async def _detect_unencrypted_efs(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """Flag EFS filesystems where encrypted == False."""
        try:
            filesystems = await data_provider.get_efs_filesystems()
            for fs in filesystems:
                if not fs.encrypted and fs.lifecycle_state == 'available':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=fs.filesystem_id,
                        resource_type=ResourceType.EFS_FILESYSTEM,
                        waste_type=WasteType.UNENCRYPTED_EFS_FILESYSTEM,
                        title="Unencrypted EFS Filesystem",
                        description=(
                            f"EFS filesystem '{fs.name or fs.filesystem_id}' "
                            f"is not encrypted at rest."
                        ),
                        monthly_savings=0.0,
                        confidence=ConfidenceLevel.HIGH,
                        action="Create a new encrypted EFS filesystem and migrate data with DataSync.",
                        explanation={
                            'detection': f'EFS filesystem {fs.filesystem_id} has encrypted=False.',
                            'threshold': 'All EFS filesystems should be encrypted at rest.',
                            'compliance': 'SOC 2 CC6.1 — data protection controls.',
                            'why_flagged': 'Unencrypted filesystems expose data at the storage layer.',
                            'risk': 'EFS encryption is set at creation time. Migration requires DataSync or rsync to a new filesystem.',
                        },
                        metadata={
                            'name': fs.name,
                            'performance_mode': fs.performance_mode,
                            'size_bytes': fs.size_bytes,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.warning(f"Error checking EFS encryption: {e}")

    async def _detect_opensearch_no_encryption(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """Flag OpenSearch domains where encrypted == False."""
        try:
            domains = await data_provider.get_opensearch_domains()
            for domain in domains:
                if not domain.encrypted:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=domain.domain_name,
                        resource_type=ResourceType.OPENSEARCH_DOMAIN,
                        waste_type=WasteType.OPENSEARCH_NO_ENCRYPTION_AT_REST,
                        title="OpenSearch Domain Without Encryption at Rest",
                        description=(
                            f"OpenSearch domain '{domain.domain_name}' does not "
                            f"have encryption at rest enabled."
                        ),
                        monthly_savings=0.0,
                        confidence=ConfidenceLevel.HIGH,
                        action="Enable encryption at rest (triggers blue/green deployment).",
                        action_command=(
                            f"aws opensearch update-domain-config "
                            f"--domain-name {domain.domain_name} "
                            f"--encrypt-at-rest-options Enabled=true"
                        ),
                        explanation={
                            'detection': f'OpenSearch domain {domain.domain_name} has EncryptionAtRestOptions.Enabled=False.',
                            'threshold': 'All OpenSearch domains should have encryption at rest.',
                            'compliance': 'SOC 2 CC6.1 — data protection at the storage layer.',
                            'why_flagged': 'Unencrypted search indices may contain sensitive data.',
                            'risk': 'Enabling encryption triggers a blue/green deployment with brief unavailability.',
                        },
                        metadata={
                            'instance_type': domain.instance_type,
                            'instance_count': domain.instance_count,
                            'engine_version': domain.engine_version,
                            'domain_name': domain.domain_name,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.warning(f"Error checking OpenSearch encryption: {e}")

    async def _detect_unencrypted_documentdb(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """Flag DocumentDB clusters where storage_encrypted == False."""
        try:
            clusters = await data_provider.get_documentdb_clusters()
            for cluster in clusters:
                if not cluster.storage_encrypted and cluster.status == 'available':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=cluster.cluster_identifier,
                        resource_type=ResourceType.DOCUMENTDB_CLUSTER,
                        waste_type=WasteType.UNENCRYPTED_DOCUMENTDB_CLUSTER,
                        title="Unencrypted DocumentDB Cluster",
                        description=(
                            f"DocumentDB cluster '{cluster.cluster_identifier}' "
                            f"does not have storage encryption enabled."
                        ),
                        monthly_savings=0.0,
                        confidence=ConfidenceLevel.HIGH,
                        action="Create encrypted snapshot, restore with encryption enabled.",
                        explanation={
                            'detection': f'DocumentDB cluster {cluster.cluster_identifier} has StorageEncrypted=False.',
                            'threshold': 'All DocumentDB clusters should have encryption at rest.',
                            'compliance': 'SOC 2 CC6.1 — data protection controls.',
                            'why_flagged': 'Unencrypted document database storage exposes data at the storage layer.',
                            'risk': 'DocumentDB encryption must be set at creation. Requires snapshot→restore with encryption.',
                        },
                        metadata={
                            'cluster_name': cluster.cluster_identifier,
                            'engine_version': cluster.engine_version,
                            'num_instances': cluster.num_instances,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.warning(f"Error checking DocumentDB encryption: {e}")

    async def _detect_s3_no_encryption(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """Flag S3 buckets without default encryption configured."""
        try:
            buckets = await data_provider.get_s3_buckets()
            for bucket in buckets:
                if not bucket.default_encryption_enabled:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=bucket.bucket_name,
                        resource_type=ResourceType.S3_BUCKET,
                        waste_type=WasteType.S3_NO_DEFAULT_ENCRYPTION,
                        title="S3 Bucket Without Default Encryption",
                        description=(
                            f"S3 bucket '{bucket.bucket_name}' does not have "
                            f"default encryption configured."
                        ),
                        monthly_savings=0.0,
                        confidence=ConfidenceLevel.MEDIUM,
                        action="Enable default SSE-S3 or SSE-KMS encryption.",
                        action_command=(
                            f"aws s3api put-bucket-encryption --bucket {bucket.bucket_name} "
                            f"--server-side-encryption-configuration "
                            f"'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'"
                        ),
                        explanation={
                            'detection': f'S3 bucket {bucket.bucket_name} has no default encryption configuration.',
                            'threshold': 'All S3 buckets should have default encryption enabled.',
                            'compliance': 'SOC 2 CC6.1, CC6.7 — data encryption at rest.',
                            'why_flagged': 'Objects uploaded without explicit encryption headers will be stored unencrypted.',
                            'risk': 'Low — enabling default encryption does not affect existing objects.',
                        },
                        metadata={
                            'bucket_name': bucket.bucket_name,
                            'total_size_bytes': bucket.total_size_bytes,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.warning(f"Error checking S3 encryption: {e}")

    # ─── Deletion Protection Detectors ────────────────────────────────────

    async def _detect_rds_no_deletion_protection(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """Flag RDS instances without deletion protection.

        CLO-531: DocumentDB and Neptune members are skipped. DescribeDBInstances
        returns them (both are reached through the RDS API), but their deletion
        protection is a cluster setting (ModifyDBCluster), so the instance flag
        is not the control and ``modify-db-instance --deletion-protection`` is
        the wrong fix. No cluster-level DocumentDB/Neptune deletion-protection
        check exists today; none is invented here.

        CLO-532 item 1: Aurora members (engine aurora*) are skipped for the
        same reason: ModifyDBInstance's DeletionProtection doesn't apply to
        Aurora DB instances; the cluster carries it.
        """
        try:
            instances = await data_provider.get_rds_instances()
            for inst in instances:
                if not instance_flag_is_deletion_control(inst.engine):
                    continue
                if not inst.deletion_protection and inst.status == 'available':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=inst.db_instance_id,
                        resource_type=ResourceType.RDS_INSTANCE,
                        waste_type=WasteType.RDS_NO_DELETION_PROTECTION,
                        title="RDS Without Deletion Protection",
                        description=(
                            f"RDS instance '{inst.db_instance_id}' ({inst.engine}) "
                            f"does not have deletion protection enabled."
                        ),
                        monthly_savings=0.0,
                        confidence=ConfidenceLevel.HIGH,
                        action="Enable deletion protection to prevent accidental database deletion.",
                        action_command=(
                            f"aws rds modify-db-instance "
                            f"--db-instance-identifier {inst.db_instance_id} "
                            f"--deletion-protection --apply-immediately"
                        ),
                        explanation={
                            'detection': f'RDS instance {inst.db_instance_id} has DeletionProtection=False.',
                            'threshold': 'All production RDS instances should have deletion protection enabled.',
                            'compliance': 'AWS Well-Architected REL09 — protect data with backups and deletion safeguards.',
                            'why_flagged': 'Without deletion protection, a single API call or console click can destroy the database.',
                            'risk': 'None — enabling deletion protection is non-destructive and immediate.',
                        },
                        metadata={
                            'engine': inst.engine,
                            'instance_class': inst.db_instance_class,
                            'multi_az': inst.multi_az,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.warning(f"Error checking RDS deletion protection: {e}")

    async def _detect_dynamodb_no_deletion_protection(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """Flag DynamoDB tables without deletion protection."""
        try:
            tables = await data_provider.get_dynamodb_tables()
            for table in tables:
                if not table.deletion_protection and table.status == 'ACTIVE':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=table.table_name,
                        resource_type=ResourceType.DYNAMODB_TABLE,
                        waste_type=WasteType.DYNAMODB_NO_DELETION_PROTECTION,
                        title="DynamoDB Without Deletion Protection",
                        description=(
                            f"DynamoDB table '{table.table_name}' does not have "
                            f"deletion protection enabled."
                        ),
                        monthly_savings=0.0,
                        confidence=ConfidenceLevel.HIGH,
                        action="Enable deletion protection to prevent accidental table deletion.",
                        action_command=(
                            f"aws dynamodb update-table "
                            f"--table-name {table.table_name} "
                            f"--deletion-protection-enabled"
                        ),
                        explanation={
                            'detection': f'DynamoDB table {table.table_name} has DeletionProtectionEnabled=False.',
                            'threshold': 'All production DynamoDB tables should have deletion protection.',
                            'compliance': 'AWS Well-Architected REL09 — protect data with deletion safeguards.',
                            'why_flagged': 'A single delete-table call can permanently destroy the table and all data.',
                            'risk': 'None — enabling deletion protection is non-destructive.',
                        },
                        metadata={
                            'table_name': table.table_name,
                            'billing_mode': table.billing_mode,
                            'item_count': table.item_count,
                            'size_bytes': table.size_bytes,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.warning(f"Error checking DynamoDB deletion protection: {e}")

    # ─── Public Access Detectors ──────────────────────────────────────────

    async def _detect_rds_publicly_accessible(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """Flag RDS instances with PubliclyAccessible=True."""
        try:
            instances = await data_provider.get_rds_instances()
            for inst in instances:
                if inst.publicly_accessible and inst.status == 'available':
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=inst.db_instance_id,
                        resource_type=ResourceType.RDS_INSTANCE,
                        waste_type=WasteType.RDS_PUBLICLY_ACCESSIBLE,
                        title="RDS Instance Publicly Accessible",
                        description=(
                            f"RDS instance '{inst.db_instance_id}' ({inst.engine}) "
                            f"is configured as publicly accessible."
                        ),
                        monthly_savings=0.0,
                        confidence=ConfidenceLevel.HIGH,
                        action="Move database to private subnets and use VPN/bastion for access.",
                        explanation={
                            'detection': f'RDS instance {inst.db_instance_id} has PubliclyAccessible=True.',
                            'threshold': 'Databases should not be publicly accessible.',
                            'compliance': 'SOC 2 CC6.1, CC6.6 — restrict network access to authorized users.',
                            'why_flagged': 'Public accessibility exposes the database to the internet, increasing attack surface.',
                            'risk': 'Medium — disabling public access may break applications that connect via the public endpoint.',
                        },
                        metadata={
                            'engine': inst.engine,
                            'instance_class': inst.db_instance_class,
                            'endpoint': inst.endpoint,
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.warning(f"Error checking RDS public access: {e}")

    # ─── Backup Coverage Detector ─────────────────────────────────────────

    async def _detect_resources_without_backup(
        self,
        data_provider: "WasteDataProvider",
        waste_items: List[WasteItem],
    ) -> None:
        """
        Cross-reference RDS and DynamoDB resources against every native
        backup mechanism to identify resources with no backup coverage.

        CLO-384 (METHOD.md pinned decision 1): AWS Backup recovery points
        were the only signal, matched by ARN *substring* — a false positive
        both because most tables use DynamoDB PITR instead of AWS Backup,
        and because a substring match treats an ARN prefix collision (e.g.
        table "orders" matching a recovery point for "orders-archive") as
        coverage. Coverage now also counts:
          - DynamoDB point-in-time recovery (PITR) enabled;
          - an AWS Backup recovery point for the resource's EXACT ARN;
          - RDS automated backups (BackupRetentionPeriod > 0).
        A single on-demand backup is not coverage on its own — an on-demand
        AWS Backup recovery point has no `backup_plan_id`, so it only
        counts when it's the exact-ARN match above (a real, if manual,
        backup of THIS resource), never as a stand-in for automation.
        """
        try:
            # Recovery points keyed by the EXACT resource ARN they cover —
            # never a substring match, which is what let an ARN-prefix
            # collision pass as coverage.
            recovery_points = await data_provider.get_backup_recovery_points()
            recovery_points_by_arn: Dict[str, List] = {}
            for rp in recovery_points:
                recovery_points_by_arn.setdefault(rp.resource_arn, []).append(rp)

            # CLO-456: the SAME unreadable-signal bug, one permission over.
            # `get_backup_recovery_points` returns [] when
            # backup:ListRecoveryPointsByBackupVault is denied (online.py:4293),
            # which is indistinguishable from "this account has no recovery
            # points" — so every resource looks uncovered and every finding
            # below rests on a signal we never read. A customer account has
            # exactly that denial today; it holds no DynamoDB tables, so the
            # mechanism is live but currently invisible, which is the worse
            # kind of live.
            #
            # No coverage signal, no coverage claim: skip the whole detector
            # rather than emit assertions built on an empty list. The denial
            # reaches the account row through `permission_errors` either way.
            backup_signal_unreadable = any(
                entry.get('permission') == 'backup:ListRecoveryPointsByBackupVault'
                for entry in getattr(data_provider, 'permission_errors', [])
            )
            if backup_signal_unreadable:
                logger.warning(
                    "Backup coverage not evaluated: backup:ListRecoveryPointsByBackupVault "
                    "was denied, so AWS Backup coverage could not be read for ANY resource. "
                    "Findings for resource_without_backup_coverage are SUPPRESSED rather than "
                    "reported as uncovered (CLO-456). Grant the permission to restore them."
                )
                return waste_items

            # CLO-551: the same rule when the recovery-point list is
            # incomplete for a reason other than that denial: a vault list
            # or a vault's recovery-point read failed (online), or the
            # Air-Gapped export failed it or cannot tell (an old export wrote
            # an empty list for a failed read). A resource whose recovery
            # points sit in an unread vault would read as "not backed up".
            unread_fn = getattr(data_provider, 'backup_recovery_points_unread', None)
            unread = unread_fn() if callable(unread_fn) else None
            if isinstance(unread, str):
                logger.warning(
                    "Backup coverage not evaluated: the AWS Backup recovery-point list is "
                    "incomplete (%s). resource_without_backup_coverage findings are withheld "
                    "(MISSING, not uncovered; CLO-551).", unread,
                )
                note = getattr(data_provider, '_note_idle_verdict_missing', None)
                if callable(note):
                    note('backup coverage', 'all resources', unread,
                         verdict='no-backup-coverage',
                         evidence='AWS Backup recovery-point listings')
                return waste_items

            # Table names whose PITR could not be read; reported once, below.
            pitr_unreadable: List[str] = []

            # Check RDS instances
            rds_instances = await data_provider.get_rds_instances()
            for inst in rds_instances:
                if inst.status != 'available':
                    continue

                has_backup_plan_coverage = bool(recovery_points_by_arn.get(inst.db_instance_arn))
                has_automated_backups = inst.backup_retention_period > 0

                if has_backup_plan_coverage or has_automated_backups:
                    continue

                waste_items.append(WasteItem(
                    id=str(uuid.uuid4()),
                    resource_id=inst.db_instance_id,
                    resource_type=ResourceType.RDS_INSTANCE,
                    waste_type=WasteType.RESOURCE_WITHOUT_BACKUP_COVERAGE,
                    title="RDS Instance Without Backup Coverage",
                    description=(
                        f"RDS instance '{inst.db_instance_id}' ({inst.engine}) has no "
                        f"AWS Backup recovery points and automated backups are disabled "
                        f"(BackupRetentionPeriod=0)."
                    ),
                    monthly_savings=0.0,
                    confidence=ConfidenceLevel.MEDIUM,
                    action="Enable automated backups or add this instance to an AWS Backup plan.",
                    explanation={
                        'detection': f'No AWS Backup recovery point for {inst.db_instance_id} and BackupRetentionPeriod=0.',
                        'threshold': 'All production databases should have automated backups or AWS Backup coverage.',
                        'compliance': 'AWS Well-Architected REL09 — back up data automatically.',
                        'why_flagged': 'This instance has neither RDS automated backups nor AWS Backup coverage.',
                        'risk': 'Low — verify no other backup strategy (a third-party tool, a snapshot Lambda) covers this instance.',
                    },
                    metadata={
                        'engine': inst.engine,
                        'instance_class': inst.db_instance_class,
                        'backup_retention_period': inst.backup_retention_period,
                        'detection_mode': data_provider.provider_type,
                    },
                ))

            # Check DynamoDB tables
            dynamodb_tables = await data_provider.get_dynamodb_tables()
            for table in dynamodb_tables:
                if table.status != 'ACTIVE':
                    continue

                if table.point_in_time_recovery_enabled:
                    continue

                has_backup_plan_coverage = bool(recovery_points_by_arn.get(table.table_arn))
                if has_backup_plan_coverage:
                    continue

                # CLO-456: PITR status is None when
                # dynamodb:DescribeContinuousBackups was DENIED, which is not
                # the same as PITR being off — and treating it as off is a
                # measured false-positive engine, not a theoretical one. On
                # 2026-09-20, 29 of the 68 production findings of this waste
                # type were tables whose PITR was ENABLED all along
                # (user, API-key and audit-log tables
                # among them), which is precision 0.60
                # against a 0.80 gate and is very likely what CLO-366 measured
                # as 0.40.
                #
                # LOW confidence was the previous answer and it was not enough:
                # the finding still asserted, in its title and its
                # `why_flagged`, that the table is unprotected. A finding is a
                # claim that a resource exhibits this waste type (CONTEXT.md),
                # so when the signal cannot be read there is no finding to
                # make. The denial is not lost — `_record_permission_error`
                # already carries `dynamodb:DescribeContinuousBackups` to the
                # account row as `permission_missing` (CLO-368), which is where
                # "we could not check" belongs: an account-level capability
                # gap, not a per-table waste claim.
                #
                # Whether an unverifiable finding should be shown as advisory
                # instead is CLO-432's product decision, not this one's.
                if table.point_in_time_recovery_enabled is None:
                    pitr_unreadable.append(table.table_name)
                    continue

                waste_items.append(WasteItem(
                    id=str(uuid.uuid4()),
                    resource_id=table.table_name,
                    resource_type=ResourceType.DYNAMODB_TABLE,
                    waste_type=WasteType.RESOURCE_WITHOUT_BACKUP_COVERAGE,
                    title="DynamoDB Table Without Backup Coverage",
                    description=(
                        f"DynamoDB table '{table.table_name}' has no AWS Backup recovery "
                        f"points, and point-in-time recovery is disabled."
                    ),
                    monthly_savings=0.0,
                    confidence=ConfidenceLevel.MEDIUM,
                    action="Enable point-in-time recovery or add this table to an AWS Backup plan.",
                    explanation={
                        'detection': (
                            f'No AWS Backup recovery point for {table.table_name}; '
                            f'PITR disabled.'
                        ),
                        'threshold': 'All production DynamoDB tables should have PITR or AWS Backup coverage.',
                        'compliance': 'AWS Well-Architected REL09 — back up data automatically.',
                        'why_flagged': 'This table has no automated backup coverage via PITR or AWS Backup.',
                        'risk': 'Low — verify no other backup strategy covers this table before acting.',
                    },
                    metadata={
                        'table_name': table.table_name,
                        'billing_mode': table.billing_mode,
                        'item_count': table.item_count,
                        'point_in_time_recovery_enabled': table.point_in_time_recovery_enabled,
                        'detection_mode': data_provider.provider_type,
                    },
                ))

            # Counted, not silent. Suppression that leaves no trace is the
            # silent zero this codebase keeps getting bitten by, so say how
            # many claims were withheld and why. WARNING, not INFO: the
            # production API Lambda drops every INFO line (CLO-326), and an
            # operator grepping for this must not find a false zero.
            if pitr_unreadable:
                logger.warning(
                    "Suppressed %d DynamoDB backup-coverage finding(s) because "
                    "dynamodb:DescribeContinuousBackups was denied, so PITR could not be "
                    "read and 'no backup coverage' could not be established (CLO-456). "
                    "Tables: %s. Grant the permission (role template 1.25.0) to restore them.",
                    len(pitr_unreadable),
                    ", ".join(sorted(pitr_unreadable)[:20]),
                )

        except Exception as e:
            logger.warning(f"Error checking backup coverage: {e}")
