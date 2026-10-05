"""
Offline Waste Data Provider

This implementation uses parsed JSON export files (from the CloudShell export script)
to provide resource data and metrics for waste detection. This enables waste detection
for users who haven't connected their AWS account.
"""

import json
import math
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from cloudwise_scan_core.cloudwatch_metrics_service import MSKMetrics, MQMetrics
from cloudwise_scan_core.cpu_sizing import (
    ec2_cpu_is_idle,
    has_min_coverage,
    is_as_old_as_window,
    summarize_ecs_utilization,
    summarize_hourly_cpu,
)
from cloudwise_scan_core.metric_window import drop_pre_creation_datapoints
from cloudwise_scan_core.data_providers.base import WasteDataProvider
from cloudwise_scan_core.data_providers.missing_data import MissingDataNotesMixin
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
    VPCEndpointData,
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
    CloudWatchDashboardData,
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


class ExportFileRemovedError(RuntimeError):
    """An export file that ``cloudwise-export.sh --anonymize`` removed because
    it could not anonymize it (manifest ``anonymize_removed``, export 1.21.0,
    CLO-554). Its data is MISSING, never an empty list: a reader that asks for
    it raises, so the detector's verdicts are withheld and the scan warns."""


class OfflineDataProvider(MissingDataNotesMixin, WasteDataProvider):
    """
    Offline data provider using parsed JSON export files.
    
    This provider reads resource data and CloudWatch metrics from JSON files
    that were exported using the CloudWise CloudShell export script.
    
    Expected file structure:
        export_data/
        ├── manifest.json
        ├── ec2_instances.json
        ├── ec2_cpu_metrics.json
        ├── ebs_volumes.json
        ├── ebs_snapshots.json
        ├── elastic_ips.json
        ├── rds_instances.json
        ├── rds_metrics.json
        ├── rds_snapshots.json
        ├── lambda_functions.json
        ├── lambda_metrics.json
        ├── nat_gateways.json
        ├── nat_metrics.json
        ├── s3_buckets.json
        ├── load_balancers.json
        ├── route53_zones.json
        ├── dynamodb_tables.json
        ├── elasticache_clusters.json
        ├── redshift_clusters.json
        ├── opensearch_domains.json
        ├── cloudwatch_log_groups.json
        ├── cloudwatch_log_group_activity.json  (script 1.16.0+, CLO-516)
        ├── ebs_iops_peaks.json                 (script 1.17.0+, CLO-516)
        ├── mq_broker_activity.json             (script 1.17.0+, CLO-516)
        ├── fsx_activity.json                   (script 1.18.0+, CLO-512)
        ├── efs_lifecycle_configs.json
        ├── kms_keys.json
        ├── secrets.json
        ├── sagemaker_notebooks.json
        ├── sagemaker_endpoints.json
        └── kinesis_streams.json
    """
    
    # CLO-488: a real AWS region code (or AZ name). Anything else in a
    # bucket's Location (e.g. a pre-1.13.0 --anonymize export hashed
    # "us-east-1" into "res_...") is an unknown region.
    _AWS_REGION_RE = re.compile(
        r'^(us|eu|ap|sa|ca|me|af|il|mx|cn)(-gov|-iso|-isob|-isoe|-isof)?-'
        r'(north|south|east|west|central|northeast|northwest|southeast|southwest)-[0-9]{1,2}$'
    )
    # What get_s3_buckets does with a bucket whose region is unknown.
    UNKNOWN_REGION_EVALUATE = "evaluate"  # single-region export: it is this region's
    UNKNOWN_REGION_NOTE = "note"          # multi-region, primary region: note it MISSING
    UNKNOWN_REGION_SKIP = "skip"          # multi-region, other regions: leave it to the primary

    def __init__(
        self,
        export_data: Dict[str, Any],
        region: str = "us-east-1",
        account_id: Optional[str] = None,
        unknown_region_buckets: str = UNKNOWN_REGION_NOTE,
        cur_data: Optional[List[Dict[str, Any]]] = None,
        legacy_failed_reads: bool = False,
        legacy_policy_reads: bool = False,
        removed_keys: Optional[List[str]] = None,
    ):
        """
        Initialize the offline data provider.
        
        Args:
            export_data: Dictionary containing all exported data files
                         Keys are file names (without .json), values are parsed content
            region: AWS region the data was exported from
            account_id: AWS account ID (from manifest)
            legacy_failed_reads: True for an export written before
                cloudwise-export.sh 1.19.0 (see :meth:`is_legacy_failed_read_export`),
                which wrote a valid empty-list document when some list or
                describe calls failed. Readers whose empty list would create
                a finding treat such an ambiguous empty as MISSING (CLO-550).
            legacy_policy_reads: True for an export written before
                cloudwise-export.sh 1.20.0 (see :meth:`is_legacy_policy_read_export`),
                which wrote the "no policy" answer when an S3 or ECR
                lifecycle-policy read failed. Such a "no policy" is MISSING
                (CLO-551).
            removed_keys: export file keys (``ecs_services``; a per-resource
                family ends in ``*``) that --anonymize removed because it
                could not anonymize them (:meth:`removed_keys_from_manifest`).
                Reading one through ``_get_data`` raises
                :class:`ExportFileRemovedError` (MISSING, CLO-554).
        """
        self._export_data = export_data
        self._legacy_failed_reads = legacy_failed_reads
        self._legacy_policy_reads = legacy_policy_reads
        self._removed_keys = {k for k in (removed_keys or []) if not k.endswith('*')}
        self._removed_prefixes = tuple(k[:-1] for k in (removed_keys or []) if k.endswith('*') and len(k) > 1)
        self._region = region
        self._account_id = account_id or "unknown"
        self._unknown_region_buckets = unknown_region_buckets
        # CLO-505: the uploaded CUR's commitment line items (RIFee,
        # SavingsPlanRecurringFee), read by the cur_unused_reservation and
        # cur_savings_plan_waste detectors. Nothing used to set this, so
        # both were dead on every real upload.
        self.cur_data: List[Dict[str, Any]] = list(cur_data or [])

        # CLO-485: "MISSING, not zero" notes for idle verdicts withheld
        # because the export lacks the metric (see missing_data). Folded into
        # WasteDetectionResult.warnings like the online provider's.
        self.data_warnings: List[str] = []
        
        # Check what data is available
        self._has_metrics = self._check_metrics_availability()
    
    @classmethod
    def from_directory(cls, export_dir: str) -> "OfflineDataProvider":
        """
        Create an OfflineDataProvider from a directory of JSON files.
        
        Args:
            export_dir: Path to the directory containing exported JSON files
            
        Returns:
            OfflineDataProvider instance
        """
        export_path = Path(export_dir)
        export_data = {}
        
        # Read manifest first
        manifest_path = export_path / "manifest.json"
        manifest = {}
        if manifest_path.exists():
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
        
        # Read all JSON files
        for json_file in export_path.glob("*.json"):
            file_name = json_file.stem  # filename without extension
            try:
                with open(json_file, 'r') as f:
                    export_data[file_name] = json.load(f)
            except json.JSONDecodeError as e:
                logger.warning(f"Error parsing {json_file}: {e}")
        
        # Read CloudWatch metrics subdirectory (per-resource metrics files)
        metrics_dir = export_path / "cloudwatch_metrics"
        if metrics_dir.exists() and metrics_dir.is_dir():
            for json_file in metrics_dir.glob("*.json"):
                file_name = json_file.stem  # e.g. sagemaker_invocations_my-endpoint
                try:
                    with open(json_file, 'r') as f:
                        export_data[file_name] = json.load(f)
                except json.JSONDecodeError as e:
                    logger.warning(f"Error parsing {json_file}: {e}")
        
        return cls(
            export_data=export_data,
            region=manifest.get('region', 'us-east-1'),
            account_id=manifest.get('account_id'),
            unknown_region_buckets=cls._unknown_region_policy(manifest),
            # CLO-551: no manifest is a legacy export too, as on the upload
            # path (an unknown export cannot vouch for its empty reads).
            legacy_failed_reads=cls.is_legacy_failed_read_export(manifest),
            legacy_policy_reads=cls.is_legacy_policy_read_export(manifest),
            removed_keys=cls.removed_keys_from_manifest(manifest),
        )

    # CLO-550: the manifest marker cloudwise-export.sh 1.19.0+ writes. Those
    # exports leave a 0-byte file (skipped by the upload parser: MISSING)
    # when a list or describe call fails; older exports wrote a valid
    # empty-list document instead, which cannot be told from a real empty.
    FAILED_READ_MARKER_KEY = 'failed_read'
    FAILED_READ_EMPTY_FILE = 'empty_file'

    @classmethod
    def is_legacy_failed_read_export(cls, manifest: Any) -> bool:
        """True unless the manifest says failed reads are 0-byte files."""
        return not (
            isinstance(manifest, dict)
            and manifest.get(cls.FAILED_READ_MARKER_KEY) == cls.FAILED_READ_EMPTY_FILE
        )

    # CLO-551: the manifest marker cloudwise-export.sh 1.20.0+ writes. Those
    # exports write null (not the "no policy" answer) when an S3 bucket
    # lifecycle or ECR lifecycle-policy read fails for any reason other than
    # AWS's own "no such policy" error. Older exports wrote "no policy" for
    # every failure, so there "no policy" is ambiguous. A marker, not the
    # version string: the version is not a format contract.
    FAILED_POLICY_READ_MARKER_KEY = 'failed_policy_read'
    FAILED_POLICY_READ_NULL = 'null_entry'

    @classmethod
    def is_legacy_policy_read_export(cls, manifest: Any) -> bool:
        """True unless the manifest says a failed policy read is null."""
        return not (
            isinstance(manifest, dict)
            and manifest.get(cls.FAILED_POLICY_READ_MARKER_KEY) == cls.FAILED_POLICY_READ_NULL
        )

    # CLO-554: export 1.21.0 --anonymize removes a file it cannot anonymize
    # and lists it here, relative to the export root ("us-east-1/ecs_services.json",
    # "us-east-1/sfn_detail_*.json" for a per-resource family).
    ANONYMIZE_REMOVED_KEY = 'anonymize_removed'

    @classmethod
    def removed_files_from_manifest(cls, manifest: Any) -> List[str]:
        """The manifest's ``anonymize_removed`` entries (strings only)."""
        if not isinstance(manifest, dict):
            return []
        entries = manifest.get(cls.ANONYMIZE_REMOVED_KEY)
        return [e for e in entries if isinstance(e, str) and e] if isinstance(entries, list) else []

    @classmethod
    def removed_keys_from_manifest(cls, manifest: Any, region: Optional[str] = None) -> List[str]:
        """Export data keys removed by --anonymize, for ``region`` when given:
        an entry under another region's directory is left out; an entry with
        no region directory applies to every region."""
        keys = []
        for entry in cls.removed_files_from_manifest(manifest):
            parts = [p for p in entry.split('/') if p]
            if not parts:
                continue
            if region and len(parts) > 1 and parts[0] != 'cloudwatch_metrics' and parts[0] != region:
                continue
            name = parts[-1]
            keys.append(name[:-5] if name.endswith('.json') else name)
        return keys

    def _is_removed(self, key: str) -> bool:
        removed = getattr(self, '_removed_keys', ())
        prefixes = getattr(self, '_removed_prefixes', ())
        return key in removed or (bool(prefixes) and key.startswith(prefixes))

    @classmethod
    def _unknown_region_policy(cls, manifest: Dict[str, Any]) -> str:
        """A single-region export holds one region's data, so a bucket of
        unknown region is judged there; a multi-region export can't place
        it, so it is noted as MISSING instead."""
        if isinstance(manifest, dict) and manifest.get('multi_region'):
            return cls.UNKNOWN_REGION_NOTE
        return cls.UNKNOWN_REGION_EVALUATE
    
    @classmethod
    def from_dict(cls, export_data: Dict[str, Any]) -> "OfflineDataProvider":
        """
        Create an OfflineDataProvider from a dictionary of parsed data.
        
        Args:
            export_data: Dictionary with file names as keys and parsed content as values
            
        Returns:
            OfflineDataProvider instance
        """
        manifest = export_data.get('manifest', {})
        return cls(
            export_data=export_data,
            region=manifest.get('region', 'us-east-1'),
            account_id=manifest.get('account_id'),
            unknown_region_buckets=cls._unknown_region_policy(manifest),
            # CLO-551: no manifest is a legacy export too, as on the upload
            # path (an unknown export cannot vouch for its empty reads).
            legacy_failed_reads=cls.is_legacy_failed_read_export(manifest),
            legacy_policy_reads=cls.is_legacy_policy_read_export(manifest),
            removed_keys=cls.removed_keys_from_manifest(manifest),
        )
    
    # The export script's default metric window (CLOUDWATCH_PERIOD in
    # frontend/public/scripts/cloudwise-export.sh). The upload path does not
    # hand the manifest to this provider, so this is the fallback when the
    # export data carries no manifest.
    DEFAULT_EXPORT_CLOUDWATCH_DAYS = 7

    def _export_cloudwatch_days(self) -> int:
        """Days of CloudWatch metrics the export collected: the manifest's
        ``cloudwatch_period_days`` when present, else the export default."""
        manifest = self._export_data.get('manifest')
        if isinstance(manifest, dict):
            try:
                days = int(manifest.get('cloudwatch_period_days') or 0)
            except (TypeError, ValueError):
                days = 0
            if days > 0:
                return days
        return self.DEFAULT_EXPORT_CLOUDWATCH_DAYS

    def _check_metrics_availability(self) -> bool:
        """Check if CloudWatch metrics are available in the export."""
        metric_files = [
            'ec2_cpu_metrics',
            'rds_metrics',
            'lambda_metrics',
            'lambda_invocation_metrics',
            'lambda_duration_metrics',
            'nat_metrics',
            'load_balancer_metrics',
        ]
        return any(f in self._export_data for f in metric_files)
    
    @property
    def provider_type(self) -> str:
        return "offline"
    
    @property
    def region(self) -> str:
        return self._region
    
    @property
    def supports_cloudwatch(self) -> bool:
        return self._has_metrics
    
    # Alias map: provider key → export filename key
    # The export script uses AWS CLI naming (e.g. elb_v2.json) while
    # provider methods use logical names (e.g. 'load_balancers').
    _KEY_ALIASES: Dict[str, str] = {
        'load_balancers': 'elb_v2',
    }

    def _get_data(self, key: str) -> List[Any]:
        """
        Get data from export by key, normalizing AWS CLI response formats.
        
        AWS CLI returns data in nested structures like:
        - EC2 instances: {"Reservations": [{"Instances": [...]}]}
        - EBS volumes: {"Volumes": [...]}
        - Lambda functions: {"Functions": [...]}
        
        This method extracts the actual resource lists from these structures.
        Falls back to _KEY_ALIASES when the primary key is not found.
        """
        data = self._export_data.get(key)
        
        # If not found under primary key, try alias
        if data is None:
            alias = self._KEY_ALIASES.get(key)
            if alias:
                data = self._export_data.get(alias)
        
        if data is None:
            # CLO-554: a file --anonymize removed is MISSING, not empty.
            alias = self._KEY_ALIASES.get(key)
            if self._is_removed(key) or (alias and self._is_removed(alias)):
                raise ExportFileRemovedError(
                    f"{key}.json was removed by --anonymize because it could not be "
                    f"anonymized safely; its data is MISSING, not empty"
                )
            return []
        
        # If it's already a list, return it directly
        if isinstance(data, list):
            return data
        
        # If it's a dict, extract the nested resources based on the key
        if isinstance(data, dict):
            return self._extract_resources_from_response(key, data)
        
        return []
    
    def _extract_resources_from_response(self, key: str, data: Dict[str, Any]) -> List[Any]:
        """
        Extract resource list from AWS CLI response format.
        
        Maps export file keys to the nested structure in AWS responses.
        """
        # Mapping of export file keys to their AWS CLI response structure
        # Note: The cloudwise-export.sh script creates some custom formats
        extraction_map = {
            # EC2 - special case with nested Reservations/Instances
            'ec2_instances': lambda d: [
                instance 
                for reservation in d.get('Reservations', [])
                for instance in reservation.get('Instances', [])
            ],
            # EBS
            'ebs_volumes': lambda d: d.get('Volumes', []),
            'ebs_snapshots': lambda d: d.get('Snapshots', []),
            'amis': lambda d: d.get('Images', []),
            'elastic_ips': lambda d: d.get('Addresses', []),
            # RDS
            'rds_instances': lambda d: d.get('DBInstances', []),
            'rds_snapshots': lambda d: d.get('DBSnapshots', []),
            'rds_clusters': lambda d: d.get('DBClusters', []),
            # Lambda
            'lambda_functions': lambda d: d.get('Functions', []),
            # S3 - export script uses custom format {"buckets": [...]}
            's3_buckets': lambda d: d.get('buckets', d.get('Buckets', [])),
            's3_incomplete_multipart': lambda d: d.get('buckets', []),
            # DynamoDB - export script uses {"tables": [{"Table": {...}}, ...]}
            'dynamodb_tables': lambda d: [
                t.get('Table', t) if isinstance(t, dict) else t 
                for t in d.get('tables', d.get('TableNames', []))
            ],
            # ElastiCache
            'elasticache_clusters': lambda d: d.get('CacheClusters', []),
            'elasticache_replication_groups': lambda d: d.get('ReplicationGroups', []),
            # Redshift
            'redshift_clusters': lambda d: d.get('Clusters', []),
            # OpenSearch
            'opensearch_domains': lambda d: d.get('DomainNames', []),
            # Network
            'nat_gateways': lambda d: d.get('NatGateways', []),
            'load_balancers': lambda d: d.get('LoadBalancers', []),
            'elb_v2': lambda d: d.get('LoadBalancers', []),
            'elb_classic': lambda d: d.get('LoadBalancerDescriptions', []),
            'lb_target_groups': lambda d: d.get('TargetGroups', []),
            'lb_target_health': lambda d: d.get('target_groups_health', []),
            'target_groups': lambda d: d.get('TargetGroups', []),
            'route53_zones': lambda d: d.get('HostedZones', []),
            'route53_details': lambda d: d.get('zones', []),
            # VPC resources
            'vpcs': lambda d: d.get('Vpcs', []),
            'subnets': lambda d: d.get('Subnets', []),
            'security_groups': lambda d: d.get('SecurityGroups', []),
            'route_tables': lambda d: d.get('RouteTables', []),
            'internet_gateways': lambda d: d.get('InternetGateways', []),
            'vpc_endpoints': lambda d: d.get('VpcEndpoints', []),
            # CloudWatch
            'cloudwatch_log_groups': lambda d: d.get('logGroups', []),
            # CLO-516: newest stream per candidate group (cloudwise-export.sh)
            'cloudwatch_log_group_activity': lambda d: d.get('logGroups', []),
            # CLO-516 (script 1.17.0+)
            'ebs_iops_peaks': lambda d: d.get('Volumes', []),
            'mq_broker_activity': lambda d: d.get('Brokers', []),
            'efs_lifecycle_configs': lambda d: d.get('LifecycleConfigs', []),
            # KMS - export script uses {"keys": [...]}
            'kms_keys': lambda d: d.get('keys', d.get('Keys', [])),
            # Secrets Manager
            'secrets': lambda d: d.get('SecretList', []),
            'secrets_manager': lambda d: d.get('SecretList', []),
            # SageMaker
            'sagemaker_notebooks': lambda d: d.get('NotebookInstances', []),
            'sagemaker_endpoints': lambda d: d.get('Endpoints', []),
            'sagemaker_endpoint_details': lambda d: d.get('EndpointDetails', []),
            # Kinesis
            'kinesis_streams': lambda d: d.get('StreamNames', []),
            'kinesis_consumers': lambda d: d.get('Consumers', []),
            'kinesis_consumer_metrics': lambda d: d.get('consumer_metrics', []),
            # Firehose
            'firehose_delivery_streams': lambda d: d.get('DeliveryStreamNames', []),
            'firehose_metrics': lambda d: d.get('firehose_metrics', []),
            # ECS - export script uses custom format
            # CLO-550: a failed describe-clusters was written as {} before
            # export 1.19.0, which read as a nameless cluster: '' matches
            # every service ARN and no autoscaling target, so each 2+ task
            # service was flagged ecs_no_autoscaling. A cluster without a
            # name is not a cluster; drop it (MISSING).
            'ecs_clusters': lambda d: [
                c for cluster_response in d.get('clusters', [])
                for c in cluster_response.get('clusters', [cluster_response])
                if isinstance(c, dict) and c.get('clusterName')
            ],
            'ecs_services': lambda d: [
                s for service_response in d.get('services', [])
                for s in service_response.get('services', [service_response])
            ],
            'ecs_task_definitions': lambda d: d.get('taskDefinitions', d.get('taskDefinition', [d]) if 'taskDefinitionArn' in d else []),
            'ecs_autoscaling_targets': lambda d: d.get('ScalableTargets', []),
            # ECR
            'ecr_repositories': lambda d: d.get('repositories', []),
            'ecr_images': lambda d: d.get('repositories', []),
            'ecr_lifecycle_policies': lambda d: d.get('policies', []),
            # AWS Backup. CLO-551: export 1.20.0 adds "FailedVaultReads" next
            # to "RecoveryPoints", so the one-list-key fallback no longer
            # applies; name the list.
            'backup_recovery_points': lambda d: d.get('RecoveryPoints', []),
            'backup_vaults': lambda d: d.get('BackupVaultList', []),
            # EFS/FSx
            'efs_filesystems': lambda d: d.get('FileSystems', []),
            'fsx_filesystems': lambda d: d.get('FileSystems', []),
            'fsx_backups': lambda d: d.get('Backups', []),
            'fsx_activity': lambda d: d.get('FileSystems', []),
            # Other services
            'workspaces': lambda d: d.get('Workspaces', []),
            'workspaces_connection_status': lambda d: d.get('WorkspacesConnectionStatus', []),
            'workspaces_pools': lambda d: d.get('WorkspacesPools', []),
            'lightsail_instances': lambda d: d.get('instances', []),
            'lightsail_static_ips': lambda d: d.get('staticIps', []),
            'lightsail_disks': lambda d: d.get('disks', []),
            'lightsail_snapshots': lambda d: d.get('instanceSnapshots', []),
            'lightsail_load_balancers': lambda d: d.get('loadBalancers', []),
            'lightsail_databases': lambda d: d.get('relationalDatabases', []),
            'beanstalk_environments': lambda d: d.get('Environments', []),
            'neptune_clusters': lambda d: d.get('DBClusters', []),
            'neptune_instances': lambda d: d.get('DBInstances', []),
            'neptune_snapshots': lambda d: d.get('DBClusterSnapshots', []),
            'documentdb_clusters': lambda d: d.get('DBClusters', []),
            'documentdb_snapshots': lambda d: d.get('DBClusterSnapshots', []),
            'msk_clusters': lambda d: d.get('ClusterInfoList', []),
            'glue_jobs': lambda d: d.get('Jobs', []),
            'glue_dev_endpoints': lambda d: d.get('DevEndpoints', []),
            'glue_crawlers': lambda d: d.get('Crawlers', []),
            'glue_catalog_stats': lambda d: d,
            'mq_brokers': lambda d: d.get('BrokerSummaries', []),
            'emr_clusters': lambda d: d.get('Clusters', []),
            'emr_instance_groups': lambda d: d.get('InstanceGroups', []),
            'emr_steps': lambda d: d.get('Steps', []),
            'emr_idle_metrics': lambda d: d.get('Datapoints', []),
            'api_gateway_rest': lambda d: d.get('items', []),
            'api_gateway_http': lambda d: d.get('Items', []),
            'appsync_apis': lambda d: d.get('graphqlApis', []),
            'step_functions': lambda d: d.get('stateMachines', []),
            'cloudfront_distributions': lambda d: d.get('DistributionList', {}).get('Items', []),
            'global_accelerators': lambda d: d.get('Accelerators', []),
            'cloudtrail_trails': lambda d: d.get('trailList', []),
            'transfer_servers': lambda d: d.get('Servers', []),
            'transfer_web_apps': lambda d: d.get('WebApps', []),
            'timestream_databases': lambda d: d.get('Databases', []),
            'qldb_ledgers': lambda d: d.get('Ledgers', []),
            'sqs_queues': lambda d: d.get('QueueUrls', []),
            'sns_topics': lambda d: d.get('Topics', []),
            # Compute Optimizer
            'compute_optimizer_ec2': lambda d: d.get('instanceRecommendations', []),
            'compute_optimizer_ebs': lambda d: d.get('volumeRecommendations', []),
            'compute_optimizer_lambda': lambda d: d.get('lambdaFunctionRecommendations', []),
            # DynamoDB autoscaling
            'dynamodb_autoscaling': lambda d: d.get('ScalableTargets', []),
        }
        
        extractor = extraction_map.get(key)
        if extractor:
            try:
                return extractor(data)
            except Exception as e:
                logger.warning(f"Error extracting {key} from response: {e}")
                return []
        
        # For metrics files, return as-is (they have custom structures)
        if 'metrics' in key or 'cloudwatch' in key.lower():
            return data if isinstance(data, list) else []
        
        # Try common patterns for unknown keys
        for common_key in ['Items', 'Resources', 'Results', 'Records']:
            if common_key in data:
                return data[common_key]
        
        # If dict has only one key containing a list, return that list
        if len(data) == 1:
            only_value = list(data.values())[0]
            if isinstance(only_value, list):
                return only_value
        
        logger.warning(f"Unknown data structure for key '{key}': {list(data.keys())[:5]}")
        return []
    
    def _parse_datetime(self, value: Any) -> Optional[datetime]:
        """Parse a datetime from various formats."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                # ISO format
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                try:
                    # AWS format
                    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
                except ValueError:
                    return None
        if isinstance(value, (int, float)):
            # Unix timestamp — auto-detect seconds vs milliseconds.
            # Timestamps > 1e12 are milliseconds (year ~33658 in seconds),
            # while AWS SageMaker and some services return epoch *seconds*.
            if value > 1e12:
                value = value / 1000  # milliseconds → seconds
            return datetime.fromtimestamp(value, tz=timezone.utc)
        return None
    
    def _get_tag_dict(self, tags: Any) -> Dict[str, str]:
        """Convert tags to dict format."""
        if isinstance(tags, dict):
            return tags
        if isinstance(tags, list):
            return {t.get('Key'): t.get('Value') for t in tags if t.get('Key')}
        return {}
    
    # =========================================================================
    # EC2 / Compute
    # =========================================================================
    
    async def get_ec2_instances(self) -> List[EC2InstanceData]:
        """Get all EC2 instances from the export."""
        instances = []
        
        for instance in self._get_data('ec2_instances'):
            tags = self._get_tag_dict(instance.get('Tags', []))
            
            instances.append(EC2InstanceData(
                instance_id=instance.get('InstanceId', ''),
                instance_type=instance.get('InstanceType', ''),
                state=instance.get('State', {}).get('Name', instance.get('state', '')),
                region=instance.get('region', self._region),
                name=tags.get('Name') or instance.get('name'),
                launch_time=self._parse_datetime(instance.get('LaunchTime')),
                platform=instance.get('Platform'),
                tags=tags,
                block_device_mappings=instance.get('BlockDeviceMappings', []),
                vpc_id=instance.get('VpcId'),
                subnet_id=instance.get('SubnetId'),
                public_ip=instance.get('PublicIpAddress') or None,
            ))
        
        return instances
    
    async def get_ec2_metrics(
        self,
        instance_ids: List[str],
        days: int = 14,
        idle_threshold: float = 5.0,
        oversized_threshold: float = 40.0,
    ) -> Dict[str, EC2MetricsData]:
        """Get CloudWatch metrics for EC2 instances from the export.

        CLO-493, in CLO-485's shape (#1479): an instance whose CPU is not in
        the export, or whose hourly series covers under 75% of the window, is
        left OUT of the map and noted MISSING in ``data_warnings``. It used to
        get a default ``cpu_avg=0.0`` entry. The window is the idle setting
        capped at the days the export collected (7 hourly by default, so 126
        of 168 hours).
        """
        metrics: Dict[str, EC2MetricsData] = {}
        window_days = max(1, min(days, self._export_cloudwatch_days()))
        
        # The upload consolidates each cloudwatch_metrics/ec2_cpu_<id>.json
        # into one ``ec2_cpu_metrics`` row: {instance_id, datapoints_count,
        # avg/cpu_avg, max/cpu_max}. An empty series is dropped (a gauge: empty
        # is missing, not 0% CPU).
        exported_metrics = {}
        for metric in self._get_data('ec2_cpu_metrics'):
            instance_id = metric.get('instance_id') or metric.get('InstanceId', '')
            if instance_id:
                exported_metrics[instance_id] = metric

        launch_times = {
            (row.get('InstanceId') or ''): self._parse_datetime(row.get('LaunchTime'))
            for row in self._get_data('ec2_instances')
        }

        def _first(m: Dict[str, Any], *keys: str) -> Optional[float]:
            for k in keys:
                if m.get(k) is not None:
                    try:
                        return float(m[k])
                    except (TypeError, ValueError):
                        return None
            return None

        def _missing(instance_id: str, reason: str) -> None:
            # A resource younger than the window can't be judged idle over it;
            # no note, as #1479 does for its age-vetoed resources.
            if is_as_old_as_window(launch_times.get(instance_id), window_days):
                self._note_idle_verdict_missing('ec2', instance_id, reason)
        
        for instance_id in instance_ids:
            m = exported_metrics.get(instance_id)
            if m is None:
                _missing(instance_id, "CPUUtilization not in export")
                continue
            cpu_avg = _first(m, 'cpu_avg', 'avg', 'Average')
            cpu_max = _first(m, 'cpu_max', 'max', 'Maximum')
            try:
                points = int(m.get('datapoints_count') or 0)
            except (TypeError, ValueError):
                points = 0
            if cpu_avg is None:
                _missing(instance_id, "CPUUtilization not in export")
                continue
            if not has_min_coverage(points, window_days, 3600):
                _missing(instance_id, "CPUUtilization under 75% coverage")
                continue
            # The peak guard (cpu_sizing.ec2_cpu_is_idle) needs the hourly
            # Maximums and both percentiles, which the upload's consolidator
            # writes as max/p95_avg/p95_max. Without them the verdict is
            # MISSING: a low mean alone does not make an instance idle.
            p95_avg = _first(m, 'p95_avg')
            p95_max = _first(m, 'p95_max')
            if cpu_max is None or p95_avg is None or p95_max is None:
                _missing(instance_id, "CPUUtilization peaks not in export")
                continue
            metrics[instance_id] = EC2MetricsData(
                instance_id=instance_id,
                cpu_avg=round(cpu_avg, 2),
                cpu_max=round(cpu_max, 2),
                period_days=window_days,
                is_idle=ec2_cpu_is_idle(cpu_avg, p95_avg, p95_max, cpu_max, idle_threshold),
                is_oversized=cpu_avg < oversized_threshold and cpu_avg >= idle_threshold,
                cpu_datapoints=points,
                cpu_p95=round(p95_avg, 2),
                cpu_p95_max=round(p95_max, 2),
            )
        
        return metrics
    
    # =========================================================================
    # EBS / Storage
    # =========================================================================
    
    async def get_ebs_volumes(self) -> List[EBSVolumeData]:
        """Get all EBS volumes from the export."""
        volumes = []
        
        for volume in self._get_data('ebs_volumes'):
            volumes.append(EBSVolumeData(
                volume_id=volume.get('VolumeId', ''),
                volume_type=volume.get('VolumeType', ''),
                size_gb=volume.get('Size', 0),
                state=volume.get('State', ''),
                region=volume.get('region', self._region),
                iops=volume.get('Iops'),
                throughput=volume.get('Throughput'),
                create_time=self._parse_datetime(volume.get('CreateTime')),
                attachments=volume.get('Attachments', []),
                encrypted=volume.get('Encrypted', False),
                tags=self._get_tag_dict(volume.get('Tags', [])),
            ))
        
        return volumes
    
    async def get_ebs_iops_peaks(
        self,
        volume_ids: List[str],
        days: int = 14,
        deadline: Optional[float] = None,
    ) -> Dict[str, EBSIopsPeakData]:
        """CLO-516: peak one-minute IOPS from ``ebs_iops_peaks.json``.

        Export script 1.17.0+ writes, for each candidate volume, the peak of
        ``(VolumeReadOps + VolumeWriteOps) / 60`` over its CloudWatch window
        (7 days) and how many minutes it covered. A volume missing from the
        file (older scripts), whose read failed, or under 75% of the window's
        minutes is left out and noted MISSING."""
        result: Dict[str, EBSIopsPeakData] = {}
        if not volume_ids:
            return result
        entries = {
            e.get('VolumeId'): e for e in self._get_data('ebs_iops_peaks')
            if isinstance(e, dict) and e.get('VolumeId')
        }
        for volume_id in volume_ids:
            entry = entries.get(volume_id)
            reason = None
            if entry is None:
                reason = 'not in export'
            elif entry.get('error'):
                reason = f"export read failed ({entry.get('error')})"
            else:
                try:
                    period = int(entry.get('PeriodSeconds') or 60)
                    window = float(entry.get('WindowSeconds') or 0)
                    count = int(entry.get('Datapoints') or 0)
                    peak = entry.get('PeakIops')
                    expected = int(window / period) if period > 0 else 0
                except (TypeError, ValueError):
                    expected, count, peak = 0, 0, None
                if expected <= 0 or peak is None:
                    reason = 'no datapoints'
                elif count < expected * 0.75:
                    reason = 'no datapoints' if count == 0 else 'under 75% coverage'
                else:
                    result[volume_id] = EBSIopsPeakData(
                        volume_id=volume_id,
                        peak_iops=float(peak),
                        datapoints=count,
                        expected_datapoints=expected,
                        window_days=round(window / 86400, 2),
                        period_seconds=period,
                    )
            if reason:
                self._note_idle_verdict_missing(
                    'ebs', volume_id, reason,
                    verdict='over-provisioned IOPS', evidence='one-minute IOPS metrics',
                )
        return result

    async def get_ebs_snapshots(
        self,
        owner_ids: Optional[List[str]] = None,
        age_threshold_days: int = 90,
    ) -> List[EBSSnapshotData]:
        """Get EBS snapshots from the export."""
        snapshots = []
        
        for snapshot in self._get_data('ebs_snapshots'):
            start_time = self._parse_datetime(snapshot.get('StartTime'))
            age_days = snapshot.get('age_days', 0)
            if start_time and not age_days:
                age_days = (datetime.now(timezone.utc) - start_time).days
            
            # Only include snapshots older than threshold
            if age_days >= age_threshold_days:
                snapshots.append(EBSSnapshotData(
                    snapshot_id=snapshot.get('SnapshotId', ''),
                    volume_id=snapshot.get('VolumeId'),
                    volume_size_gb=snapshot.get('VolumeSize', 0),
                    state=snapshot.get('State', ''),
                    region=snapshot.get('region', self._region),
                    start_time=start_time,
                    description=snapshot.get('Description'),
                    encrypted=snapshot.get('Encrypted', False),
                    tags=self._get_tag_dict(snapshot.get('Tags', [])),
                    age_days=age_days,
                ))
        
        return snapshots
    
    async def get_elastic_ips(self) -> List[ElasticIPData]:
        """Get all Elastic IPs from the export."""
        eips = []
        
        for address in self._get_data('elastic_ips'):
            instance_id = address.get('InstanceId')
            network_interface_id = address.get('NetworkInterfaceId')
            
            eips.append(ElasticIPData(
                allocation_id=address.get('AllocationId', ''),
                public_ip=address.get('PublicIp', ''),
                region=address.get('region', self._region),
                instance_id=instance_id,
                network_interface_id=network_interface_id,
                is_attached=bool(instance_id or network_interface_id),
                domain=address.get('Domain', 'vpc'),
                tags=self._get_tag_dict(address.get('Tags', [])),
            ))
        
        return eips
    
    # =========================================================================
    # RDS / Databases
    # =========================================================================
    
    async def get_rds_instances(self) -> List[RDSInstanceData]:
        """Get all RDS instances from the export."""
        instances = []
        
        for db in self._get_data('rds_instances'):
            instances.append(RDSInstanceData(
                db_instance_id=db.get('DBInstanceIdentifier', ''),
                db_instance_class=db.get('DBInstanceClass', ''),
                engine=db.get('Engine', ''),
                engine_version=db.get('EngineVersion', ''),
                status=db.get('DBInstanceStatus', ''),
                region=db.get('region', self._region),
                multi_az=db.get('MultiAZ', False),
                storage_type=db.get('StorageType', 'gp2'),
                allocated_storage_gb=db.get('AllocatedStorage', 0),
                iops=db.get('Iops'),
                publicly_accessible=db.get('PubliclyAccessible', False),
                storage_encrypted=db.get('StorageEncrypted', False),
                deletion_protection=db.get('DeletionProtection', False),
                endpoint=db.get('Endpoint', {}).get('Address') if isinstance(db.get('Endpoint'), dict) else None,
                tags=self._get_tag_dict(db.get('TagList', [])),
                db_instance_arn=db.get('DBInstanceArn', ''),
                backup_retention_period=db.get('BackupRetentionPeriod', 0),
                instance_create_time=self._parse_datetime(db.get('InstanceCreateTime')),
            ))

        return instances
    
    async def get_rds_metrics(
        self,
        db_instance_ids: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
        include_cpu: bool = False,
    ) -> Dict[str, RDSMetricsData]:
        """Get CloudWatch metrics for RDS instances from the export.

        CLO-457: the export carries pre-aggregated values with no datapoint
        timestamps, so ``create_times`` cannot filter anything here; the
        detectors' minimum-age guards still apply.

        CLO-485: CPU is always filled when exported (``include_cpu`` changes
        nothing here). ``cpu_datapoints`` is the export's hourly datapoint
        count, None when an entry carries no count, and 0 when the instance
        has no CPU entry at all, so a CPU gate vetoes rather than reading a
        missing series as 0% CPU. Coverage is measured against the days the
        export collected (``cpu_window_days``), not the detector's window."""
        metrics = {}
        
        # Build lookup from exported metrics
        # Check multiple possible key names for compatibility
        exported_cpu = {}
        exported_conn = {}
        
        for key in ['rds_metrics', 'rds_cpu_metrics']:
            for metric in self._get_data(key):
                db_id = metric.get('db_instance_id') or metric.get('DBInstanceIdentifier', '')
                if db_id:
                    exported_cpu[db_id] = metric
        
        for metric in self._get_data('rds_connection_metrics'):
            db_id = metric.get('db_instance_id') or metric.get('DBInstanceIdentifier', '')
            if db_id:
                exported_conn[db_id] = metric
        
        for db_id in db_instance_ids:
            cpu_m = exported_cpu.get(db_id, {})
            conn_m = exported_conn.get(db_id, {})
            
            if cpu_m or conn_m:
                # Handle various field names from consolidation
                cpu_avg = float(cpu_m.get('cpu_avg') or cpu_m.get('avg') or cpu_m.get('Average', 0.0))
                cpu_max = float(cpu_m.get('cpu_max') or cpu_m.get('max') or cpu_m.get('Maximum', 0.0))
                if not cpu_m:
                    cpu_datapoints: Optional[int] = 0
                elif cpu_m.get('datapoints_count') is not None:
                    cpu_datapoints = int(cpu_m.get('datapoints_count') or 0)
                else:
                    cpu_datapoints = None
                conn_max = float(
                    conn_m.get('connections_max') or 
                    conn_m.get('max') or 
                    conn_m.get('Maximum', 0.0)
                )
                conn_avg = float(conn_m.get('connections_avg') or conn_m.get('avg', 0.0))
                # CLO-506: the export's connection datapoint count, None
                # when the row carries none, 0 with no connections row.
                if not conn_m:
                    conn_datapoints: Optional[int] = 0
                elif conn_m.get('datapoints_count') is not None:
                    conn_datapoints = int(conn_m.get('datapoints_count') or 0)
                else:
                    conn_datapoints = None

                metrics[db_id] = RDSMetricsData(
                    db_instance_id=db_id,
                    connections_avg=round(conn_avg, 2),
                    connections_max=round(conn_max, 2),
                    cpu_avg=round(cpu_avg, 2),
                    cpu_max=round(cpu_max, 2),
                    period_days=days,
                    is_idle=conn_max == 0 and cpu_avg < 1.0,
                    cpu_datapoints=cpu_datapoints,
                    cpu_window_days=min(days, self._export_cloudwatch_days()),
                    connections_datapoints=conn_datapoints,
                )
            else:
                metrics[db_id] = RDSMetricsData(
                    db_instance_id=db_id,
                    period_days=days,
                    cpu_datapoints=0,
                    cpu_window_days=min(days, self._export_cloudwatch_days()),
                    connections_datapoints=0,
                )
        
        return metrics
    
    async def get_rds_snapshots(
        self,
        snapshot_type: str = "manual",
        age_threshold_days: int = 90,
    ) -> List[RDSSnapshotData]:
        """Get RDS snapshots from the export."""
        snapshots = []
        
        for snapshot in self._get_data('rds_snapshots'):
            # Filter by snapshot type if specified
            snap_type = snapshot.get('SnapshotType', 'manual')
            if snapshot_type and snap_type != snapshot_type:
                continue
            
            create_time = self._parse_datetime(snapshot.get('SnapshotCreateTime'))
            age_days = snapshot.get('age_days', 0)
            if create_time and not age_days:
                age_days = (datetime.now(timezone.utc) - create_time).days
            
            if age_days >= age_threshold_days:
                snapshots.append(RDSSnapshotData(
                    snapshot_id=snapshot.get('DBSnapshotIdentifier', ''),
                    db_instance_id=snapshot.get('DBInstanceIdentifier'),
                    snapshot_type=snap_type,
                    status=snapshot.get('Status', ''),
                    region=snapshot.get('region', self._region),
                    allocated_storage_gb=snapshot.get('AllocatedStorage', 0),
                    create_time=create_time,
                    encrypted=snapshot.get('Encrypted', False),
                    engine=snapshot.get('Engine'),
                    age_days=age_days,
                ))
        
        return snapshots
    
    # =========================================================================
    # Lambda / Serverless
    # =========================================================================
    
    async def get_lambda_functions(self) -> List[LambdaFunctionData]:
        """Get all Lambda functions from the export."""
        functions = []
        
        for func in self._get_data('lambda_functions'):
            functions.append(LambdaFunctionData(
                function_name=func.get('FunctionName', ''),
                function_arn=func.get('FunctionArn', ''),
                runtime=func.get('Runtime', 'unknown'),
                memory_mb=func.get('MemorySize', 128),
                timeout_seconds=func.get('Timeout', 3),
                region=func.get('region', self._region),
                code_size_bytes=func.get('CodeSize', 0),
                last_modified=self._parse_datetime(func.get('LastModified')),
                handler=func.get('Handler'),
                description=func.get('Description'),
                architecture=func.get('Architectures', ['x86_64'])[0] if isinstance(
                    func.get('Architectures'), list
                ) else func.get('Architecture', 'x86_64'),
            ))
        
        return functions
    
    async def get_lambda_metrics(
        self,
        function_names: List[str],
        days: int = 30,
    ) -> Dict[str, LambdaMetricsData]:
        """Get CloudWatch metrics for Lambda functions from the export."""
        metrics = {}
        
        # Build lookup from exported invocation metrics
        # Check multiple possible key names for compatibility
        exported_metrics = {}
        for key in ['lambda_metrics', 'lambda_invocation_metrics']:
            for metric in self._get_data(key):
                func_name = metric.get('function_name') or metric.get('FunctionName', '')
                if func_name:
                    exported_metrics[func_name] = metric
        
        # Build lookup from exported duration metrics
        exported_duration = {}
        for metric in self._get_data('lambda_duration_metrics'):
            func_name = metric.get('function_name') or metric.get('FunctionName', '')
            if func_name:
                exported_duration[func_name] = metric
        
        for func_name in function_names:
            if func_name in exported_metrics:
                m = exported_metrics[func_name]
                # Handle various field names from different sources
                total_invocations = (
                    m.get('invocations_total') or 
                    m.get('total') or 
                    m.get('sum') or 
                    m.get('Sum', 0)
                )
                
                # Duration can come from the same entry or from separate duration metrics
                duration_avg = m.get('duration_avg_ms', m.get('avg', m.get('Average', 0.0)))
                duration_max = m.get('duration_max_ms', m.get('max', m.get('Maximum')))
                
                # Merge duration from separate duration metrics file if available
                if func_name in exported_duration:
                    d = exported_duration[func_name]
                    dur_avg = d.get('avg', d.get('Average', 0.0))
                    dur_max = d.get('max', d.get('Maximum'))
                    if dur_avg:
                        duration_avg = dur_avg
                    if dur_max:
                        duration_max = dur_max
                
                metrics[func_name] = LambdaMetricsData(
                    function_name=func_name,
                    invocations_total=int(total_invocations),
                    duration_avg_ms=round(float(duration_avg), 2),
                    duration_max_ms=round(float(duration_max), 2) if duration_max else 0.0,
                    period_days=days,
                    is_unused=int(total_invocations) == 0,
                )
            else:
                metrics[func_name] = LambdaMetricsData(
                    function_name=func_name,
                    period_days=days,
                )
        
        return metrics
    
    async def get_lambda_provisioned_concurrency_bulk(
        self, function_names: List[str]
    ) -> Dict[str, List[LambdaProvisionedConcurrencyData]]:
        """PC configs for many functions: an export lookup each, no API
        calls. A failed parse is left out of the map (MISSING, not "none")."""
        configs: Dict[str, List[LambdaProvisionedConcurrencyData]] = {}
        for name in function_names:
            try:
                configs[name] = await self.get_lambda_provisioned_concurrency(name)
            except Exception as e:  # noqa: BLE001 - MISSING, as before CLO-481
                logger.debug(f"Could not check PC for {name}: {e}")
        return configs

    async def get_lambda_provisioned_concurrency(
        self, function_name: str
    ) -> List[LambdaProvisionedConcurrencyData]:
        """Parse Lambda Provisioned Concurrency configs from exported JSON."""
        # File was exported as lambda_pc_<func_name>.json, then anonymized
        # The offline provider receives the anonymized function name, so it matches directly
        pc_key = f'lambda_pc_{function_name}'
        pc_data = self._export_data.get(pc_key)
        
        if not pc_data:
            return []
        
        configs = []
        try:
            pc_list = pc_data if isinstance(pc_data, list) else pc_data.get('ProvisionedConcurrencyConfigs', [])
            
            for pc in pc_list:
                # Load corresponding utilization metric
                util_key = f'lambda_pc_util_{function_name}'
                util_data = self._export_data.get(util_key)
                avg_util = None
                if util_data and isinstance(util_data, dict):
                    dps = util_data.get('Datapoints', [])
                    if dps:
                        avg_util = sum(d.get('Average', 0) for d in dps) / len(dps)
                        # Convert fraction 0.0-1.0 to percentage if needed
                        if avg_util <= 1.0:
                            avg_util = round(avg_util * 100, 2)
                
                configs.append(LambdaProvisionedConcurrencyData(
                    function_name=function_name,
                    function_qualifier=pc.get('FunctionArn', '').split(':')[-1] or '$LATEST',
                    requested_provisioned_concurrent_executions=pc.get(
                        'RequestedProvisionedConcurrentExecutions', 0
                    ),
                    allocated_provisioned_concurrent_executions=pc.get(
                        'AllocatedProvisionedConcurrentExecutions', 0
                    ),
                    status=pc.get('Status', 'UNKNOWN'),
                    avg_utilization_pct=avg_util,
                ))
        except Exception as e:
            logger.warning(f"Failed to parse Lambda PC data for {function_name}: {e}")
        
        return configs
    
    # =========================================================================
    # Network
    # =========================================================================
    
    async def get_nat_gateways(self) -> List[NATGatewayData]:
        """Get all NAT Gateways from the export."""
        gateways = []
        
        for nat in self._get_data('nat_gateways'):
            gateways.append(NATGatewayData(
                nat_gateway_id=nat.get('NatGatewayId', ''),
                state=nat.get('State', ''),
                vpc_id=nat.get('VpcId', ''),
                subnet_id=nat.get('SubnetId', ''),
                region=nat.get('region', self._region),
                create_time=self._parse_datetime(nat.get('CreateTime')),
                connectivity_type=nat.get('ConnectivityType', 'public'),
                tags=self._get_tag_dict(nat.get('Tags', [])),
            ))
        
        return gateways
    
    async def get_nat_gateway_metrics(
        self,
        nat_gateway_ids: List[str],
        days: int = 7,
    ) -> Dict[str, NATGatewayMetricsData]:
        """Get CloudWatch metrics for NAT Gateways from the export."""
        metrics = {}
        
        # Build lookup from exported metrics
        # The consolidated metrics use 'nat_metrics' key with 'nat_gateway_id' field
        exported_metrics = {}
        for metric in self._get_data('nat_metrics'):
            nat_id = metric.get('nat_gateway_id') or metric.get('NatGatewayId', '')
            if nat_id:
                exported_metrics[nat_id] = metric
        
        for nat_id in nat_gateway_ids:
            if nat_id in exported_metrics:
                m = exported_metrics[nat_id]
                # Handle various field names from consolidation
                bytes_out = (
                    m.get('bytes_out_total') or
                    m.get('sum') or
                    m.get('total') or
                    m.get('Sum', 0.0)
                )
                
                metrics[nat_id] = NATGatewayMetricsData(
                    nat_gateway_id=nat_id,
                    bytes_out_total=float(bytes_out),
                    period_days=days,
                    is_idle=float(bytes_out) == 0,
                )
            else:
                metrics[nat_id] = NATGatewayMetricsData(
                    nat_gateway_id=nat_id,
                    period_days=days,
                )
        
        return metrics
    
    def _build_lb_target_health_counts(self) -> Dict[str, Dict[str, int]]:
        """
        Build LB ARN → {healthy, unhealthy} counts from exported target
        group and target health data.

        The export script creates two files:
        - lb_target_groups.json  → TG ARN → [LB ARNs]
        - lb_target_health.json  → TG ARN → TargetHealthDescriptions
        """
        # Map TG ARN → list of LB ARNs
        tg_to_lbs: Dict[str, List[str]] = {}
        for tg in self._get_data('lb_target_groups'):
            tg_arn = tg.get('TargetGroupArn', '')
            lb_arns = tg.get('LoadBalancerArns', [])
            if tg_arn and lb_arns:
                tg_to_lbs[tg_arn] = lb_arns

        # Aggregate healthy / unhealthy per LB ARN
        counts: Dict[str, Dict[str, int]] = {}  # lb_arn → {healthy, unhealthy}
        for entry in self._get_data('lb_target_health'):
            tg_arn = entry.get('TargetGroupArn', '')
            lb_arns = tg_to_lbs.get(tg_arn, [])
            if not lb_arns:
                continue
            health_descs = (
                entry.get('Health', {}).get('TargetHealthDescriptions', [])
            )
            for desc in health_descs:
                state = desc.get('TargetHealth', {}).get('State', 'unknown')
                for lb_arn in lb_arns:
                    if lb_arn not in counts:
                        counts[lb_arn] = {'healthy': 0, 'unhealthy': 0}
                    if state == 'healthy':
                        counts[lb_arn]['healthy'] += 1
                    else:
                        counts[lb_arn]['unhealthy'] += 1
        return counts

    def _has_export_key(self, key: str) -> bool:
        """Whether the export carries ``key`` (or its alias) at all, even empty."""
        if key in self._export_data:
            return True
        alias = self._KEY_ALIASES.get(key)
        return bool(alias) and alias in self._export_data

    @staticmethod
    def _target_health_descriptions(entry: Any) -> List[Any]:
        """The TargetHealthDescriptions of one lb_target_health entry."""
        if not isinstance(entry, dict):
            return []
        health = entry.get('Health')
        if isinstance(health, dict):
            descriptions = health.get('TargetHealthDescriptions')
        else:
            descriptions = entry.get('TargetHealthDescriptions')
        return descriptions if isinstance(descriptions, list) else []

    def _lb_arns_with_known_target_health(self) -> set:
        """CLO-532 review: ELBv2 LB ARNs whose healthy-target count the export
        actually measured. Needs both target-group files; an LB is known when
        every target group attached to it has a health entry (an LB with no
        target groups has a measured 0). Without the files nothing is known,
        and a 0 count is MISSING, not "no healthy targets"."""
        if not (self._has_export_key('lb_target_groups') and self._has_export_key('lb_target_health')):
            return set()
        tgs_by_lb: Dict[str, set] = {}
        for tg in self._get_data('lb_target_groups'):
            for lb_arn in tg.get('LoadBalancerArns', []) or []:
                tgs_by_lb.setdefault(lb_arn, set()).add(tg.get('TargetGroupArn', ''))
        # CLO-550: before export 1.19.0 a failed describe-target-health was
        # written as {"TargetHealthDescriptions": []}, the same document as
        # a target group with no targets, so in such an export an empty
        # entry is not a measured 0. 1.19.0+ writes no entry on failure.
        with_health = {
            e.get('TargetGroupArn', '') for e in self._get_data('lb_target_health')
            if not (self._legacy_failed_reads and not self._target_health_descriptions(e))
        }
        known = {lb.get('LoadBalancerArn', '') for lb in self._get_data('load_balancers')}
        return {arn for arn in known if tgs_by_lb.get(arn, set()) <= with_health}

    async def get_load_balancers(self) -> List[LoadBalancerData]:
        """Get all Load Balancers from the export (ELBv2 + Classic)."""
        load_balancers = []

        # Derive healthy/unhealthy target counts from target-group health
        health_counts = self._build_lb_target_health_counts()
        health_known = self._lb_arns_with_known_target_health()

        # ELBv2 (ALB/NLB/GWLB)
        for lb in self._get_data('load_balancers'):
            lb_arn = lb.get('LoadBalancerArn', '')
            hc = health_counts.get(lb_arn, {})
            load_balancers.append(LoadBalancerData(
                load_balancer_arn=lb_arn,
                load_balancer_name=lb.get('LoadBalancerName', ''),
                type=lb.get('Type', 'application'),
                scheme=lb.get('Scheme', 'internet-facing'),
                state=lb.get('State', {}).get('Code', 'unknown') if isinstance(lb.get('State'), dict) else lb.get('State', 'unknown'),
                region=lb.get('region', self._region),
                vpc_id=lb.get('VpcId'),
                dns_name=lb.get('DNSName'),
                created_time=self._parse_datetime(lb.get('CreatedTime')),
                healthy_target_count=lb.get('healthy_target_count', hc.get('healthy', 0)),
                unhealthy_target_count=lb.get('unhealthy_target_count', hc.get('unhealthy', 0)),
                target_health_known='healthy_target_count' in lb or lb_arn in health_known,
            ))
        
        # Classic Load Balancers (ELBv1)
        for clb in self._get_data('elb_classic'):
            dns_name = clb.get('DNSName', '')
            healthy = clb.get('healthy_instance_count', 0)
            unhealthy = clb.get('unhealthy_instance_count', 0)
            load_balancers.append(LoadBalancerData(
                load_balancer_arn=dns_name,  # CLBs have no ARN; use DNSName
                load_balancer_name=clb.get('LoadBalancerName', ''),
                type='classic',
                scheme=clb.get('Scheme', 'internet-facing'),
                state='active',
                region=clb.get('region', self._region),
                vpc_id=clb.get('VPCId'),
                dns_name=dns_name,
                created_time=self._parse_datetime(clb.get('CreatedTime')),
                healthy_target_count=healthy,
                unhealthy_target_count=unhealthy,
                # CLO-532 review: the export carries no instance health for
                # a CLB unless the row says so; an absent count is MISSING.
                target_health_known='healthy_instance_count' in clb,
            ))
        
        return load_balancers
    
    async def get_load_balancer_metrics(
        self,
        load_balancer_arns: List[str],
        days: int = 7,
    ) -> Dict[str, LoadBalancerMetricsData]:
        """Get CloudWatch metrics for Load Balancers from the export."""
        metrics = {}
        
        # Build lookup from exported metrics (keyed by ARN)
        exported_metrics = {}
        for metric in self._get_data('load_balancer_metrics'):
            lb_arn = metric.get('load_balancer_arn') or metric.get('LoadBalancerArn', '')
            exported_metrics[lb_arn] = metric
        
        # Build name→ARN mapping from loaded LB data so we can match
        # consolidated metrics (which only have LB name from the filename)
        name_to_arn: Dict[str, str] = {}
        for lb in self._get_data('load_balancers'):
            lb_name = lb.get('LoadBalancerName', '')
            lb_arn = lb.get('LoadBalancerArn', '')
            if lb_name and lb_arn:
                name_to_arn[lb_name] = lb_arn
        
        # Merge consolidated request-count metrics (keyed by load_balancer_name)
        for metric in self._get_data('load_balancer_metrics'):
            lb_name = metric.get('load_balancer_name', '')
            if lb_name and lb_name in name_to_arn:
                arn = name_to_arn[lb_name]
                if arn not in exported_metrics:
                    exported_metrics[arn] = metric
        
        # Merge consolidated LCU metrics (keyed by load_balancer_name)
        lcu_by_arn: Dict[str, float] = {}
        for metric in self._get_data('load_balancer_lcu_metrics'):
            lb_name = metric.get('load_balancer_name', '')
            lb_arn = metric.get('load_balancer_arn') or metric.get('LoadBalancerArn', '')
            resolved_arn = lb_arn or name_to_arn.get(lb_name, '')
            if resolved_arn:
                # Per the LoadBalancerMetricsData contract this must be average LCUs
                # per hour. The exporter now records ConsumedLCUs with `Sum`, which
                # the upload consolidator surfaces as `sum` = total LCU-hours over
                # the export window, so divide by the window hours (CLO-228).
                total_lcu_hours = metric.get('sum', metric.get('total'))
                window_hours = days * 24
                if total_lcu_hours is not None and window_hours:
                    lcu_by_arn[resolved_arn] = float(total_lcu_hours) / window_hours
                else:
                    # Legacy exports captured `Average`, which is a mean over
                    # per-minute, per-node samples — there is no sound conversion
                    # to LCUs/hour without knowing the sample and node counts.
                    # Emitting it anyway would understate LCU cost by roughly two
                    # orders of magnitude and put a wrong dollar figure in front of
                    # a customer, so drop it and let the detector stay silent.
                    legacy_avg = metric.get('avg', metric.get('consumed_lcus_avg'))
                    if legacy_avg is not None:
                        logger.warning(
                            "Ignoring legacy Average-based ConsumedLCUs for %s — "
                            "re-run the export script to capture Sum (CLO-228)",
                            lb_name or resolved_arn,
                        )
        
        for lb_arn in load_balancer_arns:
            if lb_arn in exported_metrics:
                m = exported_metrics[lb_arn]
                request_count = m.get('request_count_total',
                                      m.get('sum', m.get('total', m.get('Sum', 0))))
                consumed_lcus = m.get('consumed_lcus_avg')
                # Overlay LCU data from separate LCU metrics if available
                if consumed_lcus is None and lb_arn in lcu_by_arn:
                    consumed_lcus = lcu_by_arn[lb_arn]
                
                metrics[lb_arn] = LoadBalancerMetricsData(
                    load_balancer_arn=lb_arn,
                    request_count_total=int(request_count),
                    period_days=days,
                    is_idle=int(request_count) == 0,
                    consumed_lcus_avg=float(consumed_lcus) if consumed_lcus is not None else None,
                )
            else:
                metrics[lb_arn] = LoadBalancerMetricsData(
                    load_balancer_arn=lb_arn,
                    period_days=days,
                )
        
        return metrics
    
    # =========================================================================
    # S3
    # =========================================================================
    
    def _s3_lifecycle(self, bucket: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[bool]]:
        """``(rules, has_lifecycle_policy)`` of an exported bucket record;
        ``has_lifecycle_policy`` is None when the lifecycle read is MISSING
        (CLO-551).

        - ``"Lifecycle": null`` (1.20.0+): get-bucket-lifecycle-configuration
          failed with an error other than NoSuchLifecycleConfiguration.
        - ``"Lifecycle": {}``: export 1.20.0+ writes it only for AWS's
          NoSuchLifecycleConfiguration (a measured "no policy"); older
          exports wrote it for every failure too (AccessDenied, ...), so
          there it is MISSING (``legacy_policy_reads``).
        - No ``Lifecycle`` key: not exported, MISSING.
        Rules actually read are real in every version."""
        if 'has_lifecycle_policy' in bucket:
            rules = bucket.get('lifecycle_rules')
            return (rules if isinstance(rules, list) else []), bucket.get('has_lifecycle_policy')
        if isinstance(bucket.get('lifecycle_rules'), list) and bucket['lifecycle_rules']:
            return bucket['lifecycle_rules'], True
        lifecycle_data = bucket.get('Lifecycle')
        if not isinstance(lifecycle_data, dict):
            return [], None
        rules = lifecycle_data.get('Rules')
        if isinstance(rules, list) and rules:
            return rules, True
        if self._legacy_policy_reads:
            return [], None
        return [], False

    async def get_s3_buckets(self) -> List[S3BucketData]:
        """Get all S3 buckets from the export, enriched with CloudWatch size metrics."""
        buckets = []
        
        # Also load incomplete multipart data if available
        multipart_by_bucket = {}
        for mp in self._get_data('s3_incomplete_multipart'):
            bucket_name = mp.get('Bucket', '')
            uploads = mp.get('Uploads', [])
            if bucket_name and uploads:
                multipart_by_bucket[bucket_name] = uploads
        
        for bucket in self._get_data('s3_buckets'):
            bucket_name = bucket.get('Name', bucket.get('bucket_name', ''))
            
            # Handle lifecycle - export script stores as Lifecycle.Rules
            lifecycle_rules, has_lifecycle = self._s3_lifecycle(bucket)
            
            # Check for incomplete multipart uploads
            multipart_uploads = multipart_by_bucket.get(bucket_name, [])
            
            # ── Enrich with CloudWatch size metrics from export ──
            # CLO-488: these files are raw get-metric-statistics responses
            # ({"Label", "Datapoints"}) stored under their own keys. They
            # used to go through _get_data, whose list extraction returned
            # [] for them, so every bucket read 0 bytes and 0 objects.
            storage_breakdown = {}
            total_size = 0
            storage_types = [
                'StandardStorage', 'IntelligentTieringStorage', 'StandardIAStorage',
                'OneZoneIAStorage', 'GlacierStorage', 'GlacierInstantRetrievalStorage',
                'DeepArchiveStorage',
            ]
            has_intelligent_tiering = False
            
            for storage_type in storage_types:
                size = self._latest_s3_metric_value(f"s3_size_{bucket_name}_{storage_type}")
                if size and size > 0:
                    storage_breakdown[storage_type] = size
                    total_size += size
                    if storage_type == 'IntelligentTieringStorage':
                        has_intelligent_tiering = True
            
            # Object count
            object_count = self._latest_s3_metric_value(f"s3_objects_{bucket_name}") or 0
            
            # Growth data (30 days ago)
            size_previous = 0
            growth_pct = 0.0
            if total_size > 0:
                prev_size = self._latest_s3_metric_value(f"s3_growth_{bucket_name}")
                if prev_size and prev_size > 0:
                    size_previous = prev_size
                    growth_pct = round(
                        ((total_size - prev_size) / prev_size) * 100, 1
                    )

            # CLO-488: emptiness needs an observed listing, as online. S3
            # publishes no storage datapoints for an empty bucket, so zero
            # CloudWatch size is missing data, not zero. Export script
            # 1.13.0+ samples ListObjectsV2 (MaxKeys=1) into ``KeyCount``;
            # like online, the listing is trusted when CloudWatch shows no
            # size, including over a stale NumberOfObjects. An older export
            # has no KeyCount: the bucket's contents are MISSING, and
            # s3_empty_bucket must not fire.
            contents_observed = total_size > 0
            key_count = self._s3_key_count_sample(bucket)
            if total_size == 0 and key_count is not None:
                object_count = key_count
                contents_observed = True
            
            bucket_region = bucket.get('region') or bucket.get('Location') or 'us-east-1'
            if not self._AWS_REGION_RE.match(str(bucket_region)):
                # CLO-488: not a region code (a pre-1.13.0 --anonymize export
                # hashed it). The detector's region filter used to drop every
                # such bucket silently: no finding, no warning.
                if self._unknown_region_buckets == self.UNKNOWN_REGION_EVALUATE:
                    bucket_region = self._region
                else:
                    if self._unknown_region_buckets == self.UNKNOWN_REGION_NOTE:
                        self._note_idle_verdict_missing(
                            's3', bucket_name,
                            "bucket region unknown in export (anonymized by a script older than 1.13.0)",
                            verdict="empty-bucket", evidence="object listings",
                        )
                    # Keep it out of every region's evaluation.
                    bucket_region = f"unknown:{bucket_region}"
            if (not contents_observed and object_count == 0
                    and bucket_region == self._region):
                self._note_idle_verdict_missing(
                    's3', bucket_name,
                    "no object listing in export (export script older than 1.13.0, "
                    "or s3:ListBucket denied)",
                    verdict="empty-bucket", evidence="object listings",
                )
            
            # Parse encryption config from export
            enc_config = bucket.get('ServerSideEncryptionConfiguration', {})
            enc_rules = enc_config.get('Rules', []) if isinstance(enc_config, dict) else []
            default_encryption_enabled = True  # AWS default since Jan 2023
            encryption_algorithm = None
            if enc_rules:
                encryption_algorithm = enc_rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
            elif bucket.get('default_encryption_enabled') is False:
                default_encryption_enabled = False
            
            buckets.append(S3BucketData(
                bucket_name=bucket_name,
                region=bucket_region,
                creation_date=self._parse_datetime(bucket.get('CreationDate')),
                has_lifecycle_policy=has_lifecycle,
                lifecycle_rules=lifecycle_rules,
                has_incomplete_multipart=len(multipart_uploads) > 0,
                incomplete_multipart_count=len(multipart_uploads),
                # CLO-513: the export keeps list-multipart-uploads as is, so
                # each upload's Initiated time is there.
                incomplete_multipart_initiated=[
                    parsed for parsed in (
                        self._parse_datetime(u.get('Initiated'))
                        for u in multipart_uploads if isinstance(u, dict) and u.get('Initiated')
                    ) if parsed is not None
                ],
                total_size_bytes=total_size,
                object_count=object_count,
                storage_class_breakdown=storage_breakdown,
                has_intelligent_tiering=has_intelligent_tiering,
                size_previous_bytes=size_previous,
                size_growth_pct_30d=growth_pct,
                default_encryption_enabled=default_encryption_enabled,
                encryption_algorithm=encryption_algorithm,
                contents_observed=contents_observed,
            ))
        
        return buckets

    def _latest_s3_metric_value(self, key: str) -> Optional[int]:
        """Most recent datapoint's Average from an exported S3
        get-metric-statistics response, or None when the export has no such
        file (not collected, read failed, or renamed by --anonymize) or the
        series is empty. Read raw: _get_data's list extraction returns []
        for these files (CLO-488)."""
        data = self._export_data.get(key)
        if not isinstance(data, dict):
            return None
        datapoints = [dp for dp in data.get('Datapoints') or [] if isinstance(dp, dict)]
        if not datapoints:
            return None
        latest = max(datapoints, key=lambda dp: str(dp.get('Timestamp', '')))
        try:
            return int(latest.get('Average', 0))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _s3_key_count_sample(bucket: Dict[str, Any]) -> Optional[int]:
        """The export's ListObjectsV2 ``KeyCount`` sample (MaxKeys=1, so 0 or
        1), or None when absent (pre-1.13.0 export) or not a number (the
        listing failed and the script wrote null)."""
        value = bucket.get('KeyCount')
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return max(int(value), 0)
    
    async def get_s3_cost_breakdown(self) -> Dict[str, S3CostBreakdown]:
        """Build S3 cost breakdown from offline CUR data."""
        breakdowns: Dict[str, S3CostBreakdown] = {}
        
        s3_records = self._get_data('s3_cost_breakdown')
        if not s3_records:
            return breakdowns
        
        for record in s3_records:
            bucket_name = record.get('bucket_name', '')
            if not bucket_name:
                continue
            
            if bucket_name not in breakdowns:
                breakdowns[bucket_name] = S3CostBreakdown(bucket_name=bucket_name)
            
            bd = breakdowns[bucket_name]
            usage_type = record.get('usage_type', '')
            cost = float(record.get('cost', 0))
            
            # Same categorization logic as online provider
            if 'TimedStorage' in usage_type:
                bd.storage_cost += cost
            elif 'DataTransfer-Out' in usage_type:
                bd.transfer_out_cost += cost
            elif 'DataTransfer-Regional' in usage_type:
                bd.transfer_regional_cost += cost
            elif 'AWS-Out-' in usage_type:
                bd.transfer_cross_region_cost += cost
            elif 'Requests-Tier1' in usage_type:
                bd.request_tier1_cost += cost
            elif 'Requests-Tier2' in usage_type:
                bd.request_tier2_cost += cost
            else:
                bd.other_cost += cost
        
        return breakdowns

    async def get_extended_support_cost_breakdown(
        self,
        service_keys: Optional[List[str]] = None,
        days: int = 30,
    ) -> Dict[str, ExtendedSupportCostData]:
        """Build extended support surcharge breakdown from offline CUR data."""
        breakdowns: Dict[str, ExtendedSupportCostData] = {}
        records = self._get_data('extended_support_cost_breakdown')
        if not records:
            return breakdowns

        for record in records:
            if not isinstance(record, dict):
                continue
            service = str(record.get('service_key', '')).strip().lower()
            if not service:
                continue
            if service_keys and service not in service_keys:
                continue

            resource_id = str(record.get('resource_id', '')).strip() or None
            key = f"{service}:{resource_id}" if resource_id else service

            amount = float(record.get('cost', record.get('amount_usd', 0.0)) or 0.0)
            period_days = int(record.get('days', days) or days)
            usage_type = str(record.get('usage_type', '')).strip()

            if key not in breakdowns:
                breakdowns[key] = ExtendedSupportCostData(
                    service_key=service,
                    amount_usd=0.0,
                    days=period_days,
                    resource_id=resource_id,
                    billing_source='offline_cur',
                )

            breakdowns[key].amount_usd += amount
            if usage_type:
                breakdowns[key].usage_types.append(usage_type)

        return breakdowns
    
    # =========================================================================
    # EFS
    # =========================================================================
    
    async def get_efs_filesystems(self) -> List[EFSFilesystemData]:
        """Get all EFS filesystems from the export."""
        filesystems = []

        # CLO-516: the export writes each file system's lifecycle policies to
        # efs_lifecycle_configs.json, not into the file-system record, and this
        # provider never read that file: every file system had no policy, so
        # no_lifecycle_efs fired on every one of 1 GB or more. Join it here. A
        # file system with no entry (an export without the file) or whose entry
        # records an "error" (script 1.17.0+; older scripts wrote [] on a
        # failed read, which is read as written) is MISSING: policies None.
        lifecycle_by_fs: Dict[str, Any] = {}
        for entry in self._get_data('efs_lifecycle_configs'):
            if isinstance(entry, dict) and entry.get('FileSystemId'):
                lifecycle_by_fs[entry['FileSystemId']] = entry

        def _policies(fs: Dict[str, Any]) -> Optional[List[Dict[str, str]]]:
            if 'LifecyclePolicies' in fs or 'lifecycle_policies' in fs:
                return fs.get('LifecyclePolicies', fs.get('lifecycle_policies')) or []
            fs_id = fs.get('FileSystemId', fs.get('filesystem_id', ''))
            entry = lifecycle_by_fs.get(fs_id)
            if entry is None:
                reason = 'not in export'
            elif entry.get('error') or not isinstance(entry.get('LifecyclePolicies'), list):
                reason = f"export read failed ({entry.get('error') or 'no policy list'})"
            else:
                return entry['LifecyclePolicies']
            self._note_idle_verdict_missing(
                'efs', fs_id, reason,
                verdict='no-lifecycle-policy', evidence='lifecycle configurations',
            )
            return None

        for fs in self._get_data('efs_filesystems'):
            filesystems.append(EFSFilesystemData(
                filesystem_id=fs.get('FileSystemId', fs.get('filesystem_id', '')),
                region=fs.get('region', self._region),
                name=fs.get('Name', fs.get('name')),
                lifecycle_state=fs.get('LifeCycleState', fs.get('lifecycle_state', 'available')),
                size_bytes=fs.get('SizeInBytes', {}).get('Value', fs.get('size_bytes', 0)) if isinstance(fs.get('SizeInBytes'), dict) else fs.get('size_bytes', 0),
                has_mount_targets=fs.get('has_mount_targets', fs.get('NumberOfMountTargets', 0) > 0),
                mount_target_count=fs.get('NumberOfMountTargets', fs.get('mount_target_count', 0)),
                performance_mode=fs.get('PerformanceMode', fs.get('performance_mode', 'generalPurpose')),
                throughput_mode=fs.get('ThroughputMode', fs.get('throughput_mode', 'bursting')),
                encrypted=fs.get('Encrypted', fs.get('encrypted', False)),
                creation_time=self._parse_datetime(fs.get('CreationTime')),
                lifecycle_policies=_policies(fs),
            ))
        
        return filesystems
    
    # =========================================================================
    # ECR
    # =========================================================================
    
    async def get_ecr_repositories(self) -> List[ECRRepositoryData]:
        """
        Get all ECR repositories from the export, enriched with image data.
        
        Combines data from:
        - ecr_repositories.json: Basic repository info from describe-repositories
        - ecr_images.json: Image details including counts, sizes, and age
        - ecr_lifecycle_policies.json: Lifecycle policy status (if available)
        
        The export script creates ecr_images.json with structure:
        {"repositories": [{"repositoryName": "...", "images": {"imageDetails": [...]}}]}
        """
        from datetime import datetime, timezone, timedelta
        
        repositories = []
        
        # Debug: Log raw data from export
        raw_repos = self._get_data('ecr_repositories')
        raw_images = self._get_data('ecr_images')
        raw_policies = self._get_data('ecr_lifecycle_policies')
        logger.info(f"ECR raw data: {len(raw_repos)} repos, {len(raw_images)} image entries, {len(raw_policies)} policy entries")
        if raw_repos:
            logger.debug(f"First repo sample: {raw_repos[0]}")
        if raw_images:
            logger.debug(f"First image entry sample: {raw_images[0]}")
        
        # Build a lookup map from ecr_images for enrichment
        # Structure: {"repoName": {"imageDetails": [...], ...}}
        images_by_repo = {}
        for repo_images in raw_images:
            repo_name = repo_images.get('repositoryName', '')
            if repo_name:
                images_by_repo[repo_name] = repo_images.get('images', {}).get('imageDetails', [])
        
        # Get lifecycle policies if available. CLO-551: a repository's entry
        # is True, False ("no policy") or None (MISSING):
        # - hasLifecyclePolicy null (1.20.0+): get-lifecycle-policy failed
        #   with an error other than LifecyclePolicyNotFoundException.
        # - false: 1.20.0+ writes it only for that NotFound error; older
        #   exports wrote it for every failure, so there it is MISSING
        #   (legacy_policy_reads).
        # - no entry for the repository: not exported, MISSING.
        lifecycle_policies: Dict[str, Optional[bool]] = {}
        for policy in raw_policies:
            if not isinstance(policy, dict):
                continue
            repo_name = policy.get('repositoryName', '')
            if repo_name:
                value = policy.get('hasLifecyclePolicy')
                if value is True:
                    lifecycle_policies[repo_name] = True
                elif value is False and not self._legacy_policy_reads:
                    lifecycle_policies[repo_name] = False
                else:
                    lifecycle_policies[repo_name] = None
        
        # Define "old" as images older than 90 days
        old_threshold = datetime.now(timezone.utc) - timedelta(days=90)
        
        for repo in raw_repos:
            repo_name = repo.get('repositoryName', repo.get('repository_name', ''))
            
            # Get image details for this repository
            image_details = images_by_repo.get(repo_name, [])
            
            # Calculate image statistics
            image_count = len(image_details)
            total_size_bytes = 0
            untagged_count = 0
            untagged_size_bytes = 0
            old_count = 0
            old_size_bytes = 0
            
            for image in image_details:
                size = image.get('imageSizeInBytes', 0)
                total_size_bytes += size
                
                # Check if untagged
                tags = image.get('imageTags', [])
                if not tags:
                    untagged_count += 1
                    untagged_size_bytes += size
                
                # Check if old
                pushed_at = image.get('imagePushedAt')
                if pushed_at:
                    try:
                        # Parse ISO format date
                        if isinstance(pushed_at, str):
                            push_date = datetime.fromisoformat(pushed_at.replace('Z', '+00:00'))
                        elif isinstance(pushed_at, (int, float)):
                            push_date = datetime.fromtimestamp(pushed_at, tz=timezone.utc)
                        else:
                            push_date = None
                        
                        if push_date and push_date < old_threshold:
                            old_count += 1
                            old_size_bytes += size
                    except (ValueError, TypeError):
                        pass
            
            # Convert bytes to GB
            total_size_gb = total_size_bytes / (1024 ** 3)
            untagged_size_gb = untagged_size_bytes / (1024 ** 3)
            old_size_gb = old_size_bytes / (1024 ** 3)
            
            # Check lifecycle policy
            if repo_name in lifecycle_policies:
                has_lifecycle = lifecycle_policies[repo_name]
            else:
                has_lifecycle = repo.get('has_lifecycle_policy')
            
            repositories.append(ECRRepositoryData(
                repository_name=repo_name,
                repository_arn=repo.get('repositoryArn', repo.get('repository_arn', '')),
                repository_uri=repo.get('repositoryUri', repo.get('repository_uri', '')),
                region=repo.get('region', self._region),
                created_at=self._parse_datetime(repo.get('createdAt')),
                image_count=image_count,
                total_size_gb=total_size_gb,
                has_lifecycle_policy=has_lifecycle,
                untagged_image_count=untagged_count,
                untagged_images_size_gb=untagged_size_gb,
                old_image_count=old_count,
                old_images_size_gb=old_size_gb,
            ))
        
        logger.info(f"Loaded {len(repositories)} ECR repositories with enriched image data")
        return repositories
    
    # =========================================================================
    # Route 53
    # =========================================================================
    
    async def get_route53_zones(self) -> List[Route53ZoneData]:
        """Get all Route 53 hosted zones from the export."""
        zones = []
        
        for zone in self._get_data('route53_zones'):
            zone_id = zone.get('Id', zone.get('zone_id', '')).replace('/hostedzone/', '')
            
            zones.append(Route53ZoneData(
                zone_id=zone_id,
                zone_name=zone.get('Name', zone.get('zone_name', '')),
                record_set_count=zone.get('ResourceRecordSetCount', zone.get('record_set_count', 0)),
                is_private=zone.get('Config', {}).get('PrivateZone', zone.get('is_private', False)) if isinstance(zone.get('Config'), dict) else zone.get('is_private', False),
                comment=zone.get('Config', {}).get('Comment') if isinstance(zone.get('Config'), dict) else zone.get('comment'),
                record_sets=zone.get('ResourceRecordSets', zone.get('record_sets', [])),
            ))
        
        return zones
    
    # =========================================================================
    # VPC Endpoints
    # =========================================================================
    
    async def get_vpc_endpoints(self) -> List[VPCEndpointData]:
        """Get all VPC endpoints from the export."""
        endpoints = []
        
        for ep in self._get_data('vpc_endpoints'):
            tags = ep.get('Tags', ep.get('tags', []))
            if isinstance(tags, list):
                tags = {t.get('Key'): t.get('Value') for t in tags}
            
            endpoints.append(VPCEndpointData(
                endpoint_id=ep.get('VpcEndpointId', ep.get('endpoint_id', '')),
                service_name=ep.get('ServiceName', ep.get('service_name', '')),
                endpoint_type=ep.get('VpcEndpointType', ep.get('endpoint_type', 'Interface')),
                state=ep.get('State', ep.get('state', 'available')),
                vpc_id=ep.get('VpcId', ep.get('vpc_id', '')),
                region=ep.get('region', self._region),
                creation_time=self._parse_datetime(ep.get('CreationTimestamp', ep.get('creation_time'))),
                subnet_ids=ep.get('SubnetIds', ep.get('subnet_ids', [])),
                # CLO-528: an export without the key leaves the ENI list
                # unknown (None), which the zero-ENI heuristic reads as
                # MISSING rather than as "no interfaces".
                network_interface_ids=ep.get('NetworkInterfaceIds', ep.get('network_interface_ids')),
                tags=tags,
            ))
        
        return endpoints

    async def get_vpc_endpoint_bytes_processed(
        self,
        endpoints: List[VPCEndpointData],
        days: int = 14,
    ) -> Optional[Dict[str, float]]:
        """CLO-528: the export carries no AWS/PrivateLinkEndpoints series, so
        there is nothing to measure (None, not zeros); the detector uses the
        zero-ENI heuristic instead."""
        return None
    
    # =========================================================================
    # DynamoDB
    # =========================================================================
    
    def _dynamodb_autoscaled_resource_ids(self) -> Optional[set]:
        """ResourceIds of the exported DynamoDB Application Auto Scaling
        targets (``table/<name>``, ``table/<name>/index/<index>``), or None
        when the read is MISSING (CLO-551).

        The export has always written ``dynamodb_autoscaling.json``
        (``describe-scalable-targets --service-namespace dynamodb``), but
        nothing read it: every PROVISIONED table read as "no auto scaling"
        and was flagged dynamodb_no_autoscaling.

        - Not exported (1.19.0+ leaves a 0-byte file when the call fails,
          which the upload parser skips): MISSING.
        - An empty ``ScalableTargets`` from an export older than 1.19.0
          (``legacy_failed_reads``): that script wrote the same document on
          failure, so it is MISSING too. A non-empty list is real.
        """
        raw = self._export_data.get('dynamodb_autoscaling')
        if isinstance(raw, list):
            targets = raw
        elif isinstance(raw, dict) and isinstance(raw.get('ScalableTargets'), list):
            targets = raw['ScalableTargets']
        else:
            return None
        if not targets and self._legacy_failed_reads:
            return None
        if self._scalable_ids_unreadable(targets, 'table/'):
            return None
        return {
            t.get('ResourceId') for t in targets
            if isinstance(t, dict) and isinstance(t.get('ResourceId'), str)
        }

    @staticmethod
    def _scalable_ids_unreadable(targets: List[Any], prefix: str) -> bool:
        """CLO-551: True when any scalable target's ResourceId does not start
        with ``prefix`` (``table/`` for DynamoDB, ``service/`` for ECS).
        AWS always writes that prefix for these namespaces; an export
        anonymized before 1.20.0 hashed the whole ResourceId (``reso_...``),
        so no target can be joined to its table or service and every one
        would read as "no auto scaling". Such a target list is MISSING."""
        return any(
            not (isinstance(t, dict) and isinstance(t.get('ResourceId'), str)
                 and t['ResourceId'].startswith(prefix))
            for t in targets
        )

    async def get_dynamodb_tables(self) -> List[DynamoDBTableData]:
        """Get all DynamoDB tables from the export."""
        tables = []
        autoscaled = self._dynamodb_autoscaled_resource_ids()
        
        for table in self._get_data('dynamodb_tables'):
            provisioned = table.get('ProvisionedThroughput', {})
            billing_mode = table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED') if isinstance(table.get('BillingModeSummary'), dict) else table.get('billing_mode', 'PROVISIONED')
            
            table_name = table.get('TableName', table.get('table_name', ''))
            # CLO-551: a table-level target, as the online provider reads it
            # (ResourceIds=["table/<name>"]); None when the targets are MISSING.
            if 'has_autoscaling' in table:
                has_autoscaling = table.get('has_autoscaling')
            elif autoscaled is None:
                has_autoscaling = None
            else:
                has_autoscaling = f"table/{table_name}" in autoscaled

            tables.append(DynamoDBTableData(
                table_name=table_name,
                table_arn=table.get('TableArn', table.get('table_arn', '')),
                region=table.get('region', self._region),
                billing_mode=billing_mode,
                status=table.get('TableStatus', table.get('status', '')),
                provisioned_read_capacity=provisioned.get('ReadCapacityUnits', table.get('provisioned_read_capacity', 0)),
                provisioned_write_capacity=provisioned.get('WriteCapacityUnits', table.get('provisioned_write_capacity', 0)),
                has_autoscaling=has_autoscaling,
                item_count=table.get('ItemCount', table.get('item_count', 0)),
                size_bytes=table.get('TableSizeBytes', table.get('size_bytes', 0)),
                deletion_protection=table.get('DeletionProtectionEnabled', table.get('deletion_protection', False)),
                created_time=self._parse_datetime(table.get('CreationDateTime')),
                # CLO-384: cloudwise-export.sh does not currently capture
                # PITR (no `describe-continuous-backups` call), so this is
                # None (unknown) for every export today — the safe default,
                # never treated as "off". Read defensively in case a future
                # export version adds it.
                point_in_time_recovery_enabled=table.get(
                    'point_in_time_recovery_enabled', table.get('PointInTimeRecoveryEnabled')
                ),
            ))
        
        return tables
    
    async def get_dynamodb_metrics(
        self,
        table_names: List[str],
        days: int = 14,
    ) -> Dict[str, DynamoDBMetricsData]:
        """Get CloudWatch metrics for DynamoDB tables from the export."""
        metrics = {}
        
        # Build lookup from exported metrics
        exported_metrics = {}
        for metric in self._get_data('dynamodb_metrics'):
            table_name = metric.get('table_name') or metric.get('TableName', '')
            exported_metrics[table_name] = metric
        
        consolidated_read = {
            r.get('table_name'): r for r in self._get_data('dynamodb_read_metrics') if r.get('table_name')
        }
        consolidated_write = {
            r.get('table_name'): r for r in self._get_data('dynamodb_write_metrics') if r.get('table_name')
        }

        for table_name in table_names:
            m = exported_metrics.get(table_name)
            # CLO-485: an entry without either consumed-capacity field is no
            # measurement; do not default it to 0.0 (idle).
            if m is not None and (
                m.get('consumed_read_capacity_avg') is not None
                or m.get('consumed_write_capacity_avg') is not None
            ):
                read_avg = m.get('consumed_read_capacity_avg', 0.0)
                write_avg = m.get('consumed_write_capacity_avg', 0.0)
                
                # Per the DynamoDBMetricsData contract these are per-second rates
                # (CLO-227). Not rounded, for the same reason as the online provider:
                # 2dp would collapse a realistic sub-0.01/s rate to exactly 0.0 and
                # misclassify a live table as idle.
                metrics[table_name] = DynamoDBMetricsData(
                    table_name=table_name,
                    consumed_read_capacity_avg=float(read_avg),
                    consumed_write_capacity_avg=float(write_avg),
                    period_days=days,
                    is_idle=float(read_avg) == 0 and float(write_avg) == 0,
                )
                continue

            # CLO-485: the upload path emits ``dynamodb_read_metrics`` and
            # ``dynamodb_write_metrics`` rows ({table_name, datapoints_count,
            # sum}), one per exported ConsumedRead/WriteCapacityUnits series
            # (daily Sums over the export window). Consumed capacity is a
            # counter: a day with no requests has no datapoint, so a row with
            # datapoints_count 0 (the consolidator keeps an exported-but-empty
            # series) is a measured zero. A table with no row at all was not
            # exported (or its read failed): MISSING, not zero, and left out
            # of the map. It used to get a default model whose 0.0/0.0 read
            # as an idle table, for every uploaded provisioned table.
            read_row = consolidated_read.get(table_name)
            write_row = consolidated_write.get(table_name)
            if read_row is None or write_row is None:
                self._note_idle_verdict_missing(
                    'dynamodb', table_name, "consumed capacity not in export",
                )
                continue
            window_seconds = self._export_cloudwatch_days() * 86400
            read_total = float(read_row.get('sum') or read_row.get('total') or 0.0)
            write_total = float(write_row.get('sum') or write_row.get('total') or 0.0)
            metrics[table_name] = DynamoDBMetricsData(
                table_name=table_name,
                consumed_read_capacity_avg=read_total / window_seconds,
                consumed_write_capacity_avg=write_total / window_seconds,
                period_days=self._export_cloudwatch_days(),
                is_idle=read_total == 0 and write_total == 0,
            )
        
        return metrics
    
    # =========================================================================
    # ElastiCache
    # =========================================================================
    
    async def get_elasticache_clusters(self) -> List[ElastiCacheClusterData]:
        """Get all ElastiCache clusters including replication group topology from the export."""
        clusters = []

        # Build replication group lookup
        rg_map = {}
        for rg in self._get_data('elasticache_replication_groups'):
            rg_id = rg.get('ReplicationGroupId', rg.get('replication_group_id', ''))
            if rg_id:
                rg_map[rg_id] = rg

        for cluster in self._get_data('elasticache_clusters'):
            cluster_id = cluster.get('CacheClusterId', cluster.get('cluster_id', ''))
            rg_id = cluster.get('ReplicationGroupId', cluster.get('replication_group_id'))

            # Parse tags from export
            tags = {}
            for tag in cluster.get('Tags', cluster.get('tags', [])):
                if isinstance(tag, dict):
                    tags[tag.get('Key', tag.get('key', ''))] = tag.get('Value', tag.get('value', ''))

            # Parse replication group topology
            num_shards = 1
            replicas_per_shard = 0
            multi_az = False
            auto_failover = 'disabled'

            if rg_id and rg_id in rg_map:
                rg = rg_map[rg_id]
                node_groups = rg.get('NodeGroups', rg.get('node_groups', []))
                num_shards = len(node_groups) if node_groups else 1
                if node_groups:
                    members = node_groups[0].get('NodeGroupMembers', node_groups[0].get('node_group_members', []))
                    replicas_per_shard = max(len(members) - 1, 0)
                multi_az = rg.get('MultiAZ', rg.get('multi_az', 'disabled')) == 'enabled'
                auto_failover = rg.get('AutomaticFailover', rg.get('automatic_failover', 'disabled'))

            clusters.append(ElastiCacheClusterData(
                cluster_id=cluster_id,
                engine=cluster.get('Engine', cluster.get('engine', '')),
                engine_version=cluster.get('EngineVersion', cluster.get('engine_version', '')),
                node_type=cluster.get('CacheNodeType', cluster.get('node_type', '')),
                num_nodes=cluster.get('NumCacheNodes', cluster.get('num_nodes', 1)),
                status=cluster.get('CacheClusterStatus', cluster.get('status', '')),
                region=cluster.get('region', self._region),
                created_time=self._parse_datetime(cluster.get('CacheClusterCreateTime')),
                tags=tags,
                replication_group_id=rg_id,
                num_shards=num_shards,
                replicas_per_shard=replicas_per_shard,
                multi_az_enabled=multi_az,
                automatic_failover=auto_failover,
                data_tiering_enabled=cluster.get('DataTiering', cluster.get('data_tiering', 'disabled')) == 'enabled',
            ))
        
        return clusters

    async def get_elasticache_request_volume(
        self,
        cluster_ids: List[str],
        days: int = 30,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, ElastiCacheRequestVolumeData]:
        """CLO-508: the Air-Gapped export carries no ElastiCache command
        counts or network bytes, so no node is measured: every cluster is
        left out (its Serverless estimate is MISSING, not zero) and noted."""
        for cluster_id in cluster_ids:
            self._note_idle_verdict_missing(
                'elasticache-serverless', cluster_id, "not in export",
                verdict='serverless-estimate', evidence='command counts',
            )
        return {}

    async def get_elasticache_metrics(
        self,
        cluster_ids: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
        idle_window_days: Optional[int] = None,
    ) -> Dict[str, ElastiCacheMetricsData]:
        """Get CloudWatch metrics for ElastiCache clusters from per-cluster export files.

        CLO-457: the export reads hourly datapoints (cloudwise-export.sh);
        hours from before a cluster's creation time in ``create_times`` are
        dropped, since a reused CacheClusterId inherits its predecessor's."""
        metrics = {}

        def _extract_points(data: Any, created: Any = None) -> List[dict]:
            if isinstance(data, list):
                points = data
            elif isinstance(data, dict):
                points = data.get('Datapoints', [])
            else:
                return []
            return drop_pre_creation_datapoints(points, created, 3600)

        def _stat_avg(points: List[dict], stat: str = 'Average') -> float:
            vals = [p.get(stat, p.get(stat.lower(), 0)) for p in points]
            return sum(vals) / max(len(vals), 1) if vals else 0.0

        def _stat_max(points: List[dict], stat: str = 'Maximum') -> float:
            vals = [p.get(stat, p.get(stat.lower(), 0)) for p in points]
            return max(vals) if vals else 0.0

        def _stat_std(points: List[dict], stat: str = 'Average') -> float:
            vals = [p.get(stat, p.get(stat.lower(), 0)) for p in points]
            if len(vals) < 2:
                return 0.0
            mean = sum(vals) / len(vals)
            return (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5

        # CLO-485: the upload path (offline_upload_service._consolidate_metrics)
        # folds each elasticache_connections_{id} file into one pre-aggregated
        # ``elasticache_metrics`` row ({cache_cluster_id, datapoints_count,
        # max, sum}) and drops the raw key, which is all this method used to
        # read. The row is the fallback when the raw series is absent.
        consolidated_conn: Dict[str, Dict[str, Any]] = {}
        for row in self._get_data('elasticache_metrics'):
            cid = row.get('cache_cluster_id') or row.get('CacheClusterId') or row.get('cluster_id')
            if cid:
                consolidated_conn[cid] = row

        for cluster_id in cluster_ids:
            created = (create_times or {}).get(cluster_id)
            raw_conn_present = f'elasticache_connections_{cluster_id}' in self._export_data
            conn_data = _extract_points(self._export_data.get(f'elasticache_connections_{cluster_id}'), created)
            cpu_data = _extract_points(self._export_data.get(f'elasticache_cpu_{cluster_id}'), created)
            mem_data = _extract_points(self._export_data.get(f'elasticache_memory_{cluster_id}'), created)
            bytes_data = _extract_points(self._export_data.get(f'elasticache_bytes_{cluster_id}'), created)

            conn_avg = _stat_avg(conn_data, 'Sum') if conn_data else 0.0
            conn_max_val = _stat_max(conn_data, 'Maximum') if conn_data else 0.0
            conn_std_val = _stat_std(conn_data, 'Sum') if conn_data else 0.0
            cpu_avg = _stat_avg(cpu_data) if cpu_data else 0.0
            cpu_max_val = _stat_max(cpu_data) if cpu_data else 0.0
            mem_pct = _stat_avg(mem_data) if mem_data else 0.0
            bytes_used = _stat_avg(bytes_data) if bytes_data else 0.0

            # CLO-485: idle needs the connection series itself, covering 75%
            # of the hours the export collected (#1452's coverage rule). Any
            # other series (CPU, memory) says nothing about clients, and the
            # detector used to read a missing series as 0 connections.
            conn_window_days = min(idle_window_days or days, self._export_cloudwatch_days())
            conn_points = len(conn_data)
            conn_zero = conn_avg == 0 and conn_max_val == 0
            row = consolidated_conn.get(cluster_id)
            if not raw_conn_present and row is not None:
                # CurrConnections is a gauge (exported hourly, Maximum + Sum):
                # idle is a zero Maximum over enough of the export's hours.
                conn_points = int(row.get('datapoints_count') or 0)
                conn_max_val = float(row.get('max') or row.get('Maximum') or 0.0)
                conn_sum = float(row.get('sum') or row.get('total') or 0.0)
                conn_avg = conn_sum / conn_points if conn_points else 0.0
                conn_zero = conn_points > 0 and conn_max_val == 0 and conn_sum == 0
            conn_covered = has_min_coverage(conn_points, conn_window_days, 3600)
            if idle_window_days and not conn_covered and (conn_points == 0 or conn_zero):
                self._note_idle_verdict_missing(
                    'elasticache', cluster_id,
                    "CurrConnections not in export" if conn_points == 0
                    else "CurrConnections under 75% coverage",
                )

            metrics[cluster_id] = ElastiCacheMetricsData(
                cluster_id=cluster_id,
                cache_hits_avg=0.0,
                current_connections_avg=round(conn_avg, 2),
                current_connections_max=round(conn_max_val, 2),
                current_connections_std=round(conn_std_val, 2),
                cpu_utilization_avg=round(cpu_avg, 2),
                cpu_utilization_max=round(cpu_max_val, 2),
                database_memory_usage_pct=round(mem_pct, 2),
                bytes_used_for_cache=round(bytes_used, 2),
                period_days=days,
                is_idle=conn_covered and conn_zero,
                connection_datapoints=conn_points,
                cpu_datapoints=len(cpu_data),
                # CLO-559: oversized_elasticache's CPU coverage gate must be
                # sized to what the export actually collected, the same
                # clamp conn_window_days applies above — else an export
                # shorter than the requested window could never pass.
                cpu_window_days=min(days, self._export_cloudwatch_days()),
            )

        return metrics
    
    # =========================================================================
    # Redshift
    # =========================================================================
    
    async def get_redshift_clusters(self) -> List[RedshiftClusterData]:
        """Get all Redshift clusters from the export."""
        clusters = []
        
        # Build scheduled actions lookup
        scheduled_clusters: set = set()
        for action in self._get_data('redshift_scheduled_actions'):
            target = action.get('TargetAction', {})
            pause = target.get('PauseCluster', {})
            resume = target.get('ResumeCluster', {})
            cluster_id = pause.get('ClusterIdentifier') or resume.get('ClusterIdentifier')
            if cluster_id:
                scheduled_clusters.add(cluster_id)
        
        for cluster in self._get_data('redshift_clusters'):
            cluster_id = cluster.get('ClusterIdentifier', cluster.get('cluster_id', ''))
            status = cluster.get('ClusterStatus', cluster.get('status', ''))
            clusters.append(RedshiftClusterData(
                cluster_id=cluster_id,
                node_type=cluster.get('NodeType', cluster.get('node_type', '')),
                num_nodes=cluster.get('NumberOfNodes', cluster.get('num_nodes', 1)),
                status=status,
                region=cluster.get('region', self._region),
                database_name=cluster.get('DBName'),
                endpoint=cluster.get('Endpoint', {}).get('Address') if isinstance(cluster.get('Endpoint'), dict) else cluster.get('endpoint'),
                encrypted=cluster.get('Encrypted', False),
                created_time=self._parse_datetime(cluster.get('ClusterCreateTime')),
                has_pause_schedule=cluster.get('has_pause_schedule', cluster_id in scheduled_clusters),
                is_paused=cluster.get('is_paused', status.lower() == 'paused'),
            ))
        
        return clusters
    
    async def get_redshift_metrics(
        self,
        cluster_ids: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
        idle_window_days: Optional[int] = None,
    ) -> Dict[str, RedshiftMetricsData]:
        """Get CloudWatch metrics for Redshift clusters from the export.

        CLO-485: the entry is pre-aggregated, so coverage cannot be measured
        (``idle_window_days`` changes nothing); ``is_idle`` at least requires
        an exported connection average, never the 0.0 default of a missing
        field.

        CLO-457: the export carries pre-aggregated values with no datapoint
        timestamps, so ``create_times`` cannot filter anything here; the
        detectors' minimum-age guards still apply."""
        metrics = {}
        
        exported_metrics = {}
        for metric in self._get_data('redshift_metrics'):
            cluster_id = metric.get('cluster_id') or metric.get('ClusterIdentifier', '')
            exported_metrics[cluster_id] = metric
        
        for cluster_id in cluster_ids:
            if cluster_id in exported_metrics:
                m = exported_metrics[cluster_id]
                conn_raw = m.get('database_connections_avg')
                conn_avg = conn_raw if conn_raw is not None else 0.0
                cpu_avg = m.get('cpu_utilization_avg', 0.0)
                zero_pct = m.get('zero_connection_hours_pct', 0.0)
                
                metrics[cluster_id] = RedshiftMetricsData(
                    cluster_id=cluster_id,
                    database_connections_avg=round(float(conn_avg), 2),
                    cpu_utilization_avg=round(float(cpu_avg), 2),
                    period_days=days,
                    is_idle=conn_raw is not None and float(conn_avg) == 0,
                    zero_connection_hours_pct=round(float(zero_pct), 1),
                    wlm_queue_length_avg=round(float(m.get('wlm_queue_length_avg', 0.0)), 2),
                    wlm_queue_wait_time_avg=round(float(m.get('wlm_queue_wait_time_avg', 0.0)), 2),
                    wlm_running_queries_avg=round(float(m.get('wlm_running_queries_avg', 0.0)), 2),
                    wlm_running_queries_max=round(float(m.get('wlm_running_queries_max', 0.0)), 2),
                    concurrency_scaling_seconds_avg=round(float(m.get('concurrency_scaling_seconds_avg', 0.0)), 2),
                    concurrency_scaling_seconds_total=round(float(m.get('concurrency_scaling_seconds_total', 0.0)), 2),
                    concurrency_scaling_active_clusters_avg=round(float(m.get('concurrency_scaling_active_clusters_avg', 0.0)), 2),
                    concurrency_scaling_active_clusters_max=round(float(m.get('concurrency_scaling_active_clusters_max', 0.0)), 2),
                )
            else:
                metrics[cluster_id] = RedshiftMetricsData(
                    cluster_id=cluster_id,
                    period_days=days,
                )
        
        return metrics
    
    async def get_redshift_cost_breakdown(
        self,
        cluster_ids: List[str],
    ) -> Dict[str, RedshiftCostData]:
        """Get cost breakdown for Redshift clusters from the export."""
        costs: Dict[str, RedshiftCostData] = {}
        
        exported_costs = {}
        for cost in self._get_data('redshift_costs'):
            cid = cost.get('cluster_id', '')
            exported_costs[cid] = cost
        
        for cluster_id in cluster_ids:
            if cluster_id in exported_costs:
                c = exported_costs[cluster_id]
                compute = float(c.get('compute_cost_monthly', 0))
                spectrum = float(c.get('spectrum_cost_monthly', 0))
                storage = float(c.get('storage_cost_monthly', 0))
                total = float(c.get('total_cost_monthly', compute + spectrum + storage))
                ratio = (spectrum / compute * 100) if compute > 0 else 0
                costs[cluster_id] = RedshiftCostData(
                    cluster_id=cluster_id,
                    compute_cost_monthly=round(compute, 2),
                    spectrum_cost_monthly=round(spectrum, 2),
                    storage_cost_monthly=round(storage, 2),
                    total_cost_monthly=round(total, 2),
                    spectrum_cost_ratio=round(ratio, 1),
                )
            else:
                costs[cluster_id] = RedshiftCostData(cluster_id=cluster_id)
        
        return costs
    
    # =========================================================================
    # OpenSearch
    # =========================================================================
    
    async def get_opensearch_domains(self) -> List[OpenSearchDomainData]:
        """Get all OpenSearch domains from the export."""
        domains = []
        
        for domain in self._get_data('opensearch_domains'):
            cluster_config = domain.get('ClusterConfig', {})
            ebs_options = domain.get('EBSOptions', {})
            
            domains.append(OpenSearchDomainData(
                domain_name=domain.get('DomainName', domain.get('domain_name', '')),
                domain_arn=domain.get('ARN', domain.get('domain_arn', '')),
                instance_type=cluster_config.get('InstanceType', domain.get('instance_type', '')),
                instance_count=cluster_config.get('InstanceCount', domain.get('instance_count', 1)),
                status='available' if not domain.get('Processing', True) else 'processing',
                region=domain.get('region', self._region),
                engine_version=domain.get('EngineVersion', domain.get('engine_version', '')),
                endpoint=domain.get('Endpoint'),
                created=self._parse_datetime(domain.get('Created')),
                encrypted=domain.get('EncryptionAtRestOptions', {}).get('Enabled', False) if isinstance(domain.get('EncryptionAtRestOptions'), dict) else False,
                ebs_enabled=ebs_options.get('EBSEnabled', domain.get('ebs_enabled', False)),
                ebs_volume_type=ebs_options.get('VolumeType', domain.get('ebs_volume_type', '')),
                ebs_volume_size_gb=ebs_options.get('VolumeSize', domain.get('ebs_volume_size_gb', 0)),
                deleted=bool(domain.get('Deleted', domain.get('deleted', False))),
            ))
        
        return domains
    
    async def get_opensearch_metrics(
        self,
        domain_names: List[str],
        days: int = 14,
    ) -> Dict[str, OpenSearchMetricsData]:
        """Get CloudWatch metrics for OpenSearch domains from the export."""
        metrics = {}
        
        exported_metrics = {}
        for metric in self._get_data('opensearch_metrics'):
            domain_name = metric.get('domain_name') or metric.get('DomainName', '')
            exported_metrics[domain_name] = metric
        
        for domain_name in domain_names:
            if domain_name in exported_metrics:
                m = exported_metrics[domain_name]
                search_total = m.get('search_requests_total', 0)
                # Review of #1535: a row without the field did not measure
                # it (MISSING, never zero activity).
                search_present = 'search_requests_total' in m
                indexing_present = 'indexing_rate_avg' in m

                metrics[domain_name] = OpenSearchMetricsData(
                    domain_name=domain_name,
                    search_requests_total=int(search_total),
                    indexing_rate_avg=float(m.get('indexing_rate_avg', 0)),
                    cpu_utilization_avg=float(m.get('cpu_utilization_avg', 0)),
                    cpu_utilization_max=float(m.get('cpu_utilization_max', 0)),
                    jvm_memory_pressure_avg=float(m.get('jvm_memory_pressure_avg', 0)),
                    free_storage_space_avg=float(m.get('free_storage_space_avg', 0)),
                    free_storage_pct=float(m.get('free_storage_pct', 0)),
                    storage_growth_rate_gb_per_day=float(m.get('storage_growth_rate_gb_per_day', 0)),
                    period_days=days,
                    is_idle=search_present and int(search_total or 0) == 0,
                    search_datapoints=1 if search_present else 0,
                    indexing_datapoints=1 if indexing_present else 0,
                )
            else:
                metrics[domain_name] = OpenSearchMetricsData(
                    domain_name=domain_name,
                    period_days=days,
                )
        
        return metrics
    
    # =========================================================================
    # CloudWatch Logs
    # =========================================================================
    
    async def get_cloudwatch_log_groups(self) -> List[CloudWatchLogGroupData]:
        """Get all CloudWatch Log Groups from the export."""
        log_groups = []
        
        for group in self._get_data('cloudwatch_log_groups'):
            creation_time = group.get('creationTime')
            last_event_time = group.get('lastEventTimestamp')
            
            log_groups.append(CloudWatchLogGroupData(
                log_group_name=group.get('logGroupName', group.get('log_group_name', '')),
                region=group.get('region', self._region),
                stored_bytes=group.get('storedBytes', group.get('stored_bytes', 0)),
                retention_days=group.get('retentionInDays', group.get('retention_days')),
                creation_time=self._parse_datetime(creation_time),
                last_event_time=self._parse_datetime(last_event_time),
                days_since_last_event=group.get('days_since_last_event'),
            ))
        
        return log_groups

    async def get_cloudwatch_log_group_last_activity(
        self,
        log_group_names: List[str],
        deadline: Optional[float] = None,
    ) -> Dict[str, Optional[datetime]]:
        """CLO-516: last activity per group, from the export.

        Read in order: a ``lastEventTimestamp`` on the group record itself
        (hand-built exports; AWS never returns one), then the group's entry
        in ``cloudwatch_log_group_activity.json``, which cloudwise-export.sh
        writes from ``describe-log-streams --order-by LastEventTime
        --descending --max-items 1`` for candidate groups. An entry with no
        stream maps to None (never received an event). A group with neither,
        or whose entry records an ``error``, is left OUT and noted in
        ``data_warnings``: exports made before this capture existed hold no
        activity, and their empty/stale verdicts are MISSING, not zero."""
        result: Dict[str, Optional[datetime]] = {}
        if not log_group_names:
            return result
        wanted = set(log_group_names)

        record_times: Dict[str, Any] = {}
        for group in self._get_data('cloudwatch_log_groups'):
            name = group.get('logGroupName', group.get('log_group_name', ''))
            value = group.get('lastEventTimestamp')
            if name in wanted and value:
                record_times[name] = value

        activity_entries: Dict[str, dict] = {}
        for entry in self._get_data('cloudwatch_log_group_activity'):
            if isinstance(entry, dict) and entry.get('logGroupName') in wanted:
                activity_entries[entry['logGroupName']] = entry

        for name in log_group_names:
            if name in record_times:
                parsed = self._parse_datetime(record_times[name])
                if parsed is not None:
                    result[name] = parsed
                    continue
            entry = activity_entries.get(name)
            if entry is None:
                self._note_idle_verdict_missing(
                    'cloudwatch_logs', name, 'not in export',
                    verdict='empty/stale log group', evidence='log stream activity reads',
                )
                continue
            if entry.get('error'):
                self._note_idle_verdict_missing(
                    'cloudwatch_logs', name, f"export read failed ({entry.get('error')})",
                    verdict='empty/stale log group', evidence='log stream activity reads',
                )
                continue
            latest = None
            for stream in entry.get('logStreams') or []:
                for key in ('lastEventTimestamp', 'lastIngestionTime', 'creationTime'):
                    parsed = self._parse_datetime(stream.get(key))
                    if parsed is not None and (latest is None or parsed > latest):
                        latest = parsed
            result[name] = latest
        return result

    # =========================================================================
    # CloudWatch Dashboards
    # =========================================================================
    
    async def get_cloudwatch_dashboards(self) -> List[CloudWatchDashboardData]:
        """Get all CloudWatch Dashboards from the export."""
        dashboards = []
        
        for entry in self._get_data('cloudwatch_dashboards'):
            dashboards.append(CloudWatchDashboardData(
                dashboard_name=entry.get('DashboardName', entry.get('dashboard_name', '')),
                dashboard_arn=entry.get('DashboardArn', entry.get('dashboard_arn', '')),
                region=entry.get('region', self._region),
                last_modified=self._parse_datetime(entry.get('LastModified', entry.get('last_modified'))),
                size_bytes=entry.get('Size', entry.get('size_bytes', 0)),
            ))
        
        return dashboards
    
    # =========================================================================
    # KMS
    # =========================================================================
    
    async def get_kms_keys(self) -> List[KMSKeyData]:
        """Get all customer-managed KMS keys from the export."""
        keys = []
        
        for key_entry in self._get_data('kms_keys'):
            # Export script wraps key info: {"KeyInfo": {"KeyMetadata": {...}}, "RotationStatus": {...}}
            # Handle both wrapped and unwrapped formats
            if 'KeyInfo' in key_entry:
                key = key_entry.get('KeyInfo', {}).get('KeyMetadata', key_entry.get('KeyInfo', {}))
            else:
                key = key_entry
            
            # Skip AWS-managed keys
            key_manager = key.get('KeyManager', 'CUSTOMER')
            if key_manager == 'AWS':
                continue
            
            keys.append(KMSKeyData(
                key_id=key.get('KeyId', key.get('key_id', '')),
                key_arn=key.get('Arn', key.get('key_arn', '')),
                key_state=key.get('KeyState', key.get('key_state', '')),
                key_usage=key.get('KeyUsage', key.get('key_usage', '')),
                region=key.get('region', self._region),
                description=key.get('Description', key.get('description')),
                creation_date=self._parse_datetime(key.get('CreationDate')),
                enabled=key.get('Enabled', key.get('enabled', True)),
                days_since_last_use=key.get('days_since_last_use'),
            ))
        
        return keys
    
    # =========================================================================
    # Secrets Manager
    # =========================================================================
    
    async def get_secrets(self) -> List[SecretsManagerSecretData]:
        """Get all Secrets Manager secrets from the export."""
        secrets = []
        
        for secret in self._get_data('secrets'):
            last_accessed = secret.get('LastAccessedDate')
            days_since_access = secret.get('days_since_last_access')
            if last_accessed and not days_since_access:
                last_accessed_dt = self._parse_datetime(last_accessed)
                if last_accessed_dt:
                    days_since_access = (datetime.now(timezone.utc) - last_accessed_dt).days
            
            secrets.append(SecretsManagerSecretData(
                secret_id=secret.get('ARN', secret.get('secret_id', '')),
                secret_arn=secret.get('ARN', secret.get('secret_arn', '')),
                name=secret.get('Name', secret.get('name', '')),
                region=secret.get('region', self._region),
                description=secret.get('Description', secret.get('description')),
                created_date=self._parse_datetime(secret.get('CreatedDate')),
                last_accessed_date=self._parse_datetime(last_accessed),
                last_rotated_date=self._parse_datetime(secret.get('LastRotatedDate')),
                days_since_last_access=days_since_access,
                rotation_enabled=secret.get('RotationEnabled', False),
            ))
        
        return secrets
    
    # =========================================================================
    # SageMaker
    # =========================================================================
    
    async def get_sagemaker_notebooks(self) -> List[SageMakerNotebookData]:
        """Get all SageMaker notebook instances from the export."""
        notebooks = []
        
        for notebook in self._get_data('sagemaker_notebooks'):
            notebooks.append(SageMakerNotebookData(
                notebook_name=notebook.get('NotebookInstanceName', notebook.get('notebook_name', '')),
                notebook_arn=notebook.get('NotebookInstanceArn', notebook.get('notebook_arn', '')),
                instance_type=notebook.get('InstanceType', notebook.get('instance_type', '')),
                status=notebook.get('NotebookInstanceStatus', notebook.get('status', '')),
                region=notebook.get('region', self._region),
                creation_time=self._parse_datetime(notebook.get('CreationTime')),
                last_modified_time=self._parse_datetime(notebook.get('LastModifiedTime')),
                volume_size_gb=notebook.get('VolumeSizeInGB', notebook.get('volume_size_gb', 0)),
                url=notebook.get('Url'),
            ))
        
        return notebooks
    
    async def get_sagemaker_endpoints(self) -> List[SageMakerEndpointData]:
        """Get all SageMaker endpoints from the export."""
        endpoints = []
        
        # Build a lookup from endpoint details export (describe-endpoint data)
        endpoint_details = {}
        for detail in self._get_data('sagemaker_endpoint_details'):
            ep = detail.get('Endpoint', {})
            config = detail.get('Config', {})
            ep_name = ep.get('EndpointName', '')
            if ep_name:
                instance_type = None
                instance_count = 1
                variants = config.get('ProductionVariants', [])
                if variants:
                    instance_type = variants[0].get('InstanceType')
                    instance_count = variants[0].get('InitialInstanceCount', 1)
                endpoint_details[ep_name] = {
                    'instance_type': instance_type,
                    'instance_count': instance_count,
                }
        
        for endpoint in self._get_data('sagemaker_endpoints'):
            ep_name = endpoint.get('EndpointName', endpoint.get('endpoint_name', ''))
            details = endpoint_details.get(ep_name, {})
            
            endpoints.append(SageMakerEndpointData(
                endpoint_name=ep_name,
                endpoint_arn=endpoint.get('EndpointArn', endpoint.get('endpoint_arn', '')),
                status=endpoint.get('EndpointStatus', endpoint.get('status', '')),
                region=endpoint.get('region', self._region),
                creation_time=self._parse_datetime(endpoint.get('CreationTime')),
                last_modified_time=self._parse_datetime(endpoint.get('LastModifiedTime')),
                instance_type=details.get('instance_type') or endpoint.get('instance_type'),
                instance_count=details.get('instance_count', endpoint.get('instance_count', 1)),
            ))
        
        return endpoints
    
    async def get_sagemaker_metrics(
        self,
        endpoint_names: List[str],
        days: int = 7,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, SageMakerMetricsData]:
        """Get CloudWatch metrics for SageMaker endpoints from the export.

        CLO-457: the per-endpoint files are daily (cloudwise-export.sh,
        --period 86400); days from before an endpoint's creation time in
        ``create_times`` are dropped, since a reused EndpointName inherits its
        predecessor's. The legacy aggregated format cannot be filtered.
        
        Parses per-endpoint metrics files:
          - sagemaker_invocations_{name} for invocations
          - sagemaker_cpu_{name} for CPU utilization
          - sagemaker_memory_{name} for memory utilization
        Falls back to legacy 'sagemaker_metrics' key for backward compatibility.
        """
        metrics = {}
        
        # Try legacy aggregated format first (backward compatibility)
        legacy_metrics = {}
        for metric in self._get_data('sagemaker_metrics'):
            endpoint_name = metric.get('endpoint_name') or metric.get('EndpointName', '')
            legacy_metrics[endpoint_name] = metric
        
        for endpoint_name in endpoint_names:
            # Try per-endpoint metrics files (new format from export script)
            inv_key = f"sagemaker_invocations_{endpoint_name}"
            inv_data = self._export_data.get(inv_key, {})
            created = (create_times or {}).get(endpoint_name)
            inv_datapoints = drop_pre_creation_datapoints(
                inv_data.get('Datapoints', []) if isinstance(inv_data, dict) else [], created, 86400,
            )
            
            cpu_key = f"sagemaker_cpu_{endpoint_name}"
            cpu_data = self._export_data.get(cpu_key, {})
            cpu_datapoints = drop_pre_creation_datapoints(
                cpu_data.get('Datapoints', []) if isinstance(cpu_data, dict) else [], created, 86400,
            )
            
            mem_key = f"sagemaker_memory_{endpoint_name}"
            mem_data = self._export_data.get(mem_key, {})
            mem_datapoints = drop_pre_creation_datapoints(
                mem_data.get('Datapoints', []) if isinstance(mem_data, dict) else [], created, 86400,
            )
            
            if inv_key in self._export_data or cpu_datapoints or mem_datapoints:
                # Per-endpoint files found — use new format
                if inv_key not in self._export_data:
                    self._note_idle_verdict_missing(
                        'sagemaker', endpoint_name, "Invocations not in export",
                    )
                total = sum(dp.get('Sum', 0) for dp in inv_datapoints)
                cpu_avg = (
                    sum(dp.get('Average', 0) for dp in cpu_datapoints) / len(cpu_datapoints)
                    if cpu_datapoints else 0.0
                )
                mem_avg = (
                    sum(dp.get('Average', 0) for dp in mem_datapoints) / len(mem_datapoints)
                    if mem_datapoints else 0.0
                )
                
                metrics[endpoint_name] = SageMakerMetricsData(
                    endpoint_name=endpoint_name,
                    invocations_total=int(total),
                    invocations_avg=total / max(days, 1),
                    cpu_utilization_avg=cpu_avg,
                    memory_utilization_avg=mem_avg,
                    period_days=days,
                    # CLO-485: Invocations is a counter (no datapoint on a day
                    # without calls), so an exported but empty series is a
                    # real zero; an invocations file that is not in the
                    # export at all is not.
                    is_idle=(inv_key in self._export_data and total == 0),
                )
            elif endpoint_name in legacy_metrics:
                # Fall back to legacy aggregated format. CLO-485: the upload
                # consolidator writes the total as ``sum``/``total``, not
                # ``invocations_total``; reading only the latter defaulted
                # every endpoint, busy or not, to 0 invocations (idle).
                m = legacy_metrics[endpoint_name]
                invocations = next(
                    (m[k] for k in ('invocations_total', 'total', 'sum') if m.get(k) is not None),
                    None,
                )
                if invocations is None and m.get('datapoints_count') == 0:
                    # An exported-but-empty Invocations series (the
                    # consolidator keeps it as datapoints_count 0): a counter
                    # with no datapoints is a measured zero.
                    invocations = 0
                if invocations is None:
                    self._note_idle_verdict_missing(
                        'sagemaker', endpoint_name, "Invocations not in export",
                    )
                else:
                    metrics[endpoint_name] = SageMakerMetricsData(
                        endpoint_name=endpoint_name,
                        invocations_total=int(invocations),
                        period_days=days,
                        is_idle=int(invocations) == 0,
                    )
            else:
                # CLO-485: an endpoint with nothing exported is MISSING, not
                # zero; it used to get a default model with 0 invocations.
                self._note_idle_verdict_missing(
                    'sagemaker', endpoint_name, "Invocations not in export",
                )
        
        return metrics
    
    # =========================================================================
    # Kinesis
    # =========================================================================
    
    async def get_kinesis_streams(self) -> List[KinesisStreamData]:
        """Get all Kinesis streams from the export."""
        streams = []
        
        for stream in self._get_data('kinesis_streams'):
            streams.append(KinesisStreamData(
                stream_name=stream.get('StreamName', stream.get('stream_name', '')),
                stream_arn=stream.get('StreamARN', stream.get('stream_arn', '')),
                status=stream.get('StreamStatus', stream.get('status', '')),
                region=stream.get('region', self._region),
                shard_count=stream.get('OpenShardCount', stream.get('shard_count', 1)),
                retention_period_hours=stream.get('RetentionPeriodHours', stream.get('retention_period_hours', 24)),
                encryption_type=stream.get('EncryptionType'),
                created_time=self._parse_datetime(stream.get('StreamCreationTimestamp')),
            ))
        
        return streams
    
    async def get_kinesis_metrics(
        self,
        stream_names: List[str],
        days: int = 7,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, KinesisMetricsData]:
        """Get CloudWatch metrics for Kinesis streams from the export.

        CLO-457: the export carries pre-aggregated totals with no datapoint
        timestamps, so ``create_times`` cannot filter anything here; the
        detectors' minimum-age guards still apply."""
        metrics = {}
        
        exported_metrics = {}
        for metric in self._get_data('kinesis_metrics'):
            stream_name = metric.get('stream_name') or metric.get('StreamName', '')
            exported_metrics[stream_name] = metric
        
        for stream_name in stream_names:
            m = exported_metrics.get(stream_name)
            # CLO-488: the upload consolidates kinesis_records_<stream> (the
            # IncomingRecords Sum) as ``sum``/``total``; only a hand-built
            # export carries ``incoming_records_total``. Reading just the
            # latter defaulted every exported stream to 0 records (idle),
            # and an unexported stream got a default all-zero entry.
            incoming_records = None
            if m is not None:
                for field_name in ('incoming_records_total', 'sum', 'total'):
                    if m.get(field_name) is not None:
                        incoming_records = m[field_name]
                        break
            if incoming_records is None:
                # MISSING, not zero: the detector skips a stream with no
                # metrics entry, as online after a failed read (CLO-485).
                self._note_idle_verdict_missing(
                    'kinesis', stream_name, "IncomingRecords not in export",
                )
                continue

            get_records = m.get('get_records_total')
            metrics[stream_name] = KinesisMetricsData(
                stream_name=stream_name,
                incoming_records_total=int(incoming_records),
                incoming_bytes_total=int(m.get('incoming_bytes_total', 0) or 0),
                incoming_bytes_daily=m.get('incoming_bytes_daily'),
                # The export collects no GetRecords metric. None (not 0)
                # keeps kinesis_extended_retention_waste's "no reads" gate
                # from reading an unexported metric as zero reads.
                get_records_total=int(get_records) if get_records is not None else None,
                stream_mode=m.get('stream_mode', 'PROVISIONED'),
                period_days=days,
                is_idle=int(incoming_records) == 0,
            )
        
        return metrics

    async def get_kinesis_consumers(self, stream_arn: str) -> List[KinesisConsumerData]:
        """Get enhanced fan-out consumers from the export."""
        consumers = []
        for c in self._get_data('kinesis_consumers'):
            c_stream_arn = c.get('stream_arn', c.get('StreamARN', ''))
            if c_stream_arn == stream_arn:
                consumers.append(KinesisConsumerData(
                    consumer_name=c.get('ConsumerName', c.get('consumer_name', '')),
                    consumer_arn=c.get('ConsumerARN', c.get('consumer_arn', '')),
                    stream_arn=c_stream_arn,
                    consumer_status=c.get('ConsumerStatus', c.get('consumer_status', '')),
                    consumer_creation_timestamp=self._parse_datetime(c.get('ConsumerCreationTimestamp')),
                ))
        return consumers

    async def get_kinesis_consumer_metrics(
        self,
        stream_name: str,
        consumer_name: str,
        days: int = 14,
        consumer_create_time: Optional[datetime] = None,
    ) -> KinesisMetricsData:
        """Get consumer metrics from the export (pre-aggregated, so
        ``consumer_create_time`` cannot filter anything; CLO-457)."""
        for m in self._get_data('kinesis_consumer_metrics'):
            if (m.get('stream_name') == stream_name and
                    m.get('consumer_name') == consumer_name):
                get_records = m.get('get_records_total', 0)
                return KinesisMetricsData(
                    stream_name=stream_name,
                    get_records_total=int(get_records),
                    period_days=days,
                    is_idle=int(get_records) == 0,
                )
        return KinesisMetricsData(stream_name=stream_name, period_days=days)

    async def get_firehose_delivery_streams(self) -> List[KinesisFirehoseData]:
        """Get Firehose delivery streams from the export."""
        streams = []
        for ds in self._get_data('firehose_delivery_streams'):
            streams.append(KinesisFirehoseData(
                delivery_stream_name=ds.get('DeliveryStreamName', ds.get('delivery_stream_name', '')),
                delivery_stream_arn=ds.get('DeliveryStreamARN', ds.get('delivery_stream_arn', '')),
                delivery_stream_status=ds.get('DeliveryStreamStatus', ds.get('delivery_stream_status', '')),
                delivery_stream_type=ds.get('DeliveryStreamType', ds.get('delivery_stream_type', '')),
                source_stream_arn=ds.get('source_stream_arn'),
                has_lambda_transform=ds.get('has_lambda_transform', False),
                destination_type=ds.get('destination_type', ''),
                region=ds.get('region', self._region),
                # CLO-457: present when the export kept describe's field.
                create_time=self._parse_datetime(ds.get('CreateTimestamp')),
            ))
        return streams

    async def get_firehose_metrics(
        self,
        delivery_stream_names: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, KinesisFirehoseMetricsData]:
        """Get Firehose metrics from the export.

        CLO-457: ``create_times`` is accepted but cannot be applied: the
        export holds window totals, not timestamped datapoints. The idle
        detector's minimum-age rule is the defence here, when the export
        carries the stream's CreateTimestamp."""
        metrics = {}

        exported = {}
        for m in self._get_data('firehose_metrics'):
            name = m.get('delivery_stream_name') or m.get('DeliveryStreamName', '')
            exported[name] = m

        for name in delivery_stream_names:
            if name in exported:
                m = exported[name]
                records = m.get('incoming_records_total', 0)
                total_bytes = m.get('incoming_bytes_total', 0)
                metrics[name] = KinesisFirehoseMetricsData(
                    delivery_stream_name=name,
                    incoming_records_total=int(records),
                    incoming_bytes_total=int(total_bytes),
                    period_days=days,
                    is_idle=int(records) == 0 and int(total_bytes) == 0,
                )
            else:
                metrics[name] = KinesisFirehoseMetricsData(
                    delivery_stream_name=name,
                    period_days=days,
                )
        return metrics

    # =========================================================================
    # MSK
    # =========================================================================

    async def get_msk_clusters(self) -> List[MSKClusterData]:
        """Get MSK clusters from the export.

        Handles both list-clusters (v1, flat) and list-clusters-v2
        (nested under 'Provisioned') response formats.
        """
        clusters = []

        for c in self._get_data('msk_clusters'):
            # list-clusters-v2 nests fields under 'Provisioned'
            provisioned = c.get('Provisioned', {})

            # broker count: v2 nests under Provisioned, v1 is flat
            broker_count = (
                provisioned.get('NumberOfBrokerNodes')
                or c.get('NumberOfBrokerNodes', 3)
            )
            # instance type: v2 nests under Provisioned.BrokerNodeGroupInfo
            broker_info = (
                provisioned.get('BrokerNodeGroupInfo')
                or c.get('BrokerNodeGroupInfo', {})
            )
            instance_type = broker_info.get('InstanceType', 'kafka.m5.large')

            clusters.append(MSKClusterData(
                cluster_name=c.get('ClusterName', ''),
                cluster_arn=c.get('ClusterArn', ''),
                broker_count=broker_count,
                instance_type=instance_type,
                cluster_type=c.get('ClusterType', 'PROVISIONED'),
                state=c.get('State', 'ACTIVE'),
                tags=c.get('Tags', {}),
                # CLO-457: list-clusters(-v2) both return CreationTime.
                creation_time=self._parse_datetime(c.get('CreationTime')),
            ))

        return clusters

    async def get_msk_metrics(
        self,
        cluster_name: str,
        days: int = 7,
        created: Optional[datetime] = None,
        broker_count: Optional[int] = None,
    ) -> Optional[MSKMetrics]:
        """Get MSK metrics from the export.

        CLO-457: ``created`` is accepted but cannot be applied: the export
        holds window averages, not timestamped datapoints. The idle
        detector's minimum-age rule is the defence here.
        CLO-549: ``broker_count`` is accepted and unused here (the export
        holds one series per cluster, not per broker).

        Reads consolidated msk_messages_metrics, msk_bytes_in_metrics,
        msk_bytes_out_metrics, and msk_cpu_metrics produced by the
        upload service from the per-cluster CloudWatch metric files
        collected by cloudwise-export.sh.
        """
        # Look up each metric type for this cluster
        messages_in = 0.0
        bytes_in = 0.0
        bytes_out = 0.0
        cpu_user = 0.0
        found_any = False

        for metric_key, field_name in [
            ('msk_messages_metrics', 'messages_in'),
            ('msk_bytes_in_metrics', 'bytes_in'),
            ('msk_bytes_out_metrics', 'bytes_out'),
            ('msk_cpu_metrics', 'cpu_user'),
        ]:
            for entry in self._get_data(metric_key):
                if entry.get('cluster_name') == cluster_name:
                    found_any = True
                    avg_val = entry.get('avg', entry.get('cpu_avg', 0.0))
                    if field_name == 'messages_in':
                        messages_in = avg_val
                    elif field_name == 'bytes_in':
                        bytes_in = avg_val
                    elif field_name == 'bytes_out':
                        bytes_out = avg_val
                    elif field_name == 'cpu_user':
                        cpu_user = avg_val
                    break

        if not found_any:
            return None

        return MSKMetrics(
            messages_in_per_sec=round(messages_in, 2),
            bytes_in_per_sec=round(bytes_in, 2),
            bytes_out_per_sec=round(bytes_out, 2),
            cpu_user=round(cpu_user, 2),
            period_days=days,
            is_idle=messages_in == 0 and bytes_in == 0,
        )

    # =========================================================================
    # AMIs
    # =========================================================================

    async def get_amis(self) -> List[AMIData]:
        """Get AMIs from the export."""
        amis = []

        for image in self._get_data('amis'):
            creation_date = self._parse_datetime(image.get('CreationDate'))

            amis.append(AMIData(
                image_id=image.get('ImageId', ''),
                name=image.get('Name'),
                state=image.get('State', ''),
                region=image.get('region', self._region),
                creation_date=creation_date,
                description=image.get('Description'),
                tags=self._get_tag_dict(image.get('Tags', [])),
            ))

        return amis

    # =========================================================================
    # ECS / Fargate
    # =========================================================================

    def get_ecs_clusters(self) -> List[Dict[str, Any]]:
        """Get ECS clusters from exported data."""
        return self._get_data('ecs_clusters')

    @staticmethod
    def _ecs_cluster_name(arn: str) -> str:
        """The cluster name of a cluster ARN (or a bare name)."""
        return arn.split('/')[-1] if isinstance(arn, str) else ''

    def get_ecs_services(self, cluster_arn: str) -> List[Dict[str, Any]]:
        """Get ECS services from exported data, filtered by cluster.

        CLO-551: matched on the exact cluster name. The substring match it
        replaces gave cluster "prod" the services of "prod-eu" too, which
        hid a cluster's missing services from :meth:`ecs_services_unread`."""
        cluster_name = self._ecs_cluster_name(cluster_arn)
        return [
            s for s in self._get_data('ecs_services')
            if isinstance(s, dict) and s.get('clusterArn')
            and self._ecs_cluster_name(s.get('clusterArn')) == cluster_name
        ]

    # The failure reason cloudwise-export.sh writes for a failed ECS read.
    ECS_EXPORT_READ_FAILED = 'CLOUDWISE_EXPORT_READ_FAILED'

    def ecs_services_unread(self, cluster_arn: str) -> Optional[str]:
        """Why the exported services of ``cluster_arn`` are not its complete
        service list, or None (CLO-551; see the base method).

        - ecs_services.json not exported.
        - A failure entry for the cluster (1.20.0+ writes one carrying the
          ``clusterArn`` when list-services or describe-services fails).
        - A failure entry without a cluster (1.19.0) or a ``{}`` entry
          (older exports' describe-services fallback): the failed read
          cannot be placed, so every cluster is incomplete.
        - Any version: fewer ACTIVE services exported than the cluster's
          ``activeServicesCount`` (from describe-clusters). Older exports
          wrote nothing for a cluster whose list-services failed; this is
          that read."""
        raw = self._export_data.get('ecs_services')
        if not isinstance(raw, dict) or not isinstance(raw.get('services'), list):
            return 'services not exported'
        cluster_name = self._ecs_cluster_name(cluster_arn)
        for response in raw['services']:
            if not isinstance(response, dict) or not response:
                return 'service read failed (unattributed)'
            for failure in response.get('failures') or []:
                if not isinstance(failure, dict) or failure.get('reason') != self.ECS_EXPORT_READ_FAILED:
                    continue
                failed_cluster = failure.get('clusterArn')
                if not failed_cluster:
                    return 'service read failed (unattributed)'
                if self._ecs_cluster_name(failed_cluster) == cluster_name:
                    return 'service read failed'
        for cluster in self.get_ecs_clusters():
            if self._ecs_cluster_name(cluster.get('clusterArn') or cluster.get('clusterName', '')) != cluster_name:
                continue
            expected = cluster.get('activeServicesCount')
            if isinstance(expected, int) and not isinstance(expected, bool):
                active = sum(
                    1 for s in self.get_ecs_services(cluster_arn) if s.get('status') == 'ACTIVE'
                )
                if active < expected:
                    return 'fewer services exported than the cluster reports'
            break
        return None

    def get_ecs_task_definition(self, task_definition_arn: str) -> Optional[Dict[str, Any]]:
        """Get task definition from exported data.

        CLO-541: the export script writes ``ecs_task_definitions.json``
        (``{"taskDefinitions": [<describe-task-definition output>, ...]}``),
        matched here by ARN. The per-family ``ecs_taskdef_<family>`` key is
        still read when present; it went through ``_get_data``, which turns
        a dict into a list, so it never matched before."""
        for entry in self._get_data('ecs_task_definitions'):
            td = entry.get('taskDefinition', entry) if isinstance(entry, dict) else None
            if isinstance(td, dict) and td.get('taskDefinitionArn') == task_definition_arn:
                return td
        family = task_definition_arn.split('/')[-1].rsplit(':', 1)[0]
        data = self._export_data.get(f'ecs_taskdef_{family}')
        if isinstance(data, dict):
            return data.get('taskDefinition', data) if 'taskDefinition' in data else data if 'cpu' in data else None
        return None

    def get_ecs_metrics(
        self, cluster_name: str, service_name: str,
        metric_name: str, days: int = 7,
    ) -> Optional[Dict[str, float]]:
        """Get ECS CloudWatch metrics from exported data.

        CLO-546, as online: the mean of the Averages and the max of the
        Maximums, only when the series covers 75% of the window's hours. The
        export's period is not recorded, so coverage counts the distinct UTC
        hours the datapoints' Timestamps fall in (a daily or window-long
        series covers few hours and is withheld); datapoints without a
        parseable Timestamp cannot show coverage and are withheld, not
        guessed. Empty or under-covered is MISSING (noted), never 0% use
        (CLO-541: empty used to read as idle)."""
        key = f'cloudwatch_ecs_{metric_name.lower()}_{cluster_name}_{service_name}'
        data = self._export_data.get(key)
        if not (isinstance(data, dict) and 'Datapoints' in data):
            return None
        datapoints = data['Datapoints'] or []
        hours = set()
        for dp in datapoints:
            ts = self._parse_datetime(dp.get('Timestamp')) if isinstance(dp, dict) else None
            if ts is not None:
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                hours.add(ts.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0))
        if not has_min_coverage(len(hours), days, 3600):
            self._note_idle_verdict_missing(
                'ecs', f"{cluster_name}/{service_name}",
                f"{metric_name} under 75% hourly coverage ({len(hours)} hours)",
                verdict='oversized', evidence='hourly utilization metrics',
            )
            return None
        return summarize_ecs_utilization([dp for dp in datapoints if isinstance(dp, dict)])

    def get_ecs_autoscaling_targets(self, cluster_name: str) -> Optional[List[Dict[str, Any]]]:
        """Auto-scaling targets for a cluster's services from exported data,
        or None when the export holds no usable read (MISSING, CLO-550).

        - Not exported (export 1.19.0+ leaves a 0-byte file when
          describe-scalable-targets fails, which the upload parser skips):
          MISSING.
        - An empty ``ScalableTargets`` from an export older than 1.19.0
          (``legacy_failed_reads``): that script wrote the same document when
          the call failed, and a real empty response carries no other key to
          tell them apart, so it is MISSING too. A non-empty list is real.
        """
        raw = self._export_data.get('ecs_autoscaling_targets')
        if raw is None:
            return None
        all_targets = self._get_data('ecs_autoscaling_targets')
        if not all_targets and self._legacy_failed_reads:
            return None
        # CLO-551: a pre-1.20.0 anonymized export hashed the whole ResourceId.
        if self._scalable_ids_unreadable(all_targets, 'service/'):
            return None
        return [
            t for t in all_targets
            if t['ResourceId'].startswith(f'service/{cluster_name}/')
        ]

    def get_ecs_container_insights_status(self, cluster_name: str) -> bool:
        """Check Container Insights from exported cluster data."""
        clusters = self.get_ecs_clusters()
        for cluster in clusters:
            if cluster.get('clusterName') == cluster_name:
                for setting in cluster.get('settings', []):
                    if (setting.get('name') == 'containerInsights' and
                            setting.get('value') == 'enabled'):
                        return True
        return False

    def get_eks_clusters(self) -> List[EKSClusterData]:
        """Get EKS clusters from exported data."""
        clusters: List[EKSClusterData] = []
        data = self._get_data('eks_clusters')
        for cluster in data:
            if not isinstance(cluster, dict):
                continue

            created_at = (
                self._parse_datetime(cluster.get('createdAt'))
                or self._parse_datetime(cluster.get('created_at'))
            )

            clusters.append(EKSClusterData(
                cluster_name=cluster.get('name', cluster.get('clusterName', '')),
                version=str(cluster.get('version', '')),
                status=cluster.get('status', 'ACTIVE'),
                region=cluster.get('region', self._region),
                platform_version=cluster.get('platformVersion', ''),
                cluster_arn=cluster.get('arn', ''),
                created_at=created_at,
            ))

        return clusters

    # =========================================================================
    # Glue
    # =========================================================================

    def get_glue_jobs(self) -> List[Dict[str, Any]]:
        """Get Glue jobs from exported data."""
        return self._get_data('glue_jobs')

    def get_glue_job_runs(self, job_name: str, max_results: int = 10) -> Optional[List[Dict[str, Any]]]:
        """A job's recent runs from exported data; [] is a measured "never
        ran", None means the run history is MISSING (CLO-551).

        Before export 1.20.0 the ``glue_job_runs_<job>.json`` file was removed
        both when get-job-runs failed and when the job had no runs, so an
        absent file is not "no runs" in any export. 1.20.0+ keeps the
        ``{"JobRuns": []}`` of a job that never ran and leaves a 0-byte file
        (skipped by the upload parser) when the read fails."""
        data = self._export_data.get(f'glue_job_runs_{job_name}')
        if isinstance(data, dict):
            data = data.get('JobRuns')
        if not isinstance(data, list):
            return None
        return data[:max_results]

    def get_glue_crawlers(self) -> List[Dict[str, Any]]:
        """Get crawlers from exported data."""
        return self._get_data('glue_crawlers')

    def get_glue_catalog_stats(self) -> Optional[Dict[str, Any]]:
        """Get catalog stats from exported data."""
        data = self._get_data('glue_catalog_stats')
        if isinstance(data, dict) and 'databases' in data:
            return data
        return None

    def get_glue_metrics(self, job_name: str, metric_name: str, days: int = 14) -> Optional[float]:
        """Get Glue CloudWatch metric from exported data."""
        key = f'cloudwatch_glue_{job_name}_{metric_name}'
        data = self._get_data(key)
        if isinstance(data, dict) and 'Datapoints' in data:
            datapoints = data['Datapoints']
            if datapoints:
                return sum(dp.get('Average', 0) for dp in datapoints) / len(datapoints)
        return None

    # =========================================================================
    # Transfer Family
    # =========================================================================

    def get_transfer_servers(self) -> List[Dict[str, Any]]:
        """Get Transfer servers from exported data."""
        return self._get_data('transfer_servers')

    def get_transfer_server_users(self, server_id: str) -> Optional[List[Dict[str, Any]]]:
        """Users of a Transfer server from exported data, or None when the
        export holds no successful ``list-users`` read (MISSING).

        The export writes ``aws transfer list-users`` output as is:
        ``{"ServerId": ..., "Users": [...]}``. ``_get_data``'s generic
        extraction does not know that two-key shape and returned [], so every
        exported server with users read as user-less (CLO-546 follow-up,
        found by the parser test).

        CLO-550: a failed read must not read as "no users".
        - Export 1.19.0+ leaves a 0-byte file when list-users fails; the
          upload parser skips it, so the key is absent: MISSING.
        - Older exports wrote ``{"Users": []}`` on failure. A real response
          always carries ``ServerId`` (a required member of the ListUsers
          output and a non-aggregate key of its paginator, so the CLI keeps
          it across pages; ``--anonymize`` pseudonymizes the value, not the
          key). An empty ``Users`` list without ``ServerId`` is therefore
          that fallback: MISSING. ``{"ServerId": ..., "Users": []}`` is a
          measured empty."""
        data = self._export_data.get(f'transfer_users_{server_id}')
        if isinstance(data, list):
            return data
        if not isinstance(data, dict) or not isinstance(data.get('Users'), list):
            return None
        if not data['Users'] and 'ServerId' not in data:
            return None
        return data['Users']

    def get_transfer_web_apps(self) -> List[Dict[str, Any]]:
        """Get Transfer Web Apps from exported data."""
        return self._get_data('transfer_web_apps')

    def get_transfer_metrics(
        self, server_id: str, metric_name: str, days: int = 30,
        protocol: Optional[str] = None
    ) -> CounterRead:
        """An exported AWS/Transfer counter for a server, as a
        :class:`CounterRead` (CLO-546 follow-up, CLO-485's upload-parser
        convention): an exported series with no datapoints is EMPTY (a
        measured zero for a counter); a series not exported is MISSING.

        Two shapes are read: ``cloudwatch_transfer_<metric>_<id>[_<proto>]``
        (any metric or protocol), and what cloudwise-export.sh actually
        writes, ``cloudwatch_metrics/transfer_files_<id>.json``: the
        server-level FilesIn series only, which the upload parser keeps raw
        under its file stem ``transfer_files_<id>`` (it used to drop it: the
        prefix was claimed with no consolidation pattern). That file answers
        FilesIn alone; FilesOut and per-protocol series are not exported, so
        they are MISSING. A failed export read leaves a 0-byte file, which
        the parser skips: MISSING, not zero."""
        suffix = f"_{protocol.lower()}" if protocol else ""
        series = self._transfer_series(
            f'cloudwatch_transfer_{metric_name.lower()}_{server_id}{suffix}')
        if series is None and metric_name == 'FilesIn' and not protocol:
            series = self._transfer_series(f'transfer_files_{server_id}')
        if series is None:
            label = f"{metric_name} {protocol}" if protocol else metric_name
            return CounterRead.missing(f"{label} not in export")
        return CounterRead.from_datapoints(series)

    def _transfer_series(self, key: str) -> Optional[List[Dict[str, Any]]]:
        """The ``Datapoints`` list of an exported CloudWatch response under
        ``key`` (possibly empty), or None when it was not exported."""
        data = self._export_data.get(key)
        if isinstance(data, dict) and isinstance(data.get('Datapoints'), list):
            return data['Datapoints']
        return None

    def get_transfer_web_app_metrics(
        self, web_app_id: str, metric_name: str, days: int = 30
    ) -> CounterRead:
        """An exported AWS/Transfer web-app counter, as a :class:`CounterRead`.
        An exported empty series is EMPTY; none exported (cloudwise-export.sh
        writes no web-app series) is MISSING."""
        series = self._transfer_series(
            f'cloudwatch_transfer_webapp_{metric_name.lower()}_{web_app_id}')
        if series is None:
            return CounterRead.missing(f"{metric_name} not in export")
        return CounterRead.from_datapoints(series)

    # =========================================================================
    # AWS Backup
    # =========================================================================

    def _backup_recovery_points_gap(self) -> Optional[str]:
        """Why the exported recovery points are not the complete set, or
        None (CLO-551; see ``backup_recovery_points_unread``).

        - Not exported: 1.20.0+ leaves a 0-byte file when list-backup-vaults
          fails; older exports have no backup data at all.
        - No vault list: export 1.19.0 left a 0-byte backup_vaults.json on a
          failed list-backup-vaults but still wrote an empty recovery-point
          list.
        - ``FailedVaultReads`` (1.20.0+): vaults whose recovery points could
          not be listed.
        - An empty vault list in an export older than 1.19.0, which wrote
          ``{"BackupVaultList": []}`` when the call failed.
        - Any version: a vault whose ``NumberOfRecoveryPoints`` (from
          list-backup-vaults) is above 0 but has no exported recovery point.
          Older exports wrote ``{"RecoveryPoints": []}`` for a vault whose
          read failed; this is that read."""
        raw_points = self._export_data.get('backup_recovery_points')
        if not isinstance(raw_points, (dict, list)):
            return 'recovery points not exported'
        raw_vaults = self._export_data.get('backup_vaults')
        vaults = raw_vaults.get('BackupVaultList') if isinstance(raw_vaults, dict) else raw_vaults
        if not isinstance(vaults, list):
            return 'vault list not read'
        failed = raw_points.get('FailedVaultReads') if isinstance(raw_points, dict) else None
        if isinstance(failed, int) and failed > 0:
            return 'vault recovery-point read failed'
        if not vaults and self._legacy_failed_reads:
            return 'empty vault list in an export older than 1.19.0'
        vaults_with_points = {
            rp.get('BackupVaultName') for rp in self._get_data('backup_recovery_points')
            if isinstance(rp, dict)
        }
        for vault in vaults:
            if not isinstance(vault, dict):
                continue
            count = vault.get('NumberOfRecoveryPoints')
            if isinstance(count, int) and count > 0 and vault.get('BackupVaultName') not in vaults_with_points:
                return 'vault recovery-point read failed'
        return None

    async def get_backup_recovery_points(self) -> List[BackupRecoveryPointData]:
        """Get recovery points from exported data. CLO-551: the list may be
        partial; :meth:`backup_recovery_points_unread` says why."""
        recovery_points: List[BackupRecoveryPointData] = []
        now = datetime.now(timezone.utc)
        self._backup_recovery_points_unread = self._backup_recovery_points_gap()
        data = self._get_data('backup_recovery_points')
        if not data:
            return []
        for rp in data:
            creation_str = rp.get('CreationDate') or rp.get('creation_date')
            creation = self._parse_datetime(creation_str) if creation_str else None
            age_days = (now - creation).days if creation else 0
            recovery_points.append(BackupRecoveryPointData(
                recovery_point_arn=rp.get('RecoveryPointArn', rp.get('recovery_point_arn', '')),
                backup_vault_name=rp.get('BackupVaultName', rp.get('backup_vault_name', '')),
                backup_vault_arn=rp.get('BackupVaultArn', rp.get('backup_vault_arn', '')),
                resource_arn=rp.get('ResourceArn', rp.get('resource_arn', '')),
                resource_type=rp.get('ResourceType', rp.get('resource_type', '')),
                status=rp.get('Status', rp.get('status', 'COMPLETED')),
                creation_date=creation,
                backup_size_bytes=rp.get('BackupSizeInBytes', rp.get('backup_size_bytes')),
                lifecycle=rp.get('Lifecycle', rp.get('lifecycle')),
                is_encrypted=rp.get('IsEncrypted', rp.get('is_encrypted', False)),
                # CLO-514: the API puts the plan id under CreatedBy.
                backup_plan_id=recovery_point_plan_id(rp),
                age_days=age_days,
                is_parent=rp.get('IsParent', rp.get('is_parent', False)),
                parent_recovery_point_arn=rp.get('ParentRecoveryPointArn'),
            ))
        return recovery_points

    async def get_backup_plans(self) -> List[BackupPlanData]:
        """Get backup plans from exported data."""
        plans: List[BackupPlanData] = []
        data = self._get_data('backup_plans')
        if not data:
            return []
        for plan in data:
            creation_str = plan.get('CreationDate') or plan.get('creation_date')
            creation = self._parse_datetime(creation_str) if creation_str else None
            last_exec_str = plan.get('LastExecutionDate') or plan.get('last_execution_date')
            last_exec = self._parse_datetime(last_exec_str) if last_exec_str else None
            plans.append(BackupPlanData(
                backup_plan_id=plan.get('BackupPlanId', plan.get('backup_plan_id', '')),
                backup_plan_name=plan.get('BackupPlanName', plan.get('backup_plan_name', '')),
                backup_plan_arn=plan.get('BackupPlanArn', plan.get('backup_plan_arn', '')),
                version_id=plan.get('VersionId', plan.get('version_id')),
                creation_date=creation,
                last_execution_date=last_exec,
                rules=plan.get('Rules', plan.get('rules', [])),
            ))
        return plans

    async def get_backup_selections(self, plan_id: str) -> List[BackupSelectionData]:
        """Get backup selections from exported data."""
        selections: List[BackupSelectionData] = []
        key = f'backup_selections_{plan_id}'
        data = self._get_data(key)
        if not data:
            return []
        for sel in data:
            body = sel.get('BackupSelection', sel)
            selections.append(BackupSelectionData(
                selection_id=sel.get('SelectionId', sel.get('selection_id', '')),
                selection_name=body.get('SelectionName', body.get('selection_name', '')),
                backup_plan_id=plan_id,
                iam_role_arn=body.get('IamRoleArn', body.get('iam_role_arn', '')),
                resources=body.get('Resources', body.get('resources', [])),
                list_of_tags=body.get('ListOfTags', body.get('list_of_tags', [])),
                conditions=body.get('Conditions', body.get('conditions')),
                not_resources=body.get('NotResources', body.get('not_resources', [])),
            ))
        return selections

    async def get_backup_copy_jobs(self, days: int = 90) -> List[BackupCopyJobSummary]:
        """Get copy job summaries from exported data."""
        jobs: List[BackupCopyJobSummary] = []
        data = self._get_data('backup_copy_jobs')
        if not data:
            return []
        for job in data:
            creation_str = job.get('CreationDate') or job.get('creation_date')
            creation = self._parse_datetime(creation_str) if creation_str else None
            jobs.append(BackupCopyJobSummary(
                source_backup_vault_arn=job.get('SourceBackupVaultArn', job.get('source_backup_vault_arn', '')),
                destination_backup_vault_arn=job.get('DestinationBackupVaultArn', job.get('destination_backup_vault_arn', '')),
                resource_type=job.get('ResourceType', job.get('resource_type', '')),
                state=job.get('State', job.get('state', 'COMPLETED')),
                creation_date=creation,
                backup_size_bytes=job.get('BackupSizeInBytes', job.get('backup_size_bytes')),
            ))
        return jobs

    # =========================================================================
    # DocumentDB
    # =========================================================================

    async def get_documentdb_clusters(self) -> List[DocumentDBClusterData]:
        """Get DocumentDB clusters from exported data."""
        clusters: List[DocumentDBClusterData] = []
        data = self._get_data('documentdb_clusters')
        if not data:
            return []
        for c in data:
            if c.get('Engine') != 'docdb':
                continue
            members = c.get('DBClusterMembers', [])
            tag_list = c.get('TagList', [])
            tags = {t['Key']: t['Value'] for t in tag_list if 'Key' in t and 'Value' in t}
            clusters.append(DocumentDBClusterData(
                cluster_identifier=c.get('DBClusterIdentifier', ''),
                status=c.get('Status', 'available'),
                engine=c.get('Engine', 'docdb'),
                engine_version=c.get('EngineVersion', ''),
                db_cluster_members=members,
                instance_class=c.get('DBInstanceClass', ''),
                num_instances=len(members),
                storage_encrypted=c.get('StorageEncrypted', False),
                deletion_protection=c.get('DeletionProtection', False),
                tags=tags,
                cluster_create_time=self._parse_datetime(c.get('ClusterCreateTime')),
            ))
        return clusters

    async def get_documentdb_snapshots(self, snapshot_type: str = "manual") -> List[DocumentDBSnapshotData]:
        """Get DocumentDB snapshots from exported data."""
        snapshots: List[DocumentDBSnapshotData] = []
        data = self._get_data('documentdb_snapshots')
        if not data:
            return []
        now = datetime.now(timezone.utc)
        for s in data:
            if s.get('Engine') != 'docdb':
                continue
            snap_type = s.get('SnapshotType', 'manual')
            if snapshot_type and snap_type != snapshot_type:
                continue
            created_str = s.get('SnapshotCreateTime')
            created = self._parse_datetime(created_str) if created_str else None
            age_days = (now - created).days if created else 0
            tag_list = s.get('TagList', [])
            tags = {t['Key']: t['Value'] for t in tag_list if 'Key' in t and 'Value' in t}
            snapshots.append(DocumentDBSnapshotData(
                snapshot_identifier=s.get('DBClusterSnapshotIdentifier', ''),
                cluster_identifier=s.get('DBClusterIdentifier', ''),
                status=s.get('Status', 'available'),
                snapshot_type=snap_type,
                engine=s.get('Engine', 'docdb'),
                engine_version=s.get('EngineVersion', ''),
                snapshot_create_time=created,
                storage_encrypted=s.get('StorageEncrypted', False),
                allocated_storage=s.get('AllocatedStorage', 0),
                age_days=age_days,
                tags=tags,
            ))
        return snapshots

    async def get_documentdb_cluster_metrics(
        self, cluster_id: str, days: int = 14, cluster_create_time: Optional[datetime] = None,
    ) -> Optional[DocumentDBMetricsData]:
        """Get DocumentDB metrics from exported CloudWatch data (if available).

        CLO-500. The export (cloudwise-export.sh, every version) collects one
        DocumentDB series: hourly ``DatabaseConnections`` with
        ``--statistics Maximum`` over its CloudWatch window. This used to
        average an ``Average`` field the export never carries, defaulting it
        to 0, so ANY exported cluster, busy or not, read as idle; and it
        judged idle on however few hours there were. It also read only the
        raw ``docdb_connections_<id>`` key, which the upload consolidator
        dropped, so after an upload it never saw anything at all.

        Now: each hour's connection count is its Maximum (Average only for a
        synthetic series without one; a missing statistic is never a 0).
        DatabaseConnections is a gauge, so one hour with a non-zero Maximum
        proves the cluster was used (busy, whatever the coverage). Idle needs
        every observed hour at zero AND the hours to cover 75% of the window
        (#1479's gate; the window is the detector's, capped at the days the
        export collected). Missing or sparse data is not idle: the verdict
        is withheld with a ``data_warnings`` note (MISSING, not zero).

        The raw key is read first (it carries timestamps, so CLO-457 can
        drop a deleted namesake's hours); the upload's consolidated
        ``docdb_connection_metrics`` row ({cluster_identifier,
        datapoints_count, max}) is the fallback, pre-aggregated with no
        timestamps. The export carries no IOPS or CPU for DocumentDB, so
        ``is_overprovisioned`` is always False offline."""
        window_days = max(1, min(days, self._export_cloudwatch_days()))

        hours: Optional[int] = None
        peak: Optional[float] = None
        raw = self._export_data.get(f'docdb_connections_{cluster_id}')
        if isinstance(raw, dict):
            # CLO-457: drop hours from before the cluster existed, which a
            # reused DBClusterIdentifier inherits from its deleted predecessor.
            datapoints = drop_pre_creation_datapoints(
                raw.get('Datapoints', []), cluster_create_time, 3600,
            )
            values = [
                float(dp['Maximum'] if dp.get('Maximum') is not None else dp['Average'])
                for dp in datapoints
                if dp.get('Maximum') is not None or dp.get('Average') is not None
            ]
            hours = len(values)
            peak = max(values) if values else None
        else:
            for row in self._get_data('docdb_connection_metrics'):
                rid = row.get('cluster_identifier') or row.get('DBClusterIdentifier')
                if rid != cluster_id:
                    continue
                row_peak = row.get('max') if row.get('max') is not None else row.get('Maximum')
                if row_peak is None:
                    row_peak = row.get('avg') if row.get('avg') is not None else row.get('Average')
                if row_peak is not None:
                    hours = int(row.get('datapoints_count') or 0)
                    peak = float(row_peak)
                break

        if not hours or peak is None:
            self._note_idle_verdict_missing(
                'documentdb', cluster_id,
                "no DatabaseConnections datapoints" if isinstance(raw, dict)
                else "DatabaseConnections not in export",
            )
            return None

        if peak > 0:
            # At least one connection in an observed hour: busy.
            return DocumentDBMetricsData(
                cluster_identifier=cluster_id,
                database_connections=peak,  # peak hourly Maximum; no average is exported
                period_days=window_days,
                is_idle=False,
                is_overprovisioned=False,
            )

        if not has_min_coverage(hours, window_days, 3600):
            self._note_idle_verdict_missing(
                'documentdb', cluster_id, "DatabaseConnections under 75% coverage",
            )
            return None

        return DocumentDBMetricsData(
            cluster_identifier=cluster_id,
            database_connections=0.0,
            period_days=window_days,
            is_idle=True,
            is_overprovisioned=False,
        )

    # =========================================================================
    # FSx
    # =========================================================================

    async def get_fsx_filesystems(self) -> List[FSxFilesystemData]:
        """Get FSx filesystems from exported data."""
        filesystems: List[FSxFilesystemData] = []
        data = self._get_data('fsx_filesystems')
        if not data:
            return []
        for fs in data:
            tag_list = fs.get('Tags', [])
            tags = {t['Key']: t['Value'] for t in tag_list if 'Key' in t and 'Value' in t}
            fstype = fs.get('FileSystemType', '')
            # CLO-512: deployment type (it sets the price) was never read.
            config = fsx_filesystem_config(fs)
            creation_str = fs.get('CreationTime')
            creation_time = self._parse_datetime(creation_str) if creation_str else None
            filesystems.append(FSxFilesystemData(
                filesystem_id=fs.get('FileSystemId', ''),
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
        return filesystems

    async def get_fsx_backups(self) -> List[FSxBackupData]:
        """Get FSx backups from exported data."""
        backups: List[FSxBackupData] = []
        data = self._get_data('fsx_backups')
        if not data:
            return []
        now = datetime.now(timezone.utc)
        for b in data:
            created_str = b.get('CreationTime')
            created = self._parse_datetime(created_str) if created_str else None
            age_days = (now - created).days if created else 0
            fs_info = b.get('FileSystem', {})
            tag_list = b.get('Tags', [])
            tags = {t['Key']: t['Value'] for t in tag_list if 'Key' in t and 'Value' in t}
            backups.append(FSxBackupData(
                backup_id=b.get('BackupId', ''),
                filesystem_id=fs_info.get('FileSystemId', ''),
                filesystem_type=fs_info.get('FileSystemType', ''),
                lifecycle=b.get('Lifecycle', 'AVAILABLE'),
                backup_type=b.get('Type', 'USER_INITIATED'),
                creation_time=created,
                age_days=age_days,
                tags=tags,
                size_bytes=b.get('SizeInBytes'),
            ))
        return backups

    def _note_fsx_storage_missing(self, filesystem_id: str) -> None:
        """CLO-540: no export carries an FSx storage-capacity series, so
        free_storage_capacity_gb stays None and oversized_fsx is withheld
        (MISSING, noted), never judged from a 0 free default."""
        self._note_idle_verdict_missing(
            'fsx storage', filesystem_id, 'not in export',
            verdict='oversized', evidence='storage capacity metrics',
        )

    async def get_fsx_filesystem_metrics(
        self, filesystem_id: str, days: int = 7, filesystem_type: Optional[str] = None,
    ) -> Optional[FSxMetricsData]:
        """Get FSx metrics from exported CloudWatch data (if available).

        CLO-512: export 1.18.0+ writes ``fsx_activity.json``: per file
        system, hourly DataReadBytes + DataWriteBytes totals, the busiest
        hour (read + write) and the hour count. It is a resource file, not a
        ``cloudwatch_metrics/`` file, so the upload parser hands it over as
        exported. A failed read, or no datapoints at all, is MISSING (None,
        noted in data_warnings), never zero I/O, as online.

        Older exports only have ``fsx_data_<id>`` (daily DataReadBytes),
        which the upload parser never passed through (no consolidation
        pattern), so in practice those exports had no FSx metrics.
        """
        for entry in self._get_data('fsx_activity'):
            if not isinstance(entry, dict) or entry.get('FileSystemId') != filesystem_id:
                continue
            if entry.get('error'):
                self._note_idle_verdict_missing(
                    'fsx', filesystem_id, f"export read failed ({entry.get('error')})",
                    evidence='DataReadBytes/DataWriteBytes datapoints',
                )
                return None
            try:
                read_bytes = int(float(entry.get('ReadBytes') or 0))
                write_bytes = int(float(entry.get('WriteBytes') or 0))
                hours = int(entry.get('HourCount') or 0)
                peak = entry.get('PeakHourBytes')
                peak_bytes = int(float(peak)) if peak is not None and hours > 0 else None
            except (TypeError, ValueError):
                return None
            if hours <= 0:
                self._note_idle_verdict_missing(
                    'fsx', filesystem_id, 'no datapoints',
                    evidence='DataReadBytes/DataWriteBytes datapoints',
                )
                return None
            self._note_fsx_storage_missing(filesystem_id)
            return FSxMetricsData(
                filesystem_id=filesystem_id,
                data_read_bytes=read_bytes,
                data_write_bytes=write_bytes,
                period_days=days,
                is_idle=(read_bytes + write_bytes) == 0,
                peak_hourly_bytes=peak_bytes,
            )
        metrics_data = self._export_data.get(f'fsx_data_{filesystem_id}')
        if not metrics_data or not isinstance(metrics_data, dict):
            return None
        datapoints = metrics_data.get('Datapoints', [])
        if not datapoints:
            self._note_idle_verdict_missing(
                'fsx', filesystem_id, 'no datapoints',
                evidence='DataReadBytes/DataWriteBytes datapoints',
            )
            return None
        total_bytes = int(sum(d.get('Sum', 0) for d in datapoints))
        is_idle = total_bytes == 0
        self._note_fsx_storage_missing(filesystem_id)
        return FSxMetricsData(
            filesystem_id=filesystem_id,
            data_read_bytes=total_bytes,
            period_days=days,
            is_idle=is_idle,
        )

    # =========================================================================
    # Step Functions
    # =========================================================================

    async def get_step_function_state_machines(self) -> List[Dict[str, Any]]:
        """Get Step Functions state machines from exported data."""
        data = self._get_data('step_functions')
        if not data:
            return []
        return data

    async def get_step_function_execution_summary(
        self, state_machine_arn: str, days: int = 14, sm_type: str = 'STANDARD'
    ) -> Optional[StepFunctionExecutionSummaryData]:
        """Get execution summary from exported data (sm_type unused offline)."""
        key = f'sfn_execution_summary_{state_machine_arn.split(":")[-1]}'
        data = self._export_data.get(key)
        if not data or not isinstance(data, dict):
            return None
        return StepFunctionExecutionSummaryData(
            state_machine_arn=state_machine_arn,
            total_executions=data.get('total_executions', 0),
            succeeded=data.get('succeeded', 0),
            failed=data.get('failed', 0),
            timed_out=data.get('timed_out', 0),
            aborted=data.get('aborted', 0),
            running=data.get('running', 0),
            period_days=days,
        )

    async def get_step_function_retry_metrics(
        self, state_machine_arn: str, days: int = 14
    ) -> Optional[StepFunctionRetryMetricsData]:
        """Get retry metrics from exported CloudWatch data."""
        sm_name = state_machine_arn.split(':')[-1]
        metrics_key = f'sfn_metrics_{sm_name}'
        data = self._export_data.get(metrics_key)
        if not data or not isinstance(data, dict):
            return None

        started = data.get('ExecutionsStarted', 0)
        failed = data.get('ExecutionsFailed', 0)
        timed_out = data.get('ExecutionsTimedOut', 0)
        transitions = data.get('StateTransition', 0)

        total_exec = started if started > 0 else 1
        failure_rate = (failed + timed_out) / total_exec
        estimated_retry = int(transitions * failure_rate) if transitions > 0 else 0
        retry_ratio = estimated_retry / transitions if transitions > 0 else 0.0

        return StepFunctionRetryMetricsData(
            state_machine_arn=state_machine_arn,
            total_transitions=transitions,
            estimated_retry_transitions=estimated_retry,
            retry_ratio=retry_ratio,
            failure_rate=failure_rate,
            period_days=days,
        )

    async def get_step_function_transition_metrics(
        self, state_machine_arn: str, days: int = 14
    ) -> Optional[StepFunctionTransitionMetricsData]:
        """Get transition density metrics from exported data."""
        sm_name = state_machine_arn.split(':')[-1]
        metrics_key = f'sfn_metrics_{sm_name}'
        data = self._export_data.get(metrics_key)
        if not data or not isinstance(data, dict):
            return None

        transitions = data.get('StateTransition', 0)
        succeeded = data.get('ExecutionsSucceeded', 0)
        started = data.get('ExecutionsStarted', 0)
        avg_duration = data.get('ExecutionTime_Average', 0.0)
        max_duration = data.get('ExecutionTime_Maximum', 0.0)

        avg_per_success = transitions / succeeded if succeeded > 0 else 0.0
        daily_rate = started / days if days > 0 else 0
        monthly_estimate = int(daily_rate * 30)

        return StepFunctionTransitionMetricsData(
            state_machine_arn=state_machine_arn,
            total_transitions=transitions,
            successful_executions=succeeded,
            avg_transitions_per_success=avg_per_success,
            p95_duration_ms=max_duration,
            avg_duration_ms=avg_duration,
            monthly_execution_estimate=monthly_estimate,
            period_days=days,
        )

    # =========================================================================
    # AppSync
    # =========================================================================

    async def get_appsync_apis(self) -> List[Dict[str, Any]]:
        """Load AppSync APIs from the export's ``appsync_apis.json``
        (CLO-552: this used to call ``self._load_json``, which isn't defined
        anywhere, so this raised AttributeError and the AppSync detectors
        never ran Air-Gapped)."""
        return self._get_data('appsync_apis')

    async def get_appsync_api_cache(self, api_id: str) -> Optional[Dict[str, Any]]:
        """Load cache config from the export's
        ``appsync_cache_<api_id>.json`` (CLO-552). None when the API has no
        cache, the file was never exported (no cache configured), or
        --anonymize removed it (CLO-554: the same ``_is_removed`` check
        ``_get_data`` uses — inlined here, not a literal ``_get_data`` call,
        because this file is a single cache-config dict, not a list
        ``_get_data``'s extraction map knows how to unwrap)."""
        key = f'appsync_cache_{api_id}'
        if self._is_removed(key):
            self._note_idle_verdict_missing(
                'appsync_idle_cache', api_id,
                f"{key}.json removed by --anonymize (CLO-554)",
                verdict='idle-cache', evidence='AppSync cache config',
            )
            return None
        data = self._export_data.get(key)
        return data.get('apiCache') if isinstance(data, dict) else None

    # AWS/AppSync publishes no CacheHitCount/CacheMissCount CloudWatch
    # metric at all. The real cache metrics are Enhanced monitoring's
    # CacheHit/CacheMiss, keyed by API_Id + Resolver — neither the export
    # nor this provider reads them. The export's appsync_cache_hits_/
    # appsync_cache_misses_ files are therefore always empty, which used to
    # read as a measured zero: appsync_idle_cache fired HIGH confidence on
    # every cached API, Air-Gapped, busy or not (CLO-577 fixes the same bug
    # online; this is the offline half, blocking review on #1616).
    _APPSYNC_UNPUBLISHED_METRICS = frozenset({'CacheHitCount', 'CacheMissCount'})

    async def get_appsync_metrics(
        self, api_id: str, metric_name: str,
        days: int = 14, statistic: str = 'Sum'
    ) -> Optional[float]:
        """Sum of an exported AppSync CloudWatch metric (CLO-552).

        cloudwise-export.sh writes these under ``cloudwatch_metrics/`` as raw
        ``get-metric-statistics`` responses; the upload parser keeps them raw
        under their file stem (like Transfer FilesIn, CLO-546), since no
        consolidation pattern claims the ``appsync_*`` prefixes. None when
        the file was never exported or the export read failed — CLO-485:
        MISSING, not zero. An exported series with no datapoints sums to
        0.0, a measured zero.

        CacheHitCount/CacheMissCount are always MISSING (see
        ``_APPSYNC_UNPUBLISHED_METRICS``): AWS never publishes them, so
        there is nothing here for an export window or an anonymize-removed
        file to change.

        CLO-552 review follow-up: the export's actual CloudWatch collection
        window (``CLOUDWATCH_PERIOD``, often 7 days) can be shorter than the
        ``days`` the caller is judging — unused_appsync asks for 30,
        appsync_idle_subscriptions for 14 (both read ``metric_name ==
        'Latency'`` for their own request-count check, so ``days`` — not
        ``metric_name`` — is what tells the two apart here). "0 requests in
        30 days" would be a false claim on a 7-day export, so this is
        MISSING rather than a claim scoped to a window the export never
        covered."""
        if metric_name in self._APPSYNC_UNPUBLISHED_METRICS:
            self._note_idle_verdict_missing(
                'appsync_idle_cache', api_id,
                'cache hit/miss metric not published by AWS (CLO-577)',
                verdict='idle-cache', evidence='AppSync cache hit/miss metrics',
            )
            return None

        # days >= 30 is unused_appsync's window; appsync_idle_subscriptions
        # always asks for 14. Both constants live in detectors/integration.py,
        # which this module cannot import (detectors depend on providers,
        # not the other way round), so this keys off the value itself.
        service_key, verdict = (
            ('unused_appsync', 'unused') if days >= 30
            else ('appsync_idle_subscriptions', 'idle-subscriptions')
        )
        export_days = self._export_cloudwatch_days()
        if export_days < days:
            self._note_idle_verdict_missing(
                service_key, api_id,
                f"export covers {export_days} days, short of the {days}-day window",
                verdict=verdict, evidence='AppSync CloudWatch metrics',
            )
            return None

        metric_file_map = {
            'Latency': f'appsync_requests_{api_id}',
            'ConnectSuccess': f'appsync_connections_{api_id}',
            'ActiveConnections': f'appsync_active_connections_{api_id}',
        }
        filename = metric_file_map.get(
            metric_name, f'appsync_{metric_name.lower()}_{api_id}'
        )
        # CLO-552 review follow-up: the same anonymize-removed check
        # _get_data performs, inlined (see get_appsync_api_cache above for
        # why this can't be a literal _get_data call).
        if self._is_removed(filename):
            self._note_idle_verdict_missing(
                service_key, api_id,
                f"{filename}.json removed by --anonymize (CLO-554)",
                verdict=verdict, evidence='AppSync CloudWatch metrics',
            )
            return None
        data = self._export_data.get(filename)
        if not isinstance(data, dict) or not isinstance(data.get('Datapoints'), list):
            return None
        return sum(
            dp.get(statistic, 0)
            for dp in data['Datapoints']
        )

    # =========================================================================
    # Aurora
    # =========================================================================

    async def get_aurora_clusters(self) -> List[AuroraClusterData]:
        """Load Aurora clusters from exported rds_clusters.json."""
        clusters: List[AuroraClusterData] = []

        # Build instance class lookup from rds_instances export
        instance_class_map: Dict[str, str] = {}
        instance_created_map: Dict[str, Any] = {}  # CLO-457
        for inst in self._get_data('rds_instances'):
            instance_class_map[inst.get('DBInstanceIdentifier', '')] = inst.get('DBInstanceClass', '')
            instance_created_map[inst.get('DBInstanceIdentifier', '')] = self._parse_datetime(
                inst.get('InstanceCreateTime')
            )

        for cluster in self._get_data('rds_clusters'):
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

            clusters.append(AuroraClusterData(
                cluster_id=cluster.get('DBClusterIdentifier', ''),
                engine=engine,
                engine_version=cluster.get('EngineVersion', ''),
                engine_mode=cluster.get('EngineMode', 'provisioned'),
                storage_type=cluster.get('StorageType', 'aurora'),
                status=cluster.get('Status', ''),
                region=self._region,
                instances=instances,
                serverless_v2_config=cluster.get('ServerlessV2ScalingConfiguration'),
                is_global_secondary=bool(
                    cluster.get('ReplicationSourceIdentifier')
                ),
                cluster_create_time=self._parse_datetime(cluster.get('ClusterCreateTime')),
            ))

        return clusters

    async def get_aurora_io_metrics(
        self, cluster_id: str, days: int = 30, cluster_create_time: Optional[datetime] = None,
    ) -> Optional[AuroraIOMetricsData]:
        """Load Aurora I/O metrics from exported CloudWatch JSON.

        CLO-457: the export reads daily datapoints (Period=86400); days from
        before ``cluster_create_time`` are dropped, since a reused
        DBClusterIdentifier inherits its predecessor's."""
        read_key = f'aurora_read_iops_{cluster_id}'
        write_key = f'aurora_write_iops_{cluster_id}'
        storage_key = f'aurora_storage_{cluster_id}'

        read_data = self._export_data.get(read_key, {})
        write_data = self._export_data.get(write_key, {})
        storage_data = self._export_data.get(storage_key, {})

        if not read_data and not write_data:
            return None

        def _own(data: dict) -> list:
            return drop_pre_creation_datapoints(
                data.get('Datapoints', []), cluster_create_time, 86400,
            )

        read_sum = sum(dp.get('Sum', 0) for dp in _own(read_data))
        write_sum = sum(dp.get('Sum', 0) for dp in _own(write_data))
        datapoints = _own(storage_data)
        storage_avg = (
            sum(dp.get('Average', 0) for dp in datapoints) / max(len(datapoints), 1)
        )

        return AuroraIOMetricsData(
            cluster_id=cluster_id,
            volume_read_iops_sum=read_sum,
            volume_write_iops_sum=write_sum,
            volume_bytes_used_avg=storage_avg,
            period_days=days,
        )

    # ─── Neptune ──────────────────────────────────────────────────────

    async def get_neptune_clusters(self) -> List[NeptuneClusterData]:
        """Load Neptune clusters from exported JSON."""
        clusters_raw = self._get_data('neptune_clusters')
        instances_raw = self._get_data('neptune_instances')

        # Build instance class lookup from neptune_instances.json
        instance_class_map = {
            inst.get('DBInstanceIdentifier', ''): inst.get('DBInstanceClass', '')
            for inst in instances_raw
        }

        clusters = []
        for cluster in clusters_raw:
            if cluster.get('Engine') != 'neptune':
                continue

            instances = []
            for member in cluster.get('DBClusterMembers', []):
                inst_id = member.get('DBInstanceIdentifier', '')
                instances.append(NeptuneClusterInstanceRef(
                    db_instance_id=inst_id,
                    db_instance_class=instance_class_map.get(inst_id, 'unknown'),
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
                cluster_create_time=self._parse_datetime(cluster.get('ClusterCreateTime')),
            ))

        return clusters

    async def get_neptune_snapshots(
        self, snapshot_type: str = 'manual', age_threshold_days: int = 90
    ) -> List[NeptuneSnapshotData]:
        """Load Neptune snapshots from exported JSON."""
        snapshots_raw = self._get_data('neptune_snapshots')
        snapshots = []
        now = datetime.now(timezone.utc)
        threshold = now - timedelta(days=age_threshold_days)

        for snap in snapshots_raw:
            if snap.get('Engine') != 'neptune':
                continue
            if snapshot_type and snap.get('SnapshotType') != snapshot_type:
                continue

            create_time = self._parse_datetime(snap.get('SnapshotCreateTime'))
            if not create_time or create_time > threshold:
                continue

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

        return snapshots

    async def get_neptune_cluster_metrics(
        self, cluster_id: str, days: int = 14, cluster_create_time: Optional[datetime] = None,
    ) -> Optional[NeptuneMetricsData]:
        """Load Neptune cluster metrics from exported CloudWatch JSON."""
        gremlin_key = f'neptune_requests_{cluster_id}'
        sparql_key = f'neptune_sparql_{cluster_id}'
        cpu_key = f'neptune_cpu_{cluster_id}'

        gremlin_data = self._export_data.get(gremlin_key, {})
        sparql_data = self._export_data.get(sparql_key, {})
        cpu_data = self._export_data.get(cpu_key, {})

        if not gremlin_data and not sparql_data and not cpu_data:
            return None

        # CLO-457: drop datapoints from before the cluster existed (a reused
        # DBClusterIdentifier inherits its predecessor's). The export reads
        # requests daily (Period=86400) and CPU hourly (Period=3600).
        gremlin_requests = int(sum(
            dp.get('Sum', 0) for dp in drop_pre_creation_datapoints(
                gremlin_data.get('Datapoints', []), cluster_create_time, 86400,
            )
        ))
        sparql_requests = int(sum(
            dp.get('Sum', 0) for dp in drop_pre_creation_datapoints(
                sparql_data.get('Datapoints', []), cluster_create_time, 86400,
            )
        ))
        # The export collects hourly CPU (Period=3600, Average + Maximum), so
        # the shared CPU rule (cpu_sizing, CLO-480) applies offline too.
        cpu = summarize_hourly_cpu(drop_pre_creation_datapoints(
            cpu_data.get('Datapoints', []), cluster_create_time, 3600,
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
            # The coverage gate is measured against the window the export
            # actually collected, not the one the detector asked for: the
            # export script collects 7 days (CLOUDWATCH_PERIOD) while
            # oversized_neptune asks for 14, and 168 of 336 hours would veto
            # every air-gapped cluster.
            cpu_window_days=min(days, self._export_cloudwatch_days()),
            is_idle=(gremlin_requests + sparql_requests) == 0,
        )

    # =========================================================================
    # Amazon MQ
    # =========================================================================

    async def get_mq_brokers(self) -> List[MQBrokerData]:
        """Load MQ brokers from exported JSON."""
        brokers = []

        for summary in self._get_data('mq_brokers'):
            brokers.append(MQBrokerData(
                broker_id=summary.get('BrokerId', ''),
                broker_name=summary.get('BrokerName', ''),
                engine_type=summary.get('EngineType', 'ACTIVEMQ'),
                host_instance_type=summary.get('HostInstanceType', 'mq.m5.large'),
                deployment_mode=summary.get('DeploymentMode', 'SINGLE_INSTANCE'),
                broker_state=summary.get('BrokerState', ''),
                region=self._region,
                created=self._parse_datetime(summary.get('Created')),  # CLO-457
            ))

        return brokers

    async def get_mq_metrics(
        self, broker_id: str, days: int = 14, broker: Optional[MQBrokerData] = None,
    ) -> Optional[MQMetrics]:
        """CLO-516: broker activity and CPU from ``mq_broker_activity.json``.

        Export script 1.17.0+ reads AWS/AmazonMQ by broker NAME with the
        engine's metric set (ActiveMQ ``<name>-1``/``-2``: TotalMessageCount,
        TotalConsumerCount, TotalProducerCount, CpuUtilization; RabbitMQ
        ``<name>``: MessageCount, ConsumerCount, ConnectionCount,
        SystemCpuUtilization) and writes, per broker, the hourly maximum and
        hour count of each activity gauge and the mean hourly CPU. Older
        scripts queried by broker ID, which returns no datapoints, and this
        provider read that empty series as an idle broker. A broker missing
        from the file, whose read failed, or under 75% of the window's hours
        is MISSING (noted), never idle; its CPU is None, never 0%."""
        entry = None
        for candidate in self._get_data('mq_broker_activity'):
            if isinstance(candidate, dict) and candidate.get('BrokerId') == broker_id:
                entry = candidate
                break
        if entry is None or entry.get('error'):
            reason = 'not in export' if entry is None else f"export read failed ({entry.get('error')})"
            self._note_idle_verdict_missing('mq', broker_id, reason, evidence='broker activity metrics')
            return None

        try:
            hours = int(entry.get('HourCount') or 0)
        except (TypeError, ValueError):
            hours = 0
        series = entry.get('Series') or {}

        def _stat(key: str, field: str):
            item = series.get(key) or {}
            try:
                count = int(item.get('count') or 0)
            except (TypeError, ValueError):
                count = 0
            value = item.get(field)
            if hours <= 0 or count < hours * 0.75 or value is None:
                return None, count
            try:
                return float(value), count
            except (TypeError, ValueError):
                return None, count

        activity = {key: _stat(key, 'max') for key in ('messages', 'consumers', 'producers')}
        cpu, cpu_count = _stat('cpu', 'avg')
        activity_ok = all(value is not None for value, _ in activity.values())
        if not activity_ok:
            reason = (
                'no datapoints' if all(count == 0 for _, count in activity.values())
                else 'under 75% coverage'
            )
            self._note_idle_verdict_missing('mq', broker_id, reason, evidence='broker activity metrics')
        if cpu is None:
            self._note_idle_verdict_missing(
                'mq', broker_id, 'no datapoints' if cpu_count == 0 else 'under 75% coverage',
                verdict='oversized', evidence='broker CPU metrics',
            )
        if not activity_ok and cpu is None:
            return None

        def _peak(key: str) -> int:
            value = activity[key][0]
            return int(math.ceil(value)) if value is not None else 0

        messages, consumers, producers = _peak('messages'), _peak('consumers'), _peak('producers')
        return MQMetrics(
            total_message_count=messages,
            total_consumer_count=consumers,
            total_producer_count=producers,
            cpu_utilization=round(cpu, 2) if cpu is not None else None,
            period_days=max(1, round(hours / 24)) if hours else days,
            is_idle=activity_ok and messages == 0 and consumers == 0 and producers == 0,
        )

    # ─── Lightsail ────────────────────────────────────────────────

    async def get_lightsail_instances(self) -> List[LightsailInstanceData]:
        """Load Lightsail instances from exported JSON."""
        results = []
        for i in self._get_data('lightsail_instances'):
            results.append(LightsailInstanceData(
                name=i.get('name', ''),
                state=i.get('state', {}).get('name', 'unknown') if isinstance(i.get('state'), dict) else str(i.get('state', 'unknown')),
                bundle_id=i.get('bundleId', ''),
                blueprint_id=i.get('blueprintId', ''),
                ip_address=i.get('publicIpAddress'),
                is_static_ip=i.get('isStaticIp', False),
                region=self._region,
            ))
        return results

    async def get_lightsail_static_ips(self) -> List[LightsailStaticIpData]:
        """Load Lightsail static IPs from exported JSON."""
        results = []
        for ip in self._get_data('lightsail_static_ips'):
            results.append(LightsailStaticIpData(
                name=ip.get('name', ''),
                ip_address=ip.get('ipAddress', ''),
                is_attached=ip.get('isAttached', False),
                attached_to=ip.get('attachedTo'),
                region=self._region,
            ))
        return results

    async def get_lightsail_disks(self) -> List[LightsailDiskData]:
        """Load Lightsail disks from exported JSON."""
        results = []
        for d in self._get_data('lightsail_disks'):
            results.append(LightsailDiskData(
                name=d.get('name', ''),
                size_in_gb=d.get('sizeInGb', 0),
                state=d.get('state', 'unknown'),
                is_attached=d.get('isAttached', False),
                attached_to=d.get('attachedTo'),
                path=d.get('path'),
                region=self._region,
            ))
        return results

    async def get_lightsail_snapshots(self) -> List[LightsailSnapshotData]:
        """Load Lightsail snapshots from exported JSON."""
        from datetime import datetime
        results = []
        for s in self._get_data('lightsail_snapshots'):
            created_at = s.get('createdAt')
            if isinstance(created_at, str):
                try:
                    created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    created_at = datetime.min
            elif not isinstance(created_at, datetime):
                created_at = datetime.min
            results.append(LightsailSnapshotData(
                name=s.get('name', ''),
                size_in_gb=s.get('sizeInGb', 0),
                created_at=created_at,
                from_instance_name=s.get('fromInstanceName'),
                is_from_auto_snapshot=s.get('isFromAutoSnapshot', False),
                region=self._region,
            ))
        return results

    async def get_lightsail_load_balancers(self) -> List[LightsailLoadBalancerData]:
        """Load Lightsail load balancers from exported JSON."""
        results = []
        for lb in self._get_data('lightsail_load_balancers'):
            results.append(LightsailLoadBalancerData(
                name=lb.get('name', ''),
                dns_name=lb.get('dnsName', ''),
                instance_port=lb.get('instancePort', 80),
                health_check_path=lb.get('healthCheckPath', '/'),
                instance_health_summary=lb.get('instanceHealthSummary', []),
                tls_certificate_summaries=lb.get('tlsCertificateSummaries', []),
                region=self._region,
            ))
        return results

    async def get_lightsail_databases(self) -> List[LightsailDatabaseData]:
        """Load Lightsail databases from exported JSON."""
        results = []
        for db in self._get_data('lightsail_databases'):
            results.append(LightsailDatabaseData(
                name=db.get('name', ''),
                state=db.get('state', 'unknown'),
                engine=db.get('engine', ''),
                engine_version=db.get('engineVersion', ''),
                bundle_id=db.get('relationalDatabaseBundleId', ''),
                master_database_name=db.get('masterDatabaseName', ''),
                secondary_availability_zone=db.get('secondaryAvailabilityZone'),
                region=self._region,
            ))
        return results

    async def get_lightsail_metrics(
        self, resource_name: str, resource_type: str = 'instance'
    ) -> LightsailMetricsData:
        """Load Lightsail metrics from exported CloudWatch JSON."""
        if resource_type == 'instance':
            # CLO-506: hourly datapoint count against the export's window,
            # so the detector can gate an idle verdict on 75% coverage. The
            # raw GetInstanceMetricData file (``metricData``) is read when
            # the export carries it; a consolidated ``lightsail_cpu_metrics``
            # row (``datapoints_count``) otherwise.
            window_hours = self._export_cloudwatch_days() * 24
            cpu_key = f'lightsail_cpu_{resource_name}'
            cpu_data = self._export_data.get(cpu_key, {})
            if not isinstance(cpu_data, dict):
                cpu_data = {}
            datapoints = cpu_data.get('metricData', cpu_data.get('Datapoints', []))
            values = [
                v for v in (d.get('average', d.get('Average')) for d in datapoints or [])
                if v is not None
            ]
            if values:
                return LightsailMetricsData(
                    resource_name=resource_name,
                    avg_cpu=sum(values) / len(values),
                    max_cpu=max(values),
                    cpu_datapoints=len(values),
                    cpu_window_hours=window_hours,
                )
            for row in self._get_data('lightsail_cpu_metrics'):
                if row.get('instance_name') == resource_name and row.get('avg') is not None:
                    count = row.get('datapoints_count')
                    return LightsailMetricsData(
                        resource_name=resource_name,
                        avg_cpu=float(row['avg']),
                        max_cpu=float(row['max']) if row.get('max') is not None else None,
                        cpu_datapoints=int(count) if count is not None else None,
                        cpu_window_hours=window_hours,
                    )
            return LightsailMetricsData(resource_name=resource_name, cpu_window_hours=window_hours)
        elif resource_type == 'database':
            cpu_key = f'lightsail_db_cpu_{resource_name}'
            conn_key = f'lightsail_db_conn_{resource_name}'
            cpu_data = self._export_data.get(cpu_key, {})
            conn_data = self._export_data.get(conn_key, {})
            cpu_points = cpu_data.get('metricData', cpu_data.get('Datapoints', []))
            conn_points = conn_data.get('metricData', conn_data.get('Datapoints', []))
            # CLO-540: a datapoint without a value is skipped, not read as
            # 0, and a missing series is MISSING (None, noted).
            def _mean(points):
                values = [
                    v for v in (d.get('average', d.get('Average')) for d in points or [])
                    if v is not None
                ]
                return sum(values) / len(values) if values else None
            avg_cpu = _mean(cpu_points)
            avg_conn = _mean(conn_points)
            if avg_cpu is None or avg_conn is None:
                self._note_idle_verdict_missing(
                    'lightsail database', resource_name, 'not in export',
                    evidence='CPUUtilization/DatabaseConnections datapoints',
                )
            return LightsailMetricsData(
                resource_name=resource_name,
                avg_cpu=avg_cpu,
                avg_connections=avg_conn,
            )
        return LightsailMetricsData(resource_name=resource_name)

    # =========================================================================
    # EMR / Analytics
    # =========================================================================

    async def get_emr_clusters(self) -> List[EMRClusterData]:
        """Get EMR clusters from offline export."""
        clusters = []
        raw_clusters = self._get_data('emr_clusters')
        for c in raw_clusters:
            cluster_id = c.get('Id', '')
            detail_raw = self._export_data.get(f'emr_cluster_detail_{cluster_id}', {})
            cluster_detail = detail_raw.get('Cluster', detail_raw) if isinstance(detail_raw, dict) else {}

            ig_data = self._get_data(f'emr_instance_groups_{cluster_id}')
            instance_groups_raw = ig_data if isinstance(ig_data, list) else ig_data.get('InstanceGroups', []) if isinstance(ig_data, dict) else []

            timeline = cluster_detail.get('Status', c.get('Status', {})).get('Timeline', {})
            total_instances = sum(ig.get('RunningInstanceCount', 0) for ig in instance_groups_raw)

            master_type = ''
            for ig in instance_groups_raw:
                if ig.get('InstanceGroupType') == 'MASTER':
                    master_type = ig.get('InstanceType', '')
                    break

            ready_dt = timeline.get('ReadyDateTime')
            if isinstance(ready_dt, str):
                try:
                    ready_dt = datetime.fromisoformat(ready_dt.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    ready_dt = None

            created_dt = timeline.get('CreationDateTime')
            if isinstance(created_dt, str):
                try:
                    created_dt = datetime.fromisoformat(created_dt.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    created_dt = None

            # CLO-574: the export's cluster detail is a raw DescribeCluster
            # response, which has AutoTerminate (not KeepJobFlowAliveWhenNoSteps)
            # and never carries an auto-termination policy -- the export script
            # does not run GetAutoTerminationPolicy (CLO-574 follow-up ticket).
            # keep_alive is still derivable from AutoTerminate; the policy itself
            # is always unknown offline, so the detector must withhold the
            # finding rather than read "no policy".
            auto_terminate = cluster_detail.get('AutoTerminate')
            keep_alive = (not auto_terminate) if auto_terminate is not None else True
            # Mirror the detector's own age gate (and online.py's): a cluster
            # younger than 24h is never a candidate for this finding, so a
            # young cluster raises no MISSING note either.
            ref_dt = ready_dt or created_dt
            # An export timestamp without an offset parses naive, and a non-
            # datetime (e.g. a CLI v1 epoch) can't be aged: treat naive as UTC,
            # like the detector does, and anything else as not old enough.
            if isinstance(ref_dt, datetime) and ref_dt.tzinfo is None:
                ref_dt = ref_dt.replace(tzinfo=timezone.utc)
            old_enough = isinstance(ref_dt, datetime) and (
                datetime.now(timezone.utc) - ref_dt
            ) > timedelta(hours=24)
            if keep_alive and old_enough:
                self._note_idle_verdict_missing(
                    'emr auto-termination', cluster_id, 'not in export',
                    verdict='auto-termination', evidence='GetAutoTerminationPolicy',
                )

            clusters.append(EMRClusterData(
                cluster_id=cluster_id,
                cluster_name=c.get('Name', cluster_id),
                state=c.get('Status', {}).get('State', cluster_detail.get('Status', {}).get('State', '')),
                cluster_arn=cluster_detail.get('ClusterArn', ''),
                region=self._region,
                release_label=cluster_detail.get('ReleaseLabel', ''),
                auto_termination_policy=None,
                auto_termination_unknown=True,
                keep_alive=keep_alive,
                ready_datetime=ready_dt,
                created_datetime=created_dt,
                instance_groups=[{
                    'InstanceGroupType': ig.get('InstanceGroupType'),
                    'InstanceType': ig.get('InstanceType'),
                    'RunningInstanceCount': ig.get('RunningInstanceCount', 0),
                    'Market': ig.get('Market', 'ON_DEMAND'),
                    'InstanceGroupId': ig.get('Id', ''),
                } for ig in instance_groups_raw],
                total_instances=total_instances,
                master_instance_type=master_type,
                tags={t['Key']: t['Value'] for t in cluster_detail.get('Tags', []) if isinstance(t, dict)},
            ))
        return clusters

    async def get_emr_instance_groups(self, cluster_id: str) -> List[EMRInstanceGroupData]:
        """Get instance groups from offline export."""
        groups = []
        raw = self._get_data(f'emr_instance_groups_{cluster_id}')
        ig_list = raw if isinstance(raw, list) else raw.get('InstanceGroups', []) if isinstance(raw, dict) else []
        for ig in ig_list:
            ebs_config = None
            ebs_volumes = ig.get('EbsBlockDevices', [])
            if ebs_volumes:
                vol = ebs_volumes[0].get('VolumeSpecification', {}) if isinstance(ebs_volumes[0], dict) else {}
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
                status=ig.get('Status', {}).get('State', '') if isinstance(ig.get('Status'), dict) else str(ig.get('Status', '')),
            ))
        return groups

    async def get_emr_step_summary(self, cluster_id: str) -> EMRStepSummaryData:
        """Get step summary from offline export."""
        raw = self._get_data(f'emr_steps_{cluster_id}')
        steps = raw if isinstance(raw, list) else raw.get('Steps', []) if isinstance(raw, dict) else []

        completed = [s for s in steps if isinstance(s, dict) and s.get('Status', {}).get('State') == 'COMPLETED']
        running = [s for s in steps if isinstance(s, dict) and s.get('Status', {}).get('State') == 'RUNNING']
        pending = [s for s in steps if isinstance(s, dict) and s.get('Status', {}).get('State') == 'PENDING']

        last_end = None
        if completed:
            end_times = []
            for s in completed:
                end_dt = s.get('Status', {}).get('Timeline', {}).get('EndDateTime')
                if end_dt:
                    if isinstance(end_dt, str):
                        try:
                            end_dt = datetime.fromisoformat(end_dt.replace('Z', '+00:00'))
                        except (ValueError, TypeError):
                            continue
                    end_times.append(end_dt)
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

    async def get_emr_metrics(
        self,
        cluster_ids: List[str],
        days: int = 14,
    ) -> Dict[str, EMRMetricsData]:
        """Get EMR metrics from offline export."""
        metrics = {}
        for cluster_id in cluster_ids:
            idle_data = self._get_data(f'emr_idle_{cluster_id}')
            idle_points = idle_data if isinstance(idle_data, list) else idle_data.get('Datapoints', []) if isinstance(idle_data, dict) else []
            is_idle_avg = sum(d.get('Average', d.get('average', 0)) for d in idle_points) / max(len(idle_points), 1) if idle_points else 0

            yarn_data = self._get_data(f'emr_yarn_memory_{cluster_id}')
            yarn_points = yarn_data if isinstance(yarn_data, list) else yarn_data.get('Datapoints', []) if isinstance(yarn_data, dict) else []
            yarn_avail = sum(d.get('Average', d.get('average', 0)) for d in yarn_points) / max(len(yarn_points), 1) if yarn_points else 0

            apps_data = self._get_data(f'emr_apps_running_{cluster_id}')
            apps_points = apps_data if isinstance(apps_data, list) else apps_data.get('Datapoints', []) if isinstance(apps_data, dict) else []
            apps_avg = sum(d.get('Average', d.get('average', 0)) for d in apps_points) / max(len(apps_points), 1) if apps_points else 0

            metrics[cluster_id] = EMRMetricsData(
                cluster_id=cluster_id,
                is_idle=is_idle_avg > 0.5,
                yarn_memory_available_pct=yarn_avail,
                apps_running_avg=apps_avg,
                period_days=days,
            )
        return metrics

    # =========================================================================
    # WorkSpaces
    # =========================================================================

    async def get_workspaces(self) -> List[WorkspaceData]:
        """Get WorkSpaces from offline export."""
        results = []
        raw = self._get_data('workspaces')
        for w in raw:
            props = w.get('WorkspaceProperties', {})
            results.append(WorkspaceData(
                workspace_id=w.get('WorkspaceId', ''),
                bundle_id=w.get('BundleId', ''),
                state=w.get('State', 'UNKNOWN'),
                running_mode=props.get('RunningMode', 'ALWAYS_ON'),
                compute_type=props.get('ComputeTypeName', 'STANDARD'),
                operating_system=w.get('OperatingSystemName', ''),
                region=self._region,
                tags={t['Key']: t['Value'] for t in w.get('Tags', []) if isinstance(t, dict)},
            ))
        return results

    async def get_workspaces_connection_status(self, workspace_ids: List[str]) -> List[WorkspaceConnectionData]:
        """Get WorkSpaces connection status from offline export."""
        results = []
        raw = self._get_data('workspaces_connection_status')
        for c in raw:
            wid = c.get('WorkspaceId', '')
            if workspace_ids and wid not in workspace_ids:
                continue
            last_ts = c.get('LastKnownUserConnectionTimestamp')
            if isinstance(last_ts, str):
                try:
                    last_ts = datetime.fromisoformat(last_ts.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    last_ts = None
            results.append(WorkspaceConnectionData(
                workspace_id=wid,
                connection_state=c.get('ConnectionState', ''),
                last_known_user_connection_timestamp=last_ts,
            ))
        return results

    async def get_workspaces_pools(self) -> List[WorkspacePoolData]:
        """Get WorkSpaces Pools from offline export."""
        results = []
        raw = self._get_data('workspaces_pools')
        for p in raw:
            capacity = p.get('Capacity', {})
            results.append(WorkspacePoolData(
                pool_id=p.get('PoolId', ''),
                pool_name=p.get('PoolName', p.get('PoolId', '')),
                state=p.get('State', ''),
                desired_user_sessions=capacity.get('DesiredUserSessions', 0),
                running_user_sessions=capacity.get('RunningUserSessions', 0) if capacity else 0,
            ))
        return results

    async def get_workspaces_metrics(
        self,
        workspace_ids: List[str],
        days: int = 14,
    ) -> Dict[str, WorkspaceMetricsData]:
        """Get WorkSpaces metrics from offline export."""
        metrics = {}
        for wid in workspace_ids:
            sessions_data = self._get_data(f'workspaces_sessions_{wid}')
            sessions_points = (
                sessions_data if isinstance(sessions_data, list)
                else sessions_data.get('Datapoints', []) if isinstance(sessions_data, dict)
                else []
            )
            session_maxes = [
                d.get('Maximum', d.get('maximum', 0)) for d in sessions_points
            ]

            connected_data = self._get_data(f'workspaces_connections_{wid}')
            connected_points = (
                connected_data if isinstance(connected_data, list)
                else connected_data.get('Datapoints', []) if isinstance(connected_data, dict)
                else []
            )
            connected_sums = [
                d.get('Sum', d.get('sum', 0)) for d in connected_points
            ]

            metrics[wid] = WorkspaceMetricsData(
                workspace_id=wid,
                user_sessions_max_daily=session_maxes,
                user_connected_sum_daily=connected_sums,
                period_days=days,
                observation_days=len(session_maxes),
            )
        return metrics

    # =========================================================================
    # Elastic Beanstalk / Compute
    # =========================================================================

    async def get_beanstalk_environments(self) -> List[BeanstalkEnvironmentData]:
        """Get Beanstalk environments from offline export."""
        environments = []
        raw_envs = self._get_data('beanstalk_environments')
        for env in raw_envs:
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
        return environments

    async def get_beanstalk_configurations(self) -> Dict[str, BeanstalkConfigData]:
        """Get Beanstalk configuration settings from offline export."""
        configs = {}
        raw_envs = self._get_data('beanstalk_environments')
        for env in raw_envs:
            env_id = env.get('EnvironmentId', '')
            env_name = env.get('EnvironmentName', '')
            config_data = self._get_data(f'beanstalk_config_{env_name}')
            if not config_data:
                configs[env_id] = BeanstalkConfigData(environment_id=env_id)
                continue

            settings = config_data if isinstance(config_data, list) else config_data.get('ConfigurationSettings', [{}])
            if settings:
                setting = settings[0] if isinstance(settings, list) else settings
                options = {
                    (opt.get('Namespace', ''), opt.get('OptionName', '')): opt.get('Value', '')
                    for opt in setting.get('OptionSettings', [])
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
            else:
                configs[env_id] = BeanstalkConfigData(environment_id=env_id)
        return configs

    async def get_beanstalk_metrics(
        self,
        environment_names: List[str],
        days: int = 14,
        endpoint_urls: Optional[Dict[str, str]] = None,
    ) -> Dict[str, BeanstalkMetricsData]:
        """Beanstalk metrics from the offline export (CLO-524).

        The export (script 1.17.x) collects, per environment, AWS/ElasticBeanstalk
        EnvironmentHealth, RequestCount (a metric Beanstalk does not publish,
        so always empty) and ApplicationRequestsTotal (published only when
        enhanced health is configured). Only the last can measure traffic:
        request_count_14d is its total when its daily series covers 75% of
        the export's days, else -1 (MISSING). No per-instance CPU or load
        balancer RequestCount is exported, so avg_cpu_14d is always -1."""
        metrics = {}
        export_days = min(days, self._export_cloudwatch_days())
        need_days = math.ceil(export_days * 0.75)
        for env_name in environment_names:
            raw = self._export_data.get(f'beanstalk_app_requests_{env_name}')
            if isinstance(raw, dict):
                points = raw.get('Datapoints', [])
            elif isinstance(raw, list):
                points = raw
            else:
                points = []
            values = [
                (d.get('Timestamp'), d.get('Sum', d.get('sum')))
                for d in points if isinstance(d, dict) and d.get('Sum', d.get('sum')) is not None
            ]
            covered_days = len({str(ts)[:10] for ts, _ in values})
            entry = BeanstalkMetricsData(
                environment_name=env_name,
                period_days=days,
                missing_reason='no per-instance CPU in export',
            )
            if covered_days >= need_days and covered_days > 0:
                entry.request_count_14d = int(sum(v for _, v in values))
                entry.request_source = 'enhanced_health'
                entry.request_coverage_days = covered_days
            else:
                entry.missing_reason = (
                    f"enhanced-health requests for {covered_days} of {export_days} days in export; "
                    f"no per-instance CPU in export"
                )
            metrics[env_name] = entry
        return metrics

    async def get_beanstalk_rds_instances(self) -> Optional[List[RDSInstanceData]]:
        """CLO-506: the export's RDS instances that carry a Beanstalk mark.
        (beanstalk_orphaned_rds is still online-only: its connection
        coverage can't be proven from the export; see the detector.)"""
        return [db for db in await self.get_rds_instances() if beanstalk_rds_marks(db.tags)]

    async def get_api_gateway_rest_apis(self) -> Optional[List[ApiGatewayRestApiData]]:
        """CLO-507: REST APIs from the export's GetRestApis output."""
        apis = []
        for api in self._get_data('api_gateway_rest'):
            if not isinstance(api, dict):
                continue
            apis.append(ApiGatewayRestApiData(
                api_id=api.get('id', ''),
                name=api.get('name', '') or api.get('id', ''),
                created_date=self._parse_datetime(api.get('createdDate')),
                endpoint_types=list((api.get('endpointConfiguration') or {}).get('types') or []),
            ))
        return apis

    async def get_api_gateway_request_counts(
        self, apis: List[ApiGatewayRestApiData], days: int = 30,
    ) -> Dict[str, float]:
        """CLO-507: the export reads AWS/ApiGateway Count on an ApiId
        dimension, which REST APIs do not publish (they use ApiName), so its
        series can't tell an unused API from a mislabelled read: every API
        is MISSING, and noted."""
        for api in apis:
            self._note_idle_verdict_missing(
                'apigateway', api.api_id, "not in export",
                verdict='unused', evidence='request counts',
            )
        return {}

    async def get_api_gateway_cache_enabled(self, api_id: str) -> Optional[bool]:
        return None  # stages are not exported

    async def get_sagemaker_notebook_last_activity(
        self, notebook_names: List[str],
    ) -> Dict[str, Optional[datetime]]:
        """CLO-510: the export carries no CloudWatch Logs, so no notebook's
        Jupyter activity is known: every idle verdict is MISSING, noted."""
        for name in notebook_names:
            self._note_idle_verdict_missing(
                'sagemaker-notebook', name, "not in export", evidence='Jupyter server logs',
            )
        return {}

    # =========================================================================
    # Global Accelerator / Network
    # =========================================================================

    def _ga_bytes_sum(self, key: str) -> Optional[float]:
        """Sum of an exported Global Accelerator ProcessedBytes series, or
        None when it is MISSING (CLO-550): not exported, or an older
        export's ``{"Datapoints": []}`` failure fallback, told apart from a
        real get-metric-statistics response by its ``Label`` (always
        present in the real output)."""
        raw = self._export_data.get(key)
        if isinstance(raw, list):
            datapoints = raw
        elif isinstance(raw, dict) and isinstance(raw.get('Datapoints'), list):
            datapoints = raw['Datapoints']
            if not datapoints and 'Label' not in raw:
                return None
        else:
            return None
        return float(sum(
            dp.get('Sum', dp.get('sum', 0.0)) for dp in datapoints if isinstance(dp, dict)
        ))

    async def get_global_accelerator_resources(self) -> List[GlobalAcceleratorData]:
        """Parse Global Accelerator data from exported JSON."""
        results = []
        raw_accelerators = self._get_data('global_accelerators')

        for acc in raw_accelerators:
            arn = acc.get('AcceleratorArn', '')
            acc_id = arn.split('/')[-1] if '/' in arn else ''

            # CloudWatch ProcessedBytes sums. CLO-550: None (MISSING) when
            # the series was not exported (1.19.0+ leaves a 0-byte file on a
            # failed read) or is an older export's failure fallback; only a
            # real (possibly empty) response counts as a measured sum.
            processed_in = self._ga_bytes_sum(f'global_accelerator_bytes_in_{acc_id}')
            processed_out = self._ga_bytes_sum(f'global_accelerator_bytes_out_{acc_id}')

            # Determine endpoint status from enriched export data.
            # CLO-550: None (MISSING) unless the export merged the listener
            # and endpoint-group reads in. 1.19.0+ merges them only when
            # every read succeeded; an older export merged
            # {"Listeners": []} when list-listeners failed, the same as an
            # accelerator with no listeners, so there "no endpoints" is
            # MISSING; only endpoints actually seen are measured.
            listeners_data = acc.get('Listeners', [])
            endpoint_groups_data = acc.get('EndpointGroups', [])
            has_endpoints: Optional[bool] = None
            if isinstance(endpoint_groups_data, list) and 'EndpointGroups' in acc:
                has_endpoints = any(
                    isinstance(eg, dict) and eg.get('EndpointDescriptions')
                    for eg in endpoint_groups_data
                )
                # A pre-1.19.0 export also dropped the endpoint groups of a
                # listener whose list-endpoint-groups failed (no pipefail),
                # so any "no endpoints" there is ambiguous.
                if not has_endpoints and self._legacy_failed_reads:
                    has_endpoints = None
            if has_endpoints is None:
                endpoint_groups_data = endpoint_groups_data if isinstance(endpoint_groups_data, list) else []

            ip_sets = acc.get('IpSets', [])
            ip_addresses = []
            if ip_sets:
                ip_addresses = [
                    ip.get('IpAddress', '') for ip in ip_sets[0].get('IpAddresses', [])
                ]

            results.append(GlobalAcceleratorData(
                name=acc.get('Name', ''),
                arn=arn,
                status=acc.get('Status', ''),
                enabled=acc.get('Enabled', True),
                ip_addresses=ip_addresses,
                dns_name=acc.get('DnsName', ''),
                created_time=str(acc.get('CreatedTime', '')),
                listeners=listeners_data,
                endpoint_groups=endpoint_groups_data,
                has_endpoints=has_endpoints,
                processed_bytes_in_sum=processed_in,
                processed_bytes_out_sum=processed_out,
            ))

        return results
