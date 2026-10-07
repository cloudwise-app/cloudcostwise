"""
Data Models for Waste Detection Providers

These dataclasses represent the normalized resource data that both
online and offline providers return. Detectors work with these models
regardless of data source.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional


@dataclass
class EC2InstanceData:
    """Normalized EC2 instance data."""
    instance_id: str
    instance_type: str
    state: str  # 'running', 'stopped', 'terminated', etc.
    region: str
    name: Optional[str] = None
    launch_time: Optional[datetime] = None
    platform: Optional[str] = None  # 'windows' or None (Linux)
    tags: Dict[str, str] = field(default_factory=dict)
    block_device_mappings: List[Dict[str, Any]] = field(default_factory=list)
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    # CLO-493: the instance's public IPv4 (``PublicIpAddress``), None when it
    # has none. ``_detect_orphaned_dns_waste`` reads it to recognise an A
    # record that points at a live instance; the field did not exist, so that
    # read raised AttributeError and the cross-check was always skipped.
    public_ip: Optional[str] = None


@dataclass
class EC2MetricsData:
    """CloudWatch metrics for an EC2 instance.

    CLO-493: the fields are ``cpu_avg``/``cpu_max``. ``_detect_ec2_waste``
    read ``avg_cpu``/``max_cpu`` (a test fake's shape), so every idle instance
    raised AttributeError and the whole EC2 detector's findings were lost.
    """
    instance_id: str
    cpu_avg: float  # Average CPU utilization (0-100)
    cpu_max: float  # Maximum CPU utilization (0-100)
    network_in_avg: float = 0.0  # Average network in (bytes)
    network_out_avg: float = 0.0  # Average network out (bytes)
    period_days: int = 14
    is_idle: bool = False
    is_oversized: bool = False
    # CLO-493: CPU datapoints the verdict was read from (None = not recorded),
    # and the percentiles idle_ec2's peak guard reads (cpu_sizing.ec2_cpu_is_idle):
    # p95 of the hourly Averages and of the hourly Maximums.
    cpu_datapoints: Optional[int] = None
    cpu_p95: Optional[float] = None
    cpu_p95_max: Optional[float] = None


@dataclass
class EBSVolumeData:
    """Normalized EBS volume data."""
    volume_id: str
    volume_type: str  # 'gp2', 'gp3', 'io1', 'io2', 'st1', 'sc1'
    size_gb: int
    state: str  # 'available', 'in-use', 'creating', 'deleted'
    region: str
    iops: Optional[int] = None
    throughput: Optional[int] = None
    create_time: Optional[datetime] = None
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    encrypted: bool = False
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class EBSIopsPeakData:
    """CLO-516: a volume's measured peak IOPS over a metric window.

    ``peak_iops`` is the highest one-minute average of VolumeReadOps +
    VolumeWriteOps (operations / 60s). Providers return an entry only when
    the series covers at least 75% of the window's minutes; anything else is
    MISSING (noted in ``data_warnings``), never a zero."""
    volume_id: str
    peak_iops: float
    datapoints: int
    expected_datapoints: int
    window_days: float
    period_seconds: int = 60


@dataclass
class EBSSnapshotData:
    """Normalized EBS snapshot data."""
    snapshot_id: str
    volume_id: Optional[str]
    volume_size_gb: int
    state: str  # 'pending', 'completed', 'error'
    region: str
    start_time: Optional[datetime] = None
    description: Optional[str] = None
    encrypted: bool = False
    tags: Dict[str, str] = field(default_factory=dict)
    age_days: int = 0


@dataclass
class ElasticIPData:
    """Normalized Elastic IP data."""
    allocation_id: str
    public_ip: str
    region: str
    instance_id: Optional[str] = None
    network_interface_id: Optional[str] = None
    is_attached: bool = False
    domain: str = "vpc"  # 'vpc' or 'standard'
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class RDSInstanceData:
    """Normalized RDS instance data."""
    db_instance_id: str
    db_instance_class: str
    engine: str
    engine_version: str
    status: str  # 'available', 'stopped', etc.
    region: str
    multi_az: bool = False
    storage_type: str = "gp2"
    allocated_storage_gb: int = 0
    iops: Optional[int] = None
    publicly_accessible: bool = False
    storage_encrypted: bool = False
    deletion_protection: bool = False
    endpoint: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    db_instance_arn: str = ''
    # CLO-384: RDS automated backups (BackupRetentionPeriod > 0) count as
    # backup coverage — already returned by describe-db-instances, no new
    # permission needed.
    backup_retention_period: int = 0
    # CLO-457: DescribeDBInstances' InstanceCreateTime. AWS/RDS metrics are
    # keyed on DBInstanceIdentifier, a NAME, so an instance recreated under a
    # reused identifier inherits its predecessor's datapoints unless the
    # metric window is cut at this time (cloudwise_scan_core.metric_window).
    instance_create_time: Optional[datetime] = None


@dataclass
class RDSMetricsData:
    """CloudWatch metrics for an RDS instance."""
    db_instance_id: str
    connections_avg: float = 0.0
    connections_max: float = 0.0
    cpu_avg: float = 0.0
    cpu_max: float = 0.0
    free_memory_avg: float = 0.0
    period_days: int = 14
    is_idle: bool = False
    # CLO-485: hourly CPUUtilization datapoints behind cpu_avg/cpu_max. None
    # means CPU was not read (the online provider reads it only when a
    # detector asks, ``include_cpu=True``) or the export carries no count.
    # 0 means CPU was read and nothing came back: MISSING, not 0% CPU.
    cpu_datapoints: Optional[int] = None
    # The window cpu_datapoints is measured against (the offline export may
    # hold fewer days than the detector asks for). None = period_days.
    cpu_window_days: Optional[int] = None
    # CLO-506: daily DatabaseConnections datapoints behind connections_*.
    # None = not recorded (older callers); 0 = read, nothing came back.
    connections_datapoints: Optional[int] = None


@dataclass
class RDSSnapshotData:
    """Normalized RDS snapshot data."""
    snapshot_id: str
    db_instance_id: Optional[str]
    snapshot_type: str  # 'manual', 'automated'
    status: str
    region: str
    allocated_storage_gb: int = 0
    create_time: Optional[datetime] = None
    encrypted: bool = False
    engine: Optional[str] = None
    age_days: int = 0


@dataclass
class LambdaFunctionData:
    """Normalized Lambda function data."""
    function_name: str
    function_arn: str
    runtime: str
    memory_mb: int
    timeout_seconds: int
    region: str
    code_size_bytes: int = 0
    last_modified: Optional[datetime] = None
    handler: Optional[str] = None
    description: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    architecture: str = 'x86_64'  # 'x86_64' or 'arm64'


@dataclass
class LambdaMetricsData:
    """CloudWatch metrics for a Lambda function."""
    function_name: str
    invocations_total: int = 0
    invocations_avg: float = 0.0
    duration_avg_ms: float = 0.0
    duration_max_ms: float = 0.0
    errors_total: int = 0
    throttles_total: int = 0
    period_days: int = 30
    is_unused: bool = False


@dataclass
class LambdaProvisionedConcurrencyData:
    """Provisioned Concurrency configuration for a Lambda function."""
    function_name: str
    function_qualifier: str  # Alias or version number
    requested_provisioned_concurrent_executions: int
    allocated_provisioned_concurrent_executions: int
    status: str  # 'READY', 'IN_PROGRESS', 'FAILED'
    avg_utilization_pct: Optional[float] = None  # From CloudWatch


@dataclass
class NATGatewayData:
    """Normalized NAT Gateway data."""
    nat_gateway_id: str
    state: str  # 'available', 'pending', 'failed', 'deleted'
    vpc_id: str
    subnet_id: str
    region: str
    create_time: Optional[datetime] = None
    connectivity_type: str = "public"
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class NATGatewayMetricsData:
    """CloudWatch metrics for a NAT Gateway."""
    nat_gateway_id: str
    bytes_out_total: float = 0.0
    bytes_in_total: float = 0.0
    packets_out_total: float = 0.0
    packets_in_total: float = 0.0
    active_connections_avg: float = 0.0
    period_days: int = 7
    is_idle: bool = False


@dataclass
class S3BucketData:
    """Normalized S3 bucket data."""
    bucket_name: str
    region: Optional[str] = None
    creation_date: Optional[datetime] = None
    # CLO-551: None when the lifecycle read is MISSING (failed with an error
    # other than NoSuchLifecycleConfiguration, or an export that cannot tell
    # such a failure from "no policy"); lifecycle_rules is then [] but unknown.
    has_lifecycle_policy: Optional[bool] = False
    lifecycle_rules: List[Dict[str, Any]] = field(default_factory=list)
    versioning_enabled: bool = False
    has_incomplete_multipart: bool = False
    incomplete_multipart_count: int = 0
    # CLO-513: each listed incomplete upload's Initiated time (the first
    # ListMultipartUploads page), so only stale uploads are flagged. None =
    # not collected; an upload without a date is left out of the list.
    incomplete_multipart_initiated: Optional[List[datetime]] = None
    tags: Dict[str, str] = field(default_factory=dict)
    # ── S3 size & storage class fields (CloudWatch metrics) ──
    total_size_bytes: int = 0                 # Total across all storage classes
    object_count: int = 0                     # Total objects across all storage classes
    storage_class_breakdown: Dict[str, int] = field(default_factory=dict)
    # Maps storage class → bytes, e.g.:
    # {"StandardStorage": 1073741824, "StandardIAStorage": 536870912}
    has_intelligent_tiering: bool = False      # Has IT configuration
    size_previous_bytes: int = 0              # Total size 30 days ago (for growth)
    size_growth_pct_30d: float = 0.0          # Growth percentage over 30 days
    default_encryption_enabled: bool = True    # S3 default encryption (SSE-S3 default since Jan 2023)
    encryption_algorithm: Optional[str] = None # 'AES256' (SSE-S3) or 'aws:kms'
    # CLO-385: Maximum NumberOfObjects over a lookback window, checked only
    # for a bucket that is currently empty AND has a lifecycle expiration
    # rule — evidence it was recently used and self-cleared by design,
    # rather than orphaned. A daily gauge metric, so Maximum (never Average
    # over the whole window, which smears a one-day spike toward zero, and
    # never Sum, which is meaningless for a gauge). None = not checked
    # (bucket wasn't a candidate, or an offline export has no CloudWatch
    # access) — never treated as "no recent activity".
    recent_max_object_count: Optional[int] = None
    # CLO-488: True only when the provider actually observed the bucket's
    # contents: a CloudWatch size/count datapoint above zero, or an object
    # listing (online ListObjectsV2; offline, the export's ``KeyCount``
    # sample). False means size/count are unknown, and the zero defaults
    # above are NOT evidence the bucket is empty; s3_empty_bucket must not
    # fire on them. S3 publishes no storage datapoints for an empty bucket,
    # so an empty CloudWatch series is missing data, not zero.
    contents_observed: bool = False


@dataclass
class S3CostBreakdown:
    """Per-bucket S3 cost breakdown from CUR / Cost Explorer data."""
    bucket_name: str
    bucket_arn: str = ""

    # Cost categories (30-day totals in USD)
    storage_cost: float = 0.0            # TimedStorage-* usage types
    transfer_out_cost: float = 0.0       # DataTransfer-Out-Bytes (internet egress)
    transfer_regional_cost: float = 0.0  # DataTransfer-Regional, cross-AZ
    transfer_cross_region_cost: float = 0.0  # Cross-region transfer
    request_tier1_cost: float = 0.0      # PUT/COPY/POST/LIST
    request_tier2_cost: float = 0.0      # GET/SELECT/HEAD
    other_cost: float = 0.0              # EarlyDelete, misc

    @property
    def total_cost(self) -> float:
        return (self.storage_cost + self.transfer_out_cost +
                self.transfer_regional_cost + self.transfer_cross_region_cost +
                self.request_tier1_cost + self.request_tier2_cost + self.other_cost)

    @property
    def non_storage_cost(self) -> float:
        return self.total_cost - self.storage_cost

    @property
    def transfer_cost(self) -> float:
        return (self.transfer_out_cost + self.transfer_regional_cost +
                self.transfer_cross_region_cost)

    @property
    def request_cost(self) -> float:
        return self.request_tier1_cost + self.request_tier2_cost

    @property
    def dominant_non_storage_category(self) -> str:
        """Identify the dominant non-storage cost driver."""
        categories = {
            'data_transfer_out': self.transfer_out_cost,
            'cross_region_transfer': self.transfer_cross_region_cost,
            'api_requests': self.request_cost,
            'regional_transfer': self.transfer_regional_cost,
        }
        return max(categories, key=categories.get)  # type: ignore[arg-type]


@dataclass
class ExtendedSupportCostData:
    """Normalized extended support surcharge totals from billing data."""
    service_key: str
    amount_usd: float
    days: int = 30
    resource_id: Optional[str] = None
    usage_types: List[str] = field(default_factory=list)
    billing_source: str = "cost_explorer"

    @property
    def monthly_amount_usd(self) -> float:
        if self.days <= 0:
            return self.amount_usd
        return self.amount_usd * (30.0 / float(self.days))


@dataclass
class EFSFilesystemData:
    """Normalized EFS filesystem data."""
    filesystem_id: str
    region: str
    name: Optional[str] = None
    lifecycle_state: str = "available"
    size_bytes: int = 0
    has_mount_targets: bool = True
    mount_target_count: int = 0
    performance_mode: str = "generalPurpose"
    throughput_mode: str = "bursting"
    encrypted: bool = False
    creation_time: Optional[datetime] = None
    # CLO-516: None means the lifecycle configuration could not be read (a
    # failed DescribeLifecycleConfiguration, or an export without it). That
    # is MISSING, not "no policy": no_lifecycle_efs must not fire on it.
    lifecycle_policies: Optional[List[Dict[str, str]]] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class ECRRepositoryData:
    """Normalized ECR repository data."""
    repository_name: str
    repository_arn: str
    repository_uri: str
    region: str
    created_at: Optional[datetime] = None
    image_count: int = 0
    total_size_gb: float = 0.0
    # CLO-551: None when the lifecycle-policy read is MISSING (failed with an
    # error other than LifecyclePolicyNotFoundException, or an export that
    # cannot tell such a failure from "no policy").
    has_lifecycle_policy: Optional[bool] = False
    untagged_image_count: int = 0
    untagged_images_size_gb: float = 0.0
    old_image_count: int = 0
    old_images_size_gb: float = 0.0
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class LoadBalancerData:
    """Normalized Load Balancer data."""
    load_balancer_arn: str
    load_balancer_name: str
    type: str  # 'application', 'network', 'gateway', 'classic'
    scheme: str  # 'internet-facing', 'internal'
    state: str
    region: str
    vpc_id: Optional[str] = None
    dns_name: Optional[str] = None
    created_time: Optional[datetime] = None
    healthy_target_count: int = 0
    unhealthy_target_count: int = 0
    tags: Dict[str, str] = field(default_factory=dict)
    # CLO-532 item 2: False when the target-health read failed or was capped,
    # so healthy_target_count is not a measurement. A "no healthy targets"
    # verdict needs it True (an unread count of 0 is MISSING, not idle).
    target_health_known: bool = True


@dataclass
class LoadBalancerMetricsData:
    """CloudWatch metrics for a Load Balancer."""
    load_balancer_arn: str
    request_count_total: int = 0
    active_connection_count_avg: float = 0.0
    healthy_host_count_avg: float = 0.0
    unhealthy_host_count_avg: float = 0.0
    # Average LCUs consumed **per hour** over the period, i.e. total LCU-hours
    # (the `Sum` of ConsumedLCUs) divided by the window length in hours. ALB only.
    # This is the basis the hourly LCU rate multiplies, so providers must convert
    # to it themselves — CloudWatch's `Average` statistic on ConsumedLCUs is a
    # mean over per-minute, per-node samples and must never be passed through
    # here (CLO-228). None means no LCU data was available, which is distinct
    # from a measured zero.
    consumed_lcus_avg: Optional[float] = None
    period_days: int = 7
    is_idle: bool = False
    # CLO-516: NLBs publish no RequestCount (request_count_total is always 0
    # for them). Their traffic is NewFlowCount (new client flows, Sum over the
    # window); None means it was not read.
    new_flow_count_total: Optional[int] = None


@dataclass
class Route53ZoneData:
    """Normalized Route 53 hosted zone data."""
    zone_id: str
    zone_name: str
    record_set_count: int
    is_private: bool = False
    comment: Optional[str] = None
    record_sets: List[Dict[str, Any]] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class VPCEndpointData:
    """Normalized VPC Endpoint data."""
    endpoint_id: str
    service_name: str
    endpoint_type: str  # 'Interface' or 'Gateway'
    state: str  # 'available', 'pending', 'deleting', etc.
    vpc_id: str
    region: str
    creation_time: Optional[datetime] = None
    subnet_ids: List[str] = field(default_factory=list)
    # None = unknown (an export without NetworkInterfaceIds), not empty.
    network_interface_ids: Optional[List[str]] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class DynamoDBTableData:
    """Normalized DynamoDB table data."""
    table_name: str
    table_arn: str
    region: str
    billing_mode: str  # 'PROVISIONED', 'PAY_PER_REQUEST'
    status: str
    provisioned_read_capacity: int = 0
    provisioned_write_capacity: int = 0
    # CLO-551: None when the Application Auto Scaling read is MISSING.
    has_autoscaling: Optional[bool] = False
    item_count: int = 0
    size_bytes: int = 0
    deletion_protection: bool = False
    created_time: Optional[datetime] = None
    tags: Dict[str, str] = field(default_factory=dict)
    # CLO-384: PITR counts as backup coverage (METHOD.md pinned decision 1).
    # None = not checked (e.g. dynamodb:DescribeContinuousBackups denied, or
    # an offline export that doesn't carry it) — never treated as "off".
    point_in_time_recovery_enabled: Optional[bool] = None


@dataclass
class DynamoDBMetricsData:
    """
    CloudWatch metrics for a DynamoDB table.

    Unit contract (CLO-227): ``consumed_read_capacity_avg`` and
    ``consumed_write_capacity_avg`` are average consumed capacity units **per
    second**, averaged over the whole ``period_days`` window — the same basis as
    a table's provisioned RCU/WCU, so the two are directly comparable. Providers
    must convert to this basis themselves; in particular CloudWatch's ``Average``
    statistic on ``Consumed*CapacityUnits`` is units *per request* and must never
    be passed through here. Values are intentionally not rounded: real rates are
    frequently below 0.01/s, and rounding would collapse them to zero and make a
    live table look idle.
    """
    table_name: str
    consumed_read_capacity_avg: float = 0.0
    consumed_write_capacity_avg: float = 0.0
    read_throttle_events: int = 0
    write_throttle_events: int = 0
    period_days: int = 14
    is_idle: bool = False
    is_over_provisioned: bool = False


@dataclass
class ElastiCacheClusterData:
    """Normalized ElastiCache cluster data."""
    cluster_id: str
    engine: str  # 'redis', 'valkey', 'memcached'
    engine_version: str
    node_type: str
    num_nodes: int
    status: str
    region: str
    endpoint: Optional[str] = None
    created_time: Optional[datetime] = None
    tags: Dict[str, str] = field(default_factory=dict)
    # Replication topology fields
    replication_group_id: Optional[str] = None
    num_shards: int = 1
    replicas_per_shard: int = 0
    multi_az_enabled: bool = False
    automatic_failover: str = 'disabled'
    cache_parameter_group: Optional[str] = None
    data_tiering_enabled: bool = False


@dataclass
class ElastiCacheMetricsData:
    """CloudWatch metrics for an ElastiCache cluster."""
    cluster_id: str
    cache_hits_avg: float = 0.0
    cache_misses_avg: float = 0.0
    current_connections_avg: float = 0.0
    cpu_utilization_avg: float = 0.0
    memory_usage_avg: float = 0.0
    period_days: int = 14
    is_idle: bool = False
    # Additional metrics for deep detectors
    cpu_utilization_max: float = 0.0
    current_connections_max: float = 0.0
    current_connections_std: float = 0.0
    bytes_used_for_cache: float = 0.0
    database_memory_usage_pct: float = 0.0
    # CLO-485: CurrConnections datapoints behind current_connections_avg.
    # is_idle requires 75% coverage of the window; None = not reported.
    connection_datapoints: Optional[int] = None
    # CLO-485: CPUUtilization datapoints behind cpu_utilization_avg. 0 means
    # no CPU data (MISSING, not 0% CPU); None = not reported.
    cpu_datapoints: Optional[int] = None
    # CLO-559: the window oversized_elasticache's 75% CPU-coverage gate must
    # check cpu_datapoints against. None means use ``period_days`` (the
    # online provider's CloudWatch read actually covers the requested
    # window). The offline provider sets this to the export's own shorter
    # window (``_export_cloudwatch_days()``) when that is less than
    # ``period_days``, the same clamp ``get_elasticache_metrics`` already
    # applies to the CurrConnections coverage check — otherwise a shorter
    # export could never pass a coverage gate sized to the full window.
    cpu_window_days: Optional[int] = None
    # CLO-572: DatabaseMemoryUsagePercentage datapoints behind
    # database_memory_usage_pct, the same convention as cpu_datapoints: None
    # means not reported, 0 means a read with no data (MISSING, never read
    # as 0% used). oversized_elasticache's memory gate needs 75% coverage
    # of memory_window_days (cpu_window_days's sibling: None means use
    # period_days, the offline provider clamps it to the export's own
    # shorter window).
    memory_datapoints: Optional[int] = None
    memory_window_days: Optional[int] = None


@dataclass
class ElastiCacheRequestVolumeData:
    """CLO-508: an ElastiCache node's request volume over a window, the
    measured input for an ElastiCache Serverless ECPU estimate.

    ``commands_total`` is the window's Sum of ``ProcessedCommands`` (every
    command the engine ran), or of ``GetTypeCmds`` + ``SetTypeCmds`` when
    the node publishes no ``ProcessedCommands``; ``command_metric`` says
    which. ``network_bytes_total`` is NetworkBytesIn + NetworkBytesOut,
    because Serverless bills one ECPU per KB a request transfers."""
    cluster_id: str
    commands_total: float
    network_bytes_total: float
    period_days: int
    command_metric: str = 'ProcessedCommands'


@dataclass
class RedshiftClusterData:
    """Normalized Redshift cluster data."""
    cluster_id: str
    node_type: str
    num_nodes: int
    status: str
    region: str
    database_name: Optional[str] = None
    endpoint: Optional[str] = None
    encrypted: bool = False
    created_time: Optional[datetime] = None
    has_pause_schedule: bool = False
    is_paused: bool = False
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class RedshiftMetricsData:
    """CloudWatch metrics for a Redshift cluster."""
    cluster_id: str
    database_connections_avg: float = 0.0
    cpu_utilization_avg: float = 0.0
    read_iops_avg: float = 0.0
    write_iops_avg: float = 0.0
    period_days: int = 14
    is_idle: bool = False
    zero_connection_hours_pct: float = 0.0
    # WLM metrics (Detector 5: WLM Over-Provisioned)
    wlm_queue_length_avg: float = 0.0
    wlm_queue_wait_time_avg: float = 0.0
    wlm_running_queries_avg: float = 0.0
    wlm_running_queries_max: float = 0.0
    # Concurrency Scaling metrics (Detector 6: Concurrency Scaling Waste)
    concurrency_scaling_seconds_avg: float = 0.0
    concurrency_scaling_seconds_total: float = 0.0
    concurrency_scaling_active_clusters_avg: float = 0.0
    concurrency_scaling_active_clusters_max: float = 0.0
    # CLO-485: hourly DatabaseConnections datapoints inside the idle claim
    # window (redshift_idle_days). is_idle requires 75% of its hours; None =
    # not reported (the offline export is pre-aggregated).
    connection_hours_in_idle_window: Optional[int] = None


@dataclass
class RedshiftCostData:
    """Cost Explorer data for a Redshift cluster."""
    cluster_id: str
    compute_cost_monthly: float = 0.0
    spectrum_cost_monthly: float = 0.0
    storage_cost_monthly: float = 0.0
    total_cost_monthly: float = 0.0
    spectrum_cost_ratio: float = 0.0  # spectrum / compute as percentage


@dataclass
class OpenSearchDomainData:
    """Normalized OpenSearch domain data."""
    domain_name: str
    domain_arn: str
    instance_type: str
    instance_count: int
    status: str
    region: str
    engine_version: str
    endpoint: Optional[str] = None
    created: Optional[datetime] = None
    encrypted: bool = False
    ebs_enabled: bool = False
    ebs_volume_type: str = ''
    ebs_volume_size_gb: int = 0
    tags: Dict[str, str] = field(default_factory=dict)
    # DescribeDomain's DomainStatus.Deleted: True while AWS is deleting the
    # domain. Providers never set status 'Deleted' (status is only
    # available/processing), so detectors must read this flag.
    deleted: bool = False


@dataclass
class OpenSearchMetricsData:
    """CloudWatch metrics for an OpenSearch domain."""
    domain_name: str
    search_requests_total: int = 0
    indexing_rate_avg: float = 0.0
    cpu_utilization_avg: float = 0.0
    cpu_utilization_max: float = 0.0  # window maximum; reported, not gated (CLO-480)
    # CLO-480: the shared CPU rule's inputs (cloudwise_scan_core.cpu_sizing),
    # from HOURLY CPUUtilization datapoints
    cpu_p95: float = 0.0  # nearest-rank p95 of the hourly CPU Averages
    cpu_p95_max: float = 0.0  # nearest-rank p95 of the hourly CPU Maximums
    cpu_datapoints: int = 0  # hourly CPU datapoints in the window
    jvm_memory_pressure_avg: float = 0.0
    free_storage_space_avg: float = 0.0
    free_storage_pct: float = 0.0
    storage_growth_rate_gb_per_day: float = 0.0
    period_days: int = 14
    is_idle: bool = False
    is_overprovisioned: bool = False
    is_ebs_overprovisioned: bool = False
    # Review of #1535: datapoints behind search_requests_total and
    # indexing_rate_avg. A missing series is MISSING, never zero activity:
    # is_idle needs SearchRate coverage, and the idle verdict also needs
    # IndexingRate datapoints. None = not reported.
    search_datapoints: Optional[int] = None
    indexing_datapoints: Optional[int] = None


@dataclass
class CloudWatchLogGroupData:
    """Normalized CloudWatch Log Group data."""
    log_group_name: str
    region: str
    stored_bytes: int = 0
    retention_days: Optional[int] = None  # None = never expire
    creation_time: Optional[datetime] = None
    # CLO-516: always None online (DescribeLogGroups has no lastEventTimestamp);
    # last activity comes from get_cloudwatch_log_group_last_activity.
    last_event_time: Optional[datetime] = None
    days_since_last_event: Optional[int] = None


@dataclass
class CloudWatchDashboardData:
    """Normalized CloudWatch Dashboard data."""
    dashboard_name: str
    dashboard_arn: str
    region: str
    last_modified: Optional[datetime] = None
    size_bytes: int = 0


@dataclass
class KMSKeyData:
    """Normalized KMS key data."""
    key_id: str
    key_arn: str
    key_state: str  # 'Enabled', 'Disabled', 'PendingDeletion', etc.
    key_usage: str  # 'ENCRYPT_DECRYPT', 'SIGN_VERIFY'
    region: str
    description: Optional[str] = None
    creation_date: Optional[datetime] = None
    enabled: bool = True
    last_used_date: Optional[datetime] = None
    days_since_last_use: Optional[int] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class SecretsManagerSecretData:
    """Normalized Secrets Manager secret data."""
    secret_id: str
    secret_arn: str
    name: str
    region: str
    description: Optional[str] = None
    created_date: Optional[datetime] = None
    last_accessed_date: Optional[datetime] = None
    last_rotated_date: Optional[datetime] = None
    days_since_last_access: Optional[int] = None
    rotation_enabled: bool = False
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class SageMakerNotebookData:
    """Normalized SageMaker notebook instance data."""
    notebook_name: str
    notebook_arn: str
    instance_type: str
    status: str  # 'InService', 'Stopped', 'Pending', etc.
    region: str
    creation_time: Optional[datetime] = None
    last_modified_time: Optional[datetime] = None
    volume_size_gb: int = 0
    url: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class SageMakerEndpointData:
    """Normalized SageMaker endpoint data."""
    endpoint_name: str
    endpoint_arn: str
    status: str
    region: str
    creation_time: Optional[datetime] = None
    last_modified_time: Optional[datetime] = None
    instance_type: Optional[str] = None
    instance_count: int = 1
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class SageMakerMetricsData:
    """CloudWatch metrics for a SageMaker endpoint."""
    endpoint_name: str
    invocations_total: int = 0
    invocations_avg: float = 0.0
    model_latency_avg_ms: float = 0.0
    cpu_utilization_avg: float = 0.0
    memory_utilization_avg: float = 0.0
    period_days: int = 7
    is_idle: bool = False


@dataclass
class KinesisStreamData:
    """Normalized Kinesis stream data."""
    stream_name: str
    stream_arn: str
    status: str
    region: str
    shard_count: int = 1
    retention_period_hours: int = 24
    encryption_type: Optional[str] = None
    created_time: Optional[datetime] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class KinesisMetricsData:
    """CloudWatch metrics for a Kinesis stream."""
    stream_name: str
    incoming_records_total: int = 0
    incoming_bytes_total: int = 0
    # None = not measured (an air-gapped export carries no GetRecords
    # series, CLO-488); never read as zero reads.
    get_records_total: Optional[int] = 0
    put_records_success_avg: float = 0.0
    period_days: int = 7
    is_idle: bool = False
    incoming_bytes_daily: Optional[List[float]] = None
    get_records_bytes_total: int = 0
    stream_mode: str = 'PROVISIONED'
    max_incoming_bytes_per_sec: float = 0.0


@dataclass
class KinesisConsumerData:
    """Enhanced fan-out consumer metadata."""
    consumer_name: str
    consumer_arn: str
    stream_arn: str
    consumer_status: str = ''
    consumer_creation_timestamp: Optional[datetime] = None


@dataclass
class KinesisFirehoseData:
    """Kinesis Data Firehose delivery stream metadata."""
    delivery_stream_name: str
    delivery_stream_arn: str = ''
    delivery_stream_status: str = ''
    delivery_stream_type: str = ''
    source_stream_arn: Optional[str] = None
    has_lambda_transform: bool = False
    destination_type: str = ''
    region: Optional[str] = None
    # CLO-457: DescribeDeliveryStream's CreateTimestamp. AWS/Firehose keys
    # its metrics on DeliveryStreamName, a reusable name. None = unknown.
    create_time: Optional[datetime] = None


@dataclass
class KinesisFirehoseMetricsData:
    """CloudWatch metrics for Firehose delivery streams."""
    delivery_stream_name: str
    incoming_records_total: int = 0
    incoming_bytes_total: int = 0
    delivery_to_s3_records_total: int = 0
    period_days: int = 14
    is_idle: bool = False


@dataclass
class MSKClusterData:
    """Normalized MSK cluster data."""
    cluster_name: str
    cluster_arn: str
    # None = the source did not report it (CLO-549: no per-broker read).
    broker_count: Optional[int] = 3
    instance_type: str = 'kafka.m5.large'
    cluster_type: str = 'PROVISIONED'  # 'PROVISIONED' or 'SERVERLESS'
    state: str = 'ACTIVE'
    tags: Dict[str, str] = field(default_factory=dict)
    # CLO-457: ListClusters' ClusterInfo.CreationTime. AWS/Kafka keys its
    # metrics on "Cluster Name", a reusable name. None = unknown.
    creation_time: Optional[datetime] = None


@dataclass
class AMIData:
    """Normalized AMI data for orphan snapshot detection."""
    image_id: str
    name: Optional[str] = None
    state: str = ''  # 'available', 'pending', 'failed', 'deregistered'
    region: str = ''
    creation_date: Optional[datetime] = None
    description: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


# =========================================================================
# AWS Backup
# =========================================================================

@dataclass
class BackupRecoveryPointData:
    """Normalized AWS Backup recovery point data."""
    recovery_point_arn: str
    backup_vault_name: str
    resource_arn: str
    resource_type: str = ''
    status: str = 'COMPLETED'
    creation_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    backup_size_bytes: Optional[int] = None
    lifecycle: Optional[Dict[str, Any]] = None
    is_encrypted: bool = False
    backup_vault_arn: str = ''
    backup_plan_id: Optional[str] = None
    age_days: int = 0
    is_parent: bool = False
    parent_recovery_point_arn: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class BackupPlanData:
    """Normalized AWS Backup plan data."""
    backup_plan_id: str
    backup_plan_name: str
    backup_plan_arn: str = ''
    version_id: Optional[str] = None
    creation_date: Optional[datetime] = None
    last_execution_date: Optional[datetime] = None
    rules: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class BackupSelectionData:
    """Normalized AWS Backup plan selection data."""
    selection_id: str
    selection_name: str
    backup_plan_id: str
    iam_role_arn: str = ''
    resources: List[str] = field(default_factory=list)
    list_of_tags: List[Dict[str, str]] = field(default_factory=list)
    conditions: Optional[Dict[str, Any]] = None
    not_resources: List[str] = field(default_factory=list)


@dataclass
class BackupCopyJobSummary:
    """Summary of AWS Backup cross-region/cross-account copy activity."""
    source_backup_vault_arn: str
    destination_backup_vault_arn: str
    resource_type: str = ''
    state: str = 'COMPLETED'
    creation_date: Optional[datetime] = None
    backup_size_bytes: Optional[int] = None


# =========================================================================
# DocumentDB
# =========================================================================

@dataclass
class DocumentDBClusterData:
    """Normalized DocumentDB cluster data."""
    cluster_identifier: str
    status: str = 'available'
    engine: str = 'docdb'
    engine_version: str = ''
    db_cluster_members: List[Dict[str, Any]] = field(default_factory=list)
    instance_class: str = ''
    num_instances: int = 0
    storage_encrypted: bool = False
    deletion_protection: bool = False
    tags: Dict[str, str] = field(default_factory=dict)
    # CLO-455: for the overprovisioned minimum-age guard. None = unknown.
    cluster_create_time: Optional[datetime] = None


@dataclass
class DocumentDBSnapshotData:
    """Normalized DocumentDB cluster snapshot data."""
    snapshot_identifier: str
    cluster_identifier: str
    status: str = 'available'
    snapshot_type: str = 'manual'
    engine: str = 'docdb'
    engine_version: str = ''
    snapshot_create_time: Optional[datetime] = None
    storage_encrypted: bool = False
    allocated_storage: int = 0  # GiB
    age_days: int = 0
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class DocumentDBMetricsData:
    """Normalized DocumentDB cluster CloudWatch metrics."""
    cluster_identifier: str
    database_connections: float = 0.0
    read_iops: float = 0.0
    write_iops: float = 0.0
    avg_cpu: float = 0.0
    max_cpu: float = 0.0  # window maximum of hourly Maximums; reported, not gated
    # CLO-455: the overprovisioned gates (see online.py's DOCDB_* constants)
    p95_cpu: float = 0.0  # nearest-rank p95 of the hourly CPU Averages
    p95_max_cpu: float = 0.0  # nearest-rank p95 of the hourly CPU Maximums
    cpu_datapoints: int = 0  # hourly CPU datapoints in the window
    period_days: int = 14
    is_idle: bool = False
    is_overprovisioned: bool = False


# =========================================================================
# FSx
# =========================================================================

@dataclass
class FSxFilesystemData:
    """Normalized FSx filesystem data."""
    filesystem_id: str
    filesystem_type: str = ''  # LUSTRE, WINDOWS, ONTAP, OPENZFS
    lifecycle: str = 'AVAILABLE'
    storage_capacity_gb: int = 0
    storage_type: str = 'SSD'  # SSD, HDD
    throughput_capacity_mbps: int = 0
    deployment_type: str = ''
    creation_time: Optional[datetime] = None
    tags: Dict[str, str] = field(default_factory=dict)
    # CLO-512: Lustre persistent storage is priced by MB/s per TiB.
    per_unit_storage_throughput: int = 0


def recovery_point_plan_id(rp: Dict[str, Any]) -> Optional[str]:
    """The backup plan that created a recovery point (CLO-514 review).
    ListRecoveryPointsByBackupVault puts it only under
    ``CreatedBy.BackupPlanId``; a top-level ``BackupPlanId`` /
    ``backup_plan_id`` is accepted as a fallback for hand-shaped exports.
    None for an on-demand point."""
    created_by = rp.get('CreatedBy')
    if isinstance(created_by, dict) and created_by.get('BackupPlanId'):
        return created_by['BackupPlanId']
    return rp.get('BackupPlanId') or rp.get('backup_plan_id') or None


_FSX_CONFIG_KEYS = {
    'WINDOWS': 'WindowsConfiguration',
    'ONTAP': 'OntapConfiguration',
    'OPENZFS': 'OpenZFSConfiguration',
    'LUSTRE': 'LustreConfiguration',
}


def fsx_filesystem_config(fs: Dict[str, Any]) -> Dict[str, Any]:
    """Throughput capacity, deployment type and Lustre per-unit throughput
    from one DescribeFileSystems entry (CLO-512; shared by both providers).
    Each lives in the type's own configuration block."""
    fstype = (fs.get('FileSystemType') or '').upper()
    config = fs.get(_FSX_CONFIG_KEYS.get(fstype, ''), None)
    config = config if isinstance(config, dict) else {}

    def _int(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    return {
        'throughput_capacity_mbps': 0 if fstype == 'LUSTRE' else _int(config.get('ThroughputCapacity')),
        'deployment_type': str(config.get('DeploymentType') or ''),
        'per_unit_storage_throughput': _int(config.get('PerUnitStorageThroughput')),
    }


def fsx_hourly_peak_bytes(series: List[Dict[str, Any]]) -> Optional[int]:
    """Busiest hour of read + write bytes from [{'Timestamp': t, 'Sum': n}]
    datapoints of both metrics (CLO-512); None when there are none."""
    by_hour: Dict[Any, float] = {}
    for point in series:
        if not isinstance(point, dict) or point.get('Timestamp') is None:
            continue
        key = point['Timestamp']
        by_hour[key] = by_hour.get(key, 0.0) + float(point.get('Sum', 0) or 0)
    return int(max(by_hour.values())) if by_hour else None


@dataclass
class FSxMetricsData:
    """Normalized FSx filesystem CloudWatch metrics."""
    filesystem_id: str
    data_read_bytes: int = 0
    data_write_bytes: int = 0
    avg_cpu: float = 0.0
    max_cpu: float = 0.0
    avg_throughput_utilization_pct: float = 0.0
    max_throughput_utilization_pct: float = 0.0
    # CLO-540: None = MISSING (the type publishes no usable free-capacity
    # series, or it was empty or unreadable). Never read as 0 free.
    free_storage_capacity_gb: Optional[float] = None
    period_days: int = 7
    is_idle: bool = False
    # CLO-512: read + write bytes of the busiest hour in the window. None =
    # no hourly data (fsx_throughput_overprovisioned then does not judge).
    peak_hourly_bytes: Optional[int] = None


@dataclass
class FSxBackupData:
    """Normalized FSx backup data."""
    backup_id: str
    filesystem_id: str = ''
    filesystem_type: str = ''
    lifecycle: str = 'AVAILABLE'
    backup_type: str = 'USER_INITIATED'  # USER_INITIATED, AUTOMATIC, AWS_BACKUP
    creation_time: Optional[datetime] = None
    age_days: int = 0
    tags: Dict[str, str] = field(default_factory=dict)
    # CLO-512: DescribeBackups SizeInBytes (data a restore would hold).
    size_bytes: Optional[int] = None


# =========================================================================
# Step Functions
# =========================================================================

@dataclass
class StepFunctionExecutionSummaryData:
    """Summarized execution metrics for a Step Functions state machine."""
    state_machine_arn: str
    total_executions: int = 0
    succeeded: int = 0
    failed: int = 0
    timed_out: int = 0
    aborted: int = 0
    running: int = 0
    period_days: int = 14


@dataclass
class StepFunctionRetryMetricsData:
    """Retry and failure metrics for a Step Functions state machine."""
    state_machine_arn: str
    total_transitions: int = 0
    estimated_retry_transitions: int = 0
    retry_ratio: float = 0.0       # retries / total transitions
    failure_rate: float = 0.0      # failed / total executions
    period_days: int = 14


@dataclass
class StepFunctionTransitionMetricsData:
    """Transition density metrics for a Step Functions state machine."""
    state_machine_arn: str
    total_transitions: int = 0
    successful_executions: int = 0
    avg_transitions_per_success: float = 0.0
    p95_duration_ms: float = 0.0   # Used for Express duration waste
    avg_duration_ms: float = 0.0
    monthly_execution_estimate: int = 0
    period_days: int = 14


# =========================================================================
# Glue
# =========================================================================

@dataclass
class GlueJobData:
    """Glue job configuration and metadata."""
    name: str
    max_capacity: Optional[float] = None
    number_of_workers: Optional[int] = None
    worker_type: str = 'Standard'
    timeout: int = 2880
    max_retries: int = 0
    last_modified: Optional[datetime] = None
    created: Optional[datetime] = None
    glue_version: Optional[str] = None
    command_name: Optional[str] = None  # 'glueetl', 'gluestreaming', 'pythonshell'


@dataclass
class GlueCrawlerData:
    """Glue crawler configuration and metadata."""
    name: str
    state: str = 'READY'
    last_crawl_time: Optional[datetime] = None
    last_crawl_status: Optional[str] = None
    created: Optional[datetime] = None
    schedule: Optional[str] = None


@dataclass
class GlueJobRunData:
    """Glue job run execution details."""
    job_name: str
    run_id: str
    state: str  # STARTING, RUNNING, STOPPING, STOPPED, SUCCEEDED, FAILED, TIMEOUT, ERROR
    execution_time: int = 0  # seconds
    started_on: Optional[datetime] = None
    completed_on: Optional[datetime] = None
    error_message: Optional[str] = None
    dpu_seconds: Optional[float] = None


@dataclass
class GlueCatalogStats:
    """Glue Data Catalog object counts."""
    databases: int = 0
    tables: int = 0
    table_versions: int = 0
    partitions: int = 0
    total_objects: int = 0


@dataclass
class GlueMetricsData:
    """Glue CloudWatch metrics."""
    job_name: str
    jvm_heap_usage_avg: Optional[float] = None       # %
    completed_tasks_sum: Optional[float] = None
    failed_tasks_sum: Optional[float] = None


@dataclass
class TransferServerData:
    """Transfer Family server details."""
    server_id: str
    state: str = 'ONLINE'
    protocols: List[str] = field(default_factory=lambda: ['SFTP'])
    identity_provider_type: Optional[str] = None
    endpoint_type: Optional[str] = None
    domain: Optional[str] = None
    user_count: int = 0


@dataclass
class TransferWebAppData:
    """Transfer Family Web App details."""
    web_app_id: str
    provisioned_units: int = 1
    arn: Optional[str] = None


@dataclass
class TransferMetricsData:
    """Transfer Family CloudWatch metrics."""
    server_id: str
    files_in: Optional[float] = None
    files_out: Optional[float] = None
    bytes_in: Optional[float] = None
    bytes_out: Optional[float] = None


# ── ECS / Fargate ──────────────────────────────────────────────────────────


@dataclass
class ECSClusterData:
    """ECS cluster details."""
    cluster_arn: str
    cluster_name: str
    status: str = 'ACTIVE'
    active_services_count: int = 0
    running_tasks_count: int = 0
    settings: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ECSServiceData:
    """ECS service details."""
    service_arn: str
    service_name: str
    cluster_arn: str
    status: str = 'ACTIVE'
    desired_count: int = 0
    running_count: int = 0
    launch_type: str = 'FARGATE'
    task_definition: str = ''
    deployments: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ECSTaskDefinitionData:
    """ECS task definition details."""
    task_definition_arn: str
    family: str
    cpu: str = '256'
    memory: str = '512'
    requires_compatibilities: List[str] = field(default_factory=lambda: ['FARGATE'])
    container_definitions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ECSMetricsData:
    """ECS CloudWatch metrics for a service."""
    cluster_name: str
    service_name: str
    avg_cpu_utilization: Optional[float] = None
    max_cpu_utilization: Optional[float] = None
    avg_memory_utilization: Optional[float] = None
    max_memory_utilization: Optional[float] = None


@dataclass
class EKSClusterData:
    """EKS cluster details for version lifecycle detectors."""
    cluster_name: str
    version: str
    status: str = 'ACTIVE'
    region: str = ''
    platform_version: str = ''
    cluster_arn: str = ''
    created_at: Optional[datetime] = None


@dataclass
class AppSyncCacheData:
    """AppSync API cache configuration."""
    api_id: str
    cache_type: str          # T2_SMALL, R4_XLARGE, etc.
    status: str              # AVAILABLE, CREATING, DELETING, etc.
    ttl: int                 # Cache TTL in seconds
    caching_behavior: str    # FULL_REQUEST_CACHING, PER_RESOLVER_CACHING


# ── Aurora ─────────────────────────────────────────────────────────────────


@dataclass
class AuroraClusterInstanceRef:
    """Reference to an instance within an Aurora cluster."""
    db_instance_id: str
    db_instance_class: str
    is_writer: bool
    multi_az: bool = False
    # CLO-457: the member instance's InstanceCreateTime (see RDSInstanceData).
    instance_create_time: Optional[datetime] = None


@dataclass
class AuroraClusterData:
    """Normalized Aurora cluster data."""
    cluster_id: str
    engine: str                        # 'aurora-postgresql' or 'aurora-mysql'
    engine_version: str                # e.g., '15.4', '12.14'
    engine_mode: str                   # 'provisioned' or 'serverless'
    storage_type: str                  # 'aurora' (Standard) or 'aurora-iopt1' (I/O-Optimized)
    status: str                        # 'available', 'stopped', etc.
    region: str
    instances: List[AuroraClusterInstanceRef] = field(default_factory=list)
    serverless_v2_config: Optional[Dict] = None  # min/max ACU if Serverless v2
    is_global_secondary: bool = False
    tags: Dict[str, str] = field(default_factory=dict)
    # CLO-457: DescribeDBClusters' ClusterCreateTime. The cluster-level
    # AWS/RDS metrics are keyed on DBClusterIdentifier, a NAME.
    cluster_create_time: Optional[datetime] = None


@dataclass
class AuroraIOMetricsData:
    """CloudWatch I/O metrics for an Aurora cluster."""
    cluster_id: str
    volume_read_iops_sum: float = 0.0   # Total read I/Os over period
    volume_write_iops_sum: float = 0.0  # Total write I/Os over period
    volume_bytes_used_avg: float = 0.0  # Average storage bytes used
    period_days: int = 30


# ─── Neptune Models ───────────────────────────────────────────────────


@dataclass
class NeptuneClusterInstanceRef:
    """Reference to an instance within a Neptune cluster."""
    db_instance_id: str
    db_instance_class: str
    is_writer: bool


@dataclass
class NeptuneClusterData:
    """Normalized Neptune cluster data."""
    cluster_id: str
    engine: str                        # 'neptune'
    engine_version: str                # e.g., '1.3.1.0'
    engine_mode: str                   # 'provisioned' or 'serverless'
    status: str                        # 'available', 'stopped', etc.
    region: str
    instances: List[NeptuneClusterInstanceRef] = field(default_factory=list)
    serverless_v2_config: Optional[Dict] = None  # min/max NCU if Serverless
    tags: Dict[str, str] = field(default_factory=dict)
    # CLO-480: for oversized_neptune's minimum-age guard. None = unknown.
    cluster_create_time: Optional[datetime] = None


@dataclass
class NeptuneSnapshotData:
    """Normalized Neptune cluster snapshot data."""
    snapshot_id: str
    cluster_id: str
    snapshot_type: str                 # 'manual' or 'automated'
    status: str
    engine: str
    allocated_storage_gb: int
    create_time: Optional[datetime] = None
    age_days: int = 0


@dataclass
class NeptuneMetricsData:
    """Normalized Neptune cluster CloudWatch metrics."""
    cluster_id: str
    # CLO-584: floats, not int -- a lightly used cluster's per-second-rate
    # Sum over the window can be well under 1, and an int() truncation made
    # that indistinguishable from true zero traffic.
    gremlin_requests: float = 0.0
    sparql_requests: float = 0.0
    avg_cpu: float = 0.0
    max_cpu: float = 0.0  # window maximum of hourly Maximums; reported, not gated by oversized_neptune
    # CLO-480: the shared CPU rule's inputs (cloudwise_scan_core.cpu_sizing)
    p95_cpu: float = 0.0  # nearest-rank p95 of the hourly CPU Averages
    p95_max_cpu: float = 0.0  # nearest-rank p95 of the hourly CPU Maximums
    cpu_datapoints: int = 0  # hourly CPU datapoints in the window
    period_days: int = 14
    # The window the CPU was actually collected over, when shorter than
    # period_days (an air-gapped export collects 7 days); None = period_days.
    # The coverage gate is measured against it.
    cpu_window_days: Optional[int] = None
    is_idle: bool = False


# =========================================================================
# Amazon MQ
# =========================================================================

@dataclass
class MQBrokerData:
    """Normalized Amazon MQ broker data."""
    broker_id: str
    broker_name: str
    engine_type: str          # 'ACTIVEMQ' or 'RABBITMQ'
    host_instance_type: str   # e.g., 'mq.m5.large'
    deployment_mode: str      # 'SINGLE_INSTANCE', 'ACTIVE_STANDBY_MULTI_AZ', 'CLUSTER_MULTI_AZ'
    broker_state: str         # 'RUNNING', 'CREATION_IN_PROGRESS', etc.
    region: str
    # CLO-457: ListBrokers' BrokerSummary.Created. AWS/AmazonMQ keys its
    # metrics on the broker NAME, which is reusable. None = unknown.
    created: Optional[datetime] = None


# =========================================================================
# Lightsail
# =========================================================================

@dataclass
class LightsailInstanceData:
    """Lightsail instance metadata."""
    name: str
    state: str                    # 'running', 'stopped', 'pending', 'starting'
    bundle_id: str                # e.g., 'nano_2_0', 'medium_2_0'
    blueprint_id: str             # e.g., 'amazon_linux_2', 'wordpress'
    ip_address: Optional[str] = None
    is_static_ip: bool = False
    region: Optional[str] = None


@dataclass
class LightsailStaticIpData:
    """Lightsail static IP metadata."""
    name: str
    ip_address: str
    is_attached: bool
    attached_to: Optional[str] = None  # Instance name if attached
    region: Optional[str] = None


@dataclass
class LightsailDiskData:
    """Lightsail additional block storage disk."""
    name: str
    size_in_gb: int
    state: str                     # 'available', 'in-use', 'error'
    is_attached: bool
    attached_to: Optional[str] = None  # Instance name if attached
    path: Optional[str] = None
    region: Optional[str] = None


@dataclass
class LightsailSnapshotData:
    """Lightsail instance snapshot."""
    name: str
    size_in_gb: int
    created_at: datetime
    from_instance_name: Optional[str] = None
    is_from_auto_snapshot: bool = False
    region: Optional[str] = None


@dataclass
class LightsailLoadBalancerData:
    """Lightsail load balancer."""
    name: str
    dns_name: str
    instance_port: int
    health_check_path: str
    instance_health_summary: List[Dict[str, str]] = field(default_factory=list)
    tls_certificate_summaries: List[Dict[str, str]] = field(default_factory=list)
    region: Optional[str] = None


@dataclass
class LightsailDatabaseData:
    """Lightsail managed database."""
    name: str
    state: str                     # 'available', 'stopped', 'creating', 'deleting'
    engine: str                    # 'mysql', 'postgres'
    engine_version: str
    bundle_id: str                 # e.g., 'micro_2_0'
    master_database_name: str
    secondary_availability_zone: Optional[str] = None  # Populated if HA
    region: Optional[str] = None


@dataclass
class LightsailMetricsData:
    """CloudWatch metrics for a Lightsail resource."""
    resource_name: str
    avg_cpu: Optional[float] = None        # Average CPU over 14 days
    max_cpu: Optional[float] = None        # Max CPU over 14 days
    avg_connections: Optional[float] = None # Average DB connections (databases only)
    avg_network_in: Optional[float] = None # Average NetworkIn bytes
    avg_network_out: Optional[float] = None # Average NetworkOut bytes
    # CLO-506: hourly CPU datapoints behind avg_cpu, and the hours they were
    # read over. None = not recorded; an idle verdict needs 75% coverage.
    cpu_datapoints: Optional[int] = None
    cpu_window_hours: Optional[int] = None


@dataclass
class ReservedInstanceData:
    """Normalized EC2 Reserved Instance data."""
    reserved_instances_id: str
    instance_type: str
    instance_count: int
    state: str                    # 'active', 'payment-pending', 'retired', 'payment-failed'
    offering_class: str           # 'standard' | 'convertible'
    offering_type: str            # 'No Upfront' | 'Partial Upfront' | 'All Upfront'
    start_date: str               # ISO 8601
    end_date: str                 # ISO 8601
    tenancy: str                  # 'default' | 'dedicated' | 'host'
    product_description: str      # 'Linux/UNIX' | 'Windows' | etc.
    monthly_effective_cost: float = 0.0
    on_demand_equivalent_monthly_cost: float = 0.0


@dataclass
class SavingsPlanData:
    """Normalized Savings Plan data."""
    savings_plan_id: str
    savings_plan_arn: str
    savings_plan_type: str           # 'Compute', 'EC2Instance', 'SageMaker'
    payment_option: str              # 'No Upfront', 'Partial Upfront', 'All Upfront'
    state: str                       # 'active', 'expired', 'retired'
    start_time: str                  # ISO 8601
    end_time: str                    # ISO 8601
    commitment: float                # Hourly commitment in USD
    term_duration_seconds: int = 0
    region: str = ''
    instance_family: str = ''        # For EC2Instance SPs only
    monthly_commitment: float = 0.0  # Computed: commitment × 730


@dataclass
class EMRClusterData:
    """Normalized EMR cluster data."""
    cluster_id: str
    cluster_name: str
    state: str                              # 'STARTING', 'BOOTSTRAPPING', 'RUNNING', 'WAITING', 'TERMINATING', 'TERMINATED'
    cluster_arn: str = ''
    region: Optional[str] = None
    release_label: str = ''                 # e.g. 'emr-6.15.0'
    # CLO-574: DescribeCluster's Cluster shape has neither AutoTerminationPolicy
    # nor KeepJobFlowAliveWhenNoSteps (botocore 1.40.21 confirmed) -- the real
    # policy comes only from GetAutoTerminationPolicy. `auto_termination_policy`
    # is meaningful ONLY when `auto_termination_unknown` is False: None then
    # means a successful GetAutoTerminationPolicy call confirmed no policy. The
    # default is "unknown" (safe): a provider that forgets to set this after a
    # successful read never has the detector read None as a confirmed no-policy
    # answer.
    auto_termination_policy: Optional[Dict] = None  # {'IdleTimeout': 3600} or None (confirmed)
    auto_termination_unknown: bool = True   # True = not read / read failed; withhold the finding
    keep_alive: bool = True                 # derived from NOT Cluster.AutoTerminate
    ready_datetime: Optional[datetime] = None
    created_datetime: Optional[datetime] = None
    instance_groups: List[Dict] = field(default_factory=list)
    total_instances: int = 0
    master_instance_type: str = ''
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class EMRInstanceGroupData:
    """Normalized EMR instance group data."""
    instance_group_id: str
    instance_group_type: str    # 'MASTER', 'CORE', 'TASK'
    instance_type: str          # e.g. 'm5.xlarge'
    market: str = 'ON_DEMAND'   # 'ON_DEMAND' or 'SPOT'
    running_instance_count: int = 0
    requested_instance_count: int = 0
    ebs_config: Optional[Dict] = None
    status: str = 'RUNNING'


@dataclass
class EMRStepSummaryData:
    """Summary of EMR step execution history."""
    cluster_id: str
    total_steps: int = 0
    completed_steps: int = 0
    last_step_end_time: Optional[datetime] = None
    running_steps: int = 0
    pending_steps: int = 0


@dataclass
class EMRMetricsData:
    """CloudWatch metrics for an EMR cluster."""
    cluster_id: str
    is_idle: bool = False
    yarn_memory_available_pct: float = 0.0
    apps_running_avg: float = 0.0
    apps_pending_avg: float = 0.0
    hdfs_utilization_pct: float = 0.0
    core_nodes_running_avg: float = 0.0
    period_days: int = 14


@dataclass
class WorkspaceData:
    """Normalized WorkSpace data."""
    workspace_id: str
    bundle_id: str
    state: str                          # 'AVAILABLE', 'STOPPED', 'IMPAIRED', etc.
    running_mode: str = 'ALWAYS_ON'     # 'ALWAYS_ON' or 'AUTO_STOP'
    compute_type: str = 'STANDARD'      # 'VALUE', 'STANDARD', 'PERFORMANCE', 'POWER', etc.
    operating_system: str = ''          # 'WINDOWS', 'AMAZON_LINUX_2', etc.
    region: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class WorkspaceConnectionData:
    """Connection status for a WorkSpace."""
    workspace_id: str
    connection_state: str = ''          # 'CONNECTED', 'DISCONNECTED', 'UNKNOWN'
    last_known_user_connection_timestamp: Optional[datetime] = None


@dataclass
class WorkspacePoolData:
    """Normalized WorkSpaces Pool data."""
    pool_id: str
    pool_name: str
    state: str = ''                     # 'CREATING', 'AVAILABLE', etc.
    desired_user_sessions: int = 0
    running_user_sessions: int = 0


@dataclass
class WorkspaceMetricsData:
    """CloudWatch metrics for a WorkSpace."""
    workspace_id: str
    user_sessions_max_daily: List[float] = field(default_factory=list)
    user_connected_sum_daily: List[float] = field(default_factory=list)
    period_days: int = 14
    observation_days: int = 0           # days with actual data points
    # CLO-506: the WorkSpace's own load (AWS/WorkSpaces CPUUsage and
    # MemoryUsage, hourly Maximum). None = not read or not covered: an
    # oversized verdict is MISSING. utilization_days is the number of days
    # with both series present.
    cpu_peak_p95: Optional[float] = None
    memory_peak_max: Optional[float] = None
    utilization_days: int = 0


@dataclass
class BeanstalkEnvironmentData:
    """Normalized Elastic Beanstalk environment data."""
    environment_id: str
    environment_name: str
    application_name: str
    status: str                         # 'Launching', 'Updating', 'Ready', 'Terminating', 'Terminated'
    health: str                         # 'Green', 'Yellow', 'Red', 'Grey'
    health_status: str = ''             # Enhanced health: 'Ok', 'Info', 'Warning', 'Degraded', 'Severe', 'Suspended'
    tier: str = 'WebServer'             # 'WebServer' or 'Worker'
    platform_arn: str = ''
    version_label: str = ''
    cname: str = ''
    date_created: Optional[datetime] = None
    date_updated: Optional[datetime] = None
    endpoint_url: str = ''
    solution_stack_name: str = ''
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class BeanstalkConfigData:
    """Normalized Elastic Beanstalk environment configuration."""
    environment_id: str
    instance_type: str = 't3.micro'
    instance_count: int = 1
    environment_type: str = 'SingleInstance'   # 'SingleInstance' or 'LoadBalanced'
    load_balancer_type: str = ''               # 'application', 'classic', 'network'
    min_size: int = 1
    max_size: int = 1
    rds_endpoint: str = ''
    rds_instance_type: str = ''
    ebs_volume_type: str = 'gp3'
    ebs_volume_size: int = 10                  # GB


def beanstalk_rds_marks(tags: Dict[str, str]) -> Optional[Dict[str, str]]:
    """Elastic Beanstalk's own marks on an RDS instance (CLO-515/CLO-506),
    or None when it carries none.

    Beanstalk propagates ``elasticbeanstalk:environment-id``/``-name`` to
    what it creates, and its CloudFormation stack is ``awseb-<env id>-stack``.
    Returns ``{'env_id', 'env_name', 'stack_env_id'}`` (empty strings for the
    marks absent)."""
    tags = tags or {}
    stack_name = tags.get('aws:cloudformation:stack-name', '') or ''
    stack_env_id = ''
    if stack_name.startswith('awseb-') and stack_name.endswith('-stack'):
        stack_env_id = stack_name[len('awseb-'):-len('-stack')]
    marks = {
        'env_id': tags.get('elasticbeanstalk:environment-id', '') or '',
        'env_name': tags.get('elasticbeanstalk:environment-name', '') or '',
        'stack_env_id': stack_env_id,
    }
    return marks if any(marks.values()) else None


@dataclass
class ApiGatewayRestApiData:
    """A REST API (API Gateway v1), from GetRestApis (CLO-507)."""
    api_id: str
    name: str
    created_date: Optional[datetime] = None
    endpoint_types: List[str] = field(default_factory=list)


@dataclass
class BeanstalkMetricsData:
    """CloudWatch metrics for a Beanstalk environment."""
    environment_name: str
    request_count_14d: int = -1         # -1 = no data, 0 = zero requests, >0 = active
    avg_cpu_14d: float = -1.0           # Average CPU utilization over 14 days
    environment_health_avg: float = 0.0 # Average EnvironmentHealth metric
    period_days: int = 14
    # CLO-524: where the measurements came from and how much of the window
    # they cover. request_count_14d is -1 unless its source covered 75% of
    # the window's days; avg_cpu_14d is -1 unless the environment's
    # instances reported CPU for 75% of the window's hours.
    request_source: str = ''            # 'alb', 'elb' (Classic), 'enhanced_health' or ''
    request_coverage_days: int = 0      # days the request source (or its liveness metric) reported
    cpu_coverage_hours: int = 0         # hours with CPU from at least one instance
    instance_ids: List[str] = field(default_factory=list)  # running instances, by tag
    load_balancer: str = ''             # ALB dimension value or Classic ELB name
    missing_reason: str = ''            # why a measurement is MISSING, when it is


@dataclass
class GlobalAcceleratorData:
    """Normalized Global Accelerator data for waste detection."""
    name: str
    arn: str
    status: str                     # DEPLOYED, IN_PROGRESS
    enabled: bool
    ip_addresses: List[str] = field(default_factory=list)
    dns_name: str = ''
    created_time: Optional[str] = None
    listeners: List[Dict] = field(default_factory=list)
    endpoint_groups: List[Dict] = field(default_factory=list)
    # CLO-550: None when the listener / endpoint-group reads are MISSING
    # (failed, or an export that cannot tell a failed read from none).
    has_endpoints: Optional[bool] = False
    # CloudWatch metrics (optional, for idle detection). CLO-485: None when
    # the read failed (MISSING, not zero); the idle gate needs a real 0.
    processed_bytes_in_sum: Optional[float] = 0.0
    processed_bytes_out_sum: Optional[float] = 0.0
    metrics_period_days: int = 30


@dataclass(frozen=True)
class CounterRead:
    """One CloudWatch COUNTER read and how it ended (CLO-546 follow-up).

    The Transfer Family reads (``get_transfer_metrics``,
    ``get_transfer_web_app_metrics``) return this instead of an
    ``Optional[float]``, so "the read succeeded and the series was empty"
    and "the read failed" are never told apart by an overloaded None/0:

    - ``MEASURED``: datapoints came back; ``total`` is their Sum (may be 0).
    - ``EMPTY``: the read succeeded with no datapoints. For a counter metric,
      published only when something happens (AWS/Transfer FilesIn, FilesOut,
      ActiveSessions), that is a measured zero (CLO-485's counter rule), but
      only for a resource that existed for the whole window: the detector
      applies the age gate. Offline: an exported file whose series is empty
      (the CLO-485 upload-parser convention).
    - ``MISSING``: the read failed (exception, access denied) or, offline,
      the series was never exported. Not zero: the verdict is withheld and
      noted; ``reason`` says why.
    """

    MEASURED = 'measured'
    EMPTY = 'empty'
    MISSING = 'missing'

    status: str
    total: float = 0.0
    reason: str = ''

    @classmethod
    def from_datapoints(cls, datapoints: List[Dict[str, Any]], stat: str = 'Sum') -> 'CounterRead':
        """A successful read: EMPTY with no datapoints, else MEASURED."""
        if not datapoints:
            return cls(cls.EMPTY)
        return cls(cls.MEASURED, float(sum(dp.get(stat) or 0 for dp in datapoints)))

    @classmethod
    def missing(cls, reason: str) -> 'CounterRead':
        return cls(cls.MISSING, 0.0, reason)

    @property
    def is_missing(self) -> bool:
        return self.status == self.MISSING

    @property
    def value(self) -> Optional[float]:
        """The measured total (0.0 for EMPTY); None only when MISSING."""
        return None if self.is_missing else self.total
