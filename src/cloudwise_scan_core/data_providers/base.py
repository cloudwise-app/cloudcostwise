"""
Base Waste Data Provider Interface

This abstract base class defines the interface for data access in waste detection.
Implementations include OnlineDataProvider (live AWS APIs) and OfflineDataProvider
(parsed JSON exports).

The detector logic remains unchanged - only the data source differs.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any

from cloudwise_scan_core.cloudwatch_metrics_service import MSKMetrics
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
    StepFunctionExecutionSummaryData,
    StepFunctionRetryMetricsData,
    StepFunctionTransitionMetricsData,
    EKSClusterData,
    AuroraClusterData,
    AuroraIOMetricsData,
    NeptuneClusterData,
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
    GlobalAcceleratorData,
)


class WasteDataProvider(ABC):
    """
    Abstract base class for waste detection data providers.
    
    This interface allows the same detector logic to work with different
    data sources:
    - OnlineDataProvider: Live AWS API calls via boto3
    - OfflineDataProvider: Parsed JSON export files
    
    All methods are async to support concurrent data fetching.
    """
    
    @property
    @abstractmethod
    def provider_type(self) -> str:
        """Return 'online' or 'offline' to identify the provider type."""
        pass
    
    @property
    @abstractmethod
    def region(self) -> str:
        """Return the AWS region this provider is configured for."""
        pass
    
    @property
    def supports_cloudwatch(self) -> bool:
        """Whether this provider has CloudWatch metrics available."""
        return True
    
    # =========================================================================
    # EC2 / Compute
    # =========================================================================
    
    @abstractmethod
    async def get_ec2_instances(self) -> List[EC2InstanceData]:
        """Get all EC2 instances in the region."""
        pass
    
    @abstractmethod
    async def get_ec2_metrics(
        self,
        instance_ids: List[str],
        days: int = 14,
        idle_threshold: float = 5.0,
        oversized_threshold: float = 40.0,
    ) -> Dict[str, EC2MetricsData]:
        """
        Get CloudWatch metrics for EC2 instances.
        
        Args:
            instance_ids: List of instance IDs to fetch metrics for
            days: Number of days of metrics to analyze
            idle_threshold: CPU % below which instance is considered idle
            oversized_threshold: CPU % below which instance may be oversized
            
        Returns:
            Dict mapping instance_id to EC2MetricsData
        """
        pass
    
    # =========================================================================
    # EBS / Storage
    # =========================================================================
    
    @abstractmethod
    async def get_ebs_volumes(self) -> List[EBSVolumeData]:
        """Get all EBS volumes in the region."""
        pass
    
    @abstractmethod
    async def get_ebs_iops_peaks(
        self,
        volume_ids: List[str],
        days: int = 14,
        deadline: Optional[float] = None,
    ) -> Dict[str, EBSIopsPeakData]:
        """CLO-516: each volume's peak one-minute IOPS (VolumeReadOps +
        VolumeWriteOps) over the last ``days``.

        A volume LEFT OUT of the map could not be measured (read failed,
        under 75% of the window's minutes, over the time budget, not in the
        export): its over_provisioned_iops verdict is MISSING, not zero, and
        providers note it in ``data_warnings``. ``deadline`` is a
        ``time.monotonic()`` instant after which no new read starts."""
        pass

    @abstractmethod
    async def get_ebs_snapshots(
        self,
        owner_ids: Optional[List[str]] = None,
        age_threshold_days: int = 90,
    ) -> List[EBSSnapshotData]:
        """
        Get EBS snapshots in the region.
        
        Args:
            owner_ids: Filter by owner account IDs (default: self)
            age_threshold_days: Only return snapshots older than this
            
        Returns:
            List of EBSSnapshotData
        """
        pass
    
    @abstractmethod
    async def get_elastic_ips(self) -> List[ElasticIPData]:
        """Get all Elastic IPs in the region."""
        pass
    
    # =========================================================================
    # RDS / Databases
    # =========================================================================
    
    @abstractmethod
    async def get_rds_instances(self) -> List[RDSInstanceData]:
        """Get all RDS instances in the region."""
        pass
    
    @abstractmethod
    async def get_rds_metrics(
        self,
        db_instance_ids: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
        include_cpu: bool = False,
    ) -> Dict[str, RDSMetricsData]:
        """
        Get CloudWatch metrics for RDS instances.
        
        Args:
            db_instance_ids: List of RDS instance IDs
            days: Number of days of metrics to analyze
            create_times: CLO-457. Optional creation time per id. The
                dimension is a NAME, so a resource recreated under a reused
                name would otherwise inherit its predecessor's datapoints;
                with a creation time, datapoints from before it are excluded.
            include_cpu: CLO-485. Also fill cpu_avg, cpu_max and
                cpu_datapoints from hourly CPUUtilization (the Aurora sizing
                detectors' CPU gates). A provider that cannot read CPU sets
                cpu_datapoints to 0, never a silent 0.0% CPU.
            
        Returns:
            Dict mapping db_instance_id to RDSMetricsData
        """
        pass
    
    @abstractmethod
    async def get_rds_snapshots(
        self,
        snapshot_type: str = "manual",
        age_threshold_days: int = 90,
    ) -> List[RDSSnapshotData]:
        """
        Get RDS snapshots in the region.
        
        Args:
            snapshot_type: 'manual' or 'automated'
            age_threshold_days: Only return snapshots older than this
            
        Returns:
            List of RDSSnapshotData
        """
        pass
    
    # =========================================================================
    # Lambda / Serverless
    # =========================================================================
    
    @abstractmethod
    async def get_lambda_functions(self) -> List[LambdaFunctionData]:
        """Get all Lambda functions in the region."""
        pass
    
    @abstractmethod
    async def get_lambda_metrics(
        self,
        function_names: List[str],
        days: int = 30,
    ) -> Dict[str, LambdaMetricsData]:
        """
        Get CloudWatch metrics for Lambda functions.
        
        Args:
            function_names: List of function names
            days: Number of days of metrics to analyze
            
        Returns:
            Dict mapping function_name to LambdaMetricsData
        """
        pass

    @abstractmethod
    async def get_lambda_provisioned_concurrency(
        self, function_name: str
    ) -> List[LambdaProvisionedConcurrencyData]:
        """Get Provisioned Concurrency configurations for a Lambda function."""
        return []

    @abstractmethod
    async def get_lambda_provisioned_concurrency_bulk(
        self, function_names: List[str]
    ) -> Dict[str, List[LambdaProvisionedConcurrencyData]]:
        """PC configs for many functions, keyed by function name (CLO-481).

        A function left out of the map is one whose lookup failed: its PC
        is MISSING, not "none", and the detector skips its idle-PC check.
        """
        return {}
    
    # =========================================================================
    # Network
    # =========================================================================
    
    @abstractmethod
    async def get_nat_gateways(self) -> List[NATGatewayData]:
        """Get all NAT Gateways in the region."""
        pass
    
    @abstractmethod
    async def get_nat_gateway_metrics(
        self,
        nat_gateway_ids: List[str],
        days: int = 7,
    ) -> Dict[str, NATGatewayMetricsData]:
        """
        Get CloudWatch metrics for NAT Gateways.
        
        Args:
            nat_gateway_ids: List of NAT Gateway IDs
            days: Number of days of metrics to analyze
            
        Returns:
            Dict mapping nat_gateway_id to NATGatewayMetricsData
        """
        pass
    
    @abstractmethod
    async def get_load_balancers(self) -> List[LoadBalancerData]:
        """Get all Load Balancers (ALB, NLB, CLB) in the region."""
        pass
    
    @abstractmethod
    async def get_load_balancer_metrics(
        self,
        load_balancer_arns: List[str],
        days: int = 7,
    ) -> Dict[str, LoadBalancerMetricsData]:
        """
        Get CloudWatch metrics for Load Balancers.
        
        Args:
            load_balancer_arns: List of load balancer ARNs
            days: Number of days of metrics to analyze
            
        Returns:
            Dict mapping load_balancer_arn to LoadBalancerMetricsData
        """
        pass
    
    # =========================================================================
    # S3
    # =========================================================================
    
    @abstractmethod
    async def get_s3_buckets(self) -> List[S3BucketData]:
        """
        Get all S3 buckets with lifecycle policy info.
        
        Note: S3 is a global service, but this should be called
        only from us-east-1 to avoid duplicate results.
        """
        pass
    
    @abstractmethod
    async def get_s3_cost_breakdown(self) -> Dict[str, S3CostBreakdown]:
        """Get per-bucket S3 cost breakdown from CUR / Cost Explorer data.
        
        Returns:
            Dict mapping bucket_name to S3CostBreakdown.
            Only includes buckets with cost data.
        """
        pass

    @abstractmethod
    async def get_extended_support_cost_breakdown(
        self,
        service_keys: Optional[List[str]] = None,
        days: int = 30,
    ) -> Dict[str, ExtendedSupportCostData]:
        """Get extended support surcharges from billing data.

        Returns:
            Dict keyed by `service` or `service:resource_id` with surcharge totals.
        """
        pass
    
    # =========================================================================
    # EFS
    # =========================================================================
    
    @abstractmethod
    async def get_efs_filesystems(self) -> List[EFSFilesystemData]:
        """Get all EFS filesystems in the region."""
        pass
    
    # =========================================================================
    # ECR
    # =========================================================================
    
    @abstractmethod
    async def get_ecr_repositories(self) -> List[ECRRepositoryData]:
        """Get all ECR repositories in the region."""
        pass
    
    # =========================================================================
    # Route 53
    # =========================================================================
    
    @abstractmethod
    async def get_route53_zones(self) -> List[Route53ZoneData]:
        """
        Get all Route 53 hosted zones.
        
        Note: Route 53 is a global service, call from us-east-1.
        """
        pass

    @abstractmethod
    async def get_vpc_endpoints(self) -> List["VPCEndpointData"]:
        """Get all VPC endpoints in the region."""
        pass

    @abstractmethod
    async def get_vpc_endpoint_bytes_processed(
        self,
        endpoints: List["VPCEndpointData"],
        days: int = 14,
    ) -> Optional[Dict[str, float]]:
        """CLO-528: total ``AWS/PrivateLinkEndpoints`` BytesProcessed over the
        last ``days`` per interface endpoint id.

        None means this provider carries no PrivateLink metrics at all (the
        caller falls back to its structural heuristic). Otherwise an endpoint
        is in the dict only when it was measured: a failed or partial read
        (StatusCode not Complete), or an all-zero series under 75% daily
        coverage leaves it out (MISSING, noted as a scan warning), never 0.

        CLO-533: idle endpoints publish no datapoints at all. A Complete,
        empty series is 0 only for an endpoint at least ``days`` old whose
        series identity is confirmed (another endpoint in the same request
        returned datapoints, or ListMetrics shows the exact 4-dimension
        series in the region); otherwise it is MISSING."""
        pass
    
    # =========================================================================
    # DynamoDB
    # =========================================================================
    
    @abstractmethod
    async def get_dynamodb_tables(self) -> List[DynamoDBTableData]:
        """Get all DynamoDB tables in the region."""
        pass
    
    @abstractmethod
    async def get_dynamodb_metrics(
        self,
        table_names: List[str],
        days: int = 14,
    ) -> Dict[str, DynamoDBMetricsData]:
        """
        Get CloudWatch metrics for DynamoDB tables.
        
        Args:
            table_names: List of table names
            days: Number of days of metrics to analyze
            
        Returns:
            Dict mapping table_name to DynamoDBMetricsData
        """
        pass
    
    # =========================================================================
    # ElastiCache
    # =========================================================================
    
    @abstractmethod
    async def get_elasticache_clusters(self) -> List[ElastiCacheClusterData]:
        """Get all ElastiCache clusters in the region."""
        pass
    
    @abstractmethod
    async def get_elasticache_metrics(
        self,
        cluster_ids: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
        idle_window_days: Optional[int] = None,
    ) -> Dict[str, ElastiCacheMetricsData]:
        """
        Get CloudWatch metrics for ElastiCache clusters.
        
        Args:
            cluster_ids: List of cluster IDs
            days: Number of days of metrics to analyze
            create_times: CLO-457. Optional creation time per id. The
                dimension is a NAME, so a resource recreated under a reused
                name would otherwise inherit its predecessor's datapoints;
                with a creation time, datapoints from before it are excluded.
            idle_window_days: CLO-485. Set by the idle detector: the window
                its claim is about. ``is_idle`` needs 75% of it observed
                (``days`` when not given), and a verdict withheld for missing
                data is reported as a scan warning.
            
        Returns:
            Dict mapping cluster_id to ElastiCacheMetricsData
        """
        pass

    @abstractmethod
    async def get_elasticache_request_volume(
        self,
        cluster_ids: List[str],
        days: int = 30,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, ElastiCacheRequestVolumeData]:
        """CLO-508: each node's command count and network bytes over the
        window (see ElastiCacheRequestVolumeData), for the Serverless ECPU
        estimate of elasticache_serverless_optimization.

        A cluster LEFT OUT of the map could not be measured (read failed, no
        datapoints, under 75% coverage of the window): its Serverless
        estimate is MISSING, not zero. The Air-Gapped export carries no
        command counts, so offline every cluster is left out and the detector
        notes it in ``data_warnings``."""
        pass
    
    # =========================================================================
    # Redshift
    # =========================================================================
    
    @abstractmethod
    async def get_redshift_clusters(self) -> List[RedshiftClusterData]:
        """Get all Redshift clusters in the region."""
        pass
    
    @abstractmethod
    async def get_redshift_metrics(
        self,
        cluster_ids: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
        idle_window_days: Optional[int] = None,
    ) -> Dict[str, RedshiftMetricsData]:
        """
        Get CloudWatch metrics for Redshift clusters.
        
        Args:
            cluster_ids: List of cluster identifiers
            days: Number of days of metrics to analyze
            create_times: CLO-457. Optional creation time per id. The
                dimension is a NAME, so a resource recreated under a reused
                name would otherwise inherit its predecessor's datapoints;
                with a creation time, datapoints from before it are excluded.
            idle_window_days: CLO-485. The window the idle claim is about
                (redshift_idle_days); ``is_idle`` needs 75% of its hours
                observed. Defaults to ``days``.
            
        Returns:
            Dict mapping cluster_id to RedshiftMetricsData
        """
        pass
    
    @abstractmethod
    async def get_redshift_cost_breakdown(
        self,
        cluster_ids: List[str],
    ) -> Dict[str, "RedshiftCostData"]:
        """
        Get Cost Explorer data for Redshift clusters.
        
        Args:
            cluster_ids: List of cluster identifiers
            
        Returns:
            Dict mapping cluster_id to RedshiftCostData
        """
        pass
    
    # =========================================================================
    # OpenSearch
    # =========================================================================
    
    @abstractmethod
    async def get_opensearch_domains(self) -> List[OpenSearchDomainData]:
        """Get all OpenSearch domains in the region."""
        pass
    
    @abstractmethod
    async def get_opensearch_metrics(
        self,
        domain_names: List[str],
        days: int = 14,
    ) -> Dict[str, OpenSearchMetricsData]:
        """
        Get CloudWatch metrics for OpenSearch domains.
        
        Args:
            domain_names: List of domain names
            days: Number of days of metrics to analyze
            
        Returns:
            Dict mapping domain_name to OpenSearchMetricsData
        """
        pass
    
    # =========================================================================
    # CloudWatch Logs
    # =========================================================================
    
    @abstractmethod
    async def get_cloudwatch_log_groups(self) -> List[CloudWatchLogGroupData]:
        """Get all CloudWatch Log Groups in the region."""
        pass

    @abstractmethod
    async def get_cloudwatch_log_group_last_activity(
        self,
        log_group_names: List[str],
        deadline: Optional[float] = None,
    ) -> Dict[str, Optional[datetime]]:
        """CLO-516: the last time each named log group received an event.

        ``DescribeLogGroups`` carries no ``lastEventTimestamp`` (the wire
        response has none; only log STREAMS do), so a group's last activity
        must come from its most recent stream.

        Returns ``{name: datetime}`` for a group with activity and
        ``{name: None}`` for a group with no log stream at all (it never
        received an event). A name LEFT OUT of the map could not be read
        (throttled, denied, over the time budget, not in the export): its
        activity is MISSING, not zero, and callers must not read absence as
        "never received logs". Providers note the missing names in
        ``data_warnings``.

        ``deadline`` is a ``time.monotonic()`` instant after which no new
        lookup starts.
        """
        pass

    @abstractmethod
    async def get_cloudwatch_dashboards(self) -> List["CloudWatchDashboardData"]:
        """Get all CloudWatch Dashboards in the region."""
        pass
    
    # =========================================================================
    # KMS
    # =========================================================================
    
    @abstractmethod
    async def get_kms_keys(self) -> List[KMSKeyData]:
        """Get all customer-managed KMS keys in the region."""
        pass
    
    # =========================================================================
    # Secrets Manager
    # =========================================================================
    
    @abstractmethod
    async def get_secrets(self) -> List[SecretsManagerSecretData]:
        """Get all Secrets Manager secrets in the region."""
        pass
    
    # =========================================================================
    # SageMaker
    # =========================================================================
    
    @abstractmethod
    async def get_sagemaker_notebooks(self) -> List[SageMakerNotebookData]:
        """Get all SageMaker notebook instances in the region."""
        pass
    
    @abstractmethod
    async def get_sagemaker_endpoints(self) -> List[SageMakerEndpointData]:
        """Get all SageMaker endpoints in the region."""
        pass

    @abstractmethod
    async def get_sagemaker_notebook_last_activity(
        self, notebook_names: List[str],
    ) -> Dict[str, Optional[datetime]]:
        """CLO-510: the last event time of each notebook instance's Jupyter
        server log (CloudWatch Logs ``/aws/sagemaker/NotebookInstances``,
        stream ``<name>/jupyter.log``), which records the Jupyter server's
        activity (kernels, sessions, saves).

        A name LEFT OUT has no usable log (read failed, no log group or
        stream: the instance may not ship logs at all): its idle verdict is
        MISSING, not zero, and the provider notes it in ``data_warnings``.
        The Air-Gapped export carries no CloudWatch Logs, so offline every
        name is left out."""
        pass
    
    @abstractmethod
    async def get_sagemaker_metrics(
        self,
        endpoint_names: List[str],
        days: int = 7,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, SageMakerMetricsData]:
        """
        Get CloudWatch metrics for SageMaker endpoints.
        
        Args:
            endpoint_names: List of endpoint names
            days: Number of days of metrics to analyze
            create_times: CLO-457. Optional creation time per name. The
                dimension is a NAME, so a resource recreated under a reused
                name would otherwise inherit its predecessor's datapoints;
                with a creation time, datapoints from before it are excluded.
            
        Returns:
            Dict mapping endpoint_name to SageMakerMetricsData
        """
        pass
    
    # =========================================================================
    # Kinesis
    # =========================================================================
    
    @abstractmethod
    async def get_kinesis_streams(self) -> List[KinesisStreamData]:
        """Get all Kinesis streams in the region."""
        pass
    
    @abstractmethod
    async def get_kinesis_metrics(
        self,
        stream_names: List[str],
        days: int = 7,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, KinesisMetricsData]:
        """
        Get CloudWatch metrics for Kinesis streams.
        
        Args:
            stream_names: List of stream names
            days: Number of days of metrics to analyze
            create_times: CLO-457. Optional creation time per name. The
                dimension is a NAME, so a resource recreated under a reused
                name would otherwise inherit its predecessor's datapoints;
                with a creation time, datapoints from before it are excluded.
            
        Returns:
            Dict mapping stream_name to KinesisMetricsData
        """
        pass

    @abstractmethod
    async def get_kinesis_consumers(self, stream_arn: str) -> List['KinesisConsumerData']:
        """Get enhanced fan-out consumers for a Kinesis stream."""
        pass

    @abstractmethod
    async def get_kinesis_consumer_metrics(
        self,
        stream_name: str,
        consumer_name: str,
        days: int = 14,
        consumer_create_time: Optional[datetime] = None,
    ) -> Optional['KinesisMetricsData']:
        """Get CloudWatch metrics for a specific enhanced fan-out consumer.

        ``consumer_create_time`` (CLO-457): StreamName and ConsumerName are
        both names; datapoints from before the consumer existed are excluded."""
        pass

    @abstractmethod
    async def get_firehose_delivery_streams(self) -> List['KinesisFirehoseData']:
        """Get all Kinesis Data Firehose delivery streams."""
        pass

    @abstractmethod
    async def get_firehose_metrics(
        self,
        delivery_stream_names: List[str],
        days: int = 14,
        create_times: Optional[Dict[str, Optional[datetime]]] = None,
    ) -> Dict[str, 'KinesisFirehoseMetricsData']:
        """Get CloudWatch metrics for Firehose delivery streams.

        CLO-457: ``create_times`` maps a stream name to its CreateTimestamp;
        a provider that can starts the stream's reads at it."""
        pass

    # =========================================================================
    # MSK
    # =========================================================================

    @abstractmethod
    async def get_msk_clusters(self) -> List['MSKClusterData']:
        """Get MSK clusters.

        Returns:
            List of MSKClusterData objects
        """
        pass

    @abstractmethod
    async def get_msk_metrics(
        self,
        cluster_name: str,
        days: int = 7,
        created: Optional[datetime] = None,
        broker_count: Optional[int] = None,
    ) -> Optional[MSKMetrics]:
        """
        Get CloudWatch metrics for an MSK cluster.

        CLO-457: ``created`` is the cluster's CreationTime; a provider that
        can drops datapoints from before it ("Cluster Name" is reusable).
        CLO-549: ``broker_count`` is ListClusters' NumberOfBrokerNodes; the
        online provider reads AWS/Kafka per broker (ids "1".."N").

        Args:
            cluster_name: MSK cluster name
            days: Number of days of metrics to analyse

        Returns:
            MSKMetrics object, or None on error / offline mode
        """
        pass

    # =========================================================================
    # AMIs
    # =========================================================================

    @abstractmethod
    async def get_amis(self) -> List[AMIData]:
        """Get registered AMIs owned by this account."""
        pass

    # =========================================================================
    # ECS / Fargate
    # =========================================================================

    @abstractmethod
    def get_ecs_clusters(self) -> List[Dict[str, Any]]:
        """Get all ECS clusters with settings and statistics."""
        pass

    @abstractmethod
    def get_ecs_services(self, cluster_arn: str) -> List[Dict[str, Any]]:
        """Get ECS services for a specific cluster. The list may be
        partial; see :meth:`ecs_services_unread`."""
        pass

    def ecs_services_unread(self, cluster_arn: str) -> Optional[str]:
        """Why :meth:`get_ecs_services` for ``cluster_arn`` is not the
        cluster's complete service list (a list-services or describe-services
        read failed, or the export cannot tell), or None when it is complete
        (CLO-551). Per-service checks still run on the services read; a
        check over the whole cluster's services (ecs_container_insights_waste:
        "few / no active services") must not."""
        reasons = getattr(self, '_ecs_services_unread', None)
        reason = reasons.get(cluster_arn) if isinstance(reasons, dict) else None
        return reason if isinstance(reason, str) else None

    @abstractmethod
    def get_ecs_task_definition(self, task_definition_arn: str) -> Optional[Dict[str, Any]]:
        """Get task definition details by ARN."""
        pass

    @abstractmethod
    def get_ecs_metrics(
        self, cluster_name: str, service_name: str,
        metric_name: str, days: int = 7,
    ) -> Optional[Dict[str, float]]:
        """
        Get ECS service CloudWatch metrics.

        Returns: {'average': float, 'maximum': float} or None
        """
        pass

    @abstractmethod
    def get_ecs_autoscaling_targets(self, cluster_name: str) -> Optional[List[Dict[str, Any]]]:
        """Application Auto Scaling scalable targets for ECS services in a
        cluster; [] is a measured "none", None means the read failed or the
        export cannot tell a failed read from none (MISSING, CLO-550)."""
        pass

    @abstractmethod
    def get_ecs_container_insights_status(self, cluster_name: str) -> bool:
        """Check if Container Insights is enabled for a cluster."""
        pass

    @abstractmethod
    def get_eks_clusters(self) -> List[EKSClusterData]:
        """Get all EKS clusters with version and lifecycle metadata."""
        pass

    # =========================================================================
    # Glue
    # =========================================================================

    @abstractmethod
    def get_glue_jobs(self) -> List[Dict[str, Any]]:
        """Get all Glue ETL job definitions."""
        pass

    @abstractmethod
    def get_glue_job_runs(self, job_name: str, max_results: int = 10) -> Optional[List[Dict[str, Any]]]:
        """Recent runs of a Glue job; [] is a measured "never ran", None
        means the read failed or the export lacks it (MISSING, CLO-551)."""
        pass

    @abstractmethod
    def get_glue_crawlers(self) -> List[Dict[str, Any]]:
        """Get all Glue crawlers."""
        pass

    @abstractmethod
    def get_glue_catalog_stats(self) -> Optional[Dict[str, Any]]:
        """Get Data Catalog object counts."""
        pass

    @abstractmethod
    def get_glue_metrics(self, job_name: str, metric_name: str, days: int = 14) -> Optional[float]:
        """Average of a Glue job's metric (JobName, JobRunId=ALL, Type=gauge)
        in the metric's own unit: glue.ALL.jvm.heap.usage is a 0-1
        fraction, not a percent (CLO-547). None when unmeasured."""
        pass

    # =========================================================================
    # Transfer Family
    # =========================================================================

    @abstractmethod
    def get_transfer_servers(self) -> List[Dict[str, Any]]:
        """Get all Transfer Family servers."""
        pass

    @abstractmethod
    def get_transfer_server_users(self, server_id: str) -> Optional[List[Dict[str, Any]]]:
        """Users of a Transfer Family server; [] is a measured "no users",
        None means the read failed or the export lacks it (MISSING, CLO-550)."""
        pass

    @abstractmethod
    def get_transfer_web_apps(self) -> List[Dict[str, Any]]:
        """Get all Transfer Family Web Apps."""
        pass

    @abstractmethod
    def get_transfer_metrics(
        self, server_id: str, metric_name: str, days: int = 30,
        protocol: Optional[str] = None
    ) -> CounterRead:
        """The Sum of an AWS/Transfer counter (FilesIn, FilesOut) for a
        server, optionally one protocol, over ``days``. A successful read
        with no datapoints is ``CounterRead.EMPTY`` (a measured zero once
        the detector's age gate passes); a failed or unexported read is
        ``CounterRead.MISSING`` (CLO-546 follow-up, CLO-485)."""
        pass

    @abstractmethod
    def get_transfer_web_app_metrics(
        self, web_app_id: str, metric_name: str, days: int = 30
    ) -> CounterRead:
        """The Sum of an AWS/Transfer counter (ActiveSessions) for a web
        app over ``days``; EMPTY / MISSING as ``get_transfer_metrics``."""
        pass

    # =========================================================================
    # AWS Backup
    # =========================================================================

    @abstractmethod
    async def get_backup_recovery_points(self) -> List[BackupRecoveryPointData]:
        """Get all recovery points across backup vaults. The list may be
        partial; see :meth:`backup_recovery_points_unread`."""
        pass

    def backup_recovery_points_unread(self) -> Optional[str]:
        """Why the last :meth:`get_backup_recovery_points` list is not the
        complete set of recovery points (a vault list or a vault's
        recovery-point read failed, or the export cannot tell), or None when
        it is complete (CLO-551).

        The list itself stays usable for checks over the recovery points it
        holds; a check that reads "no recovery point for this resource" as
        "not backed up" (resource_without_backup_coverage) must not run on
        an incomplete list."""
        reason = getattr(self, '_backup_recovery_points_unread', None)
        return reason if isinstance(reason, str) else None

    @abstractmethod
    async def get_backup_plans(self) -> List[BackupPlanData]:
        """Get all backup plans with rules."""
        pass

    @abstractmethod
    async def get_backup_selections(self, plan_id: str) -> List[BackupSelectionData]:
        """Get backup selections for a specific plan."""
        pass

    @abstractmethod
    async def get_backup_copy_jobs(self, days: int = 90) -> List[BackupCopyJobSummary]:
        """Get copy job summaries for the specified lookback period."""
        pass

    # =========================================================================
    # DocumentDB
    # =========================================================================

    @abstractmethod
    async def get_documentdb_clusters(self) -> List[DocumentDBClusterData]:
        """Get all DocumentDB clusters."""
        pass

    @abstractmethod
    async def get_documentdb_snapshots(self, snapshot_type: str = "manual") -> List[DocumentDBSnapshotData]:
        """Get DocumentDB cluster snapshots."""
        pass

    @abstractmethod
    async def get_documentdb_cluster_metrics(
        self, cluster_id: str, days: int = 14, cluster_create_time: Optional[datetime] = None,
    ) -> Optional[DocumentDBMetricsData]:
        """Get CloudWatch metrics for a DocumentDB cluster.

        ``cluster_create_time`` (CLO-457): when known, datapoints from before
        the cluster existed are excluded. ``DBClusterIdentifier`` is a name, so
        a cluster recreated under a reused name would otherwise inherit its
        predecessor's datapoints."""
        pass

    # =========================================================================
    # FSx
    # =========================================================================

    @abstractmethod
    async def get_fsx_filesystems(self) -> List[FSxFilesystemData]:
        """Get all FSx filesystems."""
        pass

    @abstractmethod
    async def get_fsx_backups(self) -> List[FSxBackupData]:
        """Get FSx backups."""
        pass

    @abstractmethod
    async def get_fsx_filesystem_metrics(
        self, filesystem_id: str, days: int = 7, filesystem_type: Optional[str] = None,
    ) -> Optional[FSxMetricsData]:
        """Get CloudWatch metrics for an FSx filesystem."""
        pass

    # =========================================================================
    # Step Functions
    # =========================================================================

    @abstractmethod
    async def get_step_function_state_machines(self) -> List[Dict[str, Any]]:
        """Get all Step Functions state machines."""
        pass

    @abstractmethod
    async def get_step_function_execution_summary(
        self, state_machine_arn: str, days: int = 14, sm_type: str = 'STANDARD'
    ) -> Optional[StepFunctionExecutionSummaryData]:
        """Get execution summary metrics for a state machine.

        ``sm_type`` ('STANDARD' | 'EXPRESS') lets online providers avoid
        ``ListExecutions`` for EXPRESS workflows (which don't support it) and
        derive the summary from CloudWatch instead.
        """
        pass

    @abstractmethod
    async def get_step_function_retry_metrics(
        self, state_machine_arn: str, days: int = 14
    ) -> Optional[StepFunctionRetryMetricsData]:
        """Get retry and failure metrics for a state machine."""
        pass

    @abstractmethod
    async def get_step_function_transition_metrics(
        self, state_machine_arn: str, days: int = 14
    ) -> Optional[StepFunctionTransitionMetricsData]:
        """Get transition density and duration metrics for a state machine."""
        pass

    # =========================================================================
    # AppSync
    # =========================================================================

    @abstractmethod
    async def get_appsync_apis(self) -> List[Dict[str, Any]]:
        """Return all AppSync GraphQL APIs in the region."""
        pass

    @abstractmethod
    async def get_appsync_api_cache(self, api_id: str) -> Optional[Dict[str, Any]]:
        """Return cache configuration for an AppSync API, or None."""
        pass

    @abstractmethod
    async def get_appsync_metrics(
        self, api_id: str, metric_name: str,
        days: int = 14, statistic: str = 'Sum'
    ) -> Optional[float]:
        """Return aggregated CloudWatch metric for an AppSync API, or None
        when it could not be read (CLO-485: MISSING, not zero)."""
        pass

    # =========================================================================
    # Aurora
    # =========================================================================

    @abstractmethod
    async def get_aurora_clusters(self) -> List[AuroraClusterData]:
        """Get all Aurora clusters in the region."""
        pass

    @abstractmethod
    async def get_aurora_io_metrics(
        self, cluster_id: str, days: int = 30, cluster_create_time: Optional[datetime] = None,
    ) -> Optional[AuroraIOMetricsData]:
        """Get I/O and storage metrics for an Aurora cluster.

        ``cluster_create_time``: as for get_documentdb_cluster_metrics (CLO-457)."""
        pass

    # ─── Neptune ──────────────────────────────────────────────────

    @abstractmethod
    async def get_neptune_clusters(self) -> List[NeptuneClusterData]:
        """Get all Neptune clusters in the region."""
        pass

    @abstractmethod
    async def get_neptune_snapshots(
        self, snapshot_type: str = 'manual', age_threshold_days: int = 90
    ) -> List[NeptuneSnapshotData]:
        """Get Neptune cluster snapshots matching criteria."""
        pass

    @abstractmethod
    async def get_neptune_cluster_metrics(
        self, cluster_id: str, days: int = 14, cluster_create_time: Optional[datetime] = None,
    ) -> Optional[NeptuneMetricsData]:
        """Get CloudWatch metrics for a Neptune cluster.

        ``cluster_create_time``: as for get_documentdb_cluster_metrics (CLO-457)."""
        pass

    # ─── Amazon MQ ────────────────────────────────────────────────

    @abstractmethod
    async def get_mq_brokers(self) -> List[MQBrokerData]:
        """Get all Amazon MQ brokers in the region."""
        pass

    @abstractmethod
    async def get_mq_metrics(
        self, broker_id: str, days: int = 14, broker: Optional[MQBrokerData] = None,
    ) -> Optional["MQMetrics"]:
        """Get CloudWatch metrics for an Amazon MQ broker.

        CLO-516: AWS/AmazonMQ's ``Broker`` dimension is the broker NAME
        (ActiveMQ: ``<name>-1``, plus ``<name>-2`` for active/standby), not
        its id, and the metric set depends on the engine, so providers need
        ``broker``. Returns None when the broker's activity could not be
        measured (MISSING, noted in ``data_warnings``), never an all-zero
        "idle" reading."""
        pass

    # ─── Lightsail ────────────────────────────────────────────────

    @abstractmethod
    async def get_lightsail_instances(self) -> List[LightsailInstanceData]:
        """Get all Lightsail instances in the region."""
        pass

    @abstractmethod
    async def get_lightsail_static_ips(self) -> List[LightsailStaticIpData]:
        """Get all Lightsail static IPs in the region."""
        pass

    @abstractmethod
    async def get_lightsail_disks(self) -> List[LightsailDiskData]:
        """Get all Lightsail additional block storage disks."""
        pass

    @abstractmethod
    async def get_lightsail_snapshots(self) -> List[LightsailSnapshotData]:
        """Get all Lightsail instance snapshots."""
        pass

    @abstractmethod
    async def get_lightsail_load_balancers(self) -> List[LightsailLoadBalancerData]:
        """Get all Lightsail load balancers."""
        pass

    @abstractmethod
    async def get_lightsail_databases(self) -> List[LightsailDatabaseData]:
        """Get all Lightsail managed databases."""
        pass

    @abstractmethod
    async def get_lightsail_metrics(
        self, resource_name: str, resource_type: str = 'instance'
    ) -> LightsailMetricsData:
        """Get CloudWatch metrics for a Lightsail resource."""
        pass

    # =========================================================================
    # EMR / Analytics
    # =========================================================================

    @abstractmethod
    async def get_emr_clusters(self) -> List[EMRClusterData]:
        """Get all active EMR clusters (RUNNING + WAITING states)."""
        pass

    @abstractmethod
    async def get_emr_instance_groups(self, cluster_id: str) -> List[EMRInstanceGroupData]:
        """Get instance groups for an EMR cluster."""
        pass

    @abstractmethod
    async def get_emr_step_summary(self, cluster_id: str) -> EMRStepSummaryData:
        """Get step execution summary for an EMR cluster."""
        pass

    @abstractmethod
    async def get_emr_metrics(
        self,
        cluster_ids: List[str],
        days: int = 14,
    ) -> Dict[str, EMRMetricsData]:
        """Get CloudWatch metrics for EMR clusters."""
        pass

    # =========================================================================
    # WorkSpaces
    # =========================================================================

    @abstractmethod
    async def get_workspaces(self) -> List[WorkspaceData]:
        """Get all WorkSpaces."""
        pass

    @abstractmethod
    async def get_workspaces_connection_status(self, workspace_ids: List[str]) -> List[WorkspaceConnectionData]:
        """Get connection status for WorkSpaces."""
        pass

    @abstractmethod
    async def get_workspaces_pools(self) -> List[WorkspacePoolData]:
        """Get WorkSpaces Pools."""
        pass

    @abstractmethod
    async def get_workspaces_metrics(
        self,
        workspace_ids: List[str],
        days: int = 14,
    ) -> Dict[str, WorkspaceMetricsData]:
        """Get CloudWatch metrics for WorkSpaces."""
        pass

    # =========================================================================
    # Elastic Beanstalk / Compute
    # =========================================================================

    @abstractmethod
    async def get_beanstalk_environments(self) -> List[BeanstalkEnvironmentData]:
        """Get all active Elastic Beanstalk environments."""
        pass

    @abstractmethod
    async def get_beanstalk_configurations(self) -> Dict[str, BeanstalkConfigData]:
        """Get configuration settings for all Beanstalk environments.
        Returns dict keyed by environment_id.
        """
        pass

    @abstractmethod
    async def get_beanstalk_metrics(
        self,
        environment_names: List[str],
        days: int = 14,
        endpoint_urls: Optional[Dict[str, str]] = None,
    ) -> Dict[str, BeanstalkMetricsData]:
        """Get CloudWatch metrics for Beanstalk environments.
        Returns dict keyed by environment_name.

        CLO-524: ``request_count_14d`` is the environment's load balancer
        RequestCount (ALB or Classic), else enhanced health's
        ApplicationRequestsTotal; ``avg_cpu_14d`` averages AWS/EC2
        CPUUtilization over the environment's instances. Each is -1
        (MISSING) unless its source covered 75% of the window.
        """
        pass

    @abstractmethod
    async def get_beanstalk_rds_instances(self) -> Optional[List[RDSInstanceData]]:
        """CLO-506: every RDS instance in the region that carries one of
        Elastic Beanstalk's own marks (an ``elasticbeanstalk:environment-id``
        or ``-name`` tag, or an ``awseb-<env id>-stack`` CloudFormation
        stack tag), across all DescribeDBInstances pages. None when the read
        failed (MISSING, not "no databases")."""
        pass

    # =========================================================================
    # API Gateway (CLO-507)
    # =========================================================================

    @abstractmethod
    async def get_api_gateway_rest_apis(self) -> Optional[List[ApiGatewayRestApiData]]:
        """Every REST API in the region (GetRestApis, all pages up to a
        bound). None when the read failed (MISSING, not "no APIs")."""
        pass

    @abstractmethod
    async def get_api_gateway_request_counts(
        self, apis: List[ApiGatewayRestApiData], days: int = 30,
    ) -> Dict[str, float]:
        """Each REST API's AWS/ApiGateway Count (ApiName dimension, every
        stage) over the window, keyed by api_id. Count is a counter metric,
        published only when a request arrives, so a read that succeeds with
        no datapoints is a measured zero (CLO-485's counter rule). An API
        LEFT OUT could not be read: MISSING, not zero, and noted."""
        pass

    @abstractmethod
    async def get_api_gateway_cache_enabled(self, api_id: str) -> Optional[bool]:
        """Whether any stage of the API has a cache cluster. None = unknown."""
        pass

    # =========================================================================
    # Global Accelerator / Network
    # =========================================================================

    @abstractmethod
    async def get_global_accelerator_resources(self) -> List[GlobalAcceleratorData]:
        """Return Global Accelerator data for waste detection."""
        pass
