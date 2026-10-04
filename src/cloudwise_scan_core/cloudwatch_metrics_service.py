"""
CloudWatch Metrics Service

Provides CloudWatch metrics integration for accurate waste detection.
Retrieves utilization metrics for EC2, RDS, EBS, NAT Gateway, and other resources.

This service is the key differentiator between basic waste detection
(configuration-only) and accurate waste detection (metrics-based).
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
import asyncio
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CPUMetrics:
    """CPU utilization metrics for a resource."""
    avg_cpu: float
    max_cpu: float
    min_cpu: float
    datapoints: int
    period_days: int
    is_idle: bool = False
    is_oversized: bool = False


@dataclass
class ConnectionMetrics:
    """Database connection metrics."""
    total_connections: int
    max_connections: int
    avg_connections: float
    days_with_zero: int
    period_days: int
    is_idle: bool = False


@dataclass
class IOMetrics:
    """I/O metrics for storage resources."""
    total_read_ops: int
    total_write_ops: int
    days_with_zero_io: int
    period_days: int
    is_unused: bool = False


@dataclass
class NetworkMetrics:
    """Network traffic metrics."""
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int
    days_with_zero_traffic: int
    period_days: int
    is_idle: bool = False


@dataclass
class LambdaMetrics:
    """Lambda function metrics."""
    total_invocations: int
    avg_duration_ms: Optional[float]
    max_duration_ms: Optional[float]
    errors: int
    period_days: int
    is_unused: bool = False
    memory_utilization: Optional[float] = None  # Max memory used as % of allocated


@dataclass
class ElastiCacheMetrics:
    """ElastiCache cluster metrics."""
    avg_cpu: float
    max_cpu: float
    avg_connections: float
    cache_hits: int
    cache_misses: int
    period_days: int
    is_idle: bool = False
    is_oversized: bool = False


@dataclass
class RedshiftMetrics:
    """Redshift cluster metrics."""
    avg_cpu: float
    max_cpu: float
    database_connections: int
    read_iops: int
    write_iops: int
    period_days: int
    is_idle: bool = False
    is_oversized: bool = False


@dataclass
class DynamoDBMetrics:
    """DynamoDB table metrics."""
    consumed_read_units: float
    consumed_write_units: float
    provisioned_read_units: float
    provisioned_write_units: float
    throttled_requests: int
    period_days: int
    is_idle: bool = False
    is_over_provisioned: bool = False


@dataclass
class OpenSearchMetrics:
    """OpenSearch domain metrics."""
    avg_cpu: float
    max_cpu: float
    search_rate: float
    indexing_rate: float
    period_days: int
    is_idle: bool = False
    is_oversized: bool = False


@dataclass
class KinesisMetrics:
    """Kinesis stream metrics."""
    incoming_records: int
    incoming_bytes: int
    get_records_success: int
    iterator_age_ms: float
    period_days: int
    is_idle: bool = False
    is_over_provisioned: bool = False


@dataclass
class SageMakerMetrics:
    """SageMaker endpoint metrics."""
    invocations: int
    model_latency_ms: float
    overhead_latency_ms: float
    invocations_per_instance: float
    period_days: int
    is_idle: bool = False


@dataclass
class EFSMetrics:
    """EFS filesystem metrics."""
    client_connections: int
    data_read_bytes: int
    data_write_bytes: int
    period_days: int
    is_idle: bool = False


@dataclass
class MSKMetrics:
    """MSK cluster metrics."""
    messages_in_per_sec: float
    bytes_in_per_sec: float
    bytes_out_per_sec: float
    # Online (CLO-549): the busiest broker's mean CpuUser + CpuSystem, and
    # traffic summed across brokers. Offline: the export's cluster figure.
    cpu_user: float
    period_days: int
    is_idle: bool = False
    # CLO-457: hourly CpuUser datapoints behind ``cpu_user``. 0 means CPU was
    # not measured (``cpu_user`` is then a placeholder 0.0, not 0% CPU);
    # None means the source does not count them (the offline export).
    cpu_datapoints: Optional[int] = None


@dataclass
class NeptuneMetrics:
    """Neptune cluster metrics."""
    gremlin_requests: int
    sparql_requests: int
    loader_requests: int
    avg_cpu: float
    max_cpu: float
    connections: int
    period_days: int
    is_idle: bool = False


@dataclass
class DocumentDBMetrics:
    """DocumentDB cluster metrics."""
    database_connections: int
    read_iops: int
    write_iops: int
    avg_cpu: float
    max_cpu: float
    period_days: int
    is_idle: bool = False


@dataclass
class FSxMetrics:
    """FSx filesystem metrics."""
    data_read_bytes: int
    data_write_bytes: int
    client_connections: int
    period_days: int
    is_idle: bool = False


@dataclass
class MQMetrics:
    """Amazon MQ broker metrics.

    CLO-516: ``cpu_utilization`` is None when no CPU datapoints were read
    (MISSING, not 0%), and ``is_idle`` is True only when the activity series
    were actually measured and every one read zero."""
    total_message_count: int
    total_consumer_count: int
    total_producer_count: int
    cpu_utilization: Optional[float]
    period_days: int
    is_idle: bool = False


@dataclass
class QLDBMetrics:
    """QLDB ledger metrics."""
    commands_total: int
    read_ios: int
    write_ios: int
    period_days: int
    is_idle: bool = False


@dataclass
class APIGatewayMetrics:
    """API Gateway metrics."""
    total_requests: int
    error_4xx: int
    error_5xx: int
    avg_latency_ms: float
    period_days: int
    is_idle: bool = False


@dataclass
class CloudFrontMetrics:
    """CloudFront distribution metrics."""
    total_requests: int
    bytes_downloaded: int
    bytes_uploaded: int
    error_rate: float
    period_days: int
    is_idle: bool = False


class CloudWatchMetricsService:
    """
    Service for retrieving CloudWatch metrics for waste detection.
    
    Uses customer's AWS credentials to query their CloudWatch metrics.
    All API calls are read-only and cost approximately $0.01 per 1000 requests.
    """
    
    def __init__(self, aws_factory=None):
        """Initialize the CloudWatch metrics service."""
        # aws_factory is retained for backward-compat with the FastAPI
        # backend but is never invoked here (CloudWatch clients are built
        # from per-scan customer credentials). Default None to avoid an
        # app.* import inside scan-core (see SCAN-PIPELINE-SCALING-SPEC §6.5).
        self.aws_factory = aws_factory
        
        logger.info("CloudWatch Metrics Service initialized")
    
    def _create_cloudwatch_client(self, access_key_id: str, secret_access_key: str, 
                                   region: str, session_token: str = None):
        """Create a CloudWatch client with customer credentials."""
        import boto3
        from botocore.config import Config
        
        config = Config(
            read_timeout=30,
            retries={'max_attempts': 2, 'mode': 'adaptive'}
        )
        
        client_kwargs = {
            'service_name': 'cloudwatch',
            'aws_access_key_id': access_key_id,
            'aws_secret_access_key': secret_access_key,
            'region_name': region,
            'config': config,
        }
        
        if session_token:
            client_kwargs['aws_session_token'] = session_token
        
        return boto3.client(**client_kwargs)
    
    async def get_ec2_cpu_utilization(
        self,
        instance_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 14,
        session_token: str = None,
        idle_threshold: float = 5.0,
        oversized_threshold: float = 20.0,
    ) -> Optional[CPUMetrics]:
        """
        Get CPU utilization metrics for an EC2 instance.
        
        Args:
            instance_id: EC2 instance ID (e.g., i-0abc123def456)
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 14)
            session_token: Optional session token for assumed roles
            idle_threshold: CPU % below which instance is considered idle
            oversized_threshold: CPU % below which instance is considered oversized
            
        Returns:
            CPUMetrics object with utilization statistics, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Use 1-hour periods for 14 days = 336 datapoints max
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/EC2',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,  # 1 hour
                    Statistics=['Average', 'Maximum', 'Minimum']
                )
            )
            
            datapoints = response.get('Datapoints', [])
            
            if not datapoints:
                logger.warning(f"No CloudWatch data for EC2 instance {instance_id}")
                return None
            
            avg_cpu = sum(dp.get('Average', 0) for dp in datapoints) / len(datapoints)
            max_cpu = max(dp.get('Maximum', 0) for dp in datapoints)
            min_cpu = min(dp.get('Minimum', 0) for dp in datapoints)
            
            metrics = CPUMetrics(
                avg_cpu=round(avg_cpu, 2),
                max_cpu=round(max_cpu, 2),
                min_cpu=round(min_cpu, 2),
                datapoints=len(datapoints),
                period_days=days,
                is_idle=avg_cpu < idle_threshold and max_cpu < oversized_threshold,
                is_oversized=max_cpu < oversized_threshold,
            )
            
            logger.debug(f"EC2 {instance_id}: avg={metrics.avg_cpu}%, max={metrics.max_cpu}%")
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting CPU metrics for EC2 {instance_id}: {e}")
            return None
    
    async def get_rds_connection_metrics(
        self,
        db_instance_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 14,
        session_token: str = None,
    ) -> Optional[ConnectionMetrics]:
        """
        Get database connection metrics for an RDS instance.
        
        Args:
            db_instance_id: RDS instance identifier
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 14)
            session_token: Optional session token for assumed roles
            
        Returns:
            ConnectionMetrics object with connection statistics, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/RDS',
                    MetricName='DatabaseConnections',
                    Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,  # 1 hour
                    Statistics=['Sum', 'Maximum', 'Average']
                )
            )
            
            datapoints = response.get('Datapoints', [])
            
            if not datapoints:
                logger.warning(f"No CloudWatch data for RDS instance {db_instance_id}")
                return None
            
            total_connections = sum(dp.get('Sum', 0) for dp in datapoints)
            max_connections = max(dp.get('Maximum', 0) for dp in datapoints)
            avg_connections = sum(dp.get('Average', 0) for dp in datapoints) / len(datapoints)
            
            # Count days with zero connections
            # Group datapoints by day and check if all hours in a day had 0 connections
            days_with_zero = 0
            datapoints_by_day: Dict[str, List] = {}
            for dp in datapoints:
                day_key = dp['Timestamp'].strftime('%Y-%m-%d')
                if day_key not in datapoints_by_day:
                    datapoints_by_day[day_key] = []
                datapoints_by_day[day_key].append(dp.get('Sum', 0))
            
            for day_key, day_values in datapoints_by_day.items():
                if all(v == 0 for v in day_values):
                    days_with_zero += 1
            
            metrics = ConnectionMetrics(
                total_connections=int(total_connections),
                max_connections=int(max_connections),
                avg_connections=round(avg_connections, 2),
                days_with_zero=days_with_zero,
                period_days=days,
                is_idle=total_connections == 0 or days_with_zero >= days,
            )
            
            logger.debug(f"RDS {db_instance_id}: total={metrics.total_connections}, idle_days={metrics.days_with_zero}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting connection metrics for RDS {db_instance_id}: {e}")
            return None
    
    async def get_rds_cpu_metrics(
        self,
        db_instance_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 14,
        session_token: str = None,
        oversized_threshold: float = 20.0,
    ) -> Optional[CPUMetrics]:
        """
        Get CPU utilization metrics for an RDS instance.
        
        Args:
            db_instance_id: RDS instance identifier
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 14)
            session_token: Optional session token for assumed roles
            oversized_threshold: CPU % below which instance is considered oversized
            
        Returns:
            CPUMetrics object with utilization statistics, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/RDS',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average', 'Maximum', 'Minimum']
                )
            )
            
            datapoints = response.get('Datapoints', [])
            
            if not datapoints:
                return None
            
            avg_cpu = sum(dp.get('Average', 0) for dp in datapoints) / len(datapoints)
            max_cpu = max(dp.get('Maximum', 0) for dp in datapoints)
            min_cpu = min(dp.get('Minimum', 0) for dp in datapoints)
            
            metrics = CPUMetrics(
                avg_cpu=round(avg_cpu, 2),
                max_cpu=round(max_cpu, 2),
                min_cpu=round(min_cpu, 2),
                datapoints=len(datapoints),
                period_days=days,
                is_idle=avg_cpu < 5.0,
                is_oversized=max_cpu < oversized_threshold,
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting CPU metrics for RDS {db_instance_id}: {e}")
            return None
    
    async def get_ebs_io_metrics(
        self,
        volume_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[IOMetrics]:
        """
        Get I/O metrics for an EBS volume.
        
        Args:
            volume_id: EBS volume ID
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token for assumed roles
            
        Returns:
            IOMetrics object with I/O statistics, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get read ops
            read_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/EBS',
                    MetricName='VolumeReadOps',
                    Dimensions=[{'Name': 'VolumeId', 'Value': volume_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # 1 day
                    Statistics=['Sum']
                )
            )
            
            # Get write ops
            write_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/EBS',
                    MetricName='VolumeWriteOps',
                    Dimensions=[{'Name': 'VolumeId', 'Value': volume_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # 1 day
                    Statistics=['Sum']
                )
            )
            
            read_datapoints = read_response.get('Datapoints', [])
            write_datapoints = write_response.get('Datapoints', [])
            
            total_read_ops = sum(dp.get('Sum', 0) for dp in read_datapoints)
            total_write_ops = sum(dp.get('Sum', 0) for dp in write_datapoints)
            
            # Count days with zero I/O
            days_with_zero = 0
            read_by_day = {dp['Timestamp'].strftime('%Y-%m-%d'): dp.get('Sum', 0) for dp in read_datapoints}
            write_by_day = {dp['Timestamp'].strftime('%Y-%m-%d'): dp.get('Sum', 0) for dp in write_datapoints}
            
            all_days = set(read_by_day.keys()) | set(write_by_day.keys())
            for day in all_days:
                if read_by_day.get(day, 0) == 0 and write_by_day.get(day, 0) == 0:
                    days_with_zero += 1
            
            metrics = IOMetrics(
                total_read_ops=int(total_read_ops),
                total_write_ops=int(total_write_ops),
                days_with_zero_io=days_with_zero,
                period_days=days,
                is_unused=days_with_zero >= days,
            )
            
            logger.debug(f"EBS {volume_id}: reads={metrics.total_read_ops}, writes={metrics.total_write_ops}, zero_days={metrics.days_with_zero_io}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting I/O metrics for EBS {volume_id}: {e}")
            return None
    
    async def get_nat_gateway_metrics(
        self,
        nat_gateway_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[NetworkMetrics]:
        """
        Get traffic metrics for a NAT Gateway.
        
        Args:
            nat_gateway_id: NAT Gateway ID
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token for assumed roles
            
        Returns:
            NetworkMetrics object with traffic statistics, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get bytes out to destination
            bytes_out_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/NATGateway',
                    MetricName='BytesOutToDestination',
                    Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_gateway_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # 1 day
                    Statistics=['Sum']
                )
            )
            
            # Get bytes in from destination
            bytes_in_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/NATGateway',
                    MetricName='BytesInFromDestination',
                    Dimensions=[{'Name': 'NatGatewayId', 'Value': nat_gateway_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Sum']
                )
            )
            
            bytes_out_datapoints = bytes_out_response.get('Datapoints', [])
            bytes_in_datapoints = bytes_in_response.get('Datapoints', [])
            
            total_bytes_out = sum(dp.get('Sum', 0) for dp in bytes_out_datapoints)
            total_bytes_in = sum(dp.get('Sum', 0) for dp in bytes_in_datapoints)
            
            # Count days with zero traffic
            days_with_zero = 0
            out_by_day = {dp['Timestamp'].strftime('%Y-%m-%d'): dp.get('Sum', 0) for dp in bytes_out_datapoints}
            in_by_day = {dp['Timestamp'].strftime('%Y-%m-%d'): dp.get('Sum', 0) for dp in bytes_in_datapoints}
            
            all_days = set(out_by_day.keys()) | set(in_by_day.keys())
            for day in all_days:
                if out_by_day.get(day, 0) == 0 and in_by_day.get(day, 0) == 0:
                    days_with_zero += 1
            
            metrics = NetworkMetrics(
                bytes_in=int(total_bytes_in),
                bytes_out=int(total_bytes_out),
                packets_in=0,  # Not tracked for NAT Gateway
                packets_out=0,
                days_with_zero_traffic=days_with_zero,
                period_days=days,
                is_idle=total_bytes_out == 0 and total_bytes_in == 0,
            )
            
            logger.debug(f"NAT Gateway {nat_gateway_id}: bytes_out={metrics.bytes_out}, bytes_in={metrics.bytes_in}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error getting metrics for NAT Gateway {nat_gateway_id}: {e}")
            return None
    
    async def get_load_balancer_metrics(
        self,
        load_balancer_arn: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Get traffic metrics for an Application/Network Load Balancer.
        
        Args:
            load_balancer_arn: Load Balancer ARN
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token for assumed roles
            
        Returns:
            Dictionary with load balancer metrics, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Extract load balancer name from ARN for CloudWatch dimension
            # ARN format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
            lb_name_parts = load_balancer_arn.split('/')
            if len(lb_name_parts) >= 3:
                lb_dimension = '/'.join(lb_name_parts[-3:])
            else:
                lb_dimension = load_balancer_arn.split(':')[-1]
            
            # Get request count
            request_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApplicationELB',
                    MetricName='RequestCount',
                    Dimensions=[{'Name': 'LoadBalancer', 'Value': lb_dimension}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # 1 day
                    Statistics=['Sum']
                )
            )
            
            datapoints = request_response.get('Datapoints', [])
            total_requests = sum(dp.get('Sum', 0) for dp in datapoints)
            
            # Count days with zero requests
            days_with_zero = 0
            for dp in datapoints:
                if dp.get('Sum', 0) == 0:
                    days_with_zero += 1
            
            return {
                'total_requests': int(total_requests),
                'days_with_zero_requests': days_with_zero,
                'period_days': days,
                'is_idle': total_requests == 0 or days_with_zero >= days,
            }
            
        except Exception as e:
            logger.error(f"Error getting metrics for Load Balancer {load_balancer_arn}: {e}")
            return None
    
    async def get_lambda_invocation_metrics(
        self,
        function_name: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 30,
        session_token: str = None,
    ) -> Optional[LambdaMetrics]:
        """
        Get invocation metrics for a Lambda function.
        
        Args:
            function_name: Lambda function name
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 30)
            session_token: Optional session token for assumed roles
            
        Returns:
            LambdaMetrics object with invocation and duration data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get invocation count
            invocation_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Invocations',
                    Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,  # 1 day
                    Statistics=['Sum']
                )
            )
            
            datapoints = invocation_response.get('Datapoints', [])
            total_invocations = sum(dp.get('Sum', 0) for dp in datapoints)
            
            # Get duration metrics
            avg_duration_ms = None
            max_duration_ms = None
            
            if total_invocations > 0:
                duration_response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: cloudwatch.get_metric_statistics(
                        Namespace='AWS/Lambda',
                        MetricName='Duration',
                        Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=86400 * days,  # Single period for averages
                        Statistics=['Average', 'Maximum']
                    )
                )
                
                duration_datapoints = duration_response.get('Datapoints', [])
                if duration_datapoints:
                    avg_duration_ms = duration_datapoints[0].get('Average')
                    max_duration_ms = duration_datapoints[0].get('Maximum')
            
            # Get error count
            error_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Errors',
                    Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            error_datapoints = error_response.get('Datapoints', [])
            total_errors = int(sum(dp.get('Sum', 0) for dp in error_datapoints))
            
            return LambdaMetrics(
                total_invocations=int(total_invocations),
                avg_duration_ms=avg_duration_ms,
                max_duration_ms=max_duration_ms,
                errors=total_errors,
                period_days=days,
                is_unused=(total_invocations == 0),
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for Lambda {function_name}: {e}")
            return None

    # =========================================================================
    # ElastiCache Metrics
    # =========================================================================
    
    async def get_elasticache_metrics(
        self,
        cache_cluster_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
        idle_threshold: float = 10.0,
    ) -> Optional[ElastiCacheMetrics]:
        """
        Get metrics for an ElastiCache cluster.
        
        Args:
            cache_cluster_id: ElastiCache cluster ID
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            idle_threshold: CPU % below which cluster is considered oversized
            
        Returns:
            ElastiCacheMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get CPU utilization
            cpu_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ElastiCache',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'CacheClusterId', 'Value': cache_cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average', 'Maximum']
                )
            )
            
            # Get connections
            conn_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ElastiCache',
                    MetricName='CurrConnections',
                    Dimensions=[{'Name': 'CacheClusterId', 'Value': cache_cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            # Get cache hit/miss
            hits_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ElastiCache',
                    MetricName='CacheHits',
                    Dimensions=[{'Name': 'CacheClusterId', 'Value': cache_cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            misses_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ElastiCache',
                    MetricName='CacheMisses',
                    Dimensions=[{'Name': 'CacheClusterId', 'Value': cache_cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            cpu_datapoints = cpu_response.get('Datapoints', [])
            conn_datapoints = conn_response.get('Datapoints', [])
            
            avg_cpu = sum(dp.get('Average', 0) for dp in cpu_datapoints) / len(cpu_datapoints) if cpu_datapoints else 0
            max_cpu = max((dp.get('Maximum', 0) for dp in cpu_datapoints), default=0)
            avg_connections = sum(dp.get('Average', 0) for dp in conn_datapoints) / len(conn_datapoints) if conn_datapoints else 0
            cache_hits = int(sum(dp.get('Sum', 0) for dp in hits_response.get('Datapoints', [])))
            cache_misses = int(sum(dp.get('Sum', 0) for dp in misses_response.get('Datapoints', [])))
            
            return ElastiCacheMetrics(
                avg_cpu=round(avg_cpu, 2),
                max_cpu=round(max_cpu, 2),
                avg_connections=round(avg_connections, 2),
                cache_hits=cache_hits,
                cache_misses=cache_misses,
                period_days=days,
                is_idle=(cache_hits + cache_misses) == 0,
                is_oversized=max_cpu < idle_threshold,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for ElastiCache {cache_cluster_id}: {e}")
            return None

    # =========================================================================
    # Redshift Metrics
    # =========================================================================
    
    async def get_redshift_metrics(
        self,
        cluster_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
        idle_threshold: float = 10.0,
    ) -> Optional[RedshiftMetrics]:
        """
        Get metrics for a Redshift cluster.
        
        Args:
            cluster_id: Redshift cluster identifier
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            idle_threshold: CPU % below which cluster is considered oversized
            
        Returns:
            RedshiftMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get CPU utilization
            cpu_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Redshift',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average', 'Maximum']
                )
            )
            
            # Get database connections
            conn_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Redshift',
                    MetricName='DatabaseConnections',
                    Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get I/O metrics
            read_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Redshift',
                    MetricName='ReadIOPS',
                    Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            write_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Redshift',
                    MetricName='WriteIOPS',
                    Dimensions=[{'Name': 'ClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            cpu_datapoints = cpu_response.get('Datapoints', [])
            avg_cpu = sum(dp.get('Average', 0) for dp in cpu_datapoints) / len(cpu_datapoints) if cpu_datapoints else 0
            max_cpu = max((dp.get('Maximum', 0) for dp in cpu_datapoints), default=0)
            connections = int(sum(dp.get('Sum', 0) for dp in conn_response.get('Datapoints', [])))
            read_iops = int(sum(dp.get('Sum', 0) for dp in read_response.get('Datapoints', [])))
            write_iops = int(sum(dp.get('Sum', 0) for dp in write_response.get('Datapoints', [])))
            
            return RedshiftMetrics(
                avg_cpu=round(avg_cpu, 2),
                max_cpu=round(max_cpu, 2),
                database_connections=connections,
                read_iops=read_iops,
                write_iops=write_iops,
                period_days=days,
                is_idle=connections == 0,
                is_oversized=max_cpu < idle_threshold,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for Redshift {cluster_id}: {e}")
            return None

    # =========================================================================
    # DynamoDB Metrics
    # =========================================================================
    
    async def get_dynamodb_metrics(
        self,
        table_name: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[DynamoDBMetrics]:
        """
        Get metrics for a DynamoDB table.
        
        Args:
            table_name: DynamoDB table name
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            DynamoDBMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get consumed read units
            read_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/DynamoDB',
                    MetricName='ConsumedReadCapacityUnits',
                    Dimensions=[{'Name': 'TableName', 'Value': table_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Sum']
                )
            )
            
            # Get consumed write units
            write_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/DynamoDB',
                    MetricName='ConsumedWriteCapacityUnits',
                    Dimensions=[{'Name': 'TableName', 'Value': table_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Sum']
                )
            )
            
            # Get throttled requests
            throttle_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/DynamoDB',
                    MetricName='ThrottledRequests',
                    Dimensions=[{'Name': 'TableName', 'Value': table_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            consumed_reads = sum(dp.get('Sum', 0) for dp in read_response.get('Datapoints', []))
            consumed_writes = sum(dp.get('Sum', 0) for dp in write_response.get('Datapoints', []))
            throttled = int(sum(dp.get('Sum', 0) for dp in throttle_response.get('Datapoints', [])))
            
            return DynamoDBMetrics(
                consumed_read_units=round(consumed_reads, 2),
                consumed_write_units=round(consumed_writes, 2),
                provisioned_read_units=0,  # Would need to query DynamoDB API
                provisioned_write_units=0,
                throttled_requests=throttled,
                period_days=days,
                is_idle=(consumed_reads + consumed_writes) == 0,
                is_over_provisioned=False,  # Need provisioned capacity to determine
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for DynamoDB {table_name}: {e}")
            return None

    # =========================================================================
    # OpenSearch Metrics
    # =========================================================================
    
    async def get_opensearch_metrics(
        self,
        domain_name: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
        idle_threshold: float = 10.0,
    ) -> Optional[OpenSearchMetrics]:
        """
        Get metrics for an OpenSearch domain.
        
        Args:
            domain_name: OpenSearch domain name
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            idle_threshold: CPU % below which domain is considered oversized
            
        Returns:
            OpenSearchMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get CPU utilization
            cpu_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ES',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'DomainName', 'Value': domain_name}, {'Name': 'ClientId', 'Value': '*'}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average', 'Maximum']
                )
            )
            
            # Get search rate
            search_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ES',
                    MetricName='SearchRate',
                    Dimensions=[{'Name': 'DomainName', 'Value': domain_name}, {'Name': 'ClientId', 'Value': '*'}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            # Get indexing rate
            index_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ES',
                    MetricName='IndexingRate',
                    Dimensions=[{'Name': 'DomainName', 'Value': domain_name}, {'Name': 'ClientId', 'Value': '*'}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            cpu_datapoints = cpu_response.get('Datapoints', [])
            avg_cpu = sum(dp.get('Average', 0) for dp in cpu_datapoints) / len(cpu_datapoints) if cpu_datapoints else 0
            max_cpu = max((dp.get('Maximum', 0) for dp in cpu_datapoints), default=0)
            
            search_datapoints = search_response.get('Datapoints', [])
            search_rate = sum(dp.get('Average', 0) for dp in search_datapoints) / len(search_datapoints) if search_datapoints else 0
            
            index_datapoints = index_response.get('Datapoints', [])
            indexing_rate = sum(dp.get('Average', 0) for dp in index_datapoints) / len(index_datapoints) if index_datapoints else 0
            
            return OpenSearchMetrics(
                avg_cpu=round(avg_cpu, 2),
                max_cpu=round(max_cpu, 2),
                search_rate=round(search_rate, 2),
                indexing_rate=round(indexing_rate, 2),
                period_days=days,
                is_idle=(search_rate + indexing_rate) == 0,
                is_oversized=max_cpu < idle_threshold,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for OpenSearch {domain_name}: {e}")
            return None

    # =========================================================================
    # Kinesis Metrics
    # =========================================================================
    
    async def get_kinesis_metrics(
        self,
        stream_name: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[KinesisMetrics]:
        """
        Get metrics for a Kinesis stream.
        
        Args:
            stream_name: Kinesis stream name
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            KinesisMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get incoming records
            records_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Kinesis',
                    MetricName='IncomingRecords',
                    Dimensions=[{'Name': 'StreamName', 'Value': stream_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get incoming bytes
            bytes_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Kinesis',
                    MetricName='IncomingBytes',
                    Dimensions=[{'Name': 'StreamName', 'Value': stream_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get iterator age
            age_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Kinesis',
                    MetricName='GetRecords.IteratorAgeMilliseconds',
                    Dimensions=[{'Name': 'StreamName', 'Value': stream_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            incoming_records = int(sum(dp.get('Sum', 0) for dp in records_response.get('Datapoints', [])))
            incoming_bytes = int(sum(dp.get('Sum', 0) for dp in bytes_response.get('Datapoints', [])))
            
            age_datapoints = age_response.get('Datapoints', [])
            iterator_age = sum(dp.get('Average', 0) for dp in age_datapoints) / len(age_datapoints) if age_datapoints else 0
            
            return KinesisMetrics(
                incoming_records=incoming_records,
                incoming_bytes=incoming_bytes,
                get_records_success=0,  # Would need additional metric
                iterator_age_ms=round(iterator_age, 2),
                period_days=days,
                is_idle=incoming_records == 0,
                is_over_provisioned=False,  # Would need shard utilization calculation
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for Kinesis {stream_name}: {e}")
            return None

    # =========================================================================
    # SageMaker Metrics
    # =========================================================================
    
    async def get_sagemaker_endpoint_metrics(
        self,
        endpoint_name: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[SageMakerMetrics]:
        """
        Get metrics for a SageMaker endpoint.
        
        Args:
            endpoint_name: SageMaker endpoint name
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            SageMakerMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get invocations
            inv_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/SageMaker',
                    MetricName='Invocations',
                    Dimensions=[{'Name': 'EndpointName', 'Value': endpoint_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get model latency
            latency_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/SageMaker',
                    MetricName='ModelLatency',
                    Dimensions=[{'Name': 'EndpointName', 'Value': endpoint_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            invocations = int(sum(dp.get('Sum', 0) for dp in inv_response.get('Datapoints', [])))
            
            latency_datapoints = latency_response.get('Datapoints', [])
            model_latency = sum(dp.get('Average', 0) for dp in latency_datapoints) / len(latency_datapoints) if latency_datapoints else 0
            
            return SageMakerMetrics(
                invocations=invocations,
                model_latency_ms=round(model_latency / 1000, 2),  # Convert to ms
                overhead_latency_ms=0,
                invocations_per_instance=invocations,  # Would need instance count
                period_days=days,
                is_idle=invocations == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for SageMaker {endpoint_name}: {e}")
            return None

    # =========================================================================
    # EFS Metrics
    # =========================================================================
    
    async def get_efs_metrics(
        self,
        filesystem_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[EFSMetrics]:
        """
        Get metrics for an EFS filesystem.
        
        Args:
            filesystem_id: EFS filesystem ID
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            EFSMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get client connections
            conn_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/EFS',
                    MetricName='ClientConnections',
                    Dimensions=[{'Name': 'FileSystemId', 'Value': filesystem_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Sum']
                )
            )
            
            # Get data read
            read_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/EFS',
                    MetricName='DataReadIOBytes',
                    Dimensions=[{'Name': 'FileSystemId', 'Value': filesystem_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get data write
            write_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/EFS',
                    MetricName='DataWriteIOBytes',
                    Dimensions=[{'Name': 'FileSystemId', 'Value': filesystem_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            connections = int(sum(dp.get('Sum', 0) for dp in conn_response.get('Datapoints', [])))
            read_bytes = int(sum(dp.get('Sum', 0) for dp in read_response.get('Datapoints', [])))
            write_bytes = int(sum(dp.get('Sum', 0) for dp in write_response.get('Datapoints', [])))
            
            return EFSMetrics(
                client_connections=connections,
                data_read_bytes=read_bytes,
                data_write_bytes=write_bytes,
                period_days=days,
                is_idle=(read_bytes + write_bytes) == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for EFS {filesystem_id}: {e}")
            return None

    # =========================================================================
    # MSK Metrics
    # =========================================================================
    
    async def get_msk_metrics(
        self,
        cluster_name: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[MSKMetrics]:
        """
        Get metrics for an MSK cluster.
        
        Args:
            cluster_name: MSK cluster name
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            MSKMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get messages in per second
            msg_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Kafka',
                    MetricName='MessagesInPerSec',
                    Dimensions=[{'Name': 'Cluster Name', 'Value': cluster_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            # Get bytes in per second
            bytes_in_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Kafka',
                    MetricName='BytesInPerSec',
                    Dimensions=[{'Name': 'Cluster Name', 'Value': cluster_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            # Get bytes out per second
            bytes_out_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Kafka',
                    MetricName='BytesOutPerSec',
                    Dimensions=[{'Name': 'Cluster Name', 'Value': cluster_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            # Get CPU utilization
            cpu_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Kafka',
                    MetricName='CpuUser',
                    Dimensions=[{'Name': 'Cluster Name', 'Value': cluster_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            msg_datapoints = msg_response.get('Datapoints', [])
            messages_in = sum(dp.get('Average', 0) for dp in msg_datapoints) / len(msg_datapoints) if msg_datapoints else 0
            
            bytes_in_datapoints = bytes_in_response.get('Datapoints', [])
            bytes_in = sum(dp.get('Average', 0) for dp in bytes_in_datapoints) / len(bytes_in_datapoints) if bytes_in_datapoints else 0
            
            bytes_out_datapoints = bytes_out_response.get('Datapoints', [])
            bytes_out = sum(dp.get('Average', 0) for dp in bytes_out_datapoints) / len(bytes_out_datapoints) if bytes_out_datapoints else 0
            
            cpu_datapoints = cpu_response.get('Datapoints', [])
            cpu_user = sum(dp.get('Average', 0) for dp in cpu_datapoints) / len(cpu_datapoints) if cpu_datapoints else 0
            
            return MSKMetrics(
                messages_in_per_sec=round(messages_in, 2),
                bytes_in_per_sec=round(bytes_in, 2),
                bytes_out_per_sec=round(bytes_out, 2),
                cpu_user=round(cpu_user, 2),
                period_days=days,
                is_idle=messages_in == 0 and bytes_in == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for MSK {cluster_name}: {e}")
            return None

    # =========================================================================
    # Neptune Metrics
    # =========================================================================
    
    async def get_neptune_metrics(
        self,
        cluster_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[NeptuneMetrics]:
        """
        Get metrics for a Neptune cluster.
        
        Args:
            cluster_id: Neptune cluster identifier
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            NeptuneMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get Gremlin requests
            gremlin_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Neptune',
                    MetricName='GremlinRequestsPerSec',
                    Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get SPARQL requests
            sparql_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Neptune',
                    MetricName='SparqlRequestsPerSec',
                    Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get CPU utilization
            cpu_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/Neptune',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average', 'Maximum']
                )
            )
            
            gremlin_requests = int(sum(dp.get('Sum', 0) for dp in gremlin_response.get('Datapoints', [])))
            sparql_requests = int(sum(dp.get('Sum', 0) for dp in sparql_response.get('Datapoints', [])))
            
            cpu_datapoints = cpu_response.get('Datapoints', [])
            avg_cpu = sum(dp.get('Average', 0) for dp in cpu_datapoints) / len(cpu_datapoints) if cpu_datapoints else 0
            max_cpu = max((dp.get('Maximum', 0) for dp in cpu_datapoints), default=0)
            
            return NeptuneMetrics(
                gremlin_requests=gremlin_requests,
                sparql_requests=sparql_requests,
                loader_requests=0,
                avg_cpu=round(avg_cpu, 2),
                max_cpu=round(max_cpu, 2),
                connections=0,
                period_days=days,
                is_idle=(gremlin_requests + sparql_requests) == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for Neptune {cluster_id}: {e}")
            return None

    # =========================================================================
    # DocumentDB Metrics
    # =========================================================================
    
    async def get_documentdb_metrics(
        self,
        cluster_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[DocumentDBMetrics]:
        """
        Get metrics for a DocumentDB cluster.
        
        Args:
            cluster_id: DocumentDB cluster identifier
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            DocumentDBMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get database connections
            conn_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/DocDB',
                    MetricName='DatabaseConnections',
                    Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get read IOPS
            read_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/DocDB',
                    MetricName='ReadIOPS',
                    Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get write IOPS
            write_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/DocDB',
                    MetricName='WriteIOPS',
                    Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get CPU utilization
            cpu_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/DocDB',
                    MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'DBClusterIdentifier', 'Value': cluster_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average', 'Maximum']
                )
            )
            
            connections = int(sum(dp.get('Sum', 0) for dp in conn_response.get('Datapoints', [])))
            read_iops = int(sum(dp.get('Sum', 0) for dp in read_response.get('Datapoints', [])))
            write_iops = int(sum(dp.get('Sum', 0) for dp in write_response.get('Datapoints', [])))
            
            cpu_datapoints = cpu_response.get('Datapoints', [])
            avg_cpu = sum(dp.get('Average', 0) for dp in cpu_datapoints) / len(cpu_datapoints) if cpu_datapoints else 0
            max_cpu = max((dp.get('Maximum', 0) for dp in cpu_datapoints), default=0)
            
            return DocumentDBMetrics(
                database_connections=connections,
                read_iops=read_iops,
                write_iops=write_iops,
                avg_cpu=round(avg_cpu, 2),
                max_cpu=round(max_cpu, 2),
                period_days=days,
                is_idle=connections == 0 and (read_iops + write_iops) == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for DocumentDB {cluster_id}: {e}")
            return None

    # =========================================================================
    # FSx Metrics
    # =========================================================================
    
    async def get_fsx_metrics(
        self,
        filesystem_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[FSxMetrics]:
        """
        Get metrics for an FSx filesystem.
        
        Args:
            filesystem_id: FSx filesystem ID
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            FSxMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get data read bytes
            read_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/FSx',
                    MetricName='DataReadBytes',
                    Dimensions=[{'Name': 'FileSystemId', 'Value': filesystem_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get data write bytes
            write_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/FSx',
                    MetricName='DataWriteBytes',
                    Dimensions=[{'Name': 'FileSystemId', 'Value': filesystem_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            read_bytes = int(sum(dp.get('Sum', 0) for dp in read_response.get('Datapoints', [])))
            write_bytes = int(sum(dp.get('Sum', 0) for dp in write_response.get('Datapoints', [])))
            
            return FSxMetrics(
                data_read_bytes=read_bytes,
                data_write_bytes=write_bytes,
                client_connections=0,
                period_days=days,
                is_idle=(read_bytes + write_bytes) == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for FSx {filesystem_id}: {e}")
            return None

    # =========================================================================
    # Amazon MQ Metrics
    # =========================================================================
    
    async def get_mq_metrics(
        self,
        broker_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[MQMetrics]:
        """
        Get metrics for an Amazon MQ broker.
        
        Args:
            broker_id: Amazon MQ broker ID
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            MQMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get total message count
            msg_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/AmazonMQ',
                    MetricName='TotalMessageCount',
                    Dimensions=[{'Name': 'Broker', 'Value': broker_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get consumer count
            consumer_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/AmazonMQ',
                    MetricName='TotalConsumerCount',
                    Dimensions=[{'Name': 'Broker', 'Value': broker_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            # Get producer count
            producer_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/AmazonMQ',
                    MetricName='TotalProducerCount',
                    Dimensions=[{'Name': 'Broker', 'Value': broker_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            # Get CPU utilization
            cpu_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/AmazonMQ',
                    MetricName='CpuUtilization',
                    Dimensions=[{'Name': 'Broker', 'Value': broker_id}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            messages = int(sum(dp.get('Sum', 0) for dp in msg_response.get('Datapoints', [])))
            
            consumer_datapoints = consumer_response.get('Datapoints', [])
            consumers = int(sum(dp.get('Average', 0) for dp in consumer_datapoints) / len(consumer_datapoints)) if consumer_datapoints else 0
            
            producer_datapoints = producer_response.get('Datapoints', [])
            producers = int(sum(dp.get('Average', 0) for dp in producer_datapoints) / len(producer_datapoints)) if producer_datapoints else 0
            
            cpu_datapoints = cpu_response.get('Datapoints', [])
            cpu = sum(dp.get('Average', 0) for dp in cpu_datapoints) / len(cpu_datapoints) if cpu_datapoints else 0
            
            return MQMetrics(
                total_message_count=messages,
                total_consumer_count=consumers,
                total_producer_count=producers,
                cpu_utilization=round(cpu, 2),
                period_days=days,
                is_idle=messages == 0 and consumers == 0 and producers == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for MQ {broker_id}: {e}")
            return None

    # =========================================================================
    # QLDB Metrics
    # =========================================================================
    
    async def get_qldb_metrics(
        self,
        ledger_name: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 7,
        session_token: str = None,
    ) -> Optional[QLDBMetrics]:
        """
        Get metrics for a QLDB ledger.
        
        Args:
            ledger_name: QLDB ledger name
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 7)
            session_token: Optional session token
            
        Returns:
            QLDBMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get commands executed
            cmd_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/QLDB',
                    MetricName='CommandLatency',
                    Dimensions=[{'Name': 'LedgerName', 'Value': ledger_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['SampleCount']
                )
            )
            
            # Get read IOs
            read_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/QLDB',
                    MetricName='ReadIOs',
                    Dimensions=[{'Name': 'LedgerName', 'Value': ledger_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get write IOs
            write_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/QLDB',
                    MetricName='WriteIOs',
                    Dimensions=[{'Name': 'LedgerName', 'Value': ledger_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            commands = int(sum(dp.get('SampleCount', 0) for dp in cmd_response.get('Datapoints', [])))
            read_ios = int(sum(dp.get('Sum', 0) for dp in read_response.get('Datapoints', [])))
            write_ios = int(sum(dp.get('Sum', 0) for dp in write_response.get('Datapoints', [])))
            
            return QLDBMetrics(
                commands_total=commands,
                read_ios=read_ios,
                write_ios=write_ios,
                period_days=days,
                is_idle=commands == 0 and (read_ios + write_ios) == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for QLDB {ledger_name}: {e}")
            return None

    # =========================================================================
    # API Gateway Metrics
    # =========================================================================
    
    async def get_api_gateway_metrics(
        self,
        api_name: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 30,
        session_token: str = None,
    ) -> Optional[APIGatewayMetrics]:
        """
        Get metrics for an API Gateway.
        
        Args:
            api_name: API Gateway name or ID
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region
            days: Number of days to analyze (default 30)
            session_token: Optional session token
            
        Returns:
            APIGatewayMetrics object with utilization data, or None on error
        """
        try:
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, region, session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get request count
            count_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApiGateway',
                    MetricName='Count',
                    Dimensions=[{'Name': 'ApiName', 'Value': api_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get 4XX errors
            error_4xx_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApiGateway',
                    MetricName='4XXError',
                    Dimensions=[{'Name': 'ApiName', 'Value': api_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get 5XX errors
            error_5xx_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApiGateway',
                    MetricName='5XXError',
                    Dimensions=[{'Name': 'ApiName', 'Value': api_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get latency
            latency_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/ApiGateway',
                    MetricName='Latency',
                    Dimensions=[{'Name': 'ApiName', 'Value': api_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            total_requests = int(sum(dp.get('Sum', 0) for dp in count_response.get('Datapoints', [])))
            error_4xx = int(sum(dp.get('Sum', 0) for dp in error_4xx_response.get('Datapoints', [])))
            error_5xx = int(sum(dp.get('Sum', 0) for dp in error_5xx_response.get('Datapoints', [])))
            
            latency_datapoints = latency_response.get('Datapoints', [])
            avg_latency = sum(dp.get('Average', 0) for dp in latency_datapoints) / len(latency_datapoints) if latency_datapoints else 0
            
            return APIGatewayMetrics(
                total_requests=total_requests,
                error_4xx=error_4xx,
                error_5xx=error_5xx,
                avg_latency_ms=round(avg_latency, 2),
                period_days=days,
                is_idle=total_requests == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for API Gateway {api_name}: {e}")
            return None

    # =========================================================================
    # CloudFront Metrics
    # =========================================================================
    
    async def get_cloudfront_metrics(
        self,
        distribution_id: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        days: int = 30,
        session_token: str = None,
    ) -> Optional[CloudFrontMetrics]:
        """
        Get metrics for a CloudFront distribution.
        
        Args:
            distribution_id: CloudFront distribution ID
            access_key_id: Customer's AWS access key
            secret_access_key: Customer's AWS secret key
            region: AWS region (Note: CloudFront metrics are in us-east-1)
            days: Number of days to analyze (default 30)
            session_token: Optional session token
            
        Returns:
            CloudFrontMetrics object with utilization data, or None on error
        """
        try:
            # CloudFront metrics are always in us-east-1
            cloudwatch = self._create_cloudwatch_client(
                access_key_id, secret_access_key, 'us-east-1', session_token
            )
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days)
            
            # Get request count
            requests_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/CloudFront',
                    MetricName='Requests',
                    Dimensions=[
                        {'Name': 'DistributionId', 'Value': distribution_id},
                        {'Name': 'Region', 'Value': 'Global'}
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get bytes downloaded
            bytes_down_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/CloudFront',
                    MetricName='BytesDownloaded',
                    Dimensions=[
                        {'Name': 'DistributionId', 'Value': distribution_id},
                        {'Name': 'Region', 'Value': 'Global'}
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * days,
                    Statistics=['Sum']
                )
            )
            
            # Get error rate
            error_response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: cloudwatch.get_metric_statistics(
                    Namespace='AWS/CloudFront',
                    MetricName='TotalErrorRate',
                    Dimensions=[
                        {'Name': 'DistributionId', 'Value': distribution_id},
                        {'Name': 'Region', 'Value': 'Global'}
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average']
                )
            )
            
            total_requests = int(sum(dp.get('Sum', 0) for dp in requests_response.get('Datapoints', [])))
            bytes_downloaded = int(sum(dp.get('Sum', 0) for dp in bytes_down_response.get('Datapoints', [])))
            
            error_datapoints = error_response.get('Datapoints', [])
            error_rate = sum(dp.get('Average', 0) for dp in error_datapoints) / len(error_datapoints) if error_datapoints else 0
            
            return CloudFrontMetrics(
                total_requests=total_requests,
                bytes_downloaded=bytes_downloaded,
                bytes_uploaded=0,
                error_rate=round(error_rate, 2),
                period_days=days,
                is_idle=total_requests == 0,
            )
            
        except Exception as e:
            logger.error(f"Error getting metrics for CloudFront {distribution_id}: {e}")
            return None


# Singleton instance
_cloudwatch_metrics_service: Optional[CloudWatchMetricsService] = None


def get_cloudwatch_metrics_service() -> CloudWatchMetricsService:
    """Get or create the CloudWatch metrics service singleton."""
    global _cloudwatch_metrics_service
    if _cloudwatch_metrics_service is None:
        _cloudwatch_metrics_service = CloudWatchMetricsService()
    return _cloudwatch_metrics_service
