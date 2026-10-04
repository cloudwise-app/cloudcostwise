"""
Waste Detection Data Providers

This module provides the abstraction layer for data access in waste detection.
It enables both online (live AWS API) and offline (exported JSON) modes to use
the same detection logic.

Classes:
    WasteDataProvider: Abstract base class defining the data access interface
    OnlineDataProvider: Implementation using live boto3 AWS API calls
    OfflineDataProvider: Implementation using parsed JSON export files
"""

from cloudwise_scan_core.data_providers.base import WasteDataProvider
from cloudwise_scan_core.data_providers.online import OnlineDataProvider
from cloudwise_scan_core.data_providers.offline import OfflineDataProvider
from cloudwise_scan_core.data_providers.models import (
    EC2InstanceData,
    EC2MetricsData,
    EBSVolumeData,
    EBSSnapshotData,
    ElasticIPData,
    RDSInstanceData,
    RDSMetricsData,
    RDSSnapshotData,
    LambdaFunctionData,
    LambdaMetricsData,
    NATGatewayData,
    NATGatewayMetricsData,
    S3BucketData,
    ExtendedSupportCostData,
    LoadBalancerData,
    LoadBalancerMetricsData,
    Route53ZoneData,
    DynamoDBTableData,
    DynamoDBMetricsData,
    ElastiCacheClusterData,
    ElastiCacheMetricsData,
    ElastiCacheRequestVolumeData,
    ApiGatewayRestApiData,
    RedshiftClusterData,
    RedshiftMetricsData,
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
)

__all__ = [
    # Base classes
    "WasteDataProvider",
    "OnlineDataProvider", 
    "OfflineDataProvider",
    # Data models
    "EC2InstanceData",
    "EC2MetricsData",
    "EBSVolumeData",
    "EBSSnapshotData",
    "ElasticIPData",
    "RDSInstanceData",
    "RDSMetricsData",
    "RDSSnapshotData",
    "LambdaFunctionData",
    "LambdaMetricsData",
    "NATGatewayData",
    "NATGatewayMetricsData",
    "S3BucketData",
    "ExtendedSupportCostData",
    "LoadBalancerData",
    "LoadBalancerMetricsData",
    "Route53ZoneData",
    "DynamoDBTableData",
    "DynamoDBMetricsData",
    "ElastiCacheClusterData",
    "ElastiCacheMetricsData",
    "ElastiCacheRequestVolumeData",
    "ApiGatewayRestApiData",
    "RedshiftClusterData",
    "RedshiftMetricsData",
    "OpenSearchDomainData",
    "OpenSearchMetricsData",
    "CloudWatchLogGroupData",
    "KMSKeyData",
    "SecretsManagerSecretData",
    "SageMakerNotebookData",
    "SageMakerEndpointData",
    "SageMakerMetricsData",
    "KinesisStreamData",
    "KinesisMetricsData",
]
