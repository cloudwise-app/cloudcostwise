"""
Waste Detection Detector Modules

This package contains the modularized waste detectors, organized by AWS service category.

Each module provides a Mixin class that can be inherited by the main WasteDetectionService
to add detector capabilities.

Modules:
- compute: EC2, Lambda, ECS, SageMaker, WorkSpaces, Lightsail, Elastic Beanstalk
- storage: EBS, S3, EFS, FSx, ECR, Backup
- database: RDS, DynamoDB, ElastiCache, Redshift, OpenSearch, Neptune, DocumentDB, Timestream, QLDB
- network: Elastic IPs, NAT Gateways, Load Balancers, CloudFront, Route 53, Global Accelerator
- analytics: EMR, Kinesis, Glue
- integration: API Gateway, MSK, MQ, Step Functions, AppSync, Transfer Family
- management: CloudWatch, Secrets Manager, KMS, CloudTrail
- optimizer: AWS Compute Optimizer (EC2, EBS, Lambda rightsizing)
- savings: Reserved Instances, Savings Plans recommendations

Usage:
    from cloudwise_scan_core.detectors import (
        ComputeDetectorsMixin,
        StorageDetectorsMixin,
        DatabaseDetectorsMixin,
        NetworkDetectorsMixin,
        AnalyticsDetectorsMixin,
        IntegrationDetectorsMixin,
        ManagementDetectorsMixin,
        ComputeOptimizerDetectorsMixin,
        SavingsOpportunitiesDetectorsMixin,
    )
    
    class WasteDetectionService(
        ComputeDetectorsMixin,
        StorageDetectorsMixin,
        DatabaseDetectorsMixin,
        NetworkDetectorsMixin,
        AnalyticsDetectorsMixin,
        IntegrationDetectorsMixin,
        ManagementDetectorsMixin,
        ComputeOptimizerDetectorsMixin,
        SavingsOpportunitiesDetectorsMixin,
    ):
        # ... main service code
"""

# CLO-562: resolved lazily (PEP 562) so that importing
# ``cloudwise_scan_core.detectors.open`` does not load the closed detector
# modules. ``from cloudwise_scan_core.detectors import XMixin`` keeps working.
_MIXIN_MODULES = {
    'ComputeDetectorsMixin': 'compute',
    'StorageDetectorsMixin': 'storage',
    'DatabaseDetectorsMixin': 'database',
    'NetworkDetectorsMixin': 'network',
    'AnalyticsDetectorsMixin': 'analytics',
    'IntegrationDetectorsMixin': 'integration',
    'ManagementDetectorsMixin': 'management',
    'ComputeOptimizerDetectorsMixin': 'optimizer',
    'SavingsOpportunitiesDetectorsMixin': 'savings',
    'SecurityPostureDetectorsMixin': 'security',
    'CommitmentRiskDetectorsMixin': 'commitment',
}


def __getattr__(name):
    module = _MIXIN_MODULES.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(f"{__name__}.{module}"), name)


__all__ = [
    'ComputeDetectorsMixin',
    'StorageDetectorsMixin',
    'DatabaseDetectorsMixin',
    'NetworkDetectorsMixin',
    'AnalyticsDetectorsMixin',
    'IntegrationDetectorsMixin',
    'ManagementDetectorsMixin',
    'ComputeOptimizerDetectorsMixin',
    'SavingsOpportunitiesDetectorsMixin',
    'SecurityPostureDetectorsMixin',
    'CommitmentRiskDetectorsMixin',
]
