"""
Waste Detection Data Models

Defines the data structures for waste detection results, settings, and configurations.
These models are used throughout the waste detection service.
"""

import functools
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Dict, Any, Optional, List


# UUID v4 pattern for detecting random UUIDs that need replacement
_UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)


def generate_deterministic_id(
    resource_id: str,
    waste_type: str,
    region: str,
    account_id: str = ""
) -> str:
    """
    Generate a deterministic ID for a waste item based on the resource itself.
    
    This ensures the same resource produces the same ID across scans,
    enabling natural deduplication through DynamoDB's put_item overwrite.
    
    Args:
        resource_id: AWS resource identifier (e.g., i-0abc123, vol-xyz)
        waste_type: Type of waste detected (e.g., unattached_ebs)
        region: AWS region (e.g., us-east-1)
        account_id: AWS account ID (optional, for cross-account uniqueness)
        
    Returns:
        24-character deterministic hash ID
    """
    identity = f"{account_id}|{region}|{waste_type}|{resource_id}"
    return hashlib.sha256(identity.encode()).hexdigest()[:24]


def _utc_now() -> datetime:
    """Get current UTC time (timezone-aware). Replaces deprecated utcnow()."""
    return datetime.now(timezone.utc)


class WasteType(str, Enum):
    """
    Types of waste that can be detected.
    
    DEPRECATED Types (kept for backwards compatibility, not actively detected):
    - OVERSIZED_EC2: Removed - 25-50% savings estimate is arbitrary
    - PREVIOUS_GEN_EC2: Removed - 10-20% savings varies too widely (5-30%)
    - OVERSIZED_RDS: Removed - 50% savings estimate doesn't account for memory/IOPS
    - MULTIAZ_NONPROD: Removed - Name-based heuristic is unreliable
    - IDLE_QLDB: Removed (CLO-168) - dead code (missing provider method, never fired);
      near-zero savings (~$0.025/GB); AWS QLDB is being retired
    - IDLE_TIMESTREAM: Removed (CLO-168) - only flagged empty databases (not "idle" by
      writes as advertised); trivial $0.01 savings
    - IDLE_GLUE_DEV_ENDPOINT, GLUE_DEV_ENDPOINT_MIGRATION: Removed (CLO-462) - AWS has
      disabled the GetDevEndpoints API for every account ("GetDevEndpoints operation is
      currently disabled"), so neither can ever fire; Glue dev endpoints are retired
      in favour of Glue interactive sessions
    - REDSHIFT_SPECTRUM_HEAVY: Removed (CLO-747) - its 60% saving from moving to Athena
      was false: Redshift Data Scan and Athena both cost $5.00/TB in us-east-1. It never
      fired on real AWS
    
    For right-sizing recommendations, use AWS Compute Optimizer instead.
    """
    # EC2 Waste Types
    IDLE_EC2 = "idle_ec2"
    OVERSIZED_EC2 = "oversized_ec2"  # DEPRECATED: Not actively detected
    PREVIOUS_GEN_EC2 = "previous_gen_ec2"  # DEPRECATED: Not actively detected
    STOPPED_EC2_WITH_EBS = "stopped_ec2_with_ebs"
    
    # EBS Waste Types
    UNATTACHED_EBS = "unattached_ebs"
    OLD_EBS_SNAPSHOT = "old_ebs_snapshot"
    ORPHANED_EBS_SNAPSHOT = "orphaned_ebs_snapshot"
    AMI_ORPHANED_SNAPSHOT = "ami_orphaned_snapshot"
    GP2_MIGRATION = "gp2_migration"
    OVER_PROVISIONED_IOPS = "over_provisioned_iops"
    
    # RDS Waste Types
    IDLE_RDS = "idle_rds"
    OVERSIZED_RDS = "oversized_rds"  # DEPRECATED: Not actively detected
    MULTIAZ_NONPROD = "multiaz_nonprod"  # DEPRECATED: Not actively detected
    OLD_RDS_SNAPSHOT = "old_rds_snapshot"
    
    # Aurora Waste Types
    AURORA_IO_OPTIMIZATION_OPPORTUNITY = "aurora_io_optimization_opportunity"
    AURORA_EXTENDED_SUPPORT_COST = "aurora_extended_support_cost"
    AURORA_SERVERLESS_OPPORTUNITY = "aurora_serverless_opportunity"
    AURORA_TO_RDS_DOWNGRADE_OPPORTUNITY = "aurora_to_rds_downgrade_opportunity"
    RDS_EXTENDED_SUPPORT_COST = "rds_extended_support_cost"
    ELASTICACHE_EXTENDED_SUPPORT_COST = "elasticache_extended_support_cost"
    EKS_EXTENDED_SUPPORT_COST = "eks_extended_support_cost"
    OPENSEARCH_EXTENDED_SUPPORT_COST = "opensearch_extended_support_cost"
    DOCUMENTDB_EXTENDED_SUPPORT_COST = "documentdb_extended_support_cost"
    
    # Network Waste Types
    UNATTACHED_EIP = "unattached_eip"
    IDLE_NAT_GATEWAY = "idle_nat_gateway"
    IDLE_LOAD_BALANCER = "idle_load_balancer"
    LOW_TRAFFIC_ALB = "low_traffic_alb"
    HIGH_LCU_COST_ALB = "high_lcu_cost_alb"
    CLASSIC_LB_MIGRATION = "classic_lb_migration"
    UNUSED_VPC_ENDPOINT = "unused_vpc_endpoint"
    
    # Lambda Waste Types
    UNUSED_LAMBDA = "unused_lambda"
    OVER_PROVISIONED_LAMBDA = "over_provisioned_lambda"
    LAMBDA_PROVISIONED_CONCURRENCY_IDLE = "lambda_provisioned_concurrency_idle"
    LAMBDA_EXCESSIVE_TIMEOUT = "lambda_excessive_timeout"
    LAMBDA_ARM64_MIGRATION = "lambda_arm64_migration"
    LAMBDA_OLD_RUNTIME = "lambda_old_runtime"
    
    # S3 Waste Types
    NO_LIFECYCLE_POLICY = "no_lifecycle_policy"
    INCOMPLETE_MULTIPART = "incomplete_multipart"
    S3_RAPID_GROWTH = "s3_rapid_growth"
    S3_WRONG_STORAGE_CLASS = "s3_wrong_storage_class"
    S3_EMPTY_BUCKET = "s3_empty_bucket"
    S3_HIGH_REQUEST_AND_TRANSFER_COST = "s3_high_request_and_transfer_cost"
    S3_KMS_BUCKET_KEY_DISABLED = "s3_kms_bucket_key_disabled"
    
    # DynamoDB Waste Types
    IDLE_DYNAMODB = "idle_dynamodb"
    OVER_PROVISIONED_DYNAMODB = "over_provisioned_dynamodb"
    DYNAMODB_NO_AUTOSCALING = "dynamodb_no_autoscaling"
    
    # ElastiCache Waste Types
    IDLE_ELASTICACHE = "idle_elasticache"
    OVERSIZED_ELASTICACHE = "oversized_elasticache"
    ELASTICACHE_REPLICATION_WASTE = "elasticache_replication_waste"
    ELASTICACHE_ENGINE_MIGRATION = "elasticache_engine_migration"
    ELASTICACHE_SERVERLESS_OPTIMIZATION = "elasticache_serverless_optimization"
    ELASTICACHE_DATA_TIERING_OPPORTUNITY = "elasticache_data_tiering_opportunity"
    
    # Redshift Waste Types
    IDLE_REDSHIFT = "idle_redshift"
    OVERSIZED_REDSHIFT = "oversized_redshift"
    UNDERUTILIZED_REDSHIFT = "underutilized_redshift"
    REDSHIFT_NO_PAUSE = "redshift_no_pause"
    REDSHIFT_SPECTRUM_HEAVY = "redshift_spectrum_heavy"  # DEPRECATED (CLO-747): Not actively detected
    REDSHIFT_LEGACY_DC2 = "redshift_legacy_dc2"
    REDSHIFT_WLM_OVER_PROVISIONED = "redshift_wlm_over_provisioned"
    REDSHIFT_CONCURRENCY_SCALING_WASTE = "redshift_concurrency_scaling_waste"
    
    # OpenSearch Waste Types
    IDLE_OPENSEARCH = "idle_opensearch"
    OVERSIZED_OPENSEARCH = "oversized_opensearch"
    OPENSEARCH_EBS_OVERPROVISIONED = "opensearch_ebs_overprovisioned"
    
    # ECS/Fargate Waste Types
    OVERSIZED_ECS_TASK = "oversized_ecs_task"
    IDLE_ECS_SERVICE = "idle_ecs_service"
    ECS_NO_AUTOSCALING = "ecs_no_autoscaling"
    ECS_CONTAINER_INSIGHTS_WASTE = "ecs_container_insights_waste"
    OVERSIZED_ECS_MEMORY = "oversized_ecs_memory"
    
    # CloudWatch Waste Types
    UNUSED_DASHBOARD = "unused_dashboard"
    OLD_LOG_GROUP = "old_log_group"
    NO_RETENTION_LOG_GROUP = "no_retention_log_group"
    EXCESSIVE_RETENTION_LOG_GROUP = "excessive_retention_log_group"
    EMPTY_LOG_GROUP = "empty_log_group"
    
    # Secrets Manager Waste Types
    UNUSED_SECRET = "unused_secret"
    
    # KMS Waste Types
    UNUSED_KMS_KEY = "unused_kms_key"
    
    # EMR Waste Types
    IDLE_EMR_CLUSTER = "idle_emr_cluster"
    LONG_RUNNING_EMR = "long_running_emr"
    EMR_OVER_PROVISIONED = "emr_over_provisioned"
    EMR_MISSING_AUTO_TERMINATION = "emr_missing_auto_termination"
    EMR_PREVIOUS_GEN_INSTANCES = "emr_previous_gen_instances"
    EMR_SPOT_OPPORTUNITY = "emr_spot_opportunity"
    
    # SageMaker Waste Types
    IDLE_SAGEMAKER_NOTEBOOK = "idle_sagemaker_notebook"
    IDLE_SAGEMAKER_ENDPOINT = "idle_sagemaker_endpoint"
    OVERSIZED_SAGEMAKER_ENDPOINT = "oversized_sagemaker_endpoint"
    STOPPED_SAGEMAKER_NOTEBOOK_STORAGE = "stopped_sagemaker_notebook_storage"
    PREVIOUS_GEN_SAGEMAKER_INSTANCE = "previous_gen_sagemaker_instance"
    
    # WorkSpaces Waste Types
    IDLE_WORKSPACE = "idle_workspace"
    OVERSIZED_WORKSPACE = "oversized_workspace"
    WORKSPACES_AUTOSTOP_OPPORTUNITY = "workspaces_autostop_opportunity"
    WORKSPACES_POOL_OVERPROVISIONED_CAPACITY = "workspaces_pool_overprovisioned_capacity"
    WORKSPACES_WINDOWS_LICENSE_OPTIMIZATION = "workspaces_windows_license_optimization"
    
    # CloudFront Waste Types
    UNUSED_DISTRIBUTION = "unused_distribution"
    
    # Route 53 Waste Types
    UNUSED_HOSTED_ZONE = "unused_hosted_zone"
    ORPHANED_DNS_RECORD = "orphaned_dns_record"
    
    # Kinesis Waste Types
    IDLE_KINESIS_STREAM = "idle_kinesis_stream"
    OVER_PROVISIONED_KINESIS = "over_provisioned_kinesis"
    KINESIS_ON_DEMAND_DOWNGRADE = "kinesis_on_demand_downgrade"
    KINESIS_EXTENDED_RETENTION_WASTE = "kinesis_extended_retention_waste"
    KINESIS_ENHANCED_FAN_OUT_WASTE = "kinesis_enhanced_fan_out_waste"
    KINESIS_FIREHOSE_IDLE = "kinesis_firehose_idle"
    
    # MSK Waste Types
    IDLE_MSK_CLUSTER = "idle_msk_cluster"
    OVERSIZED_MSK_CLUSTER = "oversized_msk_cluster"
    
    # Amazon MQ Waste Types
    IDLE_MQ_BROKER = "idle_mq_broker"
    OVERSIZED_MQ_BROKER = "oversized_mq_broker"
    
    # EFS Waste Types
    IDLE_EFS = "idle_efs"
    NO_LIFECYCLE_EFS = "no_lifecycle_efs"
    
    # FSx Waste Types
    IDLE_FSX = "idle_fsx"
    OVERSIZED_FSX = "oversized_fsx"
    FSX_THROUGHPUT_OVERPROVISIONED = "fsx_throughput_overprovisioned"
    OLD_FSX_BACKUP = "old_fsx_backup"
    
    # API Gateway Waste Types
    UNUSED_API_GATEWAY = "unused_api_gateway"
    
    # AppSync Waste Types
    UNUSED_APPSYNC = "unused_appsync"
    APPSYNC_IDLE_CACHE = "appsync_idle_cache"
    APPSYNC_IDLE_SUBSCRIPTIONS = "appsync_idle_subscriptions"
    
    # ECR Waste Types
    OLD_ECR_IMAGES = "old_ecr_images"
    UNTAGGED_ECR_IMAGES = "untagged_ecr_images"
    ECR_NO_LIFECYCLE_POLICY = "ecr_no_lifecycle_policy"
    
    # Glue Waste Types
    IDLE_GLUE_DEV_ENDPOINT = "idle_glue_dev_endpoint"  # DEPRECATED (CLO-462): Not actively detected
    OLD_GLUE_JOB = "old_glue_job"
    IDLE_GLUE_CRAWLER = "idle_glue_crawler"
    OVERSIZED_GLUE_JOB = "oversized_glue_job"
    GLUE_JOB_MISSING_TIMEOUT = "glue_job_missing_timeout"
    FAILED_GLUE_JOB_RETRY = "failed_glue_job_retry"
    GLUE_DEV_ENDPOINT_MIGRATION = "glue_dev_endpoint_migration"  # DEPRECATED (CLO-462): Not actively detected
    GLUE_CATALOG_BLOAT = "glue_catalog_bloat"
    
    # Step Functions Waste Types
    IDLE_STATE_MACHINE = "idle_state_machine"
    STEP_FUNCTIONS_RETRY_STORM = "step_functions_retry_storm"
    STEP_FUNCTIONS_HIGH_TRANSITION_DENSITY = "step_functions_high_transition_density"
    STEP_FUNCTIONS_EXPRESS_DURATION_WASTE = "step_functions_express_duration_waste"
    
    # AWS Backup Waste Types
    OLD_BACKUP = "old_backup"
    REDUNDANT_BACKUP = "redundant_backup"
    BACKUP_NO_LIFECYCLE_TIERING = "backup_no_lifecycle_tiering"
    STALE_BACKUP_PLAN_ASSIGNMENT = "stale_backup_plan_assignment"
    BACKUP_COPY_POLICY_OVERREACH = "backup_copy_policy_overreach"
    
    # Neptune Waste Types
    IDLE_NEPTUNE = "idle_neptune"
    NEPTUNE_SERVERLESS_OPPORTUNITY = "neptune_serverless_opportunity"
    OVERSIZED_NEPTUNE = "oversized_neptune"
    NEPTUNE_OLD_SNAPSHOT = "neptune_old_snapshot"
    
    # DocumentDB Waste Types
    IDLE_DOCUMENTDB = "idle_documentdb"
    OLD_DOCUMENTDB_SNAPSHOT = "old_documentdb_snapshot"
    OVERPROVISIONED_DOCUMENTDB = "overprovisioned_documentdb"
    
    # Timestream Waste Types
    IDLE_TIMESTREAM = "idle_timestream"  # DEPRECATED: Not actively detected

    # QLDB Waste Types
    IDLE_QLDB = "idle_qldb"  # DEPRECATED: Not actively detected
    
    # Elastic Beanstalk Waste Types
    IDLE_BEANSTALK = "idle_beanstalk"
    BEANSTALK_IDLE_TRAFFIC = "beanstalk_idle_traffic"
    BEANSTALK_UNNECESSARY_ALB = "beanstalk_unnecessary_alb"
    BEANSTALK_PREVIOUS_GEN_INSTANCES = "beanstalk_previous_gen_instances"
    BEANSTALK_OVER_PROVISIONED = "beanstalk_over_provisioned"
    BEANSTALK_ORPHANED_RDS = "beanstalk_orphaned_rds"
    
    # Lightsail Waste Types
    IDLE_LIGHTSAIL = "idle_lightsail"
    LIGHTSAIL_UNATTACHED_STATIC_IP = "lightsail_unattached_static_ip"
    LIGHTSAIL_UNATTACHED_DISK = "lightsail_unattached_disk"
    LIGHTSAIL_OLD_SNAPSHOT = "lightsail_old_snapshot"
    LIGHTSAIL_IDLE_LOAD_BALANCER = "lightsail_idle_load_balancer"
    LIGHTSAIL_IDLE_DATABASE = "lightsail_idle_database"
    
    # Global Accelerator Waste Types
    UNUSED_ACCELERATOR = "unused_accelerator"
    IDLE_GLOBAL_ACCELERATOR = "idle_global_accelerator"
    DISABLED_GLOBAL_ACCELERATOR = "disabled_global_accelerator"
    
    # Transfer Family Waste Types
    IDLE_TRANSFER_SERVER = "idle_transfer_server"
    IDLE_TRANSFER_NO_ACTIVITY = "idle_transfer_no_activity"
    UNUSED_TRANSFER_PROTOCOL = "unused_transfer_protocol"
    IDLE_TRANSFER_WEB_APP = "idle_transfer_web_app"
    
    # AWS Compute Optimizer Recommendations (ML-backed rightsizing)
    OVERSIZED_EC2_OPTIMIZER = "oversized_ec2_optimizer"
    OVERSIZED_RDS_OPTIMIZER = "oversized_rds_optimizer"
    OVERSIZED_LAMBDA_OPTIMIZER = "oversized_lambda_optimizer"
    OVERSIZED_EBS_OPTIMIZER = "oversized_ebs_optimizer"
    
    # Reserved Instance / Savings Plans Opportunities
    RI_OPPORTUNITY_EC2 = "ri_opportunity_ec2"
    RI_OPPORTUNITY_RDS = "ri_opportunity_rds"
    RI_OPPORTUNITY_ELASTICACHE = "ri_opportunity_elasticache"
    RI_OPPORTUNITY_OPENSEARCH = "ri_opportunity_opensearch"
    RI_OPPORTUNITY_REDSHIFT = "ri_opportunity_redshift"
    SP_OPPORTUNITY_COMPUTE = "sp_opportunity_compute"
    SP_OPPORTUNITY_EC2 = "sp_opportunity_ec2"
    SP_OPPORTUNITY_SAGEMAKER = "sp_opportunity_sagemaker"
    
    # Commitment Risk — Utilization, Expiry, Exchange, Coverage, CUR
    UNUSED_RESERVED_INSTANCE = "unused_reserved_instance"
    UNUSED_SAVINGS_PLAN = "unused_savings_plan"
    EXPIRING_RESERVED_INSTANCE = "expiring_reserved_instance"
    EXPIRING_SAVINGS_PLAN = "expiring_savings_plan"
    CONVERTIBLE_RI_EXCHANGE_OPPORTUNITY = "convertible_ri_exchange_opportunity"
    SAVINGS_PLAN_COVERAGE_GAP = "savings_plan_coverage_gap"
    CUR_UNUSED_RESERVATION = "cur_unused_reservation"
    CUR_SAVINGS_PLAN_WASTE = "cur_savings_plan_waste"
    
    # IPv4 Address Optimization
    EIP_ON_STOPPED_INSTANCE = "eip_on_stopped_instance"
    MULTIPLE_EIPS_PER_INSTANCE = "multiple_eips_per_instance"
    
    # CloudTrail Waste
    DUPLICATE_CLOUDTRAIL = "duplicate_cloudtrail"
    CLOUDTRAIL_S3_NO_LIFECYCLE = "cloudtrail_s3_no_lifecycle"
    
    # Security Posture — Encryption
    UNENCRYPTED_EBS_VOLUME = "unencrypted_ebs_volume"
    UNENCRYPTED_RDS_INSTANCE = "unencrypted_rds_instance"
    UNENCRYPTED_EFS_FILESYSTEM = "unencrypted_efs_filesystem"
    OPENSEARCH_NO_ENCRYPTION_AT_REST = "opensearch_no_encryption_at_rest"
    UNENCRYPTED_DOCUMENTDB_CLUSTER = "unencrypted_documentdb_cluster"
    S3_NO_DEFAULT_ENCRYPTION = "s3_no_default_encryption"
    
    # Security Posture — Deletion Protection
    RDS_NO_DELETION_PROTECTION = "rds_no_deletion_protection"
    DYNAMODB_NO_DELETION_PROTECTION = "dynamodb_no_deletion_protection"
    
    # Security Posture — Public Access
    RDS_PUBLICLY_ACCESSIBLE = "rds_publicly_accessible"
    
    # Security Posture — Backup Coverage
    RESOURCE_WITHOUT_BACKUP_COVERAGE = "resource_without_backup_coverage"
    
    # Generic
    OTHER = "other"


# Waste types that represent governance or advisory findings with no direct
# dollar-cost savings.  These bypass the min_waste_threshold_usd filter so
# they are always reported regardless of threshold settings.
GOVERNANCE_WASTE_TYPES: frozenset = frozenset({
    WasteType.S3_EMPTY_BUCKET,
    WasteType.S3_HIGH_REQUEST_AND_TRANSFER_COST,
    WasteType.BACKUP_NO_LIFECYCLE_TIERING,
    WasteType.STALE_BACKUP_PLAN_ASSIGNMENT,
    WasteType.OVERPROVISIONED_DOCUMENTDB,
    WasteType.STEP_FUNCTIONS_RETRY_STORM,
    WasteType.STEP_FUNCTIONS_HIGH_TRANSITION_DENSITY,
    WasteType.STEP_FUNCTIONS_EXPRESS_DURATION_WASTE,
    WasteType.EMPTY_LOG_GROUP,
    # Security posture — advisory findings with no direct savings
    WasteType.UNENCRYPTED_EBS_VOLUME,
    WasteType.UNENCRYPTED_RDS_INSTANCE,
    WasteType.UNENCRYPTED_EFS_FILESYSTEM,
    WasteType.OPENSEARCH_NO_ENCRYPTION_AT_REST,
    WasteType.UNENCRYPTED_DOCUMENTDB_CLUSTER,
    WasteType.S3_NO_DEFAULT_ENCRYPTION,
    WasteType.RDS_NO_DELETION_PROTECTION,
    WasteType.DYNAMODB_NO_DELETION_PROTECTION,
    WasteType.RDS_PUBLICLY_ACCESSIBLE,
    WasteType.RESOURCE_WITHOUT_BACKUP_COVERAGE,
    # Kinesis Firehose — housekeeping (pay-per-GB, $0 idle cost)
    WasteType.KINESIS_FIREHOSE_IDLE,
    # Dangling DNS records — $0 savings but a subdomain-takeover risk
    WasteType.ORPHANED_DNS_RECORD,
    # CLO-507: an ECS service with no running task bills nothing for it;
    # reported at $0 as a broken/abandoned service.
    WasteType.IDLE_ECS_SERVICE,
    # CLO-513/514: findings whose saving is unmeasured or counted on another
    # finding, so they report $0 rather than a guessed figure.
    WasteType.INCOMPLETE_MULTIPART,         # part sizes need ListMultipartUploadParts
    WasteType.NO_LIFECYCLE_POLICY,          # $0 when s3_wrong_storage_class counts it
    WasteType.ECR_NO_LIFECYCLE_POLICY,      # $0 when old/untagged images count it
    # CLO-993: the KMS request saving depends on the bucket's request volume,
    # which no scan reads, so the finding reports $0 rather than a guessed figure.
    WasteType.S3_KMS_BUCKET_KEY_DISABLED,
    WasteType.BACKUP_COPY_POLICY_OVERREACH, # which copies are unneeded is a DR call
    # CLO-771: planning alerts. CLO-505 set their saving to $0 on purpose, since
    # acting on them costs money or leaves the commitment unchanged.
    WasteType.EXPIRING_RESERVED_INSTANCE,
    WasteType.EXPIRING_SAVINGS_PLAN,
    WasteType.CONVERTIBLE_RI_EXCHANGE_OPPORTUNITY,
    # CLO-962: a stuck-invocation exposure is not a recurring saving, so the
    # finding reports $0 (the exposure sits in metadata) and is still shown.
    WasteType.LAMBDA_EXCESSIVE_TIMEOUT,
})

# Membership buys VISIBILITY only, never a savings figure (CLO-448). The floor
# in ``WasteDetectionService._reconcile_and_collect`` runs after CLO-234
# reconciliation, so a governance finding on a resource AWS bills $0 for
# persists with ``monthly_savings == 0.0`` and ``confirmed_zero_billed`` — its
# detector's list price stays on ``estimated_savings_list_price``. Restoring the
# list price would break AGENTS.md §7 "no saving exceeds billed cost". Do not
# add a type here to force a $0 finding to persist: that changes what customers
# see for the wrong reason (CLO-432 owns advisory persistence).
#
# CLO-513/514 added four types for the right reason: their DETECTOR emits $0
# by design, as s3_empty_bucket does, instead of a guessed figure. Without
# membership the floor would drop every one of them, so removing a fabricated
# number would silently remove the finding too.
#   - incomplete_multipart: part sizes need s3:ListMultipartUploadParts,
#     which the scan role lacks; the saving is not measured.
#   - backup_copy_policy_overreach: which copies are unneeded is a DR
#     decision CloudWise cannot see; the cost at stake is in the explanation.
#   - no_lifecycle_policy / ecr_no_lifecycle_policy: $0 only when another
#     finding on the same bucket/repository (s3_wrong_storage_class,
#     old/untagged_ecr_images) already carries those dollars, so they are
#     counted once. Otherwise they carry a real estimate. Side effect: one
#     that reconciliation pulls below the floor now persists at $0 instead of
#     dropping.
#
# CLO-771 added the three commitment alerts for the same reason: CLO-505 made
# their detector emit $0 by design, and the floor then removed every one.


# RI/SP purchase recommendations and existing-commitment findings (CLO-376).
#
# ``resource_id`` on every one of these is either a label the detector
# invented for display (an instance type, "Savings Plan", "Savings Plan
# Coverage") or an RI/SP entity id that AWS's CUR does not bill line items
# against (``lineItem/ResourceId`` is blank on RIFee/SavingsPlan*Fee rows —
# see ``lambdas/shared_modules/cur_processing.py``). Feeding either shape
# through ``billed_cost.reconcile_savings``'s per-resource CUR match always
# misses, and on an account with resource-level CUR the miss reads as "AWS
# bills $0 for this" — silently zeroing and dropping every commitment
# recommendation. These types are routed to
# ``billed_cost.reconcile_commitment_savings`` instead, which caps against
# the detector's own aggregate covering spend rather than a resource match.
COMMITMENT_WASTE_TYPES: frozenset = frozenset({
    # Purchase recommendations (detectors/savings.py) — resource_id is an
    # instance type/class or "<X> Savings Plan" label; no resource exists yet.
    WasteType.RI_OPPORTUNITY_EC2,
    WasteType.RI_OPPORTUNITY_RDS,
    WasteType.RI_OPPORTUNITY_ELASTICACHE,
    WasteType.RI_OPPORTUNITY_OPENSEARCH,
    WasteType.RI_OPPORTUNITY_REDSHIFT,
    WasteType.SP_OPPORTUNITY_COMPUTE,
    WasteType.SP_OPPORTUNITY_EC2,
    WasteType.SP_OPPORTUNITY_SAGEMAKER,
    # Existing-commitment risk (detectors/commitment.py) — resource_id is an
    # instance type/RI id/SP id/plan label, not a CUR-billed resource.
    WasteType.UNUSED_RESERVED_INSTANCE,
    WasteType.UNUSED_SAVINGS_PLAN,
    WasteType.EXPIRING_RESERVED_INSTANCE,
    WasteType.EXPIRING_SAVINGS_PLAN,
    WasteType.CONVERTIBLE_RI_EXCHANGE_OPPORTUNITY,
    WasteType.SAVINGS_PLAN_COVERAGE_GAP,
    WasteType.CUR_UNUSED_RESERVATION,
    WasteType.CUR_SAVINGS_PLAN_WASTE,
})


class ResourceType(str, Enum):
    """AWS resource types."""
    EC2_INSTANCE = "ec2_instance"
    EBS_VOLUME = "ebs_volume"
    EBS_SNAPSHOT = "ebs_snapshot"
    RDS_INSTANCE = "rds_instance"
    RDS_SNAPSHOT = "rds_snapshot"
    ELASTIC_IP = "elastic_ip"
    NAT_GATEWAY = "nat_gateway"
    LOAD_BALANCER = "load_balancer"
    VPC_ENDPOINT = "vpc_endpoint"
    LAMBDA_FUNCTION = "lambda_function"
    S3_BUCKET = "s3_bucket"
    DYNAMODB_TABLE = "dynamodb_table"
    ELASTICACHE_CLUSTER = "elasticache_cluster"
    REDSHIFT_CLUSTER = "redshift_cluster"
    OPENSEARCH_DOMAIN = "opensearch_domain"
    ECS_SERVICE = "ecs_service"
    ECS_TASK = "ecs_task"
    CLOUDWATCH_DASHBOARD = "cloudwatch_dashboard"
    CLOUDWATCH_LOG_GROUP = "cloudwatch_log_group"
    SECRETS_MANAGER_SECRET = "secrets_manager_secret"
    KMS_KEY = "kms_key"
    # New resource types
    EMR_CLUSTER = "emr_cluster"
    SAGEMAKER_NOTEBOOK = "sagemaker_notebook"
    SAGEMAKER_ENDPOINT = "sagemaker_endpoint"
    WORKSPACE = "workspace"
    CLOUDFRONT_DISTRIBUTION = "cloudfront_distribution"
    ROUTE53_HOSTED_ZONE = "route53_hosted_zone"
    KINESIS_STREAM = "kinesis_stream"
    KINESIS_CONSUMER = "kinesis_consumer"
    KINESIS_FIREHOSE = "kinesis_firehose"
    MSK_CLUSTER = "msk_cluster"
    MQ_BROKER = "mq_broker"
    EFS_FILESYSTEM = "efs_filesystem"
    FSX_FILESYSTEM = "fsx_filesystem"
    API_GATEWAY = "api_gateway"
    APPSYNC_API = "appsync_api"
    ECR_REPOSITORY = "ecr_repository"
    GLUE_DEV_ENDPOINT = "glue_dev_endpoint"
    GLUE_JOB = "glue_job"
    GLUE_CRAWLER = "glue_crawler"
    GLUE_CATALOG = "glue_catalog"
    STEP_FUNCTION = "step_function"
    BACKUP_VAULT = "backup_vault"
    BACKUP_RECOVERY_POINT = "backup_recovery_point"
    BACKUP_PLAN = "backup_plan"
    BACKUP_SELECTION = "backup_selection"
    NEPTUNE_CLUSTER = "neptune_cluster"
    DOCUMENTDB_CLUSTER = "documentdb_cluster"
    DOCUMENTDB_SNAPSHOT = "documentdb_snapshot"
    FSX_BACKUP = "fsx_backup"
    TIMESTREAM_DATABASE = "timestream_database"
    QLDB_LEDGER = "qldb_ledger"
    BEANSTALK_ENVIRONMENT = "beanstalk_environment"
    LIGHTSAIL_INSTANCE = "lightsail_instance"
    LIGHTSAIL_STATIC_IP = "lightsail_static_ip"
    LIGHTSAIL_DISK = "lightsail_disk"
    LIGHTSAIL_SNAPSHOT = "lightsail_snapshot"
    LIGHTSAIL_LOAD_BALANCER = "lightsail_load_balancer"
    LIGHTSAIL_DATABASE = "lightsail_database"
    GLOBAL_ACCELERATOR = "global_accelerator"
    TRANSFER_SERVER = "transfer_server"
    TRANSFER_WEB_APP = "transfer_web_app"
    # Compute Optimizer / Savings recommendations
    COMPUTE_OPTIMIZER_RECOMMENDATION = "compute_optimizer_recommendation"
    RI_RECOMMENDATION = "ri_recommendation"
    SAVINGS_PLAN_RECOMMENDATION = "savings_plan_recommendation"
    CLOUDTRAIL = "cloudtrail"
    OTHER = "other"


class ConfidenceLevel(str, Enum):
    """Confidence level of the waste detection."""
    HIGH = "high"      # CloudWatch metrics confirm waste
    MEDIUM = "medium"  # Strong indicators but no metrics
    LOW = "low"        # Heuristic-based detection


class ServiceCategory(str, Enum):
    """
    Service categories for grouping waste detection findings.
    
    These align with the AWS Service Classifier categories used elsewhere
    in CloudWise for consistent categorization across the platform.
    """
    COMPUTE = "Compute Optimization"
    STORAGE = "Storage Optimization"
    DATABASE = "Database Optimization"
    NETWORK = "Network Optimization"
    ANALYTICS = "Analytics Optimization"
    ML_AI = "ML/AI Optimization"
    MANAGEMENT = "Management & Operations"
    SECURITY = "Security & Compliance"
    SERVERLESS = "Serverless Optimization"
    CONTAINERS = "Container Optimization"
    OTHER = "General Optimization"


# Mapping from WasteType to ServiceCategory for categorizing waste findings
WASTE_TYPE_TO_CATEGORY: Dict[str, ServiceCategory] = {
    # Compute Optimization
    WasteType.IDLE_EC2.value: ServiceCategory.COMPUTE,
    WasteType.OVERSIZED_EC2.value: ServiceCategory.COMPUTE,
    WasteType.PREVIOUS_GEN_EC2.value: ServiceCategory.COMPUTE,
    WasteType.STOPPED_EC2_WITH_EBS.value: ServiceCategory.COMPUTE,
    WasteType.IDLE_WORKSPACE.value: ServiceCategory.COMPUTE,
    WasteType.OVERSIZED_WORKSPACE.value: ServiceCategory.COMPUTE,
    WasteType.WORKSPACES_AUTOSTOP_OPPORTUNITY.value: ServiceCategory.COMPUTE,
    WasteType.WORKSPACES_POOL_OVERPROVISIONED_CAPACITY.value: ServiceCategory.COMPUTE,
    WasteType.WORKSPACES_WINDOWS_LICENSE_OPTIMIZATION.value: ServiceCategory.COMPUTE,
    WasteType.IDLE_LIGHTSAIL.value: ServiceCategory.COMPUTE,
    WasteType.LIGHTSAIL_UNATTACHED_STATIC_IP.value: ServiceCategory.COMPUTE,
    WasteType.LIGHTSAIL_UNATTACHED_DISK.value: ServiceCategory.COMPUTE,
    WasteType.LIGHTSAIL_OLD_SNAPSHOT.value: ServiceCategory.COMPUTE,
    WasteType.LIGHTSAIL_IDLE_LOAD_BALANCER.value: ServiceCategory.COMPUTE,
    WasteType.LIGHTSAIL_IDLE_DATABASE.value: ServiceCategory.COMPUTE,
    WasteType.IDLE_BEANSTALK.value: ServiceCategory.COMPUTE,
    WasteType.BEANSTALK_IDLE_TRAFFIC.value: ServiceCategory.COMPUTE,
    WasteType.BEANSTALK_UNNECESSARY_ALB.value: ServiceCategory.COMPUTE,
    WasteType.BEANSTALK_PREVIOUS_GEN_INSTANCES.value: ServiceCategory.COMPUTE,
    WasteType.BEANSTALK_OVER_PROVISIONED.value: ServiceCategory.COMPUTE,
    WasteType.BEANSTALK_ORPHANED_RDS.value: ServiceCategory.COMPUTE,
    
    # Storage Optimization
    WasteType.UNATTACHED_EBS.value: ServiceCategory.STORAGE,
    WasteType.OLD_EBS_SNAPSHOT.value: ServiceCategory.STORAGE,
    WasteType.ORPHANED_EBS_SNAPSHOT.value: ServiceCategory.STORAGE,
    WasteType.AMI_ORPHANED_SNAPSHOT.value: ServiceCategory.STORAGE,
    WasteType.GP2_MIGRATION.value: ServiceCategory.STORAGE,
    WasteType.OVER_PROVISIONED_IOPS.value: ServiceCategory.STORAGE,
    WasteType.NO_LIFECYCLE_POLICY.value: ServiceCategory.STORAGE,
    WasteType.INCOMPLETE_MULTIPART.value: ServiceCategory.STORAGE,
    WasteType.S3_RAPID_GROWTH.value: ServiceCategory.STORAGE,
    WasteType.S3_WRONG_STORAGE_CLASS.value: ServiceCategory.STORAGE,
    WasteType.S3_EMPTY_BUCKET.value: ServiceCategory.STORAGE,
    WasteType.S3_HIGH_REQUEST_AND_TRANSFER_COST.value: ServiceCategory.STORAGE,
    WasteType.S3_KMS_BUCKET_KEY_DISABLED.value: ServiceCategory.STORAGE,
    WasteType.IDLE_EFS.value: ServiceCategory.STORAGE,
    WasteType.NO_LIFECYCLE_EFS.value: ServiceCategory.STORAGE,
    WasteType.IDLE_FSX.value: ServiceCategory.STORAGE,
    WasteType.OVERSIZED_FSX.value: ServiceCategory.STORAGE,
    WasteType.FSX_THROUGHPUT_OVERPROVISIONED.value: ServiceCategory.STORAGE,
    WasteType.OLD_FSX_BACKUP.value: ServiceCategory.STORAGE,
    WasteType.OLD_BACKUP.value: ServiceCategory.STORAGE,
    WasteType.REDUNDANT_BACKUP.value: ServiceCategory.STORAGE,
    WasteType.BACKUP_NO_LIFECYCLE_TIERING.value: ServiceCategory.STORAGE,
    WasteType.STALE_BACKUP_PLAN_ASSIGNMENT.value: ServiceCategory.STORAGE,
    WasteType.BACKUP_COPY_POLICY_OVERREACH.value: ServiceCategory.STORAGE,
    WasteType.OLD_ECR_IMAGES.value: ServiceCategory.STORAGE,
    WasteType.UNTAGGED_ECR_IMAGES.value: ServiceCategory.STORAGE,
    
    # Database Optimization
    WasteType.IDLE_RDS.value: ServiceCategory.DATABASE,
    WasteType.OVERSIZED_RDS.value: ServiceCategory.DATABASE,
    WasteType.MULTIAZ_NONPROD.value: ServiceCategory.DATABASE,
    WasteType.OLD_RDS_SNAPSHOT.value: ServiceCategory.DATABASE,
    WasteType.IDLE_DYNAMODB.value: ServiceCategory.DATABASE,
    WasteType.OVER_PROVISIONED_DYNAMODB.value: ServiceCategory.DATABASE,
    WasteType.IDLE_ELASTICACHE.value: ServiceCategory.DATABASE,
    WasteType.OVERSIZED_ELASTICACHE.value: ServiceCategory.DATABASE,
    WasteType.ELASTICACHE_REPLICATION_WASTE.value: ServiceCategory.DATABASE,
    WasteType.ELASTICACHE_ENGINE_MIGRATION.value: ServiceCategory.DATABASE,
    WasteType.ELASTICACHE_SERVERLESS_OPTIMIZATION.value: ServiceCategory.DATABASE,
    WasteType.ELASTICACHE_DATA_TIERING_OPPORTUNITY.value: ServiceCategory.DATABASE,
    WasteType.IDLE_REDSHIFT.value: ServiceCategory.DATABASE,
    WasteType.OVERSIZED_REDSHIFT.value: ServiceCategory.DATABASE,
    WasteType.UNDERUTILIZED_REDSHIFT.value: ServiceCategory.DATABASE,
    WasteType.REDSHIFT_NO_PAUSE.value: ServiceCategory.DATABASE,
    WasteType.REDSHIFT_SPECTRUM_HEAVY.value: ServiceCategory.DATABASE,
    WasteType.REDSHIFT_LEGACY_DC2.value: ServiceCategory.DATABASE,
    WasteType.REDSHIFT_WLM_OVER_PROVISIONED.value: ServiceCategory.DATABASE,
    WasteType.REDSHIFT_CONCURRENCY_SCALING_WASTE.value: ServiceCategory.DATABASE,
    WasteType.IDLE_OPENSEARCH.value: ServiceCategory.DATABASE,
    WasteType.OVERSIZED_OPENSEARCH.value: ServiceCategory.DATABASE,
    WasteType.OPENSEARCH_EBS_OVERPROVISIONED.value: ServiceCategory.DATABASE,
    WasteType.IDLE_NEPTUNE.value: ServiceCategory.DATABASE,
    WasteType.NEPTUNE_SERVERLESS_OPPORTUNITY.value: ServiceCategory.DATABASE,
    WasteType.OVERSIZED_NEPTUNE.value: ServiceCategory.DATABASE,
    WasteType.NEPTUNE_OLD_SNAPSHOT.value: ServiceCategory.DATABASE,
    WasteType.IDLE_DOCUMENTDB.value: ServiceCategory.DATABASE,
    WasteType.OLD_DOCUMENTDB_SNAPSHOT.value: ServiceCategory.DATABASE,
    WasteType.OVERPROVISIONED_DOCUMENTDB.value: ServiceCategory.DATABASE,
    WasteType.IDLE_TIMESTREAM.value: ServiceCategory.DATABASE,
    WasteType.IDLE_QLDB.value: ServiceCategory.DATABASE,
    WasteType.AURORA_IO_OPTIMIZATION_OPPORTUNITY.value: ServiceCategory.DATABASE,
    WasteType.AURORA_EXTENDED_SUPPORT_COST.value: ServiceCategory.DATABASE,
    WasteType.AURORA_SERVERLESS_OPPORTUNITY.value: ServiceCategory.DATABASE,
    WasteType.AURORA_TO_RDS_DOWNGRADE_OPPORTUNITY.value: ServiceCategory.DATABASE,
    WasteType.RDS_EXTENDED_SUPPORT_COST.value: ServiceCategory.DATABASE,
    WasteType.ELASTICACHE_EXTENDED_SUPPORT_COST.value: ServiceCategory.DATABASE,
    WasteType.OPENSEARCH_EXTENDED_SUPPORT_COST.value: ServiceCategory.DATABASE,
    WasteType.DOCUMENTDB_EXTENDED_SUPPORT_COST.value: ServiceCategory.DATABASE,
    
    # Network Optimization
    WasteType.UNATTACHED_EIP.value: ServiceCategory.NETWORK,
    WasteType.IDLE_NAT_GATEWAY.value: ServiceCategory.NETWORK,
    WasteType.IDLE_LOAD_BALANCER.value: ServiceCategory.NETWORK,
    WasteType.LOW_TRAFFIC_ALB.value: ServiceCategory.NETWORK,
    WasteType.HIGH_LCU_COST_ALB.value: ServiceCategory.NETWORK,
    WasteType.CLASSIC_LB_MIGRATION.value: ServiceCategory.NETWORK,
    WasteType.UNUSED_VPC_ENDPOINT.value: ServiceCategory.NETWORK,
    WasteType.UNUSED_DISTRIBUTION.value: ServiceCategory.NETWORK,
    WasteType.UNUSED_HOSTED_ZONE.value: ServiceCategory.NETWORK,
    WasteType.ORPHANED_DNS_RECORD.value: ServiceCategory.NETWORK,
    WasteType.UNUSED_ACCELERATOR.value: ServiceCategory.NETWORK,
    WasteType.IDLE_GLOBAL_ACCELERATOR.value: ServiceCategory.NETWORK,
    WasteType.DISABLED_GLOBAL_ACCELERATOR.value: ServiceCategory.NETWORK,
    WasteType.IDLE_TRANSFER_SERVER.value: ServiceCategory.NETWORK,
    WasteType.IDLE_TRANSFER_NO_ACTIVITY.value: ServiceCategory.NETWORK,
    WasteType.UNUSED_TRANSFER_PROTOCOL.value: ServiceCategory.NETWORK,
    WasteType.IDLE_TRANSFER_WEB_APP.value: ServiceCategory.NETWORK,
    
    # Serverless Optimization
    WasteType.UNUSED_LAMBDA.value: ServiceCategory.SERVERLESS,
    WasteType.OVER_PROVISIONED_LAMBDA.value: ServiceCategory.SERVERLESS,
    WasteType.LAMBDA_OLD_RUNTIME.value: ServiceCategory.SERVERLESS,
    WasteType.UNUSED_API_GATEWAY.value: ServiceCategory.SERVERLESS,
    WasteType.UNUSED_APPSYNC.value: ServiceCategory.SERVERLESS,
    WasteType.APPSYNC_IDLE_CACHE.value: ServiceCategory.SERVERLESS,
    WasteType.APPSYNC_IDLE_SUBSCRIPTIONS.value: ServiceCategory.SERVERLESS,
    WasteType.IDLE_STATE_MACHINE.value: ServiceCategory.SERVERLESS,
    WasteType.STEP_FUNCTIONS_RETRY_STORM.value: ServiceCategory.SERVERLESS,
    WasteType.STEP_FUNCTIONS_HIGH_TRANSITION_DENSITY.value: ServiceCategory.SERVERLESS,
    WasteType.STEP_FUNCTIONS_EXPRESS_DURATION_WASTE.value: ServiceCategory.SERVERLESS,
    
    # Compute Optimization — Lambda
    WasteType.LAMBDA_PROVISIONED_CONCURRENCY_IDLE.value: ServiceCategory.COMPUTE,
    WasteType.LAMBDA_EXCESSIVE_TIMEOUT.value: ServiceCategory.COMPUTE,
    WasteType.LAMBDA_ARM64_MIGRATION.value: ServiceCategory.COMPUTE,
    WasteType.EKS_EXTENDED_SUPPORT_COST.value: ServiceCategory.COMPUTE,
    
    # Container Optimization
    WasteType.OVERSIZED_ECS_TASK.value: ServiceCategory.CONTAINERS,
    WasteType.IDLE_ECS_SERVICE.value: ServiceCategory.CONTAINERS,
    WasteType.ECS_NO_AUTOSCALING.value: ServiceCategory.CONTAINERS,
    WasteType.ECS_CONTAINER_INSIGHTS_WASTE.value: ServiceCategory.CONTAINERS,
    WasteType.OVERSIZED_ECS_MEMORY.value: ServiceCategory.CONTAINERS,
    
    # Analytics Optimization
    WasteType.IDLE_KINESIS_STREAM.value: ServiceCategory.ANALYTICS,
    WasteType.OVER_PROVISIONED_KINESIS.value: ServiceCategory.ANALYTICS,
    WasteType.KINESIS_ON_DEMAND_DOWNGRADE.value: ServiceCategory.ANALYTICS,
    WasteType.KINESIS_EXTENDED_RETENTION_WASTE.value: ServiceCategory.ANALYTICS,
    WasteType.KINESIS_ENHANCED_FAN_OUT_WASTE.value: ServiceCategory.ANALYTICS,
    WasteType.KINESIS_FIREHOSE_IDLE.value: ServiceCategory.ANALYTICS,
    WasteType.IDLE_MSK_CLUSTER.value: ServiceCategory.ANALYTICS,
    WasteType.OVERSIZED_MSK_CLUSTER.value: ServiceCategory.ANALYTICS,
    WasteType.IDLE_GLUE_DEV_ENDPOINT.value: ServiceCategory.ANALYTICS,
    WasteType.OLD_GLUE_JOB.value: ServiceCategory.ANALYTICS,
    WasteType.IDLE_GLUE_CRAWLER.value: ServiceCategory.ANALYTICS,
    WasteType.OVERSIZED_GLUE_JOB.value: ServiceCategory.ANALYTICS,
    WasteType.GLUE_JOB_MISSING_TIMEOUT.value: ServiceCategory.ANALYTICS,
    WasteType.FAILED_GLUE_JOB_RETRY.value: ServiceCategory.ANALYTICS,
    WasteType.GLUE_DEV_ENDPOINT_MIGRATION.value: ServiceCategory.ANALYTICS,
    WasteType.GLUE_CATALOG_BLOAT.value: ServiceCategory.ANALYTICS,
    WasteType.IDLE_EMR_CLUSTER.value: ServiceCategory.ANALYTICS,
    WasteType.LONG_RUNNING_EMR.value: ServiceCategory.ANALYTICS,
    WasteType.EMR_OVER_PROVISIONED.value: ServiceCategory.ANALYTICS,
    WasteType.EMR_MISSING_AUTO_TERMINATION.value: ServiceCategory.ANALYTICS,
    WasteType.EMR_PREVIOUS_GEN_INSTANCES.value: ServiceCategory.ANALYTICS,
    WasteType.EMR_SPOT_OPPORTUNITY.value: ServiceCategory.ANALYTICS,
    WasteType.IDLE_MQ_BROKER.value: ServiceCategory.ANALYTICS,
    WasteType.OVERSIZED_MQ_BROKER.value: ServiceCategory.ANALYTICS,
    
    # ML/AI Optimization
    WasteType.IDLE_SAGEMAKER_NOTEBOOK.value: ServiceCategory.ML_AI,
    WasteType.IDLE_SAGEMAKER_ENDPOINT.value: ServiceCategory.ML_AI,
    WasteType.OVERSIZED_SAGEMAKER_ENDPOINT.value: ServiceCategory.ML_AI,
    WasteType.STOPPED_SAGEMAKER_NOTEBOOK_STORAGE.value: ServiceCategory.ML_AI,
    WasteType.PREVIOUS_GEN_SAGEMAKER_INSTANCE.value: ServiceCategory.ML_AI,
    
    # Management & Operations
    WasteType.UNUSED_DASHBOARD.value: ServiceCategory.MANAGEMENT,
    WasteType.OLD_LOG_GROUP.value: ServiceCategory.MANAGEMENT,
    WasteType.NO_RETENTION_LOG_GROUP.value: ServiceCategory.MANAGEMENT,
    WasteType.EXCESSIVE_RETENTION_LOG_GROUP.value: ServiceCategory.MANAGEMENT,
    WasteType.EMPTY_LOG_GROUP.value: ServiceCategory.MANAGEMENT,
    
    # Security & Compliance
    WasteType.UNUSED_SECRET.value: ServiceCategory.SECURITY,
    WasteType.UNUSED_KMS_KEY.value: ServiceCategory.SECURITY,
    WasteType.UNENCRYPTED_EBS_VOLUME.value: ServiceCategory.SECURITY,
    WasteType.UNENCRYPTED_RDS_INSTANCE.value: ServiceCategory.SECURITY,
    WasteType.UNENCRYPTED_EFS_FILESYSTEM.value: ServiceCategory.SECURITY,
    WasteType.OPENSEARCH_NO_ENCRYPTION_AT_REST.value: ServiceCategory.SECURITY,
    WasteType.UNENCRYPTED_DOCUMENTDB_CLUSTER.value: ServiceCategory.SECURITY,
    WasteType.S3_NO_DEFAULT_ENCRYPTION.value: ServiceCategory.SECURITY,
    WasteType.RDS_NO_DELETION_PROTECTION.value: ServiceCategory.SECURITY,
    WasteType.DYNAMODB_NO_DELETION_PROTECTION.value: ServiceCategory.SECURITY,
    WasteType.RDS_PUBLICLY_ACCESSIBLE.value: ServiceCategory.SECURITY,
    WasteType.RESOURCE_WITHOUT_BACKUP_COVERAGE.value: ServiceCategory.SECURITY,
    
    # Storage - ECR and DynamoDB
    WasteType.ECR_NO_LIFECYCLE_POLICY.value: ServiceCategory.STORAGE,
    
    # Database - DynamoDB Auto-scaling
    WasteType.DYNAMODB_NO_AUTOSCALING.value: ServiceCategory.DATABASE,
    
    # Compute Optimizer Recommendations (ML-backed rightsizing)
    WasteType.OVERSIZED_EC2_OPTIMIZER.value: ServiceCategory.COMPUTE,
    WasteType.OVERSIZED_RDS_OPTIMIZER.value: ServiceCategory.DATABASE,
    WasteType.OVERSIZED_LAMBDA_OPTIMIZER.value: ServiceCategory.SERVERLESS,
    WasteType.OVERSIZED_EBS_OPTIMIZER.value: ServiceCategory.STORAGE,
    
    # Reserved Instance / Savings Plans Opportunities
    WasteType.RI_OPPORTUNITY_EC2.value: ServiceCategory.COMPUTE,
    WasteType.RI_OPPORTUNITY_RDS.value: ServiceCategory.DATABASE,
    WasteType.RI_OPPORTUNITY_ELASTICACHE.value: ServiceCategory.DATABASE,
    WasteType.RI_OPPORTUNITY_OPENSEARCH.value: ServiceCategory.DATABASE,
    WasteType.RI_OPPORTUNITY_REDSHIFT.value: ServiceCategory.DATABASE,
    WasteType.SP_OPPORTUNITY_COMPUTE.value: ServiceCategory.COMPUTE,
    WasteType.SP_OPPORTUNITY_EC2.value: ServiceCategory.COMPUTE,
    WasteType.SP_OPPORTUNITY_SAGEMAKER.value: ServiceCategory.ML_AI,
    
    # Commitment Risk — Utilization, Expiry, Exchange, Coverage, CUR
    WasteType.UNUSED_RESERVED_INSTANCE.value: ServiceCategory.COMPUTE,
    WasteType.UNUSED_SAVINGS_PLAN.value: ServiceCategory.COMPUTE,
    WasteType.EXPIRING_RESERVED_INSTANCE.value: ServiceCategory.COMPUTE,
    WasteType.EXPIRING_SAVINGS_PLAN.value: ServiceCategory.COMPUTE,
    WasteType.CONVERTIBLE_RI_EXCHANGE_OPPORTUNITY.value: ServiceCategory.COMPUTE,
    WasteType.SAVINGS_PLAN_COVERAGE_GAP.value: ServiceCategory.COMPUTE,
    WasteType.CUR_UNUSED_RESERVATION.value: ServiceCategory.COMPUTE,
    WasteType.CUR_SAVINGS_PLAN_WASTE.value: ServiceCategory.COMPUTE,
    
    # IPv4 Address Optimization
    WasteType.EIP_ON_STOPPED_INSTANCE.value: ServiceCategory.NETWORK,
    WasteType.MULTIPLE_EIPS_PER_INSTANCE.value: ServiceCategory.NETWORK,
    
    # CloudTrail Waste
    WasteType.DUPLICATE_CLOUDTRAIL.value: ServiceCategory.MANAGEMENT,
    WasteType.CLOUDTRAIL_S3_NO_LIFECYCLE.value: ServiceCategory.MANAGEMENT,
    
    # Other
    WasteType.OTHER.value: ServiceCategory.OTHER,
}


def get_category_for_waste_type(waste_type: str | WasteType) -> ServiceCategory:
    """
    Get the ServiceCategory for a given waste type.
    
    Args:
        waste_type: The waste type (enum or string value)
        
    Returns:
        ServiceCategory for the waste type, defaults to OTHER if not found
    """
    if isinstance(waste_type, WasteType):
        waste_type = waste_type.value
    return WASTE_TYPE_TO_CATEGORY.get(waste_type, ServiceCategory.OTHER)


@dataclass
class WasteItem:
    """
    Represents a single detected waste item.
    
    This is the core data structure returned by all waste detectors.
    """
    # Identifiers
    id: str                           # Unique identifier (generated)
    resource_id: str                  # AWS resource ID (e.g., i-0abc123)
    resource_type: ResourceType       # Type of AWS resource
    waste_type: WasteType             # Type of waste detected
    
    # Display Information
    title: str                        # Human-readable title
    description: str                  # Detailed description
    
    # Financial Impact
    #
    # CLO-234: ``monthly_savings`` is the RECONCILED figure — capped at what
    # AWS actually billed for this resource where we could check. It is the
    # canonical number every surface sums, so a surface that ignores the
    # reconciliation fields below still reports a safe total. The list-price
    # estimate is preserved separately as evidence, never as the headline.
    monthly_savings: float            # Reconciled monthly savings in USD
    confidence: ConfidenceLevel       # How confident we are in this finding

    # Recommended Actions
    action: str                       # Human-readable recommended action
    action_command: Optional[str] = None  # AWS CLI command (optional)
    ai_action_steps: Optional[List[str]] = None  # AI-generated action steps
    action_steps_generated_at: Optional[datetime] = None  # When AI steps were generated
    
    # Explanation (structured context for engineers to validate findings)
    explanation: Optional[Dict[str, str]] = None

    # Billed-cost reconciliation (CLO-234) — evidence for ``monthly_savings``.
    # Explicit fields rather than ``metadata`` entries so they survive typing,
    # the WasteItem→dict conversion, and DynamoDB persistence.
    #
    # ``reconciliation_status`` is one of ``billed_cost.ReconciliationStatus``.
    # It is None only on items that never went through the reconciliation pass
    # (e.g. constructed directly in a unit test).
    estimated_savings_list_price: Optional[float] = None
    billed_cost_observed: Optional[float] = None
    reconciliation_status: Optional[str] = None
    cost_basis: Optional[str] = None

    # Location
    region: str = ""                  # AWS region (set during scan)
    account_id: str = ""              # AWS account ID
    
    # Categorization
    category: Optional[str] = None    # ServiceCategory (auto-derived from waste_type)
    
    # Timestamps
    detected_at: datetime = field(default_factory=_utc_now)
    
    # Additional Context
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """
        Auto-populate category from waste_type if not provided.
        Also replace random UUID IDs with deterministic IDs based on resource identity.
        """
        # Auto-populate category
        if self.category is None:
            waste_type_value = self.waste_type.value if isinstance(self.waste_type, WasteType) else self.waste_type
            self.category = get_category_for_waste_type(waste_type_value).value
        
        # Replace random UUID IDs with deterministic IDs
        # This ensures the same resource produces the same ID across scans,
        # enabling natural deduplication in DynamoDB (put_item overwrites same SK)
        if self.id and _UUID_PATTERN.match(self.id):
            waste_type_str = self.waste_type.value if isinstance(self.waste_type, WasteType) else self.waste_type
            self.id = generate_deterministic_id(
                resource_id=self.resource_id,
                waste_type=waste_type_str,
                region=self.region,
                account_id=self.account_id
            )
    
    def _get_resource_name(self) -> str:
        """Get the human-friendly resource name from metadata or resource_id."""
        if self.metadata:
            # Try common metadata keys for resource names
            for key in ['name', 'resource_name', 'instance_name', 'table_name', 'bucket_name', 
                       'function_name', 'log_group_name', 'secret_name', 'volume_name', 
                       'endpoint_name', 'cluster_name', 'domain_name', 'repo_name', 'trail_name']:
                if key in self.metadata and self.metadata[key]:
                    return str(self.metadata[key])
        return self.resource_id
    
    def _get_action_command_with_region(self) -> Optional[str]:
        """Get action_command with --region flag added if missing."""
        if not self.action_command or not self.region:
            return self.action_command
        
        # Skip if region is already in the command
        if '--region' in self.action_command or self.action_command.strip() == 'null':
            return self.action_command
        
        # Add --region flag to aws CLI commands
        if self.action_command.strip().startswith('aws '):
            return f"{self.action_command.rstrip()} --region {self.region}"
        
        return self.action_command
    
    def _get_action_with_context(self) -> str:
        """Get action recommendation with resource name and region context."""
        resource_name = self._get_resource_name()
        
        # If action already contains the resource name, just add region
        if resource_name in self.action or self.resource_id in self.action:
            if self.region and self.region not in self.action:
                return f"{self.action} (Region: {self.region})"
            return self.action
        
        # Add both resource name and region context
        if self.region:
            return f"{self.action} Resource: '{resource_name}' in {self.region}"
        return f"{self.action} Resource: '{resource_name}'"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        # Imported here, not at module top: scripts/generate_waste_type_catalog.py
        # loads this file standalone (no package), where a package import at
        # module level would fail. to_dict() only runs inside the package.
        from cloudwise_scan_core.advisory_types import validation_for

        return {
            "id": self.id,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type.value if isinstance(self.resource_type, ResourceType) else self.resource_type,
            "waste_type": self.waste_type.value if isinstance(self.waste_type, WasteType) else self.waste_type,
            "title": self.title,
            "description": self.description,
            "monthly_savings": self.monthly_savings,
            "confidence": self.confidence.value if isinstance(self.confidence, ConfidenceLevel) else self.confidence,
            "action": self._get_action_with_context(),  # Now includes resource name and region
            "action_command": self._get_action_command_with_region(),  # Now includes --region flag
            "ai_action_steps": self.ai_action_steps,
            "action_steps_generated_at": self.action_steps_generated_at.isoformat() if isinstance(self.action_steps_generated_at, datetime) else self.action_steps_generated_at,
            "region": self.region,
            "account_id": self.account_id,
            "category": self.category,
            "detected_at": self.detected_at.isoformat() if isinstance(self.detected_at, datetime) else self.detected_at,
            "metadata": self.metadata,
            "explanation": self.explanation,
            # CLO-234 reconciliation evidence
            "estimated_savings_list_price": self.estimated_savings_list_price,
            "billed_cost_observed": self.billed_cost_observed,
            "reconciliation_status": self.reconciliation_status,
            "cost_basis": self.cost_basis,
            # CLO-432: advisory / trusted / unvalidated, from the ledger via
            # the generated advisory_types module. Derived, never stored on
            # the dataclass, so it cannot go stale against the waste type.
            # None for a type the ledger does not know (MISSING, not zero).
            "validation": validation_for(self.waste_type),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WasteItem":
        """Create WasteItem from dictionary."""
        return cls(
            id=data["id"],
            resource_id=data["resource_id"],
            resource_type=ResourceType(data["resource_type"]) if isinstance(data["resource_type"], str) else data["resource_type"],
            waste_type=WasteType(data["waste_type"]) if isinstance(data["waste_type"], str) else data["waste_type"],
            title=data["title"],
            description=data["description"],
            monthly_savings=data["monthly_savings"],
            confidence=ConfidenceLevel(data["confidence"]) if isinstance(data["confidence"], str) else data["confidence"],
            action=data["action"],
            action_command=data.get("action_command"),
            ai_action_steps=data.get("ai_action_steps"),
            action_steps_generated_at=datetime.fromisoformat(data["action_steps_generated_at"]) if isinstance(data.get("action_steps_generated_at"), str) else data.get("action_steps_generated_at"),
            region=data.get("region", ""),
            account_id=data.get("account_id", ""),
            category=data.get("category"),  # Let __post_init__ derive if None
            detected_at=datetime.fromisoformat(data["detected_at"]) if isinstance(data.get("detected_at"), str) else data.get("detected_at", _utc_now()),
            metadata=data.get("metadata", {}),
            explanation=data.get("explanation"),
            estimated_savings_list_price=data.get("estimated_savings_list_price"),
            billed_cost_observed=data.get("billed_cost_observed"),
            reconciliation_status=data.get("reconciliation_status"),
            cost_basis=data.get("cost_basis"),
        )


@dataclass
class WasteDetectionSettings:
    """
    User-configurable waste detection settings.
    
    Settings are stored per AWS account (not per user) since waste
    detection operates at the account level.
    
    All thresholds are designed to balance detection accuracy with cost.
    CloudWatch API calls: ~$0.01 per 1,000 requests.
    Service describe/list calls: Free.
    """
    # CloudWatch Integration
    cloudwatch_enabled: bool = True   # Enabled by default for all tiers

    # CLO-771: the regions a local scan covers, for the account-wide RI inventory.
    # None (hosted) reads the account's enabled regions, if its role may list them.
    scan_regions: Optional[List[str]] = None
    
    # EC2 Thresholds
    ec2_idle_cpu_threshold: float = 5.0      # % CPU average to consider idle
    ec2_idle_days: int = 14                   # Days to evaluate
    ec2_oversized_cpu_threshold: float = 20.0 # % CPU max to consider oversized
    
    # RDS Thresholds
    rds_idle_days: int = 14                   # Days with 0 connections = idle
    rds_oversized_cpu_threshold: float = 20.0 # % CPU max to consider oversized
    
    # EBS Thresholds
    ebs_unused_days: int = 7                  # Days with no I/O = unused
    ebs_iops_utilization_threshold: float = 10.0  # % IOPS utilization to consider over-provisioned
    
    # Snapshot Thresholds
    snapshot_age_days: int = 90               # Snapshots older than this flagged
    ami_age_days: int = 180                   # AMIs older than this flagged
    
    # Lambda Thresholds
    lambda_unused_days: int = 30              # Days with 0 invocations = unused
    lambda_memory_utilization_threshold: float = 20.0  # % memory to consider over-provisioned
    
    # DynamoDB Thresholds
    dynamodb_idle_days: int = 7               # Days with 0 reads/writes = idle
    dynamodb_capacity_utilization_threshold: float = 20.0  # % capacity to consider over-provisioned
    
    # ElastiCache Thresholds
    elasticache_idle_days: int = 7            # Days with 0 connections = idle
    elasticache_cpu_threshold: float = 10.0   # % CPU to consider oversized
    
    # Redshift Thresholds
    redshift_idle_days: int = 7               # Days with 0 connections = idle
    redshift_cpu_threshold: float = 10.0      # % CPU to consider oversized
    redshift_zero_connection_hours_threshold: float = 40.0  # % zero-connection hours for no-pause
    
    # OpenSearch Thresholds
    opensearch_idle_days: int = 7             # Days with low activity = idle
    opensearch_cpu_threshold: float = 10.0    # % CPU to consider oversized
    opensearch_oversized_cpu_threshold: float = 20.0  # % avg CPU for oversized detection
    opensearch_oversized_cpu_max: float = 40.0        # % max CPU ceiling for oversized
    opensearch_ebs_free_storage_pct: float = 60.0     # % free storage to flag EBS overprov.
    opensearch_ebs_min_free_pct: float = 40.0         # % min free storage floor
    opensearch_ebs_growth_rate_gb_day: float = 0.1    # GB/day growth rate ceiling
    
    # SageMaker Thresholds
    sagemaker_notebook_idle_days: int = 7     # Days since last modified = idle
    sagemaker_endpoint_idle_days: int = 7     # Days with 0 invocations = idle
    
    # Kinesis Thresholds
    kinesis_idle_days: int = 7                # Days with 0 records = idle
    kinesis_utilization_threshold: float = 20.0  # % shard utilization for over-provisioned
    
    # MSK Thresholds
    msk_idle_days: int = 7                    # Days with low activity = idle
    msk_broker_utilization_threshold: float = 20.0  # % to consider oversized
    
    # WorkSpaces Thresholds
    workspaces_idle_days: int = 30            # Days disconnected = idle
    
    # EFS Thresholds
    efs_idle_days: int = 7                    # Days with no I/O = idle
    
    # FSx Thresholds
    fsx_idle_days: int = 7                    # Days with no I/O = idle
    fsx_backup_age_days: int = 90             # Days before backup flagged as old
    fsx_oversize_capacity_pct: float = 40.0   # Used capacity < this % = oversized
    fsx_throughput_utilization_pct: float = 30.0  # Throughput < this % = overprovisioned
    
    # Step Functions Thresholds
    sfn_evaluation_days: int = 14              # Window for metric evaluation
    sfn_retry_ratio_threshold: float = 0.25    # retries / total transitions > 25% = storm
    sfn_failure_rate_threshold: float = 0.20   # execution failure rate > 20%
    sfn_min_executions: int = 50               # Minimum executions to avoid small-sample noise
    sfn_transitions_per_success_ceiling: int = 50  # Avg transitions per success above this = high density
    sfn_express_p95_duration_ms: int = 30000   # p95 duration above 30s = duration waste
    sfn_express_min_monthly_executions: int = 10000  # Minimum monthly executions for Express
    
    # S3 Thresholds
    s3_growth_threshold_pct: float = 100.0     # 100% growth in 30 days = doubling
    s3_growth_min_size_gb: float = 1.0        # Ignore buckets under 1 GB
    s3_growth_min_absolute_gb: float = 10.0   # Minimum absolute growth to flag
    s3_tiering_min_size_gb: float = 50.0      # Minimum size for tiering recommendation
    s3_tiering_savings_pct: float = 40.0      # Conservative savings estimate %
    # CLO-610: no production path (online or offline/export) currently
    # supplies a per-bucket access-pattern signal for this estimate — see
    # _s3_tiering_savings_estimate's docstring. Every real scan takes this
    # no-signal path, so it's the primary defense against overstating the
    # saving on a bucket that's actually read all the time: half of
    # s3_tiering_savings_pct, not the whole thing, absent any evidence the
    # bucket's data really does go cold.
    s3_tiering_no_signal_factor: float = 0.5
    s3_lifecycle_min_size_gb: float = 10.0    # Only flag buckets > 10 GB for no lifecycle
    s3_request_transfer_min_cost_usd: float = 10.0      # Minimum total S3 cost to flag
    s3_request_transfer_ratio_threshold: float = 1.0    # Non-storage must exceed storage
    s3_request_transfer_min_nonstorage_usd: float = 5.0  # Minimum non-storage cost
    
    # ECR Thresholds
    ecr_image_age_days: int = 90              # Images older than this flagged
    
    # Glue Thresholds
    glue_job_age_days: int = 90               # Jobs not run in this many days flagged
    glue_job_heap_threshold: float = 30.0     # Flag if avg JVM heap < this %
    glue_job_min_dpus: int = 2                # Don't flag jobs with <= this many DPUs
    glue_job_timeout_ratio: float = 10.0      # Flag if timeout >= this x avg duration
    glue_job_min_timeout_minutes: int = 60    # Only flag if timeout >= this
    glue_job_failure_rate_threshold: float = 0.50  # Flag if >= 50% of runs failed
    glue_job_min_runs_for_pattern: int = 3    # Need >= 3 runs to determine pattern
    glue_catalog_warning_threshold: int = 500_000  # Warn when table versions exceed this
    
    # Transfer Family Thresholds
    transfer_idle_days: int = 30              # Days with zero file transfers = idle
    transfer_protocol_idle_days: int = 30     # Days with zero per-protocol transfers
    transfer_web_app_idle_days: int = 30      # Days with zero sessions = idle
    
    # Reporting Thresholds
    min_waste_threshold_usd: float = 0.01    # Report all waste items (catch everything)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "cloudwatch_enabled": self.cloudwatch_enabled,
            # EC2
            "ec2_idle_cpu_threshold": self.ec2_idle_cpu_threshold,
            "ec2_idle_days": self.ec2_idle_days,
            "ec2_oversized_cpu_threshold": self.ec2_oversized_cpu_threshold,
            # RDS
            "rds_idle_days": self.rds_idle_days,
            "rds_oversized_cpu_threshold": self.rds_oversized_cpu_threshold,
            # EBS
            "ebs_unused_days": self.ebs_unused_days,
            "ebs_iops_utilization_threshold": self.ebs_iops_utilization_threshold,
            # Snapshots
            "snapshot_age_days": self.snapshot_age_days,
            "ami_age_days": self.ami_age_days,
            # Lambda
            "lambda_unused_days": self.lambda_unused_days,
            "lambda_memory_utilization_threshold": self.lambda_memory_utilization_threshold,
            # DynamoDB
            "dynamodb_idle_days": self.dynamodb_idle_days,
            "dynamodb_capacity_utilization_threshold": self.dynamodb_capacity_utilization_threshold,
            # ElastiCache
            "elasticache_idle_days": self.elasticache_idle_days,
            "elasticache_cpu_threshold": self.elasticache_cpu_threshold,
            # Redshift
            "redshift_idle_days": self.redshift_idle_days,
            "redshift_cpu_threshold": self.redshift_cpu_threshold,
            "redshift_zero_connection_hours_threshold": self.redshift_zero_connection_hours_threshold,
            # OpenSearch
            "opensearch_idle_days": self.opensearch_idle_days,
            "opensearch_cpu_threshold": self.opensearch_cpu_threshold,
            "opensearch_oversized_cpu_threshold": self.opensearch_oversized_cpu_threshold,
            "opensearch_oversized_cpu_max": self.opensearch_oversized_cpu_max,
            "opensearch_ebs_free_storage_pct": self.opensearch_ebs_free_storage_pct,
            "opensearch_ebs_min_free_pct": self.opensearch_ebs_min_free_pct,
            "opensearch_ebs_growth_rate_gb_day": self.opensearch_ebs_growth_rate_gb_day,
            # SageMaker
            "sagemaker_notebook_idle_days": self.sagemaker_notebook_idle_days,
            "sagemaker_endpoint_idle_days": self.sagemaker_endpoint_idle_days,
            # Kinesis
            "kinesis_idle_days": self.kinesis_idle_days,
            "kinesis_utilization_threshold": self.kinesis_utilization_threshold,
            # MSK
            "msk_idle_days": self.msk_idle_days,
            "msk_broker_utilization_threshold": self.msk_broker_utilization_threshold,
            # WorkSpaces
            "workspaces_idle_days": self.workspaces_idle_days,
            # EFS
            "efs_idle_days": self.efs_idle_days,
            # FSx
            "fsx_idle_days": self.fsx_idle_days,
            "fsx_backup_age_days": self.fsx_backup_age_days,
            "fsx_oversize_capacity_pct": self.fsx_oversize_capacity_pct,
            "fsx_throughput_utilization_pct": self.fsx_throughput_utilization_pct,
            # S3
            "s3_growth_threshold_pct": self.s3_growth_threshold_pct,
            "s3_growth_min_size_gb": self.s3_growth_min_size_gb,
            "s3_growth_min_absolute_gb": self.s3_growth_min_absolute_gb,
            "s3_tiering_min_size_gb": self.s3_tiering_min_size_gb,
            "s3_tiering_savings_pct": self.s3_tiering_savings_pct,
            "s3_tiering_no_signal_factor": self.s3_tiering_no_signal_factor,
            "s3_lifecycle_min_size_gb": self.s3_lifecycle_min_size_gb,
            "s3_request_transfer_min_cost_usd": self.s3_request_transfer_min_cost_usd,
            "s3_request_transfer_ratio_threshold": self.s3_request_transfer_ratio_threshold,
            "s3_request_transfer_min_nonstorage_usd": self.s3_request_transfer_min_nonstorage_usd,
            # ECR
            "ecr_image_age_days": self.ecr_image_age_days,
            # Glue
            "glue_job_age_days": self.glue_job_age_days,
            "glue_job_heap_threshold": self.glue_job_heap_threshold,
            "glue_job_min_dpus": self.glue_job_min_dpus,
            "glue_job_timeout_ratio": self.glue_job_timeout_ratio,
            "glue_job_min_timeout_minutes": self.glue_job_min_timeout_minutes,
            "glue_job_failure_rate_threshold": self.glue_job_failure_rate_threshold,
            "glue_job_min_runs_for_pattern": self.glue_job_min_runs_for_pattern,
            "glue_catalog_warning_threshold": self.glue_catalog_warning_threshold,
            # Step Functions
            "sfn_evaluation_days": self.sfn_evaluation_days,
            "sfn_retry_ratio_threshold": self.sfn_retry_ratio_threshold,
            "sfn_failure_rate_threshold": self.sfn_failure_rate_threshold,
            "sfn_min_executions": self.sfn_min_executions,
            "sfn_transitions_per_success_ceiling": self.sfn_transitions_per_success_ceiling,
            "sfn_express_p95_duration_ms": self.sfn_express_p95_duration_ms,
            "sfn_express_min_monthly_executions": self.sfn_express_min_monthly_executions,
            # Transfer Family
            "transfer_idle_days": self.transfer_idle_days,
            "transfer_protocol_idle_days": self.transfer_protocol_idle_days,
            "transfer_web_app_idle_days": self.transfer_web_app_idle_days,
            # Reporting
            "min_waste_threshold_usd": self.min_waste_threshold_usd,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WasteDetectionSettings":
        """Create settings from dictionary."""
        return cls(
            cloudwatch_enabled=data.get("cloudwatch_enabled", True),
            # EC2
            ec2_idle_cpu_threshold=data.get("ec2_idle_cpu_threshold", 5.0),
            ec2_idle_days=data.get("ec2_idle_days", 14),
            ec2_oversized_cpu_threshold=data.get("ec2_oversized_cpu_threshold", 20.0),
            # RDS
            rds_idle_days=data.get("rds_idle_days", 14),
            rds_oversized_cpu_threshold=data.get("rds_oversized_cpu_threshold", 20.0),
            # EBS
            ebs_unused_days=data.get("ebs_unused_days", 7),
            ebs_iops_utilization_threshold=data.get("ebs_iops_utilization_threshold", 10.0),
            # Snapshots
            snapshot_age_days=data.get("snapshot_age_days", 90),
            ami_age_days=data.get("ami_age_days", 180),
            # Lambda
            lambda_unused_days=data.get("lambda_unused_days", 30),
            lambda_memory_utilization_threshold=data.get("lambda_memory_utilization_threshold", 20.0),
            # DynamoDB
            dynamodb_idle_days=data.get("dynamodb_idle_days", 7),
            dynamodb_capacity_utilization_threshold=data.get("dynamodb_capacity_utilization_threshold", 20.0),
            # ElastiCache
            elasticache_idle_days=data.get("elasticache_idle_days", 7),
            elasticache_cpu_threshold=data.get("elasticache_cpu_threshold", 10.0),
            # Redshift
            redshift_idle_days=data.get("redshift_idle_days", 7),
            redshift_cpu_threshold=data.get("redshift_cpu_threshold", 10.0),
            redshift_zero_connection_hours_threshold=data.get("redshift_zero_connection_hours_threshold", 40.0),
            # OpenSearch
            opensearch_idle_days=data.get("opensearch_idle_days", 7),
            opensearch_cpu_threshold=data.get("opensearch_cpu_threshold", 10.0),
            opensearch_oversized_cpu_threshold=data.get("opensearch_oversized_cpu_threshold", 20.0),
            opensearch_oversized_cpu_max=data.get("opensearch_oversized_cpu_max", 40.0),
            opensearch_ebs_free_storage_pct=data.get("opensearch_ebs_free_storage_pct", 60.0),
            opensearch_ebs_min_free_pct=data.get("opensearch_ebs_min_free_pct", 40.0),
            opensearch_ebs_growth_rate_gb_day=data.get("opensearch_ebs_growth_rate_gb_day", 0.1),
            # SageMaker
            sagemaker_notebook_idle_days=data.get("sagemaker_notebook_idle_days", 7),
            sagemaker_endpoint_idle_days=data.get("sagemaker_endpoint_idle_days", 7),
            # Kinesis
            kinesis_idle_days=data.get("kinesis_idle_days", 7),
            kinesis_utilization_threshold=data.get("kinesis_utilization_threshold", 20.0),
            # MSK
            msk_idle_days=data.get("msk_idle_days", 7),
            msk_broker_utilization_threshold=data.get("msk_broker_utilization_threshold", 20.0),
            # WorkSpaces
            workspaces_idle_days=data.get("workspaces_idle_days", 30),
            # EFS
            efs_idle_days=data.get("efs_idle_days", 7),
            # FSx
            fsx_idle_days=data.get("fsx_idle_days", 7),
            fsx_backup_age_days=data.get("fsx_backup_age_days", 90),
            fsx_oversize_capacity_pct=data.get("fsx_oversize_capacity_pct", 40.0),
            fsx_throughput_utilization_pct=data.get("fsx_throughput_utilization_pct", 30.0),
            # S3
            s3_growth_threshold_pct=data.get("s3_growth_threshold_pct", 100.0),
            s3_growth_min_size_gb=data.get("s3_growth_min_size_gb", 1.0),
            s3_growth_min_absolute_gb=data.get("s3_growth_min_absolute_gb", 10.0),
            s3_tiering_min_size_gb=data.get("s3_tiering_min_size_gb", 50.0),
            s3_tiering_savings_pct=data.get("s3_tiering_savings_pct", 40.0),
            s3_tiering_no_signal_factor=data.get("s3_tiering_no_signal_factor", 0.5),
            s3_lifecycle_min_size_gb=data.get("s3_lifecycle_min_size_gb", 10.0),
            s3_request_transfer_min_cost_usd=data.get("s3_request_transfer_min_cost_usd", 10.0),
            s3_request_transfer_ratio_threshold=data.get("s3_request_transfer_ratio_threshold", 1.0),
            s3_request_transfer_min_nonstorage_usd=data.get("s3_request_transfer_min_nonstorage_usd", 5.0),
            # ECR
            ecr_image_age_days=data.get("ecr_image_age_days", 90),
            # Glue
            glue_job_age_days=data.get("glue_job_age_days", 90),
            glue_job_heap_threshold=data.get("glue_job_heap_threshold", 30.0),
            glue_job_min_dpus=data.get("glue_job_min_dpus", 2),
            glue_job_timeout_ratio=data.get("glue_job_timeout_ratio", 10.0),
            glue_job_min_timeout_minutes=data.get("glue_job_min_timeout_minutes", 60),
            glue_job_failure_rate_threshold=data.get("glue_job_failure_rate_threshold", 0.50),
            glue_job_min_runs_for_pattern=data.get("glue_job_min_runs_for_pattern", 3),
            glue_catalog_warning_threshold=data.get("glue_catalog_warning_threshold", 500_000),
            # Step Functions
            sfn_evaluation_days=data.get("sfn_evaluation_days", 14),
            sfn_retry_ratio_threshold=data.get("sfn_retry_ratio_threshold", 0.25),
            sfn_failure_rate_threshold=data.get("sfn_failure_rate_threshold", 0.20),
            sfn_min_executions=data.get("sfn_min_executions", 50),
            sfn_transitions_per_success_ceiling=data.get("sfn_transitions_per_success_ceiling", 50),
            sfn_express_p95_duration_ms=data.get("sfn_express_p95_duration_ms", 30000),
            sfn_express_min_monthly_executions=data.get("sfn_express_min_monthly_executions", 10000),
            # Transfer Family
            transfer_idle_days=data.get("transfer_idle_days", 30),
            transfer_protocol_idle_days=data.get("transfer_protocol_idle_days", 30),
            transfer_web_app_idle_days=data.get("transfer_web_app_idle_days", 30),
            # Reporting
            min_waste_threshold_usd=data.get("min_waste_threshold_usd", 0.01),
        )
    
    @classmethod
    def get_defaults(cls) -> "WasteDetectionSettings":
        """Get default settings."""
        return cls()


@dataclass
class WasteDetectionResult:
    """
    Complete result of a waste detection scan.
    """
    # Account Information
    account_id: str
    region: str
    
    # Results
    waste_items: List[WasteItem] = field(default_factory=list)
    total_monthly_savings: float = 0.0
    
    # Scan Information
    scan_started_at: datetime = field(default_factory=_utc_now)
    scan_completed_at: Optional[datetime] = None
    scan_duration_seconds: float = 0.0
    
    # Status
    success: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # CLO-217: a tier-filtered or CUR-filtered detector is neither an error
    # nor a warning — it's a deliberate, non-faulty omission — but it MUST
    # still be recorded, mirroring the "findings MISSING, not zero" guarantee
    # CLO-193 shipped for detector exceptions (see ``warnings`` above). Kept
    # as separate fields (not folded into ``warnings``) so a tier skip never
    # reads as a fault in the UI. ``tier_skipped`` = detector ids dropped by
    # ``tier_routing.py`` for the account's subscription tier;
    # ``cur_skipped`` = detector ids dropped because the account's Cost &
    # Usage Report shows no active usage for that service. Both are
    # region-invariant for a given scan (same tier / same CUR snapshot).
    tier_skipped: List[str] = field(default_factory=list)
    cur_skipped: List[str] = field(default_factory=list)

    # CLO-234: per-status counts from the billed-cost reconciliation pass,
    # e.g. {"reconciled": 12, "unreconciled_no_cur": 3}. Carried here for the
    # same reason as the two lists above — "we could not check this against
    # your bill" is a fact about the scan that must survive to the persisted
    # row, not be inferred from a savings figure that looks confident. Also
    # records how many findings were dropped by the savings floor *after*
    # reconciliation, so a shrunken finding count is explainable.
    reconciliation_counts: Dict[str, int] = field(default_factory=dict)
    reconciled_below_threshold: int = 0

    # CLO-430 / ADR 0002: the items the savings floor dropped, kept rather than
    # only counted. `reconciled_below_threshold` above says HOW MANY went; this
    # says WHICH, which is what L2 validation needs — a findings-table (or
    # post-floor S3) oracle cannot tell "detector silent" from "detector fired,
    # finding floored", and those are opposite bugs.
    #
    # Memory cost is ~nil: `_reconcile_and_collect` receives every item in
    # `staged` before deciding anything, so these objects are already resident
    # at peak. This keeps references, it does not build a second copy.
    #
    # Deliberately NOT in `to_dict()`. That feeds the result cache and the Step
    # Functions payload, which has a 256 KB state limit — the reason the Hub
    # manifest already goes to S3. A large account can drop many items, so they
    # travel as their own S3 object and nowhere else (ADR 0002).
    below_floor_items: List[WasteItem] = field(default_factory=list)

    # Permission tracking for template update notifications
    # Tracks which AWS services/APIs returned AccessDenied errors
    permission_errors: List[str] = field(default_factory=list)

    # CLO-368: structured, per-detector view of the same AccessDenied
    # failures ``permission_errors`` already tracks as human-readable
    # strings. Kept as a separate field (not a replacement) so existing
    # callers of ``permission_errors`` are unaffected. Each entry is
    # ``{"detector": <detector_key>, "action": <best-effort IAM action>}``,
    # deduplicated. CLO-354 copies this onto the account row so the
    # customer can be told which permissions to add to the role template.
    permission_missing: List[Dict[str, str]] = field(default_factory=list)

    # CLO-375: ``{"source", "state"}`` entries for a free AWS input this
    # account has not enabled (e.g. ``{"source": "compute_optimizer",
    # "state": "not_enrolled"}``). Not an error and not a missing
    # permission: the scan succeeded, but the findings that input feeds are
    # MISSING, not zero. CLO-354's aggregate step copies it onto the
    # account row next to ``permission_missing``.
    coverage_notes: List[Dict[str, str]] = field(default_factory=list)

    # Statistics
    resources_scanned: int = 0
    waste_items_found: int = 0
    # CLO-857: how many detectors actually ran in this region (after tier, CUR
    # and skip filtering). Feeds the per-region scan progress record. Not in
    # to_dict(): that feeds the result cache and the SFN payload.
    detectors_run: int = 0

    # Settings Used
    settings: Optional[WasteDetectionSettings] = None
    
    def complete(self):
        """Mark the scan as complete and calculate totals."""
        self.scan_completed_at = _utc_now()
        self.scan_duration_seconds = (self.scan_completed_at - self.scan_started_at).total_seconds()
        self.waste_items_found = len(self.waste_items)
        self.total_monthly_savings = sum(item.monthly_savings for item in self.waste_items)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "account_id": self.account_id,
            "region": self.region,
            "waste_items": [item.to_dict() for item in self.waste_items],
            "total_monthly_savings": self.total_monthly_savings,
            "scan_started_at": self.scan_started_at.isoformat() if self.scan_started_at else None,
            "scan_completed_at": self.scan_completed_at.isoformat() if self.scan_completed_at else None,
            "scan_duration_seconds": self.scan_duration_seconds,
            "success": self.success,
            "errors": self.errors,
            "warnings": self.warnings,
            "tier_skipped": self.tier_skipped,
            "cur_skipped": self.cur_skipped,
            "reconciliation_counts": self.reconciliation_counts,
            "reconciled_below_threshold": self.reconciled_below_threshold,
            "permission_errors": self.permission_errors,
            "permission_missing": self.permission_missing,
            "coverage_notes": self.coverage_notes,
            "resources_scanned": self.resources_scanned,
            "waste_items_found": self.waste_items_found,
            "settings": self.settings.to_dict() if self.settings else None,
        }


# Pricing constants for waste calculations
EC2_PRICING = {
    # On-Demand hourly pricing (US East) - monthly = hourly * 730
    "t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
    "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
    "t2.nano": 0.0058, "t2.micro": 0.0116, "t2.small": 0.023, "t2.medium": 0.0464,
    "t2.large": 0.0928, "t2.xlarge": 0.1856, "t2.2xlarge": 0.3712,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384, "m5.4xlarge": 0.768,
    "m6i.large": 0.096, "m6i.xlarge": 0.192, "m6i.2xlarge": 0.384,
    "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34,
    "r5.large": 0.126, "r5.xlarge": 0.252, "r5.2xlarge": 0.504,
}

EBS_PRICING = {
    # Per GB-month pricing (US East). CLO-975: the only EBS per-GB table;
    # AWSPricingService.FALLBACK_EBS_PRICING and
    # WasteDetectionService._estimate_ebs_monthly_cost read it. sc1 is $0.015
    # per GB-month ("Cold HDD (sc1) provisioned storage - US East (Northern
    # Virginia)"; AWS Price List API, AmazonEC2, us-east-1, read 2026-11-13).
    # It was 0.025 here, which overstated an sc1 volume by two thirds.
    "gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125,
    "st1": 0.045, "sc1": 0.015, "standard": 0.05,
}

# Provisioned-IOPS list prices (us-east-1, per IOPS-month). gp3 includes
# 3,000 IOPS; io1 bills every IOPS; io2 bills in tiers (first 32,000,
# 32,001-64,000, above 64,000). CLO-516 put these in
# detectors/open/storage.py; CLO-975 moved them here so
# get_ebs_monthly_cost and the over-provisioned-IOPS check price IOPS the
# same way (storage.py re-exports them). io2 above 64,000 IOPS is
# $0.03185 (AWS Price List API, AmazonEC2 us-east-1 offer, SKU
# AX8G343U7JZBRKJB, usage type EBS:VolumeP-IOPS.io2.tier3, effective
# 2026-11-01; AWS's description text rounds it to $0.032).
GP3_FREE_IOPS = 3000
GP3_IOPS_PRICE = 0.005
IO1_IOPS_PRICE = 0.065
IO2_IOPS_TIERS = ((32000, 0.065), (64000, 0.0455), (None, 0.03185))


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

PRICE_UNKNOWN_REASON = "price unknown, saving not estimated"


def price_note_service(service: str) -> str:
    """The note-channel service key for a price-unknown note ("<svc> price")."""
    return f"{service} price"


def note_price_unknown(data_provider, service: str, resource_id: str, what: str = "list price") -> None:
    """Withhold a finding whose saving needs a price CloudWise does not have.

    CLO-975: an unknown instance class, node type or bundle used to be priced
    at an invented default ($0.10, $0.15, $1.00, $0.20 an hour, $15 a month).
    The finding is now skipped and the scan's data warnings say "price
    unknown, saving not estimated" for the resource (MISSING, not zero). A
    test double without the provider's note channel is skipped."""
    note = getattr(data_provider, '_note_idle_verdict_missing', None)
    if callable(note):
        # The note state is keyed by service only, and the idle-metric notes of
        # the same services (workspaces, redshift, opensearch, lightsail,
        # beanstalk) use the bare name: a price note under it would be deduped
        # away or relabel earlier ids. Same pattern as KINESIS_EFO_NOTE_SERVICE.
        note(price_note_service(service), resource_id, PRICE_UNKNOWN_REASON,
             verdict='saving', evidence=f"{what}s")


# CLO-975 item 7: WorkSpaces, one table. AWS Price List, AmazonWorkSpaces,
# us-east-1 (location US East (N. Virginia)), read 2026-11-14. Basis: Windows,
# license included, Basic utilities (usage types USE1-AW-HW-*), at each bundle's
# smallest volume configuration (the lowest price, so the smaller saving), per
# month. Keyed by the API's ComputeType name. The price depends on the bundle's
# root and user volumes (Power $70 at 80+10 GB to $78 at 175+100 GB, PowerPro
# $127 to $140); a WorkSpace with larger volumes costs more, so a saving built
# from this table can only be understated. The legacy GRAPHICS bundle has no
# price in the list, so it is absent: no saving is estimated for it.
WORKSPACES_ALWAYS_ON_MONTHLY = {
    "VALUE": 25.0,               # USE1-AW-HW-5   (Value, 80 GB root + 10 GB user)
    "STANDARD": 33.0,            # USE1-AW-HW-1-0 (Standard, 80 + 10)
    "PERFORMANCE": 45.0,         # USE1-AW-HW-3-0 (Performance, 80 + 10)
    "POWER": 70.0,               # USE1-AW-HW-8-0 (Power, 80 + 10)
    "POWERPRO": 127.0,           # USE1-AW-HW-10-0 (PowerPro, 80 + 10)
    "GRAPHICSPRO": 999.0,        # USE1-AW-HW-12  (GraphicsPro, 100 + 100)
    "GRAPHICS_G4DN": 537.0,      # USE1-AW-HW-GFX-G4DN (100 + 100)
    "GRAPHICSPRO_G4DN": 959.0,   # USE1-AW-HW-GFXPRO-G4DN (100 + 100)
}

# AutoStop billing, same basis: the per-hour usage rate (USE1-AW-HW-*-AutoStop-
# Usage) and the monthly fee per WorkSpace (USE1-AW-HW-*-AutoStop-User; $7.25
# at 80 + 10 GB on the Value to PowerPro bundles, $66 on GraphicsPro).
WORKSPACES_AUTOSTOP_HOURLY = {
    "VALUE": 0.22, "STANDARD": 0.30, "PERFORMANCE": 0.47, "POWER": 0.68,
    "POWERPRO": 1.53, "GRAPHICSPRO": 11.62, "GRAPHICS_G4DN": 1.54,
    "GRAPHICSPRO_G4DN": 11.16,
}
WORKSPACES_AUTOSTOP_MONTHLY_BASE = {
    "VALUE": 7.25, "STANDARD": 7.25, "PERFORMANCE": 7.25, "POWER": 7.25,
    "POWERPRO": 7.25, "GRAPHICSPRO": 66.0, "GRAPHICS_G4DN": 22.0,
    "GRAPHICSPRO_G4DN": 66.0,
}

US_EAST_1_PRICES_NOTE = (
    "Prices are us-east-1 list prices; they are not adjusted for the region "
    "the resource runs in."
)


def us_east_1_prices(skip=()):
    """Decorator for an async detector whose prices are built-in us-east-1 list
    prices with no region scaling (SageMaker, Redshift, OpenSearch, Neptune,
    EMR: CLO-975 item 9, owner decision "accept for now, but say so").

    Appends ``US_EAST_1_PRICES_NOTE`` to every returned finding's
    ``explanation['pricing']``, except findings whose waste type value is in
    ``skip`` (a price in that detector that IS region-scaled)."""

    def wrap(fn):
        @functools.wraps(fn)
        async def inner(*args, **kwargs):
            items = await fn(*args, **kwargs)
            for item in items or []:
                if getattr(item, "waste_type", None) in skip:
                    continue
                explanation = getattr(item, "explanation", None)
                if isinstance(explanation, dict):
                    current = explanation.get("pricing")
                    if US_EAST_1_PRICES_NOTE not in str(current or ""):
                        explanation["pricing"] = (
                            f"{current} {US_EAST_1_PRICES_NOTE}" if current else US_EAST_1_PRICES_NOTE
                        )
            return items

        return inner

    return wrap


RDS_PRICING = {
    # On-Demand hourly pricing (US East) - monthly = hourly * 730
    "db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068,
    "db.t3.large": 0.136, "db.t3.xlarge": 0.272, "db.t3.2xlarge": 0.544,
    # CLO-589: Graviton burstable. Without these rows db.t4g.micro (the
    # cheapest current class, ~$11.68/month) fell back to the $0.10/hr
    # default ($73/month), a sixfold overstatement. MySQL/PostgreSQL
    # Single-AZ list rates, not re-read from the Pricing API in that session.
    "db.t4g.micro": 0.016, "db.t4g.small": 0.032, "db.t4g.medium": 0.065,
    "db.t4g.large": 0.129, "db.t4g.xlarge": 0.258, "db.t4g.2xlarge": 0.517,
    "db.m5.large": 0.171, "db.m5.xlarge": 0.342, "db.m5.2xlarge": 0.684,
    "db.m6i.large": 0.171, "db.m6i.xlarge": 0.342, "db.m6i.2xlarge": 0.684,
    "db.r5.large": 0.24, "db.r5.xlarge": 0.48, "db.r5.2xlarge": 0.96,
    # CLO-975 item 5: the rows below were missing, so db.r6g/db.r7g (common
    # Aurora and RDS classes) priced at an invented $0.10/hr. All are RDS for
    # MySQL, Single-AZ, license model "No license required" (not "License
    # included"), On-Demand, us-east-1: AWS Price List API, AmazonRDS, productFamily "Database Instance", deploymentOption
    # Single-AZ, databaseEngine MySQL, read 2026-11-14 (publication
    # 2026-11-13T21:52:33Z). The same basis as every row above (r5.large
    # 0.24 is the MySQL rate). Aurora and PostgreSQL list their own, higher
    # rates (r6g.large Aurora MySQL 0.26, PostgreSQL 0.225).
    "db.m5.4xlarge": 1.368,
    "db.r5.4xlarge": 1.92, "db.r5.8xlarge": 3.84, "db.r5.12xlarge": 5.76,
    "db.r5.16xlarge": 7.68, "db.r5.24xlarge": 11.52,
    "db.r6g.large": 0.215, "db.r6g.xlarge": 0.43, "db.r6g.2xlarge": 0.859,
    "db.r6g.4xlarge": 1.718, "db.r6g.8xlarge": 3.437, "db.r6g.12xlarge": 5.155,
    "db.r6g.16xlarge": 6.874,
    "db.r6i.large": 0.24, "db.r6i.xlarge": 0.48, "db.r6i.2xlarge": 0.96,
    "db.r6i.4xlarge": 1.92, "db.r6i.8xlarge": 3.84, "db.r6i.12xlarge": 5.76,
    "db.r6i.16xlarge": 7.68, "db.r6i.24xlarge": 11.52, "db.r6i.32xlarge": 15.36,
    "db.r7g.large": 0.239, "db.r7g.xlarge": 0.478, "db.r7g.2xlarge": 0.956,
    "db.r7g.4xlarge": 1.913, "db.r7g.8xlarge": 3.825, "db.r7g.12xlarge": 5.738,
    "db.r7g.16xlarge": 7.65,
    # CLO-975 review (N1): more common classes, same basis and same price
    # file (AmazonRDS, us-east-1, publication 2026-11-13T21:52:33Z): RDS for
    # MySQL, Single-AZ, On-Demand, license model "No license required". Without
    # a row a class has no price, and Idle RDS withholds its finding.
    "db.m6g.large": 0.152, "db.m6g.xlarge": 0.304, "db.m6g.2xlarge": 0.608,
    "db.m6g.4xlarge": 1.216, "db.m6g.8xlarge": 2.432, "db.m6g.12xlarge": 3.648,
    "db.m6g.16xlarge": 4.864,
    "db.m7g.large": 0.168, "db.m7g.xlarge": 0.337, "db.m7g.2xlarge": 0.674,
    "db.m7g.4xlarge": 1.348, "db.m7g.8xlarge": 2.696, "db.m7g.12xlarge": 4.044,
    "db.m7g.16xlarge": 5.392,
    "db.m7i.large": 0.178, "db.m7i.xlarge": 0.356, "db.m7i.2xlarge": 0.712,
    "db.m7i.4xlarge": 1.424, "db.m7i.8xlarge": 2.848, "db.m7i.12xlarge": 4.272,
    "db.m7i.16xlarge": 5.696, "db.m7i.24xlarge": 8.544, "db.m7i.48xlarge": 17.088,
    "db.m8g.large": 0.168, "db.m8g.xlarge": 0.336, "db.m8g.2xlarge": 0.672,
    "db.m8g.4xlarge": 1.344, "db.m8g.8xlarge": 2.688, "db.m8g.12xlarge": 4.032,
    "db.m8g.16xlarge": 5.376, "db.m8g.24xlarge": 8.064, "db.m8g.48xlarge": 16.128,
    "db.r7i.large": 0.25, "db.r7i.xlarge": 0.5, "db.r7i.2xlarge": 1, "db.r7i.4xlarge": 2,
    "db.r7i.8xlarge": 4, "db.r7i.12xlarge": 6, "db.r7i.16xlarge": 8, "db.r7i.24xlarge": 12,
    "db.r7i.48xlarge": 24,
    "db.r8g.large": 0.239, "db.r8g.xlarge": 0.478, "db.r8g.2xlarge": 0.956,
    "db.r8g.4xlarge": 1.912, "db.r8g.8xlarge": 3.824, "db.r8g.12xlarge": 5.736,
    "db.r8g.16xlarge": 7.648, "db.r8g.24xlarge": 11.472, "db.r8g.48xlarge": 22.944,
    "db.r5b.large": 0.296, "db.r5b.xlarge": 0.592, "db.r5b.2xlarge": 1.184,
    "db.r5b.4xlarge": 2.368, "db.r5b.8xlarge": 4.736, "db.r5b.12xlarge": 7.104,
    "db.r5b.16xlarge": 9.472, "db.r5b.24xlarge": 14.208,
    "db.r5d.large": 0.286, "db.r5d.xlarge": 0.571, "db.r5d.2xlarge": 1.143,
    "db.r5d.4xlarge": 2.286, "db.r5d.8xlarge": 4.571, "db.r5d.12xlarge": 6.857,
    "db.r5d.16xlarge": 9.143, "db.r5d.24xlarge": 13.714,
    "db.m5d.large": 0.21, "db.m5d.xlarge": 0.419, "db.m5d.2xlarge": 0.838,
    "db.m5d.4xlarge": 1.676, "db.m5d.8xlarge": 3.352, "db.m5d.12xlarge": 5.028,
    "db.m5d.16xlarge": 6.705, "db.m5d.24xlarge": 10.057,
    "db.m4.large": 0.175, "db.m4.xlarge": 0.35, "db.m4.2xlarge": 0.7, "db.m4.4xlarge": 1.401,
    "db.m4.10xlarge": 3.502, "db.m4.16xlarge": 5.6,
    "db.r4.large": 0.24, "db.r4.xlarge": 0.48, "db.r4.2xlarge": 0.96, "db.r4.4xlarge": 1.92,
    "db.r4.8xlarge": 3.84, "db.r4.16xlarge": 7.68,
    "db.t2.micro": 0.017, "db.t2.small": 0.034, "db.t2.medium": 0.068, "db.t2.large": 0.136,
    "db.t2.xlarge": 0.272, "db.t2.2xlarge": 0.544,
    "db.x2g.large": 0.326, "db.x2g.xlarge": 0.652, "db.x2g.2xlarge": 1.304,
    "db.x2g.4xlarge": 2.608, "db.x2g.8xlarge": 5.216, "db.x2g.12xlarge": 7.824,
    "db.x2g.16xlarge": 10.432,
}

# Fixed monthly costs. CLO-975: every monthly figure below is an hourly
# us-east-1 list price × HOURS_PER_MONTH (730, the basis AWS's own pricing
# pages and calculator use), rounded half-up to the cent. Until CLO-975 NAT
# Gateway and ALB/NLB used 720 hours (32.40, 16.20) while EIP and Classic LB
# used 730, so the Classic-to-ALB saving subtracted one basis from the other.
# AWSPricingService.FALLBACK_*_HOURLY read the hourly rates from here.
HOURS_PER_MONTH = 730


def monthly_from_hourly(hourly: float) -> float:
    """``hourly`` × 730, rounded half-up to the cent (0.0225 → 16.43).

    Decimal arithmetic, so a product on a half cent (16.425) always rounds
    up instead of following the float's binary representation.
    """
    return float(
        (Decimal(str(hourly)) * HOURS_PER_MONTH).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    )


EIP_IDLE_HOURLY = 0.005               # Public IPv4 address, per hour
NAT_GATEWAY_HOURLY = 0.045            # NAT Gateway, per hour (+ data processing)
ALB_HOURLY = 0.0225                   # Application Load Balancer, per hour (+ LCU)
NLB_HOURLY = 0.0225                   # Network Load Balancer, per hour (+ NLCU)
CLB_HOURLY = 0.025                    # Classic Load Balancer, per hour
VPC_INTERFACE_ENDPOINT_AZ_HOURLY = 0.01   # Interface endpoint, per AZ per hour
TRANSFER_PROTOCOL_HOURLY = 0.30       # Transfer Family server, per enabled protocol per hour
TRANSFER_WEB_APP_UNIT_HOURLY = 0.50   # Transfer Family web app, per unit per hour

EIP_MONTHLY_COST = monthly_from_hourly(EIP_IDLE_HOURLY)              # 3.65
NAT_GATEWAY_MONTHLY_BASE = monthly_from_hourly(NAT_GATEWAY_HOURLY)   # 32.85 (+ data transfer)
ALB_MONTHLY_BASE = monthly_from_hourly(ALB_HOURLY)                   # 16.43 (+ LCU hours)
NLB_MONTHLY_BASE = monthly_from_hourly(NLB_HOURLY)                   # 16.43 (+ LCU hours)
CLB_MONTHLY_BASE = monthly_from_hourly(CLB_HOURLY)                   # 18.25
ALB_LCU_HOURLY = 0.008    # ALB LCU-hour rate (us-east-1)
NLB_NLCU_HOURLY = 0.006   # NLB NLCU-hour rate (us-east-1)
# CLO-975: replaces VPC_ENDPOINT_MONTHLY = 7.20, which nothing used and which
# disagreed with the 7.30 the unused-endpoint check typed inline.
VPC_INTERFACE_ENDPOINT_AZ_MONTHLY = monthly_from_hourly(VPC_INTERFACE_ENDPOINT_AZ_HOURLY)  # 7.30
TRANSFER_PROTOCOL_MONTHLY = monthly_from_hourly(TRANSFER_PROTOCOL_HOURLY)            # 219.00
TRANSFER_WEB_APP_UNIT_MONTHLY = monthly_from_hourly(TRANSFER_WEB_APP_UNIT_HOURLY)    # 365.00
# CLO-975: Kinesis Data Streams provisioned shard-hour, us-east-1 (AWS Price List,
# AmazonKinesis, usage type Storage-ShardHour, $0.015 per provisioned shard-hour,
# read 2026-11-14). The detector typed "$11" per shard-month twice, three ways
# with this rate (0.015 x 730 = 10.95).
KINESIS_SHARD_HOURLY = 0.015
# CLO-975: MSK broker storage, us-east-1 (AWS Price List, AmazonMSK, usage type
# USE1-Kafka.Storage.GP2, $0.10 per GB-month, publication 2026-11-11T00:23:59Z).
# Billed per GB of EBS volume provisioned on each broker.
MSK_STORAGE_PER_GB_MONTH = 0.10
KINESIS_SHARD_MONTHLY = monthly_from_hourly(KINESIS_SHARD_HOURLY)    # 10.95
# Kinesis enhanced fan-out: the consumer-shard-hour charge. This is a different
# usage type from the provisioned shard-hour above; the rate happens to be the
# same number (0.015), so it has its own constant and must not reuse
# KINESIS_SHARD_HOURLY. Verified against the AWS Price List (AmazonKinesis,
# us-east-1, publication 2026-11-10T16:19:53Z): usage type EnhancedFanoutHour,
# unit ConsumerShardHour, $0.015 per enhanced fan-out consumer-shard hour.
KINESIS_EFO_CONSUMER_SHARD_HOURLY = 0.015
KINESIS_EFO_CONSUMER_SHARD_MONTHLY = monthly_from_hourly(KINESIS_EFO_CONSUMER_SHARD_HOURLY)  # 10.95 per shard

# EFS list prices (us-east-1, per GB-month; AWS Price List API, AmazonEFS,
# us-east-1, read 2026-11-13). CLO-975: the only EFS table; the EFS checks
# and AWSPricingService.FALLBACK_EFS_PRICING read these. Infrequent Access
# has two prices by the file system's ThroughputMode: Standard-Infrequent
# Access (USE1-IATimedStorage-ByteHrs, bursting or provisioned throughput)
# $0.025, and Infrequent Access with Elastic Throughput
# (USE1-IATimedStorage-ET-ByteHrs) $0.016. The detector used 0.025 for every
# file system and the pricing service 0.016; neither was simply wrong.
# These are Regional (multi-AZ) prices; One Zone file systems ($0.16 and
# $0.0133) are not told apart yet (no AvailabilityZoneName in
# EFSFilesystemData).
EFS_STANDARD_PER_GB = 0.30
EFS_IA_PER_GB = 0.025            # bursting / provisioned throughput
EFS_IA_ELASTIC_PER_GB = 0.016    # elastic throughput


def efs_ia_per_gb(throughput_mode: Optional[str]) -> float:
    """EFS Infrequent Access price for a file system's ThroughputMode.

    ``elastic`` -> 0.016; ``bursting``, ``provisioned`` and anything unknown or
    missing -> 0.025, the higher price, so an unread mode gives the smaller
    (conservative) lifecycle saving.
    """
    if (throughput_mode or "").strip().lower() == "elastic":
        return EFS_IA_ELASTIC_PER_GB
    return EFS_IA_PER_GB

# S3 pricing constants (us-east-1, first 50 TB tier). Confirmed 2026-10-14
# against the AWS Price List API offer file (pricing.us-east-1.amazonaws.com/
# offers/v1.0/aws/AmazonS3/current/us-east-1/index.json, publicationDate
# 2026-10-12T23:11:02Z, version 20261012231102): SKU 7DR3RFK9W2W43KSC (fee
# code "S3-Monitoring and Automation-ObjectCount") prices $0.0025 per 1,000
# objects/month; SKU WP9ANXZGBYYSGJEA (General Purpose / Standard) and SKU
# M7WA952JTYFHTE64 (Intelligent-Tiering, Infrequent Access tier) price
# $0.023 and $0.0125 per GB-month; SKU ZWQ6Q48CRJXX4FXE ("GET and all other
# requests", usage type Requests-Tier2) prices $0.0000004/request ($0.004
# per 10,000 requests).
S3_STANDARD_PER_GB = 0.023        # S3 Standard per GB-month
S3_IT_MONITORING_PER_1K = 0.0025  # Intelligent-Tiering monitoring fee per 1,000 objects
# CLO-610: GET/SELECT/HEAD ("Tier2") request price, used only to convert a
# CUR cost breakdown's request_tier2_cost back into an estimated request
# count (there's no per-bucket GET *count* anywhere in this pipeline, only
# $ costs) for the access-pattern signal below.
S3_TIER2_REQUEST_PRICE = 0.0000004
# CLO-610: Intelligent-Tiering's Infrequent Access tier, the one a bucket
# normally reaches after 30 days with no access. Caps the assumed savings
# rate so a detector can never claim more than this, the real Standard ->
# Standard-IA discount (~45.7%) — never the deeper Archive Instant Access
# rate, which needs 90 days of inactivity Intelligent-Tiering does not
# guarantee.
S3_STANDARD_IA_PER_GB = 0.0125
# CLO-610: per aws.amazon.com/s3/pricing (fetched 2026-10-14): "S3
# Intelligent-Tiering can store objects smaller than 128 KB, but
# auto-tiering has a minimum eligible object size of 128 KB. These smaller
# objects will not be monitored and will always be charged at the Frequent
# Access tier rates, with no monitoring and automation charge." An object
# under this size never moves out of Standard/Frequent Access and is never
# billed the monitoring fee.
S3_IT_MIN_TIERABLE_BYTES = 128 * 1024


def _region_price_multiplier(region: Optional[str]) -> float:
    """Approximate on-demand price multiplier for a region vs us-east-1 (=1.0).

    CLO-359: EC2_PRICING/EBS_PRICING/RDS_PRICING/EIP_MONTHLY_COST above are
    flat us-east-1 rates with no region scaling of their own, so a resource
    in e.g. sa-east-1 (1.45x) was always priced as if it were in us-east-1
    — understating the saving, never overstating it (the CLO-234 billed-cost
    cap only guards the other direction). Reuses
    ``AWSPricingService.REGION_PRICE_MULTIPLIERS`` — the same table the
    Price-List-API-backed pricing service falls back to — as the single
    source of truth, rather than a second copy that could drift from it.
    Imported lazily to avoid a module-load-order dependency on
    ``aws_pricing_service`` from this low-level models module.
    """
    if not region:
        return 1.0
    from cloudwise_scan_core.aws_pricing_service import AWSPricingService

    return AWSPricingService.REGION_PRICE_MULTIPLIERS.get(
        region, AWSPricingService.DEFAULT_REGION_MULTIPLIER
    )


def get_ec2_monthly_cost(instance_type: str, region: Optional[str] = None) -> float:
    """Get estimated monthly cost for an EC2 instance type, region-scaled (CLO-359)."""
    hourly = EC2_PRICING.get(instance_type, 0.10)  # Default to $0.10/hr
    hourly *= _region_price_multiplier(region)
    return hourly * 730  # Hours per month


def get_ebs_monthly_cost(
    volume_type: str, size_gb: int, iops: int = 0, region: Optional[str] = None
) -> float:
    """Get estimated monthly cost for an EBS volume, region-scaled (CLO-359)."""
    mult = _region_price_multiplier(region)
    base_cost = EBS_PRICING.get(volume_type, 0.10) * mult * size_gb

    # Add IOPS cost for io1/io2 (CLO-975: io2 in its tiers, as the
    # over-provisioned-IOPS check prices it; it was a flat 0.065 here)
    if volume_type in ("io1", "io2") and iops > 0:
        base_cost += provisioned_iops_monthly_cost(volume_type, iops) * mult

    return base_cost


def rds_hourly_price(instance_class: Optional[str]) -> Optional[float]:
    """us-east-1 on-demand hourly price of an RDS instance class, or None.

    CLO-975 item 5: an unknown class has no price. It used to read as $0.10
    an hour ($73 a month), which is wrong for nearly every class a database
    actually runs on; callers now skip the saving and say the price is unknown.
    """
    return RDS_PRICING.get(instance_class or "")


def get_rds_monthly_cost(
    instance_class: str, multi_az: bool = False, region: Optional[str] = None
) -> Optional[float]:
    """Estimated monthly cost for an RDS instance, region-scaled (CLO-359), or
    None when the instance class is not in ``RDS_PRICING`` (CLO-975: price
    unknown, saving not estimated; there is no default price)."""
    hourly = rds_hourly_price(instance_class)
    if hourly is None:
        return None
    hourly *= _region_price_multiplier(region)
    monthly = hourly * 730

    if multi_az:
        monthly *= 2  # Multi-AZ doubles the cost

    return monthly


def get_eip_monthly_cost(region: Optional[str] = None) -> float:
    """Monthly cost of one public IPv4 address (CLO-1036 item 1).

    The same in every commercial region: the AWS Price List (AmazonVPC,
    PublicIPv4:IdleAddress and :InUseAddress, publication 2026-11-05) lists
    $0.005 an hour in us-east-1, eu-west-1, sa-east-1 and ap-southeast-2, and
    (read 2026-11-15, per-region index files, same publication) in every
    opt-in commercial region: af-south-1, ap-east-1, ap-east-2, ap-south-2,
    ap-southeast-3, -4, -5 and -7, ca-west-1, eu-central-2, eu-south-1,
    eu-south-2, il-central-1, me-central-1, me-south-1 and mx-central-1, plus
    us-gov-east-1 and us-gov-west-1. The public file has no China region
    (cn-north-1, cn-northwest-1; China bills in CNY). A hosted scan cannot
    reach GovCloud or China: the role ARN must start ``arn:aws:iam::``
    (backend/app/models/aws.py, models/user.py, endpoints/aws_accounts.py), and
    GovCloud and China role ARNs start ``arn:aws-us-gov:`` and ``arn:aws-cn:``.
    It used to be scaled by the region multiplier (CLO-359), which overstated the
    saving outside the US ($5.29 in sa-east-1). ``region`` is accepted for
    callers' sake and ignored.
    """
    return EIP_MONTHLY_COST
