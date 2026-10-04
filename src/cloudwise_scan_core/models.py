"""
Waste Detection Data Models

Defines the data structures for waste detection results, settings, and configurations.
These models are used throughout the waste detection service.
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    REDSHIFT_SPECTRUM_HEAVY = "redshift_spectrum_heavy"
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
    WasteType.BACKUP_COPY_POLICY_OVERREACH, # which copies are unneeded is a DR call
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
    redshift_spectrum_cost_ratio_threshold: float = 50.0    # % Spectrum cost vs compute for migration
    
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
            "redshift_spectrum_cost_ratio_threshold": self.redshift_spectrum_cost_ratio_threshold,
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
            redshift_spectrum_cost_ratio_threshold=data.get("redshift_spectrum_cost_ratio_threshold", 50.0),
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
    # Per GB-month pricing (US East)
    "gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125,
    "st1": 0.045, "sc1": 0.025, "standard": 0.05,
}

RDS_PRICING = {
    # On-Demand hourly pricing (US East) - monthly = hourly * 730
    "db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068,
    "db.t3.large": 0.136, "db.t3.xlarge": 0.272, "db.t3.2xlarge": 0.544,
    "db.m5.large": 0.171, "db.m5.xlarge": 0.342, "db.m5.2xlarge": 0.684,
    "db.m6i.large": 0.171, "db.m6i.xlarge": 0.342, "db.m6i.2xlarge": 0.684,
    "db.r5.large": 0.24, "db.r5.xlarge": 0.48, "db.r5.2xlarge": 0.96,
}

# Fixed monthly costs
EIP_MONTHLY_COST = 3.65  # Unattached EIP
NAT_GATEWAY_MONTHLY_BASE = 32.40  # NAT Gateway base cost (+ data transfer)
ALB_MONTHLY_BASE = 16.20  # ALB base cost (+ LCU hours)
NLB_MONTHLY_BASE = 16.20  # NLB base cost (+ LCU hours)
CLB_MONTHLY_BASE = 18.25  # Classic LB base cost ($0.025/hr × 730 hrs)
ALB_LCU_HOURLY = 0.008    # ALB LCU-hour rate (us-east-1)
NLB_NLCU_HOURLY = 0.006   # NLB NLCU-hour rate (us-east-1)
VPC_ENDPOINT_MONTHLY = 7.20  # Per AZ per month

# S3 pricing constants (us-east-1, first 50 TB tier)
S3_STANDARD_PER_GB = 0.023        # S3 Standard per GB-month
S3_IT_MONITORING_PER_1K = 0.0025  # Intelligent-Tiering monitoring fee per 1,000 objects


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

    # Add IOPS cost for io1/io2
    if volume_type in ("io1", "io2") and iops > 0:
        base_cost += iops * 0.065 * mult  # Per provisioned IOPS-month

    return base_cost


def get_rds_monthly_cost(
    instance_class: str, multi_az: bool = False, region: Optional[str] = None
) -> float:
    """Get estimated monthly cost for an RDS instance, region-scaled (CLO-359)."""
    hourly = RDS_PRICING.get(instance_class, 0.10)  # Default to $0.10/hr
    hourly *= _region_price_multiplier(region)
    monthly = hourly * 730

    if multi_az:
        monthly *= 2  # Multi-AZ doubles the cost

    return monthly


def get_eip_monthly_cost(region: Optional[str] = None) -> float:
    """Get estimated monthly cost for an idle/unattached Elastic IP, region-scaled (CLO-359)."""
    return EIP_MONTHLY_COST * _region_price_multiplier(region)
