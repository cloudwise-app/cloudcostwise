"""GENERATED FILE - DO NOT EDIT (CLO-432).

Source of truth: docs/waste-audit/ledger.yaml. Regenerate with:
    python docs/waste-audit/raw/build_ledger_md.py

Each non-deprecated waste type's validation state, as a finding's
``validation`` field carries it (CONTEXT.md):

- ``advisory``: cannot reach L2 within the fixture budget. Shown to
  customers as informational and kept out of the headline savings total.
- ``trusted``: every ledger row of the type is at L2 or above.
- ``unvalidated``: neither yet (L0/L1 with a path to L2).

A waste type the ledger does not know (deprecated, ``other``, empty or
misspelled) has NO validation state: :func:`validation_for` returns
None rather than guessing, so the gap is visible (MISSING, not zero).
"""
from __future__ import annotations

from typing import Dict, Optional

ADVISORY = "advisory"
TRUSTED = "trusted"
UNVALIDATED = "unvalidated"

# No path to L2 within budget.
ADVISORY_WASTE_TYPES: frozenset[str] = frozenset({
    "appsync_idle_cache",
    "aurora_io_optimization_opportunity",
    "aurora_serverless_opportunity",
    "convertible_ri_exchange_opportunity",
    "cur_savings_plan_waste",
    "cur_unused_reservation",
    "documentdb_extended_support_cost",
    "emr_over_provisioned",
    "expiring_reserved_instance",
    "expiring_savings_plan",
    "glue_catalog_bloat",
    "high_lcu_cost_alb",
    "idle_global_accelerator",
    "idle_redshift",
    "idle_transfer_no_activity",
    "idle_transfer_server",
    "idle_transfer_web_app",
    "idle_workspace",
    "kinesis_on_demand_downgrade",
    "long_running_emr",
    "oversized_redshift",
    "redshift_concurrency_scaling_waste",
    "redshift_legacy_dc2",
    "redshift_no_pause",
    "redshift_spectrum_heavy",
    "redshift_wlm_over_provisioned",
    "ri_opportunity_ec2",
    "ri_opportunity_elasticache",
    "ri_opportunity_opensearch",
    "ri_opportunity_rds",
    "ri_opportunity_redshift",
    "s3_high_request_and_transfer_cost",
    "s3_no_default_encryption",
    "savings_plan_coverage_gap",
    "sp_opportunity_compute",
    "sp_opportunity_ec2",
    "sp_opportunity_sagemaker",
    "underutilized_redshift",
    "unused_accelerator",
    "unused_reserved_instance",
    "unused_savings_plan",
    "unused_transfer_protocol",
    "workspaces_pool_overprovisioned_capacity",
    "workspaces_windows_license_optimization",
})

# Every row at L2 or above.
TRUSTED_WASTE_TYPES: frozenset[str] = frozenset({
    "ami_orphaned_snapshot",
    "appsync_idle_subscriptions",
    "backup_no_lifecycle_tiering",
    "classic_lb_migration",
    "duplicate_cloudtrail",
    "dynamodb_no_autoscaling",
    "dynamodb_no_deletion_protection",
    "ecr_no_lifecycle_policy",
    "ecs_container_insights_waste",
    "ecs_no_autoscaling",
    "eip_on_stopped_instance",
    "elasticache_engine_migration",
    "elasticache_extended_support_cost",
    "elasticache_replication_waste",
    "empty_log_group",
    "excessive_retention_log_group",
    "failed_glue_job_retry",
    "glue_job_missing_timeout",
    "gp2_migration",
    "idle_beanstalk",
    "idle_documentdb",
    "idle_dynamodb",
    "idle_ecs_service",
    "idle_efs",
    "idle_fsx",
    "idle_load_balancer",
    "idle_state_machine",
    "kinesis_firehose_idle",
    "lambda_arm64_migration",
    "lambda_excessive_timeout",
    "lambda_old_runtime",
    "lambda_provisioned_concurrency_idle",
    "lightsail_idle_database",
    "lightsail_idle_load_balancer",
    "lightsail_unattached_disk",
    "lightsail_unattached_static_ip",
    "low_traffic_alb",
    "multiple_eips_per_instance",
    "no_lifecycle_efs",
    "no_lifecycle_policy",
    "no_retention_log_group",
    "old_ecr_images",
    "old_glue_job",
    "opensearch_no_encryption_at_rest",
    "orphaned_dns_record",
    "orphaned_ebs_snapshot",
    "over_provisioned_dynamodb",
    "over_provisioned_lambda",
    "oversized_glue_job",
    "oversized_sagemaker_endpoint",
    "previous_gen_sagemaker_instance",
    "rds_no_deletion_protection",
    "rds_publicly_accessible",
    "redundant_backup",
    "resource_without_backup_coverage",
    "s3_empty_bucket",
    "s3_wrong_storage_class",
    "stale_backup_plan_assignment",
    "step_functions_express_duration_waste",
    "step_functions_high_transition_density",
    "step_functions_retry_storm",
    "stopped_ec2_with_ebs",
    "unattached_ebs",
    "unattached_eip",
    "unencrypted_documentdb_cluster",
    "unencrypted_ebs_volume",
    "unencrypted_efs_filesystem",
    "unencrypted_rds_instance",
    "untagged_ecr_images",
    "unused_appsync",
    "unused_distribution",
    "unused_hosted_zone",
    "unused_kms_key",
})

# L0/L1 with a path to L2.
UNVALIDATED_WASTE_TYPES: frozenset[str] = frozenset({
    "aurora_extended_support_cost",
    "aurora_to_rds_downgrade_opportunity",
    "backup_copy_policy_overreach",
    "beanstalk_idle_traffic",
    "beanstalk_orphaned_rds",
    "beanstalk_over_provisioned",
    "beanstalk_previous_gen_instances",
    "beanstalk_unnecessary_alb",
    "cloudtrail_s3_no_lifecycle",
    "disabled_global_accelerator",
    "eks_extended_support_cost",
    "elasticache_data_tiering_opportunity",
    "elasticache_serverless_optimization",
    "emr_missing_auto_termination",
    "emr_previous_gen_instances",
    "emr_spot_opportunity",
    "fsx_throughput_overprovisioned",
    "idle_ec2",
    "idle_elasticache",
    "idle_emr_cluster",
    "idle_glue_crawler",
    "idle_kinesis_stream",
    "idle_lightsail",
    "idle_mq_broker",
    "idle_msk_cluster",
    "idle_nat_gateway",
    "idle_neptune",
    "idle_opensearch",
    "idle_rds",
    "idle_sagemaker_endpoint",
    "idle_sagemaker_notebook",
    "incomplete_multipart",
    "kinesis_enhanced_fan_out_waste",
    "kinesis_extended_retention_waste",
    "lightsail_old_snapshot",
    "neptune_old_snapshot",
    "neptune_serverless_opportunity",
    "old_backup",
    "old_documentdb_snapshot",
    "old_ebs_snapshot",
    "old_fsx_backup",
    "old_log_group",
    "old_rds_snapshot",
    "opensearch_ebs_overprovisioned",
    "opensearch_extended_support_cost",
    "over_provisioned_iops",
    "over_provisioned_kinesis",
    "overprovisioned_documentdb",
    "oversized_ebs_optimizer",
    "oversized_ec2_optimizer",
    "oversized_ecs_memory",
    "oversized_ecs_task",
    "oversized_elasticache",
    "oversized_fsx",
    "oversized_lambda_optimizer",
    "oversized_mq_broker",
    "oversized_msk_cluster",
    "oversized_neptune",
    "oversized_opensearch",
    "oversized_rds_optimizer",
    "oversized_workspace",
    "rds_extended_support_cost",
    "s3_rapid_growth",
    "stopped_sagemaker_notebook_storage",
    "unused_api_gateway",
    "unused_dashboard",
    "unused_lambda",
    "unused_secret",
    "unused_vpc_endpoint",
    "workspaces_autostop_opportunity",
})

# Why each advisory type is advisory (ledger `advisory_reason`).
ADVISORY_REASONS: Dict[str, str] = {
    "appsync_idle_cache": "over_budget",
    "aurora_io_optimization_opportunity": "over_budget",
    "aurora_serverless_opportunity": "over_budget",
    "convertible_ri_exchange_opportunity": "commitment",
    "cur_savings_plan_waste": "commitment",
    "cur_unused_reservation": "commitment",
    "documentdb_extended_support_cost": "retired_config",
    "emr_over_provisioned": "over_budget",
    "expiring_reserved_instance": "commitment",
    "expiring_savings_plan": "commitment",
    "glue_catalog_bloat": "over_budget",
    "high_lcu_cost_alb": "over_budget",
    "idle_global_accelerator": "over_budget",
    "idle_redshift": "over_budget",
    "idle_transfer_no_activity": "over_budget",
    "idle_transfer_server": "over_budget",
    "idle_transfer_web_app": "over_budget",
    "idle_workspace": "over_budget",
    "kinesis_on_demand_downgrade": "over_budget",
    "long_running_emr": "over_budget",
    "oversized_redshift": "over_budget",
    "redshift_concurrency_scaling_waste": "over_budget",
    "redshift_legacy_dc2": "retired_config",
    "redshift_no_pause": "over_budget",
    "redshift_spectrum_heavy": "over_budget",
    "redshift_wlm_over_provisioned": "over_budget",
    "ri_opportunity_ec2": "commitment",
    "ri_opportunity_elasticache": "commitment",
    "ri_opportunity_opensearch": "commitment",
    "ri_opportunity_rds": "commitment",
    "ri_opportunity_redshift": "commitment",
    "s3_high_request_and_transfer_cost": "over_budget",
    "s3_no_default_encryption": "retired_config",
    "savings_plan_coverage_gap": "commitment",
    "sp_opportunity_compute": "commitment",
    "sp_opportunity_ec2": "commitment",
    "sp_opportunity_sagemaker": "commitment",
    "underutilized_redshift": "over_budget",
    "unused_accelerator": "over_budget",
    "unused_reserved_instance": "commitment",
    "unused_savings_plan": "commitment",
    "unused_transfer_protocol": "over_budget",
    "workspaces_pool_overprovisioned_capacity": "over_budget",
    "workspaces_windows_license_optimization": "over_budget",
}


def validation_for(waste_type: object) -> Optional[str]:
    """Return ``"advisory"``, ``"trusted"``, ``"unvalidated"``, or None.

    Accepts a ``WasteType`` member or its string value. None means the
    ledger has no row for this type; callers must pass that through as
    missing, never default it to one of the three states.
    """
    value = getattr(waste_type, "value", waste_type)
    if not isinstance(value, str) or not value:
        return None
    if value in ADVISORY_WASTE_TYPES:
        return ADVISORY
    if value in TRUSTED_WASTE_TYPES:
        return TRUSTED
    if value in UNVALIDATED_WASTE_TYPES:
        return UNVALIDATED
    return None
