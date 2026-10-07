# How we know the checks are right

Every waste type this tool can report is tracked in CloudWise's validation
ledger, which records how far each one has been proven:

| Level | Meaning |
|---|---|
| L0 | Unit-tested against synthetic AWS data |
| L1 | Desk-reviewed against current AWS documentation and pricing |
| L2 | Fired on a real AWS resource built to trigger it, and stayed silent on a healthy twin |
| L3 | Its finding rendered correctly in the CloudWise product |
| L4 | Its fix was executed or rolled back against that real resource |

**Advisory** waste types could not be proven at L2 within our test budget. They are
shown, labelled, and never added to a savings total.

Summary for the checks in this repository: 42 at L1, 42 at L2, 7 at L3.

This code was written with AI assistance and is validated against real AWS
resources as described above; the levels below are the evidence.

The last column says whether AWS's own tools (Trusted Advisor, Cost Optimization Hub,
Compute Optimizer) flag the same waste: none, partial or covered. It is recorded for
proven checks only.

| Waste type | Level | Advisory | Flagged by AWS's tools |
|---|---|---|---|
| `ami_orphaned_snapshot` | L2 |  | none |
| `classic_lb_migration` | L2 |  | none |
| `dynamodb_no_autoscaling` | L2 |  |  |
| `dynamodb_no_deletion_protection` | L3 |  | covered |
| `ecr_no_lifecycle_policy` | L2 |  | covered |
| `eip_on_stopped_instance` | L2 |  | covered |
| `elasticache_data_tiering_opportunity` | L1 |  |  |
| `elasticache_engine_migration` | L2 |  | none |
| `elasticache_extended_support_cost` | L2 |  | none |
| `elasticache_replication_waste` | L2 |  |  |
| `elasticache_serverless_optimization` | L1 |  |  |
| `empty_log_group` | L2 |  | none |
| `excessive_retention_log_group` | L2 |  | partial |
| `gp2_migration` | L3 |  |  |
| `high_lcu_cost_alb` | L1 | yes |  |
| `idle_dynamodb` | L2 |  | covered |
| `idle_ec2` | L1 |  |  |
| `idle_efs` | L2 |  | partial |
| `idle_elasticache` | L1 |  |  |
| `idle_lightsail` | L1 |  |  |
| `idle_load_balancer` | L2 |  | partial |
| `idle_nat_gateway` | L1 |  |  |
| `idle_rds` | L1 |  |  |
| `idle_sagemaker_endpoint` | L1 |  |  |
| `idle_sagemaker_notebook` | L1 |  |  |
| `idle_workspace` | L1 | yes |  |
| `incomplete_multipart` | L1 |  |  |
| `lambda_arm64_migration` | L2 |  | none |
| `lambda_excessive_timeout` | L2 |  | partial |
| `lambda_old_runtime` | L2 |  | covered |
| `lambda_provisioned_concurrency_idle` | L2 |  | none |
| `lightsail_idle_database` | L2 |  |  |
| `lightsail_idle_load_balancer` | L2 |  | none |
| `lightsail_old_snapshot` | L1 |  |  |
| `lightsail_unattached_disk` | L2 |  | none |
| `lightsail_unattached_static_ip` | L2 |  | none |
| `low_traffic_alb` | L2 |  | none |
| `multiple_eips_per_instance` | L2 |  | none |
| `no_lifecycle_efs` | L2 |  | none |
| `no_lifecycle_policy` | L2 |  | covered |
| `no_retention_log_group` | L2 |  | partial |
| `old_ebs_snapshot` | L1 |  |  |
| `old_ecr_images` | L3 |  | partial |
| `old_log_group` | L1 |  |  |
| `old_rds_snapshot` | L1 |  |  |
| `opensearch_no_encryption_at_rest` | L2 |  | covered |
| `orphaned_dns_record` | L3 |  |  |
| `orphaned_ebs_snapshot` | L2 |  |  |
| `over_provisioned_dynamodb` | L2 |  |  |
| `over_provisioned_iops` | L1 |  |  |
| `over_provisioned_lambda` | L2 |  | covered |
| `oversized_ebs_optimizer` | L1 |  |  |
| `oversized_ec2_optimizer` | L1 |  |  |
| `oversized_elasticache` | L1 |  |  |
| `oversized_lambda_optimizer` | L1 |  |  |
| `oversized_rds_optimizer` | L1 |  |  |
| `oversized_sagemaker_endpoint` | L2 |  | partial |
| `oversized_workspace` | L1 |  |  |
| `previous_gen_sagemaker_instance` | L2 |  | none |
| `rds_extended_support_cost` | L1 |  |  |
| `rds_no_deletion_protection` | L2 |  | covered |
| `rds_publicly_accessible` | L2 |  | covered |
| `resource_without_backup_coverage` | L3 |  | covered |
| `ri_opportunity_ec2` | L1 | yes |  |
| `ri_opportunity_elasticache` | L1 | yes |  |
| `ri_opportunity_opensearch` | L1 | yes |  |
| `ri_opportunity_rds` | L1 | yes |  |
| `ri_opportunity_redshift` | L1 | yes |  |
| `s3_empty_bucket` | L2 |  | none |
| `s3_high_request_and_transfer_cost` | L1 | yes |  |
| `s3_no_default_encryption` | L1 | yes |  |
| `s3_rapid_growth` | L1 |  |  |
| `s3_wrong_storage_class` | L2 |  | partial |
| `sp_opportunity_compute` | L1 | yes |  |
| `sp_opportunity_ec2` | L1 | yes |  |
| `sp_opportunity_sagemaker` | L1 | yes |  |
| `stopped_ec2_with_ebs` | L2 |  | covered |
| `stopped_sagemaker_notebook_storage` | L1 |  |  |
| `unattached_ebs` | L3 |  | covered |
| `unattached_eip` | L3 |  | covered |
| `unencrypted_documentdb_cluster` | L2 |  | covered |
| `unencrypted_ebs_volume` | L2 |  | covered |
| `unencrypted_efs_filesystem` | L2 |  | covered |
| `unencrypted_rds_instance` | L2 |  | covered |
| `untagged_ecr_images` | L2 |  | partial |
| `unused_dashboard` | L1 |  |  |
| `unused_lambda` | L1 |  |  |
| `unused_vpc_endpoint` | L1 |  |  |
| `workspaces_autostop_opportunity` | L1 |  |  |
| `workspaces_pool_overprovisioned_capacity` | L1 | yes |  |
| `workspaces_windows_license_optimization` | L1 | yes |  |
