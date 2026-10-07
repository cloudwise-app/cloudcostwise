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

Summary for the checks in this repository: 38 at L1, 42 at L2, 7 at L3.

This code was written with AI assistance and is validated against real AWS
resources as described above; the levels below are the evidence.

| Waste type | Level | Advisory |
|---|---|---|
| `ami_orphaned_snapshot` | L2 |  |
| `classic_lb_migration` | L2 |  |
| `dynamodb_no_autoscaling` | L2 |  |
| `dynamodb_no_deletion_protection` | L3 |  |
| `ecr_no_lifecycle_policy` | L2 |  |
| `eip_on_stopped_instance` | L2 |  |
| `elasticache_data_tiering_opportunity` | L1 |  |
| `elasticache_engine_migration` | L2 |  |
| `elasticache_extended_support_cost` | L2 |  |
| `elasticache_replication_waste` | L2 |  |
| `elasticache_serverless_optimization` | L1 |  |
| `empty_log_group` | L2 |  |
| `excessive_retention_log_group` | L2 |  |
| `gp2_migration` | L3 |  |
| `high_lcu_cost_alb` | L1 | yes |
| `idle_dynamodb` | L2 |  |
| `idle_ec2` | L1 |  |
| `idle_efs` | L2 |  |
| `idle_elasticache` | L1 |  |
| `idle_lightsail` | L1 |  |
| `idle_load_balancer` | L2 |  |
| `idle_nat_gateway` | L1 |  |
| `idle_rds` | L1 |  |
| `idle_sagemaker_endpoint` | L1 |  |
| `idle_sagemaker_notebook` | L1 |  |
| `idle_workspace` | L1 | yes |
| `incomplete_multipart` | L1 |  |
| `lambda_arm64_migration` | L2 |  |
| `lambda_excessive_timeout` | L2 |  |
| `lambda_old_runtime` | L2 |  |
| `lambda_provisioned_concurrency_idle` | L2 |  |
| `lightsail_idle_database` | L2 |  |
| `lightsail_idle_load_balancer` | L2 |  |
| `lightsail_old_snapshot` | L1 |  |
| `lightsail_unattached_disk` | L2 |  |
| `lightsail_unattached_static_ip` | L2 |  |
| `low_traffic_alb` | L2 |  |
| `multiple_eips_per_instance` | L2 |  |
| `no_lifecycle_efs` | L2 |  |
| `no_lifecycle_policy` | L2 |  |
| `no_retention_log_group` | L2 |  |
| `old_ebs_snapshot` | L1 |  |
| `old_ecr_images` | L3 |  |
| `old_log_group` | L1 |  |
| `old_rds_snapshot` | L1 |  |
| `opensearch_no_encryption_at_rest` | L2 |  |
| `orphaned_dns_record` | L3 |  |
| `orphaned_ebs_snapshot` | L2 |  |
| `over_provisioned_dynamodb` | L2 |  |
| `over_provisioned_iops` | L1 |  |
| `over_provisioned_lambda` | L2 |  |
| `oversized_elasticache` | L1 |  |
| `oversized_sagemaker_endpoint` | L2 |  |
| `oversized_workspace` | L1 |  |
| `previous_gen_sagemaker_instance` | L2 |  |
| `rds_extended_support_cost` | L1 |  |
| `rds_no_deletion_protection` | L2 |  |
| `rds_publicly_accessible` | L2 |  |
| `resource_without_backup_coverage` | L3 |  |
| `ri_opportunity_ec2` | L1 | yes |
| `ri_opportunity_elasticache` | L1 | yes |
| `ri_opportunity_opensearch` | L1 | yes |
| `ri_opportunity_rds` | L1 | yes |
| `ri_opportunity_redshift` | L1 | yes |
| `s3_empty_bucket` | L2 |  |
| `s3_high_request_and_transfer_cost` | L1 | yes |
| `s3_no_default_encryption` | L1 | yes |
| `s3_rapid_growth` | L1 |  |
| `s3_wrong_storage_class` | L2 |  |
| `sp_opportunity_compute` | L1 | yes |
| `sp_opportunity_ec2` | L1 | yes |
| `sp_opportunity_sagemaker` | L1 | yes |
| `stopped_ec2_with_ebs` | L2 |  |
| `stopped_sagemaker_notebook_storage` | L1 |  |
| `unattached_ebs` | L3 |  |
| `unattached_eip` | L3 |  |
| `unencrypted_documentdb_cluster` | L2 |  |
| `unencrypted_ebs_volume` | L2 |  |
| `unencrypted_efs_filesystem` | L2 |  |
| `unencrypted_rds_instance` | L2 |  |
| `untagged_ecr_images` | L2 |  |
| `unused_dashboard` | L1 |  |
| `unused_lambda` | L1 |  |
| `unused_vpc_endpoint` | L1 |  |
| `workspaces_autostop_opportunity` | L1 |  |
| `workspaces_pool_overprovisioned_capacity` | L1 | yes |
| `workspaces_windows_license_optimization` | L1 | yes |
