"""Detection thresholds as metadata, for the open-core waste types (CLO-700).

Every number that decides whether an open waste type fires (a lookback
window, a utilization cut-off, a minimum age, a minimum size) is declared here
once, by REFERENCE: ``source`` names the module constant or the
``WasteDetectionSettings`` field the detector reads, never a copy of its value.
:func:`threshold_value` resolves the reference at call time, so this file
cannot drift from the code by holding a stale number.

Two consumers keep the declaration honest:

* ``tests/test_detection_thresholds.py`` checks, for every entry, that each
  function named in ``used_in`` really reads ``source`` (an AST check of the
  method both the open and the hosted service resolve), so a detector that
  stops using a declared value, or a value declared against the wrong
  detector, fails the build.
* ``scripts/render_detection_thresholds.py`` writes the resolved values into
  ``docs-site/docs/waste-detection.md`` between
  ``<!-- threshold:<waste_type>.<key> -->`` markers, and ``--check`` fails when
  the page is stale, when a marker names an unknown key, or when a declared
  threshold is not stated on the page.

A waste type with no numeric threshold (a binary check such as "volume is
unattached") is declared with an empty tuple, so "every open type is covered"
is a checkable statement.

Closed (hosted-only) waste types are declared in
``cloudwise_scan_core.detectors.thresholds``, which this module never imports.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Dict, Mapping, Tuple, Union

PACKAGE = "cloudwise_scan_core"

# How a value is shown on the docs page. "fraction" values are stored as 0..1
# and shown as a percentage number; "headroom" is a multiplier (1.30) shown as
# the percentage it adds (30); every other unit is shown as stored.
UNITS = frozenset({
    "days", "hours", "seconds", "ms", "percent", "fraction", "headroom",
    "count", "MB", "GB", "ratio", "USD",
})


@dataclass(frozen=True)
class Threshold:
    """One named number a detector compares against.

    key:     stable id, unique within the waste type; docs markers use
             ``<waste_type>.<key>``.
    label:   what the number means, in plain words.
    source:  ``settings.<field>`` (a ``WasteDetectionSettings`` default; a
             runtime may override it per account) or ``<module>.<NAME>``
             relative to the ``cloudwise_scan_core`` package.
    unit:    one of ``UNITS``.
    used_in: the detector methods (resolved on the service class) or
             ``<module>:<function>`` helpers that read ``source``.
    """

    key: str
    label: str
    source: str
    unit: str
    used_in: Tuple[str, ...]


def _t(key: str, label: str, source: str, unit: str, *used_in: str) -> Threshold:
    return Threshold(key, label, source, unit, tuple(used_in))


def threshold_value(source: str) -> Union[int, float]:
    """Resolve a ``source`` reference to the value the code holds today."""
    if source.startswith("settings."):
        from cloudwise_scan_core.models import WasteDetectionSettings

        return getattr(WasteDetectionSettings.get_defaults(), source[len("settings."):])
    parts = source.split(".")
    # The longest importable module prefix, then attributes (a class constant
    # such as ``detectors.open.compute.OpenComputeDetectorsMixin.X``).
    for i in range(len(parts) - 1, 0, -1):
        try:
            obj = importlib.import_module(".".join([PACKAGE, *parts[:i]]))
        except ModuleNotFoundError:
            continue
        for attr in parts[i:]:
            obj = getattr(obj, attr)
        return obj
    raise ValueError(f"unresolvable threshold source: {source}")


def source_name(source: str) -> str:
    """The identifier a reading function must mention: the settings field or the constant."""
    return source.rpartition(".")[2]


def format_value(value: Union[int, float], unit: str) -> str:
    """The number as the docs page shows it: no trailing ``.0``, thousands separated,
    a ``fraction`` shown as a percentage."""
    if unit == "fraction":
        value = round(value * 100, 6)
    elif unit == "headroom":
        value = round((value - 1) * 100, 6)
    if float(value).is_integer():
        return f"{int(value):,}"
    return f"{value:,}".rstrip("0").rstrip(".")


_OC = "detectors.open.compute"
_OS = "detectors.open.storage"
_ODB = "detectors.open.database"
_ON = "detectors.open.network"
_OM = "detectors.open.management"
_OOPT = "detectors.open.optimizer"
_OSV = "detectors.open.savings"
_BASE = "data_providers.base"
_COMPUTE_MIXIN = f"{_OC}.OpenComputeDetectorsMixin"
# An Air-Gapped export carries its own CloudWatch window; this is the default
# when the export's manifest does not name one.
_OFFLINE_WINDOW = "data_providers.offline.OfflineDataProvider.DEFAULT_EXPORT_CLOUDWATCH_DAYS"
_OFFLINE_WINDOW_USE = "data_providers.offline:OfflineDataProvider._export_cloudwatch_days"
_ONLINE = "data_providers.online:OnlineDataProvider"

OPEN_THRESHOLDS: Mapping[str, Tuple[Threshold, ...]] = {
    # ── Compute ──────────────────────────────────────────────────────────
    "idle_ec2": (
        _t("avg_cpu_pct", "average CPU below this is idle", "settings.ec2_idle_cpu_threshold", "percent", "_detect_ec2_waste"),
        _t("window_days", "hourly CPU window and minimum instance age", "settings.ec2_idle_days", "days", "_detect_ec2_waste"),
        _t("window_days_air_gapped", "default Air-Gapped export window", _OFFLINE_WINDOW, "days", _OFFLINE_WINDOW_USE),
        _t("coverage_pct", "share of the window's hours that must have data", "cpu_sizing.MIN_CPU_COVERAGE", "fraction",
           "cpu_sizing:has_min_coverage"),
        _t("percentile", "percentile of hourly values the sustained-peak checks read", "cpu_sizing.CPU_PERCENTILE", "percent",
           "cpu_sizing:summarize_hourly_cpu"),
        _t("p95_avg_cpu_pct", "p95 of hourly average CPU below", "cpu_sizing.EC2_IDLE_P95_AVG_CPU_THRESHOLD", "percent",
           "cpu_sizing:ec2_cpu_is_idle"),
        _t("p95_max_cpu_pct", "p95 of hourly peak CPU below", "cpu_sizing.EC2_IDLE_P95_MAX_CPU_THRESHOLD", "percent",
           "cpu_sizing:ec2_cpu_is_idle"),
        _t("max_cpu_pct", "no hourly peak at or above", "cpu_sizing.EC2_IDLE_MAX_CPU_THRESHOLD", "percent",
           "cpu_sizing:ec2_cpu_is_idle"),
    ),
    "stopped_ec2_with_ebs": (),
    "unused_lambda": (
        _t("window_days", "Invocations window", f"{_OC}.LAMBDA_METRIC_WINDOW_DAYS", "days", "_detect_lambda_waste"),
        _t("min_age_days", "minimum days since the function last changed", f"{_OC}.UNUSED_LAMBDA_MIN_AGE_DAYS", "days",
           "_detect_lambda_waste"),
    ),
    "over_provisioned_lambda": (
        _t("min_memory_mb", "configured memory at least", f"{_OC}.OVER_PROVISIONED_LAMBDA_MIN_MEMORY_MB", "MB", "_detect_lambda_waste"),
        _t("max_avg_duration_ms", "average duration under", f"{_OC}.OVER_PROVISIONED_LAMBDA_MAX_AVG_DURATION_MS", "ms",
           "_detect_lambda_waste"),
        _t("window_days", "Duration window", f"{_OC}.LAMBDA_METRIC_WINDOW_DAYS", "days", "_detect_lambda_waste"),
    ),
    "lambda_provisioned_concurrency_idle": (
        _t("idle_pct", "average utilization below this is idle", f"{_OC}.PROVISIONED_CONCURRENCY_IDLE_PCT", "percent",
           "_detect_lambda_waste"),
        _t("window_days", "ProvisionedConcurrencyUtilization window", f"{_BASE}.PROVISIONED_CONCURRENCY_WINDOW_DAYS", "days",
           f"{_ONLINE}._pc_utilization"),
    ),
    "lambda_excessive_timeout": (
        _t("min_ratio", "timeout at least this multiple of the average duration", f"{_OC}.LAMBDA_TIMEOUT_MIN_RATIO", "ratio",
           "_detect_lambda_waste"),
        _t("longest_run_multiple", "recommended timeout is this multiple of the longest run",
           f"{_COMPUTE_MIXIN}.LAMBDA_TIMEOUT_MAX_MULTIPLIER", "ratio", "_detect_lambda_waste"),
        _t("floor_seconds", "recommended timeout is never below", f"{_COMPUTE_MIXIN}.LAMBDA_TIMEOUT_FLOOR_SECONDS", "seconds",
           "_detect_lambda_waste"),
        _t("min_invocations", "more invocations than this in the window", f"{_OC}.LAMBDA_TIMEOUT_MIN_INVOCATIONS", "count",
           "_detect_lambda_waste"),
        _t("min_timeout_seconds", "configured timeout at least", f"{_OC}.LAMBDA_TIMEOUT_MIN_SECONDS", "seconds", "_detect_lambda_waste"),
        _t("window_days", "Duration window", f"{_OC}.LAMBDA_METRIC_WINDOW_DAYS", "days", "_detect_lambda_waste"),
    ),
    "lambda_arm64_migration": (),
    "lambda_old_runtime": (),
    "idle_lightsail": (
        _t("avg_cpu_pct", "average CPU below this is idle", f"{_OC}.LIGHTSAIL_IDLE_CPU_PCT", "percent", "_detect_lightsail_idle_instances"),
        _t("window_days", "hourly CPU window", f"{_BASE}.LIGHTSAIL_METRIC_WINDOW_DAYS", "days", f"{_ONLINE}.get_lightsail_metrics"),
        _t("window_days_air_gapped", "default Air-Gapped export window", _OFFLINE_WINDOW, "days", _OFFLINE_WINDOW_USE),
        _t("coverage_pct", "share of the window's hours that must have data", f"{_OC}._MIN_COVERAGE", "fraction",
           f"{_OC}:lightsail_cpu_covers_window"),
    ),
    "lightsail_unattached_static_ip": (),
    "lightsail_unattached_disk": (),
    "lightsail_old_snapshot": (
        _t("max_age_days", "manual snapshots older than", f"{_OC}.LIGHTSAIL_SNAPSHOT_MAX_AGE_DAYS", "days", "_detect_lightsail_old_snapshots"),
    ),
    "lightsail_idle_load_balancer": (),
    "lightsail_idle_database": (
        _t("avg_cpu_pct", "average CPU below", f"{_OC}.LIGHTSAIL_IDLE_CPU_PCT", "percent", "_detect_lightsail_idle_databases"),
        _t("max_avg_connections", "average connections below", f"{_OC}.LIGHTSAIL_DB_IDLE_MAX_CONNECTIONS", "count",
           "_detect_lightsail_idle_databases"),
        _t("window_days", "metrics window", f"{_BASE}.LIGHTSAIL_METRIC_WINDOW_DAYS", "days", f"{_ONLINE}.get_lightsail_metrics"),
        _t("window_days_air_gapped", "default Air-Gapped export window", _OFFLINE_WINDOW, "days", _OFFLINE_WINDOW_USE),
    ),
    "idle_sagemaker_notebook": (),
    "idle_sagemaker_endpoint": (
        _t("window_days", "Invocations window and minimum endpoint age", "settings.sagemaker_endpoint_idle_days", "days",
           "_detect_sagemaker_waste"),
    ),
    "oversized_sagemaker_endpoint": (
        _t("window_days", "utilization window", "settings.sagemaker_endpoint_idle_days", "days", "_detect_sagemaker_waste"),
        _t("cpu_pct", "average CPU below", f"{_OC}.SAGEMAKER_OVERSIZED_CPU_PCT", "percent", "_detect_sagemaker_waste"),
        _t("mem_pct", "average memory below", f"{_OC}.SAGEMAKER_OVERSIZED_MEM_PCT", "percent", "_detect_sagemaker_waste"),
        _t("min_invocations", "at least this many invocations in the window", f"{_OC}.SAGEMAKER_OVERSIZED_MIN_INVOCATIONS", "count",
           "_detect_sagemaker_waste"),
    ),
    "previous_gen_sagemaker_instance": (),
    "stopped_sagemaker_notebook_storage": (
        _t("min_days", "stopped at least this long", f"{_OC}.SAGEMAKER_STOPPED_NOTEBOOK_MIN_DAYS", "days", "_detect_sagemaker_waste"),
    ),
    "idle_workspace": (
        _t("idle_days", "no user connection for more than", f"{_OC}.WORKSPACES_IDLE_DAYS", "days", "_detect_workspaces_waste"),
    ),
    "oversized_workspace": (
        _t("window_days", "metrics window", f"{_BASE}.WORKSPACES_METRIC_WINDOW_DAYS", "days", f"{_ONLINE}.get_workspaces_metrics"),
        _t("fit_pct", "peaks under this share of the smaller bundle", f"{_COMPUTE_MIXIN}.WORKSPACES_TARGET_FIT", "fraction",
           "_detect_workspaces_waste"),
        _t("coverage_pct", "share of the window's days that must have data", "data_providers.online.WORKSPACES_MIN_COVERAGE",
           "fraction", f"{_ONLINE}.get_workspaces_metrics"),
        _t("min_savings_usd", "estimated saving per month at least", f"{_OC}.WORKSPACES_DOWNGRADE_MIN_SAVINGS_USD", "USD",
           "_detect_workspaces_waste"),
    ),
    "workspaces_autostop_opportunity": (
        _t("min_idle_days", "AlwaysOn WorkSpace with no user connection for more than", f"{_OC}.WORKSPACES_AUTOSTOP_MIN_IDLE_DAYS",
           "days", "_detect_workspaces_waste"),
        _t("min_savings_usd", "estimated saving per month at least", f"{_OC}.WORKSPACES_AUTOSTOP_MIN_SAVINGS_USD", "USD",
           "_detect_workspaces_waste"),
    ),
    "workspaces_pool_overprovisioned_capacity": (
        _t("max_utilization_pct", "running sessions at or under this share of desired", f"{_OC}.WORKSPACES_POOL_MAX_UTILIZATION_PCT",
           "percent", "_detect_workspaces_waste"),
        _t("min_excess", "at least this many idle sessions", f"{_OC}.WORKSPACES_POOL_MIN_EXCESS", "count", "_detect_workspaces_waste"),
        _t("min_excess_cost_usd", "idle sessions cost per month at least", f"{_OC}.WORKSPACES_POOL_MIN_EXCESS_COST_USD", "USD",
           "_detect_workspaces_waste"),
    ),
    "workspaces_windows_license_optimization": (
        _t("min_count", "at least this many license-included Windows WorkSpaces", f"{_OC}.WORKSPACES_WINDOWS_LICENSE_MIN_COUNT",
           "count", "_detect_workspaces_waste"),
    ),
    # ── Storage ──────────────────────────────────────────────────────────
    "unattached_ebs": (),
    "gp2_migration": (),
    "old_ebs_snapshot": (
        _t("min_age_days", "snapshots at least this old", "settings.snapshot_age_days", "days", "_detect_ebs_waste"),
    ),
    "orphaned_ebs_snapshot": (),
    "ami_orphaned_snapshot": (),
    "over_provisioned_iops": (
        _t("window_days", "per-minute IOPS window and minimum attachment age", f"{_OS}.OVER_PROVISIONED_IOPS_DAYS", "days",
           "_detect_over_provisioned_iops"),
        _t("peak_share_pct", "highest minute below this share of provisioned IOPS", f"{_OS}.IOPS_PEAK_SHARE_GATE", "fraction",
           "_detect_over_provisioned_iops"),
        _t("headroom_pct", "headroom added to the peak for the recommendation", f"{_OS}.IOPS_HEADROOM", "headroom",
           "_detect_over_provisioned_iops"),
        _t("coverage_pct", "share of the window's minutes that must be measured", "data_providers.online.EBS_IOPS_MIN_COVERAGE",
           "fraction", f"{_ONLINE}.get_ebs_iops_peaks"),
    ),
    "ecr_no_lifecycle_policy": (),
    "old_ecr_images": (
        _t("age_days", "an image pushed longer ago than this is old", f"{_BASE}.ECR_OLD_IMAGE_AGE_DAYS", "days",
           f"{_ONLINE}.get_ecr_repositories", "data_providers.offline:OfflineDataProvider.get_ecr_repositories"),
        _t("min_gb", "old plus untagged images above", f"{_OS}.ECR_OLD_IMAGES_MIN_GB", "GB", "_detect_ecr_waste"),
    ),
    "untagged_ecr_images": (
        _t("min_gb", "untagged images above", f"{_OS}.ECR_UNTAGGED_MIN_GB", "GB", "_detect_ecr_waste"),
        _t("old_images_min_gb", "only while old plus untagged images stay at or under", f"{_OS}.ECR_OLD_IMAGES_MIN_GB", "GB",
           "_detect_ecr_waste"),
    ),
    "idle_efs": (),
    "no_lifecycle_efs": (
        _t("min_size_gb", "file systems of at least", f"{_OS}.EFS_LIFECYCLE_MIN_SIZE_GB", "GB", "_detect_efs_waste"),
    ),
    "s3_empty_bucket": (
        _t("min_age_days", "bucket created at least this long ago", f"{_OS}.S3_EMPTY_BUCKET_MIN_AGE_DAYS", "days",
           "_detect_s3_empty_bucket"),
    ),
    "s3_high_request_and_transfer_cost": (),
    "incomplete_multipart": (
        _t("min_age_days", "uploads started more than this long ago", f"{_OS}.INCOMPLETE_MULTIPART_MIN_AGE_DAYS", "days",
           "_detect_s3_incomplete_multipart"),
    ),
    "no_lifecycle_policy": (
        _t("min_size_gb", "buckets of at least", "settings.s3_lifecycle_min_size_gb", "GB", "_detect_s3_no_lifecycle"),
        _t("savings_pct", "largest share of the Standard cost the estimate claims", "settings.s3_tiering_savings_pct", "percent",
           "_s3_tiering_savings_estimate"),
    ),
    "s3_rapid_growth": (
        _t("growth_pct", "size growth of at least", "settings.s3_growth_threshold_pct", "percent", "_detect_s3_rapid_growth"),
        _t("min_size_gb", "current size at least", "settings.s3_growth_min_size_gb", "GB", "_detect_s3_rapid_growth"),
        _t("min_growth_gb", "absolute growth at least", "settings.s3_growth_min_absolute_gb", "GB", "_detect_s3_rapid_growth"),
        _t("baseline_max_days_ago", "online scans compare with the newest daily size from between this many days back",
           "data_providers.online.S3_GROWTH_BASELINE_MAX_DAYS_AGO", "days", f"{_ONLINE}.get_s3_buckets"),
        _t("baseline_min_days_ago", "and this many days back",
           "data_providers.online.S3_GROWTH_BASELINE_MIN_DAYS_AGO", "days", f"{_ONLINE}.get_s3_buckets"),
    ),
    "s3_wrong_storage_class": (
        _t("min_standard_gb", "Standard storage at least", "settings.s3_tiering_min_size_gb", "GB", "_detect_s3_wrong_storage_class"),
        _t("min_standard_pct", "Standard share of the bucket at least", f"{_OS}.S3_WRONG_CLASS_MIN_STANDARD_PCT", "percent",
           "_detect_s3_wrong_storage_class"),
        _t("savings_pct", "largest share of the Standard cost the estimate claims", "settings.s3_tiering_savings_pct", "percent",
           "_s3_tiering_savings_estimate"),
    ),
    # ── Database ─────────────────────────────────────────────────────────
    "idle_rds": (
        _t("window_days", "DatabaseConnections window and minimum instance age", "settings.rds_idle_days", "days", "_detect_rds_waste"),
    ),
    "old_rds_snapshot": (
        _t("min_age_days", "manual snapshots at least this old", "settings.snapshot_age_days", "days", f"{_ODB}:old_rds_snapshot_items"),
    ),
    "rds_extended_support_cost": (
        _t("warning_days", "warn this many days before Extended Support starts", f"{_ODB}.EXTENDED_SUPPORT_WARNING_WINDOW_DAYS",
           "days", "_detect_rds_extended_support"),
    ),
    "dynamodb_no_autoscaling": (
        _t("min_monthly_usd", "provisioned capacity costing at least this a month", f"{_ODB}.DYNAMODB_NO_AUTOSCALING_MIN_MONTHLY_USD",
           "USD", "_detect_dynamodb_waste"),
    ),
    "idle_dynamodb": (
        _t("window_days", "consumed-capacity window and minimum table age", f"{_ODB}.DYNAMODB_METRIC_WINDOW_DAYS", "days",
           "_detect_dynamodb_waste"),
        _t("window_days_air_gapped", "default Air-Gapped export window", _OFFLINE_WINDOW, "days", _OFFLINE_WINDOW_USE),
    ),
    "over_provisioned_dynamodb": (
        _t("util_pct", "read and write utilization both below", f"{_ODB}.DYNAMODB_OVER_PROVISIONED_UTIL_PCT", "percent",
           "_detect_dynamodb_waste"),
        _t("window_days", "consumed-capacity window and minimum table age", f"{_ODB}.DYNAMODB_METRIC_WINDOW_DAYS", "days",
           "_detect_dynamodb_waste"),
    ),
    "idle_elasticache": (
        _t("window_days", "CurrConnections window and minimum cluster age", f"{_ODB}.ELASTICACHE_IDLE_WINDOW_DAYS", "days",
           "_detect_elasticache_waste"),
    ),
    "oversized_elasticache": (
        _t("cpu_pct", "average CPU below", f"{_ODB}.ELASTICACHE_OVERSIZED_CPU_PCT", "percent", "_detect_elasticache_waste"),
        _t("window_days", "CPU window", f"{_ODB}.ELASTICACHE_IDLE_WINDOW_DAYS", "days", "_detect_elasticache_waste"),
    ),
    "elasticache_extended_support_cost": (
        _t("warning_days", "warn this many days before Extended Support starts", f"{_ODB}.EXTENDED_SUPPORT_WARNING_WINDOW_DAYS",
           "days", "_detect_elasticache_extended_support"),
    ),
    "elasticache_replication_waste": (),
    "elasticache_engine_migration": (),
    "elasticache_serverless_optimization": (
        _t("window_days", "metrics window", f"{_ODB}.ELASTICACHE_SERVERLESS_WINDOW_DAYS", "days",
           "_detect_elasticache_serverless_optimization"),
        _t("max_avg_cpu_pct", "average CPU below", f"{_ODB}.ELASTICACHE_SERVERLESS_MAX_AVG_CPU_PCT", "percent",
           "_detect_elasticache_serverless_optimization"),
        _t("min_peak_cpu_pct", "peak CPU above", f"{_ODB}.ELASTICACHE_SERVERLESS_MIN_PEAK_CPU_PCT", "percent",
           "_detect_elasticache_serverless_optimization"),
        _t("min_connection_cv", "daily-connections coefficient of variation above", f"{_ODB}.ELASTICACHE_SERVERLESS_MIN_CONNECTION_CV",
           "ratio", "_detect_elasticache_serverless_optimization"),
    ),
    "elasticache_data_tiering_opportunity": (),
    # ── Network ──────────────────────────────────────────────────────────
    "unattached_eip": (),
    "eip_on_stopped_instance": (),
    "multiple_eips_per_instance": (),
    "idle_nat_gateway": (
        _t("window_days", "BytesOutToDestination window and minimum gateway age", f"{_ON}.NAT_IDLE_WINDOW_DAYS", "days",
           "_detect_network_waste"),
    ),
    "idle_load_balancer": (),
    "low_traffic_alb": (
        _t("max_requests", "fewer requests than this in the window", f"{_ON}.LOW_TRAFFIC_ALB_MAX_REQUESTS", "count",
           "_detect_low_traffic_alb"),
        _t("window_days", "RequestCount window", f"{_ON}.LB_METRIC_WINDOW_DAYS", "days", "_detect_network_waste"),
    ),
    "high_lcu_cost_alb": (
        _t("base_multiple", "LCU cost above this multiple of the ALB base fee", f"{_ON}.HIGH_LCU_COST_BASE_MULTIPLE", "ratio",
           "_detect_high_lcu_cost_alb"),
        _t("window_days", "ConsumedLCUs window", f"{_ON}.LB_METRIC_WINDOW_DAYS", "days", "_detect_network_waste"),
    ),
    "classic_lb_migration": (),
    "unused_vpc_endpoint": (
        _t("window_days", "BytesProcessed window and minimum endpoint age", f"{_ON}.VPC_ENDPOINT_WINDOW_DAYS", "days",
           "_detect_vpc_endpoint_waste"),
    ),
    "orphaned_dns_record": (),
    # ── Management ───────────────────────────────────────────────────────
    "no_retention_log_group": (
        _t("large_gb", "above this much stored the finding is MEDIUM, else LOW", f"{_OM}.NO_RETENTION_LARGE_GB", "GB",
           "_detect_cloudwatch_waste"),
    ),
    "old_log_group": (
        _t("min_days", "no new events for more than", f"{_OM}.OLD_LOG_GROUP_MIN_DAYS", "days", "_detect_cloudwatch_waste"),
        _t("min_gb", "stored data above", f"{_OM}.OLD_LOG_GROUP_MIN_GB", "GB", "_detect_cloudwatch_waste"),
    ),
    "excessive_retention_log_group": (
        _t("min_retention_days", "retention of at least", f"{_OM}.EXCESSIVE_RETENTION_MIN_DAYS", "days", "_detect_cloudwatch_waste"),
        _t("min_gb", "stored data above", f"{_OM}.EXCESSIVE_RETENTION_MIN_GB", "GB", "_detect_cloudwatch_waste"),
        _t("high_confidence_gb", "HIGH confidence above this much stored", f"{_OM}.EXCESSIVE_RETENTION_HIGH_CONFIDENCE_GB", "GB",
           "_detect_cloudwatch_waste"),
        _t("recommended_days", "retention the saving is priced against", f"{_OM}.EXCESSIVE_RETENTION_RECOMMENDED_DAYS", "days",
           "_detect_cloudwatch_waste"),
    ),
    "empty_log_group": (
        _t("min_days", "no events (or created) at least this long ago", f"{_OM}.EMPTY_LOG_GROUP_MIN_DAYS", "days",
           "_detect_cloudwatch_waste"),
    ),
    "unused_dashboard": (
        _t("free_dashboards", "most recently modified dashboards that are free", f"{_OM}.FREE_DASHBOARDS", "count",
           "_detect_cloudwatch_dashboard_waste"),
        _t("min_days", "not modified for more than", f"{_OM}.UNUSED_DASHBOARD_MIN_DAYS", "days", "_detect_cloudwatch_dashboard_waste"),
    ),
    # ── AWS Compute Optimizer, RI and Savings Plans recommendations ─────
    # The windows these sections state (Compute Optimizer's 14-day analysis,
    # Cost Explorer's THIRTY_DAYS lookback) are AWS's, not CloudWise numbers.
    "oversized_ec2_optimizer": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OOPT}.MIN_SAVINGS_THRESHOLD", "USD",
           "_get_ec2_optimizer_recommendations"),
    ),
    "oversized_ebs_optimizer": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OOPT}.MIN_SAVINGS_THRESHOLD", "USD",
           "_get_ebs_optimizer_recommendations"),
    ),
    "oversized_lambda_optimizer": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OOPT}.MIN_SAVINGS_THRESHOLD", "USD",
           "_get_lambda_optimizer_recommendations"),
    ),
    "oversized_rds_optimizer": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OOPT}.MIN_SAVINGS_THRESHOLD", "USD",
           "_get_rds_optimizer_recommendations"),
    ),
    "ri_opportunity_ec2": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OSV}.MIN_SAVINGS_THRESHOLD", "USD",
           "_convert_cached_ec2_ri_to_waste_items"),
    ),
    "ri_opportunity_rds": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OSV}.MIN_SAVINGS_THRESHOLD", "USD",
           "_convert_cached_rds_ri_to_waste_items"),
    ),
    "ri_opportunity_opensearch": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OSV}.MIN_SAVINGS_THRESHOLD", "USD",
           "_convert_cached_opensearch_ri_to_waste_items"),
    ),
    "ri_opportunity_elasticache": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OSV}.MIN_SAVINGS_THRESHOLD", "USD",
           "_convert_cached_elasticache_ri_to_waste_items"),
    ),
    "ri_opportunity_redshift": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OSV}.MIN_SAVINGS_THRESHOLD", "USD",
           "_convert_cached_redshift_ri_to_waste_items"),
    ),
    "sp_opportunity_compute": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OSV}.MIN_SAVINGS_THRESHOLD", "USD",
           "_convert_cached_sp_to_waste_items"),
    ),
    "sp_opportunity_ec2": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OSV}.MIN_SAVINGS_THRESHOLD", "USD",
           "_convert_cached_sp_to_waste_items"),
    ),
    "sp_opportunity_sagemaker": (
        _t("min_savings_usd", "estimated saving per month at least", f"{_OSV}.MIN_SAVINGS_THRESHOLD", "USD",
           "_convert_cached_sp_to_waste_items"),
    ),
    # ── Security posture: binary checks ──────────────────────────────────
    "unencrypted_ebs_volume": (),
    "unencrypted_rds_instance": (),
    "unencrypted_efs_filesystem": (),
    "unencrypted_documentdb_cluster": (),
    "opensearch_no_encryption_at_rest": (),
    "s3_no_default_encryption": (),
    "rds_no_deletion_protection": (),
    "dynamodb_no_deletion_protection": (),
    "rds_publicly_accessible": (),
    "resource_without_backup_coverage": (),
}


def thresholds_for(waste_type: str) -> Tuple[Threshold, ...]:
    return OPEN_THRESHOLDS[waste_type]


def resolved(registry: Mapping[str, Tuple[Threshold, ...]] = OPEN_THRESHOLDS) -> Dict[str, Dict[str, str]]:
    """``{waste_type: {key: docs text}}`` for every declared threshold."""
    return {
        wt: {t.key: format_value(threshold_value(t.source), t.unit) for t in ts}
        for wt, ts in registry.items()
    }
