"""Shared policy and helpers for extended-support detectors."""

from datetime import date
from typing import Any, Dict, Optional, Tuple


# CLO-530: every calendar below was re-read against AWS on 2026-10-01. Dates
# are the first day a version is BILLED (start of "year 1 pricing"), and
# year3_start is the first day of "year 3 pricing" where AWS has one.
#
# The ElastiCache table had Redis 5 at 2025-08-01 and Redis 6 at 2026-06-01;
# AWS says 2026-02-01 and 2027-02-01, so every Redis 6.x node was reported
# with a surcharge AWS does not bill.


def _vcpu(start: date, year3: Optional[date], target: str, eol: Optional[date] = None) -> Dict[str, Any]:
    """RDS/Aurora Extended Support: $0.100/vCPU-hr years 1-2, $0.200 year 3 (us-east-1)."""
    policy: Dict[str, Any] = {
        "extended_start": start,
        "year3_start": year3,
        "target_version": target,
        "pricing_model": "vcpu_hour",
        "year1_2_rate": 0.100,
        "year3_rate": 0.200,
    }
    if eol is not None:
        policy["eol_date"] = eol
    return policy


def _premium(start: date, year3: date, target: str) -> Dict[str, Any]:
    """ElastiCache / DocumentDB: 80% premium on the on-demand price years 1-2, 160% year 3."""
    return {
        "extended_start": start,
        "year3_start": year3,
        "target_version": target,
        "pricing_model": "percent_of_base",
        "surcharge_ratio": 0.80,
        "year3_ratio": 1.60,
    }


# OpenSearch: $0.0065 per Normalized Instance Hour (us-east-1) on top of the
# instance price. For the versions whose ORIGINAL extended-support end has
# passed and was extended (ES 1.5/2.3/5.1-5.5/6.0-6.7/7.1-7.8, OpenSearch
# 1.0-1.2 and 2.3-2.9), the charge becomes 100% of the instance price from
# 2026-11-07. Storage is not affected.
_OS_NIH_RATE = 0.0065
_OS_EXTENSION_FULL_PRICE = date(2026, 11, 7)


def _opensearch(start: date, target: str, full_price_from: Optional[date] = None) -> Dict[str, Any]:
    policy: Dict[str, Any] = {
        "extended_start": start,
        "target_version": target,
        "pricing_model": "nih_hour",
        "rate_per_nih": _OS_NIH_RATE,
    }
    if full_price_from is not None:
        policy["full_price_start"] = full_price_from
    return policy


# Standard support ended 2025-11-07: billed from 2025-11-08, at the full
# instance price from 2026-11-07. One key per minor version: a bare
# "Elasticsearch_7" would catch 7.9/7.10, which are still in standard support.
_OS_ENDED_2025 = [
    "Elasticsearch_1.5", "Elasticsearch_2.3",
    "Elasticsearch_5.1", "Elasticsearch_5.3", "Elasticsearch_5.5",
    "Elasticsearch_6.0", "Elasticsearch_6.2", "Elasticsearch_6.3", "Elasticsearch_6.4",
    "Elasticsearch_6.5", "Elasticsearch_6.7",
    "Elasticsearch_7.1", "Elasticsearch_7.4", "Elasticsearch_7.7", "Elasticsearch_7.8",
    "OpenSearch_1.0", "OpenSearch_1.1", "OpenSearch_1.2",
    "OpenSearch_2.3", "OpenSearch_2.5", "OpenSearch_2.7", "OpenSearch_2.9",
]
# Standard support ends 2027-11-07 (billed from 2027-11-08).
_OS_ENDS_2027 = [
    "Elasticsearch_6.8", "Elasticsearch_7.9", "Elasticsearch_7.10",
    "OpenSearch_1.3", "OpenSearch_2.11", "OpenSearch_2.13", "OpenSearch_2.15",
    "OpenSearch_2.17", "OpenSearch_2.19",
]
_OS_TARGET = "OpenSearch 3.x"


EXTENDED_SUPPORT_POLICY: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {
    # Sources (read 2026-10-01):
    #   https://docs.aws.amazon.com/AmazonRDS/latest/AuroraMySQLReleaseNotes/AuroraMySQL.release-calendars.html
    #   https://docs.aws.amazon.com/AmazonRDS/latest/AuroraPostgreSQLReleaseNotes/aurorapostgresql-release-calendar.html
    #   https://aws.amazon.com/rds/aurora/pricing/ ($0.100 / $0.200 per vCPU-hr)
    # CLO-530: Aurora MySQL 5.7 was billed from 2024-11-01 here (AWS: 2024-12-01,
    # year 3 2026-12-01); Aurora PostgreSQL 13 had 2026-05-01 (AWS: 2026-03-01,
    # year 3 2028-03-01); Aurora PostgreSQL 11 was missing. Aurora MySQL 3 (8.0)
    # has no year-3 tier.
    "aurora": {
        "aurora-postgresql": {
            "11": _vcpu(date(2024, 4, 1), date(2026, 4, 1), "16", eol=date(2024, 2, 29)),
            "12": _vcpu(date(2025, 3, 1), date(2027, 3, 1), "16", eol=date(2025, 2, 28)),
            "13": _vcpu(date(2026, 3, 1), date(2028, 3, 1), "16", eol=date(2026, 2, 28)),
            "14": _vcpu(date(2027, 3, 1), date(2029, 3, 1), "16", eol=date(2027, 2, 28)),
        },
        "aurora-mysql": {
            "5.7": _vcpu(date(2024, 12, 1), date(2026, 12, 1), "8.0", eol=date(2024, 10, 31)),
            "8.0": _vcpu(date(2028, 5, 1), None, "8.4", eol=date(2028, 4, 30)),
        },
    },
    # Sources (read 2026-10-01):
    #   https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-release-calendar.html
    #   https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/MySQL.Concepts.VersionMgmt.html
    #   https://aws.amazon.com/rds/postgresql/pricing/ , https://aws.amazon.com/rds/mysql/pricing/
    # CLO-530: PostgreSQL 11 billing starts 2024-04-01 (was 2024-03-01); MySQL
    # 5.7 starts 2024-03-01 (was 2024-12-01, the Aurora date); MySQL 8.0
    # (2026-08-01) was missing; no row had a year-3 date, so PG 11 and MySQL
    # 5.7, both in year 3 now, were estimated at half the rate.
    "rds": {
        "postgres": {
            "11": _vcpu(date(2024, 4, 1), date(2026, 4, 1), "16"),
            "12": _vcpu(date(2025, 3, 1), date(2027, 3, 1), "16"),
            "13": _vcpu(date(2026, 3, 1), date(2028, 3, 1), "16"),
            "14": _vcpu(date(2027, 3, 1), date(2029, 3, 1), "16"),
        },
        "mysql": {
            # 5.7 cannot go straight to 8.4: RDS upgrades 5.7 -> 8.0 -> 8.4.
            "5.7": {**_vcpu(date(2024, 3, 1), date(2026, 3, 1), "8.4"), "upgrade_path": "5.7 → 8.0 → 8.4"},
            "8.0": _vcpu(date(2026, 8, 1), date(2028, 8, 1), "8.4"),
        },
    },
    # Sources (read 2026-10-01):
    #   https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/extended-support-versions.html
    #   https://aws.amazon.com/elasticache/pricing/ (80% premium Y1-2, 160% Y3)
    # CLO-530: Redis OSS 4 and 5 are billed from 2026-02-01 (Y3 2028-02-01),
    # Redis OSS 6 from 2027-02-01 (Y3 2029-02-01). The premium was 10%; AWS
    # charges 80% / 160%. Memcached has no Extended Support, so the invented
    # Memcached 1.5 row is gone. Valkey never matches: it has no row and the
    # single-engine fallback only applies when no engine is given.
    "elasticache": {
        "redis": {
            "4": _premium(date(2026, 2, 1), date(2028, 2, 1), "7.1"),
            "5": _premium(date(2026, 2, 1), date(2028, 2, 1), "7.1"),
            "6": _premium(date(2027, 2, 1), date(2029, 2, 1), "7.1"),
        },
    },
    # Source (read 2026-10-01):
    #   https://docs.aws.amazon.com/opensearch-service/latest/developerguide/what-is.html#end-of-support
    # CLO-530: OpenSearch 1.3 (was 2025-07-01) and Elasticsearch 7.10 (was
    # 2024-09-01) stay in standard support until 2027-11-07, so both were false
    # positives. The versions actually billed since 2025-11-08 were missing.
    # The 10%-of-instance estimate is replaced by AWS's per-NIH fee.
    "opensearch": {
        "opensearch": {
            **{v: _opensearch(date(2025, 11, 8), _OS_TARGET, _OS_EXTENSION_FULL_PRICE) for v in _OS_ENDED_2025},
            "Elasticsearch_5.6": _opensearch(date(2025, 11, 8), _OS_TARGET),
            **{v: _opensearch(date(2027, 11, 8), _OS_TARGET) for v in _OS_ENDS_2027},
        }
    },
    # Sources (read 2026-10-01):
    #   https://docs.aws.amazon.com/documentdb/latest/devguide/docdb-version-support-dates.html
    #   https://docs.aws.amazon.com/documentdb/latest/developerguide/support-charges.html
    #   https://aws.amazon.com/documentdb/pricing/ (80% premium Y1-2, 160% Y3)
    # CLO-530: 3.6 entered Extended Support on 2026-03-31 but is billed from
    # 2026-07-01 (was 2025-11-01); year 3 from 2028-03-31. 4.0 has no end of
    # standard support, so the 2026-10-01 row flagged every 4.0 cluster from
    # today on; it is removed.
    "documentdb": {
        "docdb": {
            "3.6": _premium(date(2026, 7, 1), date(2028, 3, 31), "5.0"),
        }
    },
    # CLO-506: AWS's EKS release calendar (docs "Understand the Kubernetes
    # version lifecycle on EKS", read 2026-10-01). Extended support billing
    # starts on the end-of-standard-support date (UTC). The old table had
    # 1.27-1.29 only, with invented start dates, and missed 1.31-1.33, the
    # versions actually in extended support today.
    #
    # The surcharge is the Price List's "AmazonEKS-Hours:extendedSupport" line
    # item, $0.50 per cluster-hour, on top of the $0.10 standard cluster-hour
    # (the $0.60 here before was the TOTAL, so the saving was overstated by
    # the $0.10 a cluster pays either way). Same in us-east-1, eu-west-1,
    # sa-east-1 and ap-southeast-2, so it is not region-scaled.
    #
    # target_version is the oldest version that stays in standard support
    # for more than the 90-day warning window from 2026-10-02 (CLO-527):
    # 1.34 leaves standard support on 2026-12-02, so 1.28-1.33 recommend 1.35
    # (standard support to 2027-03-27; revisit before then). Calendar re-read
    # 2026-10-02. EKS upgrades one minor at a time.
    # 1.28-1.30 are past the end of extended support: EKS auto-upgrades such
    # a control plane gradually, and it is billed until it does.
    "eks": {
        "kubernetes": {
            "1.28": {"extended_start": date(2024, 11, 26), "extended_end": date(2025, 11, 26), "target_version": "1.35", "pricing_model": "cluster_hour", "rate_per_cluster_hour": 0.50},
            "1.29": {"extended_start": date(2025, 3, 23), "extended_end": date(2026, 3, 23), "target_version": "1.35", "pricing_model": "cluster_hour", "rate_per_cluster_hour": 0.50},
            "1.30": {"extended_start": date(2025, 7, 23), "extended_end": date(2026, 7, 23), "target_version": "1.35", "pricing_model": "cluster_hour", "rate_per_cluster_hour": 0.50},
            "1.31": {"extended_start": date(2025, 11, 26), "extended_end": date(2026, 11, 26), "target_version": "1.35", "pricing_model": "cluster_hour", "rate_per_cluster_hour": 0.50},
            "1.32": {"extended_start": date(2026, 3, 23), "extended_end": date(2027, 3, 23), "target_version": "1.35", "pricing_model": "cluster_hour", "rate_per_cluster_hour": 0.50},
            "1.33": {"extended_start": date(2026, 7, 29), "extended_end": date(2027, 7, 29), "target_version": "1.35", "pricing_model": "cluster_hour", "rate_per_cluster_hour": 0.50},
            "1.34": {"extended_start": date(2026, 12, 2), "extended_end": date(2027, 12, 2), "target_version": "1.35", "pricing_model": "cluster_hour", "rate_per_cluster_hour": 0.50},
            "1.35": {"extended_start": date(2027, 3, 27), "extended_end": date(2028, 3, 27), "target_version": "1.36", "pricing_model": "cluster_hour", "rate_per_cluster_hour": 0.50},
            "1.36": {"extended_start": date(2027, 8, 2), "extended_end": date(2028, 8, 2), "target_version": "1.37", "pricing_model": "cluster_hour", "rate_per_cluster_hour": 0.50},
        }
    },
}


def _version_candidates(version: str) -> list[str]:
    if not version:
        return []
    parts = version.split(".")
    major = parts[0]
    candidates = [version]
    if len(parts) >= 2:
        candidates.append(f"{parts[0]}.{parts[1]}")
    candidates.append(major)
    # Deduplicate while preserving order.
    seen = set()
    result = []
    for c in candidates:
        if c not in seen:
            result.append(c)
            seen.add(c)
    return result


def resolve_version_policy(service_key: str, version: str, engine: str = "") -> Optional[Dict[str, Any]]:
    service_map = EXTENDED_SUPPORT_POLICY.get(service_key, {})
    if not service_map:
        return None

    engine_key = engine.strip().lower() if engine else ""
    engine_map = service_map.get(engine_key)
    # Fall back to a service's only engine table only when the caller gave no
    # engine. With an engine, a miss is a miss: a Valkey cluster must never be
    # matched against the Redis OSS table (CLO-530).
    if engine_map is None and not engine_key and len(service_map) == 1:
        engine_map = next(iter(service_map.values()))
    if engine_map is None:
        return None

    for candidate in _version_candidates(version.strip()):
        policy = engine_map.get(candidate)
        if policy:
            merged = dict(policy)
            merged["matched_version"] = candidate
            return merged
    return None


def classify_support_state(policy: Dict[str, Any], today: Optional[date] = None, warning_window_days: int = 90) -> Tuple[str, Optional[int]]:
    today = today or date.today()
    extended_start = policy.get("extended_start")
    if not extended_start:
        return "none", None

    if today < extended_start:
        days_until = (extended_start - today).days
        if days_until <= warning_window_days:
            return "warning_imminent", days_until
        return "none", days_until

    return "active_surcharge", None


def estimate_surcharge(resource_shape: Dict[str, Any], policy: Dict[str, Any], today: Optional[date] = None, hours_per_month: int = 730) -> float:
    today = today or date.today()
    pricing_model = policy.get("pricing_model")

    if pricing_model == "vcpu_hour":
        total_vcpus = float(resource_shape.get("total_vcpus", 0))
        year3_start = policy.get("year3_start")
        year1_2_rate = float(policy.get("year1_2_rate", 0.0))
        year3_rate = float(policy.get("year3_rate", year1_2_rate))
        rate = year3_rate if year3_start and today >= year3_start else year1_2_rate
        return total_vcpus * rate * hours_per_month

    if pricing_model == "cluster_hour":
        clusters = float(resource_shape.get("clusters", 1))
        rate = float(policy.get("rate_per_cluster_hour", 0.0))
        return clusters * rate * hours_per_month

    if pricing_model == "percent_of_base":
        base_monthly = float(resource_shape.get("base_monthly", 0.0))
        return base_monthly * surcharge_ratio(policy, today)

    if pricing_model == "nih_hour":
        base_monthly = float(resource_shape.get("base_monthly", 0.0))
        full_price_start = policy.get("full_price_start")
        if full_price_start and today >= full_price_start:
            return base_monthly
        factor = nih_factor(str(resource_shape.get("instance_type", "")))
        count = max(float(resource_shape.get("instance_count", 1)), 1.0)
        return factor * count * float(policy.get("rate_per_nih", 0.0)) * hours_per_month

    return 0.0


# OpenSearch normalization factors by instance size (AWS "Calculating extended
# support charges" table).
_NIH_FACTORS = {
    "nano": 0.25, "micro": 0.5, "small": 1, "medium": 2, "large": 4, "xlarge": 8,
    "2xlarge": 16, "4xlarge": 32, "8xlarge": 64, "9xlarge": 72, "10xlarge": 80,
    "12xlarge": 96, "16xlarge": 128, "18xlarge": 144, "24xlarge": 192, "32xlarge": 256,
}


def nih_factor(instance_type: str) -> float:
    """Normalization factor for an OpenSearch instance type like 'm7g.large.search'."""
    parts = instance_type.lower().split(".")
    size = parts[1] if len(parts) >= 2 else ""
    return float(_NIH_FACTORS.get(size, 4))  # unknown size: assume large


def surcharge_ratio(policy: Dict[str, Any], today: Optional[date] = None) -> float:
    """Premium ratio in force on `today` for a percent_of_base policy."""
    today = today or date.today()
    year3_start = policy.get("year3_start")
    if year3_start and today >= year3_start and policy.get("year3_ratio") is not None:
        return float(policy["year3_ratio"])
    return float(policy.get("surcharge_ratio", 0.0))


def surcharge_metadata(policy: Dict[str, Any], today: Optional[date] = None) -> Dict[str, Any]:
    """The rate in force on `today`, for a finding's metadata.

    `surcharge_rate` means what the service's pricing model charges:
      - vcpu_hour (RDS, Aurora): USD per vCPU-hour (0.100, 0.200 in year 3)
      - percent_of_base (ElastiCache, DocumentDB): premium as a fraction of
        the on-demand price (0.80, 1.60 in year 3)
      - nih_hour (OpenSearch): 1.0 once the version is charged 100% of the
        instance price, else None; the dollar fee per Normalized Instance
        Hour is in `surcharge_usd_per_nih` (None once the 100% phase starts)
    """
    today = today or date.today()
    model = policy.get("pricing_model")
    if model == "vcpu_hour":
        year3_start = policy.get("year3_start")
        in_year3 = bool(year3_start and today >= year3_start)
        rate = policy.get("year3_rate") if in_year3 else policy.get("year1_2_rate")
        return {"surcharge_rate": rate}
    if model == "percent_of_base":
        return {"surcharge_rate": surcharge_ratio(policy, today)}
    if model == "nih_hour":
        full_price_start = policy.get("full_price_start")
        if full_price_start and today >= full_price_start:
            return {"surcharge_rate": 1.0, "surcharge_usd_per_nih": None}
        return {"surcharge_rate": None, "surcharge_usd_per_nih": policy.get("rate_per_nih")}
    return {"surcharge_rate": None}


def needs_base_price(policy: Dict[str, Any], today: Optional[date] = None) -> bool:
    """True when the estimate is a share of the instance price, so an unknown
    instance price makes the estimate MISSING."""
    today = today or date.today()
    model = policy.get("pricing_model")
    if model == "percent_of_base":
        return True
    if model == "nih_hour":
        full_price_start = policy.get("full_price_start")
        return bool(full_price_start and today >= full_price_start)
    return False


def describe_estimate(policy: Dict[str, Any], base_monthly: float, today: Optional[date] = None) -> str:
    """Plain-language basis of an estimated (not billing-backed) surcharge."""
    today = today or date.today()
    model = policy.get("pricing_model")
    if model == "percent_of_base":
        pct = surcharge_ratio(policy, today) * 100
        return f"Estimated as AWS's {pct:.0f}% Extended Support premium on the on-demand cost (${base_monthly:.2f}/month)."
    if model == "nih_hour":
        full_price_start = policy.get("full_price_start")
        if full_price_start and today >= full_price_start:
            return f"Estimated as 100% of the instance cost (${base_monthly:.2f}/month), AWS's fee for this version since {full_price_start}."
        return f"Estimated at ${policy.get('rate_per_nih', 0.0)} per Normalized Instance Hour (us-east-1 rate), storage excluded."
    return "Estimated from AWS's published Extended Support rate."


def build_extended_support_explanation(detection: str, threshold: str, pricing: str, why_waste: str, risk: str) -> Dict[str, str]:
    return {
        "detection": detection,
        "threshold": threshold,
        "pricing": pricing,
        "why_waste": why_waste,
        "risk": risk,
    }


def get_billed_surcharge_monthly(cost_breakdown: Dict[str, Any], service_key: str, resource_id: str = "") -> Tuple[Optional[float], bool]:
    if not cost_breakdown:
        return None, False

    key_candidates = []
    if resource_id:
        key_candidates.append(f"{service_key}:{resource_id}")
    key_candidates.append(service_key)

    for key in key_candidates:
        cost_data = cost_breakdown.get(key)
        if not cost_data:
            continue
        monthly_amount = getattr(cost_data, "monthly_amount_usd", None)
        if monthly_amount is not None:
            return float(monthly_amount), True
        amount_usd = getattr(cost_data, "amount_usd", None)
        days = getattr(cost_data, "days", 30)
        if amount_usd is not None and days:
            return float(amount_usd) * (30.0 / float(days)), True

    return None, False
