"""
AWS Pricing Service

Fetches real-time pricing data from AWS Pricing API for accurate waste cost estimates.
Pricing data is cached with a 24-hour TTL to minimize API calls.

AWS Pricing API is only available in us-east-1 and ap-south-1 regions.
"""

import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from decimal import Decimal
import asyncio
from functools import lru_cache

import boto3
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)


# ─── Lightsail instance bundles (CLO-506) ─────────────────────────────────
# Monthly prices from lightsail:GetBundles (us-east-1, 2026-10-01, active and
# inactive bundles). Lightsail prices a bundle the same in every region
# (checked against eu-central-1, ap-south-1 and ap-southeast-2, whose bundle
# ids carry other version suffixes such as _3_1/_3_2 at the same price), so
# these are NOT region-scaled. Older bundle generations (_1_0, _2_0) are
# billed at the current prices. Keyed by (family, size); each value lists
# (Linux, Windows, Linux IPv6-only, Windows IPv6-only).
_LIGHTSAIL_BUNDLE_PRICES: Dict[tuple, tuple] = {
    ('', 'nano'): (5.0, 9.5, 3.5, 8.0),
    ('', 'micro'): (7.0, 14.0, 5.0, 12.0),
    ('', 'small'): (12.0, 22.0, 10.0, 20.0),
    ('', 'medium'): (24.0, 44.0, 20.0, 40.0),
    ('', 'large'): (44.0, 74.0, 40.0, 70.0),
    ('', 'xlarge'): (84.0, 124.0, 80.0, 120.0),
    ('', '2xlarge'): (164.0, 244.0, 160.0, 240.0),
    ('', '4xlarge'): (384.0, 574.0, 380.0, 570.0),
    ('', '8xlarge'): (884.0, 1254.0, 880.0, 1250.0),
    ('', '12xlarge'): (1324.0, 1884.0, 1320.0, 1880.0),
    ('', '16xlarge'): (1764.0, 2504.0, 1760.0, 2500.0),
    # Memory-optimized (m_*)
    ('m', 'large'): (74.0, 134.0, 70.0, 130.0),
    ('m', 'xlarge'): (144.0, 264.0, 140.0, 260.0),
    ('m', '2xlarge'): (294.0, 524.0, 290.0, 520.0),
    ('m', '4xlarge'): (584.0, 1044.0, 580.0, 1040.0),
    ('m', '8xlarge'): (1174.0, 2104.0, 1170.0, 2100.0),
    ('m', '12xlarge'): (1764.0, 3164.0, 1760.0, 3160.0),
    ('m', '16xlarge'): (2344.0, 4204.0, 2340.0, 4200.0),
    # Compute-optimized (c_*)
    ('c', 'large'): (42.0, 100.0, 38.0, 96.0),
    ('c', 'xlarge'): (84.0, 200.0, 80.0, 196.0),
    ('c', '2xlarge'): (168.0, 400.0, 164.0, 396.0),
    ('c', '4xlarge'): (336.0, 800.0, 332.0, 796.0),
    ('c', '9xlarge'): (844.0, 1888.0, 840.0, 1884.0),
    ('c', '12xlarge'): (1126.0, 2518.0, 1122.0, 2514.0),
    ('c', '18xlarge'): (1688.0, 3776.0, 1684.0, 3772.0),
}


def lightsail_bundle_monthly_price(bundle_id: str) -> Optional[float]:
    """Monthly price of a Lightsail instance bundle id, or None if unknown.

    A bundle id is ``[m_|c_]<size>[_win][_ipv6]_<major>_<minor>``, e.g.
    ``nano_3_0``, ``xlarge_win_2_0``, ``m_large_ipv6_1_0``, ``small_3_1``.
    Parsed token by token: the substring match this replaces priced
    ``xlarge_2_0`` and ``2xlarge_2_0`` as ``large``."""
    tokens = [t for t in (bundle_id or '').lower().split('_') if t]
    while tokens and tokens[-1].isdigit():
        tokens.pop()
    if not tokens:
        return None
    family = ''
    if tokens[0] in ('m', 'c'):
        family = tokens.pop(0)
    if not tokens:
        return None
    size, flags = tokens[0], set(tokens[1:])
    if flags - {'win', 'ipv6'}:
        return None
    prices = _LIGHTSAIL_BUNDLE_PRICES.get((family, size))
    if prices is None:
        return None
    index = (2 if 'ipv6' in flags else 0) + (1 if 'win' in flags else 0)
    return prices[index]


@dataclass
class EC2Pricing:
    """Pricing information for an EC2 instance type."""
    instance_type: str
    region: str
    on_demand_hourly: float  # USD per hour
    monthly_estimate: float  # USD per month (730 hours)
    vcpu: int = 0
    memory_gb: float = 0.0
    current_generation: bool = True
    
    @property
    def daily_estimate(self) -> float:
        return self.on_demand_hourly * 24
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_type": self.instance_type,
            "region": self.region,
            "on_demand_hourly": self.on_demand_hourly,
            "monthly_estimate": self.monthly_estimate,
            "vcpu": self.vcpu,
            "memory_gb": self.memory_gb,
            "current_generation": self.current_generation,
        }


@dataclass
class EBSPricing:
    """Pricing information for EBS volumes."""
    volume_type: str
    region: str
    price_per_gb_month: float
    iops_price: float = 0.0  # For io1/io2, price per IOPS-month
    throughput_price: float = 0.0  # For gp3, price per MB/s-month
    
    def calculate_monthly_cost(self, size_gb: int, iops: int = 0, throughput_mbps: int = 0) -> float:
        """Calculate monthly cost for a volume with given specs."""
        storage_cost = size_gb * self.price_per_gb_month
        iops_cost = iops * self.iops_price if self.volume_type in ("io1", "io2") else 0
        throughput_cost = throughput_mbps * self.throughput_price if self.volume_type == "gp3" else 0
        return storage_cost + iops_cost + throughput_cost
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "volume_type": self.volume_type,
            "region": self.region,
            "price_per_gb_month": self.price_per_gb_month,
            "iops_price": self.iops_price,
            "throughput_price": self.throughput_price,
        }


@dataclass
class RDSPricing:
    """Pricing information for RDS instances."""
    instance_class: str
    engine: str
    region: str
    on_demand_hourly: float
    monthly_estimate: float
    multi_az: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_class": self.instance_class,
            "engine": self.engine,
            "region": self.region,
            "on_demand_hourly": self.on_demand_hourly,
            "monthly_estimate": self.monthly_estimate,
            "multi_az": self.multi_az,
        }


class AWSPricingService:
    """
    Service for fetching AWS pricing data.
    
    Uses the AWS Price List API to get accurate, current pricing.
    Pricing data is cached in memory with a 24-hour TTL.
    
    Note: Pricing API is only available in us-east-1 and ap-south-1.
    """
    
    # AWS Pricing API is only available in these regions
    PRICING_API_REGIONS = ["us-east-1", "ap-south-1"]
    
    # Cache TTL
    CACHE_TTL_HOURS = 24
    
    # Fallback pricing (used if API fails) - approximate averages
    FALLBACK_EC2_PRICING: Dict[str, float] = {
        # Current generation
        "t3.micro": 0.0104,
        "t3.small": 0.0208,
        "t3.medium": 0.0416,
        "t3.large": 0.0832,
        "t3.xlarge": 0.1664,
        "t3.2xlarge": 0.3328,
        "m5.large": 0.096,
        "m5.xlarge": 0.192,
        "m5.2xlarge": 0.384,
        "m6i.large": 0.096,
        "m6i.xlarge": 0.192,
        "r5.large": 0.126,
        "r5.xlarge": 0.252,
        "c5.large": 0.085,
        "c5.xlarge": 0.17,
        # Previous generation  
        "t2.micro": 0.0116,
        "t2.small": 0.023,
        "t2.medium": 0.0464,
        "m4.large": 0.10,
        "m4.xlarge": 0.20,
        "m3.medium": 0.067,
        "m3.large": 0.133,
        "r3.large": 0.166,
        "c4.large": 0.10,
        "c3.large": 0.105,
    }
    
    FALLBACK_EBS_PRICING: Dict[str, float] = {
        "gp2": 0.10,
        "gp3": 0.08,
        "io1": 0.125,
        "io2": 0.125,
        "st1": 0.045,
        "sc1": 0.015,
        "standard": 0.05,
    }
    
    FALLBACK_NAT_GATEWAY_HOURLY = 0.045
    FALLBACK_EIP_IDLE_HOURLY = 0.005
    FALLBACK_ALB_HOURLY = 0.0225
    FALLBACK_NLB_HOURLY = 0.0225
    FALLBACK_CLB_HOURLY = 0.025
    
    # EMR surcharge rates (per-instance-hour, us-east-1)
    FALLBACK_EMR_SURCHARGE: Dict[str, float] = {
        "m5.xlarge": 0.048, "m5.2xlarge": 0.096, "m5.4xlarge": 0.192,
        "m6i.xlarge": 0.048, "m6i.2xlarge": 0.096,
        "r5.xlarge": 0.063, "r5.2xlarge": 0.126, "r5.4xlarge": 0.252,
        "r6i.xlarge": 0.063, "r6i.2xlarge": 0.126,
        "c5.xlarge": 0.043, "c5.2xlarge": 0.085, "c5.4xlarge": 0.170,
        "c6i.xlarge": 0.043, "c6i.2xlarge": 0.085,
        "i3.xlarge": 0.078, "i3.2xlarge": 0.155,
        "d3.xlarge": 0.062,
        "m4.xlarge": 0.060, "m4.2xlarge": 0.120,
        "r3.xlarge": 0.070, "r3.2xlarge": 0.140,
        "c4.xlarge": 0.053, "c4.2xlarge": 0.105,
        "m3.xlarge": 0.070,
    }
    
    # Additional service pricing (hourly rates for monthly estimation)
    FALLBACK_LAMBDA_PRICING = {
        "request_per_million": 0.20,
        "duration_per_gb_second": 0.0000166667,
        "provisioned_concurrency_per_gb_second": 0.0000041667,
        "provisioned_concurrency_duration_per_gb_second": 0.0000097222,
    }
    
    # Verified against the live AWS Pricing API (AmazonDynamoDB, us-east-1) 2026-07-31.
    # Provisioned rates are per capacity-unit-HOUR and differ 5x between reads and
    # writes — do not collapse them into a single rate (CLO-226).
    #   DDB-ReadUnits   / "DynamoDB Provisioned Read Units"    $0.00013 per RCU-Hr
    #   DDB-WriteUnits  / "DynamoDB Provisioned Write Units"   $0.00065 per WCU-Hr
    #   DDB-ReadUnits   / "PayPerRequest Read Request Units"   $0.000000125 per RRU
    #   DDB-WriteUnits  / "PayPerRequest Write Request Units"  $0.000000625 per WRU
    FALLBACK_DYNAMODB_PRICING = {
        "provisioned_read_unit_per_hour": 0.00013,
        "provisioned_write_unit_per_hour": 0.00065,
        "read_unit_per_million": 0.125,
        "write_unit_per_million": 0.625,
        "storage_per_gb_month": 0.25,
    }
    
    # Every ElastiCache node type's on-demand hourly price in us-east-1, from
    # the AWS Price List API (service code AmazonElastiCache, productFamily
    # "Cache Instance", cacheEngine Redis, usagetype NodeUsage:<type>, read
    # 2026-10-02; 73 types). Region-scaled by _apply_region. The old table had
    # 27 types, several of them low (r6g.large 0.164 vs 0.206, r6gd.xlarge
    # 0.429 vs 0.781), and the detectors guessed $0.10/hr for every other
    # type; an unknown type now returns None from get_elasticache_price_known.
    FALLBACK_ELASTICACHE_PRICING: Dict[str, float] = {
        "cache.c7gn.12xlarge": 6.11,
        "cache.c7gn.16xlarge": 8.147,
        "cache.c7gn.2xlarge": 1.018,
        "cache.c7gn.4xlarge": 2.037,
        "cache.c7gn.8xlarge": 4.073,
        "cache.c7gn.large": 0.255,
        "cache.c7gn.xlarge": 0.509,
        "cache.m4.10xlarge": 3.112,
        "cache.m4.2xlarge": 0.623,
        "cache.m4.4xlarge": 1.245,
        "cache.m4.large": 0.156,
        "cache.m4.xlarge": 0.311,
        "cache.m5.12xlarge": 3.744,
        "cache.m5.24xlarge": 7.488,
        "cache.m5.2xlarge": 0.623,
        "cache.m5.4xlarge": 1.245,
        "cache.m5.large": 0.156,
        "cache.m5.xlarge": 0.311,
        "cache.m6g.12xlarge": 3.557,
        "cache.m6g.16xlarge": 4.743,
        "cache.m6g.2xlarge": 0.593,
        "cache.m6g.4xlarge": 1.186,
        "cache.m6g.8xlarge": 2.372,
        "cache.m6g.large": 0.149,
        "cache.m6g.xlarge": 0.297,
        "cache.m7g.12xlarge": 3.77,
        "cache.m7g.16xlarge": 5.028,
        "cache.m7g.2xlarge": 0.629,
        "cache.m7g.4xlarge": 1.257,
        "cache.m7g.8xlarge": 2.514,
        "cache.m7g.large": 0.158,
        "cache.m7g.xlarge": 0.315,
        "cache.r4.16xlarge": 7.28,
        "cache.r4.2xlarge": 0.91,
        "cache.r4.4xlarge": 1.82,
        "cache.r4.8xlarge": 3.64,
        "cache.r4.large": 0.228,
        "cache.r4.xlarge": 0.455,
        "cache.r5.12xlarge": 5.184,
        "cache.r5.24xlarge": 10.368,
        "cache.r5.2xlarge": 0.862,
        "cache.r5.4xlarge": 1.724,
        "cache.r5.large": 0.216,
        "cache.r5.xlarge": 0.431,
        "cache.r6g.12xlarge": 4.925,
        "cache.r6g.16xlarge": 6.567,
        "cache.r6g.2xlarge": 0.821,
        "cache.r6g.4xlarge": 1.642,
        "cache.r6g.8xlarge": 3.284,
        "cache.r6g.large": 0.206,
        "cache.r6g.xlarge": 0.411,
        "cache.r6gd.12xlarge": 9.358,
        "cache.r6gd.16xlarge": 12.477,
        "cache.r6gd.2xlarge": 1.56,
        "cache.r6gd.4xlarge": 3.12,
        "cache.r6gd.8xlarge": 6.24,
        "cache.r6gd.xlarge": 0.781,
        "cache.r7g.12xlarge": 5.235,
        "cache.r7g.16xlarge": 6.981,
        "cache.r7g.2xlarge": 0.873,
        "cache.r7g.4xlarge": 1.745,
        "cache.r7g.8xlarge": 3.491,
        "cache.r7g.large": 0.219,
        "cache.r7g.xlarge": 0.437,
        "cache.t2.medium": 0.068,
        "cache.t2.micro": 0.017,
        "cache.t2.small": 0.034,
        "cache.t3.medium": 0.068,
        "cache.t3.micro": 0.017,
        "cache.t3.small": 0.034,
        "cache.t4g.medium": 0.065,
        "cache.t4g.micro": 0.016,
        "cache.t4g.small": 0.032,
    }
    
    # CLO-532 item 3: Valkey node on-demand hourly prices in us-east-1, from
    # the AWS Price List API (AmazonElastiCache, productFamily "Cache
    # Instance", cacheEngine Valkey, usagetype NodeUsage:<type>, read
    # 2026-10-02; 94 types, 21 of them (c8gn, m8g, r8g) Valkey-only).
    # Every type the Redis table also has is 0.8x its Redis price, but a type
    # with no Valkey row is MISSING: it never falls back to the Redis rate.
    FALLBACK_ELASTICACHE_VALKEY_PRICING: Dict[str, float] = {
        "cache.c7gn.12xlarge": 4.888,
        "cache.c7gn.16xlarge": 6.5176,
        "cache.c7gn.2xlarge": 0.8144,
        "cache.c7gn.4xlarge": 1.6296,
        "cache.c7gn.8xlarge": 3.2584,
        "cache.c7gn.large": 0.204,
        "cache.c7gn.xlarge": 0.4072,
        "cache.c8gn.12xlarge": 4.4088,
        "cache.c8gn.16xlarge": 5.8784,
        "cache.c8gn.2xlarge": 0.7348,
        "cache.c8gn.4xlarge": 1.4696,
        "cache.c8gn.8xlarge": 2.9392,
        "cache.c8gn.large": 0.1837,
        "cache.c8gn.xlarge": 0.3674,
        "cache.m4.10xlarge": 2.4896,
        "cache.m4.2xlarge": 0.4984,
        "cache.m4.4xlarge": 0.996,
        "cache.m4.large": 0.1248,
        "cache.m4.xlarge": 0.2488,
        "cache.m5.12xlarge": 2.9952,
        "cache.m5.24xlarge": 5.9904,
        "cache.m5.2xlarge": 0.4984,
        "cache.m5.4xlarge": 0.996,
        "cache.m5.large": 0.1248,
        "cache.m5.xlarge": 0.2488,
        "cache.m6g.12xlarge": 2.8456,
        "cache.m6g.16xlarge": 3.7944,
        "cache.m6g.2xlarge": 0.4744,
        "cache.m6g.4xlarge": 0.9488,
        "cache.m6g.8xlarge": 1.8976,
        "cache.m6g.large": 0.1192,
        "cache.m6g.xlarge": 0.2376,
        "cache.m7g.12xlarge": 3.016,
        "cache.m7g.16xlarge": 4.0224,
        "cache.m7g.2xlarge": 0.5032,
        "cache.m7g.4xlarge": 1.0056,
        "cache.m7g.8xlarge": 2.0112,
        "cache.m7g.large": 0.1264,
        "cache.m7g.xlarge": 0.252,
        "cache.m8g.12xlarge": 3.0375,
        "cache.m8g.16xlarge": 4.05,
        "cache.m8g.2xlarge": 0.5062,
        "cache.m8g.4xlarge": 1.0125,
        "cache.m8g.8xlarge": 2.025,
        "cache.m8g.large": 0.1266,
        "cache.m8g.xlarge": 0.2531,
        "cache.r4.16xlarge": 5.824,
        "cache.r4.2xlarge": 0.728,
        "cache.r4.4xlarge": 1.456,
        "cache.r4.8xlarge": 2.912,
        "cache.r4.large": 0.1824,
        "cache.r4.xlarge": 0.364,
        "cache.r5.12xlarge": 4.1472,
        "cache.r5.24xlarge": 8.2944,
        "cache.r5.2xlarge": 0.6896,
        "cache.r5.4xlarge": 1.3792,
        "cache.r5.large": 0.1728,
        "cache.r5.xlarge": 0.3448,
        "cache.r6g.12xlarge": 3.94,
        "cache.r6g.16xlarge": 5.2536,
        "cache.r6g.2xlarge": 0.6568,
        "cache.r6g.4xlarge": 1.3136,
        "cache.r6g.8xlarge": 2.6272,
        "cache.r6g.large": 0.1648,
        "cache.r6g.xlarge": 0.3288,
        "cache.r6gd.12xlarge": 7.4864,
        "cache.r6gd.16xlarge": 9.9816,
        "cache.r6gd.2xlarge": 1.248,
        "cache.r6gd.4xlarge": 2.496,
        "cache.r6gd.8xlarge": 4.992,
        "cache.r6gd.xlarge": 0.6248,
        "cache.r7g.12xlarge": 4.188,
        "cache.r7g.16xlarge": 5.5848,
        "cache.r7g.2xlarge": 0.6984,
        "cache.r7g.4xlarge": 1.396,
        "cache.r7g.8xlarge": 2.7928,
        "cache.r7g.large": 0.1752,
        "cache.r7g.xlarge": 0.3496,
        "cache.r8g.12xlarge": 4.2132,
        "cache.r8g.16xlarge": 5.6177,
        "cache.r8g.2xlarge": 0.7022,
        "cache.r8g.4xlarge": 1.4044,
        "cache.r8g.8xlarge": 2.8088,
        "cache.r8g.large": 0.1756,
        "cache.r8g.xlarge": 0.3511,
        "cache.t2.medium": 0.0544,
        "cache.t2.micro": 0.0136,
        "cache.t2.small": 0.0272,
        "cache.t3.medium": 0.0544,
        "cache.t3.micro": 0.0136,
        "cache.t3.small": 0.0272,
        "cache.t4g.medium": 0.052,
        "cache.t4g.micro": 0.0128,
        "cache.t4g.small": 0.0256,
    }
    
    FALLBACK_REDSHIFT_PRICING: Dict[str, float] = {
        # Hourly pricing per node
        "dc2.large": 0.25,
        "dc2.8xlarge": 4.80,
        "ds2.xlarge": 0.85,
        "ds2.8xlarge": 6.80,
        "ra3.xlplus": 1.086,
        "ra3.4xlarge": 3.26,
        "ra3.16xlarge": 13.04,
    }
    
    # CLO-530 follow-up: every OpenSearch Service instance type's on-demand
    # hourly price in us-east-1, from the AWS Price List API (service code
    # AmazonES, productFamily "Amazon OpenSearch Service Instance", read
    # 2026-10-01; 237 types). Region-scaled by _apply_region. The old
    # table had 6 types and returned $0.10/hr for every other one; from
    # 2026-11-07 this price IS the extended-support estimate for 22 versions,
    # so an unknown type now returns None (get_opensearch_price_known) instead
    # of a guess.
    FALLBACK_OPENSEARCH_PRICING: Dict[str, float] = {
        "c4.2xlarge.search": 0.587,
        "c4.4xlarge.search": 1.174,
        "c4.8xlarge.search": 2.347,
        "c4.large.search": 0.148,
        "c4.xlarge.search": 0.294,
        "c5.18xlarge.search": 4.514,
        "c5.2xlarge.search": 0.502,
        "c5.4xlarge.search": 1.003,
        "c5.9xlarge.search": 2.257,
        "c5.large.search": 0.125,
        "c5.xlarge.search": 0.251,
        "c6g.12xlarge.search": 2.709,
        "c6g.2xlarge.search": 0.452,
        "c6g.4xlarge.search": 0.903,
        "c6g.8xlarge.search": 1.806,
        "c6g.large.search": 0.113,
        "c6g.xlarge.search": 0.226,
        "c7g.12xlarge.search": 2.888,
        "c7g.16xlarge.search": 3.851,
        "c7g.2xlarge.search": 0.481,
        "c7g.4xlarge.search": 0.963,
        "c7g.8xlarge.search": 1.926,
        "c7g.large.search": 0.12,
        "c7g.xlarge.search": 0.241,
        "c7i.12xlarge.search": 3.427,
        "c7i.16xlarge.search": 4.57,
        "c7i.2xlarge.search": 0.571,
        "c7i.4xlarge.search": 1.142,
        "c7i.8xlarge.search": 2.285,
        "c7i.large.search": 0.143,
        "c7i.xlarge.search": 0.286,
        "c8g.12xlarge.search": 3.178,
        "c8g.16xlarge.search": 4.237,
        "c8g.2xlarge.search": 0.53,
        "c8g.4xlarge.search": 1.06,
        "c8g.8xlarge.search": 2.119,
        "c8g.large.search": 0.133,
        "c8g.xlarge.search": 0.265,
        "i2.2xlarge.search": 2.387,
        "i2.xlarge.search": 1.194,
        "i3.16xlarge.search": 7.987,
        "i3.2xlarge.search": 0.998,
        "i3.4xlarge.search": 1.997,
        "i3.8xlarge.search": 3.994,
        "i3.large.search": 0.25,
        "i3.xlarge.search": 0.499,
        "i4g.16xlarge.search": 7.907,
        "i4g.2xlarge.search": 0.988,
        "i4g.4xlarge.search": 1.977,
        "i4g.8xlarge.search": 3.954,
        "i4g.large.search": 0.247,
        "i4g.xlarge.search": 0.494,
        "i4i.12xlarge.search": 6.589,
        "i4i.16xlarge.search": 8.786,
        "i4i.24xlarge.search": 13.179,
        "i4i.2xlarge.search": 1.098,
        "i4i.32xlarge.search": 17.572,
        "i4i.4xlarge.search": 2.197,
        "i4i.8xlarge.search": 4.394,
        "i4i.large.search": 0.275,
        "i4i.xlarge.search": 0.549,
        "i7i.12xlarge.search": 7.248,
        "i7i.16xlarge.search": 9.664,
        "i7i.2xlarge.search": 1.208,
        "i7i.4xlarge.search": 2.416,
        "i7i.8xlarge.search": 4.832,
        "i7i.large.search": 0.302,
        "i7i.xlarge.search": 0.604,
        "i8g.12xlarge.search": 6.589,
        "i8g.16xlarge.search": 8.786,
        "i8g.2xlarge.search": 1.098,
        "i8g.4xlarge.search": 2.196,
        "i8g.8xlarge.search": 4.393,
        "i8g.large.search": 0.275,
        "i8g.xlarge.search": 0.549,
        "i8ge.12xlarge.search": 9.112,
        "i8ge.18xlarge.search": 13.668,
        "i8ge.2xlarge.search": 1.519,
        "i8ge.3xlarge.search": 2.278,
        "i8ge.6xlarge.search": 4.556,
        "i8ge.large.search": 0.38,
        "i8ge.xlarge.search": 0.759,
        "im4gn.16xlarge.search": 8.731,
        "im4gn.2xlarge.search": 1.091,
        "im4gn.4xlarge.search": 2.183,
        "im4gn.8xlarge.search": 4.366,
        "im4gn.large.search": 0.273,
        "im4gn.xlarge.search": 0.546,
        "m3.2xlarge.search": 0.752,
        "m3.large.search": 0.188,
        "m3.medium.search": 0.094,
        "m3.xlarge.search": 0.376,
        "m4.10xlarge.search": 3.017,
        "m4.2xlarge.search": 0.603,
        "m4.4xlarge.search": 1.207,
        "m4.large.search": 0.151,
        "m4.xlarge.search": 0.301,
        "m5.12xlarge.search": 3.398,
        "m5.2xlarge.search": 0.566,
        "m5.4xlarge.search": 1.133,
        "m5.large.search": 0.142,
        "m5.xlarge.search": 0.283,
        "m6g.12xlarge.search": 3.068,
        "m6g.2xlarge.search": 0.511,
        "m6g.4xlarge.search": 1.023,
        "m6g.8xlarge.search": 2.045,
        "m6g.large.search": 0.128,
        "m6g.xlarge.search": 0.256,
        "m7g.12xlarge.search": 3.251,
        "m7g.16xlarge.search": 4.335,
        "m7g.2xlarge.search": 0.542,
        "m7g.4xlarge.search": 1.084,
        "m7g.8xlarge.search": 2.167,
        "m7g.large.search": 0.135,
        "m7g.medium.search": 0.068,
        "m7g.xlarge.search": 0.271,
        "m7i.12xlarge.search": 3.871,
        "m7i.16xlarge.search": 5.161,
        "m7i.2xlarge.search": 0.645,
        "m7i.4xlarge.search": 1.29,
        "m7i.8xlarge.search": 2.58,
        "m7i.large.search": 0.161,
        "m7i.xlarge.search": 0.323,
        "m8g.12xlarge.search": 3.577,
        "m8g.16xlarge.search": 4.769,
        "m8g.2xlarge.search": 0.597,
        "m8g.4xlarge.search": 1.193,
        "m8g.8xlarge.search": 2.385,
        "m8g.large.search": 0.15,
        "m8g.medium.search": 0.075,
        "m8g.xlarge.search": 0.299,
        "oi2.12xlarge.search": 7.00128,
        "oi2.16xlarge.search": 9.33504,
        "oi2.24xlarge.search": 14.00256,
        "oi2.2xlarge.search": 1.16688,
        "oi2.4xlarge.search": 2.33376,
        "oi2.8xlarge.search": 4.66752,
        "oi2.large.search": 0.29172,
        "oi2.xlarge.search": 0.58344,
        "om2.12xlarge.search": 3.662,
        "om2.16xlarge.search": 4.883,
        "om2.2xlarge.search": 0.61,
        "om2.4xlarge.search": 1.221,
        "om2.8xlarge.search": 2.441,
        "om2.large.search": 0.153,
        "om2.xlarge.search": 0.305,
        "or1.12xlarge.search": 5.02,
        "or1.16xlarge.search": 6.683,
        "or1.2xlarge.search": 0.836,
        "or1.4xlarge.search": 1.674,
        "or1.8xlarge.search": 3.346,
        "or1.large.search": 0.209,
        "or1.medium.search": 0.105,
        "or1.xlarge.search": 0.419,
        "or2.12xlarge.search": 4.8,
        "or2.16xlarge.search": 6.4,
        "or2.2xlarge.search": 0.8,
        "or2.4xlarge.search": 1.6,
        "or2.8xlarge.search": 3.2,
        "or2.large.search": 0.2,
        "or2.medium.search": 0.1,
        "or2.xlarge.search": 0.401,
        "r3.2xlarge.search": 0.98,
        "r3.4xlarge.search": 1.96,
        "r3.8xlarge.search": 3.92,
        "r3.large.search": 0.245,
        "r3.xlarge.search": 0.49,
        "r4.16xlarge.search": 6.278,
        "r4.2xlarge.search": 0.785,
        "r4.4xlarge.search": 1.569,
        "r4.8xlarge.search": 3.139,
        "r4.large.search": 0.196,
        "r4.xlarge.search": 0.392,
        "r5.12xlarge.search": 4.46,
        "r5.2xlarge.search": 0.743,
        "r5.4xlarge.search": 1.487,
        "r5.large.search": 0.186,
        "r5.xlarge.search": 0.372,
        "r6g.12xlarge.search": 4.016,
        "r6g.2xlarge.search": 0.669,
        "r6g.4xlarge.search": 1.339,
        "r6g.8xlarge.search": 2.677,
        "r6g.large.search": 0.167,
        "r6g.xlarge.search": 0.335,
        "r6gd.12xlarge.search": 4.59,
        "r6gd.16xlarge.search": 6.119,
        "r6gd.2xlarge.search": 0.765,
        "r6gd.4xlarge.search": 1.53,
        "r6gd.8xlarge.search": 3.06,
        "r6gd.large.search": 0.191,
        "r6gd.xlarge.search": 0.382,
        "r7g.12xlarge.search": 4.267,
        "r7g.16xlarge.search": 5.689,
        "r7g.2xlarge.search": 0.711,
        "r7g.4xlarge.search": 1.422,
        "r7g.8xlarge.search": 2.845,
        "r7g.large.search": 0.178,
        "r7g.medium.search": 0.089,
        "r7g.xlarge.search": 0.356,
        "r7gd.12xlarge.search": 5.421,
        "r7gd.16xlarge.search": 7.229,
        "r7gd.2xlarge.search": 0.904,
        "r7gd.4xlarge.search": 1.807,
        "r7gd.8xlarge.search": 3.614,
        "r7gd.large.search": 0.226,
        "r7gd.medium.search": 0.113,
        "r7gd.xlarge.search": 0.452,
        "r7i.12xlarge.search": 5.08,
        "r7i.16xlarge.search": 6.774,
        "r7i.2xlarge.search": 0.847,
        "r7i.4xlarge.search": 1.693,
        "r7i.8xlarge.search": 3.387,
        "r7i.large.search": 0.212,
        "r7i.xlarge.search": 0.423,
        "r8g.12xlarge.search": 4.694,
        "r8g.16xlarge.search": 6.259,
        "r8g.2xlarge.search": 0.783,
        "r8g.4xlarge.search": 1.565,
        "r8g.8xlarge.search": 3.13,
        "r8g.large.search": 0.196,
        "r8g.medium.search": 0.098,
        "r8g.xlarge.search": 0.392,
        "r8gd.12xlarge.search": 5.855,
        "r8gd.16xlarge.search": 7.807,
        "r8gd.2xlarge.search": 0.976,
        "r8gd.4xlarge.search": 1.952,
        "r8gd.8xlarge.search": 3.904,
        "r8gd.large.search": 0.244,
        "r8gd.medium.search": 0.122,
        "r8gd.xlarge.search": 0.488,
        "t2.medium.search": 0.073,
        "t2.micro.search": 0.018,
        "t2.small.search": 0.036,
        "t3.medium.search": 0.073,
        "t3.small.search": 0.036,
        "ultrawarm1.large.search": 2.68,
        "ultrawarm1.medium.search": 0.238,
    }
    
    FALLBACK_SAGEMAKER_PRICING: Dict[str, float] = {
        # Hourly pricing — Current generation
        "ml.t3.medium": 0.05,
        "ml.t3.large": 0.10,
        "ml.t3.xlarge": 0.20,
        "ml.m5.large": 0.115,
        "ml.m5.xlarge": 0.23,
        "ml.m5.2xlarge": 0.461,
        "ml.m5.4xlarge": 0.922,
        "ml.c5.large": 0.102,
        "ml.c5.xlarge": 0.204,
        "ml.c5.2xlarge": 0.408,
        "ml.c5.4xlarge": 0.816,
        "ml.r5.xlarge": 0.311,
        "ml.p3.2xlarge": 3.825,
        "ml.g4dn.xlarge": 0.7364,
        "ml.g4dn.2xlarge": 1.0528,
        "ml.g5.xlarge": 1.408,
        "ml.inf1.xlarge": 0.368,
        # Previous generation
        "ml.t2.medium": 0.0464,
        "ml.t2.large": 0.0928,
        "ml.t2.xlarge": 0.1856,
        "ml.m4.xlarge": 0.28,
        "ml.m4.2xlarge": 0.56,
        "ml.m4.4xlarge": 1.12,
        "ml.c4.xlarge": 0.279,
        "ml.c4.2xlarge": 0.557,
        "ml.r4.xlarge": 0.311,
        "ml.p2.xlarge": 1.125,
    }
    
    FALLBACK_KINESIS_PRICING = {
        "shard_hour": 0.015,  # Per shard hour
        "put_payload_unit": 0.014,  # Per million units
    }
    
    FALLBACK_MSK_PRICING: Dict[str, float] = {
        # Hourly pricing per broker (us-east-1)
        "kafka.t3.small": 0.052,
        "kafka.m5.large": 0.21,
        "kafka.m5.xlarge": 0.42,
        "kafka.m5.2xlarge": 0.84,
        "kafka.m5.4xlarge": 1.68,
        "kafka.m5.8xlarge": 3.36,
        "kafka.m5.12xlarge": 5.04,
        "kafka.m5.16xlarge": 6.72,
        "kafka.m5.24xlarge": 10.08,
        # Graviton3 (m7g) — ~7% cheaper than m5
        "kafka.m7g.large": 0.196,
        "kafka.m7g.xlarge": 0.392,
        "kafka.m7g.2xlarge": 0.784,
        "kafka.m7g.4xlarge": 1.568,
        "kafka.m7g.8xlarge": 3.136,
        "kafka.m7g.12xlarge": 4.704,
        "kafka.m7g.16xlarge": 6.272,
    }
    
    # MSK instance network throughput capacity in MB/s (per broker).
    # MSK is network-bound — CPU alone is unreliable for sizing decisions.
    # Values are conservative baselines from AWS published specs.
    MSK_NETWORK_CAPACITY_MBPS: Dict[str, float] = {
        "kafka.t3.small": 62.5,        # Up to 5 Gbps
        "kafka.m5.large": 125.0,       # Up to 10 Gbps
        "kafka.m5.xlarge": 125.0,      # Up to 10 Gbps
        "kafka.m5.2xlarge": 125.0,     # Up to 10 Gbps
        "kafka.m5.4xlarge": 125.0,     # Up to 10 Gbps
        "kafka.m5.8xlarge": 125.0,     # 10 Gbps baseline
        "kafka.m5.12xlarge": 150.0,    # 12 Gbps
        "kafka.m5.16xlarge": 250.0,    # 20 Gbps
        "kafka.m5.24xlarge": 312.5,    # 25 Gbps
        "kafka.m7g.large": 156.25,     # Up to 12.5 Gbps
        "kafka.m7g.xlarge": 156.25,    # Up to 12.5 Gbps
        "kafka.m7g.2xlarge": 156.25,   # Up to 12.5 Gbps
        "kafka.m7g.4xlarge": 156.25,   # Up to 12.5 Gbps
        "kafka.m7g.8xlarge": 156.25,   # 12.5 Gbps baseline
        "kafka.m7g.12xlarge": 250.0,   # 20 Gbps
        "kafka.m7g.16xlarge": 312.5,   # 25 Gbps
    }
    
    FALLBACK_GLUE_PRICING = {
        "dpu_hour": 0.44,  # Per DPU hour
        "crawler_dpu_hour": 0.44,
    }
    
    FALLBACK_STEP_FUNCTIONS_PRICING = {
        "state_transition": 0.000025,  # Per state transition
    }
    
    FALLBACK_APPSYNC_PRICING = {
        "query_per_million": 4.00,
        "realtime_per_million": 2.00,
    }
    
    FALLBACK_EFS_PRICING = {
        "standard_per_gb_month": 0.30,
        "infrequent_per_gb_month": 0.016,
    }
    
    FALLBACK_FSX_PRICING = {
        "lustre_per_gb_month": 0.140,
        "windows_per_gb_month": 0.130,
        "ontap_per_gb_month": 0.120,
    }
    
    FALLBACK_TRANSFER_FAMILY_PRICING = {
        "server_hour": 0.30,  # Per server hour
        "data_per_gb": 0.04,
    }
    
    FALLBACK_GLOBAL_ACCELERATOR_PRICING = {
        "accelerator_hour": 0.025,
        "data_per_gb": 0.015,
    }
    
    FALLBACK_WORKSPACES_PRICING: Dict[str, float] = {
        # Monthly pricing
        "Value": 21.0,
        "Standard": 35.0,
        "Performance": 60.0,
        "Power": 76.0,
        "PowerPro": 96.0,
        "GraphicsPro": 349.0,
    }
    

    # DocumentDB on-demand instance pricing (us-east-1, standard storage config, $/hr).
    # db.r5.large web-verified $0.277 (2026-07); r5 family scales linearly; r6g ≈ 11%
    # below r5 (Graviton); t3/t4g burstable per AWS. Multiplied by num_instances and
    # region-scaled at call time. Replaces the previous flat $0.10/hr any-class estimate.
    FALLBACK_DOCUMENTDB_PRICING: Dict[str, float] = {
        "db.t3.medium": 0.078,
        "db.t4g.medium": 0.072,
        "db.r5.large": 0.277,    "db.r5.xlarge": 0.554,
        "db.r5.2xlarge": 1.108,  "db.r5.4xlarge": 2.216,
        "db.r5.8xlarge": 4.432,  "db.r5.12xlarge": 6.648,
        "db.r5.16xlarge": 8.864, "db.r5.24xlarge": 13.296,
        "db.r6g.large": 0.247,   "db.r6g.xlarge": 0.494,
        "db.r6g.2xlarge": 0.988, "db.r6g.4xlarge": 1.976,
        "db.r6g.8xlarge": 3.952, "db.r6g.12xlarge": 5.928,
        "db.r6g.16xlarge": 7.904,
    }
    # Unknown/newer classes fall back to db.r5.large — far closer than the old $0.10 flat.
    FALLBACK_DOCUMENTDB_DEFAULT_HOURLY = 0.277

    # Approximate on-demand price multipliers relative to us-east-1 (=1.00). Applied to
    # the FALLBACK_* constant tables for services WITHOUT a live Pricing API path, so a
    # resource in a pricier region is no longer priced at N. Virginia rates. These are
    # coarse per-region compute/storage deltas (not per-service exact); services already
    # priced via the live Pricing API (EC2/EBS/RDS) get true per-region pricing, and a
    # few globally-uniform services (Step Functions transitions, Global Accelerator fixed
    # hourly, Lightsail bundles) are intentionally NOT scaled. Directionally correct: the
    # old behavior understated savings for every non-us-east-1 resource on these services.
    REGION_PRICE_MULTIPLIERS: Dict[str, float] = {
        "us-east-1": 1.00, "us-east-2": 1.00, "us-west-2": 1.00, "us-west-1": 1.08,
        "ca-central-1": 1.05, "ca-west-1": 1.05,
        "eu-west-1": 1.08, "eu-west-2": 1.10, "eu-west-3": 1.10,
        "eu-central-1": 1.10, "eu-central-2": 1.12, "eu-north-1": 1.05,
        "eu-south-1": 1.10, "eu-south-2": 1.10,
        "ap-northeast-1": 1.15, "ap-northeast-2": 1.12, "ap-northeast-3": 1.15,
        "ap-southeast-1": 1.12, "ap-southeast-2": 1.20, "ap-southeast-3": 1.12,
        "ap-southeast-4": 1.20, "ap-south-1": 1.08, "ap-south-2": 1.10, "ap-east-1": 1.18,
        "sa-east-1": 1.45,
        "me-south-1": 1.15, "me-central-1": 1.15, "af-south-1": 1.18, "il-central-1": 1.12,
    }
    # Unknown regions (new/opt-in) are usually pricier than us-east-1; bias up modestly.
    DEFAULT_REGION_MULTIPLIER = 1.15

    def __init__(self):
        self._pricing_client: Optional[boto3.client] = None
        self._ec2_price_cache: Dict[str, EC2Pricing] = {}
        self._ebs_price_cache: Dict[str, EBSPricing] = {}
        self._rds_price_cache: Dict[str, RDSPricing] = {}
        self._cache_timestamp: Optional[datetime] = None
        self._previous_gen_types_cache: Optional[set] = None
        self._previous_gen_cache_timestamp: Optional[datetime] = None
        # Observability: count live-Pricing-API fallbacks per service so telemetry can
        # answer "what fraction of prices this scan were live vs static?" (see CLO-170).
        self._pricing_fallback_counts: Dict[str, int] = {}

    def _region_multiplier(self, region: Optional[str]) -> float:
        """Approximate on-demand price multiplier for a region vs us-east-1 (=1.00)."""
        if not region:
            return 1.0
        return self.REGION_PRICE_MULTIPLIERS.get(region, self.DEFAULT_REGION_MULTIPLIER)

    def _apply_region(self, value, region: Optional[str]):
        """Scale a fallback constant by the region multiplier.

        Accepts a float (returns a scaled float) or a Dict[str, float] (returns a NEW
        dict with each numeric value scaled — the class constant is never mutated).
        us-east regions (multiplier 1.0) return the value unchanged.
        """
        mult = self._region_multiplier(region)
        if mult == 1.0:
            return value
        if isinstance(value, dict):
            return {
                k: (v * mult if isinstance(v, (int, float)) else v)
                for k, v in value.items()
            }
        if isinstance(value, (int, float)):
            return value * mult
        return value

    def _record_pricing_fallback(self, service: str) -> None:
        """Increment the fallback counter for a service (never raises)."""
        try:
            self._pricing_fallback_counts[service] = (
                self._pricing_fallback_counts.get(service, 0) + 1
            )
            logger.info(f"metric=PricingFallbackUsed service={service} value=1")
        except Exception:  # pragma: no cover - metric must never break a scan
            pass

    def get_pricing_fallback_stats(self) -> Dict[str, int]:
        """Return per-service live-API fallback counts accumulated this process."""
        return dict(self._pricing_fallback_counts)

    async def get_documentdb_price(
        self,
        instance_class: str,
        region: str = "us-east-1",
    ) -> float:
        """Get DocumentDB on-demand hourly price for an instance class, region-scaled.

        Replaces the detector's previous flat $0.10/hr any-class estimate. Unknown
        classes fall back to db.r5.large-equivalent (far closer than the old flat value).
        """
        base = self.FALLBACK_DOCUMENTDB_PRICING.get(
            instance_class, self.FALLBACK_DOCUMENTDB_DEFAULT_HOURLY
        )
        return self._apply_region(base, region)

    def _get_pricing_client(self) -> boto3.client:
        """Get or create the AWS Pricing API client."""
        if self._pricing_client is None:
            # Pricing API only available in us-east-1 or ap-south-1
            self._pricing_client = boto3.client("pricing", region_name="us-east-1")
        return self._pricing_client
    
    def _is_cache_valid(self) -> bool:
        """Check if the pricing cache is still valid."""
        if self._cache_timestamp is None:
            return False
        age = datetime.now(timezone.utc) - self._cache_timestamp
        return age < timedelta(hours=self.CACHE_TTL_HOURS)
    
    def _is_prev_gen_cache_valid(self) -> bool:
        """Check if the previous-gen instance types cache is still valid."""
        if self._previous_gen_cache_timestamp is None:
            return False
        age = datetime.now(timezone.utc) - self._previous_gen_cache_timestamp
        return age < timedelta(days=7)  # Cache for 7 days
    
    # =========================================================================
    # EC2 Pricing
    # =========================================================================
    
    async def get_ec2_price(
        self, 
        instance_type: str, 
        region: str = "us-east-1"
    ) -> EC2Pricing:
        """
        Get EC2 pricing for a specific instance type and region.
        
        Args:
            instance_type: EC2 instance type (e.g., 't3.medium')
            region: AWS region
            
        Returns:
            EC2Pricing object with hourly and monthly costs
        """
        cache_key = f"{instance_type}:{region}"
        
        # Check cache first
        if self._is_cache_valid() and cache_key in self._ec2_price_cache:
            return self._ec2_price_cache[cache_key]
        
        try:
            price = await self._fetch_ec2_price_from_api(instance_type, region)
            self._ec2_price_cache[cache_key] = price
            self._cache_timestamp = datetime.now(timezone.utc)
            return price
            
        except Exception as e:
            logger.warning(f"Failed to fetch EC2 pricing from API: {e}, using fallback")
            return self._get_fallback_ec2_price(instance_type, region)
    
    async def _fetch_ec2_price_from_api(
        self, 
        instance_type: str, 
        region: str
    ) -> EC2Pricing:
        """Fetch EC2 pricing from AWS Pricing API."""
        pricing_client = self._get_pricing_client()
        
        # Convert region code to region name for Pricing API
        region_name = self._get_region_name(region)
        
        filters = [
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": region_name},
            {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
            {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
            {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
        ]
        
        # Run synchronous boto3 call in thread pool
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: pricing_client.get_products(
                ServiceCode="AmazonEC2",
                Filters=filters,
                MaxResults=1
            )
        )
        
        if not response.get("PriceList"):
            logger.warning(f"No pricing found for {instance_type} in {region}")
            return self._get_fallback_ec2_price(instance_type, region)
        
        # Parse the pricing response
        price_data = json.loads(response["PriceList"][0])
        product = price_data.get("product", {})
        attributes = product.get("attributes", {})
        
        # Get on-demand pricing
        terms = price_data.get("terms", {}).get("OnDemand", {})
        hourly_price = 0.0
        
        for term_key, term_value in terms.items():
            price_dimensions = term_value.get("priceDimensions", {})
            for dim_key, dim_value in price_dimensions.items():
                price_per_unit = dim_value.get("pricePerUnit", {})
                usd_price = price_per_unit.get("USD", "0")
                hourly_price = float(usd_price)
                break
            break
        
        return EC2Pricing(
            instance_type=instance_type,
            region=region,
            on_demand_hourly=hourly_price,
            monthly_estimate=hourly_price * 730,  # 730 hours/month
            vcpu=int(attributes.get("vcpu", 0)),
            memory_gb=float(attributes.get("memory", "0 GiB").replace(" GiB", "").replace(",", "")),
            current_generation=attributes.get("currentGeneration", "Yes") == "Yes",
        )
    
    def _get_fallback_ec2_price(self, instance_type: str, region: str) -> EC2Pricing:
        """Get fallback pricing for EC2 instance type."""
        self._record_pricing_fallback('ec2')
        hourly = self._apply_region(
            self.FALLBACK_EC2_PRICING.get(instance_type, 0.10), region  # Default $0.10/hr
        )
        
        # Determine if current generation based on type prefix
        current_gen = not self._is_previous_gen_type_static(instance_type)
        
        return EC2Pricing(
            instance_type=instance_type,
            region=region,
            on_demand_hourly=hourly,
            monthly_estimate=hourly * 730,
            current_generation=current_gen,
        )
    
    def _is_previous_gen_type_static(self, instance_type: str) -> bool:
        """Static check if instance type is previous generation (fallback)."""
        prev_gen_prefixes = (
            "t1.", "t2.",  # t3 is current
            "m1.", "m2.", "m3.", "m4.",  # m5/m6/m7 are current
            "c1.", "c3.", "c4.",  # c5/c6/c7 are current
            "r3.", "r4.",  # r5/r6/r7 are current
            "i2.", "i3.",  # i3en, i4 are current
            "d2.",  # d3 is current
            "g2.", "g3.",  # g4/g5 are current
            "p2.", "p3.",  # p4/p5 are current
            "x1.", "x1e.",
            "h1.",
            "hs1.",
            "cr1.",
            "cc2.",
            "cg1.",
        )
        return instance_type.startswith(prev_gen_prefixes)
    
    # =========================================================================
    # Dynamic Previous-Generation Instance Types
    # =========================================================================
    
    async def get_previous_gen_instance_types(
        self, 
        ec2_client: boto3.client,
        region: str = "us-east-1"
    ) -> set:
        """
        Dynamically fetch previous-generation instance types from AWS.
        
        Uses describe_instance_types with current-generation filter.
        Results are cached for 7 days.
        
        Args:
            ec2_client: Boto3 EC2 client with credentials
            region: AWS region
            
        Returns:
            Set of previous-generation instance type names
        """
        if self._is_prev_gen_cache_valid() and self._previous_gen_types_cache:
            return self._previous_gen_types_cache
        
        try:
            prev_gen_types = set()
            loop = asyncio.get_event_loop()
            paginator = ec2_client.get_paginator("describe_instance_types")
            
            # Filter for previous generation instances
            async def fetch_page(page):
                for instance_type in page.get("InstanceTypes", []):
                    if not instance_type.get("CurrentGeneration", True):
                        prev_gen_types.add(instance_type["InstanceType"])
            
            # Run paginator synchronously in thread pool
            def get_all_prev_gen():
                types = set()
                for page in paginator.paginate(
                    Filters=[{"Name": "current-generation", "Values": ["false"]}]
                ):
                    for instance_type in page.get("InstanceTypes", []):
                        types.add(instance_type["InstanceType"])
                return types
            
            prev_gen_types = await loop.run_in_executor(None, get_all_prev_gen)
            
            self._previous_gen_types_cache = prev_gen_types
            self._previous_gen_cache_timestamp = datetime.now(timezone.utc)
            
            logger.info(f"Cached {len(prev_gen_types)} previous-generation instance types")
            return prev_gen_types
            
        except Exception as e:
            logger.warning(f"Failed to fetch previous-gen types dynamically: {e}")
            # Return static fallback
            return self._get_static_previous_gen_types()
    
    def _get_static_previous_gen_types(self) -> set:
        """Static fallback for previous-generation instance types."""
        return {
            # T series
            "t1.micro", "t2.nano", "t2.micro", "t2.small", "t2.medium", 
            "t2.large", "t2.xlarge", "t2.2xlarge",
            # M series
            "m1.small", "m1.medium", "m1.large", "m1.xlarge",
            "m2.xlarge", "m2.2xlarge", "m2.4xlarge",
            "m3.medium", "m3.large", "m3.xlarge", "m3.2xlarge",
            "m4.large", "m4.xlarge", "m4.2xlarge", "m4.4xlarge", "m4.10xlarge", "m4.16xlarge",
            # C series
            "c1.medium", "c1.xlarge",
            "c3.large", "c3.xlarge", "c3.2xlarge", "c3.4xlarge", "c3.8xlarge",
            "c4.large", "c4.xlarge", "c4.2xlarge", "c4.4xlarge", "c4.8xlarge",
            # R series
            "r3.large", "r3.xlarge", "r3.2xlarge", "r3.4xlarge", "r3.8xlarge",
            "r4.large", "r4.xlarge", "r4.2xlarge", "r4.4xlarge", "r4.8xlarge", "r4.16xlarge",
            # I series
            "i2.xlarge", "i2.2xlarge", "i2.4xlarge", "i2.8xlarge",
            # D series
            "d2.xlarge", "d2.2xlarge", "d2.4xlarge", "d2.8xlarge",
            # G series (GPU)
            "g2.2xlarge", "g2.8xlarge",
            # P series (GPU)
            "p2.xlarge", "p2.8xlarge", "p2.16xlarge",
        }
    
    async def is_previous_generation(
        self, 
        instance_type: str, 
        ec2_client: Optional[boto3.client] = None
    ) -> bool:
        """
        Check if an instance type is previous generation.
        
        Args:
            instance_type: EC2 instance type to check
            ec2_client: Optional EC2 client for dynamic lookup
            
        Returns:
            True if previous generation, False if current
        """
        if ec2_client:
            try:
                prev_gen_types = await self.get_previous_gen_instance_types(ec2_client)
                return instance_type in prev_gen_types
            except Exception:
                pass
        
        # Fallback to static check
        return self._is_previous_gen_type_static(instance_type)
    
    # =========================================================================
    # EBS Pricing
    # =========================================================================
    
    async def get_ebs_price(
        self, 
        volume_type: str, 
        region: str = "us-east-1"
    ) -> EBSPricing:
        """
        Get EBS pricing for a specific volume type and region.
        
        Args:
            volume_type: EBS volume type (e.g., 'gp3', 'io2')
            region: AWS region
            
        Returns:
            EBSPricing object with per-GB and IOPS pricing
        """
        cache_key = f"{volume_type}:{region}"
        
        if self._is_cache_valid() and cache_key in self._ebs_price_cache:
            return self._ebs_price_cache[cache_key]
        
        try:
            price = await self._fetch_ebs_price_from_api(volume_type, region)
            self._ebs_price_cache[cache_key] = price
            self._cache_timestamp = datetime.now(timezone.utc)
            return price
            
        except Exception as e:
            logger.warning(f"Failed to fetch EBS pricing: {e}, using fallback")
            return self._get_fallback_ebs_price(volume_type, region)
    
    async def _fetch_ebs_price_from_api(
        self, 
        volume_type: str, 
        region: str
    ) -> EBSPricing:
        """Fetch EBS pricing from AWS Pricing API."""
        pricing_client = self._get_pricing_client()
        region_name = self._get_region_name(region)
        
        # Map volume types to pricing API terminology
        volume_api_name = {
            "gp2": "General Purpose",
            "gp3": "General Purpose",
            "io1": "Provisioned IOPS",
            "io2": "Provisioned IOPS",
            "st1": "Throughput Optimized HDD",
            "sc1": "Cold HDD",
            "standard": "Magnetic",
        }.get(volume_type, volume_type)
        
        filters = [
            {"Type": "TERM_MATCH", "Field": "volumeApiName", "Value": volume_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": region_name},
        ]
        
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: pricing_client.get_products(
                ServiceCode="AmazonEC2",
                Filters=filters,
                MaxResults=10
            )
        )
        
        if not response.get("PriceList"):
            return self._get_fallback_ebs_price(volume_type, region)
        
        # Parse pricing - look for storage pricing
        price_per_gb = 0.0
        iops_price = 0.0
        throughput_price = 0.0
        
        for price_item in response["PriceList"]:
            price_data = json.loads(price_item)
            terms = price_data.get("terms", {}).get("OnDemand", {})
            
            for term in terms.values():
                for dim in term.get("priceDimensions", {}).values():
                    description = dim.get("description", "").lower()
                    usd = float(dim.get("pricePerUnit", {}).get("USD", "0"))
                    
                    if "gb-mo" in description or "storage" in description:
                        price_per_gb = usd
                    elif "iops" in description:
                        iops_price = usd
                    elif "throughput" in description or "mbps" in description:
                        throughput_price = usd
        
        return EBSPricing(
            volume_type=volume_type,
            region=region,
            price_per_gb_month=price_per_gb or self.FALLBACK_EBS_PRICING.get(volume_type, 0.10),
            iops_price=iops_price,
            throughput_price=throughput_price,
        )
    
    def _get_fallback_ebs_price(self, volume_type: str, region: str) -> EBSPricing:
        """Get fallback pricing for EBS volume type (region-scaled)."""
        self._record_pricing_fallback('ebs')
        return EBSPricing(
            volume_type=volume_type,
            region=region,
            price_per_gb_month=self._apply_region(
                self.FALLBACK_EBS_PRICING.get(volume_type, 0.10), region
            ),
            iops_price=self._apply_region(0.065 if volume_type in ("io1", "io2") else 0.0, region),
            throughput_price=self._apply_region(0.04 if volume_type == "gp3" else 0.0, region),
        )
    
    # =========================================================================
    # Other Resource Pricing
    # =========================================================================
    
    async def get_nat_gateway_price(self, region: str = "us-east-1") -> float:
        """Get NAT Gateway hourly pricing (region-scaled)."""
        return self._apply_region(self.FALLBACK_NAT_GATEWAY_HOURLY, region)

    async def get_eip_idle_price(self, region: str = "us-east-1") -> float:
        """Get Elastic IP idle hourly pricing (region-scaled)."""
        return self._apply_region(self.FALLBACK_EIP_IDLE_HOURLY, region)

    async def get_load_balancer_price(
        self,
        lb_type: str = "application",
        region: str = "us-east-1"
    ) -> float:
        """Get Load Balancer hourly pricing (region-scaled)."""
        if lb_type == "application":
            base = self.FALLBACK_ALB_HOURLY
        elif lb_type == "network":
            base = self.FALLBACK_NLB_HOURLY
        else:
            base = self.FALLBACK_CLB_HOURLY
        return self._apply_region(base, region)

    async def get_snapshot_price(self, region: str = "us-east-1") -> float:
        """Get EBS snapshot pricing per GB-month (region-scaled)."""
        return self._apply_region(0.05, region)  # Standard EBS snapshot pricing

    # =========================================================================
    # Additional Service Pricing Methods
    # =========================================================================

    async def get_lambda_price(self, region: str = "us-east-1") -> Dict[str, float]:
        """Get Lambda pricing for a region (region-scaled)."""
        return self._apply_region(self.FALLBACK_LAMBDA_PRICING, region)

    async def get_dynamodb_price(self, region: str = "us-east-1") -> Dict[str, float]:
        """Get DynamoDB pricing for a region (region-scaled)."""
        return self._apply_region(self.FALLBACK_DYNAMODB_PRICING, region)

    async def get_elasticache_price(
        self,
        node_type: str,
        region: str = "us-east-1"
    ) -> float:
        """Get ElastiCache node hourly pricing (region-scaled fallback)."""
        return self._apply_region(
            self.FALLBACK_ELASTICACHE_PRICING.get(node_type, 0.05), region
        )

    async def get_elasticache_price_known(
        self,
        node_type: str,
        region: str = "us-east-1",
        engine: str = "redis",
    ) -> Optional[float]:
        """ElastiCache node on-demand hourly price (region-scaled), or None when
        the node type is not in the Price List table. Callers must treat None
        as MISSING, never as a default price (the OpenSearch rule, #1552).

        CLO-532 item 3: ``engine`` "valkey" reads the Valkey rows (no fallback
        to the Redis rate); Redis OSS and Memcached share the Redis rows."""
        table = (
            self.FALLBACK_ELASTICACHE_VALKEY_PRICING
            if (engine or '').strip().lower() == 'valkey'
            else self.FALLBACK_ELASTICACHE_PRICING
        )
        base = table.get((node_type or '').strip())
        if base is None:
            return None
        return self._apply_region(base, region)

    async def get_redshift_price(
        self,
        node_type: str,
        region: str = "us-east-1"
    ) -> float:
        """Get Redshift node hourly pricing (region-scaled fallback)."""
        return self._apply_region(
            self.FALLBACK_REDSHIFT_PRICING.get(node_type, 0.25), region
        )

    async def get_opensearch_price(
        self,
        instance_type: str,
        region: str = "us-east-1"
    ) -> float:
        """Get OpenSearch instance hourly pricing (region-scaled)."""
        return self._apply_region(
            self.FALLBACK_OPENSEARCH_PRICING.get(instance_type, 0.10), region
        )

    async def get_opensearch_price_known(
        self,
        instance_type: str,
        region: str = "us-east-1",
    ) -> Optional[float]:
        """OpenSearch on-demand hourly price (region-scaled), or None when the
        instance type is not in the Price List table. Callers must treat None
        as MISSING, never as a default price."""
        base = self.FALLBACK_OPENSEARCH_PRICING.get((instance_type or '').strip())
        if base is None:
            return None
        return self._apply_region(base, region)

    async def get_sagemaker_price(
        self,
        instance_type: str,
        region: str = "us-east-1"
    ) -> float:
        """Get SageMaker instance hourly pricing (region-scaled)."""
        return self._apply_region(
            self.FALLBACK_SAGEMAKER_PRICING.get(instance_type, 0.10), region
        )

    async def get_kinesis_price(self, region: str = "us-east-1") -> Dict[str, float]:
        """Get Kinesis pricing for a region (region-scaled)."""
        return self._apply_region(self.FALLBACK_KINESIS_PRICING, region)

    async def get_msk_price(
        self,
        broker_type: str,
        region: str = "us-east-1"
    ) -> float:
        """Get MSK broker hourly pricing (region-scaled)."""
        return self._apply_region(
            self.FALLBACK_MSK_PRICING.get(broker_type, 0.21), region
        )

    def get_msk_network_capacity_mbps(self, broker_type: str) -> float:
        """Get MSK instance-type max network throughput in MB/s.

        MSK is network-bound — this is used alongside CPU for oversized detection.
        Returns conservative baseline throughput per broker.
        """
        return self.MSK_NETWORK_CAPACITY_MBPS.get(broker_type, 125.0)

    async def get_glue_price(self, region: str = "us-east-1") -> Dict[str, float]:
        """Get Glue pricing for a region (region-scaled)."""
        return self._apply_region(self.FALLBACK_GLUE_PRICING, region)

    async def get_step_functions_price(self, region: str = "us-east-1") -> Dict[str, float]:
        """Get Step Functions pricing for a region.

        NOT region-scaled: Standard state-transition pricing is uniform across
        commercial regions.
        """
        return self.FALLBACK_STEP_FUNCTIONS_PRICING

    async def get_appsync_price(self, region: str = "us-east-1") -> Dict[str, float]:
        """Get AppSync pricing for a region (region-scaled)."""
        return self._apply_region(self.FALLBACK_APPSYNC_PRICING, region)

    async def get_efs_price(self, region: str = "us-east-1") -> Dict[str, float]:
        """Get EFS pricing for a region (region-scaled)."""
        return self._apply_region(self.FALLBACK_EFS_PRICING, region)

    async def get_fsx_price(
        self,
        filesystem_type: str = "windows",
        region: str = "us-east-1"
    ) -> float:
        """Get FSx pricing per GB-month for a filesystem type (region-scaled)."""
        type_map = {
            "LUSTRE": self.FALLBACK_FSX_PRICING["lustre_per_gb_month"],
            "WINDOWS": self.FALLBACK_FSX_PRICING["windows_per_gb_month"],
            "ONTAP": self.FALLBACK_FSX_PRICING["ontap_per_gb_month"],
        }
        return self._apply_region(type_map.get(filesystem_type.upper(), 0.13), region)

    async def get_transfer_family_price(self, region: str = "us-east-1") -> Dict[str, float]:
        """Get Transfer Family pricing for a region (region-scaled)."""
        return self._apply_region(self.FALLBACK_TRANSFER_FAMILY_PRICING, region)

    async def get_global_accelerator_price(self, region: str = "us-east-1") -> Dict[str, float]:
        """Get Global Accelerator pricing.

        NOT region-scaled: the accelerator hourly charge is a fixed global rate.
        """
        return self.FALLBACK_GLOBAL_ACCELERATOR_PRICING

    async def get_workspaces_price(
        self,
        bundle_type: str = "Standard",
        region: str = "us-east-1"
    ) -> float:
        """Get WorkSpaces monthly pricing for a bundle type (region-scaled).

        NOTE (CLO-170 follow-up): the us-east-1 FALLBACK_WORKSPACES_PRICING constants are
        stale for the 2026 AlwaysOn line-up (Standard/Performance web-verified ~26–30% low)
        and need a full-bundle refresh from the live console — deferred to keep bundle
        ordering consistent. The region multiplier below still corrects non-us-east-1.
        """
        return self._apply_region(
            self.FALLBACK_WORKSPACES_PRICING.get(bundle_type, 35.0), region
        )

    async def get_lightsail_price(
        self,
        bundle_id: str,
        region: str = "us-east-1"
    ) -> float:
        """Get Lightsail monthly pricing for a bundle.

        NOT region-scaled: Lightsail bundle pricing is uniform across regions.
        CLO-506: parsed by ``lightsail_bundle_monthly_price``; the substring
        match it replaces priced "xlarge_2_0" as "large". An unknown bundle
        keeps the old $5 default here; detectors call the parser directly
        and treat unknown as MISSING.
        """
        price = lightsail_bundle_monthly_price(bundle_id)
        return price if price is not None else 5.0
    
    async def get_rds_price(
        self,
        instance_class: str,
        engine: str = "mysql",
        multi_az: bool = False,
        region: str = "us-east-1"
    ) -> RDSPricing:
        """
        Get RDS pricing for a specific instance class and engine.
        
        Attempts to fetch from AWS Pricing API, falls back to static rates.
        
        Args:
            instance_class: RDS instance class (e.g., 'db.t3.medium')
            engine: Database engine (mysql, postgres, mariadb, etc.)
            multi_az: Whether Multi-AZ is enabled
            region: AWS region
            
        Returns:
            RDSPricing object with hourly and monthly costs
        """
        cache_key = f"{instance_class}:{engine}:{multi_az}:{region}"
        
        if self._is_cache_valid() and cache_key in self._rds_price_cache:
            return self._rds_price_cache[cache_key]
        
        # Try to fetch from Pricing API
        try:
            pricing = await self._fetch_rds_price_from_api(instance_class, engine, multi_az, region)
            self._rds_price_cache[cache_key] = pricing
            self._cache_timestamp = datetime.now(timezone.utc)
            return pricing
        except Exception as e:
            logger.debug(f"Failed to fetch RDS pricing from API: {e}, using fallback")

        # Use fallback pricing
        self._record_pricing_fallback('rds')
        rds_hourly_rates = {
            "db.t3.micro": 0.017,
            "db.t3.small": 0.034,
            "db.t3.medium": 0.068,
            "db.t3.large": 0.136,
            "db.t3.xlarge": 0.272,
            "db.t3.2xlarge": 0.544,
            "db.m5.large": 0.171,
            "db.m5.xlarge": 0.342,
            "db.m5.2xlarge": 0.684,
            "db.m5.4xlarge": 1.368,
            "db.m6i.large": 0.171,
            "db.m6i.xlarge": 0.342,
            "db.r5.large": 0.24,
            "db.r5.xlarge": 0.48,
            "db.r5.2xlarge": 0.96,
            "db.r6i.large": 0.24,
            "db.r6i.xlarge": 0.48,
        }
        
        hourly = self._apply_region(rds_hourly_rates.get(instance_class, 0.10), region)
        if multi_az:
            hourly *= 2

        pricing = RDSPricing(
            instance_class=instance_class,
            engine=engine,
            region=region,
            on_demand_hourly=hourly,
            monthly_estimate=hourly * 730,
            multi_az=multi_az,
        )
        
        self._rds_price_cache[cache_key] = pricing
        return pricing
    
    async def _fetch_rds_price_from_api(
        self,
        instance_class: str,
        engine: str,
        multi_az: bool,
        region: str
    ) -> RDSPricing:
        """Fetch RDS pricing from AWS Pricing API."""
        pricing_client = self._get_pricing_client()
        region_name = self._get_region_name(region)
        
        # Map engine names to Pricing API terminology
        engine_map = {
            "mysql": "MySQL",
            "postgres": "PostgreSQL",
            "mariadb": "MariaDB",
            "oracle-se2": "Oracle",
            "sqlserver-se": "SQL Server",
            "aurora-mysql": "Aurora MySQL",
            "aurora-postgresql": "Aurora PostgreSQL",
        }
        engine_name = engine_map.get(engine.lower(), engine)
        
        deployment_option = "Multi-AZ" if multi_az else "Single-AZ"
        
        filters = [
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_class},
            {"Type": "TERM_MATCH", "Field": "location", "Value": region_name},
            {"Type": "TERM_MATCH", "Field": "databaseEngine", "Value": engine_name},
            {"Type": "TERM_MATCH", "Field": "deploymentOption", "Value": deployment_option},
        ]
        
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: pricing_client.get_products(
                ServiceCode="AmazonRDS",
                Filters=filters,
                MaxResults=1
            )
        )
        
        if not response.get("PriceList"):
            raise ValueError(f"No pricing found for RDS {instance_class}")
        
        price_data = json.loads(response["PriceList"][0])
        terms = price_data.get("terms", {}).get("OnDemand", {})
        hourly_price = 0.0
        
        for term_key, term_value in terms.items():
            price_dimensions = term_value.get("priceDimensions", {})
            for dim_key, dim_value in price_dimensions.items():
                price_per_unit = dim_value.get("pricePerUnit", {})
                usd_price = price_per_unit.get("USD", "0")
                hourly_price = float(usd_price)
                break
            break
        
        return RDSPricing(
            instance_class=instance_class,
            engine=engine,
            region=region,
            on_demand_hourly=hourly_price,
            monthly_estimate=hourly_price * 730,
            multi_az=multi_az,
        )
    
    async def get_elasticache_price_dynamic(
        self,
        node_type: str,
        engine: str = "redis",
        region: str = "us-east-1"
    ) -> float:
        """
        Get ElastiCache node hourly pricing with dynamic API lookup.
        
        Args:
            node_type: ElastiCache node type (e.g., 'cache.t3.medium')
            engine: Cache engine (redis or memcached)
            region: AWS region
            
        Returns:
            Hourly price for the node type
        """
        cache_key = f"elasticache:{node_type}:{engine}:{region}"
        
        if cache_key in self._ec2_price_cache and self._is_cache_valid():
            return self._ec2_price_cache[cache_key].on_demand_hourly
        
        try:
            pricing_client = self._get_pricing_client()
            region_name = self._get_region_name(region)
            
            filters = [
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": node_type},
                {"Type": "TERM_MATCH", "Field": "location", "Value": region_name},
                {"Type": "TERM_MATCH", "Field": "cacheEngine", "Value": engine.capitalize()},
            ]
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: pricing_client.get_products(
                    ServiceCode="AmazonElastiCache",
                    Filters=filters,
                    MaxResults=1
                )
            )
            
            if response.get("PriceList"):
                price_data = json.loads(response["PriceList"][0])
                terms = price_data.get("terms", {}).get("OnDemand", {})
                for term in terms.values():
                    for dim in term.get("priceDimensions", {}).values():
                        return float(dim.get("pricePerUnit", {}).get("USD", "0"))
        except Exception as e:
            logger.debug(f"Failed to fetch ElastiCache pricing: {e}")

        self._record_pricing_fallback('elasticache')
        return self._apply_region(
            self.FALLBACK_ELASTICACHE_PRICING.get(node_type, 0.05), region
        )
    
    async def get_redshift_price_dynamic(
        self,
        node_type: str,
        region: str = "us-east-1"
    ) -> float:
        """
        Get Redshift node hourly pricing with dynamic API lookup.
        
        Args:
            node_type: Redshift node type (e.g., 'dc2.large')
            region: AWS region
            
        Returns:
            Hourly price for the node type
        """
        cache_key = f"redshift:{node_type}:{region}"
        
        if cache_key in self._ec2_price_cache and self._is_cache_valid():
            return self._ec2_price_cache[cache_key].on_demand_hourly
        
        try:
            pricing_client = self._get_pricing_client()
            region_name = self._get_region_name(region)
            
            filters = [
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": node_type},
                {"Type": "TERM_MATCH", "Field": "location", "Value": region_name},
            ]
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: pricing_client.get_products(
                    ServiceCode="AmazonRedshift",
                    Filters=filters,
                    MaxResults=1
                )
            )
            
            if response.get("PriceList"):
                price_data = json.loads(response["PriceList"][0])
                terms = price_data.get("terms", {}).get("OnDemand", {})
                for term in terms.values():
                    for dim in term.get("priceDimensions", {}).values():
                        return float(dim.get("pricePerUnit", {}).get("USD", "0"))
        except Exception as e:
            logger.debug(f"Failed to fetch Redshift pricing: {e}")

        self._record_pricing_fallback('redshift')
        return self._apply_region(
            self.FALLBACK_REDSHIFT_PRICING.get(node_type, 0.25), region
        )
    
    # =========================================================================
    # Bulk Pricing Methods
    # =========================================================================
    
    async def get_service_pricing_summary(self, region: str = "us-east-1") -> Dict[str, Any]:
        """
        Get a summary of pricing for all supported services.
        
        Useful for documentation and cost estimation UI.
        
        Returns:
            Dictionary with pricing information for all services
        """
        return {
            "region": region,
            "lambda": self.FALLBACK_LAMBDA_PRICING,
            "dynamodb": self.FALLBACK_DYNAMODB_PRICING,
            "kinesis": self.FALLBACK_KINESIS_PRICING,
            "glue": self.FALLBACK_GLUE_PRICING,
            "step_functions": self.FALLBACK_STEP_FUNCTIONS_PRICING,
            "appsync": self.FALLBACK_APPSYNC_PRICING,
            "efs": self.FALLBACK_EFS_PRICING,
            "fsx": self.FALLBACK_FSX_PRICING,
            "transfer_family": self.FALLBACK_TRANSFER_FAMILY_PRICING,
            "global_accelerator": self.FALLBACK_GLOBAL_ACCELERATOR_PRICING,
            "nat_gateway_hourly": self.FALLBACK_NAT_GATEWAY_HOURLY,
            "eip_idle_hourly": self.FALLBACK_EIP_IDLE_HOURLY,
            "alb_hourly": self.FALLBACK_ALB_HOURLY,
            "nlb_hourly": self.FALLBACK_NLB_HOURLY,
            "ebs": self.FALLBACK_EBS_PRICING,
            "ec2_sample": {k: v for k, v in list(self.FALLBACK_EC2_PRICING.items())[:5]},
        }
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def _get_region_name(self, region_code: str) -> str:
        """Convert region code to full region name for Pricing API."""
        region_names = {
            "us-east-1": "US East (N. Virginia)",
            "us-east-2": "US East (Ohio)",
            "us-west-1": "US West (N. California)",
            "us-west-2": "US West (Oregon)",
            "eu-west-1": "EU (Ireland)",
            "eu-west-2": "EU (London)",
            "eu-west-3": "EU (Paris)",
            "eu-central-1": "EU (Frankfurt)",
            "eu-north-1": "EU (Stockholm)",
            "ap-northeast-1": "Asia Pacific (Tokyo)",
            "ap-northeast-2": "Asia Pacific (Seoul)",
            "ap-northeast-3": "Asia Pacific (Osaka)",
            "ap-southeast-1": "Asia Pacific (Singapore)",
            "ap-southeast-2": "Asia Pacific (Sydney)",
            "ap-south-1": "Asia Pacific (Mumbai)",
            "sa-east-1": "South America (Sao Paulo)",
            "ca-central-1": "Canada (Central)",
            "me-south-1": "Middle East (Bahrain)",
            "af-south-1": "Africa (Cape Town)",
        }
        return region_names.get(region_code, region_code)
    
    async def get_ec2_pricing_bulk(
        self, 
        instance_types: List[str], 
        region: str = "us-east-1"
    ) -> Dict[str, EC2Pricing]:
        """
        Get pricing for multiple EC2 instance types at once.
        
        Args:
            instance_types: List of instance types to price
            region: AWS region
            
        Returns:
            Dict mapping instance type to EC2Pricing
        """
        results = {}
        
        # Fetch in parallel for efficiency
        tasks = [
            self.get_ec2_price(instance_type, region) 
            for instance_type in instance_types
        ]
        
        prices = await asyncio.gather(*tasks, return_exceptions=True)
        
        for instance_type, price in zip(instance_types, prices):
            if isinstance(price, Exception):
                logger.warning(f"Failed to get price for {instance_type}: {price}")
                results[instance_type] = self._get_fallback_ec2_price(instance_type, region)
            else:
                results[instance_type] = price
        
        return results
    
    def clear_cache(self):
        """Clear all pricing caches."""
        self._ec2_price_cache.clear()
        self._ebs_price_cache.clear()
        self._rds_price_cache.clear()
        self._cache_timestamp = None
        self._previous_gen_types_cache = None
        self._previous_gen_cache_timestamp = None

    def get_emr_instance_cost(self, instance_type: str) -> float:
        """Get total hourly cost for an EMR instance (EC2 + EMR surcharge)."""
        ec2_rate = self.FALLBACK_EC2_PRICING.get(instance_type, 0.192)
        emr_surcharge = self.FALLBACK_EMR_SURCHARGE.get(instance_type, ec2_rate * 0.25)
        return ec2_rate + emr_surcharge


# Singleton instance
_pricing_service: Optional[AWSPricingService] = None


def get_pricing_service() -> AWSPricingService:
    """Get the singleton pricing service instance."""
    global _pricing_service
    if _pricing_service is None:
        _pricing_service = AWSPricingService()
    return _pricing_service
