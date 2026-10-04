"""
Tier-based detector routing constants.

Defines which detector subset each customer tier runs. This module is
intentionally pure data + small pure helpers so it can be imported from
anywhere (lambdas, backend, tests) without pulling in AWS clients or the
full ``WasteDetectionService``.

See ``docs/operations/SCAN-PIPELINE-SCALING-SPEC.md`` §3.7 and §5 Phase 5.

Current scope (Phase 5 step 1):
    - Define ``Tier`` enum mirroring ``backend/app/models/tier.py``.
    - Declare ``FREE_TIER_DETECTORS`` (curated top-20 high-signal set).
    - Declare ``TIER_DETECTOR_MAP`` → selector function.
    - Provide ``resolve_detector_set()`` helper that callers use once
      plumbing lands in the region scanner (Phase 5 step 3).

Non-goals for this PR:
    - Wiring into the region scanner handler.
    - Fetching tier from DynamoDB.
    - CUR-based pre-filter (Phase 5b).
"""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet, Set


class Tier(str, Enum):
    """Customer tier.

    Mirrors ``backend/app/models/tier.py``. Duplicated here so that
    ``cloudwise_scan_core`` (runtime-agnostic) does not depend on the
    FastAPI backend package.
    """

    FREE = "free"
    SHIELD = "shield"
    AGENTIC = "agentic"
    COMPLIANCE = "compliance"


# Top-20 high-signal detectors run on the Free tier.
#
# Selection criteria (see spec §3.7):
#   1. High probability of producing a finding in a typical single-account setup.
#   2. Covers the forgotten-resource classes users can't see themselves
#      (unattached EBS, idle EIPs, orphaned DNS, old snapshots).
#   3. Runs against services almost every account uses (EC2, S3, Lambda,
#      CloudWatch, IAM/security posture).
#   4. Cheap to execute — avoids detectors that scan large inventories
#      (e.g. per-resource Redshift / OpenSearch / FSx deep dives).
#
# Conversion hook: a Free user should reliably see ≥ 1 finding on their
# first scan, which drives the Free → Shield upgrade funnel (§3.7).
FREE_TIER_DETECTORS: FrozenSet[str] = frozenset({
    # Compute (most common waste)
    "ec2",
    "lambda",
    "sagemaker",
    "lightsail",
    "workspaces",
    # Storage (high-hit, low-cost to scan)
    "ebs",
    "s3",
    "efs",
    "ecr",
    # Database (ubiquitous)
    "rds",
    "dynamodb",
    "elasticache",
    # Network (forgotten-resource class)
    "network",           # EIPs, NAT Gateways, unused LBs
    "vpc_endpoint",
    "orphaned_dns",
    # Management (cheap, high-signal)
    "cloudwatch",
    "cloudwatch_dashboard",
    # Security & savings (always valuable)
    "security_posture",
    "savings_opportunities",
    "compute_optimizer",
})

assert len(FREE_TIER_DETECTORS) == 20, (
    f"FREE_TIER_DETECTORS must contain exactly 20 entries, got {len(FREE_TIER_DETECTORS)}"
)


def _paid_detector_set(all_keys: Set[str]) -> Set[str]:
    """Paid tiers run the full detector set."""
    return set(all_keys)


def _free_detector_set(all_keys: Set[str]) -> Set[str]:
    """Free tier runs only the curated top-20 (intersected with what's registered)."""
    return set(FREE_TIER_DETECTORS) & all_keys


# Map: Tier → selector(all_detector_keys) -> Set[str]
#
# Shield, Agentic, and Compliance share the same base detector set. The
# premium features of Agentic (deep optimization, auto-remediation) and
# Compliance (air-gapped, 365-day retention) are orthogonal to which
# detectors run and are layered on top downstream.
TIER_DETECTOR_MAP = {
    Tier.FREE: _free_detector_set,
    Tier.SHIELD: _paid_detector_set,
    Tier.AGENTIC: _paid_detector_set,
    Tier.COMPLIANCE: _paid_detector_set,
}


def resolve_detector_set(tier: Tier, all_detector_keys: Set[str]) -> Set[str]:
    """Return the set of detector keys that should run for ``tier``.

    Parameters
    ----------
    tier:
        Customer tier. If an unknown value slips through (e.g. a legacy
        row in the users table), we default to the Free set rather than
        the paid set — fail safe on cost, not on coverage.
    all_detector_keys:
        Full set of registered detector keys (``DETECTOR_METHODS.keys()``
        in ``waste_detection_service``). Passed in rather than imported
        to keep this module free of the AWS-heavy service dependency.
    """

    selector = TIER_DETECTOR_MAP.get(tier, _free_detector_set)
    return selector(all_detector_keys)
