"""The RI/Savings Plans cache key, shared by the open savings detector and the
closed commitment detector (FSL-1.1-ALv2).

Moved verbatim from ``detectors/commitment.py`` (CLO-562) because
``savings_opportunities`` (open) writes the cache that ``commitment`` (closed)
reads, and both must use the same key.
"""

import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)


# CLO-505: the savings cache (RI/SP utilization + inventory) is keyed by the
# scanned AWS account. Neither real provider has an ``account_id`` attribute,
# so the old ``getattr(data_provider, 'account_id', '')`` keyed EVERY tenant's
# cache as ``ACCOUNT#`` — one tenant's commitments shown to all. The key is now
# the 12-digit AWS ID the scan's credentials belong to, from
# ``_aws_account_id_from_sts()``: the cache is a tenant-isolation boundary, so
# the key never trusts a caller-supplied ``_account_id``. An unresolvable ID
# skips the read.
UNRESOLVED_ACCOUNT_WARNING = (
    "Commitment checks (RI/Savings Plans) skipped: the AWS account ID could not "
    "be resolved, so the commitment data for this account could not be read. "
    "This is MISSING data, not 'no commitment waste'."
)


def commitment_cache_account_id(data_provider: Any) -> Optional[str]:
    """The AWS account ID that keys the RI/SP savings cache, or None.

    Shared by the cache writer (savings.py) and the reader (this module) so
    both always use the same key. Never falls back to '' or the CloudWise
    UUID: a None means the caller must skip the cache entirely. Uses the
    strict STS-only resolver (always sts:GetCallerIdentity on the scan's own
    credentials, once per provider), never the trusting ``_aws_account_id``."""
    resolver = getattr(data_provider, '_aws_account_id_from_sts', None)
    if not callable(resolver):
        return None
    try:
        account = resolver()
    except Exception as e:  # noqa: BLE001 - unknown ID means skip, never guess
        logger.warning("Could not resolve AWS account ID for commitment cache: %s", e)
        return None
    if isinstance(account, str) and re.fullmatch(r'\d{12}', account):
        return account
    return None


def note_unresolved_account(data_provider: Any) -> None:
    """Record the skipped commitment read as a MISSING-data scan warning."""
    warnings = getattr(data_provider, 'data_warnings', None)
    if isinstance(warnings, list) and UNRESOLVED_ACCOUNT_WARNING not in warnings:
        warnings.append(UNRESOLVED_ACCOUNT_WARNING)
