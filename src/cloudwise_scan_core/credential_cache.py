"""
Credential cache for short-lived STS AssumeRole sessions.

See ``docs/operations/SCAN-PIPELINE-SCALING-SPEC.md`` §3.5 (v1.11).

The scan engine obtains temporary credentials for each (account, role) pair
via ``sts:AssumeRole`` before scanning a region. At thousands of accounts
the aggregate call rate approaches the shared 3K-rps STS throttle — the
cache exists to turn that O(scans-per-day) call rate into
O(accounts-per-day) by reusing still-valid sessions.

The **port** (Protocol) is framework-free: it just defines ``get`` and
``put``. Concrete adapters live in runtime-specific packages
(Lambda → ``lambdas/waste_detection_region_scanner/adapters.py`` →
``DynamoDBCredentialCache``). The default provider is a no-op so tests and
ad-hoc scripts never need DynamoDB configured.

Safety contract:
- The cache is a **perf optimisation**, not a correctness requirement.
- Adapters must swallow their own backend errors and return ``None`` from
  ``get`` / silently no-op from ``put``. Callers then fall through to a
  live AssumeRole.
- Adapters must enforce a 5-minute safety margin: never return a cached
  entry whose expiration is within the next 300 seconds.
- ``cache_key`` is hashed (sha256) before being used as the partition key,
  so customer role ARNs don't appear verbatim in DynamoDB item IDs or
  CloudWatch query logs.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# 5 minute safety margin — never return credentials that are about to expire.
_MIN_REMAINING_SECONDS = 300


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CachedCredentials:
    """Short-lived STS credentials plus their absolute expiration.

    ``expiration`` is an aware UTC datetime matching what
    ``sts:AssumeRole`` returns in ``Credentials.Expiration``.
    """

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime

    def is_fresh(self, *, now: Optional[datetime] = None) -> bool:
        """True if the session still has > 5 minutes of life left."""
        current = now or datetime.now(timezone.utc)
        return (self.expiration - current).total_seconds() > _MIN_REMAINING_SECONDS


# ---------------------------------------------------------------------------
# Cache key derivation
# ---------------------------------------------------------------------------


def build_cache_key(
    *,
    account_id: str,
    role_arn: str,
    external_id: Optional[str],
) -> str:
    """Deterministic sha256 of the identity tuple.

    The output is safe to log (opaque 64-char hex) and stable across
    processes so warm and cold Lambda invocations land on the same entry.
    """
    payload = f"sts:{account_id}:{role_arn}:{external_id or '-'}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Port Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class CredentialCachePort(Protocol):
    """Read-through cache for STS AssumeRole output.

    Implementations MUST:
    - swallow backend errors (log at WARNING; never raise from get/put),
    - enforce a 5-minute safety margin on freshness,
    - never return credentials they cannot fully validate.
    """

    def get(
        self,
        *,
        account_id: str,
        role_arn: str,
        external_id: Optional[str],
    ) -> Optional[CachedCredentials]:  # pragma: no cover - Protocol
        ...

    def put(
        self,
        *,
        account_id: str,
        role_arn: str,
        external_id: Optional[str],
        credentials: CachedCredentials,
    ) -> None:  # pragma: no cover - Protocol
        ...


@runtime_checkable
class CredentialCacheProvider(Protocol):
    """Factory returning a ``CredentialCachePort`` (or ``None`` if disabled)."""

    def __call__(self) -> Optional[CredentialCachePort]:  # pragma: no cover - Protocol
        ...


# ---------------------------------------------------------------------------
# Default: no-op cache
# ---------------------------------------------------------------------------


class NullCredentialCache:
    """Cache that always misses and accepts every write silently.

    Used as the default provider and in tests / CLI scripts where the
    DynamoDB table does not exist.
    """

    def get(
        self,
        *,
        account_id: str,
        role_arn: str,
        external_id: Optional[str],
    ) -> Optional[CachedCredentials]:
        return None

    def put(
        self,
        *,
        account_id: str,
        role_arn: str,
        external_id: Optional[str],
        credentials: CachedCredentials,
    ) -> None:
        return None


__all__ = [
    "CachedCredentials",
    "CredentialCachePort",
    "CredentialCacheProvider",
    "NullCredentialCache",
    "build_cache_key",
]


# ---------------------------------------------------------------------------
# Optional coerce helper for adapters — used by DynamoDB impl to parse the
# ISO-8601 ``expiration`` attribute we wrote on put(). Broken out here so
# the adapter can share the normalisation logic without duplicating it.
# ---------------------------------------------------------------------------


def parse_expiration(value: Any) -> Optional[datetime]:
    """Parse an ``expiration`` column back into an aware UTC datetime.

    Accepts either a datetime (pass-through, ensures tz-aware UTC) or an
    ISO-8601 string. Returns None on parse failure so callers can treat it
    as a cache miss.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        # Normalise trailing Z to +00:00 for fromisoformat.
        normalised = value.rstrip()
        if normalised.endswith("Z"):
            normalised = normalised[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalised)
        except ValueError:
            logger.debug("Failed to parse expiration value: %r", value)
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None
