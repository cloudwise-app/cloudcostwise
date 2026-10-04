"""
Per-(account, detector) circuit breaker.

See ``docs/operations/SCAN-PIPELINE-SCALING-SPEC.md`` §3.6 (Phase 4).

The in-process ``CircuitBreaker`` in ``waste_detection_service.py`` opens
for all detectors after 5 consecutive failures of any detector — too
coarse (one flaky detector punishes the other 40) and non-persistent
(warm and cold Lambda invokes start from zero state). Phase 4 replaces
it with a **per-(account_id, detector_id)** breaker persisted in
DynamoDB with a 1-hour TTL, matching the spec:

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_run_detector_guarded, d, ctx): d
                   for d in detectors if not _is_circuit_open(d, account_id)}

Semantics:
- After ``failure_threshold`` consecutive timeouts/errors on the same
  (account, detector) pair, the breaker opens for ``ttl_seconds``.
- While open, the scan engine skips the detector and emits
  ``DetectorCircuitOpen`` metric (see ``metrics.py``).
- On a successful run the breaker is reset (item deleted).
- AccessDenied is **not** a breaker-worthy failure — customers missing
  permissions for a service is expected steady-state, not a transient
  condition that should hide the detector.

Port contract:
- ``is_open(account, detector)``: cheap read, returns True if open now.
- ``record_failure(account, detector, error_class)``: increments the
  consecutive-failure counter and opens the circuit when threshold is hit.
- ``record_success(account, detector)``: resets the counter.

Safety contract (matches credential_cache.py):
- Adapters MUST swallow backend errors; ``is_open`` falls through to
  False on any DynamoDB error so the detector still runs.
- Adapters MUST never raise.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# Defaults — tune at the adapter (terraform env var) if needed.
DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_TTL_SECONDS = 3600  # 1 hour


# ---------------------------------------------------------------------------
# Value object (returned by state inspection — for tests & diagnostics)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CircuitState:
    """Observed state of a single (account, detector) circuit."""

    is_open: bool
    fail_count: int
    opened_at_epoch: Optional[int] = None
    expires_at_epoch: Optional[int] = None


@dataclass(frozen=True)
class Reservation:
    """Outcome of a ``try_reserve`` call.

    - ``granted`` — True iff the caller may invoke the detector and MUST
      release the reservation afterwards.
    - ``state`` — observed circuit state at the moment of the decision,
      for logging / metrics. Populated best-effort.
    """

    granted: bool
    state: CircuitState


# ---------------------------------------------------------------------------
# Port Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class CircuitBreakerPort(Protocol):
    """Per-(account, detector) circuit breaker.

    Implementations MUST:
    - return False from ``is_open`` on any backend failure (fail-open so
      observability never takes down scans),
    - swallow backend errors from ``record_failure`` / ``record_success`` /
      ``try_reserve`` / ``release_reservation``,
    - never raise.

    ``try_reserve`` / ``release_reservation`` (Phase 4.x, issue #318) are
    optional for Port consumers — the scan engine uses ``getattr`` to
    detect them and falls back to ``is_open`` when they are absent. The
    distinction matters under parallel region fan-out: N concurrent
    region scanners can each see ``is_open = False`` simultaneously
    (because no failure has committed yet), each run the flaky detector
    to its full per-call timeout, and only *then* collectively trip the
    breaker after N > threshold failures all commit. ``try_reserve``
    closes the race with an atomic conditional increment of an
    ``in_flight`` counter on the same DynamoDB row: once
    ``fail_count + in_flight >= threshold``, further reservations are
    rejected and the detector is short-circuited.
    """

    def is_open(
        self,
        *,
        account_id: str,
        detector_id: str,
    ) -> bool:  # pragma: no cover - Protocol
        ...

    def record_failure(
        self,
        *,
        account_id: str,
        detector_id: str,
        error_class: Optional[str] = None,
    ) -> CircuitState:  # pragma: no cover - Protocol
        ...

    def record_success(
        self,
        *,
        account_id: str,
        detector_id: str,
    ) -> None:  # pragma: no cover - Protocol
        ...

    def try_reserve(
        self,
        *,
        account_id: str,
        detector_id: str,
    ) -> "Reservation":  # pragma: no cover - Protocol
        """Atomically attempt to reserve a slot for running the detector.

        Returns a ``Reservation`` whose ``granted`` attribute indicates
        whether the caller may invoke the detector. Implementations MUST
        return ``Reservation(granted=True, ...)`` on any backend failure
        (fail-open: resilience infra never reduces coverage).
        """
        ...

    def release_reservation(
        self,
        *,
        account_id: str,
        detector_id: str,
        success: bool = False,
    ) -> None:  # pragma: no cover - Protocol
        """Release a previously-granted reservation.

        Idempotent from the caller's perspective and best-effort at the
        backend; callers MUST invoke exactly once per granted reservation
        (typically in a ``finally`` block). Releasing a reservation that
        was never granted is a no-op.

        ``success`` (CLO-360) tells an implementation that the detector
        call this reservation covered succeeded, so it MAY fold
        ``record_success``'s effect into this same call instead of the
        caller paying for a separate one. Purely an optimization hint —
        an implementation with no failure-marker state (like
        ``NullCircuitBreaker``) may ignore it.
        """
        ...


@runtime_checkable
class CircuitBreakerProvider(Protocol):
    """Factory returning a ``CircuitBreakerPort`` (or ``None`` if disabled)."""

    def __call__(self) -> Optional[CircuitBreakerPort]:  # pragma: no cover - Protocol
        ...


# ---------------------------------------------------------------------------
# Key helper (mirrors credential_cache.build_cache_key — same safety rationale)
# ---------------------------------------------------------------------------


def build_breaker_key(*, account_id: str, detector_id: str) -> str:
    """Partition-key value for the circuit-breaker table.

    Uses a human-readable ``{account}#{detector}`` composite so ops can
    inspect items in the console without running hashes manually.

    CLO-178: the scan engine passes a region-qualified detector identity
    (``"s3@us-east-1"``), so circuits are effectively scoped per
    (account, detector, region). The daily pipeline runs all regions in
    parallel; an account-level scope made them share one reserve budget
    and silently blanked heavy detectors in most regions. Account
    IDs are already considered semi-sensitive but not secret; we do not
    SHA them here because the cardinality + readability trade-off favours
    plaintext in this table (contrast with the credential cache, which
    hashes because the role ARN embedded in the key *is* sensitive).
    """
    return f"{account_id}#{detector_id}"


# ---------------------------------------------------------------------------
# Default: no-op breaker (always closed, never records)
# ---------------------------------------------------------------------------


class NullCircuitBreaker:
    """Circuit breaker that is always closed.

    Default when the runtime does not configure a DynamoDB-backed
    breaker. Tests and CLI scripts get this for free and see no change
    in behaviour.
    """

    def is_open(self, *, account_id: str, detector_id: str) -> bool:
        return False

    def record_failure(
        self,
        *,
        account_id: str,
        detector_id: str,
        error_class: Optional[str] = None,
    ) -> CircuitState:
        return CircuitState(is_open=False, fail_count=0)

    def record_success(self, *, account_id: str, detector_id: str) -> None:
        return None

    def try_reserve(
        self,
        *,
        account_id: str,
        detector_id: str,
    ) -> Reservation:
        return Reservation(granted=True, state=CircuitState(is_open=False, fail_count=0))

    def release_reservation(
        self, *, account_id: str, detector_id: str, success: bool = False
    ) -> None:
        return None


__all__ = [
    "DEFAULT_FAILURE_THRESHOLD",
    "DEFAULT_TTL_SECONDS",
    "CircuitBreakerPort",
    "CircuitBreakerProvider",
    "CircuitState",
    "NullCircuitBreaker",
    "Reservation",
    "build_breaker_key",
]
