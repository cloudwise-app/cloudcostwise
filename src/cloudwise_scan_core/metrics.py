"""
Per-detector CloudWatch Embedded Metric Format (EMF) emitter.

See ``docs/operations/SCAN-PIPELINE-SCALING-SPEC.md`` §4.1 (Phase 4).

EMF is a JSON payload that, when written to a Lambda's stdout (or any
CloudWatch Logs log group), is automatically parsed by CloudWatch Logs
and the declared metrics are published to the corresponding namespace at
**no additional ingestion cost** — we pay for Log ingestion once and get
metrics for free. This avoids the per-metric ``PutMetricData`` cost that
would otherwise be material at ~40 detectors × thousands of accounts ×
daily scans.

Design:
- A ``MetricsEmitter`` port Protocol that the scan engine calls from
  ``_run_detector_with_timeout`` (and in the future from the outer
  Aggregate Lambda for per-account summary metrics).
- A default ``StdoutEmfMetricsEmitter`` that serialises the EMF document
  to ``print(...)``. Lambda's default log driver forwards stdout to
  CloudWatch Logs, so this is all that's needed in production.
- Dimensions and non-dimension properties are both expressible; the
  non-dimension ``AccountIdHash``, ``RunId`` and ``Success`` are carried
  as searchable log fields (CloudWatch Logs Insights) without inflating
  the metric cardinality — CloudWatch metrics bill per unique dimension
  set, so we keep dimensions to three and push everything else into the
  flat log body.

Safety contract:
- Metrics are **observability**, never correctness. Emission failures are
  logged at DEBUG and swallowed. A broken emitter must never fail a scan.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, runtime_checkable

logger = logging.getLogger(__name__)


# The CloudWatch metric namespace is the single place Phase 4 metrics land.
# Do not change without updating the dashboards & alarms in §4.2 / §4.3.
METRIC_NAMESPACE = "CloudWise/Scan"


# ---------------------------------------------------------------------------
# Dimension configuration (cost control, 2026-04-28)
# ---------------------------------------------------------------------------
#
# CloudWatch bills $0.30/series/month per unique dimension combination
# (USAGE_TYPE = ``CW:MetricMonitorUsage`` → ``MetricStorage:AWS/Logs-EMF``).
# At full Phase 4/5 cardinality (Env × DetectorId × Region + tier dim set)
# this layer alone produces ~2.6k series ≈ $660/mo. To preserve runway
# we ship a runtime kill-switch:
#
#   CLOUDWISE_EMF_DIMENSIONS         comma list, primary dim set
#   CLOUDWISE_EMF_TIER_DIMENSIONS    comma list, parallel tier dim set
#
# Both UNSET → no ``_aws`` block in the EMF document → CloudWatch Logs
# stores the line as plain structured JSON, no metrics extracted, $0
# marginal cost. Log fields (Environment, DetectorId, Region, ScanTier,
# all counters) are still present at the top level so CloudWatch Logs
# Insights queries continue to work — you trade live dashboards for
# ad-hoc Logs Insights queries until you re-enable.
#
# Re-enable recipes (set Lambda env vars, no code change required):
#
#   # Cheapest useful setting (~$38/mo): per-detector totals across all regions
#   CLOUDWISE_EMF_DIMENSIONS=Environment,DetectorId
#
#   # Add per-tier rollups (~$50/mo extra)
#   CLOUDWISE_EMF_TIER_DIMENSIONS=Environment,ScanTier,DetectorId
#
#   # Full Phase 4 fidelity (~$660/mo) — only after >=1 paid customer
#   CLOUDWISE_EMF_DIMENSIONS=Environment,DetectorId,Region
#
# See ``docs/operations/SCAN-PIPELINE-SCALING-SPEC.md`` §4.1a for the cost
# math and decision log.

_ALLOWED_PRIMARY_DIMENSIONS: Tuple[str, ...] = (
    "Environment",
    "DetectorId",
    "Region",
)
_ALLOWED_TIER_DIMENSIONS: Tuple[str, ...] = (
    "Environment",
    "ScanTier",
    "DetectorId",
)

ENV_PRIMARY_DIMENSIONS = "CLOUDWISE_EMF_DIMENSIONS"
ENV_TIER_DIMENSIONS = "CLOUDWISE_EMF_TIER_DIMENSIONS"


def _parse_dimension_list(raw: Optional[str], allowed: Tuple[str, ...]) -> List[str]:
    """Parse a comma-separated dim list, dropping unknown / empty entries.

    Unknown values are ignored (logged at DEBUG) rather than raised so
    that a typo in env config never crashes a scan — this is observability,
    not correctness.
    """
    if not raw:
        return []
    parts = [p.strip() for p in raw.split(",")]
    out: List[str] = []
    for part in parts:
        if not part:
            continue
        if part not in allowed:
            logger.debug("metrics: ignoring unknown dimension %r", part)
            continue
        if part not in out:
            out.append(part)
    return out


@dataclass(frozen=True)
class EmfDimensionsConfig:
    """Which dimension sets the emitter publishes to CloudWatch.

    Empty lists mean "do not extract any metrics for that set". When
    BOTH are empty, the EMF document is written without the ``_aws``
    block — log line still ingested (cheap) but no metric series are
    created (zero ``MetricStorage:AWS/Logs-EMF`` cost).
    """

    primary: Tuple[str, ...] = ()
    tier: Tuple[str, ...] = ()

    @classmethod
    def from_env(cls, environ: Optional[Dict[str, str]] = None) -> "EmfDimensionsConfig":
        env = environ if environ is not None else os.environ
        primary = _parse_dimension_list(env.get(ENV_PRIMARY_DIMENSIONS), _ALLOWED_PRIMARY_DIMENSIONS)
        tier = _parse_dimension_list(env.get(ENV_TIER_DIMENSIONS), _ALLOWED_TIER_DIMENSIONS)
        return cls(primary=tuple(primary), tier=tuple(tier))

    def any_metrics_enabled(self) -> bool:
        return bool(self.primary) or bool(self.tier)


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass
class DetectorMetricEvent:
    """A single detector execution's metric payload.

    One call to ``emit`` per detector invocation produces one EMF record,
    which in turn drives one datapoint per metric on the declared
    dimensions. Keep the fields flat and JSON-friendly.
    """

    environment: str
    detector_id: str
    region: str
    duration_ms: int
    findings_count: int
    # Counters — we always emit 0 when a dimension did not occur so that
    # CloudWatch rate math (SUM over 1m / 5m) works without gaps.
    errors: int = 0
    api_throttles: int = 0
    circuit_open: int = 0
    timeouts: int = 0
    access_denied: int = 0
    # Phase 5 — §3.8: detector skipped before execution because the
    # account's CUR showed no spend on any service that maps to it
    # (``DetectorSkippedCURFilter``) or because the customer's
    # subscription tier does not include it (``DetectorSkippedTierFilter``).
    # Both are emitted as zero-duration, zero-findings events so that
    # dashboards can graph "detectors skipped / scan" without affecting
    # the existing duration / findings SUMs.
    skipped_cur_filter: int = 0
    skipped_tier_filter: int = 0
    # Non-dimension context (carried as EMF properties for Logs Insights).
    account_id: Optional[str] = None
    run_id: Optional[str] = None
    success: bool = True
    error_class: Optional[str] = None
    # Customer tier of the account being scanned (Phase 5 — §3.7). When
    # set, the emitter adds a parallel dimension set [Environment,
    # ScanTier, DetectorId] so dashboards can roll up per-tier duration
    # / findings / error rates. Absent means "tier unknown / N/A" and
    # the extra dimension set is not emitted.
    scan_tier: Optional[str] = None
    extras: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Port
# ---------------------------------------------------------------------------


@runtime_checkable
class MetricsEmitter(Protocol):
    """Runtime-supplied metrics sink.

    Implementations MUST swallow their own errors — metrics emission
    cannot be allowed to fail a scan.
    """

    def emit(self, event: DetectorMetricEvent) -> None:  # pragma: no cover - Protocol
        ...


@runtime_checkable
class MetricsEmitterProvider(Protocol):
    def __call__(self) -> Optional[MetricsEmitter]:  # pragma: no cover - Protocol
        ...


# ---------------------------------------------------------------------------
# Default implementation — EMF over stdout
# ---------------------------------------------------------------------------


class StdoutEmfMetricsEmitter:
    """Default ``MetricsEmitter`` writing EMF JSON lines to stdout.

    On AWS Lambda, stdout is forwarded to CloudWatch Logs where the EMF
    parser converts the declared metrics into the ``CloudWise/Scan``
    namespace. Outside Lambda (tests, local scripts) the output is still
    well-formed JSON and harmless.
    """

    def __init__(
        self,
        *,
        namespace: str = METRIC_NAMESPACE,
        writer: Optional[Callable[[str], None]] = None,
        dimensions: Optional[EmfDimensionsConfig] = None,
    ) -> None:
        self._namespace = namespace
        # Writer defaults to ``print`` via sys.stdout. Kept injectable for
        # tests (capsys can observe, or supply a list.append).
        self._writer = writer or (lambda line: print(line, file=sys.stdout, flush=False))
        # Dimension config. ``None`` → read env at construction time;
        # tests can pass an explicit ``EmfDimensionsConfig`` to bypass env.
        self._dimensions = dimensions if dimensions is not None else EmfDimensionsConfig.from_env()

    def emit(self, event: DetectorMetricEvent) -> None:
        try:
            doc = self._build_emf_document(event)
            self._writer(json.dumps(doc, default=str, separators=(",", ":")))
        except Exception as exc:  # noqa: BLE001 — metrics never fail a scan
            logger.debug(
                "metrics emission failed (%s); skipping detector=%s",
                exc.__class__.__name__,
                getattr(event, "detector_id", "?"),
            )

    def _build_emf_document(self, event: DetectorMetricEvent) -> Dict[str, Any]:
        # Account IDs never appear verbatim in metrics; we hash them so
        # ``AccountIdHash`` can be grouped in Logs Insights without
        # leaking the AWS account number into CloudWatch query text.
        account_hash = (
            "sha256:" + hashlib.sha256(event.account_id.encode("utf-8")).hexdigest()[:16]
            if event.account_id
            else None
        )
        timestamp_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        metrics: List[Dict[str, str]] = [
            {"Name": "DetectorDurationMs", "Unit": "Milliseconds"},
            {"Name": "DetectorFindingsCount", "Unit": "Count"},
            {"Name": "DetectorErrors", "Unit": "Count"},
            {"Name": "DetectorAPIThrottles", "Unit": "Count"},
            {"Name": "DetectorCircuitOpen", "Unit": "Count"},
            {"Name": "DetectorTimeouts", "Unit": "Count"},
            {"Name": "DetectorAccessDenied", "Unit": "Count"},
            {"Name": "DetectorSkippedCURFilter", "Unit": "Count"},
            {"Name": "DetectorSkippedTierFilter", "Unit": "Count"},
        ]

        # Dimension sets are now configurable (cost control, 2026-04-28).
        # See module docstring + SCAN-PIPELINE-SCALING-SPEC.md §4.1a.
        dimension_sets: List[List[str]] = []
        if self._dimensions.primary:
            dimension_sets.append(list(self._dimensions.primary))
        # Tier dim set is only meaningful when the event carries scan_tier.
        if self._dimensions.tier and event.scan_tier:
            dimension_sets.append(list(self._dimensions.tier))

        doc: Dict[str, Any] = {
            # Dimensions / context (always present at top level so Logs
            # Insights queries work regardless of whether metrics are on).
            "Environment": event.environment,
            "DetectorId": event.detector_id,
            "Region": event.region,
            # Metric values
            "DetectorDurationMs": int(event.duration_ms),
            "DetectorFindingsCount": int(event.findings_count),
            "DetectorErrors": int(event.errors),
            "DetectorAPIThrottles": int(event.api_throttles),
            "DetectorCircuitOpen": int(event.circuit_open),
            "DetectorTimeouts": int(event.timeouts),
            "DetectorAccessDenied": int(event.access_denied),
            "DetectorSkippedCURFilter": int(event.skipped_cur_filter),
            "DetectorSkippedTierFilter": int(event.skipped_tier_filter),
            # Non-dimension context (searchable via Logs Insights).
            "Success": bool(event.success),
        }

        # Only attach the ``_aws`` block when at least one dimension set
        # is configured. Without it CloudWatch Logs treats the line as
        # plain JSON and creates zero metric series — the cost-saving
        # default. With it, declared metrics are extracted as usual.
        if dimension_sets:
            doc["_aws"] = {
                "Timestamp": timestamp_ms,
                "CloudWatchMetrics": [
                    {
                        "Namespace": self._namespace,
                        "Dimensions": dimension_sets,
                        "Metrics": metrics,
                    }
                ],
            }
        if event.scan_tier:
            # Top-level field so both the (optional) tier dim set and
            # Logs Insights can see it.
            doc["ScanTier"] = event.scan_tier
        if account_hash:
            doc["AccountIdHash"] = account_hash
        if event.run_id:
            doc["RunId"] = event.run_id
        if event.error_class:
            doc["ErrorClass"] = event.error_class
        if event.extras:
            # Merge last — never shadow required fields.
            for k, v in event.extras.items():
                if k not in doc:
                    doc[k] = v
        return doc


class NullMetricsEmitter:
    """Emitter that discards all events. Used as the library default."""

    def emit(self, event: DetectorMetricEvent) -> None:  # pragma: no cover - trivial
        return None


# ---------------------------------------------------------------------------
# Throttle classification
# ---------------------------------------------------------------------------


_THROTTLE_SIGNATURES = (
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
    "RequestThrottled",
    "ProvisionedThroughputExceededException",
)


def is_throttle_error(exc: BaseException) -> bool:
    """Return True if ``exc`` is a recognisable AWS-side rate-limit error.

    The scan engine calls this when classifying a detector failure so the
    ``DetectorAPIThrottles`` metric is attributed correctly. Covers both
    botocore ``ClientError`` (inspected via ``response['Error']['Code']``)
    and bare exception message matches for non-botocore callers.
    """
    code = None
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
    if code and any(sig in code for sig in _THROTTLE_SIGNATURES):
        return True
    message = str(exc)
    return any(sig in message for sig in _THROTTLE_SIGNATURES)


__all__ = [
    "ENV_PRIMARY_DIMENSIONS",
    "ENV_TIER_DIMENSIONS",
    "EmfDimensionsConfig",
    "METRIC_NAMESPACE",
    "DetectorMetricEvent",
    "MetricsEmitter",
    "MetricsEmitterProvider",
    "NullMetricsEmitter",
    "StdoutEmfMetricsEmitter",
    "is_throttle_error",
]
