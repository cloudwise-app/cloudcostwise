"""
cloudwise_scan_core — runtime-agnostic waste detection engine.

See README.md and docs/operations/SCAN-PIPELINE-SCALING-SPEC.md §5 Phase 1.

The scan engine is framework-free. Runtimes (Lambda, ECS, EKS, FastAPI,
CLI, tests) wire concrete adapters via ``configure_providers(...)``.
"""

from cloudwise_scan_core.config import (
    configure_providers,
    get_billed_cost_provider,
    get_circuit_breaker_provider,
    get_credential_cache_provider,
    get_env_detector_provider,
    get_metrics_emitter_provider,
    get_parameter_store_provider,
    get_settings_provider,
    reset_providers_for_tests,
)
from cloudwise_scan_core.billed_cost import (
    DEFAULT_MIN_DAYS_COVERED,
    DISCOUNT_LINE_ITEM_TYPES,
    BilledCostLookup,
    BilledCostPort,
    BilledCostProvider,
    BilledCostRollup,
    CostBasis,
    NullBilledCostLookup,
    ReconciliationOutcome,
    ReconciliationStatus,
    reconcile_commitment_savings,
    reconcile_savings,
)
from cloudwise_scan_core.circuit_breaker import (
    DEFAULT_FAILURE_THRESHOLD,
    DEFAULT_TTL_SECONDS,
    CircuitBreakerPort,
    CircuitBreakerProvider,
    CircuitState,
    NullCircuitBreaker,
    Reservation,
    build_breaker_key,
)
from cloudwise_scan_core.credential_cache import (
    CachedCredentials,
    CredentialCachePort,
    CredentialCacheProvider,
    NullCredentialCache,
    build_cache_key,
)
from cloudwise_scan_core.metrics import (
    METRIC_NAMESPACE,
    DetectorMetricEvent,
    MetricsEmitter,
    MetricsEmitterProvider,
    NullMetricsEmitter,
    StdoutEmfMetricsEmitter,
    is_throttle_error,
)
from cloudwise_scan_core.models import (
    ConfidenceLevel,
    ResourceType,
    WasteDetectionResult,
    WasteDetectionSettings,
    WasteItem,
    WasteType,
    get_category_for_waste_type,
)
from cloudwise_scan_core.ports import (
    EnvironmentDetector,
    EnvironmentDetectorProvider,
    ParameterStoreAdapter,
    ParameterStoreProvider,
    SettingsProvider,
)
from cloudwise_scan_core.tier_routing import (
    FREE_TIER_DETECTORS,
    TIER_DETECTOR_MAP,
    Tier,
    resolve_detector_set,
)

__all__ = [
    # Service (lazy-exported below to keep package import cheap)
    "WasteDetectionService",
    "get_waste_detection_service",
    # Models
    "WasteItem",
    "WasteDetectionSettings",
    "WasteDetectionResult",
    "WasteType",
    "ResourceType",
    "ConfidenceLevel",
    "get_category_for_waste_type",
    # DI
    "configure_providers",
    "reset_providers_for_tests",
    "get_settings_provider",
    "get_env_detector_provider",
    "get_parameter_store_provider",
    "get_credential_cache_provider",
    "get_circuit_breaker_provider",
    "get_metrics_emitter_provider",
    "get_billed_cost_provider",
    # Ports (for adapter authors)
    "SettingsProvider",
    "EnvironmentDetector",
    "EnvironmentDetectorProvider",
    "ParameterStoreAdapter",
    "ParameterStoreProvider",
    # Billed-cost reconciliation (CLO-234)
    "BilledCostLookup",
    "BilledCostPort",
    "BilledCostProvider",
    "BilledCostRollup",
    "CostBasis",
    "NullBilledCostLookup",
    "ReconciliationOutcome",
    "ReconciliationStatus",
    "reconcile_commitment_savings",
    "reconcile_savings",
    "DEFAULT_MIN_DAYS_COVERED",
    "DISCOUNT_LINE_ITEM_TYPES",
    # Credential cache (Phase 3 — §3.5)
    "CachedCredentials",
    "CredentialCachePort",
    "CredentialCacheProvider",
    "NullCredentialCache",
    "build_cache_key",
    # Circuit breaker (Phase 4 — §3.6)
    "CircuitBreakerPort",
    "CircuitBreakerProvider",
    "CircuitState",
    "NullCircuitBreaker",
    "Reservation",
    "build_breaker_key",
    "DEFAULT_FAILURE_THRESHOLD",
    "DEFAULT_TTL_SECONDS",
    # Metrics (Phase 4 — §4.1)
    "METRIC_NAMESPACE",
    "DetectorMetricEvent",
    "MetricsEmitter",
    "MetricsEmitterProvider",
    "NullMetricsEmitter",
    "StdoutEmfMetricsEmitter",
    "is_throttle_error",
    # Tier routing (Phase 5 — §3.7)
    "Tier",
    "FREE_TIER_DETECTORS",
    "TIER_DETECTOR_MAP",
    "resolve_detector_set",
]


def __getattr__(name: str):
    """Lazy import of the heavy service class (2.5k-line module).

    Avoids paying the detector-import cost for consumers that only need
    models / DI (e.g. the orchestrator Lambda's list_regions mode).
    """
    if name == "WasteDetectionService":
        from cloudwise_scan_core.waste_detection_service import WasteDetectionService

        return WasteDetectionService
    if name == "get_waste_detection_service":
        from cloudwise_scan_core.waste_detection_service import (
            get_waste_detection_service,
        )

        return get_waste_detection_service
    raise AttributeError(f"module 'cloudwise_scan_core' has no attribute {name!r}")
