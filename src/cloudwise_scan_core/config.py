"""
Dependency injection configuration for cloudwise_scan_core.

The runtime that embeds this package (backend FastAPI app, region scanner
Lambda, future ECS worker, CLI, tests) calls ``configure_providers(...)`` once
at startup to wire concrete adapters into the scan engine. Core code then
reads providers through the accessor helpers below.

Defaults fall back to environment variables so the package remains usable
without explicit configuration (e.g. for ad-hoc scripts).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .billed_cost import BilledCostPort, BilledCostProvider, NullBilledCostLookup
from .circuit_breaker import CircuitBreakerPort, CircuitBreakerProvider, NullCircuitBreaker
from .credential_cache import CredentialCachePort, CredentialCacheProvider, NullCredentialCache
from .metrics import MetricsEmitter, MetricsEmitterProvider, NullMetricsEmitter
from .ports import (
    EnvironmentDetector,
    EnvironmentDetectorProvider,
    ParameterStoreAdapter,
    ParameterStoreProvider,
    SettingsProvider,
)


# ---------------------------------------------------------------------------
# Default adapters (env-var driven) — used when the runtime doesn't override.
# ---------------------------------------------------------------------------


@dataclass
class _EnvSettings:
    """Minimum settings object read from environment variables."""

    AWS_REGION: str | None = None


def _default_settings_provider() -> _EnvSettings:
    return _EnvSettings(AWS_REGION=os.environ.get("AWS_REGION"))


class _EnvEnvironmentDetector:
    """Environment detector backed by ``CLOUDWISE_ENVIRONMENT`` / ``ENVIRONMENT``."""

    @property
    def environment_name(self) -> str | None:
        return (
            os.environ.get("CLOUDWISE_ENVIRONMENT")
            or os.environ.get("ENVIRONMENT")
        )


def _default_env_detector_provider() -> EnvironmentDetector:
    return _EnvEnvironmentDetector()


def _default_parameter_store_provider() -> Optional[ParameterStoreAdapter]:
    return None


_null_credential_cache = NullCredentialCache()


def _default_credential_cache_provider() -> Optional[CredentialCachePort]:
    """Phase 3 (§3.5): default is a no-op cache so runtimes that don't
    configure DynamoDB (tests, CLI, ad-hoc scripts) see every lookup as a
    miss and every write as silent."""
    return _null_credential_cache


_null_circuit_breaker = NullCircuitBreaker()


def _default_circuit_breaker_provider() -> Optional[CircuitBreakerPort]:
    """Phase 4 (§3.6): default is an always-closed breaker — no detector
    is ever skipped unless a runtime wires in a real adapter."""
    return _null_circuit_breaker


_null_metrics_emitter = NullMetricsEmitter()


def _default_metrics_emitter_provider() -> Optional[MetricsEmitter]:
    """Phase 4 (§4.1): default discards events. Lambda runtimes override
    with the EMF emitter; tests that want to observe metrics inject a
    capturing emitter."""
    return _null_metrics_emitter


_null_billed_cost = NullBilledCostLookup()


def _default_billed_cost_provider() -> Optional[BilledCostPort]:
    """CLO-234: default is a no-op lookup — every resource comes back as
    ``unreconciled_no_cur``, keeping the list-price estimate and labelling it.

    Deliberately not ``None``-meaning-skip: a runtime that forgets to wire an
    adapter must still produce *visible* unreconciled findings rather than
    silently confident ones."""
    return _null_billed_cost


# ---------------------------------------------------------------------------
# Module-level registry (set via configure_providers).
# ---------------------------------------------------------------------------


_settings_provider: SettingsProvider = _default_settings_provider
_env_detector_provider: EnvironmentDetectorProvider = _default_env_detector_provider
_parameter_store_provider: ParameterStoreProvider = _default_parameter_store_provider
_credential_cache_provider: CredentialCacheProvider = _default_credential_cache_provider
_circuit_breaker_provider: CircuitBreakerProvider = _default_circuit_breaker_provider
_metrics_emitter_provider: MetricsEmitterProvider = _default_metrics_emitter_provider
_billed_cost_provider: BilledCostProvider = _default_billed_cost_provider


def configure_providers(
    *,
    settings_provider: SettingsProvider | None = None,
    env_detector_provider: EnvironmentDetectorProvider | None = None,
    parameter_store_provider: ParameterStoreProvider | None = None,
    credential_cache_provider: CredentialCacheProvider | None = None,
    circuit_breaker_provider: CircuitBreakerProvider | None = None,
    metrics_emitter_provider: MetricsEmitterProvider | None = None,
    billed_cost_provider: BilledCostProvider | None = None,
) -> None:
    """Wire runtime-specific adapters into the scan engine.

    Call once at application startup. Any provider left as ``None`` keeps its
    previously configured value (or the environment-variable default on first
    invocation).
    """
    global _settings_provider, _env_detector_provider, _parameter_store_provider
    global _credential_cache_provider, _circuit_breaker_provider
    global _metrics_emitter_provider, _billed_cost_provider
    if settings_provider is not None:
        _settings_provider = settings_provider
    if env_detector_provider is not None:
        _env_detector_provider = env_detector_provider
    if parameter_store_provider is not None:
        _parameter_store_provider = parameter_store_provider
    if credential_cache_provider is not None:
        _credential_cache_provider = credential_cache_provider
    if circuit_breaker_provider is not None:
        _circuit_breaker_provider = circuit_breaker_provider
    if metrics_emitter_provider is not None:
        _metrics_emitter_provider = metrics_emitter_provider
    if billed_cost_provider is not None:
        _billed_cost_provider = billed_cost_provider


def get_settings_provider() -> SettingsProvider:
    return _settings_provider


def get_env_detector_provider() -> EnvironmentDetectorProvider:
    return _env_detector_provider


def get_parameter_store_provider() -> ParameterStoreProvider:
    return _parameter_store_provider


def get_credential_cache_provider() -> CredentialCacheProvider:
    """Return the configured credential-cache provider (§3.5).

    Callers should invoke the returned callable to obtain a concrete cache
    (or ``None`` if caching is disabled for this runtime).
    """
    return _credential_cache_provider


def get_circuit_breaker_provider() -> CircuitBreakerProvider:
    """Return the configured circuit-breaker provider (§3.6, Phase 4)."""
    return _circuit_breaker_provider


def get_metrics_emitter_provider() -> MetricsEmitterProvider:
    """Return the configured metrics-emitter provider (§4.1, Phase 4)."""
    return _metrics_emitter_provider


def get_billed_cost_provider() -> BilledCostProvider:
    """Return the configured billed-cost provider (CLO-234).

    Callers invoke the returned callable to obtain a concrete lookup. A
    ``None`` result, or a lookup that returns ``None``, means findings stay at
    their list-price estimate and are labelled ``unreconciled_no_cur``.
    """
    return _billed_cost_provider


def reset_providers_for_tests() -> None:
    """Restore default env-var providers. Intended for test suites only."""
    global _settings_provider, _env_detector_provider, _parameter_store_provider
    global _credential_cache_provider, _circuit_breaker_provider
    global _metrics_emitter_provider, _billed_cost_provider
    _settings_provider = _default_settings_provider
    _env_detector_provider = _default_env_detector_provider
    _parameter_store_provider = _default_parameter_store_provider
    _credential_cache_provider = _default_credential_cache_provider
    _circuit_breaker_provider = _default_circuit_breaker_provider
    _metrics_emitter_provider = _default_metrics_emitter_provider
    _billed_cost_provider = _default_billed_cost_provider
