"""
Port Protocols for cloudwise_scan_core.

The scan engine depends on these narrow abstractions rather than on any
concrete configuration, credential, or persistence framework. Each runtime
(Lambda, ECS, EKS, CLI, FastAPI backend) provides adapter classes that
implement these Protocols.

This is the Dependency Inversion seam of the package. Do not import
FastAPI / Lambda / concrete config classes into the core engine; instead
inject an adapter through ``config.configure_providers(...)``.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SettingsProvider(Protocol):
    """Returns an object exposing application settings as attributes.

    Minimum contract:
    - ``AWS_REGION`` (str | None) — default AWS region to construct SDK clients in.

    The backend FastAPI app implements this via ``app.core.config.get_settings``.
    The Lambda adapter implements this by reading environment variables.
    """

    def __call__(self) -> Any:  # pragma: no cover - Protocol
        ...


@runtime_checkable
class EnvironmentDetector(Protocol):
    """Detects which deployment environment (staging/production/local) we are in."""

    @property
    def environment_name(self) -> str | None:  # pragma: no cover - Protocol
        ...


@runtime_checkable
class EnvironmentDetectorProvider(Protocol):
    """Factory returning an ``EnvironmentDetector``."""

    def __call__(self) -> EnvironmentDetector:  # pragma: no cover - Protocol
        ...


@runtime_checkable
class ParameterStoreAdapter(Protocol):
    """Reads named parameters from a parameter store (e.g. SSM).

    Implementations may be no-ops (e.g. for local CLI usage) in which case
    ``is_using_parameter_store`` should return False and callers must fall
    back to env-var / default naming.
    """

    @property
    def is_using_parameter_store(self) -> bool:  # pragma: no cover - Protocol
        ...

    def get_parameter(self, name: str) -> str | None:  # pragma: no cover - Protocol
        ...


@runtime_checkable
class ParameterStoreProvider(Protocol):
    """Factory returning a ``ParameterStoreAdapter`` (or None if not configured)."""

    def __call__(self) -> ParameterStoreAdapter | None:  # pragma: no cover - Protocol
        ...
