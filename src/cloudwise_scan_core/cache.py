"""
In-package cache abstractions for cloudwise_scan_core.

The scan engine opportunistically memoises per-user / per-scan payloads
through a small async-shaped cache interface (``get_cached_data`` /
``set_cache_data``). In the FastAPI backend this is backed by Redis; in
leaner runtimes (Lambda region scanner, ECS worker, CLI, tests) we default
to ``NoOpCacheService`` — a correct-but-forgetful implementation that
always misses and silently accepts writes.

A real cache is a performance hint: correctness of the scan must not
depend on the cache returning previously-stored values. Callers that want
a warm cache inject their own adapter at ``WasteDetectionService`` or
``get_waste_detection_service`` construction time.
"""

from __future__ import annotations

from typing import Any


class NoOpCacheService:
    """Minimal cache that never hits and silently accepts writes.

    Shape matches the subset of the backend ``cache_service`` that the
    scan engine uses (``get_cached_data`` / ``set_cache_data``). Any
    additional methods called on it will raise ``AttributeError`` — which
    is the correct fail-loud behaviour for unexpected coupling.
    """

    async def get_cached_data(self, user_id: str, cache_key: str) -> Any | None:  # noqa: ARG002
        return None

    async def set_cache_data(
        self,
        user_id: str,  # noqa: ARG002
        cache_key: str,  # noqa: ARG002
        cache_data: Any,  # noqa: ARG002
        *,
        ttl_hours: int = 24,  # noqa: ARG002
    ) -> None:
        return None
