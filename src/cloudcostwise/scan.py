"""Run the open scan engine over one account and a list of regions."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from collections import Counter
from typing import Callable, Dict, List, Optional, Type

from cloudwise_scan_core.models import WasteItem
from cloudwise_scan_core.open_service import OpenWasteDetectionService

from cloudcostwise.runtime import COST_EXPLORER_SERVICE, Credentials, ReadOnlyViolation, read_only_guard

# The one open entrypoint that calls Cost Explorer's billed APIs (RI and
# Savings Plans recommendations). --no-cost-explorer drops it.
COST_EXPLORER_DETECTORS = frozenset({"savings_opportunities"})


@dataclass
class ScanReport:
    account_id: str
    regions: List[str]
    findings: List[WasteItem] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    api_calls: Dict[str, int] = field(default_factory=dict)
    blocked_calls: Dict[str, int] = field(default_factory=dict)
    entrypoints: int = 0
    cost_explorer_skipped: bool = False


def service_class(include_cost_explorer: bool = True) -> Type[OpenWasteDetectionService]:
    if include_cost_explorer:
        return OpenWasteDetectionService
    base = OpenWasteDetectionService
    return type(
        "OpenWasteDetectionServiceNoCE",
        (base,),
        {
            "DETECTOR_METHODS": {k: v for k, v in base.DETECTOR_METHODS.items() if k not in COST_EXPLORER_DETECTORS},
            "ALWAYS_RUN_DETECTORS": base.ALWAYS_RUN_DETECTORS - COST_EXPLORER_DETECTORS,
            "GLOBAL_SERVICE_DETECTORS": base.GLOBAL_SERVICE_DETECTORS - COST_EXPLORER_DETECTORS,
            "SERVICE_TO_DETECTORS": {
                svc: [k for k in keys if k not in COST_EXPLORER_DETECTORS]
                for svc, keys in base.SERVICE_TO_DETECTORS.items()
            },
        },
    )


async def _scan_region(cls, creds: Credentials, region: str):
    return await cls().detect_waste(
        user_id="local",
        account_id=creds.account_id,
        access_key_id=creds.access_key_id,
        secret_access_key=creds.secret_access_key,
        session_token=creds.session_token,
        region=region,
        force_refresh=True,
    )


@dataclass
class RegionResult:
    region: str
    findings: List[WasteItem]
    warnings: List[str]
    errors: List[str]
    calls: Dict[str, int]
    blocked: Dict[str, int]
    violations: List[str]
    seconds: float


def scan_region(creds: Credentials, region: str, include_cost_explorer: bool,
                log_level: Optional[int] = None) -> RegionResult:
    """Scan one region in THIS process, under its own read-only guard.

    Runs in a worker process when regions are scanned in parallel: the engine
    shares one detector thread pool (and per-detector timeouts) per process,
    so two regions in one process would queue behind each other and could
    time out into MISSING findings. A process per region keeps every region's
    scan exactly what a sequential scan would do.
    """
    import logging
    import sys
    import time

    from cloudcostwise.runtime import configure_local_runtime

    if log_level is not None:
        # A spawned worker starts with no logging config: without this the
        # engine's warnings land on stderr even when the user asked for quiet,
        # and anything on stdout would corrupt the MCP protocol or the JSON.
        logging.basicConfig(level=log_level, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s",
                            force=True)

    configure_local_runtime()
    cls = service_class(include_cost_explorer)
    blocked = frozenset() if include_cost_explorer else frozenset({COST_EXPLORER_SERVICE})
    started = time.monotonic()
    with read_only_guard(blocked) as guard:
        result = asyncio.run(_scan_region(cls, creds, region))
    for item in result.waste_items:
        if not item.region:
            item.region = region
    return RegionResult(
        region=region, findings=list(result.waste_items),
        warnings=[f"{region}: {w}" for w in result.warnings],
        errors=[f"{region}: {e}" for e in result.errors],
        calls=dict(guard.calls), blocked=dict(guard.blocked), violations=list(guard.violations),
        seconds=round(time.monotonic() - started, 1),
    )


DEFAULT_PARALLEL_REGIONS = 4


async def run_scan_async(
    creds: Credentials,
    regions: List[str],
    include_cost_explorer: bool = True,
    on_region: Optional[Callable[[RegionResult], None]] = None,
    parallel: int = DEFAULT_PARALLEL_REGIONS,
) -> ScanReport:
    """Scan regions, up to ``parallel`` at a time, each in its own process.

    ``on_region`` is called as each region finishes (progress). The report
    lists regions and findings in the order requested, whatever order they
    finished in.
    """
    import concurrent.futures
    import logging
    import multiprocessing

    report = ScanReport(account_id=creds.account_id, regions=list(regions),
                        entrypoints=len(service_class(include_cost_explorer).DETECTOR_METHODS),
                        cost_explorer_skipped=not include_cost_explorer)
    results: Dict[str, RegionResult] = {}
    if parallel <= 1 or len(regions) <= 1:
        for region in regions:
            results[region] = await asyncio.to_thread(scan_region, creds, region, include_cost_explorer)
            if on_region:
                on_region(results[region])
    else:
        loop = asyncio.get_running_loop()
        ctx = multiprocessing.get_context("spawn")  # never fork a process holding boto3 sessions/threads
        with concurrent.futures.ProcessPoolExecutor(max_workers=min(parallel, len(regions)), mp_context=ctx) as pool:
            level = logging.getLogger().getEffectiveLevel()  # workers follow the parent's verbosity
            pending = {loop.run_in_executor(pool, scan_region, creds, r, include_cost_explorer, level): r
                       for r in regions}
            for done in asyncio.as_completed(list(pending)):
                res = await done
                results[res.region] = res
                if on_region:
                    on_region(res)

    calls: Counter = Counter()
    blocked: Counter = Counter()
    violations: List[str] = []
    for region in regions:
        res = results[region]
        report.findings.extend(res.findings)
        report.warnings.extend(res.warnings)
        report.errors.extend(res.errors)
        calls.update(res.calls)
        blocked.update(res.blocked)
        violations.extend(res.violations)
    report.api_calls = dict(calls)
    report.blocked_calls = dict(blocked)
    if violations:
        raise ReadOnlyViolation(f"refused non-read AWS call(s): {', '.join(sorted(set(violations)))}")
    return report


def run_scan(
    creds: Credentials,
    regions: List[str],
    include_cost_explorer: bool = True,
    on_region: Optional[Callable[[RegionResult], None]] = None,
    parallel: int = DEFAULT_PARALLEL_REGIONS,
) -> ScanReport:
    return asyncio.run(run_scan_async(creds, regions, include_cost_explorer, on_region, parallel))
