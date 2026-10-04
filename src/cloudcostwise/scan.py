"""Run the open scan engine over one account and a list of regions."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type

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


async def run_scan_async(
    creds: Credentials,
    regions: List[str],
    include_cost_explorer: bool = True,
    on_region: Optional[callable] = None,
) -> ScanReport:
    """Scan each region in turn under the read-only guard."""
    cls = service_class(include_cost_explorer)
    report = ScanReport(account_id=creds.account_id, regions=list(regions),
                        entrypoints=len(cls.DETECTOR_METHODS),
                        cost_explorer_skipped=not include_cost_explorer)
    blocked = frozenset() if include_cost_explorer else frozenset({COST_EXPLORER_SERVICE})
    with read_only_guard(blocked) as guard:
        for region in regions:
            if on_region:
                on_region(region)
            result = await _scan_region(cls, creds, region)
            for item in result.waste_items:
                if not item.region:
                    item.region = region
            report.findings.extend(result.waste_items)
            report.warnings.extend(f"{region}: {w}" for w in result.warnings)
            report.errors.extend(f"{region}: {e}" for e in result.errors)
    report.api_calls = dict(guard.calls)
    report.blocked_calls = dict(guard.blocked)
    if guard.violations:
        raise ReadOnlyViolation(f"refused non-read AWS call(s): {', '.join(sorted(set(guard.violations)))}")
    return report


def run_scan(
    creds: Credentials,
    regions: List[str],
    include_cost_explorer: bool = True,
    on_region: Optional[callable] = None,
) -> ScanReport:
    return asyncio.run(run_scan_async(creds, regions, include_cost_explorer, on_region))
