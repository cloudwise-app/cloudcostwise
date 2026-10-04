"""Format a ScanReport as a terminal table, Markdown or JSON.

Advisory waste types (no path to validation, CLO-432) are listed but never
counted in a total, the same rule the hosted product applies everywhere
(CLO-504).
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List

from cloudwise_scan_core.advisory_types import ADVISORY, validation_for

from cloudcostwise.runtime import COST_EXPLORER_PRICE_PER_REQUEST, COST_EXPLORER_SERVICE
from cloudcostwise.scan import ScanReport

HOSTED_URL = "https://cloudcostwise.io/connect?src=cli"
TOTAL_ENTRYPOINTS = 46
OPEN_ENTRYPOINTS = 20
CE_SKIPPED_NOTE = ("RI/Savings Plans checks skipped (--no-cost-explorer); "
                   "extended-support surcharges are estimates, not billed amounts.")


def waste_type_name(item) -> str:
    wt = item.waste_type
    return str(getattr(wt, "value", wt))


def is_advisory(item) -> bool:
    return validation_for(item.waste_type) == ADVISORY


@dataclass
class Group:
    waste_type: str
    advisory: bool
    items: list

    @property
    def monthly(self) -> float:
        return round(sum(float(i.monthly_savings or 0) for i in self.items), 2)


def groups(report: ScanReport) -> List[Group]:
    by_type: Dict[str, list] = defaultdict(list)
    for item in report.findings:
        by_type[waste_type_name(item)].append(item)
    out = [Group(t, is_advisory(items[0]), sorted(items, key=lambda i: -float(i.monthly_savings or 0)))
           for t, items in by_type.items()]
    return sorted(out, key=lambda g: (g.advisory, -g.monthly, g.waste_type))


def counted_total(report: ScanReport) -> float:
    return round(sum(float(i.monthly_savings or 0) for i in report.findings if not is_advisory(i)), 2)


def advisory_total(report: ScanReport) -> float:
    return round(sum(float(i.monthly_savings or 0) for i in report.findings if is_advisory(i)), 2)


def cost_explorer_note(report: ScanReport, skip_hint: str = "--no-cost-explorer") -> str:
    n = report.api_calls.get(COST_EXPLORER_SERVICE, 0)
    if not n:
        return ""
    return (f"This scan made {n} Cost Explorer request(s), which AWS bills at "
            f"${COST_EXPLORER_PRICE_PER_REQUEST:.2f} each (about ${n * COST_EXPLORER_PRICE_PER_REQUEST:.2f}). "
            f"Use {skip_hint} to skip them.")


def footer(report: ScanReport) -> str:
    # Counts the open checks, not how many ran: a check the user switched off
    # (--no-cost-explorer) is still a local one, not one of the hosted 26.
    return (f"{OPEN_ENTRYPOINTS} of {TOTAL_ENTRYPOINTS} service checks run locally. "
            f"The other {TOTAL_ENTRYPOINTS - OPEN_ENTRYPOINTS}, history, alerts and safe fixes: {HOSTED_URL}")


def scope_notes(report: ScanReport) -> List[str]:
    return [CE_SKIPPED_NOTE] if report.cost_explorer_skipped else []


def _money(x: float) -> str:
    return f"${x:,.2f}"


def as_table(report: ScanReport, verbose: bool = False) -> str:
    lines = [f"AWS account {report.account_id} | regions: {', '.join(report.regions)}", ""]
    gs = groups(report)
    if not gs:
        lines.append("No waste found by the checks that ran.")
    for g in gs:
        tag = "  (advisory, not counted in the total)" if g.advisory else ""
        lines.append(f"{g.waste_type}  x{len(g.items)}  {_money(g.monthly)}/mo{tag}")
        for i in g.items:
            lines.append(f"    {i.region or '-':<15} {i.resource_id:<60} {_money(float(i.monthly_savings or 0)):>12}/mo")
    lines += ["", f"Estimated savings: {_money(counted_total(report))}/month"]
    adv = advisory_total(report)
    if adv:
        lines.append(f"Advisory (unvalidated, excluded): {_money(adv)}/month")
    if report.warnings:
        if verbose:
            lines += ["", "Data warnings (findings these affect are MISSING, not zero):"]
            lines += [f"  - {w}" for w in report.warnings]
        else:
            lines.append(f"{len(report.warnings)} data warning(s); rerun with --verbose to see them.")
    for e in report.errors:
        lines.append(f"error: {e}")
    note = cost_explorer_note(report)
    lines += ["", *scope_notes(report), *( [note] if note else [] ), footer(report)]
    return "\n".join(lines)


def as_markdown(report: ScanReport) -> str:
    out = [f"# AWS waste, account {report.account_id}", "",
           f"Regions: {', '.join(report.regions)}", "",
           "| Waste type | Region | Resource | Monthly |", "|---|---|---|---:|"]
    for g in groups(report):
        name = f"{g.waste_type} (advisory)" if g.advisory else g.waste_type
        for i in g.items:
            out.append(f"| {name} | {i.region or '-'} | `{i.resource_id}` | {_money(float(i.monthly_savings or 0))} |")
    out += ["", f"**Estimated savings: {_money(counted_total(report))}/month** (advisory excluded)"]
    note = cost_explorer_note(report)
    out += ["", *[n + "\n" for n in scope_notes(report)], *( [note, ""] if note else [] ), footer(report)]
    return "\n".join(out)


def as_json(report: ScanReport) -> str:
    return json.dumps({
        "account_id": report.account_id,
        "regions": report.regions,
        "estimated_monthly_savings": counted_total(report),
        "advisory_monthly_savings_excluded": advisory_total(report),
        "findings": [
            {
                "waste_type": waste_type_name(i),
                "validation": validation_for(i.waste_type),
                "region": i.region,
                "resource_id": i.resource_id,
                "title": i.title,
                "monthly_savings": round(float(i.monthly_savings or 0), 2),
                "confidence": str(getattr(i.confidence, "value", i.confidence)),
                "action": i.action,
            }
            for g in groups(report) for i in g.items
        ],
        "warnings": report.warnings,
        "errors": report.errors,
        "aws_api_calls": report.api_calls,
        "checks_run": report.entrypoints,
        "checks_open": OPEN_ENTRYPOINTS,
        "checks_total": TOTAL_ENTRYPOINTS,
        "cost_explorer_skipped": report.cost_explorer_skipped,
    }, indent=2)
