"""Format a ScanReport as a terminal table, Markdown or JSON.

Advisory waste types (no path to validation, CLO-432) are listed but never
counted in a total, the same rule the hosted product applies everywhere
(CLO-504).
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

from cloudwise_scan_core.advisory_types import ADVISORY, validation_for
from cloudwise_scan_core.detectors.open.storage import EBS_SNAPSHOT_WITHHELD_NOTE_PREFIXES
from cloudwise_scan_core.score import Score, compute_score

from cloudcostwise.runtime import COST_EXPLORER_PRICE_PER_REQUEST, COST_EXPLORER_SERVICE
from cloudcostwise.scan import COST_EXPLORER_DETECTORS, ScanReport

HOSTED_URL = "https://cloudcostwise.io/connect?utm_source=cloudcostwise&utm_medium=cli"
TOTAL_ENTRYPOINTS = 46
OPEN_ENTRYPOINTS = 20
FEEDBACK_URL = "https://github.com/cloudwise-app/cloudcostwise/issues/1"
FEEDBACK_NOTE = (f"Wrong, or missed something? Tell us at {FEEDBACK_URL} or cloudwise@cloudcostwise.io. "
                 "Waste types and counts are enough; leave out account IDs and resource names.")
CE_SKIPPED_NOTE = "RI/Savings Plans checks skipped (--no-cost-explorer)."


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
            f"The other {TOTAL_ENTRYPOINTS - OPEN_ENTRYPOINTS}, history, alerts and safe fixes: {HOSTED_URL}\n"
            f"{FEEDBACK_NOTE}")


def _is_withheld_note(warning: str) -> bool:
    """CLO-848: a deliberate skip (keep tag, newest snapshot), not lost data.
    Scan notes carry a region prefix ("us-east-1: ebs_snapshot_keep: ...")."""
    body = warning.split(": ", 1)[1] if ": " in warning else warning
    return warning.startswith(EBS_SNAPSHOT_WITHHELD_NOTE_PREFIXES) or body.startswith(EBS_SNAPSHOT_WITHHELD_NOTE_PREFIXES)


def withheld_notes(report: ScanReport) -> List[str]:
    return [w for w in report.warnings if _is_withheld_note(w)]


def data_warnings(report: ScanReport) -> List[str]:
    """Warnings that mean findings are MISSING (everything but withheld notes)."""
    return [w for w in report.warnings if not _is_withheld_note(w)]


def left_out_lines(report: ScanReport, verbose: bool = False) -> List[str]:
    """Everything under "Left out on purpose": the exclude-list count (with the IDs when ``verbose``;
    --anonymize empties that list), then the withheld notes."""
    from cloudcostwise import exclude

    note = exclude.note(report)
    ids = list(report.excluded_resource_ids) if verbose else []
    return [*([note] if note else []), *([f"excluded: {', '.join(ids)}"] if note and ids else []),
            *withheld_notes(report)]


def scope_notes(report: ScanReport) -> List[str]:
    return [CE_SKIPPED_NOTE] if report.cost_explorer_skipped else []


def _money(x: float) -> str:
    return f"${x:,.2f}"


# --- CLO-858: score card and share grid ---------------------------------

BASIS_LABEL = {"spend": "of your last 30 days of spend", "no_spend": "without spend data"}
TONE_WORD = {"celebratory": "healthy", "neutral": "room to improve", "urgent": "leaking money"}
GRID_ROW = 10
_PLAIN_GLYPHS = {"fired": "X", "clean": ".", "skipped": "-"}
_EMOJI_GLYPHS = {"fired": "\U0001F7E5", "clean": "\U0001F7E9", "skipped": "\u2B1C"}


def score_for(report: ScanReport) -> Score:
    return compute_score(counted_total(report), report.spend_monthly)


@lru_cache(maxsize=1)
def _entrypoint_types() -> Dict[str, FrozenSet[str]]:
    """Open service entrypoint (detector key) -> the waste types its code can emit.

    Read from the shipped detector modules, never typed: for each entrypoint's method, the
    ``WasteType.X`` members named in it and in any ``self.<helper>`` it reaches. A waste type
    shared by two entrypoints belongs to both, so either may light up for it.
    """
    import ast

    from cloudwise_scan_core.detectors import open as open_pkg
    from cloudwise_scan_core.models import WasteType
    from cloudwise_scan_core.open_service import OpenWasteDetectionService

    funcs: Dict[str, list] = defaultdict(list)
    for path in Path(open_pkg.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs[node.name].append(node)

    def types_of(method: str) -> FrozenSet[str]:
        seen, stack, found = set(), [method], set()
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            for fn in funcs.get(name, []):
                for n in ast.walk(fn):
                    if isinstance(n, ast.Attribute):
                        if getattr(n.value, "id", "") == "WasteType":
                            member = WasteType.__members__.get(n.attr)
                            if member is not None:
                                found.add(str(member.value))
                        elif getattr(n.value, "id", "") == "self":
                            stack.append(n.attr)
        return frozenset(found)

    return {key: types_of(method) for key, method in OpenWasteDetectionService.DETECTOR_METHODS.items()}


def grid_states(report: ScanReport) -> List[Tuple[str, str]]:
    """(entrypoint, fired|clean|skipped) per service check, in a fixed order.

    ``fired``: a counted (non-advisory) finding has a waste type that entrypoint emits.
    ``skipped``: the check did not run (Cost Explorer off). Advisory findings never fire a cell.
    """
    counted = {waste_type_name(i) for i in report.findings if not is_advisory(i)}
    out = []
    for key, types in sorted(_entrypoint_types().items()):
        if report.cost_explorer_skipped and key in COST_EXPLORER_DETECTORS:
            out.append((key, "skipped"))
        else:
            out.append((key, "fired" if types & counted else "clean"))
    return out


def share_grid(report: ScanReport, emoji: bool = False) -> List[str]:
    glyphs = _EMOJI_GLYPHS if emoji else _PLAIN_GLYPHS
    cells = [glyphs[state] for _k, state in grid_states(report)]
    return ["".join(cells[i:i + GRID_ROW]) for i in range(0, len(cells), GRID_ROW)]


def fired_types(report: ScanReport) -> List[str]:
    """Waste types found, by name, counted ones first."""
    return [g.waste_type + (" (advisory)" if g.advisory else "") for g in groups(report)]


def score_card(report: ScanReport, markdown: bool = False, emoji: bool = False) -> List[str]:
    """The end-of-scan card and its pasteable grid. Never contains a URL."""
    score = score_for(report)
    states = grid_states(report)
    ran = [s for _k, s in states if s != "skipped"]
    glyphs = _EMOJI_GLYPHS if emoji else _PLAIN_GLYPHS
    legend = f"{glyphs['fired']} fired  {glyphs['clean']} clean  {glyphs['skipped']} skipped"
    head = f"Cost health score: {score.value}/100 ({BASIS_LABEL[score.basis]}), {TONE_WORD[score.tone]}"
    facts = (f"{_money(counted_total(report))}/month found | {ran.count('fired')} of {len(ran)} checks fired | "
             f"{len(report.regions)} region(s) | {report.seconds:.1f}s")
    names = fired_types(report)
    body = [f"cloudcostwise {score.value}/100 ({BASIS_LABEL[score.basis]})", *share_grid(report, emoji), legend]
    if names:
        body.append("Found: " + ", ".join(names))
    body.append("Advisory findings are listed, not counted in the score.")
    if markdown:
        return [f"**{head}**", "", facts, "", "```", *body, "```"]
    return [head, facts, "", *body]


def as_table(report: ScanReport, verbose: bool = False, emoji: bool = False) -> str:
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
    withheld = left_out_lines(report, verbose)
    if withheld:
        lines += ["", "Left out on purpose:"]
        lines += [f"  - {w}" for w in withheld]
    warnings = data_warnings(report)
    if warnings:
        if verbose:
            lines += ["", "Data warnings (findings these affect are MISSING, not zero):"]
            lines += [f"  - {w}" for w in warnings]
        else:
            lines.append(f"{len(warnings)} data warning(s); rerun with --verbose to see them.")
    for e in report.errors:
        lines.append(f"error: {e}")
    lines += ["", *score_card(report, emoji=emoji)]
    note = cost_explorer_note(report)
    lines += ["", *scope_notes(report), *( [note] if note else [] ), footer(report)]
    return "\n".join(lines)


def as_markdown(report: ScanReport, emoji: bool = False, verbose: bool = False) -> str:
    out = [f"# AWS waste, account {report.account_id}", "",
           f"Regions: {', '.join(report.regions)}", "",
           "| Waste type | Region | Resource | Monthly |", "|---|---|---|---:|"]
    for g in groups(report):
        name = f"{g.waste_type} (advisory)" if g.advisory else g.waste_type
        for i in g.items:
            out.append(f"| {name} | {i.region or '-'} | `{i.resource_id}` | {_money(float(i.monthly_savings or 0))} |")
    withheld = left_out_lines(report, verbose)
    if withheld:
        out += ["", "**Left out on purpose:**", "", *[f"- {w}" for w in withheld]]
    out += ["", f"**Estimated savings: {_money(counted_total(report))}/month** (advisory excluded)",
           "", *score_card(report, markdown=True, emoji=emoji)]
    note = cost_explorer_note(report)
    # A single newline is a soft break in markdown; keep each footer sentence on its own line.
    out += ["", *[n + "\n" for n in scope_notes(report)], *( [note, ""] if note else [] ),
            footer(report).replace("\n", "\n\n")]
    return "\n".join(out)


def as_json(report: ScanReport) -> str:
    score = score_for(report)
    return json.dumps({
        "account_id": report.account_id,
        "regions": report.regions,
        "estimated_monthly_savings": counted_total(report),
        "advisory_monthly_savings_excluded": advisory_total(report),
        # CLO-931: findings your exclude list left out (not in the total above); the ids are empty under --anonymize
        "excluded_by_list_count": int(report.excluded_count or 0),
        "excluded_by_list_resource_ids": list(report.excluded_resource_ids),
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
        "permission_errors": report.permission_errors,
        "coverage_notes": report.coverage_notes,
        "aws_api_calls": report.api_calls,
        "checks_run": report.entrypoints,
        "checks_open": OPEN_ENTRYPOINTS,
        "checks_total": TOTAL_ENTRYPOINTS,
        "cost_explorer_skipped": report.cost_explorer_skipped,
        "score": score.value,
        "score_basis": score.basis,
    }, indent=2)
