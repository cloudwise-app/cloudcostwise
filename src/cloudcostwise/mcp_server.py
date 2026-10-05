"""`cloudcostwise mcp`: the local scan as an MCP server (stdio) for AI assistants.

Four tools, all read-only: ``scan`` runs the same engine and read-only guard
as ``cloudcostwise scan``; the other three read the last scan held in this
process. Nothing here can change an AWS resource: ``fix_guidance`` returns
text and never executes it.
"""

from __future__ import annotations

import asyncio

from dataclasses import dataclass, field
from typing import Dict, Optional

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import ToolAnnotations

from cloudcostwise import __version__, render
from cloudcostwise.runtime import (
    CredentialsError,
    ReadOnlyViolation,
    configure_local_runtime,
    resolve_credentials,
    resolve_regions,
)
from cloudcostwise.scan import ScanReport, run_scan_async

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True,
                            open_world_hint=True)
LOCAL_READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True,
                             open_world_hint=False)

INSTRUCTIONS = (
    "cloudcostwise finds AWS waste in the user's own account with their own read-only credentials. "
    "Call `scan` first (it takes 30-60 seconds per region), then `list_findings`, `explain_finding` "
    "and `fix_guidance` on its results. Nothing can modify AWS. Before the first `scan`, tell the user "
    "that the RI/Savings Plans checks call Cost Explorer, which AWS bills at $0.01 per request "
    "(about $0.13 a scan), and that include_cost_explorer=false skips them."
)


@dataclass
class _Session:
    report: Optional[ScanReport] = None
    by_id: Dict[str, object] = field(default_factory=dict)
    footer_shown: bool = False

    def footer_once(self) -> str:
        if self.footer_shown or self.report is None:
            return ""
        self.footer_shown = True
        return "\n\n" + render.footer(self.report)


def _money(x) -> str:
    return f"${float(x or 0):,.2f}"


def build_server() -> MCPServer:
    configure_local_runtime()
    session = _Session()
    server = MCPServer(name="cloudcostwise", version=__version__, instructions=INSTRUCTIONS)

    @server.tool(
        annotations=READ_ONLY,
        description=(
            "Scan the user's AWS account for waste with their local credentials (read-only; any non-read "
            "AWS call is refused). Takes 30-60 s per region; up to 4 regions run at once. COST: the RI/Savings Plans checks call Cost "
            "Explorer, billed by AWS at $0.01 per request (about $0.13 a scan); tell the user before "
            "running, and pass include_cost_explorer=false to skip them. regions: comma-separated, or "
            "'all'; default us-east-1 plus the profile's region."
        ),
    )
    async def scan(ctx: Context, profile: Optional[str] = None, regions: Optional[str] = None,
                   include_cost_explorer: bool = True) -> str:
        try:
            creds = resolve_credentials(profile)
            region_list = resolve_regions(regions, creds)
            finished = 0

            def progress(res) -> None:
                # Clients that sent a progress token show this; others ignore it.
                nonlocal finished
                finished += 1
                asyncio.ensure_future(ctx.report_progress(
                    finished, len(region_list),
                    f"{res.region}: {len(res.findings)} finding(s) in {res.seconds:.0f}s"))

            report = await run_scan_async(creds, region_list, include_cost_explorer=include_cost_explorer,
                                          on_region=progress)
        except CredentialsError as e:
            return f"Could not scan: {e}"
        except ReadOnlyViolation as e:
            return f"Scan stopped: {e}. This is a bug in cloudcostwise; nothing was changed in AWS."
        session.report = report
        session.by_id = {str(i.id): i for i in report.findings}
        lines = [f"Account {report.account_id}, regions {', '.join(report.regions)}: "
                 f"{len(report.findings)} findings, estimated savings "
                 f"{_money(render.counted_total(report))}/month (advisory findings excluded)."]
        for g in render.groups(report)[:15]:
            tag = " (advisory, not counted)" if g.advisory else ""
            lines.append(f"- {g.waste_type}: {len(g.items)} resource(s), {_money(g.monthly)}/month{tag}")
        if len(render.groups(report)) > 15:
            lines.append("- ... call list_findings for the rest")
        lines += render.scope_notes(report)
        note = render.cost_explorer_note(report, skip_hint="include_cost_explorer=false")
        if note:
            lines.append(note)
        if report.warnings:
            lines.append(f"{len(report.warnings)} data warning(s): those findings are MISSING, not zero.")
        lines.append("Use list_findings for finding ids, then explain_finding or fix_guidance.")
        return "\n".join(lines) + session.footer_once()

    @server.tool(annotations=LOCAL_READ,
                 description="List findings from the last scan, with ids, optionally filtered by waste type "
                             "or a minimum monthly saving in USD.")
    async def list_findings(waste_type: Optional[str] = None, min_monthly_savings: float = 0.0) -> str:
        if session.report is None:
            return "No scan yet in this session: call scan first."
        rows = [f"| id | waste type | region | resource | monthly |", "|---|---|---|---|---:|"]
        n = 0
        for g in render.groups(session.report):
            if waste_type and g.waste_type != waste_type:
                continue
            for i in g.items:
                if float(i.monthly_savings or 0) < min_monthly_savings:
                    continue
                name = f"{g.waste_type} (advisory)" if g.advisory else g.waste_type
                rows.append(f"| {i.id} | {name} | {i.region or '-'} | `{i.resource_id}` | {_money(i.monthly_savings)} |")
                n += 1
        if not n:
            return "No findings match."
        return "\n".join(rows) + session.footer_once()

    @server.tool(annotations=LOCAL_READ,
                 description="Explain one finding: what was detected, the threshold, the pricing used, why "
                             "it is waste, the risk of acting, and how validated this check is.")
    async def explain_finding(finding_id: str) -> str:
        item = session.by_id.get(finding_id)
        if item is None:
            return f"No finding {finding_id!r} in the last scan; call list_findings for ids."
        validation = render.validation_for(item.waste_type) or "unknown"
        out = [f"{item.title}", f"Resource: {item.resource_id} ({item.region or '-'})",
               f"Waste type: {render.waste_type_name(item)}",
               f"Estimated saving: {_money(item.monthly_savings)}/month"
               + (" (advisory: not counted in totals)" if render.is_advisory(item) else ""),
               f"Confidence: {getattr(item.confidence, 'value', item.confidence)}; validation: {validation}",
               "", item.description or ""]
        for key in ("detection", "threshold", "pricing", "why_waste", "risk"):
            value = (item.explanation or {}).get(key)
            if value:
                out.append(f"{key.replace('_', ' ').capitalize()}: {value}")
        return "\n".join(out).strip() + session.footer_once()

    @server.tool(annotations=LOCAL_READ,
                 description="How to fix one finding: the recommended action and, where known, the AWS CLI "
                             "command, as text for the user to review. Never executes anything.")
    async def fix_guidance(finding_id: str) -> str:
        item = session.by_id.get(finding_id)
        if item is None:
            return f"No finding {finding_id!r} in the last scan; call list_findings for ids."
        out = [f"Recommended action for {item.resource_id}: {item.action}"]
        if item.action_command:
            out += ["", "Command (review before running; cloudcostwise never runs it):",
                    f"```\n{item.action_command}\n```"]
        risk = (item.explanation or {}).get("risk")
        if risk:
            out += ["", f"Risk: {risk}"]
        out += ["", f"Safe, approved fixes with rollback are part of the hosted product: {render.HOSTED_URL}"]
        return "\n".join(out) + session.footer_once()

    return server


def serve() -> None:
    build_server().run("stdio")
