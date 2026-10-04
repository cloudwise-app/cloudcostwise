"""The MCP server, driven through the SDK's in-process client."""

import asyncio
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mcp.client import Client

from cloudcostwise import mcp_server
from cloudcostwise.runtime import Credentials
from cloudcostwise.scan import ScanReport

ADVISORY = "aurora_serverless_opportunity"
CREDS = Credentials("AKIATEST", "secret", None, "123456789012", "us-east-1")


def _item(id_, waste_type, resource_id, monthly, command=None):
    return SimpleNamespace(
        id=id_, waste_type=waste_type, resource_id=resource_id, monthly_savings=monthly, region="us-east-1",
        title=f"{waste_type} on {resource_id}", description="A test finding.", confidence="high",
        action="Delete the volume after taking a snapshot.", action_command=command,
        explanation={"detection": "Unattached for 30 days", "risk": "Data loss if still needed"},
    )


REPORT = ScanReport(
    account_id="123456789012", regions=["us-east-1"], entrypoints=20,
    findings=[_item("f1", "unattached_ebs", "vol-1", 40.0, "aws ec2 delete-volume --volume-id vol-1"),
              _item("f2", "idle_efs", "fs-1", 12.5),
              _item("f3", ADVISORY, "db-1", 300.0)],
    api_calls={"ce": 13},
)


def _text(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "text", None))


async def _session(calls):
    server = mcp_server.build_server()

    async def fake_scan(creds, regions, include_cost_explorer=True, on_region=None):
        return REPORT

    with patch.object(mcp_server, "resolve_credentials", return_value=CREDS), \
         patch.object(mcp_server, "resolve_regions", return_value=["us-east-1"]), \
         patch.object(mcp_server, "run_scan_async", side_effect=fake_scan):
        async with Client(server) as client:
            return [await step(client) for step in calls]


def test_four_read_only_tools_and_the_scan_tool_states_its_cost():
    async def tools(client):
        return (await client.list_tools()).tools

    [listed] = asyncio.run(_session([tools]))
    assert sorted(t.name for t in listed) == ["explain_finding", "fix_guidance", "list_findings", "scan"]
    for tool in listed:
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is False, tool.name
    scan = next(t for t in listed if t.name == "scan")
    assert "$0.01 per request" in scan.description and "include_cost_explorer=false" in scan.description
    assert set(scan.input_schema["properties"]) == {"profile", "regions", "include_cost_explorer"}


def test_tools_before_a_scan_ask_for_one():
    async def call(client):
        return _text(await client.call_tool("list_findings", {}))

    [text] = asyncio.run(_session([call]))
    assert "call scan first" in text


def test_scan_then_list_explain_fix_with_advisory_excluded_and_footer_once():
    async def scan(c): return _text(await c.call_tool("scan", {}))
    async def listing(c): return _text(await c.call_tool("list_findings", {"min_monthly_savings": 10}))
    async def explain(c): return _text(await c.call_tool("explain_finding", {"finding_id": "f1"}))
    async def fix(c): return _text(await c.call_tool("fix_guidance", {"finding_id": "f1"}))
    async def missing(c): return _text(await c.call_tool("explain_finding", {"finding_id": "nope"}))

    s, listing_text, e, f, m = asyncio.run(_session([scan, listing, explain, fix, missing]))
    assert "estimated savings $52.50/month (advisory findings excluded)" in s
    assert f"{ADVISORY}: 1 resource(s), $300.00/month (advisory, not counted)" in s
    assert "13 Cost Explorer request(s)" in s and "include_cost_explorer=false to skip" in s
    assert "--no-cost-explorer" not in s
    assert "service checks run locally" in s                     # footer, first result only
    assert "| f1 | unattached_ebs |" in listing_text and "| f2 | idle_efs |" in listing_text
    assert f"{ADVISORY} (advisory)" in listing_text
    assert "Detection: Unattached for 30 days" in e and "validation:" in e
    assert "aws ec2 delete-volume --volume-id vol-1" in f and "never runs it" in f
    assert "No finding 'nope'" in m
    for later in (listing_text, e, f, m):
        assert "service checks run locally" not in later


def test_the_server_module_cannot_execute_commands():
    tree = ast.parse(Path(mcp_server.__file__).read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not imported & {"subprocess", "os", "shlex", "pty"}
