"""CLO-1057: demo mode. A recorded scan, no AWS, always marked as sample data, never shared."""

import asyncio
import io
import json
import re
from unittest.mock import patch

import boto3
import pytest
from mcp.client import Client

from cloudcostwise import cli, demo, mcp_server, render, share
from cloudcostwise.anonymize import anonymize_report


@pytest.fixture(autouse=True)
def no_aws_no_network(tmp_path, monkeypatch):
    """Any boto3 session or client, any credential lookup, any socket or HTTP request fails the test."""
    def boom(*a, **k):
        raise AssertionError("demo mode touched AWS or the network")

    monkeypatch.setattr(boto3, "client", boom)
    monkeypatch.setattr(boto3, "resource", boom)
    monkeypatch.setattr(boto3.session, "Session", boom)
    monkeypatch.setattr(boto3, "Session", boom)
    monkeypatch.setattr("cloudcostwise.runtime.resolve_credentials", boom)
    monkeypatch.setattr("cloudcostwise.mcp_server.resolve_credentials", boom)  # the name mcp_server really calls
    monkeypatch.setattr("cloudcostwise.mcp_server.run_scan_async", boom)
    monkeypatch.setattr("cloudcostwise.scan.run_scan", boom)
    monkeypatch.setattr("cloudcostwise.scan.run_scan_async", boom)
    monkeypatch.setattr("urllib.request.urlopen", boom)
    monkeypatch.setattr("cloudcostwise.share._open", boom)  # the share send uses its own no-redirect opener
    monkeypatch.setattr("socket.socket.connect", boom)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv(share.ENV_SHARE, raising=False)


def _run(args, capsys):
    rc = cli.main(["scan", *args])
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_table_output_is_marked_first_and_last_line(capsys):
    rc, out, err = _run(["--demo"], capsys)
    lines = out.rstrip("\n").split("\n")
    assert rc == 0
    assert lines[0] == demo.BANNER_TOP and lines[-1] == demo.BANNER_BOTTOM
    assert "AWS account demo-account" in out and "Estimated savings: $" in out
    assert "scanning" not in err and "Cost Explorer" not in err  # no scan, no billing notice


def test_markdown_output_is_marked_first_and_last_line(capsys):
    rc, out, _ = _run(["--demo", "--format", "markdown"], capsys)
    lines = out.rstrip("\n").split("\n")
    assert rc == 0
    assert demo.BANNER_TOP in lines[0] and demo.BANNER_BOTTOM in lines[-1]
    assert "| Waste type | Region | Resource | Monthly |" in out


def test_json_output_has_a_top_level_demo_field(capsys):
    rc, out, _ = _run(["--demo", "--format", "json"], capsys)
    data = json.loads(out)
    assert rc == 0 and next(iter(data)) == "demo" and data["demo"] is True
    assert data["demo_note"] == demo.JSON_NOTE and data["account_id"] == "demo-account"
    assert data["findings"] and data["aws_api_calls"] == {} and data["cost_explorer_skipped"] is True


def test_a_real_report_is_not_marked(capsys):
    from cloudcostwise.scan import ScanReport

    report = ScanReport(account_id="123456789012", regions=["us-east-1"])
    assert "demo" not in json.loads(render.as_json(report))
    assert "SAMPLE DATA" not in render.as_table(report) and "SAMPLE DATA" not in render.as_markdown(report)


def test_totals_come_from_the_recording():
    report = demo.load_report()
    assert report.demo and len(report.findings) == len(demo._load_raw()["findings"])
    assert render.counted_total(report) == round(sum(f["monthlySavings"] for f in demo._load_raw()["findings"]), 2)


def test_profile_and_regions_are_refused(capsys):
    for flag in (["--profile", "p"], ["--regions", "us-west-2"]):
        rc, out, err = _run(["--demo", *flag], capsys)
        assert rc == 2 and out == "" and "--demo" in err


@pytest.mark.parametrize("extra", [["--no-cost-explorer"], ["--parallel", "1"], ["--no-exclude"], ["--verbose"]])
def test_other_flags_are_accepted(extra, capsys):
    rc, out, _ = _run(["--demo", *extra], capsys)
    assert rc == 0 and out.startswith("SAMPLE DATA")


def test_anonymize_keeps_the_marker_and_the_data_is_placeholders(capsys):
    rc, out, _ = _run(["--demo", "--anonymize", "--format", "json"], capsys)
    data = json.loads(out)
    assert rc == 0 and data["demo"] is True
    assert anonymize_report(demo.load_report()).demo is True


def test_the_exclude_list_is_not_read(tmp_path, capsys, monkeypatch):
    def boom(report):
        raise AssertionError("exclude list read in demo mode")

    monkeypatch.setattr("cloudcostwise.exclude.apply", boom)
    assert _run(["--demo"], capsys)[0] == 0


def test_the_recording_has_no_real_identifiers():
    text = json.dumps(demo._load_raw())
    assert not re.search(r"(?<![\w.-])\d{12}(?![\w.-])", text)
    assert not re.search(r"cloudwise-(?:production|staging|dev)|\b(?:i|vol|snap|eni|sg|subnet|vpc)-[0-9a-f]{8,17}\b",
                         text)
    assert not re.search(r"arn:aws", text)


# --- never shared, by any path --------------------------------------------------------------------

class Tty(io.StringIO):
    def isatty(self):
        return True


def test_cli_demo_never_offers_to_share(capsys, monkeypatch):
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    sent = []
    monkeypatch.setattr(share, "send", lambda payload, **k: sent.append(payload) or True)
    monkeypatch.setattr(share, "offer", lambda *a, **k: sent.append("offer") or "sent")
    assert _run(["--demo"], capsys)[0] == 0
    assert sent == []


@pytest.mark.parametrize("env", [{share.ENV_SHARE: "yes"}, {}, {share.ENV_SHARE: "no"}])
def test_share_offer_skips_a_demo_report_with_every_setting(env):
    sent = []
    err = io.StringIO()
    result = share.offer(demo.load_report(), stdin=Tty("y\n"), stdout=Tty(), stderr=err, env=env,
                         sender=lambda p: sent.append(p) or True)
    assert result == "skipped" and sent == [] and err.getvalue() == ""
    assert not share.config_path().exists()  # not even "asked" is recorded


def test_mcp_share_and_payload_refuse_a_demo_report():
    sent = []
    assert share.share_from_settings_mcp(demo.load_report(), env={share.ENV_SHARE: "yes"},
                                         sender=sent.append) == "demo"
    assert sent == []
    with pytest.raises(ValueError):
        share.build_payload(demo.load_report(), "cli")
    with pytest.raises(ValueError):
        share.settings_payload(demo.load_report(), "mcp")


def test_prompt_cannot_be_reached_with_a_demo_report():
    sent = []
    assert share._prompt(demo.load_report(), "cli", Tty("y\n"), io.StringIO(), sent.append) == "skipped"
    assert sent == [] and not share.config_path().exists()


# --- MCP ------------------------------------------------------------------------------------------

def _text(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "text", None))


def _res(result) -> str:
    return "\n".join(c.text for c in result.contents if getattr(c, "text", None))


def _mcp(steps, *, share_on=False):
    server = mcp_server.build_server(share=share_on)

    async def go():
        async with Client(server) as client:
            return [await step(client) for step in steps]

    return asyncio.run(go())


def test_mcp_demo_scan_then_the_other_tools_work_on_it(monkeypatch):
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    sent = []
    monkeypatch.setattr(share, "send", lambda payload, **k: sent.append(payload) or True)
    ids = {}

    async def scan(c):
        return _text(await c.call_tool("scan", {"demo": True, "profile": "ignored", "regions": "all"}))

    async def listing(c):
        text = _text(await c.call_tool("list_findings", {"waste_type": "idle_dynamodb"}))
        ids["one"] = re.search(r"\| (demo-\d+) \|", text).group(1)
        return text

    async def explain(c):
        return _text(await c.call_tool("explain_finding", {"finding_id": ids["one"]}))

    async def fix(c):
        return _text(await c.call_tool("fix_guidance", {"finding_id": ids["one"]}))

    async def res_json(c):
        return _res(await c.read_resource("cloudcostwise://scan/latest"))

    async def res_summary(c):
        return _res(await c.read_resource("cloudcostwise://scan/latest/summary"))

    out = _mcp([scan, listing, explain, fix, res_json, res_summary], share_on=True)
    scan_t, list_t, explain_t, fix_t, res_json_t, res_sum_t = out
    for text in (scan_t, list_t, explain_t, fix_t, res_sum_t):
        assert text.startswith(demo.MCP_NOTE) and text.rstrip().endswith(demo.BANNER_BOTTOM)
    assert "Tell the user this is sample data" in scan_t
    assert "idle_dynamodb" in list_t and "Idle DynamoDB" in explain_t and "Delete or switch" in fix_t
    assert json.loads(res_json_t)["demo"] is True
    assert "ignored in demo mode" in scan_t
    assert sent == []  # CLOUDCOSTWISE_SHARE=yes and an MCP server with sharing on: still nothing


def test_mcp_demo_does_not_resolve_credentials(monkeypatch):
    async def scan(c):
        return _text(await c.call_tool("scan", {"demo": True}))

    assert "SAMPLE DATA" in _mcp([scan])[0]


def test_mcp_text_says_what_demo_is_and_never_asks_to_recommend():
    desc = {}

    async def tools(c):
        desc["scan"] = next(t for t in (await c.list_tools()).tools if t.name == "scan").description

    _mcp([tools])
    for text in (desc["scan"], mcp_server.INSTRUCTIONS, demo.MCP_NOTE):
        assert "demo" in text.lower() and "sample data" in text.lower()
        assert not re.search(r"recommend|upgrade|promote|sign up|suggest", text, re.I)


def test_demo_output_has_no_false_flag_note_and_the_card_is_marked(capsys):
    _, out, _ = _run(["--demo"], capsys)
    assert "--no-cost-explorer" not in out.replace("Add --no-cost-explorer", "")
    assert "RI/Savings Plans checks skipped" not in out
    card = out.split("cloudcostwise 100/100")[0].rsplit("\n", 2)[-2:]
    assert demo.CARD_MARK in out.split("Cost health score")[1].split("Found:")[0]
    _, md, _ = _run(["--demo", "--format", "markdown"], capsys)
    fenced = md.split("```")[1]
    assert demo.CARD_MARK in fenced


def _real_report():
    from types import SimpleNamespace
    from cloudcostwise.scan import ScanReport

    item = SimpleNamespace(id="r1", waste_type="unattached_ebs", resource_id="vol-real", monthly_savings=9.0,
                           region="us-east-1", title="Volume", description="d", confidence="high",
                           action="Delete it.", action_command=None, explanation={})
    return ScanReport(account_id="123456789012", regions=["us-east-1"], entrypoints=20, findings=[item])


def _mixed(order, monkeypatch):
    from cloudcostwise.runtime import Credentials

    sent = []
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    # CLO-1055: the MCP server waits for the capped send itself (share.send); both are caught here.
    monkeypatch.setattr(share, "send", lambda payload, **k: sent.append(payload) or True)
    real = _real_report()

    async def fake_scan(creds, regions, include_cost_explorer=True, on_region=None, full=False, with_spend=False):
        return real

    monkeypatch.setattr("cloudcostwise.mcp_server.resolve_credentials",
                        lambda p: Credentials("AKIATEST", "s", None, "123456789012", "us-east-1"))
    monkeypatch.setattr("cloudcostwise.mcp_server.resolve_regions", lambda r, c: ["us-east-1"])
    monkeypatch.setattr("cloudcostwise.mcp_server.run_scan_async", fake_scan)
    monkeypatch.setattr("cloudcostwise.exclude.apply", lambda r: r)
    out = {}

    def step(name, args):
        async def go(c):
            out[name] = _text(await c.call_tool("scan", args))
            out[name + "_list"] = _text(await c.call_tool("list_findings", {}))
        return go

    _mcp([step(n, a) for n, a in order], share_on=True)
    return out, sent


def test_demo_then_real_scan_in_one_session(monkeypatch):
    out, sent = _mixed([("demo", {"demo": True}), ("real", {})], monkeypatch)
    assert "SAMPLE DATA" in out["demo"] and "SAMPLE DATA" not in out["real"] and "SAMPLE DATA" not in out["real_list"]
    assert "vol-real" in out["real_list"] and "demo-001" not in out["real_list"]
    assert "service checks run locally" in out["real"]  # the footer was not used up by the demo scan
    assert len(sent) == 1 and sent[0]["findings_count"] == 1  # only the real scan was shared


def test_real_then_demo_scan_in_one_session(monkeypatch):
    out, sent = _mixed([("real", {}), ("demo", {"demo": True})], monkeypatch)
    assert "SAMPLE DATA" not in out["real"] and "vol-real" in out["real_list"]
    assert out["demo"].startswith(demo.MCP_NOTE) and "vol-real" not in out["demo_list"]
    assert len(sent) == 1 and sent[0]["findings_count"] == 1
