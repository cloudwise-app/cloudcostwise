"""CLO-858: score card, share grid, spend lookup, live board."""

import asyncio
import io
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from cloudcostwise import board, render
from cloudcostwise import scan as scan_mod
from cloudcostwise.runtime import Credentials, ReadOnlyViolation
from cloudcostwise.scan import ScanReport, fetch_monthly_spend as real_fetch  # real, before the autouse stub

CREDS = Credentials("AKIATEST", "secret", None, "123456789012", "eu-west-1")
TRUSTED = "backup_no_lifecycle_tiering"
ADVISORY = "aurora_serverless_opportunity"


def _item(wt, rid, monthly, region="us-east-1"):
    return SimpleNamespace(waste_type=wt, resource_id=rid, monthly_savings=monthly, region=region,
                           title=f"{wt} {rid}", confidence="high", action="x")


def _report(*items, spend=None, ce_skipped=False):
    return ScanReport(account_id="123456789012", regions=["us-east-1", "eu-west-1"], findings=list(items),
                      entrypoints=20, spend_monthly=spend, seconds=12.3, cost_explorer_skipped=ce_skipped)


def test_card_without_spend_is_labelled_and_has_no_url():
    r = _report(_item(TRUSTED, "a", 100.0))
    card = "\n".join(render.score_card(r))
    assert "without spend data" in card
    assert "$100.00/month found" in card and "2 region(s)" in card and "12.3s" in card
    assert "http" not in card and "cloudcostwise.io" not in card
    assert "X" in card  # one fired glyph


def test_card_with_spend_uses_the_spend_formula():
    r = _report(_item(TRUSTED, "a", 150.0), spend=1000.0)
    assert render.score_for(r).value == 75 and render.score_for(r).basis == "spend"
    assert "75/100 (of your last 30 days of spend)" in "\n".join(render.score_card(r))


def test_advisory_is_not_counted_in_the_score_and_fires_no_cell():
    r = _report(_item(ADVISORY, "a", 999.0))
    assert render.score_for(r).value == 100
    assert {st for _k, st in render.grid_states(r)} == {"clean"}
    card = "\n".join(render.score_card(r))
    assert f"{ADVISORY} (advisory)" in card
    assert "Advisory findings are listed, not counted in the score." in card


def test_grid_is_one_cell_per_service_check_and_lights_the_emitting_check():
    states = dict(render.grid_states(_report(_item("idle_efs", "a", 5.0))))
    assert states["efs"] == "fired" and states["ec2"] == "clean"
    n = len(states)
    assert n == len(scan_mod.service_class(True).DETECTOR_METHODS)
    rows = render.share_grid(_report())
    assert sum(len(x) for x in rows) == n and all(len(x) <= render.GRID_ROW for x in rows)
    assert set("".join(rows)) <= set(".X-")


def test_no_cost_explorer_marks_the_ce_check_skipped_and_counts_only_checks_that_ran():
    r = _report(ce_skipped=True)
    r.entrypoints = len(scan_mod.service_class(False).DETECTOR_METHODS)
    states = dict(render.grid_states(r))
    assert states["savings_opportunities"] == "skipped"
    assert [k for k, v in states.items() if v == "skipped"] == ["savings_opportunities"]
    assert f"0 of {len(states) - 1} checks fired" in "\n".join(render.score_card(r))


def test_emoji_grid_only_when_asked():
    assert "\U0001F7E9" in "\n".join(render.score_card(_report(), emoji=True))
    assert "\U0001F7E9" not in "\n".join(render.score_card(_report()))


def test_table_and_markdown_gain_the_card_and_json_gains_two_keys():
    r = _report(_item(TRUSTED, "a", 10.0))
    assert "Cost health score:" in render.as_table(r)
    assert "**Cost health score:" in render.as_markdown(r)
    data = json.loads(render.as_json(r))
    assert data["score"] == render.score_for(r).value and data["score_basis"] == "no_spend"
    without = {k: v for k, v in data.items() if k not in ("score", "score_basis", "excluded_by_list_count",
                                                            "excluded_by_list_resource_ids")}  # CLO-931 keys
    assert "findings" in without and len(without) == 14


def test_table_output_is_unchanged_apart_from_the_card_lines():
    r = _report(_item(TRUSTED, "a", 10.0))
    card = render.score_card(r)
    table = render.as_table(r)
    for line in card:
        if line:
            assert line in table
    stripped = table
    for line in card:
        stripped = stripped.replace(line + "\n", "", 1) if line else stripped
    assert "Estimated savings: $10.00/month" in stripped and "Cost health" not in stripped


# --- spend lookup -------------------------------------------------------

def _ce_client(response=None, error=None):
    client = boto3.client("ce", region_name="us-east-1", aws_access_key_id="a", aws_secret_access_key="b")
    stub = Stubber(client)
    expected = {"TimePeriod": {"Start": scan_mod.spend_window()[0], "End": scan_mod.spend_window()[1]},
                "Granularity": "DAILY", "Metrics": ["UnblendedCost"]}
    if error:
        stub.add_client_error("get_cost_and_usage", service_error_code=error, expected_params=expected)
    else:
        stub.add_response("get_cost_and_usage", response, expected)
    stub.activate()
    return client


def test_spend_window_is_the_last_30_complete_days_like_the_backend():
    import datetime
    # backend complete_day_window(30): yesterday and the 29 days before; CE's end is exclusive (today)
    assert scan_mod.spend_window(datetime.date(2026, 11, 7)) == ("2026-10-08", "2026-11-07")
    assert scan_mod.spend_window(datetime.date(2027, 1, 15)) == ("2026-12-16", "2027-01-15")


def test_spend_is_one_request_and_counted():
    resp = {"ResultsByTime": [{"TimePeriod": {"Start": "x", "End": "y"}, "Estimated": False,
                               "Total": {"UnblendedCost": {"Amount": "1234.5", "Unit": "USD"}}}]}
    r = _report()
    with patch.object(scan_mod.boto3, "client", return_value=_ce_client(resp)) as mk:
        real_fetch(CREDS, r)
    assert mk.call_count == 1 and mk.call_args[0][0] == "ce"
    assert r.spend_monthly == 1234.5 and r.api_calls == {"ce": 1}


def test_a_cost_explorer_error_falls_back_and_never_raises():
    r = _report()
    with patch.object(scan_mod.boto3, "client", return_value=_ce_client(error="AccessDeniedException")):
        real_fetch(CREDS, r)
    assert r.spend_monthly is None
    assert render.score_for(r).basis == "no_spend"


def test_the_read_only_guard_still_covers_the_spend_lookup():
    client = MagicMock()
    client.meta.service_model.service_name = "ce"
    # a write operation reaching the guard through the same path is refused, not swallowed
    from cloudcostwise.runtime import read_only_guard
    import botocore.client
    with read_only_guard() as g:
        with pytest.raises(ReadOnlyViolation):
            botocore.client.BaseClient._make_api_call(client, "DeleteAnomalyMonitor", {})
        assert g.violations == ["ce:DeleteAnomalyMonitor"]


def test_no_cost_explorer_makes_no_spend_call_and_labels_the_fallback(monkeypatch):
    res = scan_mod.RegionResult("us-east-1", [], [], [], {}, {}, [], 0.1)
    monkeypatch.setattr(scan_mod, "scan_region", lambda *a, **k: res)
    called = MagicMock()
    monkeypatch.setattr(scan_mod, "fetch_monthly_spend", called)
    with patch.object(scan_mod.boto3, "client") as mk:
        report = scan_mod.run_scan(CREDS, ["us-east-1"], include_cost_explorer=False, parallel=1)
    called.assert_not_called()
    mk.assert_not_called()
    assert report.spend_monthly is None and report.api_calls.get("ce", 0) == 0
    assert "without spend data" in render.as_table(report)


def test_run_scan_fetches_spend_when_cost_explorer_is_on(monkeypatch):
    res = scan_mod.RegionResult("us-east-1", [], [], [], {}, {}, [], 0.1)
    monkeypatch.setattr(scan_mod, "scan_region", lambda *a, **k: res)
    monkeypatch.setattr(scan_mod, "fetch_monthly_spend", lambda c, r: setattr(r, "spend_monthly", 500.0))
    report = scan_mod.run_scan(CREDS, ["us-east-1"], parallel=1, with_spend=True)
    assert report.spend_monthly == 500.0 and report.seconds >= 0


def test_the_spend_lookup_is_opt_in_so_other_callers_make_the_same_requests_as_before(monkeypatch):
    res = scan_mod.RegionResult("us-east-1", [], [], [], {}, {}, [], 0.1)
    monkeypatch.setattr(scan_mod, "scan_region", lambda *a, **k: res)
    called = MagicMock()
    monkeypatch.setattr(scan_mod, "fetch_monthly_spend", called)
    scan_mod.run_scan(CREDS, ["us-east-1"], parallel=1)
    called.assert_not_called()


# --- live board ---------------------------------------------------------

class _TTY(io.StringIO):
    def isatty(self):
        return True


def _res(region, n, monthly):
    return SimpleNamespace(region=region, findings=[_item(TRUSTED, f"r{i}", monthly) for i in range(n)], seconds=2.0)


def test_board_rewrites_in_place_and_totals(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    out = _TTY()
    b = board.RegionBoard(["us-east-1", "eu-west-1", "us-west-2"], 2, out)
    b.draw()
    first = out.getvalue()
    assert "running" in first and "pending" in first and "\x07" not in first
    b.region_done(_res("us-east-1", 2, 10.0))
    text = out.getvalue()
    assert "\x1b[4A" in text  # 3 regions + the total line, moved up before the rewrite
    assert "done" in text and "found so far $20.00/month" in text


def test_board_uses_no_colour_under_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    out = _TTY()
    board.RegionBoard(["us-east-1", "eu-west-1"], 1, out).draw()
    assert "\x1b[1m" not in out.getvalue() and "\x1b[2m" not in out.getvalue()


def test_wants_board_only_for_a_tty(monkeypatch):
    monkeypatch.setenv("TERM", "xterm")
    assert board.wants_board(_TTY()) and not board.wants_board(io.StringIO())
    monkeypatch.setenv("TERM", "dumb")
    assert not board.wants_board(_TTY())


def _run_cli(monkeypatch, capsys, fmt, tty):
    from cloudcostwise import cli
    from cloudcostwise import runtime
    res = scan_mod.RegionResult("us-east-1", [_item(TRUSTED, "a", 10.0)], [], [], {}, {}, [], 0.1)
    monkeypatch.setattr(runtime, "resolve_credentials", lambda p: CREDS)
    monkeypatch.setattr(runtime, "resolve_regions", lambda s, c: ["us-east-1"])
    monkeypatch.setattr(scan_mod, "scan_region", lambda *a, **k: res)
    monkeypatch.setattr(runtime, "configure_local_runtime", lambda: None)
    monkeypatch.setattr(board, "wants_board", lambda s: tty)
    monkeypatch.setattr("cloudcostwise.share.offer", lambda r: None)
    assert cli.main(["scan", "--parallel", "1", "--format", fmt, "--no-cost-explorer"]) == 0
    return capsys.readouterr()


def test_cli_piped_keeps_the_plain_region_line(monkeypatch, capsys):
    cap = _run_cli(monkeypatch, capsys, "table", tty=False)
    assert "  [1/1] us-east-1" in cap.err and "\x1b[" not in cap.err
    assert "Cost health score:" in cap.out


def test_cli_on_a_tty_shows_the_board_and_ends_with_the_card(monkeypatch, capsys):
    cap = _run_cli(monkeypatch, capsys, "table", tty=True)
    assert "found so far $10.00/month" in cap.err and "  [1/1]" not in cap.err
    assert "Cost health score:" in cap.out


def test_cli_json_never_gets_the_board(monkeypatch, capsys):
    cap = _run_cli(monkeypatch, capsys, "json", tty=True)
    assert "  [1/1] us-east-1" in cap.err and "found so far" not in cap.err
    assert json.loads(cap.out)["score_basis"] == "no_spend"
