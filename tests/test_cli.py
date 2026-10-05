"""Unit tests for the local CLI: totals, rendering, the read-only guard, regions."""

import json
from types import SimpleNamespace
from unittest.mock import patch

import boto3
import pytest
from botocore.stub import Stubber

from cloudcostwise import render
from cloudcostwise.runtime import (
    Credentials,
    ReadOnlyViolation,
    configure_local_runtime,
    read_only_guard,
    resolve_regions,
)
from cloudcostwise.scan import COST_EXPLORER_DETECTORS, ScanReport, service_class

ADVISORY = "aurora_serverless_opportunity"   # advisory: true in the ledger
TRUSTED = "backup_no_lifecycle_tiering"      # trusted (L2)
CREDS = Credentials("AKIATEST", "secret", None, "123456789012", "eu-west-1")


def _item(waste_type, resource_id, monthly, region="us-east-1"):
    return SimpleNamespace(waste_type=waste_type, resource_id=resource_id, monthly_savings=monthly,
                           region=region, title=f"{waste_type} on {resource_id}", confidence="high",
                           action="delete it")


def _report(*items, calls=None):
    return ScanReport(account_id="123456789012", regions=["us-east-1"], findings=list(items),
                      api_calls=calls or {}, entrypoints=20)


def test_advisory_findings_are_listed_but_never_counted_in_the_total():
    report = _report(_item(TRUSTED, "a", 10.0), _item(TRUSTED, "b", 5.5), _item(ADVISORY, "c", 100.0))
    assert render.counted_total(report) == 15.5
    assert render.advisory_total(report) == 100.0
    data = json.loads(render.as_json(report))
    assert data["estimated_monthly_savings"] == 15.5
    assert data["advisory_monthly_savings_excluded"] == 100.0
    assert {f["validation"] for f in data["findings"]} == {"trusted", "advisory"}
    table = render.as_table(report)
    assert "Estimated savings: $15.50/month" in table
    assert "(advisory, not counted in the total)" in table
    assert "**Estimated savings: $15.50/month** (advisory excluded)" in render.as_markdown(report)


def test_counted_groups_come_before_advisory_and_sort_by_savings():
    report = _report(_item(ADVISORY, "z", 999.0), _item(TRUSTED, "small", 1.0), _item("idle_efs", "big", 50.0))
    order = [g.waste_type for g in render.groups(report)]
    assert order == ["idle_efs", TRUSTED, ADVISORY]


def test_footer_and_cost_explorer_note():
    report = _report(calls={"ce": 13, "ec2": 4})
    assert render.footer(report).startswith("20 of 46 service checks run locally. The other 26,")
    assert "connect?utm_source=cloudcostwise&utm_medium=cli" in render.footer(report)
    assert "13 Cost Explorer request(s)" in render.cost_explorer_note(report)
    assert "about $0.13" in render.cost_explorer_note(report)
    assert render.cost_explorer_note(_report(calls={"ec2": 4})) == ""


def test_empty_scan_says_so_and_totals_zero():
    report = _report()
    assert "No waste found" in render.as_table(report)
    assert json.loads(render.as_json(report))["estimated_monthly_savings"] == 0


def _client(service="dynamodb"):
    return boto3.client(service, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y")


def test_guard_refuses_a_write_before_it_is_sent_and_records_it():
    client = _client()
    with Stubber(client):  # no response queued: a call that got through would fail differently
        with read_only_guard() as guard:
            with pytest.raises(ReadOnlyViolation, match="dynamodb:PutItem"):
                client.put_item(TableName="t", Item={"pk": {"S": "x"}})
    assert guard.violations == ["dynamodb:PutItem"]
    assert guard.calls == {}


def test_guard_lets_reads_through_and_counts_them():
    client = _client()
    with Stubber(client) as stub:
        stub.add_response("list_tables", {"TableNames": []})
        with read_only_guard() as guard:
            client.list_tables()
    assert guard.violations == []
    assert guard.calls == {"dynamodb": 1}


def test_guard_restores_botocore_afterwards():
    import botocore.client
    before = botocore.client.BaseClient._make_api_call
    with read_only_guard():
        pass
    assert botocore.client.BaseClient._make_api_call is before


def test_default_regions_are_us_east_1_then_the_profile_region():
    assert resolve_regions(None, CREDS) == ["us-east-1", "eu-west-1"]
    no_region = Credentials("a", "b", None, "1", None)
    assert resolve_regions(None, no_region) == ["us-east-1"]
    assert resolve_regions("eu-west-1, us-east-1,eu-west-1", CREDS) == ["eu-west-1", "us-east-1"]


def test_all_regions_puts_us_east_1_first():
    client = _client("ec2")
    with Stubber(client) as stub:
        stub.add_response("describe_regions", {"Regions": [{"RegionName": "us-west-2"}, {"RegionName": "us-east-1"}]})
        with patch("cloudcostwise.runtime.boto3.client", return_value=client):
            assert resolve_regions("all", CREDS) == ["us-east-1", "us-west-2"]


def test_no_cost_explorer_drops_only_the_cost_explorer_entrypoint():
    full, no_ce = service_class(True), service_class(False)
    assert set(full.DETECTOR_METHODS) - set(no_ce.DETECTOR_METHODS) == set(COST_EXPLORER_DETECTORS)
    assert not COST_EXPLORER_DETECTORS & no_ce.ALWAYS_RUN_DETECTORS
    assert len(full.DETECTOR_METHODS) == 20


def test_local_runtime_savings_cache_never_touches_dynamodb():
    import asyncio
    from cloudwise_scan_core import savings_cache_service

    configure_local_runtime()
    cache = savings_cache_service.get_savings_cache_service()
    with patch.object(savings_cache_service.boto3, "resource") as resource:
        asyncio.run(cache.set_cached_recommendations("123456789012", "ec2_ri", [{"x": 1}]))
        assert asyncio.run(cache.get_cached_recommendations("123456789012", "ec2_ri")) == [{"x": 1}]
        assert asyncio.run(cache.needs_refresh("999999999999")) is True
    resource.assert_not_called()


def test_iam_policy_is_read_only():
    from pathlib import Path

    policy = json.loads((Path(__file__).resolve().parents[1] / "docs" / "iam-policy.json").read_text())
    actions = policy["Statement"][0]["Action"]
    assert actions == sorted(actions)
    for action in actions:
        verb = action.split(":", 1)[1]
        assert verb.startswith(("Describe", "List", "Get")), action


def test_blocked_service_is_answered_locally_as_access_denied_not_sent():
    from botocore.exceptions import ClientError

    client = _client("ce")
    with Stubber(client):  # nothing queued: a call that got through would raise StubResponseError
        with read_only_guard(frozenset({"ce"})) as guard:
            with pytest.raises(ClientError, match="AccessDenied"):
                client.get_cost_and_usage(TimePeriod={"Start": "2026-09-01", "End": "2026-10-01"},
                                          Granularity="MONTHLY", Metrics=["UnblendedCost"])
    assert guard.blocked == {"ce": 1}
    assert guard.violations == [] and guard.calls == {}


def test_no_cost_explorer_says_what_was_skipped_and_footer_still_counts_20_open_checks():
    report = _report()
    report.cost_explorer_skipped = True
    report.entrypoints = 19
    table = render.as_table(report)
    assert "RI/Savings Plans checks skipped (--no-cost-explorer)" in table
    assert "extended-support surcharges are estimates" in table
    assert "20 of 46 service checks run locally. The other 26," in table
    assert json.loads(render.as_json(report))["cost_explorer_skipped"] is True


def _region_result(region, n_findings, calls=None, violations=None, seconds=1.0):
    from cloudcostwise.scan import RegionResult
    return RegionResult(region=region, findings=[_item(TRUSTED, f"{region}-{i}", 1.0, region) for i in range(n_findings)],
                        warnings=[f"{region}: w"], errors=[], calls=calls or {"ec2": 2}, blocked={},
                        violations=violations or [], seconds=seconds)


def test_regions_aggregate_in_requested_order_with_summed_calls():
    from cloudcostwise import scan as scan_mod

    fake = {"us-east-1": _region_result("us-east-1", 2, {"ec2": 3, "ce": 13}), "eu-west-1": _region_result("eu-west-1", 1)}
    seen = []
    with patch.object(scan_mod, "scan_region", side_effect=lambda creds, r, ce: fake[r]):
        report = scan_mod.run_scan(CREDS, ["us-east-1", "eu-west-1"], on_region=lambda res: seen.append(res.region),
                                   parallel=1)
    assert [i.resource_id for i in report.findings] == ["us-east-1-0", "us-east-1-1", "eu-west-1-0"]
    assert report.api_calls == {"ec2": 5, "ce": 13}
    assert seen == ["us-east-1", "eu-west-1"]
    assert report.warnings == ["us-east-1: w", "eu-west-1: w"]


def test_a_refused_write_in_any_region_fails_the_whole_scan():
    from cloudcostwise import scan as scan_mod

    fake = {"us-east-1": _region_result("us-east-1", 1), "eu-west-1": _region_result("eu-west-1", 0, violations=["ec2:DeleteVolume"])}
    with patch.object(scan_mod, "scan_region", side_effect=lambda creds, r, ce: fake[r]):
        with pytest.raises(ReadOnlyViolation, match="ec2:DeleteVolume"):
            scan_mod.run_scan(CREDS, ["us-east-1", "eu-west-1"], parallel=1)


def test_scan_region_result_pickles_for_worker_processes():
    import pickle
    res = _region_result("us-east-1", 1)
    assert pickle.loads(pickle.dumps(res)).region == "us-east-1"


def test_placeholder_default_profile_falls_back_to_the_standard_chain(tmp_path, monkeypatch):
    from cloudcostwise import runtime

    cfg = tmp_path / "config"
    cfg.write_text("[profile other]\nregion = us-east-1\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    for value in ("default", "", "  "):
        monkeypatch.setenv("AWS_PROFILE", value)
        runtime._drop_placeholder_profile()
        assert "AWS_PROFILE" not in __import__("os").environ, repr(value)


def test_existing_default_or_named_profile_is_kept(tmp_path, monkeypatch):
    import os
    from cloudcostwise import runtime

    cfg = tmp_path / "config"
    cfg.write_text("[default]\nregion = us-east-1\n[profile other]\nregion = us-east-1\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.setenv("AWS_PROFILE", "default")
    runtime._drop_placeholder_profile()
    assert os.environ["AWS_PROFILE"] == "default"
    monkeypatch.setenv("AWS_PROFILE", "typo-profile")   # a real typo must still fail loudly later
    runtime._drop_placeholder_profile()
    assert os.environ["AWS_PROFILE"] == "typo-profile"
