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
    assert "connect?src=cli" in render.footer(report)
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
