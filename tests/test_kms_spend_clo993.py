"""CLO-993: ONE scan-level Cost Explorer request for the account's KMS spend, only when a finding needs it."""
from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.stub import Stubber
from cloudwise_scan_core.detectors.open.storage import KMS_SPEND_UNAVAILABLE_LINE
from cloudwise_scan_core.models import ConfidenceLevel, ResourceType, WasteItem, WasteType

from cloudcostwise import scan as scan_mod
from cloudcostwise.runtime import Credentials

REAL_KMS = scan_mod.fetch_kms_spend  # the autouse conftest stub replaces the module attribute
CREDS = Credentials("AKIATEST", "secret", None, "123456789012", "eu-west-1")


def _finding(bucket, waste_type=WasteType.S3_KMS_BUCKET_KEY_DISABLED, region="us-east-1"):
    return WasteItem(
        id=bucket, resource_id=bucket, resource_type=ResourceType.S3_BUCKET, waste_type=waste_type,
        title="t", description="d", monthly_savings=0.0, confidence=ConfidenceLevel.MEDIUM, action="a",
        explanation={"pricing": "Saving not claimed. " + KMS_SPEND_UNAVAILABLE_LINE},
        metadata={"account_kms_request_spend_usd": None}, region=region)


def _report(*findings):
    r = scan_mod.ScanReport(account_id="123456789012", regions=["us-east-1", "eu-west-1"])
    r.findings.extend(findings)
    return r


def _client(response=None, error=None):
    client = boto3.client("ce", region_name="us-east-1", aws_access_key_id="a", aws_secret_access_key="b")
    stub = Stubber(client)
    start, end = scan_mod.kms_spend_window()
    expected = {
        "TimePeriod": {"Start": start, "End": end}, "Granularity": "MONTHLY", "Metrics": ["UnblendedCost"],
        "Filter": {"Dimensions": {"Key": "SERVICE", "Values": ["AWS Key Management Service"]}},
        "GroupBy": [{"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
    }
    if error:
        stub.add_client_error("get_cost_and_usage", service_error_code=error, expected_params=expected)
    else:
        stub.add_response("get_cost_and_usage", response, expected)
    stub.activate()
    return client


def _groups(*pairs):
    return {"ResultsByTime": [{"TimePeriod": {"Start": "x", "End": "y"}, "Estimated": False, "Total": {}, "Groups": [
        {"Keys": [k], "Metrics": {"UnblendedCost": {"Amount": str(v), "Unit": "USD"}}} for k, v in pairs]}]}


def test_the_window_is_the_last_complete_calendar_month():
    assert scan_mod.kms_spend_window(datetime.date(2026, 11, 13)) == ("2026-10-01", "2026-11-01")
    assert scan_mod.kms_spend_window(datetime.date(2027, 1, 2)) == ("2026-12-01", "2027-01-01")


def test_findings_in_several_regions_make_exactly_one_request_and_all_get_the_spend():
    r = _report(_finding("a", region="us-east-1"), _finding("b", region="eu-west-1"), _finding("c", region="us-east-1"))
    resp = _groups(("USE1-KMS-Requests", 12.34), ("USE1-KMS-Keys", 1.0), ("EUW1-KMS-Requests-Asymmetric-RSA_2048", 0.66))
    with patch.object(scan_mod.boto3, "client", return_value=_client(resp)) as mk:
        REAL_KMS(CREDS, r)
    assert mk.call_count == 1 and r.api_calls == {"ce": 1}
    for f in r.findings:
        assert "last month (" in f.explanation["pricing"] and "$13.00" in f.explanation["pricing"]
        assert KMS_SPEND_UNAVAILABLE_LINE not in f.explanation["pricing"]
        assert f.metadata["account_kms_request_spend_usd"] == 13.0
        assert f.monthly_savings == 0.0


def test_nothing_firing_makes_no_request():
    r = _report(_finding("a", waste_type=WasteType.S3_NO_DEFAULT_ENCRYPTION))
    with patch.object(scan_mod.boto3, "client") as mk:
        REAL_KMS(CREDS, r)
    mk.assert_not_called()
    assert r.api_calls == {}


def test_a_cost_explorer_error_keeps_the_findings_and_adds_no_warning():
    r = _report(_finding("a"))
    with patch.object(scan_mod.boto3, "client", return_value=_client(error="AccessDeniedException")):
        REAL_KMS(CREDS, r)
    assert KMS_SPEND_UNAVAILABLE_LINE in r.findings[0].explanation["pricing"]
    assert r.findings[0].metadata["account_kms_request_spend_usd"] is None
    assert r.warnings == [] and r.errors == [] and r.permission_errors == []


def _run(monkeypatch, **kwargs):
    res = scan_mod.RegionResult("us-east-1", [_finding("a")], [], [], {}, {}, [], 0.1)
    monkeypatch.setattr(scan_mod, "scan_region", lambda *a, **k: res)
    monkeypatch.setattr(scan_mod, "fetch_monthly_spend", lambda c, r: None)
    called = MagicMock()
    monkeypatch.setattr(scan_mod, "fetch_kms_spend", called)
    report = scan_mod.run_scan(CREDS, ["us-east-1"], parallel=1, **kwargs)
    return report, called


def test_cost_explorer_off_makes_no_request_and_no_warning(monkeypatch):
    report, called = _run(monkeypatch, include_cost_explorer=False, with_spend=True)
    called.assert_not_called()
    assert report.api_calls.get("ce", 0) == 0 and report.permission_errors == []
    assert not any("MISSING" in w for w in report.warnings)


def test_a_scan_with_spend_runs_the_step_once_after_the_regions_are_merged(monkeypatch):
    report, called = _run(monkeypatch, with_spend=True)
    assert called.call_count == 1
    assert len(called.call_args[0][1].findings) == 1


def test_other_callers_do_not_run_the_step(monkeypatch):
    _, called = _run(monkeypatch)
    called.assert_not_called()
