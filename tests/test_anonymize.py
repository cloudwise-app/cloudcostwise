"""CLO-929: --anonymize writes a report that is safe to email."""

import json
import re
from types import SimpleNamespace

import pytest

from cloudcostwise import cli, render
from cloudcostwise.anonymize import anonymize_report
from cloudcostwise.scan import ScanReport

ACCT = "123456789012"
OTHER_ACCT = "111122223333"  # an ID scripts/export_open_core.py allows (AWS documentation example)
VOL_ARN = f"arn:aws:ec2:eu-west-1:{ACCT}:volume/vol-0abc123def4567890"
LB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCT}:loadbalancer/app/payroll-alb/50dc6c495c0c9188"
SECRET_NAMES = ["payroll-alb", "acme-billing-db", "vol-0abc123def4567890", "orders-bucket-prod", "Team Phoenix",
                "50dc6c495c0c9188", ACCT, OTHER_ACCT]


def _item(waste_type, resource_id, monthly, region, title, action, **meta):
    return SimpleNamespace(waste_type=waste_type, resource_id=resource_id, monthly_savings=monthly, region=region,
                           title=title, confidence="high", action=action, account_id=ACCT, metadata=meta,
                           description=f"details for {resource_id}", action_command=f"aws ec2 delete-volume {resource_id}",
                           ai_action_steps=None, explanation=None)


def _report():
    items = [
        _item("backup_no_lifecycle_tiering", VOL_ARN, 40.0, "eu-west-1",
              "Unattached volume vol-0abc123def4567890 owned by Team Phoenix",
              "Snapshot then delete vol-0abc123def4567890 in account " + ACCT,
              name="acme-billing-db", tags=[{"Key": "team", "Value": "Team Phoenix"}]),
        _item("backup_no_lifecycle_tiering", "vol-0abc123def4567890", 5.5, "eu-west-1",
              "Second look at vol-0abc123def4567890", "Delete it"),
        _item("aurora_serverless_opportunity", LB_ARN, 12.25, "us-east-1",
              "Idle load balancer payroll-alb", "Delete payroll-alb (" + LB_ARN + ")"),
        _item("backup_no_lifecycle_tiering", "orders-bucket-prod", 3.0, "us-east-1",
              "Bucket orders-bucket-prod has no lifecycle rule", "Add a rule to orders-bucket-prod"),
    ]
    return ScanReport(
        account_id=ACCT, regions=["us-east-1", "eu-west-1"], findings=items, entrypoints=20,
        warnings=[f"us-east-1: could not read metrics for payroll-alb in {ACCT}", f"role arn:aws:iam::{OTHER_ACCT}:role/admin"],
        errors=["eu-west-1: timeout on vol-0abc123def4567890"],
        permission_errors=[f"AccessDenied: arn:aws:iam::{ACCT}:user/rick calling ec2:DescribeVolumes on acme-billing-db"],
        coverage_notes=["Compute Optimizer is not enabled for orders-bucket-prod's account " + ACCT],
    )


def _json(report, anonymize):
    return json.loads(render.as_json(anonymize_report(report) if anonymize else report))


def test_json_has_no_account_id_arn_resource_id_or_tag_value():  # acceptance 1
    text = render.as_json(anonymize_report(_report()))
    for secret in SECRET_NAMES:
        assert secret not in text, secret
    assert not re.search(r"(?<!\d)\d{12}(?!\d)", text)
    assert "arn:aws" not in text
    data = json.loads(text)
    assert data["account_id"] == "account-1"


def test_the_same_value_gets_the_same_placeholder_everywhere():  # acceptance 2
    data = _json(_report(), True)
    f = data["findings"]
    by_savings = {x["monthly_savings"]: x for x in f}
    # the ARN and the bare id of one volume are one resource
    assert by_savings[40.0]["resource_id"] == by_savings[5.5]["resource_id"] == "resource-1"
    assert "resource-1" in by_savings[40.0]["title"] and "resource-1" in by_savings[40.0]["action"]
    assert "resource-1" in data["errors"][0]
    # the load balancer: ARN in resource_id, name in title and action, one placeholder
    lb = by_savings[12.25]
    assert lb["resource_id"] in lb["title"] and lb["resource_id"] in lb["action"]
    assert lb["resource_id"] in data["warnings"][0]
    # the account: report, action text, warning, coverage note
    assert "account-1" in by_savings[40.0]["action"] and "account-1" in data["warnings"][0]
    assert "account-1" in data["coverage_notes"][0]
    assert "arn-1" in data["warnings"][1]  # an ARN no finding names still goes, whole
    # metadata name resolved to the same resource as its ARN
    assert "acme" not in json.dumps(data)


def test_numbers_and_wording_match_the_unredacted_report():  # acceptance 3
    plain, anon = _json(_report(), False), _json(_report(), True)
    for key in ("estimated_monthly_savings", "advisory_monthly_savings_excluded", "regions", "checks_run",
                "score", "score_basis", "aws_api_calls", "cost_explorer_skipped"):
        assert plain[key] == anon[key]
    assert len(plain["findings"]) == len(anon["findings"])
    for a, b in zip(plain["findings"], anon["findings"]):
        for key in ("waste_type", "validation", "region", "monthly_savings", "confidence"):
            assert a[key] == b[key]
    assert len(plain["warnings"]) == len(anon["warnings"])
    assert any("Add a rule to" in x["action"] for x in anon["findings"])  # action wording kept


def test_the_original_report_is_not_changed_and_default_output_is_byte_identical():  # acceptance 4
    report = _report()
    before = render.as_json(report)
    anonymize_report(report)
    assert render.as_json(report) == before and ACCT in before


def test_markdown_and_table_carry_no_identifiers_either():
    anon = anonymize_report(_report())
    for text in (render.as_markdown(anon), render.as_table(anon, verbose=True)):
        for secret in SECRET_NAMES:
            assert secret not in text, secret
        assert "account-1" in text and "resource-1" in text


def test_short_resource_names_do_not_eat_ordinary_words():
    r = _report()
    r.findings = [_item("backup_no_lifecycle_tiering", "a", 1.0, "us-east-1", "Table a is idle", "Delete a table in a region")]
    out = anonymize_report(r).findings[0]
    assert out.resource_id == "resource-1" and out.title == "Table resource-1 is idle"
    assert out.action == "Delete resource-1 table in resource-1 region"  # full id always replaced, whatever its length


def _run_cli(monkeypatch, capsys, argv):
    from cloudcostwise import runtime, scan

    monkeypatch.setattr(runtime, "configure_local_runtime", lambda: None)
    monkeypatch.setattr(runtime, "resolve_credentials",
                        lambda profile: runtime.Credentials("AKIATEST", "s", None, ACCT, "us-east-1"))
    monkeypatch.setattr(runtime, "resolve_regions", lambda regions, creds: ["us-east-1", "eu-west-1"])
    monkeypatch.setattr(scan, "run_scan", lambda *a, **k: _report())
    monkeypatch.setattr("cloudcostwise.share.offer", lambda report: "skipped")
    assert cli.main(argv) == 0
    return capsys.readouterr().out


@pytest.mark.parametrize("fmt, direct", [
    ("json", lambda r: render.as_json(r)),
    ("markdown", lambda r: render.as_markdown(r, emoji=False)),
    ("table", lambda r: render.as_table(r, verbose=False, emoji=False)),
])
def test_cli_output_without_the_flag_is_the_plain_render_and_with_it_the_anonymized_one(monkeypatch, capsys, fmt, direct):
    plain = _run_cli(monkeypatch, capsys, ["scan", "--format", fmt])
    assert plain == direct(_report()) + "\n" and ACCT in plain
    anon = _run_cli(monkeypatch, capsys, ["scan", "--format", fmt, "--anonymize"])
    assert anon == direct(anonymize_report(_report())) + "\n"
    assert ACCT not in anon and "payroll-alb" not in anon


def test_help_lists_the_option_and_does_not_promise_completeness(capsys):
    with pytest.raises(SystemExit):
        cli.main(["scan", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "--anonymize" in out and "not complete" in out and "review the report" in out


# --- identifiers the scan engine puts in report text without a finding naming them ---

def _provider(region="us-east-1"):
    return SimpleNamespace(region=region, data_warnings=[])


def test_ebs_snapshot_notes_built_by_scan_core_lose_their_snapshot_ids():
    from cloudwise_scan_core.detectors.open import storage

    dp = _provider()
    storage._note_ebs_snapshots_kept(dp, ["snap-0123456789abcdef0", "snap-0fedcba9876543210"])
    storage._note_ebs_snapshots_newest(dp, [("snap-00aa11bb22cc33dd4", storage._NEWEST_OF_LIVE_VOLUME)])
    assert all(p in "".join(dp.data_warnings) for p in storage.EBS_SNAPSHOT_WITHHELD_NOTE_PREFIXES)
    r = _report()
    r.warnings = [f"us-east-1: {w}" for w in dp.data_warnings]
    out = anonymize_report(r)
    text = "\n".join(out.warnings) + render.as_table(out)
    assert "snap-" not in text and "0123456789abcdef0" not in text
    assert "newest snapshot of a volume that still exists" in text and "(x1)" in text  # reasons and counts stay
    assert render.withheld_notes(out) == out.warnings  # still recognised as deliberate skips


def test_rds_snapshot_note_built_by_scan_core_loses_user_chosen_snapshot_names():
    from cloudwise_scan_core.detectors.open import database

    dp = _provider()
    database._note_rds_snapshots_withheld(dp, [("acme-payroll-final-2023", "shared with another account", database._SHARING),
                                               ("manual-before-upgrade", "the only copy", database._ONLY_COPY)])
    assert database.RDS_SNAPSHOT_NOTE_PREFIX in dp.data_warnings[0] and "acme-payroll-final-2023" in dp.data_warnings[0]
    r = _report()
    r.warnings = dp.data_warnings
    text = "\n".join(anonymize_report(r).warnings)
    assert "acme-payroll" not in text and "manual-before-upgrade" not in text
    assert "(x1)" in text and "Review these by hand" in text


def test_permission_error_resources_go_even_when_no_finding_names_them():
    # Format of waste_detection_service.py (provider_permission_errors) behind scan.py's "<region>: " prefix.
    r = _report()
    r.permission_errors = [
        "us-east-1: ec2: arn:aws:ec2:us-east-1:111122223333:volume/vol-0aaaabbbb1111cccc needs ec2:DescribeVolumes (AccessDenied)",
        "eu-west-1: s3: hr-secret-bucket needs s3:GetBucketTagging (AccessDenied)",
        "eu-west-1: s3: hr-secret-bucket needs s3:GetLifecycleConfiguration (AccessDenied)",
    ]
    got = anonymize_report(r).permission_errors
    assert "hr-secret-bucket" not in "".join(got) and "vol-0aaaabbbb" not in "".join(got) and "111122223333" not in "".join(got)
    assert got[1].startswith("eu-west-1: s3: resource-") and "needs s3:GetBucketTagging (AccessDenied)" in got[1]
    assert got[1].split(" needs ")[0] == got[2].split(" needs ")[0]  # same bucket, same placeholder


def test_bare_aws_ids_in_any_text_are_replaced_and_numbers_are_kept():
    r = _report()
    r.coverage_notes = ["eu-west-1: i-0123456789abcdef0 and ami-0abcdef1234567890 and 3 volumes, $12.00"]
    out = anonymize_report(r).coverage_notes[0]
    assert "i-0123" not in out and "ami-0abc" not in out and "3 volumes, $12.00" in out


def test_names_match_in_any_case():
    r = _report()
    r.findings = [_item("backup_no_lifecycle_tiering", "Acme-Payroll-DB", 9.0, "us-east-1",
                        "Idle acme-payroll-db", "Stop ACME-PAYROLL-DB tonight")]
    out = anonymize_report(r).findings[0]
    assert out.title == "Idle resource-1" and out.action == "Stop resource-1 tonight"


def test_url_encoded_identifiers_are_replaced():
    r = _report()
    arn = "arn:aws:s3:::hr-secret-bucket/reports/q3"
    r.findings = [_item("backup_no_lifecycle_tiering", arn, 9.0, "us-east-1", "t", "see https://console/?id=" + "arn%3Aaws%3As3%3A%3A%3Ahr-secret-bucket%2Freports%2Fq3")]
    r.warnings = ["arn%253Aaws%253As3%253A%253A%253Ahr-secret-bucket%252Freports%252Fq3 (double encoded)", "hr-secret-bucket%2Fx"]
    out = anonymize_report(r)
    text = json.dumps([out.findings[0].action, out.warnings])
    assert "hr-secret-bucket" not in text and "arn%3A" not in text and "%25" not in text


def test_identifier_style_metadata_keys_are_used():
    r = _report()
    r.findings = [_item("backup_no_lifecycle_tiering", "db-ABCDEFGHIJKLMNOP", 9.0, "us-east-1",
                        "Idle database ledger-prod-primary", "Resize ledger-prod-primary or i-keep",
                        DBInstanceIdentifier="ledger-prod-primary", InstanceId="legacy-box-07")]
    r.warnings = ["could not read legacy-box-07"]
    out = anonymize_report(r)
    text = json.dumps([out.findings[0].title, out.findings[0].action, out.warnings])
    assert "ledger-prod" not in text and "legacy-box" not in text


def test_two_resources_sharing_a_name_tag_do_not_read_as_one_resource():
    r = _report()
    r.findings = [
        _item("backup_no_lifecycle_tiering", "vol-0aaaa1111bbbb2222", 5.0, "us-east-1", "Volume of web-server-tier", "Delete",
              Name="web-server-tier"),
        _item("backup_no_lifecycle_tiering", "vol-0cccc3333dddd4444", 4.0, "us-east-1", "Volume of web-server-tier", "Delete",
              Name="web-server-tier"),
    ]
    data = json.loads(render.as_json(anonymize_report(r)))
    a, b = data["findings"]
    assert a["resource_id"] != b["resource_id"]
    assert "web-server-tier" not in json.dumps(data)
    assert a["title"] == b["title"] and a["title"] not in (a["resource_id"], b["resource_id"]) and "name-1" in a["title"]
