"""CLO-931: a local exclude list that survives the next scan."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from mcp.client import Client

from cloudcostwise import cli, exclude, mcp_server, render, share
from cloudcostwise.anonymize import anonymize_report
from cloudcostwise.runtime import Credentials
from cloudcostwise.scan import ScanReport

ACCT = "123456789012"
VOL = "vol-0abc123def4567890"
VOL_ARN = f"arn:aws:ec2:eu-west-1:{ACCT}:volume/{VOL}"
FS = "fs-0123456789abcdef0"
BUCKET = "orders-bucket-prod"
TRUSTED = "backup_no_lifecycle_tiering"  # a counted (non-advisory) type, as in test_share.py


def _item(rid, monthly, fid=None):
    return SimpleNamespace(id=fid or rid, waste_type=TRUSTED, resource_id=rid, monthly_savings=monthly,
                           region="eu-west-1", title=f"Idle {rid}", confidence="high", action="delete it",
                           account_id=ACCT, metadata={}, description="d", action_command=None, explanation={})


def _report():
    return ScanReport(account_id=ACCT, regions=["eu-west-1"], entrypoints=20, findings=[
        _item(VOL_ARN, 40.0, "f1"), _item(FS, 10.0, "f2"), _item(BUCKET, 5.0, "f3")])


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _run(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


def _scan(monkeypatch, capsys, *extra):
    from cloudcostwise import runtime, scan

    monkeypatch.setattr(runtime, "configure_local_runtime", lambda: None)
    monkeypatch.setattr(runtime, "resolve_credentials",
                        lambda profile: runtime.Credentials("AKIATEST", "s", None, ACCT, "eu-west-1"))
    monkeypatch.setattr(runtime, "resolve_regions", lambda regions, creds: ["eu-west-1"])
    monkeypatch.setattr(scan, "run_scan", lambda *a, **k: _report())
    monkeypatch.setattr("cloudcostwise.share.offer", lambda report: "skipped")
    capsys.readouterr()
    assert cli.main(["scan", *extra]) == 0
    return capsys.readouterr().out


# --- acceptance 1: add, then scan leaves it out of every format and the total ------------------

@pytest.mark.parametrize("fmt", ["table", "markdown", "json"])
def test_added_resource_is_left_out_of_every_format_and_the_total(monkeypatch, capsys, fmt):  # acceptance 1
    assert _run(["exclude", "add", FS, "--reason", "shared by the data team"], capsys)[0] == 0
    text = _scan(monkeypatch, capsys, "--format", fmt)
    assert VOL in text and BUCKET in text
    if fmt == "json":
        data = json.loads(text)
        assert data["estimated_monthly_savings"] == 45.0
        assert [f["resource_id"] for f in data["findings"]] == [VOL_ARN, BUCKET]
        assert data["excluded_by_list_count"] == 1 and data["excluded_by_list_resource_ids"] == [FS]
    else:
        assert FS not in text
        assert "$45.00" in text and "$55.00" not in text
        assert "Left out on purpose" in text
        assert "1 finding left out by your exclude list (cloudcostwise exclude list)" in text


def test_the_count_is_plural_and_the_score_card_uses_the_reduced_total(monkeypatch, capsys):
    _run(["exclude", "add", FS], capsys)
    _run(["exclude", "add", BUCKET], capsys)
    table = _scan(monkeypatch, capsys)
    assert "2 findings left out by your exclude list (cloudcostwise exclude list)" in table
    assert "Estimated savings: $40.00/month" in table and "$40.00/month found" in table  # card agrees


# --- acceptance 2: survives a new process, remove brings it back --------------------------------

def test_the_list_is_read_from_disk_and_remove_brings_the_finding_back(monkeypatch, capsys, home):  # acceptance 2
    _run(["exclude", "add", FS], capsys)
    path = home / ".config" / "cloudcostwise" / "exclude.json"
    assert path.parent == share.config_path().parent and path.exists()
    assert json.loads(path.read_text())["entries"][0]["id"] == FS   # a fresh process reads exactly this
    assert FS not in _scan(monkeypatch, capsys)
    code, out, _ = _run(["exclude", "list"], capsys)
    assert code == 0 and FS in out
    assert _run(["exclude", "remove", FS], capsys)[0] == 0
    assert FS in _scan(monkeypatch, capsys)
    assert "left out by your exclude list" not in _scan(monkeypatch, capsys)
    assert _run(["exclude", "remove", FS], capsys)[0] == 1   # not on the list any more


def test_the_config_dir_follows_share_config_path(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(share, "config_path", lambda: tmp_path / "elsewhere" / "share.json")
    _run(["exclude", "add", FS], capsys)
    assert (tmp_path / "elsewhere" / "exclude.json").exists()


# --- acceptance 3: bare id and full ARN match whichever form was added --------------------------

DB_ARN = f"arn:aws:rds:us-east-1:{ACCT}:db:mydb"
FN_ARN = f"arn:aws:lambda:us-east-1:{ACCT}:function:fn"
LG_ARN = f"arn:aws:logs:us-east-1:{ACCT}:log-group:/aws/lambda/fn"
ALB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCT}:loadbalancer/app/payroll-alb/50dc6c495c0c9188"
NLB_ARN = f"arn:aws:elasticloadbalancing:us-east-1:{ACCT}:loadbalancer/net/edge-nlb/0123456789abcdef"
SNAP_ARN = f"arn:aws:ec2:us-east-1:{ACCT}:snapshot/snap-0123456789abcdef0"
S3_ARN = f"arn:aws:s3:::{BUCKET}"
DDB_ARN = f"arn:aws:dynamodb:us-east-1:{ACCT}:table/orders"
SG_ARN = f"arn:aws:ec2:us-east-1:{ACCT}:security-group/default"


@pytest.mark.parametrize("entry,rid,expected", [
    (VOL, VOL_ARN, True),                 # AWS-shaped bare id added, finding carries the ARN
    (VOL_ARN, VOL, True),                 # ARN added, finding carries the bare id
    (VOL_ARN, VOL_ARN, True),
    (VOL, VOL, True),
    (SNAP_ARN, "snap-0123456789abcdef0", True),
    ("snap-0123456789abcdef0", SNAP_ARN, True),
    (S3_ARN, BUCKET, True),
    (DDB_ARN, "orders", True),
    (DB_ARN, "mydb", True),               # detectors report an RDS instance by its bare name
    ("mydb", "mydb", True),
    ("mydb", DB_ARN, False),              # a bare non-AWS-shaped name matches only an identical id
    (FN_ARN, "fn", True),
    (LG_ARN, "/aws/lambda/fn", True),     # a log group is named by the whole group name
    (LG_ARN + ":*", "/aws/lambda/fn", True),
    (LG_ARN + ":*", LG_ARN, True),
    (ALB_ARN, "payroll-alb", True),       # the name, not the hash
    (NLB_ARN, "edge-nlb", True),
    (ALB_ARN, "50dc6c495c0c9188", False),
    (ALB_ARN, ALB_ARN.replace("50dc6c495c0c9188", "ffffffffffffffff"), True),   # same service and name
    ("default", SG_ARN, False),           # a plain name cannot hide a security-group ARN
    ("default", "default", True),
    (SG_ARN, "default", True),            # but an ARN entry that names it can
    (VOL, "vol-0abc123def4567891", False),
    ("vol-0abc123def456789", VOL_ARN, False),   # a prefix is not the id
    (VOL_ARN, VOL_ARN.replace(ACCT, "111122223333").replace(VOL, "vol-0aaaaaaaaaaaaaaaa"), False),
    (DB_ARN, FN_ARN.replace("fn", "mydb"), False),   # same name, different service
    ("", VOL, False),
])
def test_matching(entry, rid, expected):  # acceptance 3
    assert exclude.matches(entry, rid) is expected


def test_either_form_removes_the_finding_in_a_scan(monkeypatch, capsys):  # acceptance 3
    _run(["exclude", "add", VOL], capsys)
    assert VOL not in _scan(monkeypatch, capsys)
    _run(["exclude", "remove", VOL_ARN], capsys)   # removed by the other form
    assert VOL in _scan(monkeypatch, capsys)
    _run(["exclude", "add", VOL_ARN], capsys)
    assert VOL not in _scan(monkeypatch, capsys)


# --- acceptance 4: --no-exclude and the MCP scan -------------------------------------------------

def test_no_exclude_shows_everything_for_that_run_only(monkeypatch, capsys):  # acceptance 4
    _run(["exclude", "add", FS], capsys)
    full = _scan(monkeypatch, capsys, "--no-exclude")
    assert FS in full and "left out by your exclude list" not in full and "$55.00" in full
    assert FS not in _scan(monkeypatch, capsys)   # the list is untouched


def test_the_mcp_scan_honors_the_list():  # acceptance 4
    entries = [exclude.Entry(FS)]
    creds = Credentials("AKIATEST", "secret", None, ACCT, "eu-west-1")

    async def fake_scan(*a, **k):
        return _report()

    async def run():
        server = mcp_server.build_server()
        with patch.object(mcp_server, "resolve_credentials", return_value=creds), \
             patch.object(mcp_server, "resolve_regions", return_value=["eu-west-1"]), \
             patch.object(mcp_server, "run_scan_async", side_effect=fake_scan), \
             patch.object(exclude, "load", return_value=(entries, None)):
            async with Client(server) as client:
                scanned = await client.call_tool("scan", {})
                listed = await client.call_tool("list_findings", {})
        return ("\n".join(c.text for c in scanned.content), "\n".join(c.text for c in listed.content))

    text, listing = asyncio.run(run())
    assert "2 findings, estimated savings $45.00/month" in text
    assert "Left out on purpose: 1 finding left out by your exclude list (cloudcostwise exclude list)" in text
    assert FS not in listing and VOL in listing


# --- robustness ------------------------------------------------------------------------------

@pytest.mark.parametrize("content", ["{not json", "[]", '{"entries": 5}', '{"entries": [{"id": ""}]}'])
def test_a_corrupt_file_is_an_empty_list_with_a_warning_and_never_breaks_a_scan(monkeypatch, capsys, home, content):
    path = home / ".config" / "cloudcostwise" / "exclude.json"
    path.parent.mkdir(parents=True)
    path.write_text(content)
    out = _scan(monkeypatch, capsys)
    assert FS in out and "Left out on purpose" not in out
    code, _, err = _run(["exclude", "add", FS], capsys)
    assert code == 1 and path.read_text() == content   # never overwrites what it could not read
    assert "not changing it" in err.lower()


def test_a_corrupt_file_warns_on_stderr_during_a_scan(monkeypatch, capsys, home):
    path = home / ".config" / "cloudcostwise" / "exclude.json"
    path.parent.mkdir(parents=True)
    path.write_text("{oops")
    from cloudcostwise import runtime, scan

    monkeypatch.setattr(runtime, "configure_local_runtime", lambda: None)
    monkeypatch.setattr(runtime, "resolve_credentials", lambda p: runtime.Credentials("A", "s", None, ACCT, "eu-west-1"))
    monkeypatch.setattr(runtime, "resolve_regions", lambda r, c: ["eu-west-1"])
    monkeypatch.setattr(scan, "run_scan", lambda *a, **k: _report())
    monkeypatch.setattr("cloudcostwise.share.offer", lambda report: "skipped")
    assert cli.main(["scan", "--format", "json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["excluded_by_list_count"] == 0   # stdout stays clean JSON
    assert "warning" in captured.err and "empty" in captured.err


def test_a_missing_file_is_silent(monkeypatch, capsys):
    _scan(monkeypatch, capsys)
    assert capsys.readouterr().err == ""
    assert exclude.load() == ([], None)


def test_add_twice_keeps_one_entry_and_updates_the_reason(capsys):
    _run(["exclude", "add", FS, "--reason", "one"], capsys)
    _run(["exclude", "add", FS, "--reason", "two"], capsys)
    entries, _ = exclude.load()
    assert [(e.id, e.reason) for e in entries] == [(FS, "two")]
    assert "two" in _run(["exclude", "list"], capsys)[1]


def test_empty_list_message(capsys):
    code, out, _ = _run(["exclude", "list"], capsys)
    assert code == 0 and "empty" in out


def test_exclude_makes_no_network_call(monkeypatch, capsys):
    import urllib.request

    def boom(*a, **k):
        raise AssertionError("network")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert _run(["exclude", "add", FS], capsys)[0] == 0
    assert _run(["exclude", "list"], capsys)[0] == 0
    assert "network" not in "".join(_run(["exclude", "remove", FS], capsys)[1:])


# --- --anonymize: exclusion first, no excluded id leaks ---------------------------------------------

@pytest.mark.parametrize("fmt", ["table", "markdown", "json"])
def test_anonymize_never_leaks_an_excluded_id(monkeypatch, capsys, fmt):
    _run(["exclude", "add", FS], capsys)
    text = _scan(monkeypatch, capsys, "--format", fmt, "--anonymize")
    assert FS not in text and "0123456789abcdef0" not in text
    assert ACCT not in text
    if fmt == "json":
        data = json.loads(text)
        assert data["excluded_by_list_count"] == 1 and data["excluded_by_list_resource_ids"] == []
    else:
        assert "1 finding left out by your exclude list" in text


def test_anonymize_numbers_only_what_is_shown():
    shown = anonymize_report(exclude.apply(_report(), [exclude.Entry(FS)]))
    assert sorted(i.resource_id for i in shown.findings) == ["resource-1", "resource-2"]
    assert shown.excluded_count == 1 and shown.excluded_resource_ids == []


# --- the shared summary keeps its meaning --------------------------------------------------------------

def test_the_share_summary_describes_what_the_user_saw():
    reduced = exclude.apply(_report(), [exclude.Entry(FS)])
    payload = share.build_payload(reduced, "cli")
    assert payload["findings_count"] == 2 and payload["estimated_monthly_savings"] == 45.0
    assert set(payload) <= share.PAYLOAD_KEYS   # no excluded id, count or list rides along


def test_help_describes_the_commands(capsys):
    with pytest.raises(SystemExit):
        cli.main(["exclude", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "add" in out and "list" in out and "remove" in out and "never sent to CloudWise" in out
    with pytest.raises(SystemExit):
        cli.main(["scan", "--help"])
    assert "--no-exclude" in " ".join(capsys.readouterr().out.split())


# --- review fixes: a list problem never raises ----------------------------------------------------------

@pytest.mark.parametrize("raw", [b"\xff\xfe\x00bad", b"[" * 100000 + b"]" * 100000, b'{"entries": ' * 5000])
def test_load_never_raises_on_binary_or_deeply_nested_files(home, raw, capsys):
    path = home / ".config" / "cloudcostwise" / "exclude.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    entries, problem = exclude.load()
    assert entries == [] and problem
    assert "warning" in capsys.readouterr().err


def test_load_survives_a_directory_where_the_file_should_be(home):
    (home / ".config" / "cloudcostwise" / "exclude.json").mkdir(parents=True)
    assert exclude.load(warn=False)[0] == []


def test_apply_is_defensive(capsys):
    class Boom:
        id = "x"

        def strip(self):
            raise RuntimeError("boom")

    report = _report()
    bad = exclude.Entry(FS)
    bad.id = Boom()
    assert exclude.apply(report, [bad]) is report
    assert "showing every finding" in capsys.readouterr().err


def test_remove_reports_a_write_failure_like_add(monkeypatch, capsys):
    _run(["exclude", "add", FS], capsys)
    monkeypatch.setattr(exclude, "_save", lambda e: (_ for _ in ()).throw(OSError("read-only")))
    code, _, err = _run(["exclude", "remove", FS], capsys)
    assert code == 1 and "could not write" in err


def test_save_is_atomic_and_leaves_no_temp_file(home, capsys):
    _run(["exclude", "add", FS], capsys)
    names = sorted(p.name for p in (home / ".config" / "cloudcostwise").iterdir())
    assert names == ["exclude.json"]


# --- --anonymize scrubs excluded names from free text -------------------------------------------------

def _leaky_report():
    r = _report()
    r.findings.append(_item(BUCKET, 3.0, "f4"))
    r.warnings = [f"eu-west-1: could not read metrics for {BUCKET}"]
    return r


@pytest.mark.parametrize("fmt,extra", [("json", []), ("table", ["--verbose"]), ("markdown", ["--verbose"])])
def test_anonymize_scrubs_an_excluded_name_from_warnings(monkeypatch, capsys, fmt, extra):
    from cloudcostwise import runtime, scan

    _run(["exclude", "add", BUCKET], capsys)
    monkeypatch.setattr(runtime, "configure_local_runtime", lambda: None)
    monkeypatch.setattr(runtime, "resolve_credentials", lambda p: runtime.Credentials("A", "s", None, ACCT, "eu-west-1"))
    monkeypatch.setattr(runtime, "resolve_regions", lambda r, c: ["eu-west-1"])
    monkeypatch.setattr(scan, "run_scan", lambda *a, **k: _leaky_report())
    monkeypatch.setattr("cloudcostwise.share.offer", lambda report: "skipped")
    capsys.readouterr()
    assert cli.main(["scan", "--format", fmt, "--anonymize", *extra]) == 0
    text = capsys.readouterr().out
    assert BUCKET not in text and "orders-bucket" not in text
    if fmt == "json":
        assert json.loads(text)["warnings"] == ["eu-west-1: could not read metrics for resource-3"]
    elif fmt == "table":
        assert "could not read metrics for resource-3" in text


def test_verbose_lists_the_excluded_ids_but_never_under_anonymize():
    r = exclude.apply(_report(), [exclude.Entry(FS)])
    assert FS in render.as_table(r, verbose=True) and FS in render.as_markdown(r, verbose=True)
    assert FS not in render.as_table(r) and FS not in render.as_markdown(r)
    shown = anonymize_report(r)
    assert FS not in render.as_table(shown, verbose=True) and FS not in render.as_markdown(shown, verbose=True)
