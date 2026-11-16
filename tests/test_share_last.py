"""CLO-1055: `cloudcostwise share --last`, the saved summary, the MCP share note, the hosted line kept
out of MCP output, and the test-server URL override. Each owner decision has a test that pins it."""

import asyncio
import io
import json
import os
import re
import stat
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cloudcostwise import cli, demo, mcp_server, render, share
from cloudcostwise.scan import ScanReport

ACCOUNT = "123456789012"
TRUSTED = "backup_no_lifecycle_tiering"


def _item(rid, monthly):
    return SimpleNamespace(id=rid, waste_type=TRUSTED, resource_id=rid, monthly_savings=monthly,
                           region="eu-west-1", title=f"Backup vault {rid}", confidence="high",
                           action="delete it", description="d", action_command="aws backup delete-x",
                           explanation={"risk": "low"})


def _report():
    return ScanReport(account_id=ACCOUNT, regions=["eu-west-1"], entrypoints=20, findings=[
        _item(f"arn:aws:backup:eu-west-1:{ACCOUNT}:backup-vault:my-vault", 10.0), _item("vol-mine-1", 5.5)])


class Tty(io.StringIO):
    def __init__(self, text="", tty=True):
        super().__init__(text)
        self._tty = tty

    def isatty(self):
        return self._tty


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    for k in (share.ENV_SHARE, share.ENV_SHARE_URL):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


def _saved():
    return json.loads(share.last_summary_path().read_text())


def _last(answers="", *, stdin_tty=True, stdout_tty=True, env=None, ok=True):
    sent = []
    out, err = Tty(tty=stdout_tty), io.StringIO()
    code = share.share_last(stdin=Tty(answers, stdin_tty), stdout=out, stderr=err, env=env or {},
                            sender=lambda p: sent.append(p) or ok)
    return code, sent, out.getvalue(), err.getvalue()


def _cli_scan(*argv, report=None):
    with patch("cloudcostwise.runtime.resolve_credentials"), \
         patch("cloudcostwise.runtime.resolve_regions", return_value=["us-east-1"]), \
         patch("cloudcostwise.runtime.configure_local_runtime"), \
         patch("cloudcostwise.scan.run_scan", return_value=report or _report()):
        return cli.main(["scan", *argv])


# --- the saved summary --------------------------------------------------------------------------

def test_a_cli_scan_saves_only_the_summary_fields_privately_and_atomically(capsys):
    assert _cli_scan("--format", "json") == 0
    path = share.last_summary_path()
    assert path.parent == share.config_path().parent and path.name == "last-summary.json"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    data = _saved()
    assert set(data) == set(share.SUMMARY_KEYS) | {"saved_at", "send_attempted_at", "sent_ok"}
    assert share.summary_payload(data) == share.build_payload(_report(), "cli")
    assert data["source"] == "cli" and data["send_attempted_at"] is None
    text = path.read_text()
    for needle in (ACCOUNT, "my-vault", "vol-mine-1", "eu-west-1", "arn:", "backup"):
        assert needle not in text
    assert not [p for p in path.parent.iterdir() if p.name.endswith(".tmp")]  # no temp file left behind


def test_anonymize_does_not_change_the_saved_summary_and_the_exclude_list_does_as_the_payload_does(capsys):
    _cli_scan("--format", "json")
    plain = share.summary_payload(_saved())
    _cli_scan("--format", "json", "--anonymize")
    assert share.summary_payload(_saved()) == plain
    assert cli.main(["exclude", "add", "vol-mine-1"]) == 0
    _cli_scan("--format", "json")
    excluded = share.summary_payload(_saved())
    assert excluded["findings_count"] == 1 and excluded["estimated_monthly_savings"] == 10.0


def test_a_summary_that_cannot_be_written_never_fails_the_scan(capsys):
    with patch.object(share, "_write_private", side_effect=OSError("read-only disk")):
        assert _cli_scan("--format", "json") == 0
    assert not share.last_summary_path().exists()


def test_a_demo_scan_never_writes_a_summary_and_can_never_be_shared(capsys):
    assert cli.main(["scan", "--demo", "--format", "json"]) == 0
    assert not share.last_summary_path().exists()
    assert share.save_last_summary(demo.load_report(), "cli") is None
    assert not share.last_summary_path().exists()
    code, sent, out, _ = _last("y\n\n")
    assert code == 1 and sent == [] and out.strip() == share.LAST_NO_SUMMARY.format(path=share.last_summary_path())


def test_a_demo_scan_after_a_real_one_leaves_the_real_summary_alone(capsys):
    _cli_scan("--format", "json")
    before = _saved()
    cli.main(["scan", "--demo", "--format", "json"])
    assert _saved() == before


@pytest.mark.parametrize("change", [
    {"email": "me@example.com"},                       # an extra key is never carried along
    {"source": "web"}, {"schema_version": 2}, {"findings_count": "2"}, {"findings_count": True},
    {"estimated_monthly_savings": -1}, {"estimated_monthly_savings": float("inf")},
    {"checks_run": 501}, {"cli_version": "1.0 <script>"}, {"saved_at": "yesterday"},
])
def test_a_file_that_is_not_what_a_scan_writes_is_never_sent(change, capsys):
    _cli_scan("--format", "json")
    data = {**_saved(), **change}
    share.last_summary_path().write_text(json.dumps(data))
    assert share.load_last_summary() is None
    code, sent, out, _ = _last("y\n\n")
    assert sent == [] and "is not one a scan wrote" in out and "No scan summary saved yet" not in out
    assert "is not a summary a scan wrote" in share.status_text()


# --- share --last -------------------------------------------------------------------------------

@pytest.mark.parametrize("stdin_tty,stdout_tty", [(False, False), (True, False), (False, True)])
def test_share_last_refuses_without_a_terminal_whatever_the_setting(stdin_tty, stdout_tty, capsys):
    _cli_scan("--format", "json")
    for env in ({}, {share.ENV_SHARE: "yes"}):
        code, sent, out, err = _last("y\n\n", stdin_tty=stdin_tty, stdout_tty=stdout_tty, env=env)
        assert code == 2 and sent == [] and out == ""
        assert err.strip() == share.LAST_NO_TERMINAL
    assert _saved()["send_attempted_at"] is None
    # The refusal does not explain how to get around it.
    for hint in (share.ENV_SHARE, "share.json", "--yes", "--on", "script", "pty", "expect"):
        assert hint not in share.LAST_NO_TERMINAL


def test_share_last_has_no_flag_that_answers_for_the_human():
    for argv in (["share", "--last", "--yes"], ["share", "--last", "-y"], ["share", "--last", "--force"],
                 ["share", "--last", "--no-prompt"], ["share", "--last", "--on"]):
        with pytest.raises(SystemExit):
            cli._parser().parse_args(argv)
    sub = next(a for a in cli._parser()._actions if getattr(a, "choices", None) and "share" in a.choices)
    flags = {o for a in sub.choices["share"]._actions for o in a.option_strings}
    assert flags == {"-h", "--help", "--on", "--off", "--status", "--reset", "--last"}


def test_share_last_shows_exactly_what_is_sent_then_sends_on_y(capsys):
    _cli_scan("--format", "json")
    record = _saved()
    code, sent, out, err = _last("y\n\n")
    assert code == 0 and len(sent) == 1
    expected = share.LAST_PROMPT.format(where="the CLI", when=share._local_minutes(record["saved_at"]),
                                        payload=json.dumps(share.summary_payload(record), indent=2))
    assert out.startswith(expected)
    shown = json.loads(out[out.index("{"):out.index("}") + 1])
    assert shown == sent[0] == share.build_payload(_report(), "cli")   # unchanged shape, no saved_at
    assert "saved_at" not in out and "send_attempted_at" not in out and "sent_ok" not in out
    assert out.rstrip().endswith(share.LAST_SENT) and err == ""
    assert re.search(r"\(from the CLI, \d{4}-\d\d-\d\d \d\d:\d\d\)", out)
    assert _saved()["sent_ok"] is True


@pytest.mark.parametrize("answers", ["n\n", "\n", "", "yes please\n", "Y es\n"])
def test_share_last_sends_nothing_unless_the_answer_is_y(answers, capsys):
    _cli_scan("--format", "json")
    code, sent, out, _ = _last(answers)
    assert code == 0 and sent == [] and out.rstrip().endswith(share.LAST_DECLINED)
    assert _saved()["send_attempted_at"] is None


def test_share_last_cannot_send_the_same_summary_twice(capsys):
    _cli_scan("--format", "json")
    assert _last("y\n\n")[1]
    code, sent, out, _ = _last("y\n\n")
    assert (code, sent, out.strip()) == (0, [], share.LAST_ALREADY_SHARED)
    _cli_scan("--format", "json")          # a new scan is a new summary
    assert _last("y\n\n")[1]


def test_share_last_runs_the_same_email_flow(capsys):
    _cli_scan("--format", "json")
    code, sent, out, _ = _last("y\nme@example.com\nn\ny\ny\n")
    p = sent[0]
    assert p["email"] == "me@example.com" and p["new_checks_updates"] is True and p["email_report"] is False
    assert p["new_checks_wording"] == share.NEW_CHECKS_WORDING and share.NEW_CHECKS_WORDING in out
    assert "Final payload:" in out


def test_share_last_declined_at_the_final_confirmation_sends_nothing_and_stays_unshared(capsys):
    _cli_scan("--format", "json")
    code, sent, out, _ = _last("y\nme@example.com\ny\nn\nn\n")
    assert sent == [] and out.rstrip().endswith(share.LAST_DECLINED)
    assert _saved()["send_attempted_at"] is None


def test_share_last_with_no_summary_says_where_it_would_be(capsys):
    code, sent, out, _ = _last("y\n")
    assert code == 1 and sent == []
    assert out.strip() == share.LAST_NO_SUMMARY.format(path=share.last_summary_path())
    assert str(share.last_summary_path()).endswith(os.path.join(".config", "cloudcostwise", "last-summary.json"))


def test_share_last_that_cannot_mark_the_summary_sends_nothing(capsys):
    _cli_scan("--format", "json")
    with patch.object(share, "_write_private", side_effect=OSError("disk full")):
        code, sent, _, err = _last("y\n\n")
    assert code == 1 and sent == [] and "nothing was sent" in err


def test_share_last_failed_send_says_so_and_is_not_sent_again(capsys):
    _cli_scan("--format", "json")
    code, sent, out, _ = _last("y\n\n", ok=False)
    assert code == 1 and len(sent) == 1 and out.rstrip().endswith(share.NOT_CONFIRMED)
    assert "The scan is unaffected" not in out and "Shared" not in out
    assert _saved()["send_attempted_at"] is not None and _saved()["sent_ok"] is False
    code, sent, out, _ = _last("y\n\n")
    assert (code, sent, out.strip()) == (0, [], share.LAST_ALREADY_TRIED)        # no retry, honestly said
    assert "attempted, and CloudWise did not confirm" in share.status_text()


def test_two_terminals_with_the_same_summary_send_it_once(capsys):
    """B1: mark_attempt refuses a record whose send was already attempted, even when the caller still
    holds the stale, unattempted copy it read before the other terminal marked it."""
    _cli_scan("--format", "json")
    stale = share.load_last_summary()
    assert share.mark_attempt(stale) == share.MARKED
    assert share.mark_attempt(stale) == share.ALREADY_TRIED
    # share_last at its prompt, while the other terminal sends: it read the summary before the mark.
    real, calls = share.load_last_summary, []

    def first_stale():
        calls.append(1)
        return stale if len(calls) == 1 else real()

    with patch.object(share, "load_last_summary", side_effect=first_stale):
        code, sent, out, _ = _last("y\n\n")
    assert len(calls) >= 2                                      # mark_attempt re-read the file
    assert sent == [] and code == 0 and out.rstrip().endswith(share.LAST_ALREADY_TRIED)


def _offer(answers, env, sent, ok=True, tty=True):
    err = io.StringIO()
    result = share.offer(_report(), stdin=Tty(answers, tty), stdout=Tty(tty=tty), stderr=err, env=env,
                         sender=lambda p: sent.append(p) or ok)
    return result, err.getvalue()


@pytest.mark.parametrize("ok", [True, False])
def test_share_last_then_the_after_scan_prompt_sends_the_summary_once(ok, capsys):
    """Terminal A waits at the after-scan prompt; terminal B runs `share --last` and sends; then A
    types y. A must not send the same summary again (the server does not dedupe)."""
    _cli_scan("--format", "json")
    code, sent, _, _ = _last("y\n\n", ok=ok)
    assert len(sent) == 1
    result, err = _offer("y\n\n", {}, sent)
    assert result == "already" and len(sent) == 1
    assert err.rstrip().endswith(share.LAST_ALREADY_SHARED if ok else share.LAST_ALREADY_TRIED)
    assert share.SENT_UNSURE not in err and "Shared. Thank you." not in err


@pytest.mark.parametrize("ok", [True, False])
def test_share_last_then_a_yes_setting_sends_the_summary_once(ok, capsys):
    _cli_scan("--format", "json")
    sent = []
    sent_last = _last("y\n\n", ok=ok)[1]
    result, err = _offer("", {share.ENV_SHARE: "yes"}, sent, tty=False)
    assert len(sent_last) == 1 and sent == [] and result == "already"
    assert err.strip() == (share.LAST_ALREADY_SHARED if ok else share.LAST_ALREADY_TRIED)
    # The MCP path too, for a summary an MCP scan saved: nothing sent, and nothing claimed.
    assert share.save_last_summary(_report(), "mcp")
    assert _last("y\n\n", ok=ok)[1]
    assert share.share_from_settings_mcp(_report(), env={share.ENV_SHARE: "yes"},
                                         sender=lambda p: sent.append(p) or True) == "already"
    assert sent == []


def test_the_prompt_then_share_last_sends_the_summary_once(capsys):
    _cli_scan("--format", "json")
    sent = []
    assert _offer("y\n\n", {}, sent)[0] == "sent"
    code, more, out, _ = _last("y\n\n")
    assert len(sent) == 1 and more == [] and out.strip() == share.LAST_ALREADY_SHARED


class _ReadOnlyConfig:
    """The config directory made read-only, as the reviewer did: the attempt cannot be recorded."""

    def __enter__(self):
        self.dir = share.last_summary_path().parent
        os.chmod(self.dir, 0o500)
        return self

    def __exit__(self, *exc):
        os.chmod(self.dir, 0o700)
        return False


def test_an_attempt_that_cannot_be_recorded_sends_nothing_on_every_automatic_path(capsys, monkeypatch):
    """Item 1: scan saves, the directory turns read-only, the automatic send must not go unmarked, or
    `share --last` later sends the same summary a second time."""
    for path in ("prompt", "cli_setting", "mcp_setting"):
        saved_at = share.save_last_summary(_report(), "mcp" if path == "mcp_setting" else "cli")
        assert saved_at
        sent = []
        with _ReadOnlyConfig():
            if path == "prompt":
                result, err = _offer("y\n\n", {}, sent)
            elif path == "cli_setting":
                result, err = _offer("", {share.ENV_SHARE: "yes"}, sent, tty=False)
            else:
                result = share.share_from_settings_mcp(_report(), env={share.ENV_SHARE: "yes"},
                                                       sender=lambda p: sent.append(p) or True, saved_at=saved_at)
                err = ""
        assert sent == [], path
        assert result == "not_marked", path
        if path != "mcp_setting":
            assert err.rstrip().endswith(share.LAST_NOT_MARKED.format(path=share.last_summary_path())), path
            assert "Shared" not in err and share.SENT_UNSURE not in err
        # Writable again: the summary is still unattempted, and `share --last` sends it exactly once.
        code, once, _, _ = _last("y\n\n")
        assert code == 0 and len(once) == 1, path
        assert _last("y\n\n")[1] == [], path


def test_mcp_scan_with_an_unrecordable_attempt_claims_no_send(monkeypatch):
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    real_save = share.save_last_summary

    def save_then_lock(report, source):
        saved = real_save(report, source)
        os.chmod(share.last_summary_path().parent, 0o500)
        return saved

    try:
        with patch.object(share, "send", return_value=True) as s, \
                patch.object(share, "save_last_summary", side_effect=save_then_lock):
            [text] = _mcp([_scan])
    finally:
        os.chmod(share.last_summary_path().parent, 0o700)
    s.assert_not_called()
    assert "was sent" not in text and share.MCP_SEND_UNCONFIRMED not in text
    assert share.MCP_NOT_SENT_NOTE not in text   # the setting is on: that note is only for "not on"


def test_an_automatic_send_of_a_scan_with_no_saved_copy_still_goes(capsys):
    sent = []
    assert not share.last_summary_path().exists()
    assert _offer("", {share.ENV_SHARE: "yes"}, sent, tty=False)[0] == "sent" and len(sent) == 1
    assert share.offer(_report(), stdin=Tty(tty=False), stdout=Tty(tty=False), stderr=io.StringIO(),
                       env={share.ENV_SHARE: "yes"}, sender=lambda p: sent.append(p) or True,
                       saved_at=None) == "sent"            # the scan's save failed: nothing to mark
    assert len(sent) == 2


@pytest.mark.parametrize("path", ["cli_setting", "mcp_setting"])
def test_a_later_scan_with_the_same_numbers_is_not_marked_by_the_earlier_send(path, capsys):
    """Item 2: scan A's automatic send runs after scan B (same numbers) replaced the file. A is sent
    without a mark (no file holds it any more); B stays unattempted, and `share --last` sends B."""
    source = "mcp" if path == "mcp_setting" else "cli"
    saved_a = share.save_last_summary(_report(), source)
    saved_b = share.save_last_summary(_report(), source)
    assert saved_a and saved_b and saved_a != saved_b
    sent = []
    if path == "cli_setting":
        result = share.offer(_report(), stdin=Tty(tty=False), stdout=Tty(tty=False), stderr=io.StringIO(),
                             env={share.ENV_SHARE: "yes"}, sender=lambda p: sent.append(p) or True,
                             saved_at=saved_a)
    else:
        result = share.share_from_settings_mcp(_report(), env={share.ENV_SHARE: "yes"},
                                               sender=lambda p: sent.append(p) or True, saved_at=saved_a)
    assert result == "sent" and len(sent) == 1
    assert _saved()["saved_at"] == saved_b and _saved()["send_attempted_at"] is None
    code, more, out, _ = _last("y\n\n")
    assert code == 0 and len(more) == 1 and share.LAST_ALREADY_TRIED not in out


def test_the_cli_passes_this_scans_saved_at_to_the_offer(capsys):
    seen = {}
    with patch.object(share, "offer", side_effect=lambda r, **k: seen.update(k)):
        _cli_scan("--format", "json")
    assert seen["saved_at"] == _saved()["saved_at"]


def test_share_last_on_a_file_a_scan_did_not_write_says_so(capsys):
    share.last_summary_path().parent.mkdir(parents=True, exist_ok=True)
    share.last_summary_path().write_text(json.dumps({"schema_version": 1, "findings": 3, "shared_at": None}))
    code, sent, out, _ = _last("y\n\n")
    assert code == 1 and sent == []
    assert out.strip() == share.LAST_UNUSABLE.format(path=share.last_summary_path())
    assert "No scan summary saved yet" not in out


def test_send_in_background_is_gone():
    assert not hasattr(share, "send_in_background")

def test_mcp_scan_after_share_last_got_in_first_says_nothing_about_a_send(monkeypatch):
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    real_send_marked = share._send_marked

    def share_last_wins(payload, sender):
        assert _last("y\n\n")[1]                          # another terminal marks and sends first
        return real_send_marked(payload, sender)

    with patch.object(share, "send", return_value=True) as s, \
            patch.object(share, "_send_marked", side_effect=share_last_wins):
        [text] = _mcp([_scan])
    s.assert_not_called()
    assert "was sent" not in text and share.MCP_SEND_UNCONFIRMED not in text


def test_a_redirect_is_a_failed_send_and_is_not_followed():
    import http.server
    import threading

    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.path)
            if self.path == "/api/v1/shared-scans":
                self.send_response(302)
                self.send_header("Location", "/elsewhere")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()

        do_GET = do_POST

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/api/v1/shared-scans"
        assert share.send({"a": 1}, url=url) is False
        assert hits == ["/api/v1/shared-scans"]                 # the redirect target was never requested
        ok_url = f"http://127.0.0.1:{srv.server_port}/elsewhere"
        assert share.send({"a": 1}, url=ok_url) is True          # a plain 200 still counts
    finally:
        srv.shutdown()


def test_a_summary_sent_by_a_setting_is_marked_shared(capsys):
    _cli_scan("--format", "json")
    sent = []
    assert share.offer(_report(), stdin=Tty(tty=False), stdout=Tty(tty=False), stderr=io.StringIO(),
                       env={share.ENV_SHARE: "yes"}, sender=lambda p: sent.append(p) or True) == "sent"
    assert len(sent) == 1 and _saved()["sent_ok"] is True
    assert _last("y\n\n")[2].strip() == share.LAST_ALREADY_SHARED


def test_a_summary_sent_from_the_after_scan_prompt_is_marked_shared(capsys):
    _cli_scan("--format", "json")
    assert share.offer(_report(), stdin=Tty("y\n\n"), stdout=Tty(), stderr=io.StringIO(), env={},
                       sender=lambda p: True) == "sent"
    assert _saved()["sent_ok"] is True


def test_the_cli_command_routes_share_last(capsys):
    _cli_scan("--format", "json")
    args = cli._parser().parse_args(["share", "--last"])
    out, err = Tty(), io.StringIO()
    with patch.object(share, "send", return_value=True) as s:
        assert share.command(args, stdin=Tty("y\n\n"), stdout=out, stderr=err) == 0
    s.assert_called_once()
    assert s.call_args.kwargs["url"] == share.SHARE_URL


# --- share --off and --status -------------------------------------------------------------------

def test_share_off_deletes_the_saved_summary_and_status_reports_it(capsys):
    def status():
        out = Tty()
        share.command(cli._parser().parse_args(["share", "--status"]), stdin=Tty(), stdout=out,
                      stderr=io.StringIO())
        return out.getvalue()

    assert "Saved summary: none" in status()
    _cli_scan("--format", "json")
    assert "from the CLI" in status() and "not shared" in status()
    _last("y\n\n")
    assert status().rstrip().endswith(": shared")
    _cli_scan("--format", "json")
    out = Tty()
    assert share.command(cli._parser().parse_args(["share", "--off"]), stdin=Tty(tty=False), stdout=out,
                         stderr=io.StringIO()) == 0
    assert not share.last_summary_path().exists() and "Saved summary: none" in out.getvalue()
    # Off does not stop scans from saving a new one; only `share --last` and a typed y can send it.
    _cli_scan("--format", "json")
    assert share.last_summary_path().exists()
    assert _last("y\n\n")[1]


def test_status_says_the_source_is_sent():
    assert "whether the scan ran in the CLI or MCP" in share.status_text()


# --- CLOUDCOSTWISE_SHARE_URL ---------------------------------------------------------------------

@pytest.mark.parametrize("url,ok", [
    ("https://api.cloudcostwise.io/api/v1/shared-scans", True),
    ("http://localhost:8000/api/v1/shared-scans", True),
    ("https://localhost/api/v1/shared-scans", True),
    ("http://127.0.0.1:8000/api/v1/shared-scans", True),
    ("https://api-staging.cloudcostwise.io/api/v1/shared-scans", True),
    ("https://api-staging.cloudcostwise.io:443/api/v1/shared-scans", True),
    ("http://api-staging.cloudcostwise.io/api/v1/shared-scans", False),
    ("https://api-staging.cloudcostwise.io:8443/x", False),
    ("https://api-staging.cloudcostwise.io.evil.com/x", False),
    ("https://evil.com/api-staging.cloudcostwise.io", False),
    ("http://localhost.evil.com/x", False),
    ("http://localhost@evil.com/x", False),
    ("http://user:pw@localhost/x", False),
    ("http://evil.com\\@localhost/x", False),
    ("http://127.0.0.2/x", False),
    ("http://[::1]/x", False),
    ("https://staging.cloudcostwise.io/api/v1/shared-scans", False),
    ("https://api.cloudcostwise.io/other", False),
    ("ftp://localhost/x", False),
    ("http://localhost:99999/x", False),
    ("http://localhost /x", False),
    ("", False),
])
def test_url_override_allowlist(url, ok):
    assert share.url_allowed(url) is ok
    if url and url != share.SHARE_URL:
        if ok:
            assert share.share_url({share.ENV_SHARE_URL: url}) == url
        else:
            with pytest.raises(share.ShareUrlRefused):
                share.share_url({share.ENV_SHARE_URL: url})


def test_send_refuses_a_disallowed_url_without_a_request():
    with patch("cloudcostwise.share._open") as u:
        for url in ("http://localhost.evil.com/x", "http://localhost@evil.com/x", "https://example.com/x"):
            assert share.send({}, url=url) is False
        u.assert_not_called()


def test_the_override_redirects_every_send_path(capsys, monkeypatch):
    target = "http://127.0.0.1:8765/api/v1/shared-scans"
    _cli_scan("--format", "json")
    with patch.object(share, "send", return_value=True) as s:
        assert share.share_last(stdin=Tty("y\n\n"), stdout=Tty(), stderr=io.StringIO(),
                                env={share.ENV_SHARE_URL: target}) == 0
        share.delete_last_summary()  # that summary is spent; the automatic paths below send without a copy
        assert share.offer(_report(), stdin=Tty(tty=False), stdout=Tty(tty=False), stderr=io.StringIO(),
                           env={share.ENV_SHARE: "yes", share.ENV_SHARE_URL: target}) == "sent"
        assert share.share_from_settings_mcp(_report(), env={share.ENV_SHARE: "yes",
                                                             share.ENV_SHARE_URL: target}) == "sent"
    assert [c.kwargs["url"] for c in s.call_args_list] == [target] * 3
    assert all(set(c.args[0]) == set(share.SUMMARY_KEYS) for c in s.call_args_list)  # no field added


def test_a_refused_override_sends_nothing_on_every_path_and_says_so(capsys):
    bad = {share.ENV_SHARE_URL: "https://evil.example/api/v1/shared-scans"}
    _cli_scan("--format", "json")
    with patch.object(share, "send", return_value=True) as s:
        code, sent, out, err = _last("y\n\n", env=bad)
        assert code == 1 and sent == [] and err.strip() == share.URL_REFUSED and out == ""
        err2 = io.StringIO()
        assert share.offer(_report(), stdin=Tty(tty=False), stdout=Tty(tty=False), stderr=err2,
                           env={share.ENV_SHARE: "yes", **bad}) == "skipped"
        assert share.URL_REFUSED in err2.getvalue()
        assert share.offer(_report(), stdin=Tty("y\n\n"), stdout=Tty(), stderr=io.StringIO(),
                           env=bad) == "skipped"
        assert share.share_from_settings_mcp(_report(), env={share.ENV_SHARE: "yes", **bad}) == "refused"
    s.assert_not_called()
    assert _saved()["send_attempted_at"] is None and not share.config_path().exists()  # not even "asked"


# --- MCP -----------------------------------------------------------------------------------------

def _text(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "text", None))


def _mcp(steps, *, share_on=True, upsell=True):
    from mcp.client import Client
    from cloudcostwise.runtime import Credentials
    creds = Credentials("AKIATEST", "secret", None, ACCOUNT, "us-east-1")

    async def fake_scan(*a, **k):
        return _report()

    async def go():
        server = mcp_server.build_server(share=share_on, upsell=upsell)
        with patch.object(mcp_server, "resolve_credentials", return_value=creds), \
             patch.object(mcp_server, "resolve_regions", return_value=["us-east-1"]), \
             patch.object(mcp_server, "run_scan_async", side_effect=fake_scan):
            async with Client(server) as c:
                return [_text(await step(c)) for step in steps]

    return asyncio.run(go())


def _scan(c, **kw):
    return c.call_tool("scan", kw)


@pytest.mark.parametrize("setting", [None, "no"])
def test_mcp_note_once_per_session_when_the_setting_is_not_on(setting, monkeypatch):
    if setting:
        monkeypatch.setenv(share.ENV_SHARE, setting)
    with patch.object(share, "send") as s:
        first, second = _mcp([_scan, _scan])
    s.assert_not_called()
    assert share.MCP_NOT_SENT_NOTE in first and share.MCP_NOT_SENT_NOTE not in second
    assert share.MCP_SENT_NOTE not in first + second
    data = _saved()
    assert data["source"] == "mcp" and data["send_attempted_at"] is None
    # A new server session says it once more.
    assert share.MCP_NOT_SENT_NOTE in _mcp([_scan])[0]


def test_mcp_note_text_is_the_owner_wording():
    assert share.MCP_NOT_SENT_NOTE == (
        "Nothing from this scan has been sent to CloudWise. If you want to share its summary, run "
        "`cloudcostwise share --last` in your own terminal: it shows exactly what would be sent (CLI version, "
        "number of findings, estimated monthly savings, checks run, and that it came from MCP) and sends "
        "nothing unless you type y.")
    assert share.MCP_SENT_NOTE == (
        "A summary of this scan was sent to CloudWise because CLOUDCOSTWISE_SHARE (or share.json) is set to "
        "yes: CLI version, number of findings, estimated monthly savings, checks run, source mcp. "
        "`cloudcostwise share --off` stops it.")


def test_mcp_says_sent_only_after_the_send_was_made(monkeypatch):
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    with patch.object(share, "send", return_value=True) as s:
        first, second = _mcp([_scan, _scan])
    assert s.call_count == 2
    for text in (first, second):          # every scan that sends says so, not once per session
        assert share.MCP_SENT_NOTE in text and share.MCP_SEND_UNCONFIRMED not in text
        assert share.MCP_NOT_SENT_NOTE not in text
    assert _saved()["sent_ok"] is True          # `share --last` will not send it again
    with patch.object(share, "send", return_value=False):
        [text] = _mcp([_scan])
    assert share.MCP_SEND_UNCONFIRMED in text and "was sent" not in text


def test_mcp_with_a_refused_override_says_nothing_was_sent(monkeypatch):
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    monkeypatch.setenv(share.ENV_SHARE_URL, "https://evil.example/x")
    with patch.object(share, "send") as s:
        [text] = _mcp([_scan])
    s.assert_not_called()
    assert "was sent to CloudWise" not in text and "so nothing was sent" in text


def test_mcp_build_without_sharing_saves_nothing_and_says_nothing(monkeypatch):
    """The partner build (share=False): no summary on disk, so the free CLI's `share --last` has nothing
    from it to send, and no note."""
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    with patch.object(share, "send") as s:
        [text] = _mcp([_scan], share_on=False, upsell=False)
    s.assert_not_called()
    assert not share.last_summary_path().exists()
    assert "share --last" not in text and "sent to CloudWise" not in text


def test_mcp_demo_scan_saves_nothing_and_shows_no_share_note(monkeypatch):
    for setting in (None, "yes"):
        if setting:
            monkeypatch.setenv(share.ENV_SHARE, setting)
        with patch.object(share, "send") as s:
            [text] = _mcp([lambda c: c.call_tool("scan", {"demo": True})])
        s.assert_not_called()
        assert not share.last_summary_path().exists()
        assert "share --last" not in text and "sent to CloudWise" not in text


def test_hosted_line_is_absent_from_mcp_output_and_present_in_the_cli(capsys):
    async def listing(c):
        return await c.call_tool("list_findings", {})

    async def explain(c):
        return await c.call_tool("explain_finding", {"finding_id": "vol-mine-1"})

    async def fix(c):
        return await c.call_tool("fix_guidance", {"finding_id": "vol-mine-1"})

    async def fix_first(c):
        await c.call_tool("scan", {})
        return await c.call_tool("fix_guidance", {"finding_id": "vol-mine-1"})

    texts = _mcp([_scan, listing, explain, fix]) + _mcp([fix_first]) + _mcp([fix_first], share_on=False)
    for text in texts:
        assert render.HOSTED_URL not in text and "cloudcostwise.io/connect" not in text
        assert "hosted product" not in text and "safe fixes" not in text.lower()
        assert "history, alerts" not in text
    # The plain local-check count and the feedback note stay, once.
    assert "20 of 46 service checks run locally." in texts[0] and render.FEEDBACK_NOTE in texts[0]
    # The terminal CLI keeps the hosted line.
    _cli_scan()
    table = capsys.readouterr().out
    assert render.HOSTED_URL in table and "history, alerts and safe fixes" in table


def test_mcp_tool_list_and_instructions_do_not_push_sharing():
    server = mcp_server.build_server(share=True)
    tools = asyncio.run(server.list_tools())
    assert sorted(t.name for t in tools) == ["explain_finding", "fix_guidance", "list_findings", "scan"]
    for text in [mcp_server.INSTRUCTIONS, *(t.description or "" for t in tools)]:
        assert "share --last" not in text
        assert not re.search(r"encourage|ask the user to share|offer to share|remind|please share", text, re.I)
    # At most one factual sentence about sharing in INSTRUCTIONS.
    sentences = [s for s in re.split(r"(?<=\.)\s+", mcp_server.INSTRUCTIONS) if re.search(r"shar|send", s, re.I)]
    assert sentences == ["This server never sends a scan or its summary to CloudWise unless the user's own "
                         "setting says so."]
    # It does not name the setting either: that would tell an assistant with a shell how to switch it on.
    assert share.ENV_SHARE not in mcp_server.INSTRUCTIONS and "share.json" not in mcp_server.INSTRUCTIONS
