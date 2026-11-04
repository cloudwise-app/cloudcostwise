"""CLO-824: the opt-in shared scan. Each hard constraint has a test that pins it."""

import asyncio
import io
import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cloudcostwise import cli, mcp_server, share
from cloudcostwise.scan import ScanReport

ACCOUNT = "123456789012"
TRUSTED = "backup_no_lifecycle_tiering"


def _item(rid, monthly):
    return SimpleNamespace(id=rid, waste_type=TRUSTED, resource_id=rid, monthly_savings=monthly,
                           region="eu-west-1", title=f"Backup vault {rid}", confidence="high",
                           action="delete it", description="d", action_command=None, explanation={})


REPORT = ScanReport(account_id=ACCOUNT, regions=["eu-west-1"], entrypoints=20, findings=[
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
    for k in (share.ENV_SHARE, 'CLOUDCOSTWISE_SHARE_EMAIL', 'CLOUDCOSTWISE_SHARE_NEW_CHECKS'):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


def _offer(env=None, answers="", stdin_tty=True, stdout_tty=True):
    sent = []
    err = io.StringIO()
    out = Tty(tty=stdout_tty)
    result = share.offer(REPORT, stdin=Tty(answers, stdin_tty), stdout=out, stderr=err, env=env or {},
                         sender=lambda p: sent.append(p) or True)
    assert out.getvalue() == ""  # nothing the prompt says ever lands on stdout
    return result, sent, err.getvalue()


# --- consent matrix: tty x env yes/no/unset ---------------------------------------------------

@pytest.mark.parametrize("tty", [True, False])
@pytest.mark.parametrize("env,answers,human_yes", [
    ({}, "y\n\n", True),                          # unset: asks, only a human typed y
    ({}, "n\n", False),                           # unset: asks, default no
    ({}, "\n", False),                            # unset: Enter is no
    ({share.ENV_SHARE: "no"}, "y\n", False),      # explicit no: never asks, never sends
    ({share.ENV_SHARE: "yes"}, "", True),         # explicit yes: sends without a prompt
])
def test_consent_matrix(env, answers, human_yes, tty):
    result, sent, err = _offer(env, answers, stdin_tty=tty, stdout_tty=tty)
    setting = env.get(share.ENV_SHARE)
    if setting == "yes":
        assert len(sent) == 1 and "Share this summary?" not in err
    elif setting == "no" or not tty:
        # explicit no, or no TTY and no setting: silent, nothing sent
        assert sent == [] and result == "skipped" and "Share this summary?" not in err
    else:
        assert "Share this summary?" in err and bool(sent) is human_yes


def test_one_tty_is_not_enough_to_prompt():
    for stdin_tty, stdout_tty in [(True, False), (False, True)]:
        result, sent, err = _offer({}, "y\n", stdin_tty, stdout_tty)
        assert (result, sent, err) == ("skipped", [], "")


def test_prompt_shows_payload_before_asking_and_is_default_no():
    result, sent, err = _offer({}, "\n")
    assert result == "declined" and sent == []
    assert err.index('"findings_count": 2') < err.index("Share this summary?")
    assert '"estimated_monthly_savings": 15.5' in err


def test_asks_at_most_once_per_machine_and_reset_asks_again():
    assert _offer({}, "n\n")[0] == "declined"
    assert _offer({}, "y\n")[0] == "skipped"       # remembered, even though a human is there
    assert share.config_path().exists()
    share.save_config({})                          # what `share --reset` does
    assert _offer({}, "n\n")[0] == "declined"


def test_a_yes_at_the_prompt_is_one_send_not_standing_consent():
    assert _offer({}, "y\n\n")[0] == "sent"
    assert _offer({}, "y\n")[0] == "skipped"


def test_config_file_yes_and_no_and_env_wins():
    share.save_config({"share": "yes"})
    assert _offer({}, "")[0] == "sent"
    assert _offer({share.ENV_SHARE: "no"}, "")[0] == "skipped"
    share.save_config({"share": "no"})
    assert _offer({}, "y\n")[0] == "skipped"
    assert _offer({share.ENV_SHARE: "yes"}, "", stdin_tty=False, stdout_tty=False)[0] == "sent"


def test_eof_and_interrupt_at_the_prompt_never_raise():
    class Gone(Tty):
        def readline(self):
            raise KeyboardInterrupt

    assert share.offer(REPORT, stdin=Gone(), stdout=Tty(), stderr=io.StringIO(), env={},
                       sender=lambda p: True) == "declined"
    share.save_config({})
    assert share.offer(REPORT, stdin=Tty(""), stdout=Tty(), stderr=io.StringIO(), env={},
                       sender=lambda p: True) == "declined"


# --- email requests: interactive prompt only ---------------------------------------------------

def test_email_with_no_opt_in_is_not_sent():
    result, sent, _ = _offer({}, "y\nme@example.com\nn\nn\n")
    assert result == "sent" and "email" not in sent[0]


def test_new_checks_opt_in_carries_the_wording_shown():
    result, sent, err = _offer({}, "y\nme@example.com\nn\ny\ny\n")
    p = sent[0]
    assert p["email"] == "me@example.com" and p["new_checks_updates"] is True and p["email_report"] is False
    assert p["new_checks_wording"] == share.NEW_CHECKS_WORDING and share.NEW_CHECKS_WORDING in err
    for needed in ("CloudWise (15331269 Canada Inc.)", "4165 Fieldgate Dr, Mississauga ON L4W 2M9, Canada",
                   "cloudwise@cloudcostwise.io", "withdraw consent at any time", "confirm by reply"):
        assert needed in share.NEW_CHECKS_WORDING


def test_email_report_request_uploads_no_report_and_says_so():
    result, sent, err = _offer({}, "y\nme@example.com\ny\nn\ny\n")
    p = sent[0]
    assert p["email_report"] is True and p["email_report_wording"] == share.EMAIL_REPORT_WORDING
    assert not [k for k in p if "report_markdown" in k or k.endswith("markdown")]
    assert "--format markdown" in err and "vol-mine-1" not in json.dumps(p) and ACCOUNT not in json.dumps(p)


def test_no_email_or_marketing_consent_can_come_from_env_config_or_mcp():
    env = {share.ENV_SHARE: "yes", "CLOUDCOSTWISE_SHARE_EMAIL": "me@example.com",
           "CLOUDCOSTWISE_SHARE_NEW_CHECKS": "yes", "CLOUDCOSTWISE_SHARE_EMAIL_REPORT": "yes"}
    share.save_config({"share": "yes", "email": "me@example.com", "new_checks": True, "email_report": True})
    calls = []
    share.share_from_settings_mcp(REPORT, env=env, sender=calls.append)
    _, sent, _ = _offer(env)
    assert calls and sent
    for p in calls + sent:
        assert set(p) == {"schema_version", "source", "cli_version", "findings_count",
                          "estimated_monthly_savings", "checks_run"}


def test_share_subcommand_has_no_email_flags():
    for flag in ("--email", "--new-checks", "--email-report"):
        with pytest.raises(SystemExit):
            cli._parser().parse_args(["share", "--on", flag, "x@example.com"])


def test_endpoint_url_is_the_api_host_not_the_site():
    assert share.SHARE_URL == "https://api.cloudcostwise.io/api/v1/shared-scans"



# --- the payload carries no identifiers -----------------------------------------------------

def test_payload_has_no_account_or_resource_identifiers():
    p = share.build_payload(REPORT, "cli")
    text = json.dumps(p)
    assert set(p) <= share.PAYLOAD_KEYS
    for needle in (ACCOUNT, "my-vault", "vol-mine-1", "eu-west-1", "arn:", "backup"):
        assert needle not in text
    assert p == {"schema_version": 1, "source": "cli", "cli_version": share.__version__,
                 "findings_count": 2, "estimated_monthly_savings": 15.5, "checks_run": 20}


def test_the_payload_shown_is_the_payload_sent():
    result, sent, err = _offer({}, "y\n\n")
    shown = json.loads(err[err.index("{"):err.index("}") + 1])
    assert shown == sent[0]


# --- network: failure and timeout never fail or slow the scan --------------------------------

def test_network_failure_returns_false_and_does_not_raise():
    with patch("cloudcostwise.share.urllib.request.urlopen", side_effect=OSError("down")):
        assert share.send({"a": 1}, url="https://example.invalid/x") is False


def test_timeout_is_bounded():
    with patch("cloudcostwise.share.urllib.request.urlopen", side_effect=lambda *a, **k: time.sleep(5)):
        t = time.monotonic()
        assert share.send({"a": 1}, url="https://example.invalid/x", timeout=0.2) is False
        assert time.monotonic() - t < 1.5
    assert share.TIMEOUT_SECONDS <= 3.0


def test_non_https_url_is_refused():
    with patch("cloudcostwise.share.urllib.request.urlopen") as u:
        assert share.send({}, url="http://example.com/x") is False
        u.assert_not_called()


def test_a_failed_or_crashing_send_does_not_fail_the_offer():
    err = io.StringIO()
    r = share.offer(REPORT, stdin=Tty(), stdout=Tty(), stderr=err, env={share.ENV_SHARE: "yes"},
                    sender=lambda p: False)
    assert r == "failed" and "may not have been received" in err.getvalue()
    assert "nothing was shared" not in err.getvalue()

    def boom(p):
        raise RuntimeError("x")

    assert share.offer(REPORT, stdin=Tty(), stdout=Tty(), stderr=err, env={share.ENV_SHARE: "yes"},
                       sender=boom) == "skipped"


def test_cli_scan_prints_before_sharing_and_returns_zero(capsys):
    seen = []
    with patch("cloudcostwise.runtime.resolve_credentials"), \
         patch("cloudcostwise.runtime.resolve_regions", return_value=["us-east-1"]), \
         patch("cloudcostwise.runtime.configure_local_runtime"), \
         patch("cloudcostwise.scan.run_scan", return_value=REPORT), \
         patch("cloudcostwise.share.offer", side_effect=lambda r: seen.append(capsys.readouterr().out)):
        assert cli.main(["scan", "--format", "json"]) == 0
    assert '"estimated_monthly_savings"' in seen[0]


# --- share subcommand ------------------------------------------------------------------------

def _run(argv, tty=True):
    out, err = Tty(tty=tty), io.StringIO()
    args = cli._parser().parse_args(["share", *argv])
    return share.command(args, stdin=Tty(tty=tty), stdout=out, stderr=err), out.getvalue(), err.getvalue()


def test_share_on_off_status_reset():
    assert "ask once" in _run(["--status"])[1]
    assert _run(["--on"])[0] == 0 and share.load_config()["share"] == "yes"
    assert "on (a summary" in _run(["--status"])[1]
    assert _run(["--off"])[0] == 0 and share.read_settings({}).share is False
    assert _run(["--reset"])[0] == 0 and share.load_config() == {}


def test_share_on_refuses_without_a_terminal():
    code, _, err = _run(["--on"], tty=False)
    assert code == 2 and "interactive terminal" in err and not share.config_path().exists()
    assert _run(["--off"], tty=False)[0] == 0   # turning it off needs no terminal


# --- MCP ---------------------------------------------------------------------------------------

def test_mcp_tools_have_no_share_like_parameter():
    server = mcp_server.build_server(share=True)
    tools = asyncio.run(server.list_tools())
    schemas = {t.name: t.input_schema if hasattr(t, "input_schema") else t.inputSchema for t in tools}
    assert set(schemas) == {"scan", "list_findings", "explain_finding", "fix_guidance"}
    banned = ("share", "send", "email", "consent", "telemetry", "report_to", "optin", "opt_in", "subscribe")
    for name, schema in schemas.items():
        for prop in schema.get("properties", {}):
            assert not any(b in prop.lower() for b in banned), (name, prop)


@pytest.mark.parametrize("env,expect", [({}, False), ({share.ENV_SHARE: "no"}, False),
                                        ({share.ENV_SHARE: "yes"}, True)])
def test_mcp_never_prompts_and_sends_only_on_a_yes_setting(env, expect):
    calls = []
    assert share.share_from_settings_mcp(REPORT, env=env, sender=lambda p: calls.append(p)) is expect
    assert bool(calls) is expect
    if calls:
        assert calls[0]["source"] == "mcp" and set(calls[0]) <= share.PAYLOAD_KEYS


def test_mcp_scan_shares_only_when_the_server_enables_it_and_a_setting_says_yes(monkeypatch):
    from mcp.client import Client
    from cloudcostwise.runtime import Credentials
    creds = Credentials("AKIATEST", "secret", None, ACCOUNT, "us-east-1")

    async def fake_scan(*a, **k):
        return REPORT

    async def run(enable):
        server = mcp_server.build_server(share=enable)
        with patch.object(mcp_server, "resolve_credentials", return_value=creds), \
             patch.object(mcp_server, "resolve_regions", return_value=["us-east-1"]), \
             patch.object(mcp_server, "run_scan_async", side_effect=fake_scan):
            async with Client(server) as c:
                await c.call_tool("scan", {})

    monkeypatch.setenv(share.ENV_SHARE, "yes")
    with patch.object(share, "send_in_background") as bg:
        asyncio.run(run(False))
        bg.assert_not_called()          # default build and the partner build: never
        asyncio.run(run(True))
        bg.assert_called_once()
    monkeypatch.delenv(share.ENV_SHARE)
    with patch.object(share, "send_in_background") as bg:
        asyncio.run(run(True))
        bg.assert_not_called()          # no setting: nothing sent


def test_no_unqualified_nothing_sent_claim_remains():
    # Relative to this test file, so it works in the monorepo package dir and in the exported tree
    # alike, and with a non-editable install (where the module's own path is in site-packages).
    root = Path(__file__).resolve().parents[1]
    for f in (root / "pyproject.toml", root / "README.md", Path(cli.__file__)):
        assert f.is_file(), f"{f} is missing: this check reads the shipped copy and must not skip"
        text = f.read_text()
        assert "no telemetry" not in text.lower(), f
        assert "Nothing is sent to CloudWise." not in text, f
