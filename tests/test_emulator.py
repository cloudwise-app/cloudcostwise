"""CLO-1116: `scan --emulator`, a live scan of a fake account in AWS Emulator. None of these tests needs Docker,
an emulator, AWS credentials or a network: Docker, STS and the scan are mocked or stubbed."""

import asyncio
import dataclasses
import json
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock

import boto3
import pytest
from mcp.client import Client

from cloudcostwise import cli, demo, emulator_demo as em, mcp_server, share

PORT = 9397


@pytest.fixture(autouse=True)
def emulator_home(tmp_path_factory, monkeypatch):
    """A fake HOME holding the files the emulator would write, and a hostile environment around it."""
    home = tmp_path_factory.mktemp("emhome")
    monkeypatch.setenv("HOME", str(home))
    d = home / ".aws" / "emulator" / str(PORT)
    d.mkdir(parents=True)
    (d / "emulator_credentials").write_text("[default]\naws_access_key_id = EMULATORTEST\naws_secret_access_key = emu-secret\n")
    (d / "config").write_text("[default]\nregion = us-east-1\n")
    (d / "ca.pem").write_text("not a real certificate\n")
    monkeypatch.setenv("AWS_PROFILE", "bogus")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAREALLOOKING")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "real-secret")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://sts.amazonaws.com")
    monkeypatch.delenv(share.ENV_SHARE, raising=False)
    monkeypatch.delenv(em.PORT_ENV, raising=False)
    return d


def fake_report():
    r = demo.load_report()
    return dataclasses.replace(r, demo=False, emulator=True, account_id=em.EMULATOR_ACCOUNT, regions=["us-east-1"],
                               seconds=2.8, cost_explorer_skipped=True)


def _run(args, capsys):
    rc = cli.main(["scan", *args])
    out = capsys.readouterr()
    return rc, out.out, out.err


def _sts(host="127.0.0.1", account=em.EMULATOR_ACCOUNT):
    return MagicMock(meta=SimpleNamespace(endpoint_url=f"https://{host}:{PORT}"),
                     get_caller_identity=lambda: {"Account": account})


# --- the guards (acceptance 2) ---------------------------------------------------------------------

def test_session_ignores_profile_and_key_variables_and_uses_the_emulators_file(emulator_home):
    creds = em.make_session(PORT).get_credentials()
    assert creds.method == "shared-credentials-file"
    assert creds.access_key == "EMULATORTEST"  # not AKIAREALLOOKING, and no ProfileNotFound for AWS_PROFILE=bogus


def test_guards_pass_for_the_local_emulator(monkeypatch):
    monkeypatch.setattr(em, "client", lambda session, service, port: _sts())
    em.verify(em.make_session(PORT), PORT)


def test_guard_refuses_a_non_local_endpoint(monkeypatch):
    monkeypatch.setattr(em, "client", lambda session, service, port: _sts(host="sts.us-east-1.amazonaws.com"))
    with pytest.raises(em.Unsafe, match="not the local emulator"):
        em.verify(em.make_session(PORT), PORT)


def test_guard_refuses_credentials_that_are_not_from_the_shared_file(monkeypatch):
    monkeypatch.setattr(em, "client", lambda session, service, port: _sts())
    session = em.make_session(PORT)
    for method in ("env", "assume-role", "sso", "iam-role"):
        fake = MagicMock()
        fake.get_credentials.return_value = SimpleNamespace(method=method)
        with pytest.raises(em.Unsafe, match="shared credentials file"):
            em.verify(fake, PORT)
    assert session.get_credentials().method == "shared-credentials-file"


def test_guard_refuses_a_credentials_file_that_is_not_the_emulators(monkeypatch, tmp_path):
    monkeypatch.setattr(em, "client", lambda session, service, port: _sts())
    other = tmp_path / "creds"
    other.write_text("[default]\naws_access_key_id = AKIAREAL\naws_secret_access_key = x\n")
    bs = em.make_session(PORT)
    bs._session.set_config_variable("credentials_file", str(other))
    with pytest.raises(em.Unsafe, match="emulator's own"):
        em.verify(bs, PORT)


def test_guard_refuses_another_account(monkeypatch):
    monkeypatch.setattr(em, "client", lambda session, service, port: _sts(account="123456789012"))
    with pytest.raises(em.Unsafe, match="123456789012"):
        em.verify(em.make_session(PORT), PORT)


def test_guard_refuses_when_it_cannot_confirm(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(em, "client", boom)
    with pytest.raises(em.Unsafe, match="could not confirm"):
        em.verify(em.make_session(PORT), PORT)


def test_the_real_client_goes_to_127_0_0_1_whatever_the_environment_says():
    c = em.client(em.make_session(PORT), "sts", PORT)
    assert c.meta.endpoint_url == f"https://127.0.0.1:{PORT}"


def test_scan_env_is_a_copy_without_aws_variables_and_never_touches_the_process_environment():
    before = dict(os.environ)
    env = em.scan_env(PORT)
    assert dict(os.environ) == before
    assert "AWS_PROFILE" not in env
    assert "AWS_ACCESS_KEY_ID" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert env["AWS_ENDPOINT_URL"] == f"https://127.0.0.1:{PORT}"
    assert env["AWS_SHARED_CREDENTIALS_FILE"].endswith(f"emulator/{PORT}/emulator_credentials")
    assert env["AWS_CA_BUNDLE"].endswith("ca.pem") and env["EMULATOR_TELEMETRY"] == "off"
    leaked = em.scan_env(PORT, base={"AWS_ENDPOINT_URL_S3": "https://s3.amazonaws.com", "AWS_SESSION_TOKEN": "t", "PATH": "/bin"})
    assert "AWS_ENDPOINT_URL_S3" not in leaked and "AWS_SESSION_TOKEN" not in leaked and leaked["PATH"] == "/bin"


# --- Docker (acceptance 1) -------------------------------------------------------------------------

@pytest.fixture
def no_aws_call(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("an AWS client or session was created")

    monkeypatch.setattr(boto3, "client", boom)
    monkeypatch.setattr(boto3, "Session", boom)
    monkeypatch.setattr("cloudcostwise.runtime.resolve_credentials", boom)


def test_no_docker_exits_nonzero_with_one_clear_line_and_makes_no_aws_call(monkeypatch, capsys, no_aws_call):
    monkeypatch.setattr("shutil.which", lambda name: None)
    rc, out, err = _run(["--emulator"], capsys)
    lines = err.strip().splitlines()
    assert rc == 1 and out == "" and len(lines) == 1
    assert "needs Docker" in lines[0] and "no AWS call was made" in lines[0] and "scan --demo" in lines[0]


def test_docker_not_running_exits_nonzero_with_the_same_line(monkeypatch, capsys, no_aws_call):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "Cannot connect"))
    rc, out, err = _run(["--emulator"], capsys)
    lines = err.strip().splitlines()
    assert rc == 1 and out == "" and len(lines) == 1
    assert "needs Docker installed and running" in lines[0] and "daemon is not running" in lines[0] and "scan --demo" in lines[0]


@pytest.mark.parametrize("extra", [["--profile", "x"], ["--regions", "us-east-1"], ["--demo"]])
def test_profile_regions_and_demo_are_refused_with_emulator(extra, capsys, monkeypatch, no_aws_call):
    monkeypatch.setattr(em, "run", lambda *a, **k: pytest.fail("must refuse before starting anything"))
    rc, out, err = _run(["--emulator", *extra], capsys)
    assert rc == 2 and out == "" and "--emulator" in err and "never uses your AWS credentials" in err


def test_emulator_down_stops_the_container(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker")

    def fake_run(cmd, **k):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "25.0", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc, out, err = _run(["--emulator-down", "--emulator-port", "9555"], capsys)
    assert rc == 0 and "9555" in out
    assert ["docker", "rm", "-f", "cw-aws-emulator-9555"] in calls


def test_dockerfile_installs_awss_official_rpm():
    text = em.dockerfile()
    assert "https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/latest/aws-emulator-" in text
    assert text.count(".rpm") >= 3 and "EMULATOR_TELEMETRY=off" in text and "amazonlinux:2023" in text


def test_image_is_reused_and_a_running_container_is_reused(monkeypatch):
    calls = []

    def fake(args, timeout=120, **kw):
        calls.append(args[0] + " " + (args[1] if len(args) > 1 else ""))
        if args[:2] == ["ps", "--format"]:
            return subprocess.CompletedProcess(args, 0, "other\ncw-aws-emulator-9397\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(em, "_docker", fake)
    monkeypatch.setattr(em, "require_docker", lambda: None)
    monkeypatch.setattr(em, "_healthy", lambda port: True)
    assert em.start(PORT, lambda s: None) is True
    assert not any(c.startswith(("build", "run")) for c in calls)


def test_start_publishes_on_127_0_0_1_with_telemetry_off(monkeypatch):
    runs = []

    def fake(args, timeout=120, **kw):
        if args[0] == "run":
            runs.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(em, "_docker", fake)
    monkeypatch.setattr(em, "require_docker", lambda: None)
    monkeypatch.setattr(em, "_healthy", lambda port: True)
    assert em.start(PORT, lambda s: None) is False
    [args] = runs
    assert f"127.0.0.1:{PORT}:{PORT}" in args and "EMULATOR_TELEMETRY=off" in args and em.IMAGE in args


# --- output (acceptance 4) -------------------------------------------------------------------------

def test_every_format_says_what_it_is_and_isnt(monkeypatch, capsys):
    monkeypatch.setattr(em, "run", lambda port, say: fake_report())
    rc, table, err = _run(["--emulator"], capsys)
    lines = table.rstrip("\n").split("\n")
    assert rc == 0 and lines[0] == em.NOTE and lines[-1] == em.NOTE
    assert "Live scan of a fake AWS account running in AWS Emulator on your machine" in em.NOTE
    assert "savings use AWS list prices" in em.NOTE and "billing or usage history can't fire here" in em.NOTE
    assert em.CARD_MARK in table and "RI/Savings Plans checks skipped" not in table

    rc, md, _ = _run(["--emulator", "--format", "markdown"], capsys)
    lines = md.rstrip("\n").split("\n")
    assert rc == 0 and em.NOTE in lines[0] and em.NOTE in lines[-1]

    rc, js, _ = _run(["--emulator", "--format", "json"], capsys)
    data = json.loads(js)  # stdout is JSON alone
    assert rc == 0 and data["emulator"] is True and data["emulator_note"] == em.NOTE and "demo" not in data


def test_no_share_offer_and_nothing_saved(monkeypatch, capsys):
    monkeypatch.setattr(em, "run", lambda port, say: fake_report())
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    for name in ("offer", "save_last_summary", "send"):
        monkeypatch.setattr(share, name, lambda *a, **k: pytest.fail("a fake-account scan reached share"))
    rc, _, _ = _run(["--emulator"], capsys)
    assert rc == 0 and not share.last_summary_path().exists()


def test_share_refuses_an_emulator_report_on_every_path():
    r = fake_report()
    sent = []
    assert share.share_from_settings_mcp(r, env={share.ENV_SHARE: "yes"}, sender=sent.append) == "demo"
    assert share.save_last_summary(r, "cli") is None
    for call in (lambda: share.build_payload(r, "cli"), lambda: share.settings_payload(r, "mcp")):
        with pytest.raises(ValueError):
            call()
    assert share._prompt(r, "cli", None, None, sent.append) == "skipped" and sent == []


def test_port_is_overridable(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(em, "run", lambda port, say: seen.append(port) or fake_report())
    _run(["--emulator", "--emulator-port", "9555"], capsys)
    monkeypatch.setenv(em.PORT_ENV, "9444")
    _run(["--emulator"], capsys)
    monkeypatch.delenv(em.PORT_ENV)
    _run(["--emulator"], capsys)
    assert seen == [9555, 9444, 9397]


# --- MCP (acceptance 3) ----------------------------------------------------------------------------

def _text(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "text", None))


def _mcp(steps):
    server = mcp_server.build_server(share=True)

    async def go():
        async with Client(server) as client:
            return [await step(client) for step in steps]

    return asyncio.run(go())


def test_mcp_emulator_scan_then_the_other_tools_work_on_it(monkeypatch):
    monkeypatch.setenv(share.ENV_SHARE, "yes")
    for name in ("offer", "save_last_summary", "send"):
        monkeypatch.setattr(share, name, lambda *a, **k: pytest.fail("a fake-account scan reached share"))
    monkeypatch.setattr(em, "run", lambda port, say=None: fake_report())
    monkeypatch.setattr(mcp_server, "resolve_credentials", lambda *a, **k: pytest.fail("the person's credentials were read"))
    ids = {}
    env = {}

    async def scan(c):
        env["before"] = dict(os.environ)  # after the server is built: it sets its own timeout defaults
        return _text(await c.call_tool("scan", {"emulator": True, "profile": "ignored", "regions": "all"}))

    async def listing(c):
        text = _text(await c.call_tool("list_findings", {}))
        ids["one"] = next(line.split("|")[1].strip() for line in text.splitlines() if line.startswith("| demo-"))
        return text

    async def explain(c):
        return _text(await c.call_tool("explain_finding", {"finding_id": ids["one"]}))

    async def fix(c):
        return _text(await c.call_tool("fix_guidance", {"finding_id": ids["one"]}))

    scan_t, list_t, explain_t, fix_t = _mcp([scan, listing, explain, fix])
    for text in (scan_t, list_t, explain_t, fix_t):
        assert text.startswith(em.MCP_NOTE) and text.rstrip().endswith(em.NOTE)
        assert "service checks run locally" not in text  # the upsell footer is dropped, as for a demo
    assert "ignored with emulator=true" in scan_t
    assert "idle_dynamodb" in list_t and "Idle DynamoDB" in explain_t and "Delete or switch" in fix_t
    assert dict(os.environ) == env["before"]


def test_mcp_emulator_without_docker_says_what_is_needed_and_suggests_demo(monkeypatch):
    def no_docker(port, say=None):
        raise em.DockerMissing("docker not found on PATH")

    monkeypatch.setattr(em, "run", no_docker)

    async def scan(c):
        return _text(await c.call_tool("scan", {"emulator": True}))

    [text] = _mcp([scan])
    assert "needs Docker installed and running" in text and "demo=true" in text and "no AWS call was made" in text


def test_mcp_refuses_emulator_with_demo(monkeypatch):
    monkeypatch.setattr(em, "run", lambda *a, **k: pytest.fail("must not start"))

    async def scan(c):
        return _text(await c.call_tool("scan", {"emulator": True, "demo": True}))

    [text] = _mcp([scan])
    assert "not both" in text


def test_mcp_tool_description_mentions_emulator():
    async def tools(c):
        return (await c.list_tools()).tools

    [listed] = _mcp([tools])
    scan = next(t for t in listed if t.name == "scan")
    assert "emulator=true" in scan.description and "FAKE account" in scan.description


# --- review fixes: the static pin, the host guard, the child's isolation, small cases ----------------

def test_emulator_demo_builds_clients_only_through_its_own_127_0_0_1_helper():
    """policy_capture leaves emulator_demo.py out of the read-only IAM policy because it only calls a local
    emulator. This pins that: no client is made outside `client()` (which passes the 127.0.0.1 endpoint) and
    `verify()`'s one environment-endpoint STS check, and `seed()` goes through `client()`."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(em.__file__).read_text())
    callers = {}
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("client", "resource"):
                callers.setdefault(fn.name, []).append(n)
    assert set(callers) <= {"client", "verify", "_worker"} and "seed" not in callers and "already_seeded" not in callers
    [call] = callers["client"]
    assert {k.arg for k in call.keywords} >= {"endpoint_url", "verify"}
    assert "endpoint(port)" in ast.unparse(call)
    # boto3.client / boto3.resource (a default session, the person's credentials) are never used
    assert not any(isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "boto3"
                   and n.attr in ("client", "resource") for n in ast.walk(tree))
    seed_src = ast.unparse(next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "seed"))
    assert "boto3." not in seed_src.split('"""')[-1] and "client(session" in seed_src


def test_session_refuses_any_request_to_another_host():
    """before-send guard: even a client built by hand on the safe session cannot reach a non-local host."""
    session = em.make_session(PORT)
    c = session.client("sts", region_name="us-east-1", endpoint_url="https://sts.amazonaws.com")
    with pytest.raises(em.Unsafe, match="only talks to the local emulator"):
        c.get_caller_identity()
    em._only_local(SimpleNamespace(url="https://127.0.0.1:9397/"))  # the local host passes


def test_the_child_runs_isolated_from_the_callers_directory(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, **k):
        seen["cmd"], seen["cwd"] = cmd, k.get("cwd")
        seen["cwd_exists"] = os.path.isdir(k["cwd"])
        return subprocess.CompletedProcess(cmd, 1, "", "boom")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(em.EmulatorError):
        em.run_scan_child(PORT)
    assert "-P" in seen["cmd"] and seen["cwd_exists"] and os.path.realpath(seen["cwd"]) != os.path.realpath(tmp_path)


def test_a_planted_boto3_in_the_callers_directory_is_not_imported(monkeypatch, tmp_path):
    marker = tmp_path / "planted-ran"
    (tmp_path / "boto3.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(em.EmulatorError):  # no emulator here: the child stops at its guards
        em.run_scan_child(PORT)
    assert not marker.exists()


def test_stop_hint_names_a_non_default_port(monkeypatch, capsys):
    monkeypatch.setattr(em, "run", lambda port, say: fake_report())
    _, _, err = _run(["--emulator", "--emulator-port", "9555"], capsys)
    assert "--emulator-down --emulator-port 9555" in err
    _, _, err = _run(["--emulator"], capsys)
    assert err.strip().endswith("cloudcostwise scan --emulator-down")


@pytest.mark.parametrize("bad", ["0", "80", "1023", "65536", "abc"])
def test_emulator_port_must_be_1024_to_65535(bad, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["scan", "--emulator", "--emulator-port", bad])
    assert e.value.code == 2 and "1024 to 65535" in capsys.readouterr().err


def test_docker_timeouts_become_clear_emulator_errors(monkeypatch):
    def slow(cmd, **k):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(em.DockerTimeout, match="did not finish"):
        em._docker(["ps"])
    monkeypatch.setattr(em, "require_docker", lambda: None)
    with pytest.raises(em.EmulatorError, match="did not finish"):
        em.ensure_image(lambda s: None)
    with pytest.raises(em.EmulatorError, match="did not finish"):
        em.start(PORT, lambda s: None)


def test_the_emulator_directory_is_created_private(monkeypatch, tmp_path):
    home = tmp_path / "fresh-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(em, "_docker", lambda args, timeout=120, **kw: subprocess.CompletedProcess(args, 0, "", ""))
    monkeypatch.setattr(em, "require_docker", lambda: None)
    monkeypatch.setattr(em, "_healthy", lambda port: True)
    em.start(PORT, lambda s: None)
    assert (home / ".aws" / "emulator").stat().st_mode & 0o777 == 0o700


def test_mcp_note_says_the_container_keeps_running_and_how_to_stop_it():
    assert "keeps running" in em.MCP_NOTE and "cloudcostwise scan --emulator-down" in em.MCP_NOTE
