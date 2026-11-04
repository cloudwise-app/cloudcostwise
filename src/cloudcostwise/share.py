"""Opt-in shared scan (CLO-824): a summary of a scan, sent to CloudWise only if a human says so.

What may be sent, and nothing else: the CLI version, how many findings, the
estimated monthly savings and how many checks ran. The payload is built from
those four numbers off the scan report; it never reads an account ID, a
resource ID or name, a region, an ARN or a tag, so it cannot carry one. The
report itself is never uploaded.

Who may consent:

- An interactive terminal: stdin and stdout are both TTYs, and the human
  types y at a prompt (the prompt and the payload go to stderr, never stdout).
- A setting the human wrote: ``CLOUDCOSTWISE_SHARE=yes|no`` in the
  environment, or ``share.json`` under ``~/.config/cloudcostwise/``.

Settings and the MCP server carry the summary numbers ONLY. An email address
and the two email requests ("please email me this report", "tell me when new
checks land") come only from the interactive prompt of that very run, which
shows the exact wording. Nothing in the environment, the config file or MCP
can attach them. With no TTY and no setting nothing is asked and nothing is
sent. Any network failure is swallowed; the send runs on a daemon thread
capped at about three seconds, after the results printed.
"""


from __future__ import annotations

import json
import os
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from cloudcostwise import __version__

SHARE_URL = "https://api.cloudcostwise.io/api/v1/shared-scans"  # the FastAPI host, not the Next.js site
TIMEOUT_SECONDS = 3.0
SCHEMA_VERSION = 1

ENV_SHARE = "CLOUDCOSTWISE_SHARE"

EMAIL_REPORT_WORDING = ("Please email me about this report, once. Nothing from the report is sent: the "
                        "request and your address are. You can produce the report yourself with "
                        "`cloudcostwise scan --format markdown`.")
NEW_CHECKS_WORDING = ("I consent to marketing email from CloudWise (15331269 Canada Inc.), 4165 Fieldgate Dr, "
                      "Mississauga ON L4W 2M9, Canada, cloudwise@cloudcostwise.io, when new checks land. "
                      "We confirm by reply before adding you. You can withdraw consent at any time by "
                      "replying to or emailing cloudwise@cloudcostwise.io.")
SENT_UNSURE = ("The summary may not have been received (could not reach CloudWise in time). "
               "The scan is unaffected.")

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}
# Anything in the payload that is not one of these keys is a bug.
PAYLOAD_KEYS = frozenset({
    "schema_version", "source", "cli_version", "findings_count", "estimated_monthly_savings",
    "checks_run", "email", "email_report", "new_checks_updates", "new_checks_wording", "email_report_wording",
})


def config_path() -> Path:
    return Path.home() / ".config" / "cloudcostwise" / "share.json"


def _truthy(value: Optional[str]) -> Optional[bool]:
    v = (value or "").strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return None


def load_config() -> Dict[str, Any]:
    try:
        data = json.loads(config_path().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_config(data: Dict[str, Any]) -> bool:
    try:
        path = config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n")
        return True
    except OSError:
        return False


class Settings:
    """The human-written settings: environment first, then the config file. Share on/off only."""

    def __init__(self, share: Optional[bool], asked: bool):
        self.share = share
        self.asked = asked


def read_settings(env: Optional[Dict[str, str]] = None) -> Settings:
    env = os.environ if env is None else env
    cfg = load_config()
    share = _truthy(env.get(ENV_SHARE))
    if share is None:
        share = _truthy(str(cfg["share"])) if "share" in cfg else None
    return Settings(share, bool(cfg.get("asked")))


def decide(settings: Settings, *, can_prompt: bool) -> str:
    """'send' (a setting says yes), 'prompt' (ask the human), or 'skip'."""
    if settings.share is False:
        return "skip"
    if settings.share is True:
        return "send"
    if can_prompt and not settings.asked:
        return "prompt"
    return "skip"


def build_payload(report, source: str, *, email: Optional[str] = None, email_report: bool = False,
                  new_checks: bool = False) -> Dict[str, Any]:
    """The summary. Reads four numbers off the report and nothing that names a resource.

    ``email`` and the two requests are passed only by the interactive prompt."""
    from cloudcostwise import render

    payload: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "cli_version": __version__,
        "findings_count": len(report.findings),
        "estimated_monthly_savings": render.counted_total(report),
        "checks_run": int(report.entrypoints or 0),
    }
    # An address with no reason to hold it is not sent.
    if email and (email_report or new_checks):
        payload["email"] = email
        payload["email_report"] = bool(email_report)
        payload["new_checks_updates"] = bool(new_checks)
        if new_checks:
            payload["new_checks_wording"] = NEW_CHECKS_WORDING
        if email_report:
            payload["email_report_wording"] = EMAIL_REPORT_WORDING
    return payload


def send(payload: Dict[str, Any], *, url: str = SHARE_URL, timeout: float = TIMEOUT_SECONDS) -> bool:
    """POST the payload. Never raises, never takes longer than about ``timeout`` seconds."""
    if not url.startswith("https://") and not url.startswith("http://localhost"):
        return False
    result = {"ok": False}

    def work() -> None:
        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode(), method="POST",
                headers={"Content-Type": "application/json", "User-Agent": f"cloudcostwise/{__version__}"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only, checked above)
                result["ok"] = 200 <= resp.status < 300
        except Exception:  # noqa: BLE001 - sharing must never fail a scan
            result["ok"] = False

    t = threading.Thread(target=work, daemon=True, name="cloudcostwise-share")
    t.start()
    t.join(timeout + 0.5)
    return result["ok"]


def send_in_background(payload: Dict[str, Any], *, url: str = SHARE_URL,
                       timeout: float = TIMEOUT_SECONDS) -> threading.Thread:
    """For the MCP server: return at once, send on a daemon thread."""
    t = threading.Thread(target=send, args=(payload,), kwargs={"url": url, "timeout": timeout},
                         daemon=True, name="cloudcostwise-share-mcp")
    t.start()
    return t


def settings_payload(report, source: str) -> Dict[str, Any]:
    # Numbers only. An address or an email request never comes from a setting or from MCP.
    return build_payload(report, source)


def share_from_settings_mcp(report, *, env: Optional[Dict[str, str]] = None,
                            sender: Optional[Callable[..., Any]] = None) -> bool:
    """MCP path: no prompt, ever. Sends only when a human-written setting says yes."""
    try:
        settings = read_settings(env)
        if decide(settings, can_prompt=False) != "send":
            return False
        (sender or send_in_background)(settings_payload(report, "mcp"))
        return True
    except Exception:  # noqa: BLE001
        return False


def _isatty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001
        return False


def _ask(question: str, stdin, stderr) -> str:
    print(question, end="", file=stderr, flush=True)
    return (stdin.readline() or "").strip()


def _yes(answer: str) -> bool:
    return answer.strip().lower() in {"y", "yes"}


def offer(report, *, source: str = "cli", stdin=None, stdout=None, stderr=None,
          env: Optional[Dict[str, str]] = None, sender: Callable[..., Any] = send) -> str:
    """CLI path, called after the results are printed. Returns what happened:
    'sent', 'failed', 'declined', or 'skipped' (nothing asked, nothing sent)."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    try:
        settings = read_settings(env)
        verdict = decide(settings, can_prompt=_isatty(stdin) and _isatty(stdout))
        if verdict == "skip":
            return "skipped"
        if verdict == "send":
            ok = sender(settings_payload(report, source))
            print("Shared a summary with CloudWise "
                  f"({ENV_SHARE}=no or `cloudcostwise share --off` turns this off)." if ok else SENT_UNSURE,
                  file=stderr)
            return "sent" if ok else "failed"
        return _prompt(report, source, stdin, stderr, sender)
    except (EOFError, KeyboardInterrupt):
        return "declined"
    except Exception:  # noqa: BLE001 - sharing must never fail a scan
        return "skipped"


def _prompt(report, source: str, stdin, stderr, sender) -> str:
    # Whatever the answer, do not ask again on this machine.
    cfg = load_config()
    cfg["asked"] = True
    save_config(cfg)

    base = build_payload(report, source)
    print("\nShare a summary of this scan with CloudWise? Optional. Nothing is sent unless you answer y.",
          file=stderr)
    print("This is exactly what would be sent (no account IDs, resource IDs or names, regions, ARNs or tags):",
          file=stderr)
    print(json.dumps(base, indent=2), file=stderr)
    if not _yes(_ask("Share this summary? [y/N] ", stdin, stderr)):
        print("Not shared. You will not be asked again; `cloudcostwise share --on` changes that.", file=stderr)
        return "declined"

    payload = base
    email = _ask("Email address (optional, Enter to skip): ", stdin, stderr)
    if email:
        print(f"\n{EMAIL_REPORT_WORDING}", file=stderr)
        want_report = _yes(_ask("Email me about this report? [y/N] ", stdin, stderr))
        print(f"\n{NEW_CHECKS_WORDING}", file=stderr)
        want_updates = _yes(_ask("Tell me when new checks land? [y/N] ", stdin, stderr))
        payload = build_payload(report, source, email=email, email_report=want_report, new_checks=want_updates)
        if "email" not in payload:
            print("No email option chosen, so the address is not sent.", file=stderr)
        else:
            print("\nFinal payload:", file=stderr)
            print(json.dumps(payload, indent=2), file=stderr)
            if not _yes(_ask("Send? [y/N] ", stdin, stderr)):
                print("Not shared.", file=stderr)
                return "declined"
    ok = sender(payload)
    print("Shared. Thank you." if ok else SENT_UNSURE, file=stderr)
    return "sent" if ok else "failed"


def status_text(settings: Optional[Settings] = None) -> str:
    s = settings or read_settings()
    state = {True: "on (a summary is sent after each scan)", False: "off (never asked, never sent)",
             None: "ask once in an interactive terminal" if not s.asked else "not asked again (already answered)"}[s.share]
    return "\n".join([
        f"Shared scan: {state}",
        f"Setting source: {ENV_SHARE} in the environment, else {config_path()}",
        "Sent when on: CLI version, number of findings, estimated monthly savings, checks run. "
        "Never account IDs, resource IDs or names, regions, ARNs or tags, and never an email address: "
        "an address is only ever asked for at the interactive prompt.",
    ])


def command(args, *, stdin=None, stdout=None, stderr=None) -> int:
    """`cloudcostwise share --on|--off|--status|--reset`."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    cfg = load_config()
    if args.on:
        # A person types this at a terminal. A script or an AI assistant's non-interactive shell
        # must not turn consent on; they can set the environment variable or edit the file instead.
        if not (_isatty(stdin) and _isatty(stdout)):
            print(f"cloudcostwise: `share --on` needs an interactive terminal. To opt in without one, set "
                  f"{ENV_SHARE}=yes yourself or write {config_path()}.", file=stderr)
            return 2
        cfg["share"] = "yes"
        cfg["asked"] = True
    elif args.off:
        cfg.update({"share": "no", "asked": True})
    elif args.reset:
        cfg = {}
    if (args.on or args.off or args.reset) and not save_config(cfg):
        print(f"cloudcostwise: could not write {config_path()}", file=stderr)
        return 1
    print(status_text(), file=stdout)
    return 0
