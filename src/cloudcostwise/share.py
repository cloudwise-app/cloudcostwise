"""Opt-in shared scan (CLO-824, CLO-1055): a summary of a scan, sent to CloudWise only if a human says so.

What may be sent, and nothing else: the CLI version, where the scan ran (``cli`` or ``mcp``), how many
findings, the estimated monthly savings and how many checks ran. The payload is built from those
numbers and that one word off the scan report; it never reads an account ID, a resource ID or name, a
region, an ARN or a tag, so it cannot carry one. The report itself is never uploaded.

Who may consent:

- An interactive terminal: stdin and stdout are both TTYs, and the human
  types y at a prompt (the prompt and the payload go to stderr, never stdout).
- A setting the human wrote: ``CLOUDCOSTWISE_SHARE=yes|no`` in the
  environment, or ``share.json`` under ``~/.config/cloudcostwise/``.
- ``cloudcostwise share --last`` (CLO-1055), typed by the human: it shows the summary of the last scan
  (CLI or MCP) and sends it only on a y typed at that prompt. It refuses to run unless stdin and stdout
  are both TTYs, and no flag, environment variable or setting skips its prompt.

The last scan's summary (CLO-1055): after every real scan, CLI and MCP (never a demo), the summary
fields are written to ``last-summary.json`` next to ``share.json``, with the time it was saved
(``saved_at``), when a send of it was attempted (``send_attempted_at``, null until then) and whether
CloudWise confirmed it (``sent_ok``: null until the send ends, then true or false). The write is
atomic, mode 0600, and a failed write never fails a scan. The file is never sent by itself: only
``share --last`` reads it, after a y. Every send of a saved summary, from ``share --last``, the
after-scan prompt or a setting, first records the attempt in the file, under a lock on the config
directory where the platform has one (fcntl). A summary whose attempt is already recorded, or whose
attempt cannot be recorded, is not sent. So each saved summary is tried at most once; a failed attempt is
not retried (a new scan makes a new summary). The one send with no record is an automatic send of a scan
whose summary was never saved (or was replaced by a later scan's): no file holds it, so it cannot be sent
again. Without the lock (no fcntl, or flock failing), two processes marking the same summary in the same
instant could both send. ``share --off`` deletes the file.

Settings and the MCP server carry the summary fields ONLY. An email address
and the two email requests ("please email me this report", "tell me when new
checks land") come only from an interactive prompt (after a CLI scan, or in
``share --last``), which shows the exact wording. Nothing in the environment, the config file or MCP
can attach them. With no TTY and no setting nothing is asked and nothing is
sent. Any network failure is swallowed; the send runs on a daemon thread
capped at about three seconds. The CLI sends after the results are printed; the MCP server waits for
that capped send before it returns the scan result, so its note can say what happened.

``CLOUDCOSTWISE_SHARE_URL`` sends to a test server instead of CloudWise (CLO-1055), so the founder's
own test scans stay out of the count without the payload carrying anything that tells them apart. It
is accepted only for http(s)://localhost, http(s)://127.0.0.1 and https://api-staging.cloudcostwise.io;
anything else is refused with an error and nothing is sent.
"""


from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
import sys
import tempfile
import threading
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from cloudcostwise import __version__

SHARE_URL = "https://api.cloudcostwise.io/api/v1/shared-scans"  # the FastAPI host, not the Next.js site
TIMEOUT_SECONDS = 3.0
SCHEMA_VERSION = 1

ENV_SHARE = "CLOUDCOSTWISE_SHARE"
ENV_SHARE_URL = "CLOUDCOSTWISE_SHARE_URL"
STAGING_API_HOST = "api-staging.cloudcostwise.io"  # infrastructure/environments/staging/main.tf
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})

EMAIL_REPORT_WORDING = ("Please email me about this report, once. Nothing from the report is sent: the "
                        "request and your address are. You can produce the report yourself with "
                        "`cloudcostwise scan --format markdown`.")
NEW_CHECKS_WORDING = ("I consent to marketing email from CloudWise (15331269 Canada Inc.), 4165 Fieldgate Dr, "
                      "Mississauga ON L4W 2M9, Canada, cloudwise@cloudcostwise.io, when new checks land. "
                      "We confirm by reply before adding you. You can withdraw consent at any time by "
                      "replying to or emailing cloudwise@cloudcostwise.io.")
# send() returns False for every failure (offline, DNS, timeout, an error answer, a redirect), so this
# never claims the summary left the machine.
NOT_CONFIRMED = "CloudWise did not confirm the summary arrived (it may not have been sent)."
SENT_UNSURE = f"{NOT_CONFIRMED} The scan is unaffected."

# --- CLO-1055 wording, fixed by the owner on 2026-11-15 (quoted verbatim; tests pin it) ---------------
MCP_NOT_SENT_NOTE = ("Nothing from this scan has been sent to CloudWise. If you want to share its summary, "
                     "run `cloudcostwise share --last` in your own terminal: it shows exactly what "
                     "would be sent (CLI version, number of findings, estimated monthly savings, checks run, "
                     "and that it came from MCP) and sends nothing unless you type y.")
MCP_SENT_NOTE = ("A summary of this scan was sent to CloudWise because CLOUDCOSTWISE_SHARE (or share.json) is "
                 "set to yes: CLI version, number of findings, estimated monthly savings, checks run, source "
                 "mcp. `cloudcostwise share --off` stops it.")
# Instead of MCP_SENT_NOTE when send() did not report success: it does not claim a send.
MCP_SEND_UNCONFIRMED = ("Your setting says to share a summary of this scan, but CloudWise did not confirm "
                        "it arrived (it may not have been sent).")
LAST_PROMPT = ("Share the summary of your last scan (from {where}, {when}) with CloudWise? Nothing is sent "
               "unless you answer y.\n"
               "This is exactly what would be sent. CloudWise also sees the time and your IP address, as for "
               "any web request. No account IDs, resource IDs or names, regions, ARNs or tags:\n"
               "{payload}\n"
               "Share this summary? [y/N] ")
LAST_DECLINED = "Not shared. Nothing was sent."
LAST_SENT = "Shared. Thank you."
LAST_NO_TERMINAL = ("cloudcostwise: `share --last` asks you before sending anything, so it only runs in a "
                    "terminal where you can type. Run it yourself in a terminal window.")
ON_NO_TERMINAL = ("cloudcostwise: `share --on` turns on sharing, which only you can do, so it only runs in a "
                  "terminal where you can type. Run it yourself in a terminal window.")
LAST_UNUSABLE = ("The saved summary in {path} is not one a scan wrote, so it is not sent. Run a new scan; "
                 "it replaces the file.")
LAST_NO_SUMMARY = ("No scan summary saved yet. Run a scan first; only its summary numbers are kept, "
                   "in {path}.")
LAST_ALREADY_SHARED = "That summary was already shared."
LAST_ALREADY_TRIED = "A send of that summary was already attempted; run a new scan to share again."
LAST_NOT_MARKED = ("cloudcostwise: could not record in {path} that this summary is being shared, so nothing "
                   "was sent (it could otherwise be sent twice).")
URL_REFUSED = (f"cloudcostwise: {ENV_SHARE_URL} must be http(s)://localhost, http(s)://127.0.0.1 or "
               f"https://{STAGING_API_HOST}. It is set to something else, so nothing was sent.")

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}
# Anything in the payload that is not one of these keys is a bug.
PAYLOAD_KEYS = frozenset({
    "schema_version", "source", "cli_version", "findings_count", "estimated_monthly_savings",
    "checks_run", "email", "email_report", "new_checks_updates", "new_checks_wording", "email_report_wording",
})
# The summary: the payload without any email field. last-summary.json holds these plus SUMMARY_META.
SUMMARY_KEYS = ("schema_version", "source", "cli_version", "findings_count", "estimated_monthly_savings",
                "checks_run")
SUMMARY_META = ("saved_at", "send_attempted_at", "sent_ok")
_CLI_VERSION = re.compile(r"^[0-9A-Za-z.+_-]{1,32}$")  # the API's own bound (shared_scans.py)


def config_path() -> Path:
    return Path.home() / ".config" / "cloudcostwise" / "share.json"


def last_summary_path() -> Path:
    return config_path().parent / "last-summary.json"


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


# --- where a summary may be sent ---------------------------------------------------------------------

class ShareUrlRefused(ValueError):
    """CLOUDCOSTWISE_SHARE_URL names a host that is not allowed. Nothing is sent."""


def url_allowed(url: str) -> bool:
    """The production endpoint, or a test server: http(s) on localhost or 127.0.0.1, https on the staging
    API. Parsed, never prefix-matched, so ``http://localhost.evil.com`` and ``http://localhost@evil.com``
    are refused."""
    if url == SHARE_URL:
        return True
    if not isinstance(url, str) or any(ord(c) <= 32 or c == "\\" for c in url):
        return False
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return False
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        return False
    host = parts.hostname or ""
    if parts.scheme in ("http", "https") and host in _LOCAL_HOSTS:
        return True
    return parts.scheme == "https" and host == STAGING_API_HOST and port in (None, 443)


def share_url(env: Optional[Dict[str, str]] = None) -> str:
    """Where to send: SHARE_URL, or CLOUDCOSTWISE_SHARE_URL when it is an allowed test server.
    Raises ShareUrlRefused for anything else."""
    env = os.environ if env is None else env
    raw = (env.get(ENV_SHARE_URL) or "").strip()
    if not raw:
        return SHARE_URL
    if not url_allowed(raw):
        raise ShareUrlRefused(URL_REFUSED)
    return raw


# --- the payload -------------------------------------------------------------------------------------

def _with_email(base: Dict[str, Any], *, email: Optional[str], email_report: bool,
                new_checks: bool) -> Dict[str, Any]:
    payload = dict(base)
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


def build_payload(report, source: str, *, email: Optional[str] = None, email_report: bool = False,
                  new_checks: bool = False) -> Dict[str, Any]:
    """The summary. Reads four numbers and the scan's source off the report, and nothing that names a
    resource.

    ``email`` and the two requests are passed only by the interactive prompt."""
    from cloudcostwise import render

    # CLO-1057: the one place every payload is built (the prompt, a setting, MCP, the saved summary), so
    # the demo recording can never become one, whatever CLOUDCOSTWISE_SHARE says.
    if _is_fake(report):
        raise ValueError("a demo (sample data) report is never shared")
    base: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "cli_version": __version__,
        "findings_count": len(report.findings),
        "estimated_monthly_savings": render.counted_total(report),
        "checks_run": int(report.entrypoints or 0),
    }
    return _with_email(base, email=email, email_report=email_report, new_checks=new_checks)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is a failed send: following it would POST elsewhere (or GET a page) and report success for a
    summary the endpoint never received."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # urllib then raises HTTPError for the 3xx, which send() counts as a failure


_OPENER = urllib.request.build_opener(_NoRedirect)


def _open(req, timeout: float):
    return _OPENER.open(req, timeout=timeout)  # noqa: S310 (the URL is allow-listed by send())


def send(payload: Dict[str, Any], *, url: str = SHARE_URL, timeout: float = TIMEOUT_SECONDS) -> bool:
    """POST the payload. Never raises, never takes longer than about ``timeout`` seconds."""
    if not url_allowed(url):
        return False
    result = {"ok": False}

    def work() -> None:
        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode(), method="POST",
                headers={"Content-Type": "application/json", "User-Agent": f"cloudcostwise/{__version__}"})
            with _open(req, timeout) as resp:
                result["ok"] = 200 <= resp.status < 300
        except Exception:  # noqa: BLE001 - sharing must never fail a scan
            result["ok"] = False

    t = threading.Thread(target=work, daemon=True, name="cloudcostwise-share")
    t.start()
    t.join(timeout + 0.5)
    return result["ok"]


def settings_payload(report, source: str) -> Dict[str, Any]:
    # Numbers only. An address or an email request never comes from a setting or from MCP.
    return build_payload(report, source)


# --- the last scan's summary (CLO-1055) -----------------------------------------------------------

def _now() -> str:
    # Microseconds: two scans in the same second must still get different saved_at values, since the
    # automatic send tells this scan's record from a later one by it.
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _write_private(path: Path, data: Dict[str, Any]) -> None:
    """Atomic write, mode 0600: a temporary file in the same directory, then a rename over the old one."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".last-summary.", suffix=".tmp")  # 0600
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _is_fake(report) -> bool:
    """A recorded demo (CLO-1057) or a scan of the AWS Emulator's fake account (CLO-1116): never saved, never shared."""
    return bool(getattr(report, "demo", False) or getattr(report, "emulator", False))


def save_last_summary(report, source: str) -> Optional[str]:
    """Keep this scan's summary for `share --last`. Never a demo; never raises. Returns the record's
    ``saved_at`` (pass it to the automatic send, so it marks this scan's record and no other), or None
    if nothing was written."""
    if _is_fake(report):
        return None  # CLO-1057: sample data is never saved, so it can never be shared
    try:
        saved_at = _now()
        record = {**build_payload(report, source), "saved_at": saved_at, "send_attempted_at": None,
                  "sent_ok": None}
        _write_private(last_summary_path(), record)
        return saved_at
    except Exception:  # noqa: BLE001 - a summary that cannot be saved must never fail a scan
        return None


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_time(v: Any) -> bool:
    if not isinstance(v, str) or len(v) > 40:
        return False
    try:
        dt.datetime.fromisoformat(v)
        return True
    except ValueError:
        return False


def load_last_summary() -> Optional[Dict[str, Any]]:
    """The saved summary, or None if there is none or it is not exactly what a scan writes.

    Anything can write this file (it is a plain local file), so every field is checked against the
    shape a scan writes and the API's bounds, and an unknown key (an email address, a note) makes the
    whole file unusable rather than being carried along."""
    try:
        data = json.loads(last_summary_path().read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or set(data) != set(SUMMARY_KEYS) | set(SUMMARY_META):
        return None
    savings = data["estimated_monthly_savings"]
    ok = (_is_int(data["schema_version"]) and data["schema_version"] == SCHEMA_VERSION
          and data["source"] in ("cli", "mcp")
          and isinstance(data["cli_version"], str) and bool(_CLI_VERSION.match(data["cli_version"]))
          and _is_int(data["findings_count"]) and 0 <= data["findings_count"] <= 1_000_000
          and isinstance(savings, (int, float)) and not isinstance(savings, bool)
          and math.isfinite(savings) and 0 <= savings <= 1_000_000_000
          and _is_int(data["checks_run"]) and 0 <= data["checks_run"] <= 500
          and _is_time(data["saved_at"])
          and (data["send_attempted_at"] is None or _is_time(data["send_attempted_at"]))
          and data["sent_ok"] in (None, True, False)
          and (data["send_attempted_at"] is not None or data["sent_ok"] is None))
    return data if ok else None


def summary_payload(record: Dict[str, Any]) -> Dict[str, Any]:
    """The payload for a saved summary: exactly the summary keys, in order, never anything else."""
    return {k: record[k] for k in SUMMARY_KEYS}


class _Lock:
    """An exclusive lock on the config directory itself (so no extra file is created), where the
    platform has fcntl (macOS, Linux). Elsewhere it is a no-op, and the check-then-write in
    mark_attempt is not atomic across processes."""

    def __enter__(self):
        self._fd = None
        try:
            import fcntl

            last_summary_path().parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._fd = os.open(str(last_summary_path().parent), os.O_RDONLY)
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except (ImportError, OSError):
            # No lock (no fcntl, or flock failed): this only reopens the race window between two
            # processes. Every send still needs mark_attempt to see no earlier attempt in the file first.
            if self._fd is not None:
                os.close(self._fd)
            self._fd = None
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            os.close(self._fd)  # closing releases the lock
        return False


# mark_attempt results. Only MARKED lets the caller send without further thought.
MARKED = "marked"                  # this call recorded the attempt: send now
ALREADY_SHARED = "already_shared"  # the same summary: an earlier send was confirmed. Do not send.
ALREADY_TRIED = "already_tried"    # the same summary: an earlier send was attempted, not confirmed. Do not send.
OTHER = "other"                    # the file holds no summary, or a different one
UNWRITABLE = "unwritable"          # the same, unattempted summary, but the mark could not be written


def mark_attempt(record: Dict[str, Any]) -> str:
    """Record that a send of ``record`` is starting, under the lock. Returns MARKED (only then may a
    send of it go ahead unconditionally), ALREADY_SHARED or ALREADY_TRIED (the same summary was already
    attempted: never send it again), OTHER or UNWRITABLE (nothing written)."""
    with _Lock():
        current = load_last_summary()
        if current is None or current["saved_at"] != record["saved_at"] or \
                summary_payload(current) != summary_payload(record):
            return OTHER
        if current["send_attempted_at"] is not None:
            return ALREADY_SHARED if current["sent_ok"] is True else ALREADY_TRIED
        try:
            _write_private(last_summary_path(), {**current, "send_attempted_at": _now(), "sent_ok": None})
            return MARKED
        except Exception:  # noqa: BLE001
            return UNWRITABLE


def record_result(record: Dict[str, Any], ok: bool) -> None:
    """After an attempted send: whether CloudWise confirmed it. Best effort."""
    try:
        with _Lock():
            current = load_last_summary()
            if current is not None and current["saved_at"] == record["saved_at"] and \
                    current["send_attempted_at"] is not None:
                _write_private(last_summary_path(), {**current, "sent_ok": bool(ok)})
    except Exception:  # noqa: BLE001
        pass


NOT_MARKED = "not_marked"
_FIND = object()  # saved_at not given: find this scan's record by its numbers (callers that did not save)


def _send_marked(payload: Dict[str, Any], sender: Callable[[Dict[str, Any]], Any], saved_at: Any = _FIND) -> str:
    """An automatic send (a setting, or the after-scan prompt). Returns 'sent', 'unconfirmed',
    ALREADY_SHARED / ALREADY_TRIED (this summary's send was already attempted, by `share --last` in
    another terminal, say), or NOT_MARKED (the attempt could not be recorded). In the last three nothing
    is sent, so a saved summary never goes twice.

    ``saved_at`` is what save_last_summary returned for this scan: the record is this scan's only if its
    saved_at matches (a later scan with the same numbers is a different summary). None means this scan's
    summary was not saved. Only when the file holds no record of this scan (OTHER) is it sent without a
    mark: then no file holds it, so `share --last` cannot send it again."""
    record = load_last_summary()
    mine = record is not None and summary_payload(record) == {k: payload.get(k) for k in SUMMARY_KEYS} and \
        (saved_at is _FIND or record["saved_at"] == saved_at)
    state = mark_attempt(record) if mine else OTHER
    if state in (ALREADY_SHARED, ALREADY_TRIED):
        return state
    if state == UNWRITABLE:
        return NOT_MARKED
    ok = bool(sender(payload))
    if state == MARKED:
        record_result(record, ok)
    return "sent" if ok else "unconfirmed"


def _already_line(state: str) -> str:
    return LAST_ALREADY_SHARED if state == ALREADY_SHARED else LAST_ALREADY_TRIED


def _held_line(state: str) -> str:
    """What the CLI says when an automatic send was held back."""
    if state == NOT_MARKED:
        return LAST_NOT_MARKED.format(path=last_summary_path())
    return _already_line(state)


def delete_last_summary() -> bool:
    try:
        last_summary_path().unlink()
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


def _local_minutes(stamp: str) -> str:
    try:
        return dt.datetime.fromisoformat(stamp).astimezone().strftime("%Y-%m-%d %H:%M")
    except (ValueError, OSError, OverflowError):
        return stamp


# --- MCP ---------------------------------------------------------------------------------------------

def share_from_settings_mcp(report, *, env: Optional[Dict[str, str]] = None,
                            sender: Optional[Callable[[Dict[str, Any]], Any]] = None,
                            saved_at: Any = _FIND) -> str:
    """MCP path: no prompt, ever. Sends only when a human-written setting says yes, and waits for the
    capped send (about 3 s at most) so the caller can say truthfully what happened. Never raises.

    Returns 'not_on' (the setting is not yes: nothing sent), 'sent' (a success answer came back),
    'unsure' (no success answer: it may not have been sent), 'already' (a send of this summary was
    already attempted from a terminal: nothing sent), 'not_marked' (the attempt could not be recorded in
    last-summary.json: nothing sent), 'refused' (CLOUDCOSTWISE_SHARE_URL not allowed: nothing
    sent), 'demo' or 'error' (nothing sent)."""
    if _is_fake(report):
        return "demo"  # CLO-1057
    try:
        settings = read_settings(env)
        if decide(settings, can_prompt=False) != "send":
            return "not_on"
        try:
            url = share_url(env)
        except ShareUrlRefused as e:
            print(e, file=sys.stderr)
            return "refused"
        outcome = _send_marked(settings_payload(report, "mcp"), sender or (lambda p: send(p, url=url)),
                               saved_at)
        if outcome in (ALREADY_SHARED, ALREADY_TRIED):
            return "already"  # attempted from a terminal first; nothing sent from here, nothing to say
        if outcome == NOT_MARKED:
            return "not_marked"
        return "sent" if outcome == "sent" else "unsure"
    except Exception:  # noqa: BLE001
        return "error"


# --- the CLI after a scan ----------------------------------------------------------------------------

def _isatty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001
        return False


def _ask(question: str, stdin, out) -> str:
    print(question, end="", file=out, flush=True)
    return (stdin.readline() or "").strip()


def _yes(answer: str) -> bool:
    return answer.strip().lower() in {"y", "yes"}


def offer(report, *, source: str = "cli", stdin=None, stdout=None, stderr=None,
          env: Optional[Dict[str, str]] = None, sender: Optional[Callable[..., Any]] = None,
          saved_at: Any = _FIND) -> str:
    """CLI path, called after the results are printed. Returns what happened:
    'sent', 'failed', 'declined', 'already' (this summary's send was already attempted, so nothing was
    sent), 'not_marked' (the attempt could not be recorded, so nothing was sent), or 'skipped' (nothing
    asked, nothing sent). ``saved_at`` is what save_last_summary returned for this scan."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    if _is_fake(report):
        return "skipped"  # CLO-1057: sample data: nothing asked, nothing sent
    try:
        settings = read_settings(env)
        verdict = decide(settings, can_prompt=_isatty(stdin) and _isatty(stdout))
        if verdict == "skip":
            return "skipped"
        try:
            url = share_url(env)
        except ShareUrlRefused as e:
            print(e, file=stderr)
            return "skipped"
        sender = sender or (lambda p: send(p, url=url))
        if verdict == "send":
            outcome = _send_marked(settings_payload(report, source), sender, saved_at)
            if outcome in (ALREADY_SHARED, ALREADY_TRIED, NOT_MARKED):
                print(_held_line(outcome), file=stderr)
                return "already" if outcome != NOT_MARKED else NOT_MARKED
            ok = outcome == "sent"
            print("Shared a summary with CloudWise "
                  f"({ENV_SHARE}=no or `cloudcostwise share --off` turns this off)." if ok else SENT_UNSURE,
                  file=stderr)
            return "sent" if ok else "failed"
        return _prompt(report, source, stdin, stderr, sender, saved_at)
    except (EOFError, KeyboardInterrupt):
        return "declined"
    except Exception:  # noqa: BLE001 - sharing must never fail a scan
        return "skipped"


def _email_flow(base: Dict[str, Any], stdin, out) -> Optional[Dict[str, Any]]:
    """After a y: the optional address and its two requests. The payload to send, or None if the human
    declined at the final confirmation."""
    email = _ask("Email address (optional, Enter to skip): ", stdin, out)
    if not email:
        return base
    print(f"\n{EMAIL_REPORT_WORDING}", file=out)
    want_report = _yes(_ask("Email me about this report? [y/N] ", stdin, out))
    print(f"\n{NEW_CHECKS_WORDING}", file=out)
    want_updates = _yes(_ask("Tell me when new checks land? [y/N] ", stdin, out))
    payload = _with_email(base, email=email, email_report=want_report, new_checks=want_updates)
    if "email" not in payload:
        print("No email option chosen, so the address is not sent.", file=out)
        return payload
    print("\nFinal payload:", file=out)
    print(json.dumps(payload, indent=2), file=out)
    if not _yes(_ask("Send? [y/N] ", stdin, out)):
        return None
    return payload


def _prompt(report, source: str, stdin, stderr, sender, saved_at: Any = _FIND) -> str:
    if _is_fake(report):
        return "skipped"  # CLO-1057: before it can record that the human was asked
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

    payload = _email_flow(base, stdin, stderr)
    if payload is None:
        print("Not shared.", file=stderr)
        return "declined"
    outcome = _send_marked(payload, sender, saved_at)
    if outcome in (ALREADY_SHARED, ALREADY_TRIED, NOT_MARKED):
        print(_held_line(outcome), file=stderr)
        return "already" if outcome != NOT_MARKED else NOT_MARKED
    ok = outcome == "sent"
    print("Shared. Thank you." if ok else SENT_UNSURE, file=stderr)
    return "sent" if ok else "failed"


# --- `cloudcostwise share --last` (CLO-1055) ---------------------------------------------------------

def share_last(*, stdin=None, stdout=None, stderr=None, env: Optional[Dict[str, str]] = None,
               sender: Optional[Callable[[Dict[str, Any]], Any]] = None) -> int:
    """Show the last scan's saved summary and send it only on a y typed in a terminal.

    Refuses unless stdin and stdout are both TTYs. There is deliberately no flag, environment variable
    or setting that answers for the human: CLOUDCOSTWISE_SHARE=yes does not skip this prompt. The prompt
    goes to stdout, the stream checked to be a terminal, so what is shown is what the human sees."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    if not (_isatty(stdin) and _isatty(stdout)):
        print(LAST_NO_TERMINAL, file=stderr)
        return 2
    record = load_last_summary()
    if record is None:
        text = LAST_UNUSABLE if last_summary_path().exists() else LAST_NO_SUMMARY
        print(text.format(path=last_summary_path()), file=stdout)
        return 1
    if record["send_attempted_at"] is not None:
        print(LAST_ALREADY_SHARED if record["sent_ok"] is True else LAST_ALREADY_TRIED, file=stdout)
        return 0
    try:
        url = share_url(env)
    except ShareUrlRefused as e:
        print(e, file=stderr)
        return 1
    base = summary_payload(record)
    try:
        answer = _ask(LAST_PROMPT.format(where="MCP" if record["source"] == "mcp" else "the CLI",
                                         when=_local_minutes(record["saved_at"]),
                                         payload=json.dumps(base, indent=2)), stdin, stdout)
        payload = _email_flow(base, stdin, stdout) if _yes(answer) else None
    except (EOFError, KeyboardInterrupt):
        print("", file=stdout)
        payload = None
    if payload is None:
        print(LAST_DECLINED, file=stdout)
        return 0
    # The attempt is recorded before the send, under the lock: of two terminals at this prompt only one
    # gets to send, and a summary that cannot be marked is not sent at all.
    state = mark_attempt(record)
    if state in (ALREADY_SHARED, ALREADY_TRIED):
        print(_already_line(state), file=stdout)
        return 0
    if state != MARKED:
        print(LAST_NOT_MARKED.format(path=last_summary_path()), file=stderr)
        return 1
    ok = bool((sender or (lambda p: send(p, url=url)))(payload))
    record_result(record, ok)
    print(LAST_SENT if ok else NOT_CONFIRMED, file=stdout)
    return 0 if ok else 1


def _summary_status() -> str:
    record = load_last_summary()
    if record is None:
        if last_summary_path().exists():
            return f"Saved summary: {last_summary_path()} is not a summary a scan wrote; `share --last` ignores it"
        return f"Saved summary: none ({last_summary_path()})"
    where = "MCP" if record["source"] == "mcp" else "the CLI"
    if record["send_attempted_at"] is None:
        shared = "not shared (`cloudcostwise share --last` shows it)"
    elif record["sent_ok"] is True:
        shared = "shared"
    else:
        shared = "a send was attempted, and CloudWise did not confirm it arrived"
    return f"Saved summary: last scan, from {where}, {_local_minutes(record['saved_at'])}: {shared}"


def status_text(settings: Optional[Settings] = None) -> str:
    s = settings or read_settings()
    state = {True: "on (a summary is sent after each scan)", False: "off (never asked, never sent)",
             None: "ask once in an interactive terminal" if not s.asked else "not asked again (already answered)"}[s.share]
    return "\n".join([
        f"Shared scan: {state}",
        f"Setting source: {ENV_SHARE} in the environment, else {config_path()}",
        "Sent when on: CLI version, number of findings, estimated monthly savings, checks run, and whether "
        "the scan ran in the CLI or MCP. "
        "Never account IDs, resource IDs or names, regions, ARNs or tags, and never an email address: "
        "an address is only ever asked for at an interactive prompt.",
        _summary_status(),
    ])


def command(args, *, stdin=None, stdout=None, stderr=None) -> int:
    """`cloudcostwise share --on|--off|--status|--reset|--last`."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    if getattr(args, "last", False):
        return share_last(stdin=stdin, stdout=stdout, stderr=stderr)
    cfg = load_config()
    if args.on:
        # A person types this at a terminal. A script or an AI assistant's non-interactive shell
        # must not turn consent on, and the refusal does not say how else it could be done.
        if not (_isatty(stdin) and _isatty(stdout)):
            print(ON_NO_TERMINAL, file=stderr)
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
    # CLO-1055: off also deletes the saved summary. Later scans save a new one, which only
    # `share --last` (asked in a terminal) can send, or a later scan's automatic send if
    # CLOUDCOSTWISE_SHARE=yes is set in the environment (it wins over share.json).
    if args.off and not delete_last_summary():
        print(f"cloudcostwise: could not delete {last_summary_path()}", file=stderr)
        return 1
    print(status_text(), file=stdout)
    return 0
