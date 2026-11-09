"""CLO-931: a local exclude list that survives the next scan.

``cloudcostwise exclude add <resource-id-or-arn>`` records a resource you have decided to keep
(a bucket that looks idle but is not, a volume you retain on purpose). Every later scan leaves any
finding for that resource out of its output and its totals and says how many it left out.

The list is one file, ``exclude.json``, next to ``share.json`` (``share.config_path()``, so wherever
that lives, this lives). It is read from disk on every scan, so it survives a new process. It is
never sent anywhere: nothing here touches the network, and the opt-in shared summary
(``share.py``) never reads it. A missing file is an empty list; a file that cannot be read or
parsed is treated as empty with a warning on stderr, and a scan never fails because of it.
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cloudcostwise import share

SCHEMA_VERSION = 1
LIST_HINT = "cloudcostwise exclude list"


def exclude_path() -> Path:
    """Beside share.json, so the same config directory (and any override of it) applies."""
    return share.config_path().parent / "exclude.json"


@dataclass
class Entry:
    id: str
    reason: str = ""
    added: str = ""


def _parse(data: Any) -> List[Entry]:
    raw = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise ValueError("expected an object with an 'entries' list")
    out: List[Entry] = []
    for e in raw:
        if isinstance(e, str):
            e = {"id": e}
        if not isinstance(e, dict) or not isinstance(e.get("id"), str) or not e["id"].strip():
            raise ValueError("every entry needs a non-empty 'id'")
        out.append(Entry(e["id"].strip(), str(e.get("reason") or ""), str(e.get("added") or "")))
    return out


def load(warn: bool = True) -> Tuple[List[Entry], Optional[str]]:
    """(entries, problem). A missing file is ([], None). A corrupt one is ([], message), with the
    message also printed to stderr when ``warn``. Never raises."""
    path = exclude_path()
    try:
        text = path.read_text()
    except FileNotFoundError:
        return [], None
    except Exception as e:  # unreadable, not UTF-8, a directory ...: never let it reach a scan
        problem = f"could not read {path}: {e}"
    else:
        try:
            return _parse(json.loads(text)), None
        except Exception as e:  # bad JSON, wrong shape, nested too deep (RecursionError)
            problem = f"{path} is not a valid exclude list ({type(e).__name__}: {str(e)[:80]})"
    if warn:
        print(f"cloudcostwise: warning: {problem}. Treating the exclude list as empty for this run; "
              f"fix or delete the file.", file=sys.stderr)
    return [], problem


def _save(entries: List[Entry]) -> None:
    path = exclude_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {"version": SCHEMA_VERSION,
            "entries": [{"id": e.id, "reason": e.reason, "added": e.added} for e in entries]}
    # Write beside the target, then replace: a crash never leaves a half-written list.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".exclude-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(body, indent=2) + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


_AWS_ID = re.compile(r"^[a-z]+(-[a-z]+)*-[0-9a-f]{8,17}$")
_ELB = re.compile(r"^loadbalancer/(?:app|net|gwy)/([^/]+)/[^/]+$")


def _is_arn(rid: str) -> bool:
    return rid.startswith("arn:") and rid.count(":") >= 5


def _arn_service_and_name(arn: str) -> Tuple[str, str]:
    """(service, resource name) of an ARN: the last non-empty segment of the resource part,
    split on / and :, after a trailing ":*" is dropped. Two shapes are special: a load balancer
    (``loadbalancer/app|net/<name>/<hash>`` is named by <name>, not the hash) and a log group
    (``log-group:/aws/x:*`` is named by the whole group name, slashes included)."""
    parts = arn.split(":", 5)
    service, res = parts[2], parts[5]
    if res.endswith(":*"):
        res = res[:-2]
    if service == "elasticloadbalancing":
        m = _ELB.match(res)
        if m:
            return service, m.group(1)
    if service == "logs" and res.startswith("log-group:"):
        return service, res[len("log-group:"):]
    segs = [x for x in re.split(r"[/:]", res) if x]
    return service, (segs[-1] if segs else res)


def matches(entry_id: str, resource_id: str) -> bool:
    """True when ``entry_id`` names ``resource_id``.

    - the same string always matches;
    - an ARN entry matches a finding whose ID is that resource's name (detectors report an RDS
      instance, a Lambda function, a log group or a load balancer by its bare name), or an ARN
      of the same service and name;
    - a bare entry matches a finding that carries an ARN only when it is AWS-shaped
      (``vol-0abc...``, ``snap-...``, ``i-...``); a plain name such as ``default`` or ``mydb``
      matches only an identical ID, so it cannot hide unrelated resources.
    """
    entry_id, resource_id = (entry_id or "").strip(), (resource_id or "").strip()
    if not entry_id or not resource_id:
        return False
    if entry_id == resource_id:
        return True
    e_arn, r_arn = _is_arn(entry_id), _is_arn(resource_id)
    if e_arn:
        service, name = _arn_service_and_name(entry_id)
        if not r_arn:
            return resource_id == name
        return _arn_service_and_name(resource_id) == (service, name)
    if r_arn:
        return bool(_AWS_ID.match(entry_id)) and _arn_service_and_name(resource_id)[1] == entry_id
    return False


def apply(report, entries: Optional[List[Entry]] = None):
    """A copy of ``report`` without the findings the list names. ``excluded_count`` and
    ``excluded_resource_ids`` record what was left out; the original is not touched. Every total
    (savings, score, grid, share summary) is computed from ``findings``, so they all see the same
    reduced list."""
    if entries is None:
        entries, _ = load()
    if not entries:
        return report
    try:
        kept, left = [], []
        for item in report.findings:
            rid = str(getattr(item, "resource_id", "") or "")
            (left if any(matches(e.id, rid) for e in entries) else kept).append(item)
        if not left:
            return report
        out = copy.copy(report)
    except Exception as e:  # a list problem never fails a scan: show everything
        print(f"cloudcostwise: warning: could not apply the exclude list ({type(e).__name__}); showing every finding.",
              file=sys.stderr)
        return report
    out.findings = kept
    out.excluded_count = len(left)
    out.excluded_resource_ids = [str(i.resource_id) for i in left]
    return out


def note(report) -> str:
    """The line under "Left out on purpose", or "" when nothing was left out."""
    n = int(getattr(report, "excluded_count", 0) or 0)
    if not n:
        return ""
    return f"{n} finding{'s' if n != 1 else ''} left out by your exclude list ({LIST_HINT})"


def command(args) -> int:
    action = args.exclude_action
    entries, problem = load(warn=action == "list")
    if action == "list":
        if problem:
            return 1
        if not entries:
            print("The exclude list is empty. Add one with: cloudcostwise exclude add <resource-id-or-arn> [--reason TEXT]")
            return 0
        print(f"{len(entries)} excluded ({exclude_path()}); scans leave these out. "
              "Nothing here is sent to CloudWise.")
        for e in entries:
            print(f"  {e.id}" + (f"  - {e.reason}" if e.reason else ""))
        return 0
    if problem:
        # Writing would replace a file we could not read; leave it for the user to look at.
        print(f"cloudcostwise: warning: {problem}. Not changing it; fix or delete the file first.", file=sys.stderr)
        return 1
    rid = (args.resource_id or "").strip()
    if not rid:
        print("cloudcostwise: give a resource ID or ARN.", file=sys.stderr)
        return 2
    if action == "add":
        today = _dt.date.today().isoformat()
        for e in entries:
            if e.id == rid:
                e.reason = args.reason or e.reason
                break
        else:
            entries.append(Entry(rid, args.reason or "", today))
        try:
            _save(entries)
        except OSError as e:
            print(f"cloudcostwise: could not write {exclude_path()}: {e}", file=sys.stderr)
            return 1
        print(f"Excluded {rid}. Scans will leave it out ({exclude_path()}); `{LIST_HINT}` shows the list.")
        return 0
    # remove: the exact entry, else an entry that names the same resource in the other form
    exact = [e for e in entries if e.id == rid]
    drop = exact or [e for e in entries if matches(e.id, rid) or matches(rid, e.id)]
    if not drop:
        print(f"cloudcostwise: {rid} is not on the exclude list ({LIST_HINT}).", file=sys.stderr)
        return 1
    try:
        _save([e for e in entries if e not in drop])
    except OSError as e:
        print(f"cloudcostwise: could not write {exclude_path()}: {e}", file=sys.stderr)
        return 1
    print("Removed " + ", ".join(e.id for e in drop) + ". Scans will report it again.")
    return 0
