"""CLO-929: a copy of a ScanReport with the identifiers it recognizes replaced.

``--anonymize`` swaps what identifies the account or its resources for stable
placeholders (account-1, resource-1, ...): the same value always gets the same
placeholder within one report. Waste type, validation level, region, savings,
confidence, action wording, warnings and counts are kept. It runs locally on the
finished report; nothing new is sent anywhere.

It is not complete. It replaces the identifiers it recognizes: the account ID,
resource IDs and the names derived from them, name/ID/tag values the scan
recorded for a finding, anything shaped like an ARN or an AWS resource ID, and
the example lists in the snapshot notes. A name it was never told about, in a
form it does not match, stays. Review the file before you send it.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, Iterable, List
from urllib.parse import quote

from cloudwise_scan_core.detectors.open.database import RDS_SNAPSHOT_NOTE_PREFIX
from cloudwise_scan_core.detectors.open.storage import EBS_SNAPSHOT_WITHHELD_NOTE_PREFIXES

from cloudcostwise.scan import ScanReport

# Shortest name taken from a resource ID or metadata and searched for in free text.
# Shorter ones ("a", "db") would also match ordinary words. A full resource_id is
# always replaced, whatever its length.
MIN_DERIVED_NAME = 4
_META_KEY_SUFFIXES = ("name", "arn", "_id", "id", "identifier", "tags")  # matched on the lower-cased key
_ARN = re.compile(r"arn:aws[a-z-]*:[A-Za-z0-9-]*:[A-Za-z0-9-]*:\d{0,12}:[^\s\"'`,;)\]}>]+", re.I)
_ACCOUNT = re.compile(r"(?<!\d)\d{12}(?!\d)")
_AWS_ID = re.compile(
    r"\b(?:snap|vol|i|ami|eni|sg|subnet|vpc|eipalloc|eipassoc|nat|igw|lt|fs|fsap|db|rtb|acl|tgw|vpce|eigw|pcx|"
    r"dopt|cgw|vgw|vpn|lb|key|rds|cluster)-[0-9a-f]{8,17}\b", re.I)
_EDGE = r"(?<![A-Za-z0-9_.-])%s(?![A-Za-z0-9_-])"
_SNAPSHOT_NOTE_PREFIXES = (*EBS_SNAPSHOT_WITHHELD_NOTE_PREFIXES, RDS_SNAPSHOT_NOTE_PREFIX)
_EXAMPLES = re.compile(r"\((?!x\d+\))[^()]*\)")  # the first parenthesised list that is not a "(x3)" count
_REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")


class _Placeholders:
    def __init__(self) -> None:
        self._seen: Dict[str, Dict[str, str]] = {k: {} for k in ("account", "resource", "name", "arn")}

    def get(self, kind: str, value: str) -> str:
        table, key = self._seen[kind], value.lower()
        if key not in table:
            table[key] = f"{kind}-{len(table) + 1}"
        return table[key]


def _strings(value: Any) -> Iterable[str]:
    """String leaves of a metadata value; for tag lists/dicts, the values."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _strings(v)


def _id_names(item) -> List[str]:
    """Names a resource goes by in free text: the end of its ID and any identifier-like part of its
    path (not type words such as "volume" or "app")."""
    rid = str(item.resource_id or "")
    resource_part = rid.split(":", 5)[5] if rid.startswith("arn:") and rid.count(":") >= 5 else rid
    segments = [seg for seg in re.split(r"[/:]", resource_part) if seg]
    return [seg for i, seg in enumerate(segments)
            if len(seg) >= MIN_DERIVED_NAME and (i == len(segments) - 1 or re.search(r"[-_.\d]", seg))]


def _meta_names(item) -> List[str]:
    out: List[str] = []
    for key, value in (getattr(item, "metadata", None) or {}).items():
        if str(key).lower().endswith(_META_KEY_SUFFIXES):
            out += [s for s in _strings(value) if len(s) >= MIN_DERIVED_NAME]
    return out


def _encodings(text: str) -> List[str]:
    once = quote(text, safe="")
    return [e for e in dict.fromkeys([once, quote(once, safe="")]) if e != text]


def anonymize_report(report: ScanReport) -> ScanReport:
    """Return a redacted copy; the original is not touched."""
    from cloudcostwise import render  # groups(): number resources in the order they are printed

    ph = _Placeholders()
    ordered = [i for g in render.groups(report) for i in g.items]

    accounts = {str(a) for a in [report.account_id, *[getattr(i, "account_id", "") for i in ordered]] if a}
    account_literals = {acct: ph.get("account", acct) for acct in sorted(accounts)}
    regions = {r.lower() for r in report.regions} | {str(i.region).lower() for i in ordered if i.region}

    literals: Dict[str, str] = {}  # lower-cased text -> placeholder
    all_ids = {str(i.resource_id).lower() for i in ordered if i.resource_id}
    for item in ordered:
        rid = str(item.resource_id or "")
        if not rid:
            continue
        # An ARN and the bare ID it ends in are one resource.
        tail = re.split(r"[/:]", rid)[-1]
        placeholder = ph.get("resource", tail if tail.lower() in all_ids else rid)
        literals[rid.lower()] = placeholder
        for name in _id_names(item):
            literals.setdefault(name.lower(), placeholder)
    # CLO-931: resources the exclude list hid are still known identifiers, so a warning that names one
    # is scrubbed. They are numbered after the shown ones, and their own list is cleared below.
    hidden = [str(r) for r in (getattr(report, "excluded_resource_ids", None) or []) if r]
    for rid in hidden:
        tail = re.split(r"[/:]", rid)[-1]
        placeholder = ph.get("resource", tail if tail.lower() in all_ids else rid)
        literals.setdefault(rid.lower(), placeholder)
        names = [seg for seg in re.split(r"[/:]", rid) if len(seg) >= MIN_DERIVED_NAME and
                 (seg == tail or re.search(r"[-_.\d]", seg))]
        for name in names:
            literals.setdefault(name.lower(), placeholder)
    # Names the scan recorded that are not part of the ID (a Name tag, a DB identifier) get a placeholder
    # of their own, so two resources sharing one name never read as one resource.
    for item in ordered:
        for name in _meta_names(item):
            low = name.lower()
            if low not in regions and low not in literals and low not in account_literals:
                literals[low] = ph.get("name", name)
    for text, repl in list(literals.items()):
        for enc in _encodings(text):
            literals.setdefault(enc.lower(), repl)

    # Longest first, so a full ARN is replaced whole before the name inside it.
    patterns = [(re.compile(_EDGE % re.escape(text), re.I), repl)
                for text, repl in sorted(literals.items(), key=lambda kv: -len(kv[0]))]

    def scrub(text: Any) -> Any:
        if not isinstance(text, str) or not text:
            return text
        if any(p in text for p in _SNAPSHOT_NOTE_PREFIXES):
            text = _EXAMPLES.sub("(identifiers omitted)", text, count=1)
        for pattern, repl in patterns:
            text = pattern.sub(repl, text)
        text = _ARN.sub(lambda m: ph.get("arn", m.group(0)), text)  # before accounts: an ARN goes whole
        text = _AWS_ID.sub(lambda m: ph.get("resource", m.group(0)), text)
        for acct, repl in account_literals.items():
            text = re.sub(_EDGE % re.escape(acct), repl, text)
        return _ACCOUNT.sub(lambda m: ph.get("account", m.group(0)), text)

    def scrub_permission_error(text: str) -> str:
        """"[region: ]detector: <resource> needs <permission> (<code>)": the resource is whatever the
        scan was reading, so it goes even when no finding names it."""
        if " needs " not in text:
            return scrub(text)
        left, right = text.split(" needs ", 1)
        segs = left.split(": ")
        keep = 2 if len(segs) > 2 and _REGION.match(segs[0]) else 1
        if len(segs) <= keep:
            return scrub(text)
        head, resource = ": ".join(segs[:keep]) + ": ", ": ".join(segs[keep:])
        replaced = scrub(resource)
        if replaced == resource and resource not in ("", "None"):
            replaced = ph.get("resource", resource)
        return f"{head}{replaced} needs {scrub(right)}"

    findings = []
    for item in ordered:
        clean = copy.copy(item)
        clean.resource_id = scrub(str(item.resource_id or ""))
        clean.title = scrub(item.title)
        clean.action = scrub(item.action)
        for attr, empty in (("description", ""), ("action_command", None), ("ai_action_steps", None),
                            ("explanation", None), ("metadata", {}), ("account_id", "")):
            if hasattr(clean, attr):
                setattr(clean, attr, empty)
        findings.append(clean)

    out = copy.copy(report)
    out.account_id = scrub(report.account_id)
    out.findings = findings
    out.excluded_resource_ids = []  # CLO-931: the count stays, the IDs of what was left out never print
    for attr in ("warnings", "errors", "coverage_notes"):
        setattr(out, attr, [scrub(s) for s in getattr(report, attr)])
    out.permission_errors = [scrub_permission_error(s) for s in report.permission_errors]
    return out
