"""CLO-1057: demo mode. A recorded scan of CloudWise's own test account, shown instead of calling AWS.

``scan --demo`` and the MCP ``scan`` tool's ``demo`` parameter print this recording. It makes no AWS
call, reads no credentials and touches no network. Every identifier in it is a placeholder
(``demo_scan.json`` is built from frontend/src/data/sample-scan.json by
scripts/sample_scan/build_demo_scan.py). The report is flagged ``demo=True``: every output says it is
sample data, and it can never be shared (share.py refuses it on every path).
"""

from __future__ import annotations

import json
from importlib import resources
from typing import List

from cloudcostwise.scan import ScanReport

DEMO_ACCOUNT = "demo-account"
# First and last line of every table and markdown output, and the note on every MCP tool result.
BANNER_TOP = ("SAMPLE DATA (demo mode): this is a recorded scan of a CloudWise test account, not your AWS "
              "account. No AWS call was made.")
CARD_MARK = "SAMPLE DATA (demo mode, not your account)"
BANNER_BOTTOM = "SAMPLE DATA (demo mode): none of the findings above are from your AWS account."
# Text for the assistant behind the MCP server.
MCP_NOTE = ("SAMPLE DATA (demo mode): this is a recorded scan of a CloudWise test account with every identifier "
            "replaced by a placeholder, not the user's AWS account, and no AWS call was made. Tell the user "
            "this is sample data, and say so whenever you quote or summarize it.")
JSON_NOTE = ("Sample data: a recorded scan of a CloudWise test account with every identifier replaced by a "
             "placeholder. It is not your AWS account and no AWS call was made.")
IGNORED_IN_MCP = ("profile, regions and include_cost_explorer are ignored in demo mode: the recording was made "
                  "with Cost Explorer off and nothing is scanned.")


def _load_raw() -> dict:
    return json.loads(resources.files("cloudcostwise").joinpath("demo_scan.json").read_text(encoding="utf-8"))


def load_report() -> ScanReport:
    """The recording as a ScanReport (``demo=True``). Reads one packaged file; nothing else."""
    from cloudwise_scan_core.models import ConfidenceLevel, ResourceType, WasteItem, WasteType

    from cloudcostwise.scan import service_class

    raw = _load_raw()
    items: List[WasteItem] = []
    for n, f in enumerate(raw["findings"], 1):
        items.append(WasteItem(
            id=f"demo-{n:03d}", resource_id=f["resource"], resource_type=ResourceType.OTHER,
            waste_type=WasteType(f["wasteType"]), title=f["title"], description="",
            monthly_savings=float(f["monthlySavings"]), confidence=ConfidenceLevel(f["confidence"]),
            action=f["action"], action_command=f["actionCommand"], explanation=dict(f["explanation"]),
            region=f["region"], account_id=DEMO_ACCOUNT))
    return ScanReport(
        account_id=DEMO_ACCOUNT, regions=list(raw["regions"]), findings=items,
        # The checks a no-Cost-Explorer scan runs, read from the engine, as a real scan reports them.
        entrypoints=len(service_class(False).DETECTOR_METHODS), cost_explorer_skipped=True, demo=True)
