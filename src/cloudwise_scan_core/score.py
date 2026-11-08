"""One cost-health score, computed the same way everywhere (CLO-858).

The CLI and the MCP server import this. It copies, on purpose and without
change, the formula in ``backend/app/services/score_share_service.py``
(``compute_score``) and the tone bands in ``backend/app/models/score_share.py``
(``tone_for_score``); ``tests/score_cases.py`` holds fixed cases the backend can
reuse to prove both stay equal. Pure functions, no imports from the rest of the
package, so it ships in the open core as is.

With a monthly spend figure the score is the waste share of spend:

    ratio = clamp(waste / spend, 0, 1)
    value = round(100 * (1 - min(ratio, 0.6) / 0.6))

Without one (spend unknown, or zero) it is a gentle curve on the dollars alone:
100 for no waste, ``20 + 80 / (1 + waste / 2500)`` otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

Basis = Literal["spend", "no_spend"]
Tone = Literal["celebratory", "neutral", "urgent"]


@dataclass(frozen=True)
class Score:
    value: int
    basis: Basis
    tone: Tone


def tone_for(value: int) -> Tone:
    if value >= 80:
        return "celebratory"
    if value >= 45:
        return "neutral"
    return "urgent"


def compute_score(waste_monthly: float, spend_monthly: Optional[float]) -> Score:
    waste = max(0.0, float(waste_monthly or 0.0))
    if spend_monthly and spend_monthly > 0:
        ratio = min(waste / float(spend_monthly), 1.0)
        value = int(round(100 * (1 - min(ratio, 0.6) / 0.6)))
        return Score(value, "spend", tone_for(value))
    if waste <= 0:
        return Score(100, "no_spend", tone_for(100))
    value = int(round(max(0.0, min(100.0, 20 + 80 * (1.0 / (1.0 + waste / 2500.0))))))
    return Score(value, "no_spend", tone_for(value))
