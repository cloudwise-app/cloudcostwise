"""Live region board for a terminal (CLO-858).

One line per region (pending, running, done with findings and dollars so far)
and a running "found so far" total, rewritten in place with plain ANSI cursor
movement. No dependency, no colour beyond dim/bold (and none under NO_COLOR),
no bell. Only used when stderr is a TTY; anything else keeps the plain lines.
"""

from __future__ import annotations

import os
import shutil
from typing import List, Optional, TextIO

from cloudcostwise import render

_UP = "\x1b[{n}A"
_CLEAR = "\r\x1b[2K"


def wants_board(stream: TextIO) -> bool:
    """True for an interactive terminal that can take cursor movement."""
    try:
        return bool(stream.isatty()) and os.environ.get("TERM", "") != "dumb"
    except (AttributeError, ValueError):
        return False


class RegionBoard:
    def __init__(self, regions: List[str], parallel: int, stream: TextIO, color: Optional[bool] = None):
        self.regions = list(regions)
        self.parallel = max(1, min(parallel, len(self.regions) or 1))
        self.stream = stream
        self.color = (not os.environ.get("NO_COLOR")) if color is None else color
        self.done: dict = {}
        self.drawn = 0

    # -- state -----------------------------------------------------------
    def _status(self, region: str) -> str:
        if region in self.done:
            res = self.done[region]
            n = len(res.findings)
            money = sum(float(i.monthly_savings or 0) for i in res.findings if not render.is_advisory(i))
            return f"done     {n:>3} finding(s)  ${money:>10,.2f}/mo  {res.seconds:>5.1f}s"
        # Workers take regions in the order given, so the next ones not done are the running ones.
        waiting = [r for r in self.regions if r not in self.done]
        return "running ..." if region in waiting[: self.parallel] else "pending"

    def total(self) -> float:
        return sum(float(i.monthly_savings or 0) for res in self.done.values() for i in res.findings
                   if not render.is_advisory(i))

    def lines(self) -> List[str]:
        width = max(20, shutil.get_terminal_size((80, 24)).columns - 1)
        rows = [f"  [{'x' if r in self.done else ' '}] {r:<15} {self._status(r)}" for r in self.regions]
        rows.append(f"  found so far ${self.total():,.2f}/month")
        out = []
        for i, row in enumerate(rows):
            row = row[:width]  # a wrapped row would break the cursor-up count
            if self.color and i == len(rows) - 1:
                row = f"\x1b[1m{row}\x1b[0m"
            elif self.color and "pending" in row:
                row = f"\x1b[2m{row}\x1b[0m"
            out.append(row)
        return out

    # -- drawing ---------------------------------------------------------
    def draw(self) -> None:
        rows = self.lines()
        if self.drawn:
            self.stream.write(_UP.format(n=self.drawn))
        for row in rows:
            self.stream.write(f"{_CLEAR}{row}\n")
        self.stream.flush()
        self.drawn = len(rows)

    def region_done(self, res) -> None:
        self.done[res.region] = res
        self.draw()
