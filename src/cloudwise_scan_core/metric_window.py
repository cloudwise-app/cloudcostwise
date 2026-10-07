"""Keep a cluster's CloudWatch window to the cluster's own lifetime (CLO-457).

CloudWatch dimensions like ``DBClusterIdentifier`` are NAMES, not immutable
resource ids. Delete a cluster and create another under the same name (a
restore, a blue/green swap, a Terraform replace, a recreated fixture) and the
new cluster's metric window silently includes the deleted one's datapoints,
for the whole lookback. Measured on ``cwfx-idle-documentdb`` (CLO-435): the
7-day window held two hours from a cluster deleted the day before, one of them
peaking at 52.1% CPU.

When the provider knows the cluster's creation time, it does two things:

* :func:`metric_start_time` starts the query at the creation time instead of
  ``end - days``, so CloudWatch aggregates nothing from before it. This is the
  only defence for a statistic read as ONE window-long datapoint (Neptune's
  request Sums), which has no timestamp to filter on.
* :func:`drop_pre_creation_datapoints` then drops every datapoint whose period
  ENDED at or before the creation time, before any statistic is computed.
  A bucket that straddles the creation time is kept: it holds the new
  cluster's first minutes (e.g. its boot).

The coverage and minimum-age gates (``cpu_sizing``) still measure against the
full window, so a young cluster is judged on fewer hours, not a shorter week.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, List, Mapping, Optional


def _as_utc(value: Any) -> Optional[datetime]:
    """A datetime (naive read as UTC) or an ISO-8601 string, else None."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def metric_start_time(end_time: datetime, days: int, created: Any) -> datetime:
    """The query's StartTime: ``end_time - days``, or the cluster's creation
    time when that falls inside the window. Unknown creation time (None, or
    anything that is not a datetime) changes nothing."""
    start = end_time - timedelta(days=days)
    created_at = _as_utc(created)
    if created_at is not None and start < created_at < end_time:
        return created_at
    return start


def drop_pre_creation_datapoints(
    datapoints: Iterable[Mapping[str, Any]],
    created: Any,
    period_seconds: int,
) -> List[Mapping[str, Any]]:
    """Drop the datapoints that belong wholly to before the cluster existed:
    those whose bucket ``[Timestamp, Timestamp + period)`` ended at or before
    ``created``. Unknown creation time keeps everything, and so does a
    datapoint with no readable Timestamp (there is nothing to judge it by)."""
    dps = list(datapoints)
    created_at = _as_utc(created)
    if created_at is None:
        return dps
    period = timedelta(seconds=period_seconds)
    kept = []
    for dp in dps:
        ts = _as_utc(dp.get('Timestamp'))
        if ts is not None and ts + period <= created_at:
            continue
        kept.append(dp)
    return kept


def trim_to_recent_window(
    datapoints: Iterable[Mapping[str, Any]],
    window_days: int,
    period_seconds: int,
    anchor: Any = None,
) -> List[Mapping[str, Any]]:
    """CLO-572: keep only the points within ``window_days`` of ``anchor``
    (the export's own ``manifest.export_timestamp`` when the caller has
    one), or the series' OWN latest Timestamp when it does not -- never
    wall-clock ``now``: an export is read long after it was collected, so a
    ``now``-anchored trim would turn every upload into MISSING. The export
    timestamp is preferable when available: it is when collection actually
    ended, so it still anchors correctly even for a series whose own latest
    point is itself a few hours stale (a slow metric, a throttled read).

    The offline export can collect more CloudWatch history than a
    detector's window asks for (a longer ``cloudwatch_period_days``, or the
    window becoming configurable later). Without this, those older hours
    would silently widen the average/coverage with data outside the window
    the finding claims. No usable anchor -- no ``anchor`` given AND no
    readable Timestamp in the series (or no points at all) -- keeps
    everything, the same fail-open convention as
    :func:`drop_pre_creation_datapoints` (whose cutoff this delegates to).

    With no explicit anchor, the cutoff is ``latest + period - window_days``:
    ``window_days`` worth of whole ``period_seconds`` buckets ending one
    period after the latest Timestamp (the end of the last bucket), not
    plain ``latest - window_days``. That bare subtraction would also keep a
    169th hourly point for a 7-day/168-hour window -- its bucket
    ``[ts, ts + period)`` straddles the ``latest - window_days`` instant, and :func:`drop_pre_creation_datapoints` only drops a bucket
    that ENDS at or before the cutoff. Shifting the cutoff forward by one
    period puts that straddling bucket's end exactly ON the cutoff, so it
    is dropped like any other bucket that ended too early. An explicit
    ``anchor`` is an instant (when collection ended), not a bucket start,
    so it uses plain ``anchor - window_days`` (PR #1620 review)."""
    dps = list(datapoints)
    if window_days <= 0:
        return dps
    anchor_at = _as_utc(anchor)
    if anchor_at is not None:
        # An explicit anchor (the export's end time) is an instant, not the
        # start of a bucket, so the window is simply [anchor - window, anchor).
        window_start = anchor_at - timedelta(days=window_days)
    else:
        timestamps = [t for t in (_as_utc(dp.get('Timestamp')) for dp in dps) if t is not None]
        if not timestamps:
            return dps
        # The series' latest Timestamp is the START of its last bucket, so
        # the window ends one period later (see the docstring).
        window_start = max(timestamps) + timedelta(seconds=period_seconds) - timedelta(days=window_days)
    return drop_pre_creation_datapoints(dps, window_start, period_seconds)
