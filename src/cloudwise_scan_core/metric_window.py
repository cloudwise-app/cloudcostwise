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
