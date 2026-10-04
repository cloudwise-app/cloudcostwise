"""The shared CPU rule for "this database is bigger than it needs to be".

CLO-455 (PR #1452) settled the rule for ``overprovisioned_documentdb``; CLO-480
applies the same rule to ``oversized_neptune`` and ``oversized_opensearch``.
It lives here, once, so the detectors cannot drift apart.

Why the rule looks like this
----------------------------
The detectors used to gate on the window MAXIMUM of CPU: the single highest
hourly (or daily) ``Maximum`` in the lookback window had to be under a
threshold. One boot hour, one maintenance window or one nightly batch job
therefore vetoed the finding for the whole window (a DocumentDB cluster's
own boot measured 52-64%, CLO-435). Rightsizing is a claim about *sustained*
utilisation, and a window maximum does not measure that.

All of these must hold, over HOURLY (Period=3600) ``CPUUtilization``
datapoints read with ``Statistics=['Average', 'Maximum']``:

* ``avg_cpu`` (the mean of the hourly Averages) < ``avg_threshold``;
* ``p95_cpu`` (nearest-rank p95 of the hourly Averages) < ``p95_avg_threshold``:
  at least 95% of the hours averaged under it, so load in more than 5% of the
  hours (8+ of 168) still vetoes;
* ``p95_max_cpu`` (nearest-rank p95 of the hourly Maximums) <
  ``p95_max_threshold``: the burst guard. The cluster/domain-level metric
  aggregates instances or nodes, so its Average dilutes a hot primary with idle
  replicas while its Maximum still shows the hot one;
* at least ``min_coverage`` (75%) of the window's hours carry a datapoint. A
  percentile of a handful of hours says nothing about a week, and zero
  datapoints vetoes rather than reading as 0% CPU.

The detector additionally requires the resource to be at least as old as the
window (CLO-233's minimum-age rule, :func:`resource_age_days`), because a
reused identifier inherits a deleted resource's datapoints (CLO-457) and can
satisfy coverage while being brand new. Unknown age counts as old.

``max_cpu`` (the window's single highest reading) is still computed and
reported. It no longer gates.
"""

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

CPU_PERCENTILE = 95.0
MIN_CPU_COVERAGE = 0.75  # fraction of the window's hours with a CPU datapoint
HOURS_PER_DAY = 24

# Sentinel age for "creation time unknown": old enough for any window. The
# same value, and the same convention, as database.UNKNOWN_RESOURCE_AGE_DAYS.
UNKNOWN_RESOURCE_AGE_DAYS = 999


def nearest_rank_percentile(values: List[float], pct: float) -> float:
    """Nearest-rank percentile: the smallest value with at least ``pct`` percent
    of the values at or below it. Always one of the inputs, never interpolated,
    and equal to max(values) whenever len(values) < 100 / (100 - pct)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100.0 * len(ordered)))
    return ordered[rank - 1]


def min_cpu_datapoints(window_days: int, min_coverage: float = MIN_CPU_COVERAGE) -> int:
    """Hourly datapoints needed for ``min_coverage`` of a ``window_days`` window
    (126 of 168 for 7 days, 252 of 336 for 14)."""
    return min_coverage_datapoints(window_days, 3600, min_coverage)


def min_coverage_datapoints(
    window_days: int,
    period_seconds: int = 3600,
    min_coverage: float = MIN_CPU_COVERAGE,
) -> int:
    """Datapoints of ``period_seconds`` needed for ``min_coverage`` of a
    ``window_days`` window: 126 of 168 hourly for 7 days, 6 of 7 daily.

    CLO-485: the same coverage rule, applied to an idle claim. "0 connections
    for 7 days" read off a series with no datapoints (a new region, a metrics
    outage, a read that failed) is not a measurement of zero, it is no
    measurement. At least ``min_coverage`` of the window must be observed, and
    zero datapoints never passes."""
    periods = window_days * 86400 / period_seconds
    return max(1, math.ceil(periods * min_coverage))


def has_min_coverage(
    datapoints: int,
    window_days: int,
    period_seconds: int = 3600,
    min_coverage: float = MIN_CPU_COVERAGE,
) -> bool:
    """True when ``datapoints`` covers ``min_coverage`` of the window (see
    :func:`min_coverage_datapoints`). Zero datapoints is always False."""
    return datapoints > 0 and datapoints >= min_coverage_datapoints(
        window_days, period_seconds, min_coverage,
    )


@dataclass(frozen=True)
class CpuSizingThresholds:
    """Per-detector thresholds for the rule. Percent CPU, strict ``<``."""
    avg_threshold: float
    p95_avg_threshold: float
    p95_max_threshold: float
    percentile: float = CPU_PERCENTILE
    min_coverage: float = MIN_CPU_COVERAGE


@dataclass(frozen=True)
class HourlyCpuStats:
    """What the rule reads from a window of hourly CPU datapoints. Unrounded:
    callers round for display, the gate compares the raw values."""
    avg_cpu: float
    max_cpu: float
    p95_cpu: float
    p95_max_cpu: float
    datapoints: int


def summarize_hourly_cpu(
    datapoints: Iterable[Mapping[str, Any]],
    percentile: float = CPU_PERCENTILE,
) -> HourlyCpuStats:
    """Summarise CloudWatch ``GetMetricStatistics`` datapoints carrying
    ``Average`` and ``Maximum``. A missing statistic reads as 0."""
    dps = list(datapoints)
    avg_cpu = sum(dp.get('Average', 0) for dp in dps) / len(dps) if dps else 0.0
    max_cpu = max((dp.get('Maximum', 0) for dp in dps), default=0.0)
    p95_cpu = nearest_rank_percentile([dp.get('Average', 0.0) for dp in dps], percentile)
    p95_max_cpu = nearest_rank_percentile([dp.get('Maximum', 0.0) for dp in dps], percentile)
    return HourlyCpuStats(
        avg_cpu=avg_cpu,
        max_cpu=max_cpu,
        p95_cpu=p95_cpu,
        p95_max_cpu=p95_max_cpu,
        datapoints=len(dps),
    )


def cpu_is_low_enough(
    avg_cpu: float,
    p95_cpu: float,
    p95_max_cpu: float,
    datapoints: int,
    window_days: int,
    thresholds: CpuSizingThresholds,
) -> bool:
    """The CPU half of the rule: coverage, the mean, and both percentiles.

    Takes plain numbers, not :class:`HourlyCpuStats`, so a detector can apply
    it to the fields a metrics model already carries."""
    return (
        avg_cpu < thresholds.avg_threshold
        and datapoints >= min_cpu_datapoints(window_days, thresholds.min_coverage)
        and p95_cpu < thresholds.p95_avg_threshold
        and p95_max_cpu < thresholds.p95_max_threshold
    )


def resource_age_days(created: Any, now: Optional[datetime] = None) -> int:
    """Whole days since ``created`` (truncated, like ``timedelta.days``).

    Anything that is not a ``datetime`` (None, or a boolean like OpenSearch's
    ``Created`` creation-status flag) is unknown and returns
    :data:`UNKNOWN_RESOURCE_AGE_DAYS`, so an unknown age never suppresses a
    finding (CLO-233's convention). A naive datetime is read as UTC."""
    if not isinstance(created, datetime):
        return UNKNOWN_RESOURCE_AGE_DAYS
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return ((now or datetime.now(timezone.utc)) - created).days


def summarize_ecs_utilization(datapoints: List[Dict[str, Any]]) -> Dict[str, float]:
    """CLO-546: ``{'average', 'maximum'}`` for oversized_ecs_task /
    oversized_ecs_memory from hourly datapoints: the mean of the Averages and
    the max of the Maximums, independent of datapoint order (CloudWatch
    promises none). A statistic absent from every datapoint reads 100, i.e.
    not under-utilised. Coverage is the caller's check (``has_min_coverage``)."""
    avgs = [float(dp['Average']) for dp in datapoints if dp.get('Average') is not None]
    maxes = [float(dp['Maximum']) for dp in datapoints if dp.get('Maximum') is not None]
    return {
        'average': sum(avgs) / len(avgs) if avgs else 100.0,
        'maximum': max(maxes) if maxes else 100.0,
    }


def is_as_old_as_window(created: Any, window_days: int, now: Optional[datetime] = None) -> bool:
    """CLO-233's minimum-age rule: a claim about a ``window_days`` window needs
    a resource that existed for all of it. Unknown age counts as old."""
    return resource_age_days(created, now) >= window_days


# ---------------------------------------------------------------------------
# CLO-493: idle_ec2's CPU rule.
#
# An idle verdict is a claim that the instance did no work in the window, and
# its fix is to stop it. The mean alone cannot carry that claim: a nightly
# batch host (90% for one hour a day), a burstable instance spending credits
# in bursts, or a bastion used an hour a day can all average under 5%. The
# rule therefore reads hourly (Period=3600) Average and Maximum datapoints and
# needs, besides the mean and the 75% coverage the provider checks:
#
# * p95 of the hourly Averages under 10%: load in more than 5% of the hours
#   (17+ of 336) vetoes;
# * p95 of the hourly Maximums under 20%: the burst guard the Averages lose,
#   the same statistic #1452/#1466 use for the database sizing rules, at an
#   idle-level ceiling rather than their 50%;
# * the window's single highest hourly Maximum under 50%: unlike rightsizing,
#   a stop claim is broken by ONE heavy job, so a nightly batch run or a
#   credit burst vetoes the whole window. This is stricter than the sizing
#   rule on purpose (precision before recall).
#
# Not derived from measurements of idle instances per family; they are
# ceilings well above an idle Linux host's 1-3% and well below any real job.
# ---------------------------------------------------------------------------
EC2_IDLE_P95_AVG_CPU_THRESHOLD = 10.0
EC2_IDLE_P95_MAX_CPU_THRESHOLD = 20.0
EC2_IDLE_MAX_CPU_THRESHOLD = 50.0


def ec2_cpu_is_idle(
    avg_cpu: float,
    p95_cpu: float,
    p95_max_cpu: float,
    max_cpu: float,
    avg_threshold: float,
) -> bool:
    """idle_ec2's CPU gate (coverage is checked by the provider)."""
    return (
        avg_cpu < avg_threshold
        and p95_cpu < EC2_IDLE_P95_AVG_CPU_THRESHOLD
        and p95_max_cpu < EC2_IDLE_P95_MAX_CPU_THRESHOLD
        and max_cpu < EC2_IDLE_MAX_CPU_THRESHOLD
    )

