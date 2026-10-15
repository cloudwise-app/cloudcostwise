"""Open-core part of ``detectors/management.py`` (FSL-1.1-ALv2).

The service entrypoints in ``FREE_TIER_DETECTORS`` and every method they call.
``ManagementDetectorsMixin`` in ``detectors/management.py`` subclasses this mixin and adds the
closed detectors. Moved verbatim from ``detectors/management.py`` (CLO-562).
"""

import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, TYPE_CHECKING
from cloudwise_scan_core.models import WasteItem, WasteDetectionSettings, WasteType, ResourceType, ConfidenceLevel
from cloudwise_scan_core.data_providers.models import merge_beanstalk_statuses
if TYPE_CHECKING:
    from cloudwise_scan_core.data_providers.base import WasteDataProvider

logger = logging.getLogger(__name__)

# CLO-516: the log-group detectors' activity gates.
EMPTY_LOG_GROUP_MIN_DAYS = 30


OLD_LOG_GROUP_MIN_DAYS = 90


OLD_LOG_GROUP_MIN_GB = 0.5


# Share of the detector's timeout the per-group DescribeLogStreams lookups may
# use, counted from the detector's START (listing thousands of groups already
# takes seconds on the 15s API path). A timeout would lose every CloudWatch
# finding, retention ones included, and count as a breaker failure; a lookup
# left over is MISSING (noted in data_warnings), which loses only that group.
_LOG_ACTIVITY_BUDGET_FRACTION = 0.6


_DEFAULT_DETECTOR_TIMEOUT_SECONDS = 15.0


def _log_activity_deadline(started: float) -> float:
    """``time.monotonic()`` instant after which no activity lookup starts.

    Mirrors ``WasteDetectionService._run_detector_with_timeout``: 15s unless
    the runtime raises every detector's cap with
    DETECTOR_TIMEOUT_DEFAULT_SECONDS (the region scanner sets 45)."""
    try:
        timeout = float(os.environ.get("DETECTOR_TIMEOUT_DEFAULT_SECONDS") or 0)
    except ValueError:
        timeout = 0
    if timeout <= 0:
        timeout = _DEFAULT_DETECTOR_TIMEOUT_SECONDS
    return started + timeout * _LOG_ACTIVITY_BUDGET_FRACTION



# CLO-609: log groups another service writes to by name. An empty one whose
# owner still exists is live and quiet (its events expired under
# retention), not orphaned, and the finding carries a delete command.
_LAMBDA_LOG_PREFIX = '/aws/lambda/'
_BEANSTALK_LOG_PREFIX = '/aws/elasticbeanstalk/'

# Lambda@Edge writes /aws/lambda/<origin region>.<function> in every region
# that serves the function; the function itself lives in the origin region,
# so this region's function list can't confirm it either way.
_LAMBDA_EDGE_REPLICA_RE = re.compile(r'^[a-z]{2}(?:-gov)?-[a-z]+-\d+\.')

# The Air-Gapped export's --anonymize replaces a log group's whole name
# ("/aws/anon/<hex>" from its ARN, "logg_<hex>" from logGroupName), so its
# owner can't be read. Offline only: online names are the customer's own.
_ANONYMIZED_LOG_GROUP_RE = re.compile(r'^(?:/aws/anon/|logg_)[0-9a-f]{8,16}$')

_OWNER_LIVE = 'live'
_OWNER_UNKNOWN = 'unknown'


def _beanstalk_env_from_log_group(name: str) -> Optional[str]:
    """The environment name in /aws/elasticbeanstalk/<env>/..., or None."""
    if not name.startswith(_BEANSTALK_LOG_PREFIX):
        return None
    env = name[len(_BEANSTALK_LOG_PREFIX):].split('/', 1)[0]
    return env or None


class OpenManagementDetectorsMixin:
    """Open detectors from ``ManagementDetectorsMixin``."""

    async def _detect_cloudwatch_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect CloudWatch-related waste using DataProvider.
        
        Detectors:
        1. Log groups without retention policy (no_retention_log_group)
        2. Log groups with no recent ingestion (old_log_group)
        3. Log groups with excessive retention ≥365 days (excessive_retention_log_group)
        4. Empty log groups — 0 bytes, no event for 30+ days (empty_log_group)
        """
        waste_items = []
        started = time.monotonic()

        try:
            # Get CloudWatch log groups from data provider
            log_groups = await data_provider.get_cloudwatch_log_groups()

            # CLO-382: an empty `/aws/lambda/<fn>` group whose function still
            # exists is not orphaned — it may just be quiet, with its events
            # already expired by retention (METHOD.md pinned decision 3).
            # CLO-609: the same holds for `/aws/elasticbeanstalk/<env>/...`
            # while the environment exists. An owner list the scan could not
            # read in full (a failed or partial ListFunctions /
            # DescribeEnvironments, an export that can't vouch for its list)
            # is MISSING: the group is withheld with a note, never flagged on
            # age alone. Offline, the export's list is used when it can vouch
            # for it (``lambda_functions_complete``); before CLO-609 offline
            # skipped the owner check and flagged on age alone.
            is_offline = data_provider.provider_type == 'offline'
            note_missing = getattr(data_provider, '_note_idle_verdict_missing', None)

            def _withhold(name: str, reason: str) -> None:
                if callable(note_missing):
                    note_missing(
                        'cloudwatch-logs', name, reason,
                        verdict='empty', evidence='log group owners',
                    )

            live_lambda_function_names = None
            if not is_offline or getattr(data_provider, 'lambda_functions_complete', False) is True:
                try:
                    functions = await data_provider.get_lambda_functions()
                    if getattr(data_provider, 'lambda_functions_complete', True):
                        live_lambda_function_names = {fn.function_name for fn in functions}
                except Exception as lambda_err:
                    logger.debug(f"Could not fetch Lambda functions for owner check: {lambda_err}")
                    live_lambda_function_names = None

            # Read only when a 0-byte Beanstalk group exists, so a region
            # without one costs no DescribeEnvironments call here.
            beanstalk_statuses: Optional[Dict[str, str]] = None
            if any(
                g.stored_bytes == 0 and g.log_group_name.startswith(_BEANSTALK_LOG_PREFIX)
                for g in log_groups
            ):
                fetch = getattr(data_provider, 'get_beanstalk_environment_statuses', None)
                statuses = None
                if callable(fetch):
                    try:
                        statuses = await fetch()
                    except Exception as eb_err:
                        logger.debug(f"Could not fetch Beanstalk environments for owner check: {eb_err}")
                        statuses = None
                if statuses is not None:
                    beanstalk_statuses = merge_beanstalk_statuses(statuses.items(), fold_case=True)

            def owner_check(name: str):
                """(state, reason): state is _OWNER_LIVE, _OWNER_UNKNOWN
                (reason says why) or None (no owner by name, or it's gone)."""
                if name.startswith(_LAMBDA_LOG_PREFIX):
                    function = name[len(_LAMBDA_LOG_PREFIX):]
                    if _LAMBDA_EDGE_REPLICA_RE.match(function):
                        return _OWNER_UNKNOWN, "Lambda@Edge replica, function is in its origin region"
                    if live_lambda_function_names is None:
                        return _OWNER_UNKNOWN, "Lambda function list not read in full"
                    if function in live_lambda_function_names:
                        return _OWNER_LIVE, None
                    return None, None
                env = _beanstalk_env_from_log_group(name)
                if env is not None:
                    if beanstalk_statuses is None:
                        return _OWNER_UNKNOWN, "Elastic Beanstalk environment list not read"
                    status = beanstalk_statuses.get(env.lower())
                    if status is not None and status != 'Terminated':
                        return _OWNER_LIVE, None
                    return None, None
                if is_offline and _ANONYMIZED_LOG_GROUP_RE.match(name):
                    return _OWNER_UNKNOWN, "log group name anonymized in export"
                return None, None

            # CLO-516: DescribeLogGroups carries no lastEventTimestamp, so a
            # group's last activity is read from its newest log stream — one
            # DescribeLogStreams call per group, made ONLY for groups the
            # cheap filters below already made candidates: 0 bytes, old
            # enough and not owned by a live Lambda (empty_log_group), or
            # over the size gate and old enough (old_log_group). A group
            # whose activity can't be read is left out of `activity` and is
            # not flagged (MISSING, not zero; the provider notes it).
            now = datetime.now(timezone.utc)

            def age_days(log_group) -> Optional[int]:
                if log_group.creation_time is None:
                    return None
                return (now - log_group.creation_time).days

            lookup: List[str] = []
            for log_group in log_groups:
                if log_group.last_event_time is not None:
                    continue  # already known (an export that carries it)
                age = age_days(log_group)
                if age is None:
                    continue
                stored_gb = (log_group.stored_bytes or 0) / (1024 ** 3)
                empty_candidate = (
                    log_group.stored_bytes == 0
                    and age >= EMPTY_LOG_GROUP_MIN_DAYS
                    and owner_check(log_group.log_group_name)[0] is None
                )
                stale_candidate = stored_gb > OLD_LOG_GROUP_MIN_GB and age > OLD_LOG_GROUP_MIN_DAYS
                if empty_candidate or stale_candidate:
                    lookup.append(log_group.log_group_name)

            activity: Dict[str, Optional[datetime]] = {}
            if lookup:
                activity = await data_provider.get_cloudwatch_log_group_last_activity(
                    lookup, deadline=_log_activity_deadline(started),
                )

            def last_activity(log_group):
                """(known, when): when is None for a group that never
                received an event; known is False when it couldn't be read."""
                if log_group.last_event_time is not None:
                    return True, log_group.last_event_time
                if log_group.log_group_name in activity:
                    return True, activity[log_group.log_group_name]
                return False, None

            for log_group in log_groups:
                log_group_name = log_group.log_group_name
                stored_gb = (log_group.stored_bytes or 0) / (1024 ** 3)
                storage_cost = stored_gb * 0.03
                
                # ── Detector 1: No retention policy ──────────────────────
                if log_group.retention_days is None:
                    if stored_gb > 1:
                        # Large log group without retention - high concern
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=log_group_name,
                            resource_type=ResourceType.CLOUDWATCH_LOG_GROUP,
                            waste_type=WasteType.NO_RETENTION_LOG_GROUP,
                            title="Log Group Without Retention Policy",
                            description=f"Log group '{log_group_name}' ({stored_gb:.1f}GB) has no retention policy and will grow indefinitely.",
                            monthly_savings=storage_cost * 0.5,
                            confidence=ConfidenceLevel.MEDIUM,
                            action="Set a retention policy to automatically delete old logs.",
                            action_command=f"aws logs put-retention-policy --log-group-name '{log_group_name}' --retention-in-days 30",
                            explanation={
                                'detection': f"Log group '{log_group_name}' stores {stored_gb:.1f} GB with no retention policy set.",
                                'threshold': 'Log groups > 1 GB without a retention policy are flagged as high concern.',
                                'pricing': f'CloudWatch Logs storage costs $0.03/GB/month — currently ${storage_cost:.2f}/month and growing.',
                                'why_waste': 'Without a retention policy, logs accumulate indefinitely, causing storage costs to grow without bound.',
                                'risk': 'Setting a 30-day retention is reversible. Old logs beyond the retention window will be deleted automatically.',
                            },
                            metadata={
                                'log_group_name': log_group_name,
                                'stored_gb': round(stored_gb, 2),
                                'storage_cost': round(storage_cost, 2),
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
                    elif log_group.stored_bytes and log_group.stored_bytes > 0:
                        # Small log group without retention - lower concern
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=log_group_name,
                            resource_type=ResourceType.CLOUDWATCH_LOG_GROUP,
                            waste_type=WasteType.NO_RETENTION_LOG_GROUP,
                            title="Log Group Without Retention Policy",
                            description=f"Log group '{log_group_name}' ({stored_gb:.3f}GB) has no retention policy. Logs will accumulate indefinitely.",
                            monthly_savings=max(storage_cost * 0.5, 0.01),
                            confidence=ConfidenceLevel.LOW,
                            action="Set a retention policy to automatically delete old logs.",
                            action_command=f"aws logs put-retention-policy --log-group-name '{log_group_name}' --retention-in-days 30",
                            explanation={
                                'detection': f"Log group '{log_group_name}' stores {stored_gb:.3f} GB with no retention policy set.",
                                'threshold': 'All log groups without a retention policy are flagged — logs will accumulate indefinitely.',
                                'pricing': f'CloudWatch Logs storage costs $0.03/GB/month — currently ${storage_cost:.4f}/month.',
                                'why_waste': 'Even small log groups grow over time. Without retention, storage costs only increase.',
                                'risk': 'Low risk — setting a retention policy is a best practice. Choose a window that matches your debugging needs.',
                            },
                            metadata={
                                'log_group_name': log_group_name,
                                'stored_gb': round(stored_gb, 4),
                                'storage_cost': round(storage_cost, 4),
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
                
                # ── Detector 2: Stale log group (no recent ingestion) ────
                activity_known, last_event = last_activity(log_group)
                if stored_gb > OLD_LOG_GROUP_MIN_GB and activity_known and last_event is not None:
                    days_since_event = (now - last_event).days

                    if days_since_event > OLD_LOG_GROUP_MIN_DAYS:
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=log_group_name,
                            resource_type=ResourceType.CLOUDWATCH_LOG_GROUP,
                            waste_type=WasteType.OLD_LOG_GROUP,
                            title="Stale Log Group",
                            description=f"Log group '{log_group_name}' ({stored_gb:.1f}GB) has had no new logs in {days_since_event} days.",
                            monthly_savings=storage_cost,
                            confidence=ConfidenceLevel.MEDIUM,
                            # CLO-516: plan-only in the catalog until L2.
                            action=(
                                "Delete this log group if no longer needed (export it to S3 first "
                                "if you may need the data). CloudWise offers a plan you review and "
                                "apply for this check, not a one-click fix."
                            ),
                            action_command=f"aws logs delete-log-group --log-group-name '{log_group_name}'",
                            explanation={
                                'detection': f"Log group '{log_group_name}' ({stored_gb:.1f} GB) has not received new logs in {days_since_event} days.",
                                'threshold': 'Log groups with > 0.5 GB and no new events in 90+ days are flagged as stale.',
                                'pricing': f'Storing {stored_gb:.1f} GB of stale logs costs ${storage_cost:.2f}/month with no active use.',
                                'why_waste': 'Stale log groups store data from decommissioned or idle services, wasting storage costs.',
                                'risk': 'Deleting a log group is irreversible. Export to S3 first if you may need the data for compliance.',
                            },
                            metadata={
                                'log_group_name': log_group_name,
                                'days_since_event': days_since_event,
                                'stored_gb': round(stored_gb, 2),
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
                
                # ── Detector 3: Excessive retention (≥365 days) ──────────
                # Only fires when retention IS set (None handled by detector 1)
                if (log_group.retention_days is not None
                        and log_group.retention_days >= 365
                        and stored_gb > 0.1):
                    recommended_retention = 30
                    reduction_factor = 1 - (recommended_retention / log_group.retention_days)
                    estimated_savings = storage_cost * reduction_factor

                    confidence = ConfidenceLevel.HIGH if stored_gb > 10 else ConfidenceLevel.MEDIUM

                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=log_group_name,
                        resource_type=ResourceType.CLOUDWATCH_LOG_GROUP,
                        waste_type=WasteType.EXCESSIVE_RETENTION_LOG_GROUP,
                        title="Excessive Log Retention",
                        description=(
                            f"Log group '{log_group_name}' has {log_group.retention_days}-day retention "
                            f"({stored_gb:.1f} GB stored, ${storage_cost:.2f}/month). "
                            f"Reducing to {recommended_retention} days could save "
                            f"~${estimated_savings:.2f}/month."
                        ),
                        monthly_savings=estimated_savings,
                        confidence=confidence,
                        action=(
                            f"Reduce retention to {recommended_retention} days. "
                            f"Most teams only query logs from the last 7-30 days."
                        ),
                        action_command=(
                            f"aws logs put-retention-policy "
                            f"--log-group-name '{log_group_name}' "
                            f"--retention-in-days {recommended_retention}"
                        ),
                        explanation={
                            'detection': f"Log group '{log_group_name}' has {log_group.retention_days}-day retention with {stored_gb:.1f} GB stored.",
                            'threshold': 'Log groups with retention ≥ 365 days and > 0.1 GB are flagged.',
                            'pricing': f'Currently ${storage_cost:.2f}/month. Reducing to {recommended_retention} days could save ~${estimated_savings:.2f}/month.',
                            'why_waste': 'Most teams only query logs from the last 7-30 days. Retaining 365+ days of logs increases storage costs significantly.',
                            'risk': 'Reducing retention deletes logs older than the new window. Export to S3 first if needed for compliance.',
                        },
                        metadata={
                            'log_group_name': log_group_name,
                            'current_retention_days': log_group.retention_days,
                            'recommended_retention_days': recommended_retention,
                            'stored_gb': round(stored_gb, 2),
                            'storage_cost': round(storage_cost, 2),
                            'estimated_savings': round(estimated_savings, 2),
                            'reduction_factor': round(reduction_factor, 2),
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                
                # ── Detector 4: Empty log group (0 bytes, 30+ days) ──────
                owner, owner_reason = (
                    owner_check(log_group_name) if log_group.stored_bytes == 0 else (None, None)
                )
                if owner == _OWNER_UNKNOWN:
                    # CLO-609: an owner the scan can't confirm gone is
                    # MISSING. Noted only for a group old enough that it
                    # would otherwise have been judged.
                    group_age = age_days(log_group)
                    if group_age is not None and group_age >= EMPTY_LOG_GROUP_MIN_DAYS:
                        _withhold(log_group_name, owner_reason)
                if (
                    log_group.stored_bytes is not None
                    and log_group.stored_bytes == 0
                    and activity_known
                    and owner is None
                ):
                    # days_empty counts from the last event; a group that
                    # never received one counts from its creation.
                    days_empty = None
                    if last_event is not None:
                        days_empty = (now - last_event).days
                    elif log_group.creation_time:
                        days_empty = (now - log_group.creation_time).days

                    if days_empty is not None and days_empty >= EMPTY_LOG_GROUP_MIN_DAYS:
                        description_detail = (
                            f"last received logs {days_empty} days ago"
                            if last_event is not None
                            else f"created {days_empty} days ago, never received logs"
                        )

                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=log_group_name,
                            resource_type=ResourceType.CLOUDWATCH_LOG_GROUP,
                            waste_type=WasteType.EMPTY_LOG_GROUP,
                            title="Empty Log Group",
                            description=(
                                f"Log group '{log_group_name}' is empty (0 bytes) and "
                                f"{description_detail}. "
                                f"This may be an orphaned log group from a deleted service."
                            ),
                            monthly_savings=0.00,
                            confidence=ConfidenceLevel.LOW,
                            action="Delete this empty log group to reduce clutter and free quota.",
                            action_command=(
                                f"aws logs delete-log-group "
                                f"--log-group-name '{log_group_name}'"
                            ),
                            explanation={
                                'detection': f"Log group '{log_group_name}' is 0 bytes and has been empty for {days_empty} days.",
                                'threshold': 'Log groups storing 0 bytes whose newest log stream has had no event for 30+ days (or that never received one and are 30+ days old) are flagged.',
                                'pricing': 'An empty log group costs nothing in storage, but contributes to API and quota limits.',
                                'why_waste': 'Empty log groups are typically orphaned from deleted services and add unnecessary clutter.',
                                'risk': 'Safe to delete. If a service recreates the log group, CloudWatch will create a new one automatically.',
                            },
                            metadata={
                                'log_group_name': log_group_name,
                                'days_empty': days_empty,
                                'has_last_event': last_event is not None,
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
            
            logger.info(f"CloudWatch detector found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"Error in CloudWatch waste detection: {e}")
            raise
    async def _detect_cloudwatch_dashboard_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect unused CloudWatch Dashboards.

        Pricing: First 3 dashboards are free, then $3/dashboard/month.
        Dashboards that haven't been modified in 90+ days are likely stale.
        """
        waste_items = []

        try:
            dashboards = await data_provider.get_cloudwatch_dashboards()

            if len(dashboards) <= 3:
                # First 3 are free — no savings possible
                return waste_items

            # Sort by last_modified (oldest first) so we flag oldest beyond free tier
            sorted_dashboards = sorted(
                dashboards,
                key=lambda d: d.last_modified or datetime.min.replace(tzinfo=timezone.utc),
            )

            # The 3 most recently modified dashboards are free
            # Flag the rest that haven't been modified in 90+ days
            paid_dashboards = sorted_dashboards[:-3] if len(sorted_dashboards) > 3 else []

            for dash in paid_dashboards:
                days_since_modified = None
                if dash.last_modified:
                    last_mod = dash.last_modified
                    if not last_mod.tzinfo:
                        last_mod = last_mod.replace(tzinfo=timezone.utc)
                    days_since_modified = (datetime.now(timezone.utc) - last_mod).days

                if days_since_modified is not None and days_since_modified > 90:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=dash.dashboard_name,
                        resource_type=ResourceType.CLOUDWATCH_DASHBOARD,
                        waste_type=WasteType.UNUSED_DASHBOARD,
                        title="Unused CloudWatch Dashboard",
                        description=(
                            f"Dashboard '{dash.dashboard_name}' hasn't been modified in "
                            f"{days_since_modified} days. Beyond the 3 free dashboards, "
                            f"each costs $3/month."
                        ),
                        monthly_savings=3.00,
                        confidence=ConfidenceLevel.MEDIUM,
                        action="Delete this dashboard if no longer monitored.",
                        action_command=f"aws cloudwatch delete-dashboards --dashboard-names {dash.dashboard_name}",
                        explanation={
                            'detection': (
                                f'Dashboard \'{dash.dashboard_name}\' last modified '
                                f'{days_since_modified} days ago. '
                                f'Account has {len(dashboards)} dashboards (3 free, {len(dashboards) - 3} paid).'
                            ),
                            'threshold': 'Not modified in > 90 days and beyond the 3 free dashboard quota',
                            'pricing': '$3/dashboard/month beyond the first 3 free dashboards',
                            'why_waste': (
                                'Stale dashboards that haven\'t been updated in months are likely no longer monitored. '
                                'Each paid dashboard costs $3/month regardless of views.'
                            ),
                            'risk': (
                                'Deleting a dashboard is permanent but the definition can be recreated. '
                                'Export the dashboard JSON first with: '
                                f'aws cloudwatch get-dashboard --dashboard-name {dash.dashboard_name}'
                            ),
                        },
                        metadata={
                            'dashboard_name': dash.dashboard_name,
                            'days_since_modified': days_since_modified,
                            'total_dashboards': len(dashboards),
                            'detection_mode': data_provider.provider_type,
                        }
                    ))

            return waste_items

        except Exception as e:
            logger.debug(f"CloudWatch Dashboard detection error: {e}")
            return waste_items
