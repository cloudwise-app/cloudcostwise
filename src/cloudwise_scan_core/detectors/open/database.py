"""Open-core part of ``detectors/database.py`` (FSL-1.1-ALv2).

The service entrypoints in ``FREE_TIER_DETECTORS`` and every method they call.
``DatabaseDetectorsMixin`` in ``detectors/database.py`` subclasses this mixin and adds the
closed detectors. Moved verbatim from ``detectors/database.py`` (CLO-562).
"""

import logging
import uuid
from datetime import date, datetime, timezone
from typing import Dict, List, Optional, TYPE_CHECKING
from cloudwise_scan_core.models import WasteItem, WasteDetectionSettings, WasteType, ResourceType, ConfidenceLevel, get_rds_monthly_cost
from cloudwise_scan_core.cpu_sizing import has_min_coverage, is_as_old_as_window
from cloudwise_scan_core.detectors.extended_support import resolve_version_policy, classify_support_state, estimate_surcharge, describe_estimate, surcharge_metadata, needs_base_price, get_billed_surcharge_monthly
if TYPE_CHECKING:
    from cloudwise_scan_core.data_providers.base import WasteDataProvider

logger = logging.getLogger(__name__)

# Lookback used for DynamoDB consumed-capacity metrics, and therefore the minimum
# age a table must reach before a finding may make a claim about that window.
DYNAMODB_METRIC_WINDOW_DAYS = 14


# idle_elasticache's lookback, and therefore the minimum age a cluster must
# reach before it may be called idle (CLO-233's rule, applied in CLO-457).
ELASTICACHE_IDLE_WINDOW_DAYS = 7


# CLO-572: node memory ("Memory (GiB)" column) for every node type that
# appears as a key OR a value of ``downsize_map`` in _detect_elasticache_waste
# below -- Redis OSS and Valkey list the same figure for every type here.
# Source: AWS ElastiCache User Guide, "Supported node types"
# https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html
# (read 2026-10-04). A type with no entry is MISSING, never guessed -- the
# oversized memory gate withholds rather than assuming it fits.
ELASTICACHE_NODE_MEMORY_GIB = {
    'cache.r7g.2xlarge': 52.82, 'cache.r7g.xlarge': 26.32, 'cache.r7g.large': 13.07,
    'cache.r6g.2xlarge': 52.82, 'cache.r6g.xlarge': 26.32, 'cache.r6g.large': 13.07,
    'cache.r5.2xlarge': 52.82, 'cache.r5.xlarge': 26.32, 'cache.r5.large': 13.07,
    'cache.m7g.2xlarge': 26.04, 'cache.m7g.xlarge': 12.93, 'cache.m7g.large': 6.38,
    'cache.m6g.2xlarge': 26.04, 'cache.m6g.xlarge': 12.93, 'cache.m6g.large': 6.38,
    'cache.m5.xlarge': 12.93, 'cache.m5.large': 6.38,
    'cache.t4g.medium': 3.09, 'cache.t4g.small': 1.37, 'cache.t4g.micro': 0.50,
    'cache.t3.medium': 3.09, 'cache.t3.small': 1.37, 'cache.t3.micro': 0.50,
}

# CLO-572: oversized_elasticache's memory gate. A one-tier downsize does not
# always halve memory -- cache.r5.large -> cache.t3.medium is a 4.2x step,
# cache.t3.small -> cache.t3.micro about 2.7x -- so gating on "% of the
# CURRENT node" (the ticket's own illustrative example) would wave through
# a workload that will not fit that SPECIFIC target. Instead the measured
# average is projected onto the target's own capacity:
#   projected_pct = avg_pct * (current_node_gib / target_node_gib)
# and the verdict is withheld above this cap, leaving at least a quarter of
# the target's memory as headroom -- the hourly/daily AVERAGE this gate
# reads cannot see a traffic spike that pushes past it and evicts or OOMs.
ELASTICACHE_MEMORY_HEADROOM_MAX_PCT = 75.0


def _elasticache_oversized_memory_ok(metrics, node_type, target_type, period_seconds, data_provider, cluster_id, engine=None):
    """CLO-572: whether the measured memory comfortably fits ``target_type``
    after oversized_elasticache's one-tier downsize. Returns ``(ok, avg_pct)``.

    ``ok`` is False -- and the oversized verdict must be withheld, never
    read as fine -- whenever the data cannot support a verdict either way:
    missing or under-covered DatabaseMemoryUsagePercentage (noted through
    ``_note_idle_verdict_missing`` under its own 'elasticache-memory' key,
    so it cannot mislabel the CPU note sharing this same aggregator), or a
    node type absent from ``ELASTICACHE_NODE_MEMORY_GIB``. The same 75%
    coverage rule CLO-559 set for CPU applies here.

    ``engine`` names the no-datapoints case precisely for Memcached, which
    AWS never publishes DatabaseMemoryUsagePercentage for (Redis OSS/Valkey
    only) -- every Memcached cluster withholds here, by design, not by
    accident; see CLO-572's Memcached follow-up ticket for a
    BytesUsedForCache-based path."""
    mem_datapoints = metrics.memory_datapoints
    mem_window_days = metrics.memory_window_days or metrics.period_days
    note = getattr(data_provider, '_note_idle_verdict_missing', None)

    def _missing(reason):
        if callable(note):
            note(
                'elasticache-memory', cluster_id, reason,
                verdict='oversized', evidence='memory metrics',
            )
        return False, None

    if mem_datapoints is None or not has_min_coverage(mem_datapoints, mem_window_days, period_seconds):
        if not mem_datapoints and (engine or '').strip().lower() == 'memcached':
            return _missing("Memcached publishes no DatabaseMemoryUsagePercentage")
        return _missing(
            "no DatabaseMemoryUsagePercentage datapoints" if not mem_datapoints
            else "DatabaseMemoryUsagePercentage under 75% coverage"
        )

    current_gib = ELASTICACHE_NODE_MEMORY_GIB.get(node_type)
    target_gib = ELASTICACHE_NODE_MEMORY_GIB.get(target_type)
    if not current_gib or not target_gib:
        return _missing(f"no memory size on file for {node_type} or {target_type}")

    avg_pct = metrics.database_memory_usage_pct
    projected_pct = avg_pct * (current_gib / target_gib)
    return projected_pct <= ELASTICACHE_MEMORY_HEADROOM_MAX_PCT, avg_pct


# CLO-535: DescribeDBInstances also lists DocumentDB and Neptune instances
# and Aurora (aurora-*) cluster members. Their idle verdicts belong to
# idle_documentdb, idle_neptune and the Aurora detectors, which judge the
# cluster; idle_rds (Fix This: stop-db-instance) judges standalone RDS only.
_NON_STANDALONE_RDS_ENGINES = frozenset({'docdb', 'neptune'})


_NON_STANDALONE_RDS_ENGINE_PREFIXES = ('aurora',)


def instance_is_standalone_rds(engine: str) -> bool:
    """CLO-535 gate (the CLO-531 deletion-protection pattern): whether
    idle_rds judges a DB instance. False for DocumentDB, Neptune and Aurora
    members, whose own detectors judge the cluster."""
    key = (engine or '').strip().lower()
    return key not in _NON_STANDALONE_RDS_ENGINES and not key.startswith(_NON_STANDALONE_RDS_ENGINE_PREFIXES)


# Stand-in age for a resource whose creation time the provider could not supply.
# Deliberately large: an age guard exists to suppress claims about resources too
# young to have been observed, and an unknown-age resource is far more likely to be
# long-lived than brand new. Mirrors analytics.py's idle-Kinesis-stream detector.
UNKNOWN_RESOURCE_AGE_DAYS = 999


# Node types the ElastiCache detectors price as a recommendation target
# (oversized downsizes and r6gd data tiering), resolved with the clusters'
# own types in one pass.
_ELASTICACHE_PRICED_TARGETS = (
    'cache.r7g.xlarge', 'cache.r7g.large', 'cache.r6g.xlarge', 'cache.r6g.large',
    'cache.r5.xlarge', 'cache.r5.large', 'cache.m7g.xlarge', 'cache.m7g.large',
    'cache.m6g.xlarge', 'cache.m6g.large', 'cache.m5.large', 'cache.t3.medium',
    'cache.t3.small', 'cache.t3.micro', 'cache.t4g.small', 'cache.t4g.micro',
    'cache.r6gd.xlarge', 'cache.r6gd.2xlarge', 'cache.r6gd.4xlarge',
    'cache.r6gd.8xlarge', 'cache.r6gd.12xlarge', 'cache.r6gd.16xlarge',
)


def _elasticache_price_engine(engine) -> str:
    """The Price List rows an ElastiCache engine bills at: Valkey has its own
    rows; Redis OSS and Memcached share the Redis rows."""
    return 'valkey' if (engine or '').strip().lower() == 'valkey' else 'redis'


def _redis_supports_data_tiering(engine_version) -> bool:
    """True when a Redis OSS engine version is 6.2 or later, the first that
    supports r6gd data tiering. '6.x', an empty string or anything else
    without a readable major.minor is unknown, so False (withheld)."""
    parts = (engine_version or '').strip().split('.')
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return False
    return (major, minor) >= (6, 2)


class ElastiCachePrices:
    """CLO-532 item 3: one scan's ElastiCache node prices, per Price List
    engine family ({'redis': {node_type: hourly}, 'valkey': {...}}),
    region-scaled. ``price`` returns None for a type with no row for that
    engine: MISSING, never the other engine's rate. Deliberately not a dict:
    a ``.get(node_type)`` that ignores the engine fails loudly."""

    def __init__(self, redis: Optional[Dict[str, float]] = None, valkey: Optional[Dict[str, float]] = None):
        self._tables = {'redis': dict(redis or {}), 'valkey': dict(valkey or {})}

    def price(self, node_type: Optional[str], engine: Optional[str]) -> Optional[float]:
        return self._tables[_elasticache_price_engine(engine)].get(node_type or '')


def _note_elasticache_price_missing(data_provider, cluster, verdict: str = 'cost-based') -> None:
    """An ElastiCache node type with no Price List entry: its cost-based
    verdicts are MISSING from the scan, noted once per cluster (#1552 rule)."""
    note = getattr(data_provider, '_note_idle_verdict_missing', None)
    if callable(note):
        note(
            'elasticache-pricing', cluster.cluster_id,
            f"no on-demand price for node type {cluster.node_type or 'unknown'}",
            verdict=verdict, evidence='node prices',
        )


# CLO-508: ElastiCache Serverless list prices, us-east-1 (AWS Price List API,
# productFamily "ElastiCache Serverless", checked 2026-10-01): data stored per
# GB-hour (CachedData), ECPUs per million (ElastiCacheProcessingUnits), and
# the minimum data each engine bills (1 GB Redis OSS, 100 MB Valkey).
ELASTICACHE_SERVERLESS_RATES = {
    'redis': {'data_gb_hour': 0.125, 'ecpu_per_million': 0.0034, 'min_data_gb': 1.0},
    'valkey': {'data_gb_hour': 0.084, 'ecpu_per_million': 0.0023, 'min_data_gb': 0.1},
}



class OpenDatabaseDetectorsMixin:
    """Open detectors from ``DatabaseDetectorsMixin``."""

    async def _detect_rds_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect RDS-related waste using DataProvider.
        
        Detectors:
        1. IDLE_RDS - No connections for extended period
        2. OLD_RDS_SNAPSHOT - Snapshots older than threshold
        """
        waste_items = []
        
        try:
            # Get RDS instances from data provider
            instances = await data_provider.get_rds_instances()
            
            for db in instances:
                # CLO-535: standalone RDS only; cluster engines have their own
                # idle detectors (no note: nothing is MISSING, it's not ours).
                if not instance_is_standalone_rds(db.engine):
                    continue
                # CLO-359: region-scaled — RDS_PRICING is flat us-east-1
                # rates otherwise.
                monthly_cost = get_rds_monthly_cost(
                    db.db_instance_class, db.multi_az, region=data_provider.region
                )
                
                # Check for idle instances (requires CloudWatch metrics).
                # CLO-233's minimum-age rule (CLO-457): "0 connections for N
                # days" needs an instance that existed for all N days. A
                # younger one has only partial data, and one recreated under a
                # reused DBInstanceIdentifier is judged on its own days only
                # (the provider drops its predecessor's), so without this an
                # hours-old instance would be called idle. Unknown creation
                # time counts as old.
                if (
                    settings.cloudwatch_enabled
                    and data_provider.supports_cloudwatch
                    and is_as_old_as_window(
                        getattr(db, 'instance_create_time', None), settings.rds_idle_days,
                    )
                ):
                    metrics_map = await data_provider.get_rds_metrics(
                        db_instance_ids=[db.db_instance_id],
                        days=settings.rds_idle_days,
                        # CLO-457: only the instance's own datapoints.
                        create_times={db.db_instance_id: getattr(db, 'instance_create_time', None)},
                    )
                    
                    metrics = metrics_map.get(db.db_instance_id)
                    if metrics and metrics.is_idle:
                        multi_az_note = ' (Multi-AZ doubles the cost)' if db.multi_az else ''
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=db.db_instance_id,
                            resource_type=ResourceType.RDS_INSTANCE,
                            waste_type=WasteType.IDLE_RDS,
                            title=f"Idle RDS Database",
                            description=f"Database '{db.db_instance_id}' ({db.db_instance_class}) has had 0 connections for {metrics.period_days} days.",
                            monthly_savings=monthly_cost,
                            confidence=ConfidenceLevel.HIGH,
                            action="Stop or delete this database.",
                            action_command=f"aws rds stop-db-instance --db-instance-identifier {db.db_instance_id}",
                            explanation={
                                'detection': f'CloudWatch DatabaseConnections = 0 for {metrics.period_days} consecutive days',
                                'threshold': f'0 connections over {metrics.period_days} days',
                                'pricing': f'{db.db_instance_class} ({db.engine}): ${monthly_cost:.2f}/month{multi_az_note}',
                                'why_waste': f'No application has connected to this database in {metrics.period_days} days. It may have been created for testing or a decommissioned service.',
                                'risk': 'RDS instances can be stopped for up to 7 days (auto-restarts after). Take a final snapshot before deleting. Check if any application uses this as a standby.',
                            },
                            metadata={
                                'db_class': db.db_instance_class,
                                'engine': db.engine,
                                'multi_az': db.multi_az,
                                'cloudwatch_verified': True,
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
            
            # Check old snapshots
            snapshots = await data_provider.get_rds_snapshots(age_threshold_days=settings.snapshot_age_days)
            
            for snapshot in snapshots:
                age_days = snapshot.age_days
                monthly_cost = snapshot.allocated_storage_gb * 0.095
                
                waste_items.append(WasteItem(
                    id=str(uuid.uuid4()),
                    resource_id=snapshot.snapshot_id,
                    resource_type=ResourceType.RDS_SNAPSHOT,
                    waste_type=WasteType.OLD_RDS_SNAPSHOT,
                    title=f"Old RDS Snapshot ({age_days} days)",
                    description=f"Snapshot '{snapshot.snapshot_id}' ({snapshot.allocated_storage_gb}GB) is {age_days} days old.",
                    monthly_savings=monthly_cost,
                    confidence=ConfidenceLevel.MEDIUM,
                    action="Delete this snapshot if no longer needed.",
                    action_command=f"aws rds delete-db-snapshot --db-snapshot-identifier {snapshot.snapshot_id}",
                    explanation={
                        'detection': f'RDS snapshot is {age_days} days old',
                        'threshold': f'> {settings.snapshot_age_days} days old',
                        'pricing': f'{snapshot.allocated_storage_gb} GB × $0.095/GB = ${monthly_cost:.2f}/month',
                        'why_waste': f'Old RDS snapshots accumulate storage charges. At {age_days} days old, this snapshot likely represents a database state that is no longer relevant for recovery.',
                        'risk': 'Verify this is not the only backup. Check automated backup retention and AWS Backup policies before deleting manual snapshots.',
                    },
                    metadata={
                        'allocated_storage_gb': snapshot.allocated_storage_gb,
                        'age_days': age_days,
                        'detection_mode': data_provider.provider_type,
                    }
                ))

            # Extended support surcharge detection for non-Aurora RDS engines
            ext_items = await self._detect_rds_extended_support(data_provider, settings)
            waste_items.extend(ext_items)
            
            logger.info(f"RDS detector found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"Error in RDS waste detection: {e}")
            raise
    async def _detect_rds_extended_support(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """Detect non-Aurora RDS instances in or near extended support windows."""
        waste_items: List[WasteItem] = []

        WARNING_WINDOW_DAYS = 90
        today = date.today()

        try:
            instances = await data_provider.get_rds_instances()
            billed_breakdown = {}
            if hasattr(data_provider, 'get_extended_support_cost_breakdown'):
                try:
                    billed_breakdown = await data_provider.get_extended_support_cost_breakdown(
                        service_keys=['rds'], days=30
                    )
                except TypeError:
                    billed_breakdown = {}

            for db in instances:
                engine = (db.engine or '').strip().lower()
                if engine.startswith('aurora'):
                    continue

                version = (db.engine_version or '').strip()
                policy = resolve_version_policy('rds', version, engine)
                if not policy:
                    continue

                extended_start = policy['extended_start']
                target_version = policy['target_version']
                state, days_until = classify_support_state(policy, today=today, warning_window_days=WARNING_WINDOW_DAYS)

                if state == 'warning_imminent' and days_until is not None:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=db.db_instance_id,
                        resource_type=ResourceType.RDS_INSTANCE,
                        waste_type=WasteType.RDS_EXTENDED_SUPPORT_COST,
                        title="RDS Extended Support Surcharge Imminent",
                        description=(
                            f"RDS instance '{db.db_instance_id}' running {engine} {version} "
                            f"enters extended support on {extended_start} ({days_until} days)."
                        ),
                        monthly_savings=settings.min_waste_threshold_usd,
                        confidence=ConfidenceLevel.HIGH,
                        action=(
                            f"Upgrade '{db.db_instance_id}' to {engine} {target_version} "
                            + (f"({policy['upgrade_path']}) " if policy.get('upgrade_path') else '')
                            + f"before {extended_start} to avoid extended support charges."
                        ),
                        explanation={
                            'detection': f"Engine version {engine} {version} has explicit extended support policy start {extended_start}",
                            'threshold': f"Within warning window ({days_until} <= {WARNING_WINDOW_DAYS} days)",
                            'pricing': 'RDS extended support applies an incremental surcharge per vCPU-hour after standard support ends.',
                            'why_waste': 'Charges are avoidable by upgrading while still in standard support.',
                            'risk': 'Plan upgrade via staging validation and a maintenance window.',
                        },
                        metadata={
                            'service': 'rds',
                            'engine': engine,
                            'current_version': version,
                            'target_version': target_version,
                            'support_eol_date': str(policy.get('eol_date', '')),
                            'extended_support_start': str(extended_start),
                            'days_until_extended_support': days_until,
                            'state': 'warning_imminent',
                            'billing_verified': False,
                            **surcharge_metadata(policy, today),
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
                    continue

                if state != 'active_surcharge':
                    continue

                vcpus = self.INSTANCE_VCPU_MAP.get(db.db_instance_class, 2)
                estimated_monthly = estimate_surcharge({'total_vcpus': vcpus}, policy, today=today)
                billed_monthly, billed_verified = get_billed_surcharge_monthly(
                    billed_breakdown, 'rds', db.db_instance_id
                )
                monthly_surcharge = billed_monthly if billed_verified and billed_monthly is not None else estimated_monthly

                if monthly_surcharge >= settings.min_waste_threshold_usd:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=db.db_instance_id,
                        resource_type=ResourceType.RDS_INSTANCE,
                        waste_type=WasteType.RDS_EXTENDED_SUPPORT_COST,
                        title="RDS Extended Support Surcharge",
                        description=(
                            f"RDS instance '{db.db_instance_id}' running {engine} {version} is in extended support. "
                            f"Estimated surcharge: ${monthly_surcharge:.2f}/month."
                        ),
                        monthly_savings=monthly_surcharge,
                        confidence=ConfidenceLevel.HIGH,
                        action=(
                            f"Upgrade '{db.db_instance_id}' to {engine} {target_version}"
                            + (f" ({policy['upgrade_path']})" if policy.get('upgrade_path') else '')
                            + " to eliminate surcharge."
                        ),
                        explanation={
                            'detection': f"RDS {engine} {version} passed extended support start date {extended_start}",
                            'threshold': 'Any engine version with explicit lifecycle policy entry is flagged after extended start.',
                            'pricing': (
                                f"Billing-backed monthly surcharge: ${monthly_surcharge:.2f}"
                                if billed_verified else
                                f"Estimated surcharge: {vcpus} vCPU × ${policy.get('year1_2_rate', 0.10)}/vCPU-hr × 730h = ${monthly_surcharge:.2f}/month"
                            ),
                            'why_waste': 'Extended support surcharge is incremental and avoidable with version upgrades.',
                            'risk': 'Engine upgrades require compatibility testing and controlled maintenance windows.',
                        },
                        metadata={
                            'service': 'rds',
                            'engine': engine,
                            'current_version': version,
                            'target_version': target_version,
                            'support_eol_date': str(policy.get('eol_date', '')),
                            'extended_support_start': str(extended_start),
                            'state': 'active_surcharge',
                            'total_vcpus': vcpus,
                            'estimated_monthly_surcharge': round(monthly_surcharge, 2),
                            'billing_verified': billed_verified,
                            **surcharge_metadata(policy, today),
                            'detection_mode': data_provider.provider_type,
                        },
                    ))

        except Exception as e:
            logger.debug(f"RDS extended support detection error: {e}")

        return waste_items
    async def _detect_dynamodb_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect DynamoDB-related waste using DataProvider.
        
        Detectors:
        1. IDLE_DYNAMODB - No read/write operations
        2. OVER_PROVISIONED_DYNAMODB - Low capacity utilization
        3. DYNAMODB_NO_AUTOSCALING - Provisioned tables without auto-scaling
        """
        waste_items = []
        
        try:
            # Get tables from data provider
            tables = await data_provider.get_dynamodb_tables()

            # Region-scaled DynamoDB rates. Reads and writes are priced separately —
            # a provisioned RCU is $0.00013/hr, a WCU is $0.00065/hr (CLO-226). The
            # previous code applied the WCU rate to both, inflating the read half of
            # every DynamoDB cost estimate by 5x.
            ddb_pricing = await self.pricing_service.get_dynamodb_price(
                getattr(data_provider, 'region', 'us-east-1')
            )
            rcu_hourly = ddb_pricing['provisioned_read_unit_per_hour']
            wcu_hourly = ddb_pricing['provisioned_write_unit_per_hour']
            read_per_million = ddb_pricing['read_unit_per_million']
            write_per_million = ddb_pricing['write_unit_per_million']

            for table in tables:
                if table.billing_mode != 'PROVISIONED':
                    continue

                read_capacity = table.provisioned_read_capacity or 0
                write_capacity = table.provisioned_write_capacity or 0
                monthly_cost = (
                    read_capacity * rcu_hourly + write_capacity * wcu_hourly
                ) * 730

                # How long the table has actually existed. A table younger than the
                # metric window cannot support a claim about that window: CloudWatch
                # returns no datapoints for the time before it was created, which is
                # indistinguishable from a table that existed and sat idle (CLO-233).
                # Unknown creation time is treated as old enough, the same convention
                # the idle-Kinesis-stream detector uses (analytics.py).
                table_age_days = UNKNOWN_RESOURCE_AGE_DAYS
                table_age_note = ''
                if table.created_time:
                    created = table.created_time
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    table_age_days = (datetime.now(timezone.utc) - created).days
                    # Only stated when it is actually known — the fallback above is a
                    # sentinel, not a measurement, and must never be shown to a user.
                    table_age_note = f', on a table {table_age_days} days old'

                # Detector 1: No auto-scaling configured. CLO-551: None means
                # the scalable-target read is MISSING (failed, or an export
                # that did not carry it): withhold and note, never "none".
                if table.has_autoscaling is None and monthly_cost >= 5.0:
                    note = getattr(data_provider, '_note_idle_verdict_missing', None)
                    if callable(note):
                        note('dynamodb autoscaling', table.table_name, 'scalable targets not read',
                             verdict='no-autoscaling',
                             evidence='Application Auto Scaling target listings')
                elif not table.has_autoscaling and monthly_cost >= 5.0:
                    estimated_savings = monthly_cost * 0.15
                    
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=table.table_name,
                        resource_type=ResourceType.DYNAMODB_TABLE,
                        waste_type=WasteType.DYNAMODB_NO_AUTOSCALING,
                        title="DynamoDB Table Without Auto-Scaling",
                        description=f"Table '{table.table_name}' has provisioned capacity ({read_capacity}RCU/{write_capacity}WCU) but no auto-scaling.",
                        monthly_savings=estimated_savings,
                        confidence=ConfidenceLevel.MEDIUM,
                        action="Enable auto-scaling or switch to on-demand billing.",
                        action_command=f"aws application-autoscaling register-scalable-target --service-namespace dynamodb --resource-id table/{table.table_name} --scalable-dimension dynamodb:table:ReadCapacityUnits --min-capacity 1 --max-capacity {read_capacity}",
                        explanation={
                            'detection': f'Provisioned mode with {read_capacity} RCU / {write_capacity} WCU and no Application Auto Scaling target registered',
                            'threshold': 'Provisioned table with monthly cost ≥ $5 and no auto-scaling',
                            'pricing': f'Provisioned: ({read_capacity} RCU × ${rcu_hourly:.5f} + {write_capacity} WCU × ${wcu_hourly:.5f}) × 730 = ${monthly_cost:.2f}/month. ~15% savings with auto-scaling: ${estimated_savings:.2f}/month',
                            'why_waste': f'Without auto-scaling, provisioned capacity is fixed 24/7. Auto-scaling adjusts capacity based on traffic, reducing cost during low-activity periods.',
                            'risk': 'Auto-scaling has a brief delay when scaling up. Set appropriate minimum capacities for baseline traffic. Consider on-demand mode as an alternative.',
                        },
                        metadata={
                            'table_name': table.table_name,
                            'read_capacity_units': read_capacity,
                            'write_capacity_units': write_capacity,
                            'billing_mode': table.billing_mode,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                
                # Detectors 2 & 3: Check usage metrics if CloudWatch available.
                # Both make an explicit claim about the last 14 days ("no activity in
                # 14 days", "utilization ... over 14 days"), so both require a table
                # that has existed for those 14 days (CLO-233). Detector 1 above is a
                # configuration check rather than a usage claim and is deliberately
                # not gated on age.
                if (
                    settings.cloudwatch_enabled
                    and data_provider.supports_cloudwatch
                    and monthly_cost >= settings.min_waste_threshold_usd
                    and table_age_days >= DYNAMODB_METRIC_WINDOW_DAYS
                ):
                    metrics_map = await data_provider.get_dynamodb_metrics(
                        table_names=[table.table_name],
                        days=DYNAMODB_METRIC_WINDOW_DAYS,
                    )
                    
                    metrics = metrics_map.get(table.table_name)
                    if metrics:
                        # Average consumed capacity in units *per second* — the same
                        # basis as provisioned RCU/WCU, so utilization below is a true
                        # ratio. See DynamoDBMetricsData for the provider contract
                        # (CLO-227 fixed the online provider, which was passing through
                        # CloudWatch's per-request `Average` here).
                        avg_read = metrics.consumed_read_capacity_avg
                        avg_write = metrics.consumed_write_capacity_avg
                        
                        if avg_read == 0 and avg_write == 0:
                            # Idle table
                            waste_items.append(WasteItem(
                                id=str(uuid.uuid4()),
                                resource_id=table.table_name,
                                resource_type=ResourceType.DYNAMODB_TABLE,
                                waste_type=WasteType.IDLE_DYNAMODB,
                                title=f"Idle DynamoDB Table",
                                description=f"Table '{table.table_name}' has had no activity in {DYNAMODB_METRIC_WINDOW_DAYS} days.",
                                monthly_savings=monthly_cost,
                                confidence=ConfidenceLevel.HIGH,
                                action="Delete or switch to on-demand billing.",
                                explanation={
                                    'detection': f'Zero consumed read and write capacity over {DYNAMODB_METRIC_WINDOW_DAYS} days ({read_capacity} RCU / {write_capacity} WCU provisioned){table_age_note}',
                                    'threshold': f'0 consumed reads AND 0 consumed writes over a {DYNAMODB_METRIC_WINDOW_DAYS}-day monitoring period, on a table at least {DYNAMODB_METRIC_WINDOW_DAYS} days old',
                                    'pricing': f'Provisioned: ${monthly_cost:.2f}/month for idle capacity',
                                    'why_waste': f'This table has had no reads or writes in {DYNAMODB_METRIC_WINDOW_DAYS} days. Provisioned capacity charges continue regardless of usage.',
                                    'risk': 'Verify no applications depend on this table. Check DynamoDB Streams consumers. If keeping, switch to on-demand to avoid idle costs.',
                                },
                                metadata={
                                    'table_name': table.table_name,
                                    'read_capacity_units': read_capacity,
                                    'write_capacity_units': write_capacity,
                                    'detection_mode': data_provider.provider_type,
                                }
                            ))
                        else:
                            # Check for over-provisioned using average consumed capacity
                            read_util = (avg_read / read_capacity * 100) if read_capacity > 0 else 0
                            write_util = (avg_write / write_capacity * 100) if write_capacity > 0 else 0
                            
                            if read_util < 20 and write_util < 20:
                                # Estimate on-demand cost based on average usage over a month.
                                # Read and write request units are priced separately
                                # ($0.125 vs $0.625 per million in us-east-1) — the flat
                                # $1.25 used for both over-stated the on-demand side and
                                # therefore under-stated the savings (CLO-226).
                                seconds_per_month = 30 * 24 * 3600
                                monthly_read_units = avg_read * seconds_per_month
                                monthly_write_units = avg_write * seconds_per_month
                                on_demand_cost = (
                                    monthly_read_units / 1e6 * read_per_million
                                    + monthly_write_units / 1e6 * write_per_million
                                )
                                savings = monthly_cost - on_demand_cost
                                
                                if savings > settings.min_waste_threshold_usd:
                                    waste_items.append(WasteItem(
                                        id=str(uuid.uuid4()),
                                        resource_id=table.table_name,
                                        resource_type=ResourceType.DYNAMODB_TABLE,
                                        waste_type=WasteType.OVER_PROVISIONED_DYNAMODB,
                                        title=f"Over-Provisioned DynamoDB Table",
                                        # 3dp, not 1dp: a badly over-provisioned table
                                        # can sit well under 0.05% utilization, and
                                        # printing that as "0.0%" next to an idle-table
                                        # detector that means literally zero is worse
                                        # than noise (CLO-227).
                                        description=f"Table '{table.table_name}' uses {read_util:.3f}% read, {write_util:.3f}% write capacity.",
                                        monthly_savings=savings,
                                        confidence=ConfidenceLevel.MEDIUM,
                                        action="Switch to on-demand billing.",
                                        explanation={
                                            'detection': f'Read utilization {read_util:.3f}%, write utilization {write_util:.3f}% over {DYNAMODB_METRIC_WINDOW_DAYS} days',
                                            'threshold': f'< 20% on both read and write utilization, on a table at least {DYNAMODB_METRIC_WINDOW_DAYS} days old',
                                            'pricing': f'Provisioned: ${monthly_cost:.2f}/month. On-demand estimate: ${on_demand_cost:.2f}/month. Savings: ${savings:.2f}/month',
                                            # 6dp, not 3dp: these are per-second rates, and a
                                            # genuinely over-provisioned table sits well below
                                            # 0.001 units/sec — printing "0.000 RCU/sec" next to
                                            # a non-zero utilization percentage in the same
                                            # finding made it contradict itself (CLO-233).
                                            'why_waste': f'Provisioned capacity is set to {read_capacity} RCU / {write_capacity} WCU but average consumption is only {avg_read:.6f} RCU/sec / {avg_write:.6f} WCU/sec. On-demand billing would match actual usage.',
                                            'risk': 'On-demand mode has higher per-request pricing. Verify traffic patterns are unpredictable before switching. For steady workloads, auto-scaling may be more cost-effective.',
                                        },
                                        metadata={
                                            'read_utilization_pct': round(read_util, 4),
                                            'write_utilization_pct': round(write_util, 4),
                                            'detection_mode': data_provider.provider_type,
                                        }
                                    ))
            
            logger.info(f"DynamoDB detector found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"Error in DynamoDB waste detection: {e}")
            raise
    async def _detect_elasticache_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """Detect idle ElastiCache clusters using DataProvider."""
        waste_items = []
        

        try:
            # Get ElastiCache clusters from data provider
            clusters = await data_provider.get_elasticache_clusters()
            # One price per node type for this scan, from the pricing
            # service's Price List table (region-scaled). A type it does not
            # know is absent from the map: every ElastiCache verdict that
            # needs its price is MISSING, never a guessed $0.10/hr.
            ELASTICACHE_PRICING = await self._elasticache_price_map(
                data_provider, clusters, _ELASTICACHE_PRICED_TARGETS,
            )

            for cluster in clusters:
                if cluster.status != 'available':
                    continue

                hourly_price = ELASTICACHE_PRICING.price(cluster.node_type, cluster.engine)
                if hourly_price is None:
                    _note_elasticache_price_missing(data_provider, cluster)
                    continue
                monthly_cost = hourly_price * 730 * cluster.num_nodes
                
                if settings.cloudwatch_enabled and data_provider.supports_cloudwatch and monthly_cost >= settings.min_waste_threshold_usd:
                    metrics_map = await data_provider.get_elasticache_metrics(
                        cluster_ids=[cluster.cluster_id],
                        days=ELASTICACHE_IDLE_WINDOW_DAYS,
                        # CLO-457: only the cluster's own datapoints, not a
                        # deleted namesake's.
                        create_times={cluster.cluster_id: getattr(cluster, 'created_time', None)},
                        idle_window_days=ELASTICACHE_IDLE_WINDOW_DAYS,  # CLO-485
                    )
                    
                    metrics = metrics_map.get(cluster.cluster_id)
                    # CLO-485: the provider's verdict, not a 0.0 average. An
                    # empty or sparse CurrConnections series (or a failed
                    # read) also averages to 0; ``is_idle`` additionally
                    # needs 75% of the window observed (#1452's rule).
                    if metrics and metrics.is_idle:
                        # CLO-233's minimum-age rule (CLO-457): "0 connections
                        # in 7 days" needs a cluster that existed for all 7.
                        # A younger one (including one recreated under a
                        # reused CacheClusterId, now judged on its own days
                        # only) is not called idle on partial data. Unknown
                        # creation time counts as old.
                        if not is_as_old_as_window(
                            getattr(cluster, 'created_time', None), ELASTICACHE_IDLE_WINDOW_DAYS,
                        ):
                            continue
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=cluster.cluster_id,
                            resource_type=ResourceType.ELASTICACHE_CLUSTER,
                            waste_type=WasteType.IDLE_ELASTICACHE,
                            title=f"Idle ElastiCache Cluster",
                            description=f"Cluster '{cluster.cluster_id}' ({cluster.node_type}, {cluster.num_nodes} nodes) has had 0 connections in 7 days.",
                            monthly_savings=monthly_cost,
                            confidence=ConfidenceLevel.HIGH,
                            action="Delete this cluster.",
                            explanation={
                                'detection': f'Average CurrConnections = 0 over 7 days ({cluster.node_type}, {cluster.num_nodes} node(s))',
                                'threshold': (
                                    '0 connections over 7-day monitoring period, with at least 75% of it '
                                    f'observed ({metrics.connection_datapoints} CurrConnections datapoints)'
                                    if metrics.connection_datapoints is not None
                                    else '0 connections over 7-day monitoring period'
                                ),
                                'pricing': f'{cluster.node_type} × {cluster.num_nodes} node(s) = ${monthly_cost:.2f}/month',
                                'why_waste': f'ElastiCache charges per node-hour regardless of usage. This {cluster.engine} cluster has had zero client connections for a week.',
                                'risk': 'Create a final snapshot before deleting. Verify no applications have hardcoded this cluster endpoint.',
                            },
                            metadata={
                                'node_type': cluster.node_type,
                                'num_nodes': cluster.num_nodes,
                                'engine': cluster.engine,
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
                    elif metrics and metrics.current_connections_avg > 0:
                        # Oversized ElastiCache: low CPU utilization with active connections
                        cpu_avg = getattr(metrics, 'cpu_utilization_avg', None)
                        # CLO-559: insufficient CPU coverage is MISSING, never
                        # a reading of low CPU — the same 75% coverage rule
                        # #1452 set for DocumentDB and CLO-516 (PR #1535)
                        # applied to the MQ broker CPU gauge. Online reads
                        # daily CPUUtilization datapoints (Period=86400);
                        # offline reads hourly (cloudwise-export.sh). A
                        # cluster recreated under a reused CacheClusterId
                        # (CLO-457 drops the predecessor's datapoints), or one
                        # with a gappy series, must not be sized on a sliver
                        # of its own data. This also covers CLO-485's "no CPU
                        # datapoints" case (the air-gapped upload carries
                        # connections but no ElastiCache CPU series): zero
                        # datapoints never has coverage.
                        cpu_datapoints = getattr(metrics, 'cpu_datapoints', None) or 0
                        cpu_period_seconds = 3600 if data_provider.provider_type == 'offline' else 86400
                        # The offline export can collect fewer days than
                        # ELASTICACHE_IDLE_WINDOW_DAYS (cpu_window_days, set
                        # from _export_cloudwatch_days()); online always
                        # covers the full requested window.
                        cpu_window_days = getattr(metrics, 'cpu_window_days', None) or metrics.period_days
                        if not has_min_coverage(cpu_datapoints, cpu_window_days, cpu_period_seconds):
                            note = getattr(data_provider, '_note_idle_verdict_missing', None)
                            if callable(note):
                                # A distinct service key from 'elasticache'
                                # (the idle note): the aggregator keeps ONE
                                # note per key, built from the latest call's
                                # verdict/evidence words, so sharing the key
                                # with the idle withhold would mislabel an
                                # idle-withheld cluster as an "oversized"
                                # finding (or vice versa) in the same scan.
                                # Same convention as 'elasticache-pricing'.
                                note(
                                    'elasticache-cpu', cluster.cluster_id,
                                    "no CPUUtilization datapoints" if cpu_datapoints == 0
                                    else "CPUUtilization under 75% coverage",
                                    verdict='oversized', evidence='CPU metrics',
                                )
                            cpu_avg = None
                        if cpu_avg is not None and cpu_avg < 10 and cluster.num_nodes >= 1:
                            # Estimate downsizing: suggest one tier smaller node type
                            downsize_map = {
                                'cache.r7g.2xlarge': 'cache.r7g.xlarge',
                                'cache.r7g.xlarge': 'cache.r7g.large',
                                'cache.r6g.2xlarge': 'cache.r6g.xlarge',
                                'cache.r6g.xlarge': 'cache.r6g.large',
                                # No cache.r6g.large entry: its only smaller
                                # memory-optimized "target" was r5.large,
                                # which costs more ($0.216 vs $0.206/hr).
                                'cache.r5.2xlarge': 'cache.r5.xlarge',
                                'cache.r5.xlarge': 'cache.r5.large',
                                'cache.r5.large': 'cache.t3.medium',
                                'cache.m7g.2xlarge': 'cache.m7g.xlarge',
                                'cache.m7g.xlarge': 'cache.m7g.large',
                                'cache.m6g.2xlarge': 'cache.m6g.xlarge',
                                'cache.m6g.xlarge': 'cache.m6g.large',
                                'cache.m5.xlarge': 'cache.m5.large',
                                'cache.m5.large': 'cache.t3.medium',
                                'cache.t4g.medium': 'cache.t4g.small',
                                'cache.t4g.small': 'cache.t4g.micro',
                                'cache.t3.medium': 'cache.t3.small',
                                'cache.t3.small': 'cache.t3.micro',
                            }
                            recommended_type = downsize_map.get(cluster.node_type)
                            # An unpriced target is MISSING, not half the
                            # current price (every mapped target is priced).
                            recommended_price = (
                                ELASTICACHE_PRICING.price(recommended_type, cluster.engine)
                                if recommended_type else None
                            )
                            if recommended_price is not None:
                                recommended_cost = recommended_price * 730 * cluster.num_nodes
                                savings = monthly_cost - recommended_cost

                                # CLO-572: low CPU alone recommends a one-tier
                                # downsize that roughly halves (or, for some
                                # targets, cuts much further into) memory. A
                                # memory-bound, low-CPU cache -- a common
                                # Redis profile -- would get a harmful
                                # recommendation. Evaluated only once the
                                # finding would otherwise fire (a priced,
                                # savings-clearing target), so a busy or
                                # unpriced cluster never gets a spurious
                                # "memory missing" note.
                                mem_ok, mem_avg = False, None
                                if savings >= settings.min_waste_threshold_usd:
                                    mem_ok, mem_avg = _elasticache_oversized_memory_ok(
                                        metrics, cluster.node_type, recommended_type,
                                        cpu_period_seconds, data_provider, cluster.cluster_id,
                                        engine=cluster.engine,
                                    )

                                if savings >= settings.min_waste_threshold_usd and mem_ok:
                                    waste_items.append(WasteItem(
                                        id=str(uuid.uuid4()),
                                        resource_id=cluster.cluster_id,
                                        resource_type=ResourceType.ELASTICACHE_CLUSTER,
                                        waste_type=WasteType.OVERSIZED_ELASTICACHE,
                                        title="Oversized ElastiCache Cluster",
                                        description=(
                                            f"Cluster '{cluster.cluster_id}' ({cluster.node_type}, {cluster.num_nodes} node(s)) "
                                            f"has {cpu_avg:.1f}% average CPU and {mem_avg:.1f}% average memory. "
                                            f"Consider downsizing to {recommended_type}."
                                        ),
                                        monthly_savings=savings,
                                        confidence=ConfidenceLevel.MEDIUM,
                                        action=f"Downsize from {cluster.node_type} to {recommended_type}.",
                                        explanation={
                                            'detection': (
                                                f'Average CPU utilization is {cpu_avg:.1f}% over 7 days with '
                                                f'{metrics.current_connections_avg:.0f} avg connections. '
                                                f'Average memory utilization is {mem_avg:.1f}% of the current node. '
                                                f'Current type: {cluster.node_type}.'
                                            ),
                                            'threshold': (
                                                'CPU utilization < 10% over 7 days, and measured memory projects to '
                                                f'at most {ELASTICACHE_MEMORY_HEADROOM_MAX_PCT:.0f}% of the target '
                                                'node after the downsize (at least 75% coverage; CLO-572)'
                                            ),
                                            'pricing': (
                                                f'Current: {cluster.node_type} × {cluster.num_nodes} = ${monthly_cost:.2f}/month. '
                                                f'Recommended: {recommended_type} × {cluster.num_nodes} = ${recommended_cost:.2f}/month. '
                                                f'Savings: ${savings:.2f}/month.'
                                            ),
                                            'why_waste': (
                                                f'This {cluster.engine} cluster is using only {cpu_avg:.1f}% of its CPU capacity, '
                                                f'and its measured memory use comfortably fits {recommended_type}. '
                                                f'A smaller node type can handle the current workload at lower cost.'
                                            ),
                                            'risk': (
                                                'Downsizing requires a maintenance window (brief failover for Redis cluster mode). '
                                                'Re-check DatabaseMemoryUsagePercentage after the change; the gate above is an '
                                                'average over the window and cannot see a traffic spike.'
                                            ),
                                        },
                                        metadata={
                                            'cluster_id': cluster.cluster_id,
                                            'current_type': cluster.node_type,
                                            'recommended_type': recommended_type,
                                            'cpu_avg': round(cpu_avg, 1),
                                            'memory_pct_avg': round(mem_avg, 1),
                                            'connections_avg': round(metrics.current_connections_avg, 0),
                                            'engine': cluster.engine,
                                            'detection_mode': data_provider.provider_type,
                                        }
                                    ))

            ext_items = await self._detect_elasticache_extended_support(data_provider, settings)
            waste_items.extend(ext_items)

            # Deep ElastiCache detectors
            repl_items = await self._detect_elasticache_replication_waste(clusters, ELASTICACHE_PRICING, settings, data_provider)
            waste_items.extend(repl_items)

            migration_items = await self._detect_elasticache_engine_migration(clusters, ELASTICACHE_PRICING, settings, data_provider)
            waste_items.extend(migration_items)

            serverless_items = await self._detect_elasticache_serverless_optimization(clusters, ELASTICACHE_PRICING, data_provider, settings)
            waste_items.extend(serverless_items)

            tiering_items = await self._detect_elasticache_data_tiering(clusters, ELASTICACHE_PRICING, settings, data_provider)
            waste_items.extend(tiering_items)
            
            logger.info(f"ElastiCache detector found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"Error in ElastiCache waste detection: {e}")
            raise
    async def _elasticache_price_map(
        self,
        data_provider: "WasteDataProvider",
        clusters: list,
        extra_types=(),
    ) -> "ElastiCachePrices":
        """On-demand hourly prices for the clusters' node types and
        ``extra_types`` (downsize and data-tiering targets), region-scaled,
        per Price List engine family the clusters use (CLO-532 item 3: Valkey
        from the Valkey rows, Redis OSS and Memcached from the Redis rows).
        A type with no row for that engine is left out, so callers read it
        as MISSING."""
        region = getattr(data_provider, 'region', None) or 'us-east-1'
        types = sorted(
            t for t in {getattr(c, 'node_type', None) for c in clusters} | set(extra_types) if t
        )
        # Both families: a Redis OSS / Memcached cluster's Valkey migration
        # saving needs its type's Valkey row too. Static table reads.
        tables: Dict[str, Dict[str, float]] = {}
        for engine in ('redis', 'valkey'):
            table = tables.setdefault(engine, {})
            for node_type in types:
                price = await self.pricing_service.get_elasticache_price_known(
                    node_type, region, engine=engine,
                )
                if price is not None:
                    table[node_type] = price
        return ElastiCachePrices(**tables)
    async def _detect_elasticache_extended_support(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """Detect ElastiCache clusters with legacy engine versions under extended support policies."""
        waste_items: List[WasteItem] = []
        WARNING_WINDOW_DAYS = 90
        today = date.today()


        try:
            clusters = await data_provider.get_elasticache_clusters()
            billed_breakdown = {}
            if hasattr(data_provider, 'get_extended_support_cost_breakdown'):
                try:
                    billed_breakdown = await data_provider.get_extended_support_cost_breakdown(
                        service_keys=['elasticache'], days=30
                    )
                except TypeError:
                    billed_breakdown = {}
            for cluster in clusters:
                engine = (cluster.engine or '').lower().strip()
                version = (cluster.engine_version or '').strip()
                policy = resolve_version_policy('elasticache', version, engine)
                if not policy:
                    continue

                extended_start = policy['extended_start']
                target_version = policy['target_version']
                state, days_until = classify_support_state(policy, today=today, warning_window_days=WARNING_WINDOW_DAYS)

                if state == 'warning_imminent' and days_until is not None:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=cluster.cluster_id,
                        resource_type=ResourceType.ELASTICACHE_CLUSTER,
                        waste_type=WasteType.ELASTICACHE_EXTENDED_SUPPORT_COST,
                        title="ElastiCache Extended Support Surcharge Imminent",
                        description=(
                            f"ElastiCache cluster '{cluster.cluster_id}' ({engine} {version}) will enter "
                            f"extended support on {extended_start} ({days_until} days)."
                        ),
                        monthly_savings=settings.min_waste_threshold_usd,
                        confidence=ConfidenceLevel.HIGH,
                        action=f"Upgrade '{cluster.cluster_id}' to {engine} {target_version} before {extended_start}.",
                        explanation={
                            'detection': f"Version policy matched {engine} {version} with extended support start {extended_start}",
                            'threshold': f"Within warning window ({days_until} <= {WARNING_WINDOW_DAYS})",
                            'pricing': 'Extended support applies incremental charges once standard support ends.',
                            'why_waste': 'This surcharge is avoidable via timely engine version upgrades.',
                            'risk': 'Upgrade in maintenance windows and validate client/library compatibility.',
                        },
                        metadata={
                            'service': 'elasticache',
                            'engine': engine,
                            'current_version': version,
                            'target_version': target_version,
                            'support_eol_date': str(policy.get('eol_date', '')),
                            'extended_support_start': str(extended_start),
                            'days_until_extended_support': days_until,
                            'state': 'warning_imminent',
                            'billing_verified': False,
                            **surcharge_metadata(policy, today),
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
                    continue

                if state != 'active_surcharge':
                    continue

                # The node price is the surcharge base (a ratio of it). An
                # unknown node type is MISSING, not $0.10/hr, unless billing
                # data covers the cluster (the #1552 OpenSearch rule).
                hourly = await self.pricing_service.get_elasticache_price_known(
                    cluster.node_type, getattr(data_provider, 'region', None) or 'us-east-1',
                    engine=_elasticache_price_engine(cluster.engine),
                )
                base_monthly = (hourly or 0.0) * 730 * cluster.num_nodes
                billed_monthly, billed_verified = get_billed_surcharge_monthly(
                    billed_breakdown, 'elasticache', cluster.cluster_id
                )
                if hourly is None and needs_base_price(policy, today) and not billed_verified:
                    _note_elasticache_price_missing(
                        data_provider, cluster, verdict='extended-support surcharge',
                    )
                    continue
                estimated_monthly = estimate_surcharge({'base_monthly': base_monthly}, policy, today=today)
                monthly_surcharge = billed_monthly if billed_verified and billed_monthly is not None else estimated_monthly
                if monthly_surcharge >= settings.min_waste_threshold_usd:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=cluster.cluster_id,
                        resource_type=ResourceType.ELASTICACHE_CLUSTER,
                        waste_type=WasteType.ELASTICACHE_EXTENDED_SUPPORT_COST,
                        title="ElastiCache Extended Support Surcharge",
                        description=(
                            f"ElastiCache cluster '{cluster.cluster_id}' ({engine} {version}) is in extended support. "
                            f"Estimated surcharge: ${monthly_surcharge:.2f}/month."
                        ),
                        monthly_savings=monthly_surcharge,
                        confidence=ConfidenceLevel.MEDIUM,
                        action=f"Upgrade '{cluster.cluster_id}' to {engine} {target_version} to eliminate surcharge.",
                        explanation={
                            'detection': f"Version policy matched active extended support for {engine} {version}",
                            'threshold': 'Extended support state active for this engine/version policy entry.',
                            'pricing': (
                                f"Billing-backed monthly surcharge: ${monthly_surcharge:.2f}"
                                if billed_verified else
                                describe_estimate(policy, base_monthly, today)
                            ),
                            'why_waste': 'Extended support surcharges are avoidable with supported engine versions.',
                            'risk': 'Validate replication groups, parameter groups, and compatibility before upgrade.',
                        },
                        metadata={
                            'service': 'elasticache',
                            'engine': engine,
                            'current_version': version,
                            'target_version': target_version,
                            'support_eol_date': str(policy.get('eol_date', '')),
                            'extended_support_start': str(extended_start),
                            'state': 'active_surcharge',
                            'estimated_monthly_surcharge': round(monthly_surcharge, 2),
                            'billing_verified': billed_verified,
                            **surcharge_metadata(policy, today),
                            'detection_mode': data_provider.provider_type,
                        },
                    ))
        except Exception as e:
            logger.debug(f"ElastiCache extended support detection error: {e}")

        return waste_items
    async def _detect_elasticache_replication_waste(
        self,
        clusters: list,
        pricing: "ElastiCachePrices",
        settings: "WasteDetectionSettings",
        data_provider: "WasteDataProvider",
    ) -> List[WasteItem]:
        """Detect non-production ElastiCache clusters with unnecessary replicas.

        CLO-585: ``get_elasticache_clusters`` returns one row per MEMBER cache
        cluster (the primary and every replica, each its own CacheClusterId),
        so a per-member loop priced and emitted the group's own replica
        saving once per member — a 1-primary/2-replica group counted its
        saving three times. Grouped by replication group (falling back to
        the cluster id for a standalone cluster) so the saving is computed,
        and emitted, exactly once per group. Tags are read per member (a
        customer may tag only the primary), so any member's matching
        Environment-style tag counts for the whole group."""
        waste_items = []
        NON_PROD_VALUES = {'dev', 'development', 'staging', 'stg', 'test', 'testing', 'sandbox', 'qa', 'uat'}

        groups: Dict[str, list] = {}
        group_order: List[str] = []
        for cluster in clusters:
            key = cluster.replication_group_id or cluster.cluster_id
            if key not in groups:
                groups[key] = []
                group_order.append(key)
            groups[key].append(cluster)

        for key in group_order:
            members = groups[key]
            # Any member: the topology fields are the group's, and every
            # member shares them (members[0] is not necessarily the primary).
            representative = members[0]
            if representative.status != 'available':
                continue
            if representative.engine not in ('redis', 'valkey'):
                continue
            if representative.replicas_per_shard <= 0:
                continue

            # Check environment tag on any member of the group.
            env_value = None
            env_tag_key = None
            env_member = representative
            for member in members:
                for tag_key in ('Environment', 'environment', 'env', 'Env', 'ENV'):
                    if tag_key in member.tags:
                        candidate = member.tags[tag_key].lower().strip()
                        if candidate in NON_PROD_VALUES:
                            env_value, env_tag_key, env_member = candidate, tag_key, member
                            break
                if env_value:
                    break

            if not env_value:
                continue

            hourly_price = pricing.price(representative.node_type, representative.engine)
            if hourly_price is None:  # MISSING (noted by _detect_elasticache_waste)
                continue
            total_replicas = representative.replicas_per_shard * representative.num_shards
            savings = hourly_price * total_replicas * 730

            if savings < settings.min_waste_threshold_usd:
                continue

            waste_items.append(WasteItem(
                id=str(uuid.uuid4()),
                resource_id=key,
                resource_type=ResourceType.ELASTICACHE_CLUSTER,
                waste_type=WasteType.ELASTICACHE_REPLICATION_WASTE,
                title="ElastiCache Replication Waste (Non-Production)",
                description=(
                    f"Replication group '{key}' "
                    f"in {env_value} environment has {total_replicas} replica(s) costing "
                    f"${savings:.2f}/month. Non-production environments typically don't need "
                    f"replicas for high availability."
                ),
                monthly_savings=savings,
                confidence=ConfidenceLevel.HIGH,
                action="Remove replicas from this non-production cluster to reduce costs.",
                explanation={
                    'detection': (
                        f'Replication group has {representative.replicas_per_shard} replica(s) per shard '
                        f'({representative.num_shards} shard(s)) in {env_value} environment. '
                        f'Environment detected via tag: {env_tag_key}={env_member.tags.get(env_tag_key, env_value)}'
                    ),
                    'threshold': 'Non-production environments (dev/staging/test/sandbox) with replicas',
                    'pricing': (
                        f'{representative.node_type} × {total_replicas} replica(s) = ${savings:.2f}/month in replica costs alone. '
                        f'Each replica is a full node at the same hourly rate as the primary.'
                    ),
                    'why_waste': (
                        'Multi-AZ replication provides high availability for production workloads. '
                        'Non-production caches rarely need replicas — a single node is sufficient for dev/test.'
                    ),
                    'risk': (
                        'Removing replicas reduces availability during node failures. '
                        'This is acceptable for non-production environments. '
                        'Verify no load tests depend on read replica endpoints.'
                    ),
                },
                metadata={
                    'cluster_id': representative.cluster_id,
                    'replication_group_id': representative.replication_group_id,
                    'node_type': representative.node_type,
                    'num_replicas': total_replicas,
                    'num_shards': representative.num_shards,
                    'replicas_per_shard': representative.replicas_per_shard,
                    'environment': env_value,
                    'monthly_savings': round(savings, 2),
                    'engine': representative.engine,
                    'detection_mode': data_provider.provider_type,
                },
            ))

        return waste_items
    async def _detect_elasticache_engine_migration(
        self,
        clusters: list,
        pricing: "ElastiCachePrices",
        settings: "WasteDetectionSettings",
        data_provider: "WasteDataProvider",
    ) -> List[WasteItem]:
        """Detect Redis OSS / Memcached clusters cheaper on Valkey.

        CLO-532 item 3: the Valkey cost is the same node type's Valkey row in
        the Price List (MISSING when there is none), not a flat 20% off."""
        waste_items = []

        for cluster in clusters:
            if cluster.status != 'available':
                continue
            if cluster.engine not in ('redis', 'memcached'):
                continue

            hourly_price = pricing.price(cluster.node_type, cluster.engine)
            if hourly_price is None:  # MISSING (noted by _detect_elasticache_waste)
                continue
            valkey_hourly = pricing.price(cluster.node_type, 'valkey')
            if valkey_hourly is None:
                _note_elasticache_price_missing(
                    data_provider, cluster, verdict='Valkey migration saving',
                )
                continue
            current_monthly = hourly_price * cluster.num_nodes * 730
            valkey_monthly = valkey_hourly * cluster.num_nodes * 730
            savings = current_monthly - valkey_monthly
            saving_pct = savings / current_monthly * 100 if current_monthly else 0.0

            if savings < settings.min_waste_threshold_usd:
                continue

            waste_items.append(WasteItem(
                id=str(uuid.uuid4()),
                resource_id=cluster.cluster_id,
                resource_type=ResourceType.ELASTICACHE_CLUSTER,
                waste_type=WasteType.ELASTICACHE_ENGINE_MIGRATION,
                title="ElastiCache Valkey Migration Savings",
                description=(
                    f"Cluster '{cluster.cluster_id}' runs {cluster.engine} {cluster.engine_version} "
                    f"({cluster.node_type}, {cluster.num_nodes} nodes). Migrating to Valkey saves "
                    f"{saving_pct:.0f}% (~${savings:.2f}/month) with API compatibility."
                ),
                monthly_savings=savings,
                confidence=ConfidenceLevel.HIGH,
                action=f"Migrate from {cluster.engine} to Valkey for {saving_pct:.0f}% cost savings.",
                explanation={
                    'detection': (
                        f'Cluster runs {cluster.engine} {cluster.engine_version}. Valkey {cluster.node_type} nodes '
                        f'are {saving_pct:.0f}% cheaper (AWS Price List) with API compatibility.'
                    ),
                    'threshold': 'Engine is Redis OSS or Memcached (not yet Valkey)',
                    'pricing': (
                        f'Current: {cluster.engine} {cluster.node_type} × {cluster.num_nodes} = ${current_monthly:.2f}/month. '
                        f'Valkey: Same configuration = ${valkey_monthly:.2f}/month. '
                        f'Savings: ${savings:.2f}/month ({saving_pct:.0f}%).'
                    ),
                    'why_waste': (
                        'AWS prices Valkey nodes below Redis OSS and Memcached nodes of the same type. '
                        'Valkey is API-compatible with Redis 7.x, so most applications require no code changes. '
                        'Existing Redis OSS reserved node reservations also apply to Valkey.'
                    ),
                    'risk': (
                        'Valkey is API-compatible with Redis 7.x but some Redis-specific modules may not be supported. '
                        'Test application compatibility in a staging environment first. '
                        'For Memcached: migration requires code changes as the protocols differ.'
                    ),
                },
                metadata={
                    'cluster_id': cluster.cluster_id,
                    'engine': cluster.engine,
                    'engine_version': cluster.engine_version,
                    'node_type': cluster.node_type,
                    'num_nodes': cluster.num_nodes,
                    'current_monthly': round(current_monthly, 2),
                    'monthly_savings': round(savings, 2),
                    'detection_mode': data_provider.provider_type,
                },
            ))

        return waste_items
    async def _detect_elasticache_serverless_optimization(
        self,
        clusters: list,
        pricing: "ElastiCachePrices",
        data_provider: "WasteDataProvider",
        settings: "WasteDetectionSettings",
    ) -> List[WasteItem]:
        """Detect node-based clusters with spiky traffic better suited for Serverless."""
        waste_items = []
        note_missing = getattr(data_provider, '_note_idle_verdict_missing', None)

        # Phase 1: the spikiness gate, per cluster (unchanged).
        candidates = []
        for cluster in clusters:
            if cluster.status != 'available':
                continue
            if cluster.engine not in ('redis', 'valkey'):
                continue

            if not (settings.cloudwatch_enabled and data_provider.supports_cloudwatch):
                continue

            hourly_price = pricing.price(cluster.node_type, cluster.engine)
            if hourly_price is None:  # MISSING (noted by _detect_elasticache_waste)
                continue
            current_monthly = hourly_price * cluster.num_nodes * 730

            if current_monthly < settings.min_waste_threshold_usd:
                continue

            try:
                metrics_map = await data_provider.get_elasticache_metrics(
                    cluster_ids=[cluster.cluster_id],
                    days=30,
                    create_times={cluster.cluster_id: getattr(cluster, 'created_time', None)},  # CLO-457
                )
            except Exception as e:
                logger.debug(f"Serverless optimization check failed for {cluster.cluster_id}: {e}")
                continue
            metrics = metrics_map.get(cluster.cluster_id)
            if not metrics:
                continue

            avg_cpu = metrics.cpu_utilization_avg
            peak_cpu = metrics.cpu_utilization_max
            conn_avg = metrics.current_connections_avg
            conn_std = metrics.current_connections_std

            # Coefficient of variation for connection spikiness
            cv = (conn_std / conn_avg) if conn_avg > 0 else 0.0

            if avg_cpu >= 15 or peak_cpu <= 60 or cv <= 2.0:
                continue

            if metrics.bytes_used_for_cache <= 0:
                if callable(note_missing):
                    note_missing(
                        'elasticache-serverless', cluster.cluster_id,
                        "no BytesUsedForCache", verdict='serverless-estimate',
                        evidence='data size and command counts',
                    )
                continue
            candidates.append((cluster, metrics, current_monthly, avg_cpu, peak_cpu, cv))

        if not candidates:
            return waste_items

        # Phase 2: request volume for every gated cluster in ONE provider
        # call (batched GetMetricData online). A cluster left out of the map
        # is MISSING; the provider notes it, so it is not noted again here.
        volume_getter = getattr(data_provider, 'get_elasticache_request_volume', None)
        try:
            volumes = await volume_getter(
                cluster_ids=[c.cluster_id for c, *_ in candidates],
                days=30,
                create_times={c.cluster_id: getattr(c, 'created_time', None) for c, *_ in candidates},
            ) if callable(volume_getter) else {}
        except Exception as e:
            logger.debug(f"ElastiCache request volume read failed: {e}")
            volumes = {}

        # Phase 3: the Serverless estimate from MEASURED inputs (CLO-508). It
        # used to assume 25% of node memory as data and a flat 259M
        # ECPU/month at Valkey rates for every engine.
        #  - data: BytesUsedForCache (the node's average allocation, which
        #    includes buffers, so it over- rather than under-states stored
        #    data), at least the engine's billed minimum;
        #  - ECPU: one per command, or one per KB transferred when the traffic
        #    outweighs the command count (Serverless bills the larger),
        #    scaled to a month;
        #  - the cluster's own engine's Serverless rates.
        for cluster, metrics, current_monthly, avg_cpu, peak_cpu, cv in candidates:
            try:
                volume = (volumes or {}).get(cluster.cluster_id)
                if volume is None or volume.period_days <= 0:
                    continue

                rates = ELASTICACHE_SERVERLESS_RATES.get(cluster.engine, ELASTICACHE_SERVERLESS_RATES['redis'])
                data_gb = max(metrics.bytes_used_for_cache / (1024 ** 3), rates['min_data_gb'])
                data_cost_monthly = data_gb * rates['data_gb_hour'] * 730
                ecpu_window = max(volume.commands_total, volume.network_bytes_total / 1024)
                ecpu_monthly_count = ecpu_window * (730 / (volume.period_days * 24))
                ecpu_monthly = ecpu_monthly_count / 1_000_000 * rates['ecpu_per_million']
                estimated_serverless = data_cost_monthly + ecpu_monthly

                savings = current_monthly - estimated_serverless
                if savings < settings.min_waste_threshold_usd:
                    continue

                waste_items.append(WasteItem(
                    id=str(uuid.uuid4()),
                    resource_id=cluster.cluster_id,
                    resource_type=ResourceType.ELASTICACHE_CLUSTER,
                    waste_type=WasteType.ELASTICACHE_SERVERLESS_OPTIMIZATION,
                    title="ElastiCache Serverless Optimization Opportunity",
                    description=(
                        f"Cluster '{cluster.cluster_id}' ({cluster.node_type}, {cluster.num_nodes} nodes) has spiky "
                        f"traffic (avg CPU {avg_cpu:.1f}%, peak {peak_cpu:.1f}%). Serverless may save "
                        f"~${savings:.2f}/month by eliminating over-provisioned capacity."
                    ),
                    monthly_savings=savings,
                    confidence=ConfidenceLevel.MEDIUM,
                    action="Evaluate migrating to ElastiCache Serverless for this spiky workload.",
                    explanation={
                        'detection': (
                            f'Cluster has spiky traffic pattern: avg CPU {avg_cpu:.1f}%, peak CPU {peak_cpu:.1f}%, '
                            f'connection CV {cv:.2f}. Over-provisioned for peaks, underutilized at baseline.'
                        ),
                        'threshold': 'Average CPU < 15%, peak CPU > 60%, connection coefficient of variation > 2.0',
                        'pricing': (
                            f'Current node-based: ${current_monthly:.2f}/month. '
                            f'Estimated Serverless ({cluster.engine}): ${estimated_serverless:.2f}/month = '
                            f'{data_gb:.2f} GB data x ${rates["data_gb_hour"]}/GB-hr x 730 '
                            f'(${data_cost_monthly:.2f}) + {ecpu_monthly_count / 1_000_000:,.0f}M ECPU/month '
                            f'x ${rates["ecpu_per_million"]}/M (${ecpu_monthly:.2f}), from measured '
                            f'BytesUsedForCache and {volume.command_metric} over {volume.period_days} days.'
                        ),
                        'why_waste': (
                            'Node-based clusters charge per-hour regardless of traffic. '
                            'With spiky workloads, most of the capacity sits idle most of the time. '
                            'Serverless scales to zero during quiet periods and auto-scales for peaks.'
                        ),
                        'risk': (
                            'Serverless has slightly higher per-request latency than node-based clusters. '
                            'Not available for Memcached. Data tiering is not supported with Serverless. '
                            'Requires migrating data and updating application endpoints. '
                            'Test with production-like traffic patterns before committing.'
                        ),
                    },
                    metadata={
                        'cluster_id': cluster.cluster_id,
                        'node_type': cluster.node_type,
                        'num_nodes': cluster.num_nodes,
                        'avg_cpu': round(avg_cpu, 1),
                        'peak_cpu': round(peak_cpu, 1),
                        'connection_cv': round(cv, 2),
                        'current_monthly': round(current_monthly, 2),
                        'estimated_serverless': round(estimated_serverless, 2),
                        'serverless_data_gb': round(data_gb, 3),
                        'serverless_ecpu_per_month': round(ecpu_monthly_count),
                        'command_metric': volume.command_metric,
                        'monthly_savings': round(savings, 2),
                        'engine': cluster.engine,
                        'detection_mode': data_provider.provider_type,
                    },
                ))
            except Exception as e:
                logger.debug(f"Serverless optimization check failed for {cluster.cluster_id}: {e}")

        return waste_items
    async def _detect_elasticache_data_tiering(
        self,
        clusters: list,
        pricing: "ElastiCachePrices",
        settings: "WasteDetectionSettings",
        data_provider: "WasteDataProvider",
    ) -> List[WasteItem]:
        """Detect R5/R6g/R7g replication groups eligible for R6gd data tiering
        (up to 52% savings).

        CLO-584: ``get_elasticache_clusters`` returns one row per MEMBER
        cache cluster (NumCacheNodes=1 for every Redis/Valkey member), so
        pricing one row's single node against one r6gd node always priced a
        loss — r6gd always costs more per node, so the "saving" was negative
        and floored out. Evaluated per replication group instead (falling
        back to the cluster id for a standalone cluster, which for
        Redis/Valkey is always a single node anyway): the memory a GROUP's
        shards hold — not the replica copies of it — decides how many r6gd
        shards are needed, and the result keeps the group's own replica
        factor (data tiering does not remove HA; a replica is a full copy of
        its shard, at the new node type, not a shard of new data)."""
        waste_items = []

        # Mapping from memory-only types to R6gd equivalents
        R6GD_MAP = {
            'cache.r6g.xlarge': 'cache.r6gd.xlarge',
            'cache.r6g.2xlarge': 'cache.r6gd.2xlarge',
            'cache.r6g.4xlarge': 'cache.r6gd.4xlarge',
            'cache.r6g.8xlarge': 'cache.r6gd.8xlarge',
            'cache.r6g.12xlarge': 'cache.r6gd.12xlarge',
            'cache.r6g.16xlarge': 'cache.r6gd.16xlarge',
            'cache.r5.xlarge': 'cache.r6gd.xlarge',
            'cache.r5.2xlarge': 'cache.r6gd.2xlarge',
            'cache.r7g.xlarge': 'cache.r6gd.xlarge',
            'cache.r7g.2xlarge': 'cache.r6gd.2xlarge',
        }

        # R6gd total capacity (memory + SSD) in GiB, AWS's documented figures.
        # Source: the ElastiCache "Data tiering" page (docs.aws.amazon.com/
        # AmazonElastiCache/latest/dg/data-tiering.html) and "Supported node
        # types" (CacheNodes.SupportedTypes.html), confirmed 2026-10-05 via
        # search excerpts of those pages (the docs host was egress-blocked):
        #   xlarge   26.32 + 99.33   = 125.65
        #   2xlarge  52.82 + 199.07  = 251.89
        #   4xlarge  105.81 + 398.14 = 503.95
        #   16xlarge 419.09 + 1592.56 = 2011.65 (AWS's launch range,
        #            26.32-419.09 GiB memory + 99.33-1592.56 GiB SSD)
        # The old table (145/290/.../2320) overstated each size by ~15%.
        # 8xlarge and 12xlarge are WITHHELD: no AWS-attributed figure could be
        # confirmed, so a group mapping to them is skipped (MISSING), not
        # sized on a guess.
        R6GD_TOTAL_CAPACITY = {
            'cache.r6gd.xlarge': 26.32 + 99.33,
            'cache.r6gd.2xlarge': 52.82 + 199.07,
            'cache.r6gd.4xlarge': 105.81 + 398.14,
            'cache.r6gd.16xlarge': 419.09 + 1592.56,
        }

        NODE_MEMORY_GIB = {
            'cache.r5.xlarge': 26.32, 'cache.r5.2xlarge': 52.82,
            'cache.r6g.xlarge': 26.32, 'cache.r6g.2xlarge': 52.82,
            'cache.r6g.4xlarge': 105.81, 'cache.r6g.8xlarge': 209.55,
            'cache.r6g.12xlarge': 317.77, 'cache.r6g.16xlarge': 419.09,
            'cache.r7g.xlarge': 26.32, 'cache.r7g.2xlarge': 52.82,
        }

        import math

        groups: Dict[str, list] = {}
        group_order: List[str] = []
        for cluster in clusters:
            key = cluster.replication_group_id or cluster.cluster_id
            if key not in groups:
                groups[key] = []
                group_order.append(key)
            groups[key].append(cluster)

        for key in group_order:
            members = groups[key]
            # Any member: the topology fields are the group's, and every
            # member shares them (members[0] is not necessarily the primary).
            cluster = members[0]
            if cluster.status != 'available':
                continue
            if cluster.engine not in ('redis', 'valkey'):
                continue
            # Data tiering needs Valkey or Redis OSS 6.2+. An older (or
            # unreadable) Redis version can't adopt r6gd without an engine
            # upgrade, so it is not recommended here.
            if cluster.engine == 'redis' and not _redis_supports_data_tiering(cluster.engine_version):
                continue
            if cluster.data_tiering_enabled:
                continue
            if cluster.node_type not in R6GD_MAP:
                continue

            r6gd_type = R6GD_MAP[cluster.node_type]
            r6gd_capacity = R6GD_TOTAL_CAPACITY.get(r6gd_type)
            if r6gd_capacity is None:  # MISSING: withheld size, see the table
                continue
            node_memory = NODE_MEMORY_GIB.get(cluster.node_type, 26.32)

            num_shards = max(cluster.num_shards, 1)
            replicas_per_shard = max(cluster.replicas_per_shard, 0)
            total_nodes = num_shards * (replicas_per_shard + 1)

            # Data tiering sizes SHARDS, not replica copies: the unique data
            # a group holds is one copy per shard, and every replica stays a
            # full copy of its own shard at the new node type.
            shard_data_gib = node_memory * num_shards
            r6gd_shards_needed = max(1, math.ceil(shard_data_gib / r6gd_capacity))
            r6gd_nodes_needed = r6gd_shards_needed * (replicas_per_shard + 1)

            current_price = pricing.price(cluster.node_type, cluster.engine)
            r6gd_price = pricing.price(r6gd_type, cluster.engine)
            if current_price is None or r6gd_price is None:
                # MISSING: an unpriced current type is noted by
                # _detect_elasticache_waste; the r6gd targets are all in the
                # Price List table.
                continue

            current_monthly = current_price * total_nodes * 730
            r6gd_monthly = r6gd_price * r6gd_nodes_needed * 730

            savings = current_monthly - r6gd_monthly
            if savings < settings.min_waste_threshold_usd:
                continue

            savings_pct = (savings / current_monthly * 100) if current_monthly > 0 else 0

            waste_items.append(WasteItem(
                id=str(uuid.uuid4()),
                resource_id=key,
                resource_type=ResourceType.ELASTICACHE_CLUSTER,
                waste_type=WasteType.ELASTICACHE_DATA_TIERING_OPPORTUNITY,
                title="ElastiCache Data Tiering Opportunity",
                description=(
                    f"Replication group '{key}' runs {num_shards} shard(s) × "
                    f"{replicas_per_shard + 1} node(s) of {cluster.node_type} (memory-only). "
                    f"Migrating to R6gd data tiering could consolidate to {r6gd_shards_needed} "
                    f"shard(s) × {replicas_per_shard + 1} node(s) of {r6gd_type}, "
                    f"saving ~${savings:.2f}/month ({savings_pct:.0f}% reduction)."
                ),
                monthly_savings=savings,
                confidence=ConfidenceLevel.MEDIUM,
                action="Evaluate migrating to R6gd nodes with data tiering for cost savings.",
                explanation={
                    'detection': (
                        f'Group runs {num_shards} shard(s) of {cluster.node_type} '
                        f'({shard_data_gib:.1f} GiB of unique memory across shards, '
                        f'{total_nodes} node(s) total with replicas). '
                        f'R6gd data tiering could provide equivalent capacity with fewer shards.'
                    ),
                    'threshold': 'Memory-optimized R5/R6g/R7g nodes at xlarge or larger, not already using R6gd',
                    'pricing': (
                        f'Current: {total_nodes}× {cluster.node_type} = ${current_monthly:.2f}/month. '
                        f'With data tiering: {r6gd_nodes_needed}× {r6gd_type} = ${r6gd_monthly:.2f}/month. '
                        f'Savings: ${savings:.2f}/month ({savings_pct:.0f}% reduction).'
                    ),
                    'why_waste': (
                        'R6gd nodes combine memory and NVMe SSD, automatically tiering least-frequently-accessed '
                        'data to SSD. This provides ~5× total storage capacity per shard, allowing fewer shards for the '
                        'same dataset while keeping the same replica count. AWS benchmarks show up to 52% cost '
                        'reduction for large datasets.'
                    ),
                    'risk': (
                        'SSD-resident data has slightly higher latency on first access (sub-millisecond vs microsecond). '
                        'Best for workloads where < 20% of data is accessed frequently. '
                        'Not available with ElastiCache Serverless. '
                        'Requires creating a new cluster and migrating data.'
                    ),
                },
                metadata={
                    'cluster_id': cluster.cluster_id,
                    'replication_group_id': cluster.replication_group_id,
                    'current_type': cluster.node_type,
                    'num_nodes': total_nodes,
                    'num_shards': num_shards,
                    'replicas_per_shard': replicas_per_shard,
                    'recommended_type': r6gd_type,
                    'recommended_nodes': r6gd_nodes_needed,
                    'recommended_shards': r6gd_shards_needed,
                    'current_monthly': round(current_monthly, 2),
                    'r6gd_monthly': round(r6gd_monthly, 2),
                    'monthly_savings': round(savings, 2),
                    'savings_pct': round(savings_pct, 1),
                    'engine': cluster.engine,
                    'detection_mode': data_provider.provider_type,
                },
            ))

        return waste_items
    # vCPU count by instance class
    INSTANCE_VCPU_MAP: Dict[str, int] = {
        'db.t3.small': 2, 'db.t3.medium': 2, 'db.t3.large': 2,
        'db.t4g.medium': 2, 'db.t4g.large': 2,
        'db.r5.large': 2, 'db.r5.xlarge': 4, 'db.r5.2xlarge': 8,
        'db.r5.4xlarge': 16, 'db.r5.8xlarge': 32, 'db.r5.12xlarge': 48,
        'db.r5.16xlarge': 64, 'db.r5.24xlarge': 96,
        'db.r6g.large': 2, 'db.r6g.xlarge': 4, 'db.r6g.2xlarge': 8,
        'db.r6g.4xlarge': 16, 'db.r6g.8xlarge': 32, 'db.r6g.12xlarge': 48,
        'db.r6g.16xlarge': 64,
        'db.r6i.large': 2, 'db.r6i.xlarge': 4, 'db.r6i.2xlarge': 8,
        'db.r6i.4xlarge': 16, 'db.r6i.8xlarge': 32, 'db.r6i.12xlarge': 48,
        'db.r6i.16xlarge': 64, 'db.r6i.24xlarge': 96,
        'db.r7g.large': 2, 'db.r7g.xlarge': 4, 'db.r7g.2xlarge': 8,
        'db.r7g.4xlarge': 16, 'db.r7g.8xlarge': 32, 'db.r7g.12xlarge': 48,
        'db.r7g.16xlarge': 64,
        'db.serverless': 0,  # Serverless — priced per ACU, not vCPU
    }
