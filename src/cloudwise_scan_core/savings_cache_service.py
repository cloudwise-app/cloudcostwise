"""
Savings Recommendations Cache Service

This service caches AWS Cost Explorer RI and Savings Plans recommendations
to minimize API costs ($0.01 per request) by refreshing weekly during waste detection.

Architecture:
- Recommendations are cached per AWS account with 7-day TTL
- During waste detection, checks if cache is older than 7 days
- If cache expired, refreshes from Cost Explorer API, then caches
- This way, API is called at most once per account per week

Cost Impact:
- Weekly refresh during waste detection: $0.16/account/month (4 API calls × 4 weeks × $0.01)
- Subsequent scans within 7 days: Use cached data ($0/scan)
"""

import asyncio
import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
import hashlib

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from cloudwise_scan_core.config import (
    get_env_detector_provider,
    get_parameter_store_provider,
    get_settings_provider,
)

logger = logging.getLogger(__name__)

# Cache TTL: 7 days (weekly refresh cycle)
CACHE_TTL_DAYS = 7

# CLO-505: bound on DescribeSavingsPlans pages per refresh (free API).
SP_INVENTORY_MAX_PAGES = 20

# Key for storing last refresh timestamp per account
LAST_REFRESH_KEY_PREFIX = "last_refresh:"

DEFAULT_BOTO_CONFIG = Config(
    read_timeout=60,
    connect_timeout=10,
    retries={'max_attempts': 3, 'mode': 'adaptive'}
)


class _CountingClient:
    """Thin proxy around a boto3 client that counts every method call
    made through it (CLO-358).

    ``refresh_account_recommendations`` previously reported ``api_calls``
    as ``len(CE_PAID_KEYS)`` (11) — one per *fetch function*, regardless of
    how many real Cost Explorer requests that function issued.
    ``_fetch_ri_utilization`` alone loops over 5 services and makes 5
    ``get_reservation_utilization`` calls, so the true count (measured via
    CloudTrail) is 15, not 11. Wrapping only the ``ce`` client (never the
    free ``ec2``/``savingsplans`` clients used for RI/SP *inventory*) makes
    the counter reflect actual billed requests, whatever fetch function or
    loop made them — and each fetch runs in its own thread via
    ``asyncio.to_thread``, hence the lock.
    """

    def __init__(self, client: Any):
        self._client = client
        self._lock = threading.Lock()
        self._count = 0

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._client, name)
        if not callable(attr):
            return attr

        def _counted(*args: Any, **kwargs: Any) -> Any:
            with self._lock:
                self._count += 1
            return attr(*args, **kwargs)

        return _counted

    @property
    def call_count(self) -> int:
        with self._lock:
            return self._count


def _get_table_name() -> str:
    """
    Get the DynamoDB table name following CloudWise naming conventions.
    
    Pattern: cloudwise-{environment}-savings-recommendations-cache
    
    Checks in order:
    1. Environment variable SAVINGS_CACHE_TABLE_NAME (for explicit override)
    2. Parameter Store: lambda/savings-recommendations-cache-table
    3. Default: cloudwise-{environment}-savings-recommendations-cache
    """
    # Check environment variable first (allows explicit override)
    env_table = os.environ.get('SAVINGS_CACHE_TABLE_NAME')
    if env_table:
        return env_table
    
    # Try Parameter Store if available (injected by the runtime adapter)
    try:
        ps_config = get_parameter_store_provider()()
        if ps_config is not None and ps_config.is_using_parameter_store:
            table_name = ps_config.get_parameter('lambda/savings-recommendations-cache-table')
            if table_name:
                logger.debug(f"Using table name from Parameter Store: {table_name}")
                return table_name
    except Exception as e:
        logger.debug(f"Parameter Store not available for table name: {e}")

    # Default: use environment-aware naming
    env_detector = get_env_detector_provider()()
    env = env_detector.environment_name or 'staging'
    table_name = f"cloudwise-{env}-savings-recommendations-cache"
    logger.debug(f"Using default table name: {table_name}")
    return table_name


class SavingsRecommendationsCacheService:
    """
    Caches RI and Savings Plans recommendations from AWS Cost Explorer.
    
    This service:
    1. Stores recommendations in DynamoDB with 7-day TTL
    2. Checks if refresh is needed (once per week per account)
    3. Refreshes during waste detection scan if cache expired
    4. Tracks API call costs for billing purposes
    
    Usage pattern (in waste detection Lambda):
    1. Call needs_refresh() to check if cache is older than 7 days
    2. If needs refresh, call refresh_account_recommendations()
    3. Read from cache using get_cached_recommendations()
    """
    
    def __init__(self, persist: bool = True):
        self.settings = get_settings_provider()()
        # persist=False keeps the cache in memory only (``_local_cache``) and
        # never touches DynamoDB: the local CLI/MCP scan runs on the user's
        # own credentials and must make no write and no non-scan call.
        self._dynamodb = None if persist else _InMemoryOnlyResource()
        self._local_cache: Dict[str, Dict] = {}  # In-memory fallback
        self._table_name: Optional[str] = None
    
    @property
    def table_name(self) -> str:
        """Get the DynamoDB table name (cached after first access)."""
        if self._table_name is None:
            self._table_name = _get_table_name()
        return self._table_name
    
    @property
    def dynamodb(self):
        """Lazy initialization of DynamoDB client."""
        if self._dynamodb is None:
            self._dynamodb = boto3.resource(
                'dynamodb',
                region_name=getattr(self.settings, 'AWS_REGION', None) or 'us-east-1'
            )
        return self._dynamodb
    
    def _get_cache_key(self, account_id: str, recommendation_type: str) -> str:
        """Generate cache key for account + recommendation type."""
        return f"{account_id}:{recommendation_type}"
    
    def _get_last_refresh_key(self, account_id: str) -> str:
        """Generate key for storing last refresh timestamp."""
        return f"{LAST_REFRESH_KEY_PREFIX}{account_id}"
    
    async def needs_refresh(self, account_id: str) -> bool:
        """
        Check if recommendations for this account need to be refreshed.
        
        Returns True if:
        - No cached data exists for this account
        - Cached data is older than CACHE_TTL_DAYS (7 days)
        
        This is the main check to decide whether to call Cost Explorer APIs.
        """
        pk = f"ACCOUNT#{account_id}"
        sk = "META#last_refresh"
        local_cache_key = f"{pk}#{sk}"
        
        # Check in-memory cache first
        if local_cache_key in self._local_cache:
            last_refresh = self._local_cache[local_cache_key].get('timestamp', 0)
            age_days = (datetime.now(timezone.utc).timestamp() - last_refresh) / 86400
            if age_days < CACHE_TTL_DAYS:
                logger.debug(f"Account {account_id} refreshed {age_days:.1f} days ago, no refresh needed")
                return False
        
        # Check DynamoDB
        try:
            table = self.dynamodb.Table(self.table_name)
            response = table.get_item(
                Key={'pk': pk, 'sk': sk}
            )
            
            item = response.get('Item')
            if item:
                last_refresh = item.get('timestamp', 0)
                # Convert Decimal to float for arithmetic (DynamoDB returns Decimal)
                if hasattr(last_refresh, '__float__'):
                    last_refresh = float(last_refresh)
                age_days = (datetime.now(timezone.utc).timestamp() - last_refresh) / 86400
                
                # Update local cache
                self._local_cache[local_cache_key] = {'timestamp': last_refresh}
                
                if age_days < CACHE_TTL_DAYS:
                    logger.debug(f"Account {account_id} refreshed {age_days:.1f} days ago, no refresh needed")
                    return False
                else:
                    logger.info(f"Account {account_id} cache is {age_days:.1f} days old, refresh needed")
                    return True
            else:
                logger.info(f"No cached recommendations for account {account_id}, refresh needed")
                return True
                
        except ClientError as e:
            logger.warning(f"DynamoDB error checking refresh status: {e}")
            # If we can't check, assume refresh is needed to be safe
            return True
        except Exception as e:
            logger.warning(f"Error checking refresh status: {e}")
            return True
    
    async def _update_last_refresh_timestamp(self, account_id: str) -> None:
        """Update the last refresh timestamp for an account."""
        pk = f"ACCOUNT#{account_id}"
        sk = "META#last_refresh"
        local_cache_key = f"{pk}#{sk}"
        timestamp = datetime.now(timezone.utc).timestamp()
        ttl = int((datetime.now(timezone.utc) + timedelta(days=CACHE_TTL_DAYS + 1)).timestamp())
        
        # Update local cache
        self._local_cache[local_cache_key] = {'timestamp': timestamp}
        
        # Update DynamoDB
        try:
            table = self.dynamodb.Table(self.table_name)
            table.put_item(
                Item={
                    'pk': pk,
                    'sk': sk,
                    'gsi1pk': f"ACCOUNT#{account_id}",
                    'gsi1sk': "META#last_refresh",
                    'timestamp': int(timestamp),
                    'updated_at': datetime.now(timezone.utc).isoformat(),
                    'account_id': account_id,
                    'ttl': ttl,
                }
            )
            logger.debug(f"Updated last refresh timestamp for account {account_id}")
        except Exception as e:
            logger.warning(f"Failed to update last refresh timestamp: {e}")
    
    async def get_cached_recommendations(
        self,
        account_id: str,
        recommendation_type: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached recommendations for an account.
        
        Args:
            account_id: AWS account ID
            recommendation_type: One of 'ec2_ri', 'rds_ri', 'compute_sp', 'ec2_sp'
        
        Returns:
            Cached recommendation data or None if cache miss/expired
        """
        pk = f"ACCOUNT#{account_id}"
        sk = f"REC#{recommendation_type}"
        local_cache_key = f"{pk}#{sk}"
        
        # Check in-memory cache first
        if local_cache_key in self._local_cache:
            cached = self._local_cache[local_cache_key]
            if cached.get('expires_at', 0) > datetime.now(timezone.utc).timestamp():
                logger.debug(f"Cache HIT (memory) for {local_cache_key}")
                return cached.get('recommendations')
        
        # Check DynamoDB
        try:
            table = self.dynamodb.Table(self.table_name)
            response = table.get_item(
                Key={'pk': pk, 'sk': sk}
            )
            
            item = response.get('Item')
            if item:
                expires_at = item.get('expires_at', 0)
                if expires_at > datetime.now(timezone.utc).timestamp():
                    logger.debug(f"Cache HIT (DynamoDB) for {local_cache_key}")
                    # Update local cache
                    self._local_cache[local_cache_key] = {
                        'recommendations': item.get('recommendations'),
                        'expires_at': expires_at
                    }
                    return item.get('recommendations')
                else:
                    logger.debug(f"Cache EXPIRED for {local_cache_key}")
            else:
                logger.debug(f"Cache MISS for {local_cache_key}")
                
        except ClientError as e:
            logger.warning(f"DynamoDB cache read error: {e}")
        except Exception as e:
            logger.warning(f"Cache read error: {e}")
        
        return None
    
    async def set_cached_recommendations(
        self,
        account_id: str,
        recommendation_type: str,
        recommendations: List[Dict[str, Any]],
        ttl_days: int = CACHE_TTL_DAYS
    ) -> bool:
        """
        Cache recommendations for an account.
        
        Args:
            account_id: AWS account ID
            recommendation_type: One of 'ec2_ri', 'rds_ri', 'compute_sp', 'ec2_sp'
            recommendations: List of recommendation data
            ttl_days: Cache TTL in days (default: 7)
        
        Returns:
            True if caching succeeded
        """
        pk = f"ACCOUNT#{account_id}"
        sk = f"REC#{recommendation_type}"
        local_cache_key = f"{pk}#{sk}"
        expires_at = int((datetime.now(timezone.utc) + timedelta(days=ttl_days)).timestamp())
        ttl = int((datetime.now(timezone.utc) + timedelta(days=ttl_days + 1)).timestamp())
        
        cache_data = {
            'recommendations': recommendations,
            'expires_at': expires_at,
            'cached_at': datetime.now(timezone.utc).isoformat(),
            'account_id': account_id,
            'recommendation_type': recommendation_type,
        }
        
        # Update local cache
        self._local_cache[local_cache_key] = cache_data
        
        # Update DynamoDB
        try:
            table = self.dynamodb.Table(self.table_name)
            table.put_item(
                Item={
                    'pk': pk,
                    'sk': sk,
                    'gsi1pk': f"ACCOUNT#{account_id}",
                    'gsi1sk': f"REC#{recommendation_type}",
                    'ttl': ttl,
                    **cache_data
                }
            )
            logger.info(f"Cached {len(recommendations)} {recommendation_type} recommendations for account {account_id}")
            return True
            
        except ClientError as e:
            logger.warning(f"DynamoDB cache write error: {e}")
            # Local cache still works
            return True
        except Exception as e:
            logger.warning(f"Cache write error: {e}")
            return False
    
    async def refresh_account_recommendations(
        self,
        creds: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Refresh all recommendations for a single account.

        All CE/EC2/SP fetches run in parallel (asyncio.to_thread) so the total
        wall-clock time is bounded by the slowest individual call (~2-3 s)
        rather than the sum of all calls (~20-30 s sequential).

        Args:
            creds: AWS credentials dict with access_key_id, secret_access_key, account_id

        Returns:
            Summary of refreshed recommendations and API costs
        """
        account_id = creds.get('account_id', 'unknown')

        try:
            ce_client = boto3.client(
                'ce',
                aws_access_key_id=creds['access_key_id'],
                aws_secret_access_key=creds['secret_access_key'],
                region_name='us-east-1',  # Cost Explorer is global
                aws_session_token=creds.get('session_token'),
                config=DEFAULT_BOTO_CONFIG
            )
            ec2_client = boto3.client(
                'ec2',
                aws_access_key_id=creds['access_key_id'],
                aws_secret_access_key=creds['secret_access_key'],
                region_name='us-east-1',  # RI inventory is global from us-east-1
                aws_session_token=creds.get('session_token'),
                config=DEFAULT_BOTO_CONFIG,
            )
            sp_client = boto3.client(
                'savingsplans',
                aws_access_key_id=creds['access_key_id'],
                aws_secret_access_key=creds['secret_access_key'],
                region_name='us-east-1',
                aws_session_token=creds.get('session_token'),
                config=DEFAULT_BOTO_CONFIG,
            )

            # CLO-358: count actual billed ce:* requests as they're made,
            # instead of assuming one per fetch function (see
            # ``_CountingClient``). ec2_client/sp_client are never wrapped —
            # RI/SP *inventory* are free APIs and must not inflate the count.
            counted_ce_client = _CountingClient(ce_client)

            # --- Run all fetches in parallel using asyncio.to_thread ---
            # Each _fetch_* is an async def that wraps synchronous boto3 calls.
            # asyncio.to_thread pushes each into the thread pool so they execute
            # concurrently rather than blocking the event loop sequentially.
            (
                ec2_ri, rds_ri, opensearch_ri, compute_sp, ec2_sp,
                elasticache_ri, redshift_ri, sagemaker_sp,
                ri_utilization, ri_inventory,
                sp_utilization, sp_inventory, sp_coverage,
            ) = await asyncio.gather(
                asyncio.to_thread(lambda: asyncio.run(self._fetch_ec2_ri_recommendations(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_rds_ri_recommendations(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_opensearch_ri_recommendations(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_compute_sp_recommendations(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_ec2_sp_recommendations(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_elasticache_ri_recommendations(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_redshift_ri_recommendations(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_sagemaker_sp_recommendations(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_ri_utilization(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_ri_inventory(ec2_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_sp_utilization(counted_ce_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_sp_inventory(sp_client))),
                asyncio.to_thread(lambda: asyncio.run(self._fetch_sp_coverage(counted_ce_client))),
                return_exceptions=True,
            )

        except Exception as e:
            logger.error(f"Error refreshing recommendations for account {account_id}: {e}")
            return {
                'success': False,
                'account_id': account_id,
                'error': str(e),
                'api_calls': 0,
                'api_cost_usd': 0.0,
            }

        # Cache results (best-effort — log but don't fail on individual errors)
        fetch_results = {
            'ec2_ri': ec2_ri, 'rds_ri': rds_ri, 'opensearch_ri': opensearch_ri,
            'compute_sp': compute_sp, 'ec2_sp': ec2_sp,
            'elasticache_ri': elasticache_ri, 'redshift_ri': redshift_ri,
            'sagemaker_sp': sagemaker_sp,
            'ri_utilization': ri_utilization, 'ri_inventory': ri_inventory,
            'sp_utilization': sp_utilization, 'sp_inventory': sp_inventory,
            'sp_coverage': sp_coverage,
        }
        # CLO-358: api_calls is the number of real ce:* requests
        # ``counted_ce_client`` actually made (see ``_CountingClient``) —
        # not the number of fetch functions that happened to succeed.
        # ``_fetch_ri_utilization`` alone issues 5 (one per service loop
        # iteration), so this is materially higher than the old
        # per-function count for a healthy run, and correctly excludes the
        # free ec2/savingsplans inventory calls (never routed through
        # ``counted_ce_client``).
        recommendations_cached: Dict[str, int] = {}
        cache_tasks = []
        for key, result in fetch_results.items():
            if isinstance(result, BaseException):
                logger.warning(f"Error fetching {key} recommendations: {result}")
                recommendations_cached[key] = 0
            else:
                recommendations_cached[key] = len(result) if result else 0
                cache_tasks.append(self.set_cached_recommendations(account_id, key, result or []))
        api_calls = counted_ce_client.call_count

        await asyncio.gather(*cache_tasks, return_exceptions=True)

        # Update last refresh timestamp after successful refresh
        await self._update_last_refresh_timestamp(account_id)

        logger.info(
            f"Refreshed {sum(recommendations_cached.values())} recommendation items "
            f"for account {account_id} ({api_calls} CE API calls, "
            f"${api_calls * 0.01:.2f} cost)"
        )
        return {
            'success': True,
            'account_id': account_id,
            'api_calls': api_calls,
            'api_cost_usd': api_calls * 0.01,
            'recommendations': recommendations_cached,
            'refreshed_at': datetime.now(timezone.utc).isoformat(),
        }
    
    # --- Commitment risk fetch methods (Phases 1-3) ---

    async def _fetch_ri_utilization(self, client) -> List[Dict]:
        """Fetch RI utilization data from Cost Explorer (Phase 1)."""
        try:
            end_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            start_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%d')

            services = [
                'Amazon Elastic Compute Cloud - Compute',
                'Amazon Relational Database Service',
                'Amazon ElastiCache',
                'Amazon Redshift',
                'Amazon OpenSearch Service',
            ]
            results = []
            for service in services:
                try:
                    response = client.get_reservation_utilization(
                        TimePeriod={'Start': start_date, 'End': end_date},
                        GroupBy=[{'Type': 'DIMENSION', 'Key': 'INSTANCE_TYPE'}],
                        Filter={'Dimensions': {'Key': 'SERVICE', 'Values': [service]}},
                    )
                    for group in response.get('UtilizationsByTime', []):
                        for item in group.get('Groups', []):
                            utilization = float(item.get('Utilization', {}).get('UtilizationPercentage', '100'))
                            total_cost = float(item.get('Utilization', {}).get('TotalAmortizedFee', '0'))
                            results.append({
                                'service': service,
                                'instance_type': item.get('Key', 'unknown'),
                                'utilization_percentage': utilization,
                                'total_amortized_fee': total_cost,
                                'unused_fee': total_cost * (1 - utilization / 100),
                            })
                except ClientError as e:
                    if 'DataUnavailable' in str(e):
                        continue
                    raise
            return results
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise

    async def _fetch_ri_inventory(self, ec2_client) -> List[Dict]:
        """Fetch EC2 Reserved Instances inventory (Phase 2 — free API)."""
        try:
            response = ec2_client.describe_reserved_instances(
                Filters=[{'Name': 'state', 'Values': ['active', 'payment-pending']}],
            )
            results = []
            for ri in response.get('ReservedInstances', []):
                end_time = ri.get('End')
                if end_time and hasattr(end_time, 'isoformat'):
                    end_str = end_time.isoformat()
                else:
                    end_str = str(end_time) if end_time else None

                start_time = ri.get('Start')
                if start_time and hasattr(start_time, 'isoformat'):
                    start_str = start_time.isoformat()
                else:
                    start_str = str(start_time) if start_time else None

                duration = ri.get('Duration', 0)
                term_months = duration // (30 * 24 * 3600) if duration else 12
                fixed_price = float(ri.get('FixedPrice', 0))
                usage_price = float(ri.get('UsagePrice', 0))
                # CLO-505: current offerings bill the hourly fee through
                # RecurringCharges (Frequency 'Hourly'); UsagePrice is 0 for
                # them, so a No Upfront RI used to read as ~$0/month. All
                # three are per-instance prices; the detectors scale by
                # InstanceCount.
                recurring_hourly = sum(
                    float(rc.get('Amount', 0) or 0)
                    for rc in (ri.get('RecurringCharges') or [])
                    if rc.get('Frequency') == 'Hourly'
                )
                monthly_effective_cost = (
                    (fixed_price / max(term_months, 1))
                    + ((usage_price + recurring_hourly) * 730)
                )

                results.append({
                    'reserved_instances_id': ri.get('ReservedInstancesId', ''),
                    'instance_type': ri.get('InstanceType', 'unknown'),
                    'instance_count': ri.get('InstanceCount', 0),
                    'state': ri.get('State', ''),
                    'offering_class': ri.get('OfferingClass', 'standard'),
                    'offering_type': ri.get('OfferingType', ''),
                    'start_date': start_str,
                    'end_date': end_str,
                    'tenancy': ri.get('InstanceTenancy', 'default'),
                    'product_description': ri.get('ProductDescription', ''),
                    'monthly_effective_cost': monthly_effective_cost,
                    'fixed_price': fixed_price,
                    'usage_price': usage_price,
                    'duration': duration,
                })
            return results
        except ClientError as e:
            if 'UnauthorizedOperation' in str(e):
                logger.info("No access to DescribeReservedInstances")
                return []
            raise

    async def _fetch_sp_utilization(self, client) -> List[Dict]:
        """Fetch Savings Plans utilization data from Cost Explorer (Phase 1)."""
        try:
            end_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            start_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%d')

            response = client.get_savings_plans_utilization(
                TimePeriod={'Start': start_date, 'End': end_date},
                Granularity='MONTHLY',
            )
            results = []
            total = response.get('Total', {})
            utilization = total.get('Utilization', {})
            amortized = total.get('AmortizedCommitment', {})

            results.append({
                'utilization_percentage': float(utilization.get('UtilizationPercentage', '100')),
                'total_commitment': float(amortized.get('TotalAmortizedCommitment', '0')),
                'used_commitment': float(utilization.get('UsedCommitment', '0')),
                'unused_commitment': float(utilization.get('UnusedCommitment', '0')),
                'net_savings': float(utilization.get('NetSavings', '0')),
            })
            return results
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise

    async def _fetch_sp_inventory(self, sp_client) -> List[Dict]:
        """Fetch active Savings Plans inventory (Phase 2 — free API)."""
        try:
            # CLO-505: DescribeSavingsPlans is paginated (nextToken); only the
            # first page was read. Free API, bounded at SP_INVENTORY_MAX_PAGES.
            plans: List[Dict] = []
            kwargs: Dict[str, Any] = {'states': ['active']}
            for _ in range(SP_INVENTORY_MAX_PAGES):
                response = sp_client.describe_savings_plans(**kwargs)
                plans.extend(response.get('savingsPlans', []))
                token = response.get('nextToken')
                if not token:
                    break
                kwargs['nextToken'] = token
            else:
                logger.warning(
                    "DescribeSavingsPlans still had more pages after %d; the "
                    "rest of the inventory is MISSING from this refresh",
                    SP_INVENTORY_MAX_PAGES,
                )
            results = []
            for sp in plans:
                commitment = float(sp.get('commitment', '0'))
                results.append({
                    'savings_plan_id': sp.get('savingsPlanId', ''),
                    'savings_plan_arn': sp.get('savingsPlanArn', ''),
                    'savings_plan_type': sp.get('savingsPlanType', ''),
                    'payment_option': sp.get('paymentOption', ''),
                    'state': sp.get('state', ''),
                    'start_time': sp.get('start', ''),
                    'end_time': sp.get('end', ''),
                    'commitment_hourly': commitment,
                    'monthly_commitment': commitment * 730,
                    'term_duration_seconds': sp.get('termDurationInSeconds', 0),
                    'region': sp.get('region', ''),
                })
            return results
        except ClientError as e:
            if 'AccessDeniedException' in str(e) or 'UnauthorizedAccess' in str(e):
                logger.info("No access to DescribeSavingsPlans")
                return []
            raise

    async def _fetch_sp_coverage(self, client) -> List[Dict]:
        """Fetch Savings Plans coverage data from Cost Explorer (Phase 3)."""
        try:
            end_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            start_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%d')

            response = client.get_savings_plans_coverage(
                TimePeriod={'Start': start_date, 'End': end_date},
                Granularity='MONTHLY',
            )
            results = []
            for period in response.get('SavingsPlansCoverages', []):
                coverage = period.get('Coverage', {})
                sp_covered = float(coverage.get('SpendCoveredBySavingsPlans', '0'))
                on_demand = float(coverage.get('OnDemandCost', '0'))
                total_cost = float(coverage.get('TotalCost', '0'))
                coverage_pct = float(coverage.get('CoveragePercentage', '0'))

                results.append({
                    'coverage_percentage': coverage_pct,
                    'spend_covered': sp_covered,
                    'on_demand_cost': on_demand,
                    'total_cost': total_cost,
                })
            return results
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise

    # --- Purchase recommendation fetch methods ---

    async def _fetch_ec2_ri_recommendations(self, client) -> List[Dict]:
        """Fetch EC2 RI recommendations from Cost Explorer."""
        try:
            response = client.get_reservation_purchase_recommendation(
                Service='Amazon Elastic Compute Cloud - Compute',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
            )
            return self._parse_ri_recommendations(response, 'EC2InstanceDetails')
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise
    
    async def _fetch_rds_ri_recommendations(self, client) -> List[Dict]:
        """Fetch RDS RI recommendations from Cost Explorer."""
        try:
            response = client.get_reservation_purchase_recommendation(
                Service='Amazon Relational Database Service',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
            )
            return self._parse_ri_recommendations(response, 'RDSInstanceDetails')
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise
    
    async def _fetch_opensearch_ri_recommendations(self, client) -> List[Dict]:
        """Fetch OpenSearch RI recommendations from Cost Explorer."""
        try:
            response = client.get_reservation_purchase_recommendation(
                Service='Amazon OpenSearch Service',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
            )
            return self._parse_ri_recommendations(response, 'ESInstanceDetails')
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise
    
    async def _fetch_elasticache_ri_recommendations(self, client) -> List[Dict]:
        """Fetch ElastiCache RI recommendations from Cost Explorer."""
        try:
            response = client.get_reservation_purchase_recommendation(
                Service='Amazon ElastiCache',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
            )
            return self._parse_ri_recommendations(response, 'ElastiCacheInstanceDetails')
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise
    
    async def _fetch_redshift_ri_recommendations(self, client) -> List[Dict]:
        """Fetch Redshift RI recommendations from Cost Explorer."""
        try:
            response = client.get_reservation_purchase_recommendation(
                Service='Amazon Redshift',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
            )
            return self._parse_ri_recommendations(response, 'RedshiftInstanceDetails')
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise
    
    async def _fetch_sagemaker_sp_recommendations(self, client) -> List[Dict]:
        """Fetch SageMaker Savings Plans recommendations."""
        try:
            response = client.get_savings_plans_purchase_recommendation(
                SavingsPlansType='SAGEMAKER_SP',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
            )
            return self._parse_sp_recommendations(response, 'SAGEMAKER_SP')
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise
    
    async def _fetch_compute_sp_recommendations(self, client) -> List[Dict]:
        """Fetch Compute Savings Plans recommendations."""
        try:
            response = client.get_savings_plans_purchase_recommendation(
                SavingsPlansType='COMPUTE_SP',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
            )
            return self._parse_sp_recommendations(response, 'COMPUTE_SP')
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise
    
    async def _fetch_ec2_sp_recommendations(self, client) -> List[Dict]:
        """Fetch EC2 Instance Savings Plans recommendations."""
        try:
            response = client.get_savings_plans_purchase_recommendation(
                SavingsPlansType='EC2_INSTANCE_SP',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
            )
            return self._parse_sp_recommendations(response, 'EC2_INSTANCE_SP')
        except ClientError as e:
            if 'DataUnavailable' in str(e):
                return []
            raise
    
    def _parse_ri_recommendations(self, response: Dict, details_key: str) -> List[Dict]:
        """Parse RI recommendations into cacheable format."""
        results = []
        recommendations = response.get('Recommendations', [])
        
        for rec in recommendations:
            details = rec.get('RecommendationDetails', [])
            for detail in details:
                instance_details = detail.get('InstanceDetails', {})
                service_details = instance_details.get(details_key, {})
                
                if not service_details:
                    continue
                
                results.append({
                    'instance_type': service_details.get('InstanceType', 'unknown'),
                    'region': service_details.get('Region', 'unknown'),
                    'platform': service_details.get('Platform', 'Linux/UNIX'),
                    'tenancy': service_details.get('Tenancy', 'Shared'),
                    'database_engine': service_details.get('DatabaseEngine'),
                    'deployment_option': service_details.get('DeploymentOption'),
                    'recommended_count': detail.get('RecommendedNumberOfInstancesToPurchase', '0'),
                    'monthly_savings': float(detail.get('EstimatedMonthlySavingsAmount', 0)),
                    'savings_percentage': float(detail.get('EstimatedMonthlySavingsPercentage', 0)),
                    'break_even_months': detail.get('EstimatedBreakEvenInMonths', 'N/A'),
                })
        
        return results
    
    def _parse_sp_recommendations(self, response: Dict, sp_type: str) -> List[Dict]:
        """Parse Savings Plans recommendations into cacheable format."""
        results = []
        details = response.get('SavingsPlansPurchaseRecommendationDetails', [])
        
        for detail in details:
            hourly_commitment = float(detail.get('HourlyCommitmentToPurchase', 0))
            current_on_demand = float(detail.get('CurrentAverageHourlyOnDemandSpend', 0))
            monthly_commitment = hourly_commitment * 730
            monthly_on_demand = current_on_demand * 730
            monthly_savings = float(detail.get('EstimatedMonthlySavingsAmount', 0))
            
            if monthly_on_demand > 0:
                savings_percentage = (monthly_savings / monthly_on_demand) * 100
            else:
                savings_percentage = 0
            
            results.append({
                'sp_type': sp_type,
                'hourly_commitment': hourly_commitment,
                'monthly_commitment': monthly_commitment,
                'current_monthly_spend': monthly_on_demand,
                'monthly_savings': monthly_savings,
                'savings_percentage': savings_percentage,
                'estimated_roi': detail.get('EstimatedROI', 0),
            })
        
        return results
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        return {
            'local_cache_entries': len(self._local_cache),
            'local_cache_keys': list(self._local_cache.keys()),
        }
    
    async def clear_account_cache(self, account_id: str) -> bool:
        """Clear all cached recommendations for an account.

        Deletes every ``REC#<type>`` record AND the ``META#last_refresh`` marker using
        the table's real ``pk``/``sk`` schema. Previously this deleted with
        ``Key={'cache_key': ...}`` (a nonexistent attribute) and used a mismatched local
        cache key, so both the DynamoDB delete and the local eviction silently no-oped —
        a cleared account kept surfacing stale RI/SP recommendations (e.g. after a
        purchase) for up to the 7-day TTL. Clearing ``META#last_refresh`` also forces the
        next scan to actually re-fetch rather than treat the account as freshly cached.
        (CLO-170)
        """
        recommendation_types = [
            'ec2_ri', 'rds_ri', 'opensearch_ri', 'elasticache_ri', 'redshift_ri',
            'compute_sp', 'ec2_sp', 'sagemaker_sp',
            'ri_utilization', 'ri_inventory', 'sp_utilization', 'sp_inventory', 'sp_coverage',
        ]
        pk = f"ACCOUNT#{account_id}"
        # REC#<type> records + the last-refresh marker (so the next scan re-fetches).
        sks = [f"REC#{rec_type}" for rec_type in recommendation_types] + ["META#last_refresh"]

        try:
            table = self.dynamodb.Table(self.table_name)
        except Exception as e:
            logger.warning(f"Error obtaining cache table for account {account_id}: {e}")
            table = None

        for sk in sks:
            # Clear local cache (keyed f"{pk}#{sk}", matching the write path).
            self._local_cache.pop(f"{pk}#{sk}", None)

            # Clear DynamoDB using the correct composite key schema.
            if table is not None:
                try:
                    table.delete_item(Key={'pk': pk, 'sk': sk})
                except Exception as e:
                    logger.warning(f"Error clearing cache for {pk} / {sk}: {e}")

        logger.info(f"Cleared all recommendation cache for account {account_id}")
        return True


class _InMemoryOnlyTable:
    """A DynamoDB Table stand-in that stores nothing: every read misses, every
    write is dropped. The service's in-memory ``_local_cache`` still works, so
    a single local scan reuses what it fetched."""

    def get_item(self, **kwargs: Any) -> Dict[str, Any]:
        return {}

    def put_item(self, **kwargs: Any) -> Dict[str, Any]:
        return {}

    def delete_item(self, **kwargs: Any) -> Dict[str, Any]:
        return {}


class _InMemoryOnlyResource:
    def Table(self, name: str) -> _InMemoryOnlyTable:  # noqa: N802 - boto3 resource API
        return _InMemoryOnlyTable()


# Global instance
_savings_cache_instance: Optional[SavingsRecommendationsCacheService] = None


def use_in_memory_savings_cache() -> SavingsRecommendationsCacheService:
    """Install a cache that never touches DynamoDB (local CLI/MCP runtime)."""
    global _savings_cache_instance
    _savings_cache_instance = SavingsRecommendationsCacheService(persist=False)
    return _savings_cache_instance


def get_savings_cache_service() -> SavingsRecommendationsCacheService:
    """Get or create the global savings cache service instance."""
    global _savings_cache_instance
    if _savings_cache_instance is None:
        _savings_cache_instance = SavingsRecommendationsCacheService()
    return _savings_cache_instance
