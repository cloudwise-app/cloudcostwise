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
- A refresh sends 8 billed requests on the free engine, and up to 10 on an engine with the
  commitment detector (``include_commitment_usage``)
- Subsequent scans within 7 days: Use cached data ($0/scan)
"""

import asyncio
import json
import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
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

# CLO-774: a refresh whose rows didn't persist writes this instead of the
# last-refresh marker. Every refresh bills the customer, so the retry is bounded:
# a day after the first failure, then the normal weekly cycle, because a failure
# that repeats (a row over DynamoDB's 400 KB) won't clear on its own.
REFRESH_RETRY_SK = "META#refresh_retry"
REFRESH_RETRY_FIRST_DAYS = 1
REFRESH_RETRY_MEMORY_DAYS = 30  # How long the attempt count is remembered

# Row fields that are whole numbers. Every other number in a row is a float.
_INT_ROW_FIELDS = frozenset({'instance_count', 'duration', 'term_duration_seconds'})


def _rows_to_dynamodb(value: Any) -> Any:
    """A copy of cached rows that boto3 can serialize: it refuses floats."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, list):
        return [_rows_to_dynamodb(v) for v in value]
    if isinstance(value, dict):
        return {k: _rows_to_dynamodb(v) for k, v in value.items()}
    return value


def _rows_from_dynamodb(value: Any, field: Optional[str] = None) -> Any:
    """Rows read back with the types they were written with.

    By field, not by value: DynamoDB trims 2.0 to Decimal('2'), and the warm and
    cold paths have to produce the same text, ids and totals.
    """
    if isinstance(value, Decimal):
        return int(value) if field in _INT_ROW_FIELDS else float(value)
    if isinstance(value, list):
        return [_rows_from_dynamodb(v) for v in value]
    if isinstance(value, dict):
        return {k: _rows_from_dynamodb(v, k) for k, v in value.items()}
    return value


DEFAULT_BOTO_CONFIG = Config(
    read_timeout=60,
    connect_timeout=10,
    retries={'max_attempts': 3, 'mode': 'adaptive'}
)

# CLO-771: the refresh waits for every region. A region hanging on the defaults
# could use up the savings check's 45s, and a refresh cut off there has already
# billed its Cost Explorer calls but lands no marker, so the next scan bills again.
RI_INVENTORY_BOTO_CONFIG = Config(
    read_timeout=6,
    connect_timeout=3,
    retries={'total_max_attempts': 2, 'mode': 'standard'},
)
_AWS_REGION = re.compile(r'[a-z]{2}(-[a-z]+)+-\d+')
_DENIED_CODES = frozenset({'UnauthorizedOperation', 'AccessDenied', 'AccessDeniedException'})
# In a refresh's failed_fetches and on its marker: RIs were readable, the region
# list wasn't, so us-east-1 alone only looks complete.
RI_REGIONS_NOT_LISTED = 'ri_inventory:regions-not-listed'


class _CountingClient:
    """Thin proxy around a boto3 client that counts every method call
    made through it (CLO-358).

    ``refresh_account_recommendations`` previously reported ``api_calls``
    as one per *fetch function*, regardless of how many real Cost Explorer
    requests that function issued. Wrapping only the ``ce`` client (never the
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


def _other_currency(*codes: Optional[str]) -> Optional[str]:
    """The first code given, if it isn't USD. Detectors print these amounts with ``$``.

    No code at all keeps the row, unlike ``ri_sp_service``, which withholds it. No
    real non-empty response has been recorded to show AWS always sends one.
    """
    code = next((c for c in codes if c), None)
    return code if code and code != 'USD' else None


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

    Every request here is unfiltered (no LINKED_ACCOUNT) and the cache is keyed
    by the credentials' own account (commitment_cache_account_id). That is
    correct only because a hosted scan runs on a role in the scanned account:
    CLO-773 refuses a row whose role is in another account (an Organizations
    member on its payer's role) before the scan assumes it. Don't add
    member-scoped requests here; a member connects on its own role.
    
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
    
    @staticmethod
    def _usage_missing(marker: Dict[str, Any], include_commitment_usage: bool) -> bool:
        """True when the caller reads Savings Plans usage but the last refresh didn't fetch it.

        CLO-880: a hosted Free refresh skips those two requests, so an account that upgrades
        inside the TTL would otherwise read empty rows for up to 7 days. A marker without the
        attribute was written before the flag existed, when every hosted refresh fetched all 10.
        """
        return include_commitment_usage and marker.get('include_commitment_usage', True) is False

    async def needs_refresh(self, account_id: str, include_commitment_usage: bool = False) -> bool:
        """
        Check if recommendations for this account need to be refreshed.
        
        Returns True if:
        - No cached data exists for this account
        - Cached data is older than CACHE_TTL_DAYS (7 days)
        
        - ``include_commitment_usage`` is True and the last refresh didn't fetch the
          Savings Plans usage rows (CLO-880)

        This is the main check to decide whether to call Cost Explorer APIs.
        """
        pk = f"ACCOUNT#{account_id}"
        sk = "META#last_refresh"
        local_cache_key = f"{pk}#{sk}"
        
        # Check in-memory cache first
        if local_cache_key in self._local_cache:
            last_refresh = self._local_cache[local_cache_key].get('timestamp', 0)
            age_days = (datetime.now(timezone.utc).timestamp() - last_refresh) / 86400
            if age_days < CACHE_TTL_DAYS and not self._usage_missing(
                self._local_cache[local_cache_key], include_commitment_usage
            ):
                logger.debug(f"Account {account_id} refreshed {age_days:.1f} days ago, no refresh needed")
                return False

        # This container already saw a failed write, whatever DynamoDB says now.
        local_retry = self._local_cache.get(f"{pk}#{REFRESH_RETRY_SK}")
        if local_retry and local_retry['retry_after'] > datetime.now(timezone.utc).timestamp():
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
                self._local_cache[local_cache_key] = {
                    'timestamp': last_refresh, 'failed_ri_regions': item.get('failed_ri_regions') or [],
                    'include_commitment_usage': item.get('include_commitment_usage', True),
                }
                
                if age_days < CACHE_TTL_DAYS:
                    if self._usage_missing(item, include_commitment_usage):
                        logger.info(f"Account {account_id} refresh skipped Savings Plans usage, refresh needed")
                        return self._retry_is_due(table, account_id)
                    logger.debug(f"Account {account_id} refreshed {age_days:.1f} days ago, no refresh needed")
                    return False
                else:
                    logger.info(f"Account {account_id} cache is {age_days:.1f} days old, refresh needed")
                    return self._retry_is_due(table, account_id)
            else:
                logger.info(f"No cached recommendations for account {account_id}, refresh needed")
                return self._retry_is_due(table, account_id)
                
        except ClientError as e:
            logger.warning(f"DynamoDB error checking refresh status: {e}")
            # If we can't check, assume refresh is needed to be safe
            return True
        except Exception as e:
            logger.warning(f"Error checking refresh status: {e}")
            return True
    
    def _retry_is_due(self, table: Any, account_id: str) -> bool:
        """False while an earlier failed write is still waiting out its retry."""
        pk = f"ACCOUNT#{account_id}"
        item = table.get_item(Key={'pk': pk, 'sk': REFRESH_RETRY_SK}).get('Item')
        if not item or float(item.get('retry_after', 0)) <= datetime.now(timezone.utc).timestamp():
            return True
        logger.info(f"Account {account_id}: last refresh failed to persist, not retrying yet")
        return False

    def _record_failed_write(self, account_id: str) -> None:
        """Hold the next refresh back, and leave the last-refresh marker alone."""
        pk = f"ACCOUNT#{account_id}"
        now = datetime.now(timezone.utc).timestamp()
        local_key = f"{pk}#{REFRESH_RETRY_SK}"
        attempts = self._local_cache.get(local_key, {}).get('attempts', 0)
        try:
            table = self.dynamodb.Table(self.table_name)
            item = table.get_item(Key={'pk': pk, 'sk': REFRESH_RETRY_SK}).get('Item') or {}
            attempts = max(attempts, int(item.get('attempts', 0)))
        except Exception as e:
            table = None
            logger.error(f"Could not read refresh retry state for account {account_id}: {e}")
        attempts += 1
        wait_days = REFRESH_RETRY_FIRST_DAYS if attempts == 1 else CACHE_TTL_DAYS
        retry_after = int(now + wait_days * 86400)
        # Kept in memory too, so a table that refuses this write as well still
        # can't bill every scan in this container.
        self._local_cache[local_key] = {'retry_after': retry_after, 'attempts': attempts}
        if table is None:
            return
        try:
            table.put_item(Item={
                'pk': pk,
                'sk': REFRESH_RETRY_SK,
                'gsi1pk': pk,
                'gsi1sk': REFRESH_RETRY_SK,
                'retry_after': retry_after,
                'attempts': attempts,
                'ttl': int(now + REFRESH_RETRY_MEMORY_DAYS * 86400),
            })
        except Exception as e:
            logger.error(f"Could not record refresh retry for account {account_id}: {e}")

    def _clear_failed_write(self, account_id: str) -> None:
        """A refresh persisted, so forget any earlier failure."""
        pk = f"ACCOUNT#{account_id}"
        self._local_cache.pop(f"{pk}#{REFRESH_RETRY_SK}", None)
        try:
            self.dynamodb.Table(self.table_name).delete_item(Key={'pk': pk, 'sk': REFRESH_RETRY_SK})
        except Exception as e:
            logger.warning(f"Could not clear refresh retry for account {account_id}: {e}")

    def refresh_gaps(self, account_id: str) -> List[str]:
        """What the last refresh couldn't read in RI inventory. Read needs_refresh first."""
        marker = self._local_cache.get(f"ACCOUNT#{account_id}#META#last_refresh") or {}
        return list(marker.get('failed_ri_regions') or [])

    async def _update_last_refresh_timestamp(
        self, account_id: str, failed_ri_regions: Optional[List[str]] = None,
        include_commitment_usage: bool = True,
    ) -> None:
        """Update the last refresh timestamp for an account."""
        pk = f"ACCOUNT#{account_id}"
        sk = "META#last_refresh"
        local_cache_key = f"{pk}#{sk}"
        timestamp = datetime.now(timezone.utc).timestamp()
        ttl = int((datetime.now(timezone.utc) + timedelta(days=CACHE_TTL_DAYS + 1)).timestamp())
        
        # Update local cache
        self._local_cache[local_cache_key] = {
            'timestamp': timestamp, 'failed_ri_regions': failed_ri_regions or [],
            'include_commitment_usage': include_commitment_usage,
        }

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
                    # CLO-880: whether the Savings Plans usage rows were fetched.
                    'include_commitment_usage': include_commitment_usage,
                    # CLO-777: so each scan until the next refresh can say so.
                    **({'failed_ri_regions': failed_ri_regions} if failed_ri_regions else {}),
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
                    recommendations = _rows_from_dynamodb(item.get('recommendations'))
                    # Update local cache
                    self._local_cache[local_cache_key] = {
                        'recommendations': recommendations,
                        'expires_at': expires_at
                    }
                    return recommendations
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
                    **cache_data,
                    'recommendations': _rows_to_dynamodb(recommendations),
                }
            )
            logger.info(f"Cached {len(recommendations)} {recommendation_type} recommendations for account {account_id}")
            return True
            
        except ClientError as e:
            # The rows are only in this container's memory: not persisted.
            logger.error(f"DynamoDB cache write error for {recommendation_type}, account {account_id}: {e}")
            return False
        except Exception as e:
            logger.error(f"Cache write error for {recommendation_type}, account {account_id}: {e}")
            return False
    
    async def refresh_account_recommendations(
        self,
        creds: Dict[str, str],
        include_commitment_usage: bool = True,
    ) -> Dict[str, Any]:
        """
        Refresh all recommendations for a single account.

        All CE/EC2/SP fetches run in parallel (asyncio.to_thread) so the total
        wall-clock time is bounded by the slowest individual call (~2-3 s)
        rather than the sum of all calls (~20-30 s sequential).

        Args:
            creds: AWS credentials dict with access_key_id, secret_access_key, account_id
            include_commitment_usage: send the billed Savings Plans utilization and
                coverage requests. Only the commitment detector reads them, so a scan
                that doesn't run it passes False: an engine without it (the free CLI
                scan) or a hosted scan whose tier doesn't route it (Free, CLO-880).
                The last-refresh marker records the choice so ``needs_refresh`` can
                ask again once the commitment detector is routed.

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
            # ``_CountingClient``). The EC2 and savingsplans clients are never
            # wrapped — RI/SP *inventory* are free APIs and must not inflate the count.
            counted_ce_client = _CountingClient(ce_client)

            # --- Run all fetches in parallel using asyncio.to_thread ---
            # Each _fetch_* is an async def that wraps synchronous boto3 calls.
            # asyncio.to_thread pushes each into the thread pool so they execute
            # concurrently rather than blocking the event loop sequentially.
            fetches = {
                'ec2_ri': lambda: asyncio.run(self._fetch_ec2_ri_recommendations(counted_ce_client)),
                'rds_ri': lambda: asyncio.run(self._fetch_rds_ri_recommendations(counted_ce_client)),
                'opensearch_ri': lambda: asyncio.run(self._fetch_opensearch_ri_recommendations(counted_ce_client)),
                'compute_sp': lambda: asyncio.run(self._fetch_compute_sp_recommendations(counted_ce_client)),
                'ec2_sp': lambda: asyncio.run(self._fetch_ec2_sp_recommendations(counted_ce_client)),
                'elasticache_ri': lambda: asyncio.run(self._fetch_elasticache_ri_recommendations(counted_ce_client)),
                'redshift_ri': lambda: asyncio.run(self._fetch_redshift_ri_recommendations(counted_ce_client)),
                'sagemaker_sp': lambda: asyncio.run(self._fetch_sagemaker_sp_recommendations(counted_ce_client)),
                'ri_inventory': lambda: self._fetch_ri_inventory_in_regions(creds),
                'sp_inventory': lambda: asyncio.run(self._fetch_sp_inventory(sp_client)),
            }
            # scripts/build_site_facts.py leaves this branch out of the public
            # default-scan count, by this exact name.
            if include_commitment_usage:
                fetches['sp_utilization'] = lambda: asyncio.run(self._fetch_sp_utilization(counted_ce_client))
                fetches['sp_coverage'] = lambda: asyncio.run(self._fetch_sp_coverage(counted_ce_client))

            results = await asyncio.gather(
                *(asyncio.to_thread(fetch) for fetch in fetches.values()),
                return_exceptions=True,
            )
            fetch_results = dict(zip(fetches, results))

        except Exception as e:
            logger.error(f"Error refreshing recommendations for account {account_id}: {e}")
            return {
                'success': False,
                'account_id': account_id,
                'error': str(e),
                'api_calls': 0,
                'api_cost_usd': 0.0,
            }

        # CLO-771: regions that answered are kept when another region didn't.
        failed_ri_regions: List[str] = []
        if not isinstance(fetch_results['ri_inventory'], BaseException):
            fetch_results['ri_inventory'], failed_ri_regions = fetch_results['ri_inventory']

        # Cache results (best-effort — log but don't fail on individual errors)
        # CLO-358: api_calls is the number of real ce:* requests
        # ``counted_ce_client`` actually made (see ``_CountingClient``) —
        # not the number of fetch functions that happened to succeed. It
        # excludes the free ec2/savingsplans inventory calls (never routed
        # through ``counted_ce_client``).
        recommendations_cached: Dict[str, int] = {}
        cache_tasks = []
        failed_fetches = [f"ri_inventory:{region}" for region in failed_ri_regions]
        for key, result in fetch_results.items():
            if isinstance(result, BaseException):
                logger.warning(f"Error fetching {key} recommendations: {result}")
                recommendations_cached[key] = 0
                failed_fetches.append(key)
            else:
                recommendations_cached[key] = len(result) if result else 0
                cache_tasks.append(self._cache_rows(account_id, key, result or []))
        api_calls = counted_ce_client.call_count

        write_results = await asyncio.gather(*cache_tasks, return_exceptions=True)
        # set_cached_recommendations catches its own errors, so a raised one here
        # is unexpected. It still means rows didn't persist.
        write_errors = [r for r in write_results if isinstance(r, BaseException)]
        failed_writes = sorted(r for r in write_results if isinstance(r, str))

        # CLO-774: no marker unless the rows persisted, or other containers would
        # read nothing for 7 days believing the cache was fresh.
        if failed_writes or write_errors:
            for key in failed_writes:
                recommendations_cached[key] = 0
            self._record_failed_write(account_id)
            error = f"Rows did not persist: {failed_writes} {write_errors or ''}".strip()
            logger.error(f"Refresh for account {account_id} not marked complete. {error}")
            return {
                'success': False,
                'account_id': account_id,
                'error': error,
                'failed_writes': failed_writes,
                'failed_fetches': failed_fetches,
                'api_calls': api_calls,
                'api_cost_usd': api_calls * 0.01,
                'recommendations': recommendations_cached,
            }

        # Update last refresh timestamp after successful refresh
        await self._update_last_refresh_timestamp(
            account_id, [f for f in failed_fetches if f.startswith('ri_inventory')],
            include_commitment_usage=include_commitment_usage,
        )
        self._clear_failed_write(account_id)

        logger.info(
            f"Refreshed {sum(recommendations_cached.values())} recommendation items "
            f"for account {account_id} ({api_calls} CE API calls, "
            f"${api_calls * 0.01:.2f} cost)"
        )
        return {
            'success': True,
            'account_id': account_id,
            'failed_fetches': failed_fetches,
            'api_calls': api_calls,
            'api_cost_usd': api_calls * 0.01,
            'recommendations': recommendations_cached,
            'refreshed_at': datetime.now(timezone.utc).isoformat(),
        }
    
    async def _cache_rows(self, account_id: str, key: str, rows: List[Dict[str, Any]]) -> Optional[str]:
        """Write one row type. Returns its key if it didn't persist."""
        return None if await self.set_cached_recommendations(account_id, key, rows) else key

    # --- Commitment risk fetch methods (Phases 1-3) ---

    # GetReservationUtilization is deliberately not sent, so nothing writes the
    # 'ri_utilization' cache key and _detect_unused_ris gets no data on any online
    # scan. The API groups only by SUBSCRIPTION_ID, and that detector can't read
    # per-subscription rows: their shape and amounts are unverified without an
    # account that holds RIs. Sending it before a recording from one exists would
    # bill 5 requests with no usable result. Uploaded CUR files have their own
    # check, _detect_cur_unused_reservations.

    @staticmethod
    def _ri_regions(creds: Dict[str, Any], home: Any) -> tuple:
        """Which regions to read: (regions, whether the list failed, whether it was denied).

        A local scan names its regions. A hosted scan's plan never reaches the
        us-east-1 scan that refreshes, so this asks for the regions enabled on the
        account, which covers every region a scan could use and leaves out opt-in
        regions the account has not enabled. It still includes an opted-in region
        whose endpoint is unreachable: the scanner's STS probe (CLO-795) does not
        run here. A role that may not list them (any stack below template 1.34.0)
        reads us-east-1, with no further denied calls.
        """
        named = creds.get('scan_regions')
        failed = denied = False
        if not named:
            try:
                named = [r.get('RegionName') for r in home.describe_regions().get('Regions', [])]
            except ClientError as e:
                denied = e.response.get('Error', {}).get('Code') in _DENIED_CODES
                failed = not denied
                named = []
            except Exception as e:  # noqa: BLE001 - us-east-1 can still be read
                logger.warning(f"Could not list enabled regions: {e}")
                failed = True
                named = []
        regions = dict.fromkeys(
            ['us-east-1'] + [r for r in named if isinstance(r, str) and _AWS_REGION.fullmatch(r)]
        )
        return list(regions), failed, denied

    def _fetch_ri_inventory_in_regions(self, creds: Dict[str, Any]) -> tuple:
        """Read the RI inventory of each region: (rows, what failed).

        DescribeReservedInstances is a regional EC2 call and isn't billed, so this
        adds nothing to the Cost Explorer count. Raises only if no region answered,
        so that stays a failed fetch rather than an empty inventory.
        """
        def client_for(region: str) -> Any:
            return boto3.client(
                'ec2',
                aws_access_key_id=creds['access_key_id'],
                aws_secret_access_key=creds['secret_access_key'],
                region_name=region,
                aws_session_token=creds.get('session_token'),
                config=RI_INVENTORY_BOTO_CONFIG,
            )

        home = client_for('us-east-1')
        regions, list_failed, list_denied = self._ri_regions(creds, home)
        failed: List[str] = ['region-list'] if list_failed else []
        error: Optional[Exception] = None

        # Clients are built here, one at a time: at once, they use more memory
        # than a 512 MB scanner has. Only the requests run in parallel.
        clients: Dict[str, Any] = {'us-east-1': home}
        for region in regions[1:]:
            try:
                clients[region] = client_for(region)
            except Exception as e:  # noqa: BLE001 - one region must not cost the others
                logger.warning(f"Error fetching Reserved Instances in {region}: {e}")
                failed.append(region)
                error = e

        denied_regions: List[str] = []

        def read_one(region: str) -> Any:
            try:
                return asyncio.run(self._fetch_ri_inventory(clients[region], region, denied_regions))
            except Exception as e:  # noqa: BLE001 - one region must not cost the others
                return e

        # One thread each, or a queue would stack the timeouts past the 45s above.
        with ThreadPoolExecutor(max_workers=len(clients)) as pool:
            outcomes = list(pool.map(read_one, clients))

        rows: Dict[str, Dict] = {}
        answered = 0
        for region, outcome in zip(clients, outcomes):
            if isinstance(outcome, Exception):
                logger.warning(f"Error fetching Reserved Instances in {region}: {outcome}")
                failed.append(region)
                error = outcome
                continue
            answered += 1
            for row in outcome:
                # An id seen twice is one reservation, whatever returned it.
                rows.setdefault(row['reserved_instances_id'] or f"{region}#{len(rows)}", row)
        if error is not None and not answered:
            raise error
        # Both denied is a stack below template 1.34.0, which the required update
        # banner covers. Only one denied means a partial read that looks complete.
        if list_denied and answered and 'us-east-1' not in denied_regions:
            failed.append(RI_REGIONS_NOT_LISTED.split(':', 1)[1])
        return list(rows.values()), failed

    async def _fetch_ri_inventory(
        self, ec2_client, region: str = 'us-east-1', denied_regions: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Fetch one region's EC2 Reserved Instances inventory (Phase 2 — free API)."""
        try:
            response = ec2_client.describe_reserved_instances(
                Filters=[{'Name': 'state', 'Values': ['active', 'payment-pending']}],
            )
            results = []
            for ri in response.get('ReservedInstances', []):
                currency = _other_currency(ri.get('CurrencyCode'))
                if currency:
                    logger.warning(f"Reserved Instance left out of the cache: {currency}")
                    continue

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
                # them, so a No Upfront RI used to read as ~$0/month.
                # CLO-771: botocore doesn't say whether these prices are per
                # instance, so this is the cost of a one-instance reservation
                # and only an estimate of anything larger (see
                # commitment.py's _ri_monthly_cost).
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
                    'region': region,
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
                if denied_regions is not None:
                    denied_regions.append(region)
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
                # CLO-777: botocore allows CNY, and the expiry alert prints this with $.
                currency = _other_currency(sp.get('currency'))
                if currency:
                    logger.warning(f"Savings Plan left out of the cache: {currency}")
                    continue
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
                    'period_start': period.get('TimePeriod', {}).get('Start'),
                    'period_end': period.get('TimePeriod', {}).get('End'),
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
            summary_currency = rec.get('RecommendationSummary', {}).get('CurrencyCode')
            for detail in details:
                currency = _other_currency(detail.get('CurrencyCode'), summary_currency)
                if currency:
                    logger.warning(f"RI recommendation left out of the cache: {currency}")
                    continue

                instance_details = detail.get('InstanceDetails', {})
                service_details = instance_details.get(details_key, {})
                
                if not service_details:
                    continue
                
                results.append({
                    'instance_type': service_details.get('InstanceType', 'unknown'),
                    'region': service_details.get('Region', 'unknown'),
                    # Missing stays None: a finding must not assert a platform AWS didn't give.
                    'platform': service_details.get('Platform'),
                    'tenancy': service_details.get('Tenancy'),
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
        recommendation = response.get('SavingsPlansPurchaseRecommendation', {})
        details = recommendation.get('SavingsPlansPurchaseRecommendationDetails', [])
        summary_currency = recommendation.get('SavingsPlansPurchaseRecommendationSummary', {}).get('CurrencyCode')
        
        for detail in details:
            currency = _other_currency(detail.get('CurrencyCode'), summary_currency)
            if currency:
                logger.warning(f"{sp_type} recommendation left out of the cache: {currency}")
                continue

            hourly_commitment = float(detail.get('HourlyCommitmentToPurchase', 0))
            current_on_demand = float(detail.get('CurrentAverageHourlyOnDemandSpend', 0))
            monthly_commitment = hourly_commitment * 730
            monthly_on_demand = current_on_demand * 730
            monthly_savings = float(detail.get('EstimatedMonthlySavingsAmount', 0))
            
            if monthly_on_demand > 0:
                savings_percentage = (monthly_savings / monthly_on_demand) * 100
            else:
                savings_percentage = 0
            
            plan = detail.get('SavingsPlansDetails', {})
            results.append({
                'sp_type': sp_type,
                # Missing or empty is None: a finding must not assert a scope AWS didn't give,
                # and '' and None must be one identity.
                'instance_family': plan.get('InstanceFamily') or None,
                'region': plan.get('Region') or None,
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
        sks = [f"REC#{rec_type}" for rec_type in recommendation_types] + ["META#last_refresh", REFRESH_RETRY_SK]

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
