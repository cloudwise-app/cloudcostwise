"""
Reserved Instance and Savings Plans Waste Detectors

This module provides recommendations for purchasing Reserved Instances (RIs)
and Savings Plans (SPs) based on AWS Cost Explorer's official recommendations.

AWS Cost Explorer API Costs:
- $0.01 per API request for RI/SP recommendations
- CloudWise runs these weekly via scheduled task to minimize costs
- Waste detection uses cached data (no per-scan API costs)

Caching Strategy:
- Weekly scheduled task calls Cost Explorer APIs and caches results
- Waste detection reads from cache with 7-day TTL
- Force refresh available for on-demand updates
- Fallback to live API if cache miss (rare, only on first scan)

Philosophy Alignment:
- Confidence: HIGH (AWS official recommendations based on 30-day usage)
- Accuracy: 100% (AWS calculates exact savings from actual usage patterns)
- No arbitrary assumptions (usage-based, not guessing)

All detectors use the DataProvider abstraction pattern for true online/offline parity.
"""

import logging
import uuid
from typing import Dict, Any, List, Optional, Tuple, TYPE_CHECKING
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudwise_scan_core.models import (
    WasteItem,
    WasteDetectionSettings,
    WasteType,
    ResourceType,
    ConfidenceLevel,
    generate_deterministic_id,
)

if TYPE_CHECKING:
    from cloudwise_scan_core.data_providers.base import WasteDataProvider

logger = logging.getLogger(__name__)

# Minimum monthly savings to report
MIN_SAVINGS_THRESHOLD = 10.0  # $10/month minimum for RI/SP recommendations


class SavingsOpportunitiesDetectorsMixin:
    """
    Mixin class providing RI and Savings Plans recommendation detectors.
    
    These detectors use AWS Cost Explorer's official purchase recommendations,
    which analyze 30 days of usage history to suggest optimal commitments.
    
    Supported Recommendations:
    - EC2 Reserved Instances (Standard and Convertible)
    - RDS Reserved Instances
    - ElastiCache Reserved Nodes
    - OpenSearch Reserved Instances
    - Redshift Reserved Nodes
    - Compute Savings Plans
    - EC2 Instance Savings Plans
    - SageMaker Savings Plans
    
    All recommendations come with exact savings calculations from AWS.
    
    Note: RI/SP recommendations are only available in online mode as they
    require access to AWS Cost Explorer's real-time analysis.
    """

    async def _detect_savings_opportunities(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Get RI and Savings Plans purchase recommendations from AWS Cost Explorer.
        
        This detector uses a smart caching strategy to minimize API costs:
        1. Check if cache is older than 7 days using needs_refresh()
        2. If refresh needed, call Cost Explorer APIs and cache results (~$0.04)
        3. Read recommendations from cache
        
        This approach ensures API is called at most once per week per account,
        regardless of how many waste detection scans are run.
        
        Note: Only available in online mode.
        
        Returns:
            List of WasteItem objects for commitment opportunities
        """
        waste_items = []
        
        # RI/SP recommendations are only available in online mode
        if data_provider.provider_type == 'offline':
            logger.debug("Savings opportunities detection not supported in offline mode")
            return waste_items
        
        # CLO-505: the cache is keyed by the scanned AWS account. Neither real
        # provider has an ``account_id`` attribute, so this was '' for every
        # tenant (one shared ``ACCOUNT#`` cache). Same key as commitment.py
        # (CLO-562: the helpers live in open/commitment_cache.py).
        from cloudwise_scan_core.detectors.open.commitment_cache import (
            commitment_cache_account_id,
            note_refresh_failed,
            note_regions_not_listed,
            note_unresolved_account,
        )
        account_id = commitment_cache_account_id(data_provider)
        if not account_id:
            note_unresolved_account(data_provider)
            return waste_items

        refreshing = False
        try:
            from cloudwise_scan_core.savings_cache_service import (
                RI_REGIONS_NOT_LISTED,
                get_savings_cache_service,
            )
            cache_service = get_savings_cache_service()

            def note_gaps(gaps: List[str]) -> None:
                if RI_REGIONS_NOT_LISTED in gaps:
                    note_regions_not_listed(data_provider)
                if any(gap != RI_REGIONS_NOT_LISTED for gap in gaps):
                    note_refresh_failed(data_provider)
            
            # Build creds dict (needed for cache refresh)
            creds = {
                'access_key_id': getattr(data_provider, '_access_key_id', ''),
                'secret_access_key': getattr(data_provider, '_secret_access_key', ''),
                'region': data_provider.region,
                'session_token': getattr(data_provider, '_session_token', None),
                'account_id': account_id,
                'scan_regions': settings.scan_regions,
            }
            
            # Check if we need to refresh recommendations (once per week)
            if await cache_service.needs_refresh(account_id):
                logger.info(f"Refreshing RI/SP recommendations for account {account_id} (weekly refresh)")
                
                refreshing = True
                refresh_result = await cache_service.refresh_account_recommendations(
                    creds,
                    # Each of these requests is billed to the customer, and only
                    # the commitment detector reads them. An engine without it
                    # (the free CLI scan) has no use for them.
                    include_commitment_usage='commitment' in getattr(self, 'DETECTOR_METHODS', ('commitment',)),
                )
                refreshing = False

                # CLO-777: a log line alone reads as "no commitment findings".
                if not refresh_result.get('success'):
                    note_refresh_failed(data_provider)
                note_gaps(refresh_result.get('failed_fetches') or [])
                
                if refresh_result.get('success'):
                    logger.info(
                        f"Refreshed RI/SP recommendations for account {account_id}: "
                        f"{refresh_result.get('api_calls')} API calls, "
                        f"${refresh_result.get('api_cost_usd', 0):.2f} cost"
                    )
                else:
                    logger.warning(
                        f"Failed to refresh RI/SP recommendations for account {account_id}: "
                        f"{refresh_result.get('error')}"
                    )
            else:
                # The regions it missed stay missing until the next refresh.
                note_gaps(cache_service.refresh_gaps(account_id))
            
            # Read from cache
            ec2_ri_cached = await cache_service.get_cached_recommendations(account_id, 'ec2_ri')
            compute_sp_cached = await cache_service.get_cached_recommendations(account_id, 'compute_sp')
            ec2_sp_cached = await cache_service.get_cached_recommendations(account_id, 'ec2_sp')
            # CLO-775: one purchase for the account's EC2 hours, not all three.
            ec2_rows = _ec2_commitment_rows(
                ec2_ri_cached, compute_sp_cached, ec2_sp_cached, floor=settings.min_waste_threshold_usd,
            )
            ec2_choice = _largest_ec2_commitment(ec2_rows)[0]
            not_shown = _other_ec2_options_line(ec2_choice, ec2_rows)

            if ec2_choice == 'ec2_ri':
                ec2_ri_items = self._convert_cached_ec2_ri_to_waste_items(ec2_ri_cached, data_provider, not_shown)
                waste_items.extend(ec2_ri_items)
            
            rds_ri_cached = await cache_service.get_cached_recommendations(account_id, 'rds_ri')
            if rds_ri_cached:
                rds_ri_items = self._convert_cached_rds_ri_to_waste_items(rds_ri_cached, data_provider)
                waste_items.extend(rds_ri_items)
            
            opensearch_ri_cached = await cache_service.get_cached_recommendations(account_id, 'opensearch_ri')
            if opensearch_ri_cached:
                opensearch_ri_items = self._convert_cached_opensearch_ri_to_waste_items(opensearch_ri_cached, data_provider)
                waste_items.extend(opensearch_ri_items)
            
            if ec2_choice == 'compute_sp':
                sp_items = self._convert_cached_sp_to_waste_items(compute_sp_cached, data_provider, 'compute', not_shown)
                waste_items.extend(sp_items)
            
            if ec2_choice == 'ec2_sp':
                ec2_sp_items = self._convert_cached_sp_to_waste_items(ec2_sp_cached, data_provider, 'ec2_instance', not_shown)
                waste_items.extend(ec2_sp_items)
            
            elasticache_ri_cached = await cache_service.get_cached_recommendations(account_id, 'elasticache_ri')
            if elasticache_ri_cached:
                elasticache_ri_items = self._convert_cached_elasticache_ri_to_waste_items(elasticache_ri_cached, data_provider)
                waste_items.extend(elasticache_ri_items)
            
            redshift_ri_cached = await cache_service.get_cached_recommendations(account_id, 'redshift_ri')
            if redshift_ri_cached:
                redshift_ri_items = self._convert_cached_redshift_ri_to_waste_items(redshift_ri_cached, data_provider)
                waste_items.extend(redshift_ri_items)
            
            sagemaker_sp_cached = await cache_service.get_cached_recommendations(account_id, 'sagemaker_sp')
            if sagemaker_sp_cached:
                sagemaker_sp_items = self._convert_cached_sp_to_waste_items(sagemaker_sp_cached, data_provider, 'sagemaker')
                waste_items.extend(sagemaker_sp_items)
            
        except ClientError as e:
            if refreshing:
                note_refresh_failed(data_provider)
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.info("No access to Cost Explorer for RI/SP recommendations")
            else:
                logger.warning(f"Error querying Cost Explorer: {e}")
        except Exception as e:
            if refreshing:
                note_refresh_failed(data_provider)
            logger.warning(f"Unexpected error in Savings Opportunities detector: {e}")
        
        return waste_items

    @staticmethod
    def _one_row_per_identity(
        cached_data: List[Dict[str, Any]],
        identity_field: str,
        rec_type: str,
    ) -> List[Dict[str, Any]]:
        """The rows that can honestly become one finding each (CLO-774).

        A finding's id comes from its resource_id, so two rows with one identity
        would share a DynamoDB key, and a batch holding both is refused, which can
        cost the region's other findings.

        - No identity: withheld. Botocore has no InstanceType for ElastiCache and
          Redshift (NodeType) or OpenSearch (InstanceClass, InstanceSize), and the
          parser doesn't write instance_class for RDS, so all of these read
          "Purchase N unknown ...". This is the state for real rows of those types.
        - Same instance type in another region, platform or tenancy: the largest
          saving is kept. The EC2 text names the kept row's platform and region
          (CLO-777), not the others', so a sum couldn't be bought as written.
          This understates rather than overstates.
        """
        best: Dict[str, Dict[str, Any]] = {}
        withheld = 0
        for rec in cached_data:
            identity = rec.get(identity_field) or 'unknown'
            if identity == 'unknown':
                withheld += 1
            elif identity not in best or rec.get('monthly_savings', 0) > best[identity].get('monthly_savings', 0):
                best[identity] = rec
        if withheld:
            logger.warning(f"Withheld {withheld} {rec_type} recommendation(s) with no instance type")
        return list(best.values())

    @staticmethod
    def _one_row_per_plan(cached_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """The plan rows that can become one finding each (CLO-784).

        The scan builds a finding's id from its resource_id, and a plan's resource_id
        names only the type, family and region. Two rows sharing those would share a
        key, and a batch holding both is refused. The largest is kept: the text names
        nothing that tells them apart, so a sum couldn't be bought as written. This
        understates rather than overstates.
        """
        best: Dict[Tuple[Any, Any], Dict[str, Any]] = {}
        for rec in cached_data:
            identity = (rec.get('instance_family'), rec.get('region'))
            if identity not in best or rec.get('monthly_savings', 0) > best[identity].get('monthly_savings', 0):
                best[identity] = rec
        return list(best.values())

    def _convert_cached_ec2_ri_to_waste_items(
        self,
        cached_data: List[Dict[str, Any]],
        data_provider: "WasteDataProvider",
        not_shown: str = '',
    ) -> List[WasteItem]:
        """Convert cached EC2 RI recommendations to WasteItem objects."""
        waste_items = []
        
        for rec in self._one_row_per_identity(cached_data, 'instance_type', 'ec2_ri'):
            instance_type = rec.get('instance_type', 'unknown')
            monthly_savings = rec.get('monthly_savings', 0)
            # CLO-774: the parser writes recommended_count. Reading only
            # 'quantity' said "Purchase 1" beside the saving for all of them.
            quantity = rec.get('quantity', rec.get('recommended_count', 1))
            # The parser writes 'unknown' for a missing Region.
            region = rec.get('region') if rec.get('region') != 'unknown' else None
            platform = rec.get('platform') if rec.get('platform') != 'unknown' else None

            if monthly_savings < MIN_SAVINGS_THRESHOLD:
                continue

            waste_items.append(WasteItem(
                id=generate_deterministic_id(instance_type, 'ec2_ri', data_provider.region),
                resource_id=instance_type,
                resource_type=ResourceType.EC2_INSTANCE,
                waste_type=WasteType.RI_OPPORTUNITY_EC2,
                title=f"EC2 Reserved Instance Opportunity",
                description=_ec2_ri_description(quantity, instance_type, platform, region, monthly_savings) + not_shown,
                monthly_savings=monthly_savings,
                confidence=ConfidenceLevel.HIGH,
                action="Purchase Reserved Instances through AWS Console.",
                explanation={
                    'detection': f"AWS Cost Explorer analyzed 30 days of EC2 usage and recommends purchasing {quantity}\u00d7 {instance_type} Reserved Instance(s).",
                    'threshold': f'Recommendations with monthly savings \u2265 ${MIN_SAVINGS_THRESHOLD:.0f} are shown.',
                    'pricing': f'Committing to a {rec.get("term", "1 year")} RI ({rec.get("payment_option", "No Upfront")}) saves ${monthly_savings:.2f}/month vs On-Demand.',
                    'why_waste': 'Running On-Demand instances that have stable, predictable usage costs significantly more than equivalent RIs.',
                    'risk': 'RIs are a commitment. If your usage decreases, you still pay. Start with No Upfront for flexibility.',
                },
                metadata={
                    'instance_type': instance_type,
                    'quantity': quantity,
                    # Where AWS recommends buying, as AWS gives it. The finding's own
                    # region can't carry this: this detector runs once for the account,
                    # so its findings are stamped with the scan's region, and the id and
                    # stale-row sweep both depend on that. Never 'region', for the same
                    # reason: this isn't where the finding was scanned.
                    'recommended_region': region,
                    'platform': rec.get('platform'),
                    'tenancy': rec.get('tenancy'),
                    # The workspace label, in place of "<id> · <scan region>". Only
                    # with a region: a label without one would read as complete.
                    **({'resource_summary': ' · '.join(filter(None, (instance_type, rec.get('platform'), region)))}
                       if region else {}),
                    'term': rec.get('term', '1 year'),
                    'payment_option': rec.get('payment_option', 'No Upfront'),
                    'source': 'aws_cost_explorer',
                    'detection_mode': data_provider.provider_type,
                }
            ))
        
        return waste_items

    def _convert_cached_rds_ri_to_waste_items(
        self,
        cached_data: List[Dict[str, Any]],
        data_provider: "WasteDataProvider",
    ) -> List[WasteItem]:
        """Convert cached RDS RI recommendations to WasteItem objects."""
        waste_items = []
        
        for rec in self._one_row_per_identity(cached_data, 'instance_class', 'rds_ri'):
            instance_class = rec.get('instance_class', 'unknown')
            monthly_savings = rec.get('monthly_savings', 0)
            
            if monthly_savings < MIN_SAVINGS_THRESHOLD:
                continue
            
            waste_items.append(WasteItem(
                id=generate_deterministic_id(instance_class, 'rds_ri', data_provider.region),
                resource_id=instance_class,
                resource_type=ResourceType.RDS_INSTANCE,
                waste_type=WasteType.RI_OPPORTUNITY_RDS,
                title=f"RDS Reserved Instance Opportunity",
                description=(
                    f"Purchase {rec.get('quantity', 1)} {instance_class} RDS Reserved Instance(s) "
                    f"to save ${monthly_savings:.2f}/month."
                ),
                monthly_savings=monthly_savings,
                confidence=ConfidenceLevel.HIGH,
                action="Purchase Reserved Instances through AWS Console.",
                explanation={
                    'detection': f"AWS Cost Explorer analyzed 30 days of RDS usage and recommends purchasing {rec.get('quantity', 1)}\u00d7 {instance_class} Reserved Instance(s).",
                    'threshold': f'Recommendations with monthly savings \u2265 ${MIN_SAVINGS_THRESHOLD:.0f} are shown.',
                    'pricing': f'Committing to a {rec.get("term", "1 year")} RI saves ${monthly_savings:.2f}/month vs On-Demand pricing for {rec.get("engine", "unknown")} instances.',
                    'why_waste': 'Running On-Demand RDS instances with steady usage costs up to 40% more than equivalent Reserved Instances.',
                    'risk': 'RIs are engine- and instance-class-specific. Ensure your RDS fleet will remain stable before committing.',
                },
                metadata={
                    'instance_class': instance_class,
                    'quantity': rec.get('quantity', 1),
                    'engine': rec.get('engine', 'unknown'),
                    'source': 'aws_cost_explorer',
                    'detection_mode': data_provider.provider_type,
                }
            ))
        
        return waste_items

    def _convert_cached_opensearch_ri_to_waste_items(
        self,
        cached_data: List[Dict[str, Any]],
        data_provider: "WasteDataProvider",
    ) -> List[WasteItem]:
        """Convert cached OpenSearch RI recommendations to WasteItem objects."""
        waste_items = []
        
        for rec in self._one_row_per_identity(cached_data, 'instance_type', 'opensearch_ri'):
            instance_type = rec.get('instance_type', 'unknown')
            monthly_savings = rec.get('monthly_savings', 0)
            
            if monthly_savings < MIN_SAVINGS_THRESHOLD:
                continue
            
            waste_items.append(WasteItem(
                id=generate_deterministic_id(instance_type, 'opensearch_ri', data_provider.region),
                resource_id=instance_type,
                resource_type=ResourceType.OPENSEARCH_DOMAIN,
                waste_type=WasteType.RI_OPPORTUNITY_OPENSEARCH,
                title="OpenSearch Reserved Instance Opportunity",
                description=(
                    f"Purchase {rec.get('quantity', rec.get('recommended_count', 1))} "
                    f"{instance_type} OpenSearch Reserved Instance(s) "
                    f"to save ${monthly_savings:.2f}/month."
                ),
                monthly_savings=monthly_savings,
                confidence=ConfidenceLevel.HIGH,
                action="Purchase Reserved Instances through AWS Console.",
                explanation={
                    'detection': (
                        f"AWS Cost Explorer analyzed 30 days of OpenSearch usage and recommends purchasing "
                        f"{rec.get('quantity', rec.get('recommended_count', 1))}× {instance_type} Reserved Instance(s)."
                    ),
                    'threshold': f'Recommendations with monthly savings ≥ ${MIN_SAVINGS_THRESHOLD:.0f} are shown.',
                    'pricing': (
                        f'Committing to a {rec.get("term", "1 year")} RI '
                        f'({rec.get("payment_option", "No Upfront")}) saves ${monthly_savings:.2f}/month '
                        f'vs On-Demand pricing.'
                    ),
                    'why_waste': 'Running On-Demand OpenSearch instances with stable baseline usage costs significantly more than equivalent Reserved Instances.',
                    'risk': 'RIs are a commitment — term lock-in, family/region scoped. Ensure your OpenSearch fleet has a stable baseline before purchasing.',
                },
                metadata={
                    'instance_type': instance_type,
                    'quantity': rec.get('quantity', rec.get('recommended_count', 1)),
                    'term': rec.get('term', '1 year'),
                    'payment_option': rec.get('payment_option', 'No Upfront'),
                    'source': 'aws_cost_explorer',
                    'detection_mode': data_provider.provider_type,
                },
            ))
        
        return waste_items

    def _convert_cached_elasticache_ri_to_waste_items(
        self,
        cached_data: List[Dict[str, Any]],
        data_provider: "WasteDataProvider",
    ) -> List[WasteItem]:
        """Convert cached ElastiCache RI recommendations to WasteItem objects."""
        waste_items = []

        for rec in self._one_row_per_identity(cached_data, 'instance_type', 'elasticache_ri'):
            instance_type = rec.get('instance_type', 'unknown')
            monthly_savings = rec.get('monthly_savings', 0)

            if monthly_savings < MIN_SAVINGS_THRESHOLD:
                continue

            waste_items.append(WasteItem(
                id=generate_deterministic_id(instance_type, 'elasticache_ri', data_provider.region),
                resource_id=instance_type,
                resource_type=ResourceType.ELASTICACHE_CLUSTER,
                waste_type=WasteType.RI_OPPORTUNITY_ELASTICACHE,
                title="ElastiCache Reserved Node Opportunity",
                description=(
                    f"Purchase {rec.get('recommended_count', rec.get('quantity', 1))} "
                    f"{instance_type} ElastiCache Reserved Node(s) "
                    f"to save ${monthly_savings:.2f}/month."
                ),
                monthly_savings=monthly_savings,
                confidence=ConfidenceLevel.HIGH,
                action="Purchase Reserved Nodes through AWS Console.",
                explanation={
                    'detection': (
                        f"AWS Cost Explorer analyzed 30 days of ElastiCache usage and recommends purchasing "
                        f"{rec.get('recommended_count', rec.get('quantity', 1))}× {instance_type} Reserved Node(s)."
                    ),
                    'threshold': f'Recommendations with monthly savings ≥ ${MIN_SAVINGS_THRESHOLD:.0f} are shown.',
                    'pricing': (
                        f'Committing to a {rec.get("term", "1 year")} Reserved Node '
                        f'saves ${monthly_savings:.2f}/month vs On-Demand pricing.'
                    ),
                    'why_waste': (
                        'Running On-Demand ElastiCache nodes with stable baseline usage '
                        'costs up to 40-55% more than equivalent Reserved Nodes.'
                    ),
                    'risk': (
                        'Reserved Nodes are a commitment — engine, node type, and region specific. '
                        'Ensure your ElastiCache fleet will remain stable before purchasing.'
                    ),
                },
                metadata={
                    'instance_type': instance_type,
                    'quantity': rec.get('recommended_count', rec.get('quantity', 1)),
                    'term': rec.get('term', '1 year'),
                    'source': 'aws_cost_explorer',
                    'detection_mode': data_provider.provider_type,
                },
            ))

        return waste_items

    def _convert_cached_redshift_ri_to_waste_items(
        self,
        cached_data: List[Dict[str, Any]],
        data_provider: "WasteDataProvider",
    ) -> List[WasteItem]:
        """Convert cached Redshift RI recommendations to WasteItem objects."""
        waste_items = []

        for rec in self._one_row_per_identity(cached_data, 'instance_type', 'redshift_ri'):
            instance_type = rec.get('instance_type', 'unknown')
            monthly_savings = rec.get('monthly_savings', 0)

            if monthly_savings < MIN_SAVINGS_THRESHOLD:
                continue

            waste_items.append(WasteItem(
                id=generate_deterministic_id(instance_type, 'redshift_ri', data_provider.region),
                resource_id=instance_type,
                resource_type=ResourceType.REDSHIFT_CLUSTER,
                waste_type=WasteType.RI_OPPORTUNITY_REDSHIFT,
                title="Redshift Reserved Node Opportunity",
                description=(
                    f"Purchase {rec.get('recommended_count', rec.get('quantity', 1))} "
                    f"{instance_type} Redshift Reserved Node(s) "
                    f"to save ${monthly_savings:.2f}/month."
                ),
                monthly_savings=monthly_savings,
                confidence=ConfidenceLevel.HIGH,
                action="Purchase Reserved Nodes through AWS Console.",
                explanation={
                    'detection': (
                        f"AWS Cost Explorer analyzed 30 days of Redshift usage and recommends purchasing "
                        f"{rec.get('recommended_count', rec.get('quantity', 1))}× {instance_type} Reserved Node(s)."
                    ),
                    'threshold': f'Recommendations with monthly savings ≥ ${MIN_SAVINGS_THRESHOLD:.0f} are shown.',
                    'pricing': (
                        f'Committing to a {rec.get("term", "1 year")} Reserved Node '
                        f'saves ${monthly_savings:.2f}/month vs On-Demand pricing.'
                    ),
                    'why_waste': (
                        'Running On-Demand Redshift nodes with predictable query workloads '
                        'costs significantly more than equivalent Reserved Nodes.'
                    ),
                    'risk': (
                        'Reserved Nodes lock in node type and region for the term. '
                        'Verify your Redshift cluster will not be resized or migrated before committing.'
                    ),
                },
                metadata={
                    'instance_type': instance_type,
                    'quantity': rec.get('recommended_count', rec.get('quantity', 1)),
                    'term': rec.get('term', '1 year'),
                    'source': 'aws_cost_explorer',
                    'detection_mode': data_provider.provider_type,
                },
            ))

        return waste_items

    def _convert_cached_sp_to_waste_items(
        self,
        cached_data: List[Dict[str, Any]],
        data_provider: "WasteDataProvider",
        sp_type: str,
        not_shown: str = '',
    ) -> List[WasteItem]:
        """Convert cached Savings Plans recommendations to WasteItem objects."""
        waste_items = []
        sp_type_map = {
            'compute': ('Compute', 'a Compute', 'compute', WasteType.SP_OPPORTUNITY_COMPUTE),
            'ec2_instance': ('EC2 Instance', 'an EC2 Instance', 'EC2', WasteType.SP_OPPORTUNITY_EC2),
            'sagemaker': ('SageMaker', 'a SageMaker', 'SageMaker', WasteType.SP_OPPORTUNITY_SAGEMAKER),
        }
        sp_type_display, with_article, usage, waste_type_enum = sp_type_map.get(sp_type, sp_type_map['compute'])
        risk = 'Savings Plans are a commitment to a minimum hourly spend.'
        if sp_type != 'sagemaker':
            risk += ' Compute SPs are more flexible than EC2 Instance SPs.'

        for rec in self._one_row_per_plan(cached_data):
            hourly_commitment = rec.get('hourly_commitment', 0)
            monthly_savings = rec.get('monthly_savings', 0)
            family = rec.get('instance_family')
            region = rec.get('region')

            if monthly_savings < MIN_SAVINGS_THRESHOLD:
                continue

            scope = (f" for the {family} family" if family else '') + (f" in {region}" if region else '')
            # The scan builds the finding's id from this, so it holds what tells two
            # rows apart, and not the commitment, which AWS can change between refreshes.
            resource_id = ' '.join(filter(None, (f"{sp_type_display} Savings Plan", family, region)))

            waste_items.append(WasteItem(
                id=generate_deterministic_id(resource_id, 'savings_plan', data_provider.region),
                resource_id=resource_id,
                resource_type=ResourceType.SAVINGS_PLAN_RECOMMENDATION,
                waste_type=waste_type_enum,
                title=f"{sp_type_display} Savings Plan Opportunity",
                description=(
                    f"Purchase {with_article} Savings Plan{scope} with a ${hourly_commitment:.3f}/hour commitment "
                    f"to save ${monthly_savings:.2f}/month.{not_shown}"
                ),
                monthly_savings=monthly_savings,
                confidence=ConfidenceLevel.HIGH,
                action="Purchase Savings Plan through AWS Console.",
                explanation={
                    'detection': f"AWS Cost Explorer analyzed 30 days of {usage} usage and recommends {with_article} Savings Plan{scope} at ${hourly_commitment:.3f}/hour.",
                    'threshold': f'Recommendations with monthly savings ≥ ${MIN_SAVINGS_THRESHOLD:.0f} are shown.',
                    'pricing': f'A {rec.get("term", "1 year")} {sp_type_display} Savings Plan ({rec.get("payment_option", "No Upfront")}) saves ${monthly_savings:.2f}/month.',
                    'why_waste': f'{sp_type_display} Savings Plans cost less than On-Demand for usage that stays steady.',
                    'risk': risk,
                },
                metadata={
                    'hourly_commitment': hourly_commitment,
                    'sp_type': sp_type,
                    'instance_family': family,
                    # Where AWS recommends buying. Never 'region': see the EC2 RI finding.
                    'recommended_region': region,
                    # The workspace label, in place of "<id> · <scan region>", which
                    # would put the scan's region beside the plan's own.
                    **({'resource_summary': ' · '.join(filter(None, (f"{sp_type_display} Savings Plan", family, region)))}
                       if family or region else {}),
                    'term': rec.get('term', '1 year'),
                    'payment_option': rec.get('payment_option', 'No Upfront'),
                    'source': 'aws_cost_explorer',
                    'detection_mode': data_provider.provider_type,
                }
            ))

        return waste_items


def _ec2_ri_description(
    quantity: Any,
    instance_type: str,
    platform: Optional[str],
    region: Optional[str],
    monthly_savings: float,
) -> str:
    """What to buy, on what platform and where (CLO-777).

    The finding's own region is the scan's, because the detector runs once for the
    account, so every reader (the card, Copilot, the agent digest) needs the text to
    say where AWS recommends buying. Platform and region are AWS's strings as given
    ("Linux/UNIX", "US East (N. Virginia)"). A missing one is left out, never guessed:
    never "unknown", and never the scan's region.

    CLO-777: approved 2026-11-03 under Rick's delegation.
    """
    what = ' '.join(filter(None, (str(quantity), instance_type, platform, 'Reserved Instance(s)')))
    where = f" in {region}" if region else ''
    return f"Purchase {what}{where} to save ${monthly_savings:.2f}/month."


_EC2_COMMITMENT_NAMES = {
    'compute_sp': 'Compute Savings Plan',
    'ec2_sp': 'EC2 Instance Savings Plan',
    'ec2_ri': 'EC2 Reserved Instances',
}


def _counted_rows(rows: List[Dict[str, Any]], floor: float) -> List[Dict[str, Any]]:
    """The rows that become findings: at or above the minimum and the scan's floor."""
    least = max(MIN_SAVINGS_THRESHOLD, floor)
    return [r for r in rows if r.get('monthly_savings', 0) >= least]


def _saving(rows: List[Dict[str, Any]]) -> float:
    return sum(r.get('monthly_savings', 0) for r in rows)


def _ec2_commitment_rows(
    ec2_ri: Optional[List[Dict[str, Any]]],
    compute_sp: Optional[List[Dict[str, Any]]],
    ec2_sp: Optional[List[Dict[str, Any]]],
    floor: float = 0.0,
) -> Dict[str, List[Dict[str, Any]]]:
    """The rows each alternative for the account's EC2 hours would show, most flexible first."""
    one_plan = SavingsOpportunitiesDetectorsMixin._one_row_per_plan
    one_type = SavingsOpportunitiesDetectorsMixin._one_row_per_identity
    return {
        'compute_sp': _counted_rows(one_plan(compute_sp or []), floor),
        'ec2_sp': _counted_rows(one_plan(ec2_sp or []), floor),
        'ec2_ri': _counted_rows(one_type(ec2_ri or [], 'instance_type', 'ec2_ri'), floor),
    }


def _largest_ec2_commitment(by_key: Dict[str, List[Dict[str, Any]]]) -> Tuple[Optional[str], float]:
    best_key, best_savings = None, 0.0
    for key, rows in by_key.items():
        if _saving(rows) > best_savings:
            best_key, best_savings = key, _saving(rows)
    return best_key, best_savings


def _other_ec2_options_line(choice: Optional[str], by_key: Dict[str, List[Dict[str, Any]]]) -> str:
    """The line on a finding when other options for the same hours aren't shown (CLO-784).

    Someone who can't buy the largest option would otherwise never see the others.
    Empty when there are no others, so it never implies there are. It sits on every
    finding of the kept option, so it states that option's total: beside a smaller
    row, "the largest" would otherwise read as that row. The others are for the
    account's hours, not for the one row it sits on.
    """
    others = [
        f"{_EC2_COMMITMENT_NAMES[key]} (${_saving(rows):.2f}/month)"
        for key, rows in sorted(by_key.items(), key=lambda kv: -_saving(kv[1]))
        if key != choice and rows
    ]
    if not others or choice is None:
        return ''
    kept = by_key[choice]
    across = f" across {len(kept)} findings" if len(kept) > 1 else ''
    return (
        f" The account's EC2 hours can only be covered once, so only the largest option, "
        f"${_saving(kept):.2f}/month{across}, is shown. "
        f"Also recommended by AWS for those hours: {', '.join(others)}."
    )


def counted_ec2_commitment(
    ec2_ri: Optional[List[Dict[str, Any]]],
    compute_sp: Optional[List[Dict[str, Any]]],
    ec2_sp: Optional[List[Dict[str, Any]]],
    floor: float = 0.0,
) -> Tuple[Optional[str], float]:
    """Which purchase counts for the account's EC2 hours, and what it saves (CLO-775).

    An EC2 RI, a Compute plan and an EC2 Instance plan are alternatives: Cost
    Explorer prices each against the same On-Demand hours, ignoring the others,
    so their savings can't be added. Only the largest one becomes findings. The
    rows inside one of them are for different usage, so those do add. A tie goes
    to the more flexible: Compute, then EC2 Instance, then the RI. RDS, OpenSearch,
    ElastiCache, Redshift and SageMaker commitments don't price an EC2 hour, so
    they aren't part of this.

    A row counts only if it can become a finding: the same rows the converters
    keep, at or above the scan's floor. Returns (cache key, monthly savings), or
    (None, 0.0) when no row counts.

    Compute plans also cover Fargate and Lambda, which an RI doesn't. Letting an
    RI replace one can understate, and never overstates.
    """
    return _largest_ec2_commitment(_ec2_commitment_rows(ec2_ri, compute_sp, ec2_sp, floor))


def counted_sagemaker_commitment(sagemaker_sp: Optional[List[Dict[str, Any]]], floor: float = 0.0) -> float:
    """What the SageMaker plan findings save, by the same rule as the EC2 ones (CLO-784).

    The coverage gap reads an unfiltered GetSavingsPlansCoverage, and botocore doesn't
    say whether that includes SageMaker-eligible usage. The gap deducts this: if it
    does include it, that stops a double count, and if it doesn't, the gap understates.
    Either way it can't overstate.
    """
    return _saving(_counted_rows(SavingsOpportunitiesDetectorsMixin._one_row_per_plan(sagemaker_sp or []), floor))
