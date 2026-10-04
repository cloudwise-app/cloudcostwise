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
from typing import Dict, Any, List, Optional, TYPE_CHECKING
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
            note_unresolved_account,
        )
        account_id = commitment_cache_account_id(data_provider)
        if not account_id:
            note_unresolved_account(data_provider)
            return waste_items

        try:
            from cloudwise_scan_core.savings_cache_service import get_savings_cache_service
            cache_service = get_savings_cache_service()
            
            # Build creds dict (needed for cache refresh and risk score)
            creds = {
                'access_key_id': getattr(data_provider, '_access_key_id', ''),
                'secret_access_key': getattr(data_provider, '_secret_access_key', ''),
                'region': data_provider.region,
                'session_token': getattr(data_provider, '_session_token', None),
                'account_id': account_id,
            }
            
            # Check if we need to refresh recommendations (once per week)
            if await cache_service.needs_refresh(account_id):
                logger.info(f"Refreshing RI/SP recommendations for account {account_id} (weekly refresh)")
                
                refresh_result = await cache_service.refresh_account_recommendations(creds)
                
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
            
            # Read from cache
            ec2_ri_cached = await cache_service.get_cached_recommendations(account_id, 'ec2_ri')
            if ec2_ri_cached:
                ec2_ri_items = self._convert_cached_ec2_ri_to_waste_items(ec2_ri_cached, data_provider)
                waste_items.extend(ec2_ri_items)
            
            rds_ri_cached = await cache_service.get_cached_recommendations(account_id, 'rds_ri')
            if rds_ri_cached:
                rds_ri_items = self._convert_cached_rds_ri_to_waste_items(rds_ri_cached, data_provider)
                waste_items.extend(rds_ri_items)
            
            opensearch_ri_cached = await cache_service.get_cached_recommendations(account_id, 'opensearch_ri')
            if opensearch_ri_cached:
                opensearch_ri_items = self._convert_cached_opensearch_ri_to_waste_items(opensearch_ri_cached, data_provider)
                waste_items.extend(opensearch_ri_items)
            
            compute_sp_cached = await cache_service.get_cached_recommendations(account_id, 'compute_sp')
            if compute_sp_cached:
                sp_items = self._convert_cached_sp_to_waste_items(compute_sp_cached, data_provider, 'compute')
                waste_items.extend(sp_items)
            
            ec2_sp_cached = await cache_service.get_cached_recommendations(account_id, 'ec2_sp')
            if ec2_sp_cached:
                ec2_sp_items = self._convert_cached_sp_to_waste_items(ec2_sp_cached, data_provider, 'ec2_instance')
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
            
            # Phase 5: Calculate commitment risk score and enrich recommendations
            if waste_items:
                logger.info(f"Found {len(waste_items)} RI/SP recommendations for account {account_id}")
                try:
                    from app.services.commitment_risk_service import CommitmentRiskService
                    risk_service = CommitmentRiskService()
                    risk_score = await risk_service.calculate_risk_score(creds)
                    self._enrich_with_commitment_risk(waste_items, risk_score)
                except Exception as e:
                    logger.warning(f"Could not calculate commitment risk score: {e}")
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.info("No access to Cost Explorer for RI/SP recommendations")
            else:
                logger.warning(f"Error querying Cost Explorer: {e}")
        except Exception as e:
            logger.warning(f"Unexpected error in Savings Opportunities detector: {e}")
        
        return waste_items

    def _convert_cached_ec2_ri_to_waste_items(
        self,
        cached_data: List[Dict[str, Any]],
        data_provider: "WasteDataProvider",
    ) -> List[WasteItem]:
        """Convert cached EC2 RI recommendations to WasteItem objects."""
        waste_items = []
        
        for rec in cached_data:
            instance_type = rec.get('instance_type', 'unknown')
            monthly_savings = rec.get('monthly_savings', 0)
            
            if monthly_savings < MIN_SAVINGS_THRESHOLD:
                continue
            
            waste_items.append(WasteItem(
                id=generate_deterministic_id(instance_type, 'ec2_ri', data_provider.region),
                resource_id=instance_type,
                resource_type=ResourceType.EC2_INSTANCE,
                waste_type=WasteType.RI_OPPORTUNITY_EC2,
                title=f"EC2 Reserved Instance Opportunity",
                description=(
                    f"Purchase {rec.get('quantity', 1)} {instance_type} Reserved Instance(s) "
                    f"to save ${monthly_savings:.2f}/month."
                ),
                monthly_savings=monthly_savings,
                confidence=ConfidenceLevel.HIGH,
                action="Purchase Reserved Instances through AWS Console.",
                explanation={
                    'detection': f"AWS Cost Explorer analyzed 30 days of EC2 usage and recommends purchasing {rec.get('quantity', 1)}\u00d7 {instance_type} Reserved Instance(s).",
                    'threshold': f'Recommendations with monthly savings \u2265 ${MIN_SAVINGS_THRESHOLD:.0f} are shown.',
                    'pricing': f'Committing to a {rec.get("term", "1 year")} RI ({rec.get("payment_option", "No Upfront")}) saves ${monthly_savings:.2f}/month vs On-Demand.',
                    'why_waste': 'Running On-Demand instances that have stable, predictable usage costs significantly more than equivalent RIs.',
                    'risk': 'RIs are a commitment. If your usage decreases, you still pay. Start with No Upfront for flexibility.',
                },
                metadata={
                    'instance_type': instance_type,
                    'quantity': rec.get('quantity', 1),
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
        
        for rec in cached_data:
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
        
        for rec in cached_data:
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

        for rec in cached_data:
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

        for rec in cached_data:
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
    ) -> List[WasteItem]:
        """Convert cached Savings Plans recommendations to WasteItem objects."""
        waste_items = []
        
        for rec in cached_data:
            hourly_commitment = rec.get('hourly_commitment', 0)
            monthly_savings = rec.get('monthly_savings', 0)
            
            if monthly_savings < MIN_SAVINGS_THRESHOLD:
                continue
            
            sp_type_map = {
                'compute': ('Compute', WasteType.SP_OPPORTUNITY_COMPUTE),
                'ec2_instance': ('EC2 Instance', WasteType.SP_OPPORTUNITY_EC2),
                'sagemaker': ('SageMaker', WasteType.SP_OPPORTUNITY_SAGEMAKER),
            }
            sp_type_display, waste_type_enum = sp_type_map.get(sp_type, ('Compute', WasteType.SP_OPPORTUNITY_COMPUTE))
            
            waste_items.append(WasteItem(
                id=generate_deterministic_id(f"{sp_type}_{hourly_commitment}", 'savings_plan', data_provider.region),
                resource_id=f"{sp_type_display} Savings Plan",
                resource_type=ResourceType.SAVINGS_PLAN_RECOMMENDATION,
                waste_type=waste_type_enum,
                title=f"{sp_type_display} Savings Plan Opportunity",
                description=(
                    f"Purchase a {sp_type_display} Savings Plan with ${hourly_commitment:.2f}/hour commitment "
                    f"to save ${monthly_savings:.2f}/month."
                ),
                monthly_savings=monthly_savings,
                confidence=ConfidenceLevel.HIGH,
                action="Purchase Savings Plan through AWS Console.",
                explanation={
                    'detection': f"AWS Cost Explorer analyzed 30 days of compute usage and recommends a {sp_type_display} Savings Plan at ${hourly_commitment:.2f}/hour.",
                    'threshold': f'Recommendations with monthly savings ≥ ${MIN_SAVINGS_THRESHOLD:.0f} are shown.',
                    'pricing': f'A {rec.get("term", "1 year")} {sp_type_display} Savings Plan ({rec.get("payment_option", "No Upfront")}) saves ${monthly_savings:.2f}/month.',
                    'why_waste': f'{sp_type_display} Savings Plans offer up to 72% savings over On-Demand for predictable compute usage.',
                    'risk': 'Savings Plans are a commitment to a minimum hourly spend. Compute SPs are more flexible than EC2 Instance SPs.',
                },
                metadata={
                    'hourly_commitment': hourly_commitment,
                    'sp_type': sp_type,
                    'term': rec.get('term', '1 year'),
                    'payment_option': rec.get('payment_option', 'No Upfront'),
                    'source': 'aws_cost_explorer',
                    'detection_mode': data_provider.provider_type,
                }
            ))
        
        return waste_items

    def _enrich_with_commitment_risk(
        self,
        waste_items: List[WasteItem],
        risk_score,
    ) -> None:
        """Add commitment risk metadata to all purchase recommendation WasteItems (Phase 5)."""
        for item in waste_items:
            # Add risk details to explanation
            item.explanation['commitment_risk'] = {
                'score': risk_score.overall_score,
                'label': risk_score.risk_label,
                'recommendation': risk_score.recommendation,
                'max_safe_term': risk_score.max_safe_term,
                'instance_family_churn': risk_score.instance_family_churn,
                'spend_volatility': risk_score.spend_volatility,
            }

            # Add risk fields to metadata
            item.metadata['commitment_risk_score'] = risk_score.overall_score
            item.metadata['commitment_risk_label'] = risk_score.risk_label
            item.metadata['max_safe_commitment_term'] = risk_score.max_safe_term

            # Modify title for HIGH/CRITICAL risk (§10.4)
            if risk_score.risk_label == 'HIGH':
                item.title = f"⚠️ {item.title} (High Risk)"
            elif risk_score.risk_label == 'CRITICAL':
                item.title = f"🚫 {item.title} (Critical Risk) — NOT RECOMMENDED"
