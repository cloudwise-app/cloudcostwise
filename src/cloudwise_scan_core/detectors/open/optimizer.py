"""
AWS Compute Optimizer Waste Detectors

This module provides rightsizing recommendations using AWS Compute Optimizer.
Compute Optimizer uses ML to analyze 14 days of CloudWatch metrics and provides
specific instance type recommendations with exact savings calculations.

AWS Compute Optimizer is FREE for:
- EC2 instances
- EBS volumes
- Lambda functions
- ECS services on Fargate

Philosophy Alignment:
- Confidence: HIGH (AWS ML-backed analysis)
- Accuracy: 100% (uses AWS's official recommendations)
- No arbitrary assumptions (AWS calculates, not us)

All detectors use the DataProvider abstraction pattern for true online/offline parity.
"""

import logging
import uuid
from typing import Dict, Any, List, Optional, TYPE_CHECKING

from botocore.exceptions import ClientError

from cloudwise_scan_core.data_providers.online import ACCESS_DENIED_ERROR_CODES
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

# Minimum monthly savings to report (avoid noise from tiny optimizations)
MIN_SAVINGS_THRESHOLD = 5.0  # $5/month minimum

# CLO-375: error codes meaning "this account has not opted in to Compute
# Optimizer", as distinct from a missing IAM permission. Opting in is free and
# the customer's call; a denied call means the role template is out of date.
# Neither may read as "no waste".
_OPT_IN_ERROR_CODES = frozenset({'OptInRequiredException', 'OptInRequired'})

COVERAGE_SOURCE = 'compute_optimizer'


def _normalize_enum_value(value: Optional[str]) -> str:
    """CLO-583: compare Compute Optimizer enum-ish strings (``finding``,
    ``instanceFinding``, utilization metric ``name``) case- and
    underscore-insensitively.

    ``GetEC2InstanceRecommendations``' ``finding`` is documented with BOTH a
    "Valid Values" list (``Overprovisioned`` / ``Underprovisioned`` /
    ``Optimized`` / ``NotOptimized``) AND, in the same field's description,
    a note that "the valid values in your API responses appear as
    ``OVER_PROVISIONED``, ``UNDER_PROVISIONED``, or ``OPTIMIZED``". AWS's own
    service team confirmed this is real, not stale copy
    (github.com/aws/aws-sdk#550, closed 2024-05-01, from
    github.com/boto/boto3#3746, where a user reported seeing exactly the
    SCREAMING_SNAKE_CASE spelling in production): their resolution was to
    add that note, not to change the API. So this field can legitimately
    come back as either spelling depending on the account/region, and
    hardcoding a comparison against only one of them is a latent bug
    regardless of which one is picked (this module's original EC2 check
    used the documented WIRE spelling and most likely worked for real
    traffic; CLO-583's RDS fix below is the one that was genuinely dead, by
    reading response keys that do not exist under any spelling). Normalizing
    both sides before comparing accepts either without having to guess, and
    costs nothing when the two sides already match (e.g. EBS/Lambda
    ``NotOptimized``, RDS ``instanceFinding``, where no such mismatch has
    been reported — applied there purely as defense-in-depth)."""
    return (value or '').replace('_', '').replace('-', '').upper()


def _best_recommendation_option(options: List[Dict[str, Any]]) -> Dict[str, Any]:
    """CLO-587: pick the recommendation option Compute Optimizer itself
    ranks best, not whichever one the API happened to list first.

    ``recommendationOptions`` (EC2) and ``instanceRecommendationOptions``
    (RDS) both carry a ``rank``. EC2's is documented as "The top
    recommendation option is ranked as 1."; RDS documents no direction, so
    lowest = best is assumed there by analogy with EC2. Neither API promises
    list order, so ``options[0]`` was whatever AWS returned first. This
    picks the lowest ``rank`` among options that carry one, falling back to
    ``[0]`` only when none has a usable (integer) rank."""
    ranked = [(opt.get('rank'), opt) for opt in options]
    with_rank = [(r, opt) for r, opt in ranked if isinstance(r, int)]
    if with_rank:
        return min(with_rank, key=lambda item: item[0])[1]
    return options[0]


def _lambda_function_name(function_arn: str) -> str:
    """The function name from a Lambda ARN, qualified or not (CLO-507).

    ``arn:aws:lambda:us-east-1:123456789012:function:my-fn:$LATEST`` is
    ``my-fn``. A value that is not a function ARN is returned as is."""
    parts = (function_arn or '').split(':')
    if len(parts) >= 7 and parts[5] == 'function':
        return parts[6]
    return function_arn or ''


def _lambda_version_rank(version: str) -> tuple:
    """Sort key: ``$LATEST`` first, then higher numbered versions."""
    if version == '$LATEST':
        return (2, 0)
    if version.isdigit():
        return (1, int(version))
    return (0, 0)


def _record_coverage_note(data_provider: "WasteDataProvider", state: str) -> None:
    record = getattr(data_provider, '_record_coverage_note', None)
    if callable(record):
        record(COVERAGE_SOURCE, state)


class ComputeOptimizerDetectorsMixin:
    """
    Mixin class providing AWS Compute Optimizer-based waste detectors.
    
    These detectors use AWS's official ML-backed recommendations for rightsizing,
    which aligns with CloudWise's "Accuracy Over Everything" philosophy.
    
    AWS Compute Optimizer provides:
    - EC2 instance rightsizing
    - EBS volume rightsizing  
    - Lambda function memory optimization
    - ECS on Fargate rightsizing
    
    All recommendations come with exact savings calculations from AWS.
    
    Note: Compute Optimizer is only available in online mode as it requires
    real-time access to AWS's ML analysis service.
    """

    def _record_optimizer_failure(
        self,
        data_provider: "WasteDataProvider",
        operation: str,
        error: Exception,
    ) -> None:
        """CLO-375: put a Compute Optimizer failure where the customer sees it.

        - Not opted in: a coverage note on the account row. The scan still
          succeeded; the rightsizing findings are missing, not zero.
        - AccessDenied: recorded on the provider, which carries it to
          ``permission_missing`` on the account row (the CLO-368 path) and the
          "role update needed" chip.
        - Anything else: a WARNING. The production API drops INFO (CLO-326),
          and these used to be logged at INFO or DEBUG.
        """
        region = getattr(data_provider, 'region', 'unknown')
        code = (
            error.response.get('Error', {}).get('Code', '')
            if isinstance(error, ClientError) else ''
        )

        if code in _OPT_IN_ERROR_CODES:
            _record_coverage_note(data_provider, 'not_enrolled')
            logger.warning(
                "Compute Optimizer is not enabled for this account (region=%s, %s calling %s): "
                "rightsizing findings are MISSING, not zero",
                region, code, operation,
            )
            return

        if code in ACCESS_DENIED_ERROR_CODES:
            permission = f"compute-optimizer:{operation}"
            record = getattr(data_provider, '_record_permission_error', None)
            if callable(record):
                record(
                    resource='Compute Optimizer recommendations',
                    permission=permission,
                    error=error,
                )
            logger.warning(
                "Compute Optimizer %s denied (region=%s, %s): findings that depend on it are "
                "MISSING, not zero, until the CloudWise role grants %s",
                operation, region, code, permission,
            )
            return

        logger.warning("Compute Optimizer %s failed (region=%s): %s", operation, region, error)

    async def _detect_compute_optimizer_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Get rightsizing recommendations from AWS Compute Optimizer.
        
        This detector queries AWS Compute Optimizer for resources that are
        Overprovisioned and returns specific recommendations with exact savings.
        
        Note: Only available in online mode as it requires real-time AWS API access.
        
        Returns:
            List of WasteItem objects for oversized resources
        """
        waste_items = []
        
        # Compute Optimizer is only available in online mode
        if data_provider.provider_type == 'offline':
            logger.debug("Compute Optimizer detection not supported in offline mode")
            return waste_items
        
        if not hasattr(data_provider, '_get_client'):
            return waste_items
        
        try:
            optimizer_client = data_provider._get_client('compute-optimizer')
            
            # Check if Compute Optimizer is enabled
            try:
                status = optimizer_client.get_enrollment_status()
            except ClientError as e:
                self._record_optimizer_failure(data_provider, 'GetEnrollmentStatus', e)
                return waste_items

            enrollment = status.get('status')
            if enrollment != 'Active':
                # CLO-375: 'Pending' means the customer just opted in and AWS
                # is still activating; anything else ('Inactive', 'Failed', or
                # no status) means it is off. Either way this is a coverage
                # gap the customer can close, never "no waste".
                state = 'pending' if enrollment == 'Pending' else 'not_enrolled'
                _record_coverage_note(data_provider, state)
                logger.warning(
                    "Compute Optimizer enrollment is %s in %s: rightsizing findings are "
                    "MISSING, not zero",
                    enrollment or 'unknown', data_provider.region,
                )
                return waste_items

            # Get EC2 recommendations
            ec2_items = await self._get_ec2_optimizer_recommendations(
                optimizer_client, data_provider, settings
            )
            waste_items.extend(ec2_items)
            
            # Get EBS recommendations
            ebs_items = await self._get_ebs_optimizer_recommendations(
                optimizer_client, data_provider, settings
            )
            waste_items.extend(ebs_items)
            
            # Get Lambda recommendations
            lambda_items = await self._get_lambda_optimizer_recommendations(
                optimizer_client, data_provider, settings
            )
            waste_items.extend(lambda_items)
            
            # Get RDS recommendations (if available)
            rds_items = await self._get_rds_optimizer_recommendations(
                optimizer_client, data_provider, settings
            )
            waste_items.extend(rds_items)

        except Exception as e:
            logger.warning(f"Unexpected error in Compute Optimizer detector: {e}")
        
        return waste_items

    async def _get_ec2_optimizer_recommendations(
        self,
        client,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """Get EC2 rightsizing recommendations from Compute Optimizer."""
        waste_items = []
        
        try:
            # Use manual pagination since get_ec2_instance_recommendations doesn't support get_paginator
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs['nextToken'] = next_token
                
                response = client.get_ec2_instance_recommendations(**kwargs)
                
                for rec in response.get('instanceRecommendations', []):
                    finding = rec.get('finding')

                    # CLO-583: this field is documented two ways -- a "Valid
                    # Values" list (Overprovisioned) and a same-field note
                    # that responses "appear as" OVER_PROVISIONED -- and AWS
                    # confirmed both are real wire spellings. Match either
                    # (_normalize_enum_value docstring) instead of hardcoding
                    # one and silently missing accounts/regions on the other.
                    if _normalize_enum_value(finding) != _normalize_enum_value('Overprovisioned'):
                        continue
                    
                    instance_arn = rec.get('instanceArn', '')
                    instance_id = instance_arn.split('/')[-1] if '/' in instance_arn else instance_arn
                    current_type = rec.get('currentInstanceType', 'unknown')
                    
                    instance_name = instance_id
                    
                    options = rec.get('recommendationOptions', [])
                    if not options:
                        continue

                    best_option = _best_recommendation_option(options)
                    recommended_type = best_option.get('instanceType', 'unknown')
                    
                    savings_opportunity = best_option.get('savingsOpportunity', {})
                    savings_percentage = savings_opportunity.get('savingsOpportunityPercentage', 0)
                    estimated_savings = savings_opportunity.get('estimatedMonthlySavings', {})
                    monthly_savings = float(estimated_savings.get('value', 0))
                    
                    if monthly_savings < MIN_SAVINGS_THRESHOLD:
                        continue
                    
                    utilization = rec.get('utilizationMetrics', [])
                    cpu_util = None
                    memory_util = None
                    for metric in utilization:
                        # CLO-583: EC2's UtilizationMetric.name enum is
                        # Cpu/Memory (not CPU/MEMORY); normalized to be safe.
                        metric_name = _normalize_enum_value(metric.get('name'))
                        if metric_name == _normalize_enum_value('Cpu'):
                            cpu_util = metric.get('value')
                        elif metric_name == _normalize_enum_value('Memory'):
                            memory_util = metric.get('value')

                    confidence = ConfidenceLevel.HIGH
                    
                    util_parts = []
                    if cpu_util is not None:
                        util_parts.append(f"CPU: {cpu_util:.1f}%")
                    if memory_util is not None:
                        util_parts.append(f"Memory: {memory_util:.1f}%")
                    util_str = ", ".join(util_parts) if util_parts else "See AWS Console"
                    
                    waste_items.append(WasteItem(
                        id=generate_deterministic_id(instance_id, 'oversized_ec2_optimizer', data_provider.region),
                        resource_id=instance_id,
                        resource_type=ResourceType.EC2_INSTANCE,
                        waste_type=WasteType.OVERSIZED_EC2_OPTIMIZER,
                        title=f"Oversized EC2 Instance (Compute Optimizer)",
                        description=(
                            f"Instance '{instance_name}' ({current_type}) can be downsized to {recommended_type}. "
                            f"Utilization: {util_str}. AWS Compute Optimizer analysis."
                        ),
                        monthly_savings=monthly_savings,
                        confidence=confidence,
                        action=f"Resize instance from {current_type} to {recommended_type}.",
                        explanation={
                            'detection': f"AWS Compute Optimizer analyzed 14 days of utilization and recommends downsizing from {current_type} to {recommended_type}.",
                            'threshold': 'Compute Optimizer flags instances as Overprovisioned when CPU/memory consistently underutilize the current size.',
                            'pricing': f'Downsizing saves ~${monthly_savings:.0f}/month ({savings_percentage:.0f}% reduction). Utilization: {util_str}.',
                            'why_waste': 'An oversized instance pays for CPU and memory capacity it does not use.',
                            'risk': 'Resize requires a brief stop/start. Test the new size in staging first and monitor after resizing.',
                        },
                        metadata={
                            'instance_id': instance_id,
                            'current_type': current_type,
                            'recommended_type': recommended_type,
                            'savings_percentage': savings_percentage,
                            'cpu_utilization': cpu_util,
                            'memory_utilization': memory_util,
                            'source': 'aws_compute_optimizer',
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                
                # Check for more pages
                next_token = response.get('nextToken')
                if not next_token:
                    break
            
        except ClientError as e:
            self._record_optimizer_failure(data_provider, 'GetEC2InstanceRecommendations', e)
        except Exception as e:
            logger.warning(f"Error getting EC2 Compute Optimizer recommendations: {e}")
        
        return waste_items

    async def _get_ebs_optimizer_recommendations(
        self,
        client,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """Get EBS volume rightsizing recommendations from Compute Optimizer."""
        waste_items = []
        
        try:
            # Use manual pagination since get_ebs_volume_recommendations doesn't support get_paginator
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs['nextToken'] = next_token
                
                response = client.get_ebs_volume_recommendations(**kwargs)
                
                for rec in response.get('volumeRecommendations', []):
                    finding = rec.get('finding')

                    # Only process volumes that are NotOptimized (have optimization
                    # opportunities). CLO-583: normalized defensively, same as the
                    # EC2/RDS finding checks (_normalize_enum_value docstring).
                    if _normalize_enum_value(finding) != _normalize_enum_value('NotOptimized'):
                        continue
                    
                    volume_arn = rec.get('volumeArn', '')
                    volume_id = volume_arn.split('/')[-1] if '/' in volume_arn else volume_arn
                    
                    current_config = rec.get('currentConfiguration', {})
                    current_type = current_config.get('volumeType', 'unknown')
                    current_size = current_config.get('volumeSize', 0)
                    
                    options = rec.get('volumeRecommendationOptions', [])
                    if not options:
                        continue
                    
                    best_option = options[0]
                    new_config = best_option.get('configuration', {})
                    recommended_type = new_config.get('volumeType', current_type)
                    recommended_size = new_config.get('volumeSize', current_size)
                    
                    savings_opportunity = best_option.get('savingsOpportunity', {})
                    estimated_savings = savings_opportunity.get('estimatedMonthlySavings', {})
                    monthly_savings = float(estimated_savings.get('value', 0))
                    
                    if monthly_savings < MIN_SAVINGS_THRESHOLD:
                        continue
                    
                    waste_items.append(WasteItem(
                        id=generate_deterministic_id(volume_id, 'oversized_ebs', data_provider.region),
                        resource_id=volume_id,
                        resource_type=ResourceType.EBS_VOLUME,
                        waste_type=WasteType.OVERSIZED_EBS_OPTIMIZER,
                        title=f"Oversized EBS Volume (Compute Optimizer)",
                        description=(
                            f"Volume {volume_id} ({current_type}, {current_size}GB) can be optimized "
                            f"to {recommended_type}, {recommended_size}GB. AWS Compute Optimizer analysis."
                        ),
                        monthly_savings=monthly_savings,
                        confidence=ConfidenceLevel.HIGH,
                        action=f"Modify volume to {recommended_type} with {recommended_size}GB.",
                        explanation={
                            'detection': f"AWS Compute Optimizer recommends changing from {current_type} ({current_size}GB) to {recommended_type} ({recommended_size}GB).",
                            'threshold': 'Compute Optimizer flags EBS volumes as NotOptimized when IOPS/throughput usage is consistently below the volume type\'s capacity.',
                            'pricing': f'Optimization saves ~${monthly_savings:.0f}/month by right-sizing volume type and capacity.',
                            'why_waste': 'An over-provisioned EBS volume pays for IOPS and throughput it does not use.',
                            'risk': 'EBS modify is online and non-disruptive for most changes. Monitor IOPS after modification.',
                        },
                        metadata={
                            'volume_id': volume_id,
                            'current_type': current_type,
                            'current_size_gb': current_size,
                            'recommended_type': recommended_type,
                            'recommended_size_gb': recommended_size,
                            'source': 'aws_compute_optimizer',
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                
                # Check for more pages
                next_token = response.get('nextToken')
                if not next_token:
                    break
            
        except ClientError as e:
            self._record_optimizer_failure(data_provider, 'GetEBSVolumeRecommendations', e)
        except Exception as e:
            logger.warning(f"Error getting EBS Compute Optimizer recommendations: {e}")
        
        return waste_items

    async def _get_lambda_optimizer_recommendations(
        self,
        client,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """Get Lambda function memory recommendations from Compute Optimizer.

        CLO-507: Compute Optimizer recommends per function VERSION, and its
        ``functionArn`` is version-qualified
        (``arn:aws:lambda:<region>:<acct>:function:<name>:<version>``), so
        ``split(':')[-1]`` named the finding "$LATEST" or "3" instead of the
        function. The name is now the ARN's function segment, and a function
        recommended for several versions yields ONE finding (its
        deterministic id is per function): the ``$LATEST`` recommendation,
        whose memory setting is the one a configuration change edits, else
        the highest numbered version."""
        waste_items = []
        # function name -> (version sort key, finding); see _pick below.
        by_function: Dict[str, Any] = {}

        try:
            # Use manual pagination since get_lambda_function_recommendations doesn't support get_paginator
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs['nextToken'] = next_token
                
                response = client.get_lambda_function_recommendations(**kwargs)
                
                for rec in response.get('lambdaFunctionRecommendations', []):
                    finding = rec.get('finding')

                    # Only process functions that are NotOptimized (have optimization
                    # opportunities). CLO-583: normalized defensively, same as the
                    # EC2/RDS finding checks (_normalize_enum_value docstring).
                    if _normalize_enum_value(finding) != _normalize_enum_value('NotOptimized'):
                        continue
                    
                    function_arn = rec.get('functionArn', '')
                    function_name = _lambda_function_name(function_arn)
                    function_version = str(rec.get('functionVersion') or '')
                    if not function_name:
                        continue

                    current_config = rec.get('currentMemorySize', 0)
                    
                    options = rec.get('memorySizeRecommendationOptions', [])
                    if not options:
                        continue
                    
                    best_option = options[0]
                    recommended_memory = best_option.get('memorySize', current_config)
                    
                    savings_opportunity = best_option.get('savingsOpportunity', {})
                    estimated_savings = savings_opportunity.get('estimatedMonthlySavings', {})
                    monthly_savings = float(estimated_savings.get('value', 0))
                    
                    if monthly_savings < MIN_SAVINGS_THRESHOLD:
                        continue
                    
                    item = WasteItem(
                        id=generate_deterministic_id(function_name, 'oversized_lambda_optimizer', data_provider.region),
                        resource_id=function_name,
                        resource_type=ResourceType.LAMBDA_FUNCTION,
                        waste_type=WasteType.OVERSIZED_LAMBDA_OPTIMIZER,
                        title=f"Over-Provisioned Lambda (Compute Optimizer)",
                        description=(
                            f"Function '{function_name}' ({current_config}MB) can be reduced "
                            f"to {recommended_memory}MB. AWS Compute Optimizer analysis."
                        ),
                        monthly_savings=monthly_savings,
                        confidence=ConfidenceLevel.HIGH,
                        action=f"Reduce memory from {current_config}MB to {recommended_memory}MB.",
                        explanation={
                            'detection': f"AWS Compute Optimizer analyzed invocation patterns and recommends reducing memory from {current_config}MB to {recommended_memory}MB.",
                            'threshold': 'Compute Optimizer flags Lambda functions as NotOptimized when memory utilization is consistently low.',
                            'pricing': f'Reducing memory saves ~${monthly_savings:.0f}/month. Lambda charges per GB-second of allocated memory.',
                            'why_waste': 'Over-provisioned memory increases per-invocation cost without improving performance.',
                            'risk': 'Reducing memory may increase duration or cause OOM errors. Test with realistic payloads before applying in production.',
                        },
                        metadata={
                            'function_name': function_name,
                            'function_version': function_version,
                            'function_arn': function_arn,
                            'current_memory_mb': current_config,
                            'recommended_memory_mb': recommended_memory,
                            'source': 'aws_compute_optimizer',
                            'detection_mode': data_provider.provider_type,
                        }
                    )
                    key = _lambda_version_rank(function_version)
                    kept = by_function.get(function_name)
                    if kept is None or key > kept[0]:
                        by_function[function_name] = (key, item)

                # Check for more pages
                next_token = response.get('nextToken')
                if not next_token:
                    break

            waste_items.extend(item for _, item in by_function.values())

        except ClientError as e:
            self._record_optimizer_failure(data_provider, 'GetLambdaFunctionRecommendations', e)
        except Exception as e:
            logger.warning(f"Error getting Lambda Compute Optimizer recommendations: {e}")
        
        return waste_items

    async def _get_rds_optimizer_recommendations(
        self,
        client,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Get RDS rightsizing recommendations from AWS Compute Optimizer.

        AWS Compute Optimizer for RDS (available since 2023) analyzes
        CloudWatch metrics to recommend instance class downsizing.
        """
        waste_items = []

        try:
            # RDS Compute Optimizer API — may not be available in all regions
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs['nextToken'] = next_token

                try:
                    response = client.get_rds_database_recommendations(**kwargs)
                except ClientError as e:
                    # CLO-375: this was logged at DEBUG, which hid that the
                    # monitoring template never granted the action, so
                    # oversized_rds_optimizer could not fire in production.
                    self._record_optimizer_failure(data_provider, 'GetRDSDatabaseRecommendations', e)
                    return waste_items
                except AttributeError as e:
                    # A botocore build too old to know the operation: our
                    # packaging, not the customer's role. Never a permission.
                    logger.warning(f"RDS Compute Optimizer API unavailable in this botocore build: {e}")
                    return waste_items

                if not isinstance(response, dict):
                    break

                # CLO-583: the real key is rdsDBRecommendations, not
                # rdsDatabaseRecommendations.
                for rec in response.get('rdsDBRecommendations', []):
                    # CLO-583: the real field is instanceFinding (there is a
                    # separate storageFinding); 'finding' does not exist.
                    finding = rec.get('instanceFinding')

                    # CLO-583: normalized defensively, same as the EC2 finding
                    # check (_normalize_enum_value docstring).
                    if _normalize_enum_value(finding) != _normalize_enum_value('Overprovisioned'):
                        continue

                    resource_arn = rec.get('resourceArn', '')
                    db_identifier = resource_arn.split(':')[-1] if ':' in resource_arn else resource_arn
                    current_config = rec.get('currentDBInstanceClass', 'unknown')

                    # CLO-583: the real key is instanceRecommendationOptions.
                    options = rec.get('instanceRecommendationOptions', [])
                    if not options:
                        continue

                    best_option = _best_recommendation_option(options)
                    recommended_class = best_option.get('dbInstanceClass', 'unknown')

                    savings_opportunity = best_option.get('savingsOpportunity', {})
                    savings_percentage = savings_opportunity.get('savingsOpportunityPercentage', 0)
                    estimated_savings = savings_opportunity.get('estimatedMonthlySavings', {})
                    monthly_savings = float(estimated_savings.get('value', 0))

                    if monthly_savings < MIN_SAVINGS_THRESHOLD:
                        continue

                    utilization = rec.get('utilizationMetrics', [])
                    cpu_util = None
                    memory_util = None
                    for metric in utilization:
                        # CLO-583: RDS's RDSDBUtilizationMetric.name enum is
                        # CPU/Memory (CPU stays upper case here, unlike EC2's
                        # Cpu/Memory); normalized to be safe.
                        metric_name = _normalize_enum_value(metric.get('name'))
                        if metric_name == _normalize_enum_value('CPU'):
                            cpu_util = metric.get('value')
                        elif metric_name == _normalize_enum_value('Memory'):
                            memory_util = metric.get('value')

                    util_parts = []
                    if cpu_util is not None:
                        util_parts.append(f"CPU: {cpu_util:.1f}%")
                    if memory_util is not None:
                        util_parts.append(f"Memory: {memory_util:.1f}%")
                    util_str = ", ".join(util_parts) if util_parts else "See AWS Console"

                    waste_items.append(WasteItem(
                        id=generate_deterministic_id(db_identifier, 'oversized_rds_optimizer', data_provider.region),
                        resource_id=db_identifier,
                        resource_type=ResourceType.RDS_INSTANCE,
                        waste_type=WasteType.OVERSIZED_RDS_OPTIMIZER,
                        title="Oversized RDS Instance (Compute Optimizer)",
                        description=(
                            f"RDS instance '{db_identifier}' ({current_config}) can be downsized to {recommended_class}. "
                            f"Utilization: {util_str}. AWS Compute Optimizer analysis."
                        ),
                        monthly_savings=monthly_savings,
                        confidence=ConfidenceLevel.HIGH,
                        action=f"Modify instance class from {current_config} to {recommended_class}.",
                        explanation={
                            'detection': (
                                f"AWS Compute Optimizer analyzed 14 days of RDS utilization and recommends "
                                f"downsizing from {current_config} to {recommended_class}."
                            ),
                            'threshold': 'Compute Optimizer flags RDS instances as Overprovisioned when CPU/memory consistently underutilize the current class.',
                            'pricing': f'Downsizing saves ~${monthly_savings:.0f}/month ({savings_percentage:.0f}% reduction). Utilization: {util_str}.',
                            'why_waste': 'An oversized RDS instance pays for CPU and memory capacity it does not use.',
                            'risk': (
                                'Instance class modification triggers a brief outage (apply during maintenance window). '
                                'Multi-AZ deployments will failover. Test with production-like queries first.'
                            ),
                        },
                        metadata={
                            'db_identifier': db_identifier,
                            'current_class': current_config,
                            'recommended_class': recommended_class,
                            'savings_percentage': savings_percentage,
                            'cpu_utilization': cpu_util,
                            'memory_utilization': memory_util,
                            'source': 'aws_compute_optimizer',
                            'detection_mode': data_provider.provider_type,
                        }
                    ))

                next_token = response.get('nextToken')
                if not next_token or not isinstance(next_token, str):
                    break

        except Exception as e:
            logger.warning(f"Error getting RDS Compute Optimizer recommendations: {e}")

        return waste_items
