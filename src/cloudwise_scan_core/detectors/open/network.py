"""Open-core part of ``detectors/network.py`` (FSL-1.1-ALv2).

The service entrypoints in ``FREE_TIER_DETECTORS`` and every method they call.
``NetworkDetectorsMixin`` in ``detectors/network.py`` subclasses this mixin and adds the
closed detectors. Moved verbatim from ``detectors/network.py`` (CLO-562).
"""

import logging
import re
import uuid
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from cloudwise_scan_core.models import WasteItem, WasteDetectionSettings, WasteType, ResourceType, ConfidenceLevel, get_eip_monthly_cost, NAT_GATEWAY_MONTHLY_BASE, ALB_MONTHLY_BASE, NLB_MONTHLY_BASE, CLB_MONTHLY_BASE, ALB_LCU_HOURLY
from cloudwise_scan_core.cpu_sizing import is_as_old_as_window
if TYPE_CHECKING:
    from cloudwise_scan_core.data_providers.base import WasteDataProvider

logger = logging.getLogger(__name__)

# CLO-528: unused_vpc_endpoint's BytesProcessed window and minimum age
# (ledger aging_d: 14).
VPC_ENDPOINT_WINDOW_DAYS = 14

# CLO-589: idle_nat_gateway's BytesOutToDestination window and minimum age
# (ledger aging_d: 7).
NAT_IDLE_WINDOW_DAYS = 7


# ELB DNS name shapes, any region: classic ELB and ALB resolve under
# <name>.<region>.elb.amazonaws.com; NLB resolves under
# <name>.elb.<region>.amazonaws.com.
_ELB_DNS_SUFFIX_RE = re.compile(r'\.(?:[a-z0-9-]+\.elb|elb\.[a-z0-9-]+)\.amazonaws\.com$')


# CLO-535 item 2: the region label of an ELB-shaped name, from either form
# above (the dualstack./ipv6./internal- prefixes sit before <name> and don't
# move it). Only a label shaped like a region counts.
_ELB_DNS_REGION_RE = re.compile(r'\.(?:([a-z0-9-]+)\.elb|elb\.([a-z0-9-]+))\.amazonaws\.com$')


_ELB_DNS_PREFIX_RE = re.compile(r'^(?:dualstack|ipv6)\.')


_AWS_REGION_RE = re.compile(r'^[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d+$')


def _elb_dns_region(target: str) -> Optional[str]:
    """The AWS region an ELB DNS name lives in, or None when the name has no
    region-shaped label (CLO-535 item 2). Needs no API call."""
    m = _ELB_DNS_REGION_RE.search(target)
    if not m:
        return None
    region = m.group(1) or m.group(2)
    return region if _AWS_REGION_RE.match(region) else None



class OpenNetworkDetectorsMixin:
    """Open detectors from ``NetworkDetectorsMixin``."""

    async def _detect_network_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect network-related waste using DataProvider.
        
        Detectors:
        1. UNATTACHED_EIP - Elastic IPs not attached to any resource
        2. EIP_ON_STOPPED_INSTANCE - Elastic IPs on stopped EC2 instances
        3. MULTIPLE_EIPS_PER_INSTANCE - Multiple EIPs on single instance (anti-pattern)
        4. IDLE_NAT_GATEWAY - NAT Gateways with no traffic
        5. IDLE_LOAD_BALANCER - Load Balancers with no healthy targets
        """
        waste_items = []

        try:
            # Get Elastic IPs from data provider
            eips = await data_provider.get_elastic_ips()

            # CLO-359: region-scaled — EIP_MONTHLY_COST is a flat us-east-1
            # rate otherwise, understating the saving everywhere else.
            eip_monthly_cost = get_eip_monthly_cost(data_provider.region)

            # Track EIPs per instance for duplicate detection
            instance_eip_map: Dict[str, List[Any]] = {}

            for eip in eips:
                # Check 1: Unattached EIP
                if not eip.instance_id and not eip.network_interface_id:
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=eip.allocation_id,
                        resource_type=ResourceType.ELASTIC_IP,
                        waste_type=WasteType.UNATTACHED_EIP,
                        title=f"Unattached Elastic IP",
                        description=f"Elastic IP {eip.public_ip} is not attached and costs ${eip_monthly_cost}/month.",
                        monthly_savings=eip_monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Release this Elastic IP if no longer needed.",
                        action_command=f"aws ec2 release-address --allocation-id {eip.allocation_id}",
                        explanation={
                            'detection': f'Elastic IP {eip.public_ip} is not associated with any instance or network interface',
                            'threshold': 'EIP not attached to any resource',
                            'pricing': f'Unattached EIP: ${eip_monthly_cost:.2f}/month (AWS charges for EIPs not associated with a running instance)',
                            'why_waste': 'AWS charges for Elastic IPs that are allocated but not associated with a running instance. This EIP was likely left behind after an instance was terminated.',
                            'risk': 'Releasing an EIP is permanent — the IP address cannot be recovered. If DNS records or allowlists reference this IP, update them first.',
                        },
                        metadata={
                            'public_ip': eip.public_ip,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
                elif eip.instance_id:
                    # Track for multi-EIP detection
                    if eip.instance_id not in instance_eip_map:
                        instance_eip_map[eip.instance_id] = []
                    instance_eip_map[eip.instance_id].append(eip)
            
            # Get instances to check for stopped instances and multi-EIP
            instances = await data_provider.get_ec2_instances()
            instance_map = {i.instance_id: i for i in instances}
            
            for instance_id, eip_list in instance_eip_map.items():
                instance = instance_map.get(instance_id)
                instance_name = instance.name if instance else instance_id
                instance_state = instance.state if instance else 'unknown'
                
                # Check 2: EIP on stopped instance
                if instance_state == 'stopped':
                    for eip in eip_list:
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=eip.allocation_id,
                            resource_type=ResourceType.ELASTIC_IP,
                            waste_type=WasteType.EIP_ON_STOPPED_INSTANCE,
                            title=f"Elastic IP on Stopped Instance",
                            description=(
                                f"Elastic IP {eip.public_ip} is attached to stopped "
                                f"instance '{instance_name}' ({instance_id}). "
                                f"You're paying ${eip_monthly_cost}/month for an unused IP."
                            ),
                            monthly_savings=eip_monthly_cost,
                            confidence=ConfidenceLevel.HIGH,
                            action="Release the EIP or start the instance if needed.",
                            action_command=f"aws ec2 release-address --allocation-id {eip.allocation_id}",
                            explanation={
                                'detection': f'EIP {eip.public_ip} is associated with instance {instance_id} which is in stopped state',
                                'threshold': 'Any EIP attached to a stopped EC2 instance',
                                'pricing': f'EIP on stopped instance: ${eip_monthly_cost}/month',
                                'why_waste': f'AWS charges for Elastic IPs associated with stopped instances. The IP is reserved but not serving traffic.',
                                'risk': 'Releasing the EIP makes the IP address available for others to claim. If you need a stable public IP, start the instance or move the EIP to an active resource.',
                            },
                            metadata={
                                'public_ip': eip.public_ip,
                                'instance_id': instance_id,
                                'instance_name': instance_name,
                                'instance_state': instance_state,
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
                
                # Check 3: Multiple EIPs per instance
                if len(eip_list) > 1:
                    eip_ips = ', '.join(e.public_ip for e in eip_list)
                    extra_eips = len(eip_list) - 1
                    
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=instance_id,
                        resource_type=ResourceType.EC2_INSTANCE,
                        waste_type=WasteType.MULTIPLE_EIPS_PER_INSTANCE,
                        title=f"Multiple Elastic IPs on Single Instance",
                        description=(
                            f"Instance '{instance_name}' has {len(eip_list)} Elastic IPs attached: {eip_ips}. "
                            f"This is typically an anti-pattern. Extra IPs cost ${eip_monthly_cost}/month each. "
                            f"Total extra cost: ${eip_monthly_cost * extra_eips:.2f}/month."
                        ),
                        monthly_savings=eip_monthly_cost * extra_eips,
                        confidence=ConfidenceLevel.HIGH,
                        action="Review and remove unnecessary EIPs.",
                        explanation={
                            'detection': f'{len(eip_list)} Elastic IPs attached to instance {instance_id}: {eip_ips}',
                            'threshold': '> 1 EIP per instance',
                            'pricing': f'{extra_eips} extra EIP(s) × ${eip_monthly_cost}/month = ${eip_monthly_cost * extra_eips:.2f}/month',
                            'why_waste': f'Most instances need at most one public IP. Multiple EIPs typically indicate leftover configurations from network changes.',
                            'risk': 'Verify each EIP\'s purpose (e.g., multi-homed networking, secondary ENIs). Release only the ones confirmed unnecessary.',
                        },
                        metadata={
                            'instance_id': instance_id,
                            'instance_name': instance_name,
                            'eip_count': len(eip_list),
                            'eips': [e.public_ip for e in eip_list],
                            'detection_mode': data_provider.provider_type,
                        }
                    ))
            
            # Check 4: Idle NAT Gateways
            nat_gateways = await data_provider.get_nat_gateways()
            
            for nat in nat_gateways:
                if nat.state != 'available':
                    continue
                # CLO-589 / CLO-233: "no traffic in 7 days" needs a gateway
                # that existed for all 7 (unknown age counts as old).
                if not is_as_old_as_window(nat.create_time, NAT_IDLE_WINDOW_DAYS):
                    continue
                
                # Check for idle NAT gateway (requires CloudWatch metrics)
                if settings.cloudwatch_enabled and data_provider.supports_cloudwatch:
                    metrics_map = await data_provider.get_nat_gateway_metrics(
                        nat_gateway_ids=[nat.nat_gateway_id],
                        days=NAT_IDLE_WINDOW_DAYS,
                    )
                    
                    metrics = metrics_map.get(nat.nat_gateway_id)
                    if metrics and metrics.is_idle:
                        nat_name = nat.tags.get('Name', '') or nat.nat_gateway_id
                        waste_items.append(WasteItem(
                            id=str(uuid.uuid4()),
                            resource_id=nat.nat_gateway_id,
                            resource_type=ResourceType.NAT_GATEWAY,
                            waste_type=WasteType.IDLE_NAT_GATEWAY,
                            title=f"Idle NAT Gateway",
                            description=f"NAT Gateway '{nat_name}' has had no traffic in {metrics.period_days} days.",
                            monthly_savings=NAT_GATEWAY_MONTHLY_BASE,
                            confidence=ConfidenceLevel.HIGH,
                            action="Delete this NAT Gateway if no longer needed.",
                            action_command=f"aws ec2 delete-nat-gateway --nat-gateway-id {nat.nat_gateway_id}",
                            explanation={
                                'detection': f'CloudWatch BytesOutToDestination sum = 0 bytes over {metrics.period_days} days',  # CLO-511: the only metric read
                                'threshold': f'Zero traffic over {metrics.period_days} days',
                                'pricing': f'NAT Gateway base: ${NAT_GATEWAY_MONTHLY_BASE:.2f}/month + data processing charges',
                                'why_waste': f'This NAT Gateway has processed zero traffic for {metrics.period_days} days. It may have been created for a VPC that no longer has private subnets needing internet access.',
                                'risk': 'Deleting a NAT Gateway will immediately cut internet access for private subnet resources using it. Verify no active workloads route through this gateway.',
                            },
                            metadata={
                                'nat_name': nat_name,
                                'vpc_id': nat.vpc_id,
                                'detection_mode': data_provider.provider_type,
                            }
                        ))
            
            # Check 5: Idle Load Balancers (improved — uses CloudWatch + correct LB type pricing)
            load_balancers = await data_provider.get_load_balancers()

            # Get metrics for all LBs (shared with low_traffic and high_lcu detectors)
            all_lb_arns = [lb.load_balancer_arn for lb in load_balancers if lb.type != 'classic']
            all_metrics = {}
            if settings.cloudwatch_enabled and data_provider.supports_cloudwatch and all_lb_arns:
                all_metrics = await data_provider.get_load_balancer_metrics(
                    load_balancer_arns=all_lb_arns,
                    days=14,
                )

            for lb in load_balancers:
                metrics = all_metrics.get(lb.load_balancer_arn)

                # Flag if: no healthy targets OR zero requests in 14 days.
                # CLO-532 item 2: "no healthy targets" needs the health read
                # to have happened; an unread count of 0 is MISSING.
                is_idle = lb.target_health_known and lb.healthy_target_count == 0
                if not lb.target_health_known and lb.healthy_target_count == 0:
                    note = getattr(data_provider, '_note_idle_verdict_missing', None)
                    if callable(note):
                        note(
                            'elb-target-health', lb.load_balancer_name,
                            'target health not read', verdict='no-healthy-targets',
                            evidence='target health',
                        )
                # CLO-516: an NLB's traffic is NewFlowCount (it publishes no
                # RequestCount, so request_count_total is always 0 for it).
                if lb.type == 'network':
                    has_zero_traffic = bool(
                        metrics and metrics.new_flow_count_total is not None
                        and metrics.new_flow_count_total == 0
                    )
                elif lb.type == 'gateway':
                    # CLO-532 item 2: a Gateway LB publishes no RequestCount;
                    # the provider's empty AWS/ApplicationELB read (is_idle)
                    # is not a measurement. No traffic verdict: MISSING.
                    has_zero_traffic = False
                    note = getattr(data_provider, '_note_idle_verdict_missing', None)
                    if metrics and callable(note):
                        note(
                            'elbv2', lb.load_balancer_name,
                            'Gateway LB: no RequestCount metric, traffic check not applied',
                            evidence='load balancer traffic metrics',
                        )
                else:
                    has_zero_traffic = bool(
                        metrics and metrics.is_idle and metrics.request_count_total == 0
                    )

                # For ALBs/NLBs with healthy targets + zero traffic, let low_traffic_alb
                # handle them (Check 6) to avoid duplicate findings with different waste types.
                # idle_load_balancer only catches zero-traffic ALBs/NLBs when they also have
                # no healthy targets. Classic LBs are always handled here since low_traffic_alb
                # excludes them.
                # CLO-516: an NLB with healthy targets and zero new flows is
                # skipped too. low_traffic_alb no longer judges NLBs, and an NLB
                # traffic verdict would be new logic behind a Fix This delete at
                # L1; it stays unflagged (noted by low_traffic_alb).
                if has_zero_traffic and not is_idle and lb.type in ('application', 'network'):
                    continue  # Will be caught by _detect_low_traffic_alb (ALBs only)

                if is_idle or has_zero_traffic:
                    base_cost = (
                        CLB_MONTHLY_BASE if lb.type == 'classic'
                        else ALB_MONTHLY_BASE if lb.type == 'application'
                        else NLB_MONTHLY_BASE
                    )

                    if has_zero_traffic and not is_idle:
                        description = (
                            f"Load Balancer '{lb.load_balancer_name}' has "
                            f"{lb.healthy_target_count} healthy target(s) but zero "
                            f"requests in {metrics.period_days} days."
                        )
                    else:
                        description = (
                            f"Load Balancer '{lb.load_balancer_name}' has no healthy targets."
                        )

                    # Classic LBs use different CLI and don't have ARNs
                    if lb.type == 'classic':
                        action_cmd = f"aws elb delete-load-balancer --load-balancer-name {lb.load_balancer_name}"
                    else:
                        action_cmd = f"aws elbv2 delete-load-balancer --load-balancer-arn {lb.load_balancer_arn}"

                    lb_type_label = {'classic': 'CLB', 'application': 'ALB', 'network': 'NLB'}.get(lb.type, lb.type.upper())
                    traffic_note = ''
                    if metrics and lb.type == 'network':
                        if metrics.new_flow_count_total is not None:
                            traffic_note = f' and {metrics.new_flow_count_total} new flows in {metrics.period_days} days'
                    elif metrics:
                        traffic_note = f' and {metrics.request_count_total} requests in {metrics.period_days} days'
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=lb.load_balancer_name,
                        resource_type=ResourceType.LOAD_BALANCER,
                        waste_type=WasteType.IDLE_LOAD_BALANCER,
                        title="Idle Load Balancer",
                        description=description,
                        monthly_savings=base_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Register healthy targets or delete this load balancer.",
                        action_command=action_cmd,
                        explanation={
                            'detection': f'{lb_type_label} has {lb.healthy_target_count} healthy targets' + traffic_note,
                            'threshold': 'No healthy targets or zero requests over 14 days',
                            'pricing': f'{lb_type_label} base cost: ${base_cost:.2f}/month (plus LCU/NLCU charges if applicable)',
                            'why_waste': f'This load balancer is not serving traffic. It may have been created for a service that was decommissioned or moved.',
                            'risk': 'Verify no DNS records (Route 53, external DNS) point to this load balancer before deleting. Check for pending deployments.',
                        },
                        metadata={
                            'lb_name': lb.load_balancer_name,
                            'lb_type': lb.type,
                            'healthy_targets': lb.healthy_target_count,
                            'request_count': metrics.request_count_total if metrics else 'N/A',
                            'detection_mode': data_provider.provider_type,
                        }
                    ))

            # Check 6: Low-Traffic ALBs/NLBs
            waste_items.extend(
                await self._detect_low_traffic_alb(
                    data_provider, load_balancers, all_metrics, settings
                )
            )

            # Check 7: High LCU Cost ALBs
            waste_items.extend(
                await self._detect_high_lcu_cost_alb(
                    data_provider, load_balancers, all_metrics, settings
                )
            )

            # Check 8: Classic Load Balancer Migration
            waste_items.extend(
                self._detect_classic_lb_migration(load_balancers, data_provider)
            )

            logger.info(f"Network detector found {len(waste_items)} waste items")
            return waste_items
            
        except Exception as e:
            logger.error(f"Error in network waste detection: {e}")
            raise
    async def _detect_low_traffic_alb(
        self,
        data_provider: "WasteDataProvider",
        load_balancers,
        metrics_map: dict,
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect ALBs/NLBs with healthy targets but near-zero traffic.

        Criteria:
        - Has at least 1 healthy target (excluded from idle_load_balancer)
        - RequestCount < 100 total over 14 days (< ~7 requests/day)
        - LB type is 'application' (CLB handled separately)

        CLO-516: NLBs are not judged. They publish no RequestCount, so this
        check read 0 requests for every NLB and flagged each one with a
        healthy target (a Fix This delete at L1). Their traffic metric
        (NewFlowCount) is a different unit with no validated threshold, so
        each NLB with healthy targets is noted in ``data_warnings`` instead.
        """
        waste_items = []

        note = getattr(data_provider, '_note_idle_verdict_missing', None)
        for lb in load_balancers:
            if lb.type == 'network' and lb.healthy_target_count > 0 and callable(note):
                note(
                    'elbv2', lb.load_balancer_name,
                    'NLB: no RequestCount metric, low-traffic check not applied',
                    verdict='low-traffic', evidence='request counts',
                )

        candidates = [
            lb for lb in load_balancers
            if lb.healthy_target_count > 0
            and lb.type == 'application'
        ]

        if not candidates:
            return waste_items

        for lb in candidates:
            metrics = metrics_map.get(lb.load_balancer_arn)
            if not metrics:
                continue

            # Low traffic threshold: < 100 requests in 14 days
            if metrics.request_count_total < 100:
                base_cost = ALB_MONTHLY_BASE if lb.type == 'application' else NLB_MONTHLY_BASE

                waste_items.append(WasteItem(
                    id=str(uuid.uuid4()),
                    resource_id=lb.load_balancer_name,
                    resource_type=ResourceType.LOAD_BALANCER,
                    waste_type=WasteType.LOW_TRAFFIC_ALB,
                    title="Low-Traffic Load Balancer",
                    description=(
                        f"Load Balancer '{lb.load_balancer_name}' ({lb.type}) has "
                        f"{lb.healthy_target_count} healthy target(s) but only "
                        f"{metrics.request_count_total} requests in {metrics.period_days} days. "
                        f"Base charge is ${base_cost:.2f}/month regardless of traffic."
                    ),
                    monthly_savings=base_cost,
                    confidence=ConfidenceLevel.MEDIUM,
                    action=(
                        "Review if this load balancer is still needed. If the service "
                        "behind it is inactive, deregister targets and delete the ALB."
                    ),
                    action_command=f"aws elbv2 delete-load-balancer --load-balancer-arn {lb.load_balancer_arn}",
                    explanation={
                        'detection': f'{lb.type.upper()} has {lb.healthy_target_count} healthy target(s) but only {metrics.request_count_total} requests in {metrics.period_days} days',
                        'threshold': '< 100 total requests over 14 days',
                        'pricing': f'Base cost: ${base_cost:.2f}/month regardless of traffic',
                        'why_waste': f'This load balancer has healthy targets registered but is receiving almost no traffic, suggesting the service behind it is inactive.',
                        'risk': 'Check if the service is in maintenance or pre-launch. Verify no DNS records point to this load balancer.',
                    },
                    metadata={
                        'lb_name': lb.load_balancer_name,
                        'lb_type': lb.type,
                        'request_count_14d': metrics.request_count_total,
                        'healthy_targets': lb.healthy_target_count,
                        'detection_mode': data_provider.provider_type,
                    }
                ))

        return waste_items
    async def _detect_high_lcu_cost_alb(
        self,
        data_provider: "WasteDataProvider",
        load_balancers,
        metrics_map: dict,
        settings: WasteDetectionSettings,
    ) -> List[WasteItem]:
        """
        Detect ALBs where LCU charges significantly exceed the base cost.

        Criteria:
        - LB type is 'application' (LCU is ALB-specific; NLB uses NLCU)
        - Average LCUs consumed per hour over 7 days -> estimated monthly LCU cost
        - Estimated LCU cost > 2x ALB base cost ($32.40)

        `consumed_lcus_avg` is LCUs per *hour* (total LCU-hours ÷ window hours),
        which is the basis ALB_LCU_HOURLY multiplies. See CLO-228 — this used to
        receive CloudWatch's `Average` statistic, which is not an hourly rate.
        """
        waste_items = []

        albs = [lb for lb in load_balancers if lb.type == 'application']
        if not albs:
            return waste_items

        for lb in albs:
            metrics = metrics_map.get(lb.load_balancer_arn)
            if not metrics or not metrics.consumed_lcus_avg:
                continue

            # Estimate monthly LCU cost
            monthly_lcu_cost = metrics.consumed_lcus_avg * ALB_LCU_HOURLY * 730

            # Only flag if LCU cost > 2x base cost
            if monthly_lcu_cost > ALB_MONTHLY_BASE * 2:
                total_monthly = ALB_MONTHLY_BASE + monthly_lcu_cost

                waste_items.append(WasteItem(
                    id=str(uuid.uuid4()),
                    resource_id=lb.load_balancer_name,
                    resource_type=ResourceType.LOAD_BALANCER,
                    waste_type=WasteType.HIGH_LCU_COST_ALB,
                    title="ALB with High LCU Charges",
                    description=(
                        f"ALB '{lb.load_balancer_name}' has estimated LCU cost of "
                        f"${monthly_lcu_cost:.2f}/month ({metrics.consumed_lcus_avg:.3f} avg LCUs/hour), "
                        f"which is {monthly_lcu_cost / ALB_MONTHLY_BASE:.1f}\u00d7 the base fee "
                        f"(${ALB_MONTHLY_BASE}/month). Total estimated: ${total_monthly:.2f}/month. "
                        f"Consider NLB migration or architecture review."
                    ),
                    monthly_savings=monthly_lcu_cost * 0.3,  # Conservative 30% potential savings
                    confidence=ConfidenceLevel.LOW,
                    action=(
                        "Review LCU consumption dimensions (new connections, active connections, "
                        "processed bytes, rule evaluations). Consider NLB if the workload is "
                        "TCP/TLS-only. Consolidate target groups to reduce rule evaluations."
                    ),
                    explanation={
                        'detection': f'Average ConsumedLCUs: {metrics.consumed_lcus_avg:.3f} LCUs/hour (total LCU-hours ÷ window hours). Estimated monthly LCU cost: ${monthly_lcu_cost:.2f} ({monthly_lcu_cost / ALB_MONTHLY_BASE:.1f}× base fee)',
                        'threshold': f'LCU cost > 2× ALB base cost (${ALB_MONTHLY_BASE}/month)',
                        'pricing': f'Base: ${ALB_MONTHLY_BASE}/month + LCU: ${monthly_lcu_cost:.2f}/month = ${total_monthly:.2f}/month total',
                        'why_waste': f'High LCU charges often indicate inefficient routing rules, many active connections, or high data throughput. Architectural optimization can reduce LCU consumption.',
                        'risk': 'Analyze which LCU dimension is dominant before making changes. Consolidating listener rules and target groups reduces rule-evaluation LCUs.',
                    },
                    metadata={
                        'lb_name': lb.load_balancer_name,
                        'lb_type': lb.type,
                        'avg_lcus_per_hour': round(metrics.consumed_lcus_avg, 4),
                        'estimated_lcu_cost_monthly': round(monthly_lcu_cost, 2),
                        'estimated_total_monthly': round(total_monthly, 2),
                        'detection_mode': data_provider.provider_type,
                    }
                ))

        return waste_items
    def _detect_classic_lb_migration(
        self,
        load_balancers,
        data_provider: "WasteDataProvider",
    ) -> List[WasteItem]:
        """
        Detect Classic Load Balancers that should migrate to ALB or NLB.

        Criteria:
        - LB type is 'classic'

        Purely metadata-based — no CloudWatch needed.
        """
        waste_items = []

        for lb in load_balancers:
            if lb.type != 'classic':
                continue

            # Calculate base savings from CLB -> ALB migration
            base_savings = max(0.01, CLB_MONTHLY_BASE - ALB_MONTHLY_BASE)

            waste_items.append(WasteItem(
                id=str(uuid.uuid4()),
                resource_id=lb.load_balancer_name,
                resource_type=ResourceType.LOAD_BALANCER,
                waste_type=WasteType.CLASSIC_LB_MIGRATION,
                title="Classic Load Balancer \u2014 Migrate to ALB/NLB",
                description=(
                    f"Classic Load Balancer '{lb.load_balancer_name}' is previous-generation. "
                    f"AWS recommends migrating to ALB (for HTTP/HTTPS) or NLB (for TCP/TLS). "
                    f"Base savings: ${base_savings:.2f}/month. Consolidating multiple CLBs "
                    f"into a single ALB with path-based routing can save significantly more."
                ),
                monthly_savings=base_savings,
                confidence=ConfidenceLevel.LOW,
                action=(
                    "Use the AWS CLB Migration Wizard to migrate to ALB or NLB. "
                    "For HTTP/HTTPS workloads, choose ALB. For TCP/TLS-only, choose NLB. "
                    "AWS CLI: aws elbv2 create-load-balancer --name <new-name> --type application"
                ),
                action_command=f"aws elb describe-load-balancers --load-balancer-names {lb.load_balancer_name}",
                explanation={
                    'detection': f'Load balancer type is Classic (previous generation)',
                    'threshold': 'Any Classic Load Balancer',
                    'pricing': f'CLB: ${CLB_MONTHLY_BASE:.2f}/month. ALB (replacement): ${ALB_MONTHLY_BASE:.2f}/month. Base savings: ${base_savings:.2f}/month. Path-based routing consolidation can save more.',
                    'why_waste': f'Classic Load Balancers are previous-generation. ALBs/NLBs offer better features (path-based routing, WebSockets, HTTP/2) and potentially lower costs.',
                    'risk': 'Use the AWS CLB Migration Wizard for automated migration. Test thoroughly in staging. Some CLB-specific features (TCP passthrough) require NLB instead of ALB.',
                },
                metadata={
                    'lb_name': lb.load_balancer_name,
                    'lb_type': 'classic',
                    'scheme': lb.scheme,
                    'detection_mode': data_provider.provider_type,
                }
            ))

        return waste_items
    async def _detect_vpc_endpoint_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """
        Detect unused VPC Interface Endpoints.

        Cost: $7.30/AZ/month per Interface Endpoint + $0.01/GB data processed.
        Gateway Endpoints (S3, DynamoDB) are free and skipped.

        Detection:
        - Interface Endpoints in "available" state with zero data processed (CloudWatch)
        - Endpoints attached to non-existent or empty subnets
        """
        waste_items = []

        try:
            endpoints = await data_provider.get_vpc_endpoints()

            candidates = []
            for ep in endpoints:
                # Gateway endpoints (S3, DynamoDB) are free — skip
                if ep.endpoint_type == 'Gateway':
                    continue

                if ep.state != 'available':
                    continue

                az_count = len(ep.subnet_ids) if ep.subnet_ids else 1
                monthly_cost = az_count * 7.30  # $0.01/hr × 730 hrs ≈ $7.30/AZ/month

                if monthly_cost < settings.min_waste_threshold_usd:
                    continue
                candidates.append((ep, az_count, monthly_cost))

            # CLO-528: BytesProcessed through the provider, under the full
            # dimension set PrivateLink publishes, batched. None = the
            # provider has no PrivateLink metrics (Air-Gapped export): use
            # the zero-ENI heuristic. Otherwise an endpoint absent from the
            # dict was not measured: MISSING (the provider notes it), never
            # idle. Endpoints younger than the window are not judged and not
            # queried (CLO-233's minimum-age rule). CLO-533: an idle endpoint
            # publishes no datapoints, so the provider reads a Complete,
            # empty series as 0 bytes when the series identity is confirmed
            # (see get_vpc_endpoint_bytes_processed); plan-only until L2.
            bytes_processed = None
            if settings.cloudwatch_enabled and data_provider.supports_cloudwatch:
                old_enough = [
                    ep for ep, _, _ in candidates
                    if is_as_old_as_window(ep.creation_time, VPC_ENDPOINT_WINDOW_DAYS)
                ]
                bytes_processed = await data_provider.get_vpc_endpoint_bytes_processed(
                    old_enough, days=VPC_ENDPOINT_WINDOW_DAYS,
                )

            for ep, az_count, monthly_cost in candidates:
                if bytes_processed is not None:
                    if not is_as_old_as_window(ep.creation_time, VPC_ENDPOINT_WINDOW_DAYS):
                        continue
                    total_bytes = bytes_processed.get(ep.endpoint_id)
                    if total_bytes is None:
                        continue
                    is_idle = total_bytes == 0
                else:
                    # Structural heuristic: an interface endpoint with zero
                    # network interfaces is unused. An unknown ENI list
                    # (None) is MISSING, not zero interfaces.
                    if ep.network_interface_ids is None:
                        continue
                    is_idle = len(ep.network_interface_ids) == 0

                if is_idle:
                    service_short = ep.service_name.split('.')[-1] if ep.service_name else 'unknown'
                    waste_items.append(WasteItem(
                        id=str(uuid.uuid4()),
                        resource_id=ep.endpoint_id,
                        resource_type=ResourceType.VPC_ENDPOINT,
                        waste_type=WasteType.UNUSED_VPC_ENDPOINT,
                        title="Unused VPC Interface Endpoint",
                        description=(
                            f"VPC Endpoint '{ep.endpoint_id}' ({service_short}) "
                            f"has processed zero data in 14 days across {az_count} AZ(s). "
                            f"Costs ${monthly_cost:.2f}/month."
                        ),
                        monthly_savings=monthly_cost,
                        confidence=ConfidenceLevel.HIGH,
                        action="Delete this VPC endpoint if the service is no longer accessed privately.",
                        action_command=f"aws ec2 delete-vpc-endpoints --vpc-endpoint-ids {ep.endpoint_id}",
                        explanation={
                            'detection': (
                                f'VPC Interface Endpoint for {ep.service_name} has 0 bytes processed over 14 days'
                                + (
                                    ' (complete CloudWatch read; an endpoint with no traffic publishes no '
                                    'BytesProcessed datapoints)'
                                    if bytes_processed is not None else
                                    ' (no network interfaces attached)'
                                )
                            ),
                            'threshold': 'Zero data processed for 14 days',
                            'pricing': f'Interface Endpoint: ${7.30}/AZ/month × {az_count} AZ(s) = ${monthly_cost:.2f}/month',
                            'why_waste': (
                                'VPC Interface Endpoints incur a fixed hourly charge per AZ '
                                'regardless of data flow. This endpoint has had no traffic, '
                                'indicating the service is no longer accessed via PrivateLink.'
                            ),
                            'risk': (
                                'Deleting a VPC endpoint immediately removes private access to the service. '
                                'Traffic will fall back to public endpoints (or fail if no public access). '
                                'Verify no services in the VPC rely on this PrivateLink connection.'
                            ),
                        },
                        metadata={
                            'endpoint_id': ep.endpoint_id,
                            'service_name': ep.service_name,
                            'vpc_id': ep.vpc_id,
                            'az_count': az_count,
                            'detection_mode': data_provider.provider_type,
                        }
                    ))

            return waste_items

        except Exception as e:
            logger.debug(f"VPC Endpoint detection error: {e}")
            return waste_items
    async def _detect_orphaned_dns_waste(
        self,
        data_provider: "WasteDataProvider",
        settings: WasteDetectionSettings
    ) -> List[WasteItem]:
        """
        Detect orphaned DNS records pointing to non-existent resources.

        Checks Route 53 A/CNAME records against known EC2 Elastic IPs,
        Load Balancer DNS names, and CloudFront distributions.

        Cost: $0.50/zone/month (zone cost) + dangling records are a security risk
        (subdomain takeover).
        """
        waste_items = []

        # Orphaned DNS detection requires cross-referencing resources
        if data_provider.provider_type == 'offline':
            logger.debug("Orphaned DNS detection not yet supported in offline mode")
            return waste_items

        try:
            if not hasattr(data_provider, '_get_client'):
                return waste_items

            route53 = data_provider._get_client('route53')

            # Build set of active resource targets
            active_ips = set()
            active_dns_names = set()

            # CLO-535 item 1: an A record is judged only against the WHOLE
            # Elastic IP and EC2 public-IP lists. A failed or incomplete read
            # (elastic_ips_complete / ec2_instances_complete False, or a
            # provider without the flags) withholds the A-record verdict
            # instead of reading every unseen IP as released.
            eip_list_complete = False
            ec2_list_complete = False
            withheld_a_records = 0
            withheld_cross_region_cnames = 0
            scan_region = getattr(data_provider, 'region', None)

            # Collect Elastic IP addresses
            try:
                eips = await data_provider.get_elastic_ips()
                for eip in eips:
                    if eip.public_ip:
                        active_ips.add(eip.public_ip)
                eip_list_complete = bool(getattr(data_provider, 'elastic_ips_complete', False))
            except Exception as e:
                if hasattr(data_provider, '_warn_swallowed'):
                    data_provider._warn_swallowed(
                        "Elastic IPs for orphaned-DNS cross-check", "ec2:DescribeAddresses", e,
                    )
                else:
                    logger.warning(
                        "orphaned_dns: Elastic IP lookup failed (%s), continuing scan",
                        e.__class__.__name__,
                    )

            # Collect EC2 public IPs
            try:
                instances = await data_provider.get_ec2_instances()
                for inst in instances:
                    if inst.public_ip:
                        active_ips.add(inst.public_ip)
                ec2_list_complete = bool(getattr(data_provider, 'ec2_instances_complete', False))
            except Exception as e:
                if hasattr(data_provider, '_warn_swallowed'):
                    data_provider._warn_swallowed(
                        "EC2 instances for orphaned-DNS cross-check", "ec2:DescribeInstances", e,
                    )
                else:
                    logger.warning(
                        "orphaned_dns: EC2 instance lookup failed (%s), continuing scan",
                        e.__class__.__name__,
                    )

            # Collect Load Balancer DNS names. CLO-532 item 2: an ELB-shaped
            # CNAME is judged only against the WHOLE load-balancer list; a
            # failed or capped read (load_balancers_complete False) withholds
            # those verdicts instead of reading every unseen LB as deleted.
            lb_list_complete = False
            lb_count = 0
            withheld_elb_cnames = 0
            try:
                lbs = await data_provider.get_load_balancers()
                lb_count = len(lbs)
                for lb in lbs:
                    if lb.dns_name:
                        active_dns_names.add(lb.dns_name.lower().rstrip('.'))
                lb_list_complete = bool(getattr(data_provider, 'load_balancers_complete', False))
            except Exception as e:
                if hasattr(data_provider, '_warn_swallowed'):
                    data_provider._warn_swallowed(
                        "Load balancers for orphaned-DNS cross-check",
                        "elasticloadbalancing:DescribeLoadBalancers",
                        e,
                    )
                else:
                    logger.warning(
                        "orphaned_dns: load balancer lookup failed (%s), continuing scan",
                        e.__class__.__name__,
                    )

            # CLO-538: classify each A-record IP against AWS's published EC2
            # ranges (pinned snapshot, no fetch). Imported here, not at module
            # top, so the online-only catalog's network.py line pins hold.
            # A stale or unreadable snapshot withholds every unmatched A value.
            from cloudwise_scan_core import aws_ip_ranges
            ranges_usable = aws_ip_ranges.snapshot_is_fresh()
            # An Application/Classic/Network LB node's public IP is in EC2
            # space and is neither an Elastic IP nor an instance IP. Unless
            # this region's load-balancer list is whole AND empty, an
            # unmatched same-region EC2 IP could be one: withheld.
            lb_ips_ruled_out = lb_list_complete and lb_count == 0
            skipped_not_ec2 = 0
            withheld_ambiguous = 0
            withheld_cross_region_a = 0
            withheld_ranges = 0
            withheld_lb_possible = 0

            zones = route53.list_hosted_zones().get('HostedZones', [])

            for zone in zones:
                zone_id = zone['Id'].split('/')[-1]
                zone_name = zone['Name']

                # Skip private zones
                if zone.get('Config', {}).get('PrivateZone', False):
                    continue

                try:
                    paginator = route53.get_paginator('list_resource_record_sets')
                    for page in paginator.paginate(HostedZoneId=zone_id):
                        for record in page.get('ResourceRecordSets', []):
                            rtype = record.get('Type', '')
                            rname = record.get('Name', '').rstrip('.')

                            # Skip NS, SOA, MX, TXT, SRV — only check A and CNAME
                            if rtype not in ('A', 'CNAME'):
                                continue

                            # Skip alias records (AWS manages target resolution)
                            if record.get('AliasTarget'):
                                continue

                            values = [rr.get('Value', '') for rr in record.get('ResourceRecords', [])]

                            # CLO-444: collect every dead value on this ONE
                            # record set before emitting anything. The old
                            # code emitted one finding per dead VALUE, so an
                            # A record with two dead IPs produced two
                            # findings sharing the identical composite id
                            # (zone:name:type[:set_identifier]) — a duplicate
                            # finding, not two distinct waste items. Trigger
                            # stays "any dead value" (unchanged); only the
                            # emit is hoisted to once per record set.
                            dead_values = []
                            orphan_reasons = []

                            for value in values:
                                is_orphaned = False
                                orphan_reason = ''

                                if rtype == 'A':
                                    # Check if IP exists in active EIPs/EC2 IPs
                                    ip_class = (
                                        aws_ip_ranges.classify_ipv4(value)
                                        if ranges_usable and value not in active_ips else None
                                    )
                                    if value in active_ips:
                                        pass
                                    elif ip_class is None:
                                        # CLO-538: no trusted range data. MISSING.
                                        withheld_ranges += 1
                                    elif ip_class.kind in ('not_ec2', 'invalid'):
                                        # CLO-538: not AWS at all (Vercel,
                                        # Cloudflare, on-prem) or AWS space
                                        # that is not EC2 (CloudFront, Global
                                        # Accelerator, API Gateway). Never an
                                        # orphaned Elastic IP or instance.
                                        skipped_not_ec2 += 1
                                    elif ip_class.kind != 'ec2':
                                        # EC2 space another service also
                                        # lists, or no single region.
                                        withheld_ambiguous += 1
                                    elif not scan_region or ip_class.region != scan_region:
                                        # CLO-538: another region's EIP and
                                        # EC2 lists are not read by this
                                        # (us-east-1, global) detector and
                                        # are not shared across the per-region
                                        # scans. MISSING, no cross-region call.
                                        withheld_cross_region_a += 1
                                    elif not (eip_list_complete and ec2_list_complete):
                                        # CLO-535 item 1: MISSING, not orphaned.
                                        withheld_a_records += 1
                                    elif not lb_ips_ruled_out:
                                        withheld_lb_possible += 1
                                    else:
                                        is_orphaned = True
                                        # Wording unchanged (CLO-444 keeps
                                        # it stable); the region goes in
                                        # metadata['ip_region'].
                                        orphan_reason = f'A record points to {value} which is not an active Elastic IP or EC2 public IP'
                                elif rtype == 'CNAME':
                                    # DescribeLoadBalancers' DNSName has no
                                    # dualstack./ipv6. prefix, but a CNAME to
                                    # the same live LB may carry one: compare
                                    # the bare name.
                                    target = _ELB_DNS_PREFIX_RE.sub('', value.lower().rstrip('.'))
                                    # Only ELB-shaped targets are checked; other
                                    # CNAME targets (external hosts, S3, etc.)
                                    # can't be verified against provider data.
                                    if not _ELB_DNS_SUFFIX_RE.search(target) or target in active_dns_names:
                                        pass
                                    elif not scan_region or _elb_dns_region(target) != scan_region:
                                        # CLO-535 item 2: the load-balancer list
                                        # is this region's only. A load balancer
                                        # in another region (or one whose name
                                        # names no region) can't be looked up
                                        # without a cross-region call: MISSING.
                                        withheld_cross_region_cnames += 1
                                    elif not lb_list_complete:
                                        withheld_elb_cnames += 1
                                    else:
                                        is_orphaned = True
                                        orphan_reason = f'CNAME points to {value} which does not match any active Load Balancer'

                                if is_orphaned:
                                    dead_values.append(value)
                                    orphan_reasons.append(orphan_reason)

                            if dead_values:
                                # CLO-437: the finding's id must name ONE
                                # record, not one NAME. A DNS name can
                                # carry an A, an AAAA, a TXT and an MX at
                                # once, and a weighted/latency set several
                                # records of the same name AND type, told
                                # apart only by SetIdentifier — so the id
                                # is "{zone}:{name}:{type}", plus
                                # ":{set_identifier}" when there is one.
                                # remediation's plan_binding decomposes
                                # this and binds every part to the DELETE
                                # call it approves
                                # (plan_binding._dns_record_finding_parts);
                                # a two-part id no longer binds at all, so
                                # this shape is load-bearing, not cosmetic.
                                set_identifier = record.get('SetIdentifier') or ''
                                composite_id = f"{zone_id}:{rname}:{rtype}"
                                if set_identifier:
                                    composite_id += f":{set_identifier}"

                                # CLO-444: single reason string. Kept
                                # identical to the pre-fix wording when only
                                # one value is dead (the common case); joined
                                # with "; " when several are, so no consumer
                                # of this exact string breaks on the common
                                # path.
                                combined_reason = '; '.join(orphan_reasons)

                                # A DELETE of this record set must match ALL
                                # of its current values exactly, live or
                                # dead — Route 53 rejects a DELETE whose
                                # ResourceRecords don't match the record set
                                # byte for byte. This is a copy-paste
                                # fallback shown to the customer, never what
                                # the executor runs (that goes through a
                                # model-authored, plan_binding-validated
                                # plan), so it lists every current value of
                                # the record, not just the dead ones.
                                resource_records_json = ','.join(
                                    f'{{"Value":"{v}"}}' for v in values
                                )
                                waste_items.append(WasteItem(
                                    id=str(uuid.uuid4()),
                                    resource_id=composite_id,
                                    resource_type=ResourceType.ROUTE53_HOSTED_ZONE,
                                    waste_type=WasteType.ORPHANED_DNS_RECORD,
                                    title="Orphaned DNS Record",
                                    description=(
                                        f"DNS record '{rname}' ({rtype}) in zone '{zone_name}' "
                                        f"points to a resource that no longer exists. "
                                        f"This is a potential subdomain takeover risk."
                                    ),
                                    monthly_savings=0.00,
                                    confidence=ConfidenceLevel.MEDIUM,
                                    action="Delete this DNS record or update it to point to a valid resource.",
                                    action_command=(
                                        f"aws route53 change-resource-record-sets --hosted-zone-id {zone_id} "
                                        f"--change-batch '{{\"Changes\":[{{\"Action\":\"DELETE\",\"ResourceRecordSet\":{{\"Name\":\"{rname}\",\"Type\":\"{rtype}\",\"TTL\":300,\"ResourceRecords\":[{resource_records_json}]}}}}]}}'"
                                    ),
                                    explanation={
                                        'detection': combined_reason,
                                        'threshold': 'DNS record target does not match any active AWS resource',
                                        'pricing': 'No direct cost savings — this is a security and hygiene finding. Zone costs $0.50/month.',
                                        'why_waste': (
                                            'Orphaned DNS records pointing to non-existent resources are a subdomain takeover risk. '
                                            'An attacker could claim the orphaned IP or hostname and serve malicious content under your domain.'
                                        ),
                                        'risk': (
                                            'Verify the target resource is truly gone before deleting. '
                                            'Check if the IP was recently released or the load balancer recently deleted.'
                                        ),
                                    },
                                    metadata={
                                        'zone_id': zone_id,
                                        'zone_name': zone_name,
                                        'record_name': rname,
                                        'record_type': rtype,
                                        # Only present when the record
                                        # belongs to a routing-policy set
                                        # (weighted, latency, failover) —
                                        # part of its identity (CLO-437).
                                        **({'set_identifier': set_identifier}
                                           if set_identifier else {}),
                                        # CLO-444: kept singular for any
                                        # existing consumer of the old
                                        # per-value field (first dead value,
                                        # for compatibility) alongside the
                                        # new plural field carrying all of
                                        # them.
                                        'target_value': dead_values[0],
                                        'orphaned_values': dead_values,
                                        # CLO-538: A values are judged only
                                        # in the scanning region's EC2 space.
                                        **({'ip_region': scan_region}
                                           if rtype == 'A' else {}),
                                        'detection_mode': data_provider.provider_type,
                                    }
                                    ))

                except Exception as e:
                    # AccessDenied here means route53:ListResourceRecordSets is
                    # missing from the monitoring role — every zone will fail
                    # the same way, so record it once (→ CLO-176 surfacing via
                    # WasteDetectionResult.permission_errors) and stop instead
                    # of silently returning [] account-wide.
                    if getattr(data_provider, '_is_access_denied', lambda _e: False)(e):
                        data_provider._record_permission_error(
                            resource="Route 53 Record Sets",
                            permission="route53:ListResourceRecordSets",
                            error=e,
                        )
                        data_provider._warn_access_denied(
                            "Route 53 Record Sets", "route53:ListResourceRecordSets", e,
                        )
                        break
                    logger.debug(f"Error checking DNS records for zone {zone_id}: {e}")

            warn_once = getattr(data_provider, '_warn_once', None)
            if withheld_elb_cnames and callable(warn_once):
                warn_once(
                    f"orphaned_dns_record: {withheld_elb_cnames} load-balancer CNAME(s) not judged; "
                    "the load-balancer list is incomplete (read failed or capped): MISSING, not orphaned"
                )
            if withheld_cross_region_cnames and callable(warn_once):
                warn_once(
                    f"orphaned_dns_record: {withheld_cross_region_cnames} load-balancer CNAME(s) not judged; "
                    f"they name a load balancer outside {scan_region or 'the scanning region'}, and only "
                    "this region's load balancers are read: MISSING, not orphaned"
                )
            if withheld_ranges and callable(warn_once):
                warn_once(
                    f"orphaned_dns_record: {withheld_ranges} A-record value(s) not judged; the pinned AWS "
                    f"ip-ranges snapshot is older than {aws_ip_ranges.SNAPSHOT_MAX_AGE_DAYS} days or "
                    "unreadable: MISSING, not orphaned"
                )
            if skipped_not_ec2 and callable(warn_once):
                warn_once(
                    f"orphaned_dns_record: {skipped_not_ec2} A-record value(s) not judged; outside AWS's "
                    "published EC2 ranges (a non-AWS host, or an AWS service that is not an Elastic IP "
                    "or instance)"
                )
            if withheld_ambiguous and callable(warn_once):
                warn_once(
                    f"orphaned_dns_record: {withheld_ambiguous} A-record value(s) not judged; the address "
                    "is in EC2 space that another AWS service also uses, or has no single region: "
                    "MISSING, not orphaned"
                )
            if withheld_cross_region_a and callable(warn_once):
                warn_once(
                    f"orphaned_dns_record: {withheld_cross_region_a} A-record value(s) not judged; the "
                    f"address is in another region's EC2 space, and only {scan_region or 'the scanning region'}'s "
                    "Elastic IPs and instances are read: MISSING, not orphaned"
                )
            if withheld_lb_possible and callable(warn_once):
                warn_once(
                    f"orphaned_dns_record: {withheld_lb_possible} A-record value(s) not judged; "
                    f"{scan_region or 'the scanning region'} has load balancers (or the list is "
                    "incomplete), and a load balancer node's public IP is not an Elastic IP or "
                    "instance IP: MISSING, not orphaned"
                )
            if withheld_a_records and callable(warn_once):
                warn_once(
                    f"orphaned_dns_record: {withheld_a_records} A-record value(s) not judged; the Elastic IP "
                    "or EC2 instance list is incomplete (read failed or more pages): MISSING, not orphaned"
                )
            return waste_items

        except Exception as e:
            if getattr(data_provider, '_is_access_denied', lambda _e: False)(e):
                data_provider._record_permission_error(
                    resource="Route 53 Hosted Zones",
                    permission="route53:ListHostedZones",
                    error=e,
                )
                data_provider._warn_access_denied(
                    "Route 53 Hosted Zones", "route53:ListHostedZones", e,
                )
            else:
                logger.debug(f"Orphaned DNS detection error: {e}")
            return waste_items
