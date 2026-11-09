"""
Billed-cost reconciliation for waste findings (CLO-234).

Every savings figure the engine produces is **list-price arithmetic**: we
compute what a resource *would* cost at published on-demand rates and call the
whole thing recoverable. We never check what AWS actually charged for it. That
overstates savings whenever a free tier, Reserved Instance, Savings Plan, EDP
discount, or credit applies — the always-free DynamoDB allowance (25 RCU +
25 WCU) being the case that surfaced it.

This module is the reconciliation seam. The **port** (Protocol) is
framework-free: it looks up trailing actual cost per resource id from whatever
CUR store the runtime has. Concrete adapters live in runtime-specific packages
(backend → ``app/services/waste_detection_adapters.py``, Lambda →
``lambdas/waste_detection_region_scanner/adapters.py``). The default provider
returns ``None`` so tests and ad-hoc scripts never need a CUR table configured.

Safety contract — note how this differs from ``credential_cache``:
- Adapters must swallow their own backend errors and return ``None``. A missing
  or broken lookup is **never** allowed to zero out a finding; it degrades to
  ``UNRECONCILED_NO_CUR``, which keeps the list-price estimate and labels it.
- Silently falling back to list price is the bug this module exists to fix, so
  every non-reconciled outcome carries a status that the scan result rolls up
  and the UI renders — the same guarantee CLO-217 established for
  ``cur_skipped`` and CLO-178/185/193 established for missing detectors.
- We **cap**, never replace: right-sizing detectors claim a *delta*, not full
  resource cost, so ``min(estimate, billed)`` is correct where ``= billed``
  would overstate them.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Mapping, Optional, Protocol, Sequence, runtime_checkable

logger = logging.getLogger(__name__)


# Minimum days of CUR coverage before we trust a daily→monthly extrapolation.
# Below this, a young resource's small trailing cost would cap savings to near
# zero and we would trade an overstatement bug for an understatement one.
DEFAULT_MIN_DAYS_COVERED = 7

# House convention, matching ``detectors/extended_support.py``'s
# ``get_billed_surcharge_monthly``: normalise a windowed total to a month with
# ``amount * 30 / days``.
_DAYS_PER_MONTH = 30

# CUR ``lineItem/LineItemType`` values that mean "this resource's unblended
# cost does not represent what the customer effectively pays for it".
#
# RI- and SP-covered usage lands as DiscountedUsage / SavingsPlanCoveredUsage at
# ~$0 unblended, with the actual charge on a separate RIFee / SavingsPlan*Fee
# line. Our CUR ingest stores no amortized column (see
# ``lambdas/shared_modules/cur_processing.py`` — only ``cost``,
# ``unblended_cost``, ``blended_cost``), so we cannot compute the true
# per-resource figure. Capping on unblended here would report ~$0 savings on
# genuinely wasteful reserved instances — a false negative on exactly the
# accounts most likely to be paying customers. We label instead.
DISCOUNT_LINE_ITEM_TYPES = frozenset(
    {
        "discountedusage",
        "savingsplancoveredusage",
        "savingsplannegation",
        "savingsplanupfrontfee",
        "savingsplanrecurringfee",
        "rifee",
        "edpdiscount",
        "privateratediscount",
        "bundleddiscount",
        "discount",
        "credit",
        "refund",
    }
)


class ReconciliationStatus:
    """Outcome of reconciling one finding against the CUR.

    Plain string constants rather than an ``Enum`` so the values survive the
    ``WasteItem`` → dict → DynamoDB → JSON round trip without the enum
    unwrapping every other field needs (see ``_waste_item_to_dict``).
    """

    #: CUR rows found with real cost — savings capped at billed.
    RECONCILED = "reconciled"

    #: Account demonstrably has resource-level CUR, and this resource has no
    #: billed cost in it. The free-tier case. Savings are genuinely $0.
    CONFIRMED_ZERO_BILLED = "confirmed_zero_billed"

    #: Account has no resource-granular CUR (the ``Include resource IDs``
    #: setting is opt-in). Estimate stands, labelled.
    UNRECONCILED_NO_CUR = "unreconciled_no_cur"

    #: RI/SP/credit line items present — see DISCOUNT_LINE_ITEM_TYPES.
    UNRECONCILED_DISCOUNTED = "unreconciled_discounted"

    #: Too few days of CUR coverage to extrapolate safely (young resource, or
    #: CUR still backfilling). Estimate stands, labelled.
    UNRECONCILED_INSUFFICIENT_DATA = "unreconciled_insufficient_data"

    #: A commitment finding (RI/SP purchase recommendation, unused/expiring
    #: RI/SP, coverage gap) whose ``resource_id`` is a label — an instance
    #: type, ``"Savings Plan"``, an RI/SP entity id — not a resource AWS bills
    #: against, and the detector supplied no aggregate covering spend to cap
    #: it against either. Per-resource CUR matching does not apply here at
    #: all (see ``reconcile_commitment_savings``); estimate stands, labelled.
    UNRECONCILED_COMMITMENT = "unreconciled_commitment"

    #: A commitment finding capped against the aggregate covering spend the
    #: detector itself computed (already CE-actual dollars, not list price) —
    #: e.g. a Savings Plan coverage gap capped at the uncovered on-demand
    #: spend it would apply to. Not a per-resource CUR match, so distinct
    #: from ``RECONCILED``, but the value is not the raw estimate either.
    RECONCILED_COMMITMENT = "reconciled_commitment"

    #: CLO-367: was ``UNRECONCILED_DISCOUNTED``; the processor's aggregate step
    #: checked it against AWS Cost Optimization Hub's after-discount estimate
    #: (the figure our CUR ingest cannot compute) and kept the lower of the
    #: two. Set in ``lambdas/waste_detection_processor/handler.py``, which
    #: mirrors this string because that Lambda has no scan-core layer.
    RECONCILED_HUB_AFTER_DISCOUNTS = "reconciled_hub_after_discounts"

    #: CLO-739: the finding's name matched more than one CUR resource (an
    #: alias two resources share, e.g. an endpoint and its same-named log
    #: group), nothing matched it uniquely, and those resources' bills
    #: disagree. We cannot tell which bill is this resource's, so we cannot
    #: say AWS bills it $0 either (if every candidate bills $0, it reads as
    #: ``CONFIRMED_ZERO_BILLED`` as before; see ``BilledCostMatch``). Estimate
    #: stands, labelled. Before CLO-739 this read as ``CONFIRMED_ZERO_BILLED``
    #: and the $0.01 floor dropped the finding.
    UNRECONCILED_AMBIGUOUS = "unreconciled_ambiguous"

    #: CLO-740: AWS bills ECS by task, and the CUR cannot tie a task to its
    #: service: a task ARN names the cluster and the task only, our ingest
    #: stores no tags or split-cost columns, and ListTasks returns only
    #: current tasks. A service-level finding therefore has no billed cost we
    #: can read, whichever rows the CUR holds. Estimate stands, labelled.
    #: Before CLO-740 this read as ``CONFIRMED_ZERO_BILLED`` and the $0.01
    #: floor dropped the finding. See ``CUR_NOT_ATTRIBUTABLE_WASTE_TYPES``.
    UNRECONCILED_NOT_ATTRIBUTABLE = "unreconciled_not_attributable"

    #: The account has resource-level CUR, but this resource has no rows in it,
    #: and either it is younger than the CUR's latest covered day or it is a
    #: type AWS bills whenever it exists (an Elastic IP), so "no rows" cannot
    #: mean "$0". The CUR lands a day or more behind usage, so every
    #: brand-new resource used to read as "AWS bills $0" here and the $0.01
    #: floor dropped it (an idle Elastic IP created at 14:06 UTC, scanned at
    #: 14:08, reported $0 although AWS bills it from that hour). Estimate
    #: stands, labelled, until the CUR catches up. See
    #: :func:`_not_yet_billed` for the exact rule.
    UNRECONCILED_NOT_YET_BILLED = "unreconciled_not_yet_billed"

    #: CLO-746: AWS bills Container Insights as CloudWatch metrics for the
    #: whole account, by namespace (``CW:MetricMonitorUsage``,
    #: ``MetricStorage:AWS/...``), never under a per-cluster resource id. A
    #: cluster that is running tasks therefore has no CUR row to match, and a
    #: miss is not "not billed". Estimate stands, labelled. An empty cluster
    #: (no running tasks) emits no metrics and keeps the ordinary $0 result.
    #: See ``CUR_ACCOUNT_WIDE_WASTE_TYPES``.
    UNRECONCILED_BILLED_ACCOUNT_WIDE = "unreconciled_billed_account_wide"

    #: Every status that leaves ``monthly_savings`` at the list-price estimate.
    UNRECONCILED = frozenset(
        {
            UNRECONCILED_NO_CUR,
            UNRECONCILED_DISCOUNTED,
            UNRECONCILED_INSUFFICIENT_DATA,
            UNRECONCILED_COMMITMENT,
            UNRECONCILED_AMBIGUOUS,
            UNRECONCILED_NOT_ATTRIBUTABLE,
            UNRECONCILED_NOT_YET_BILLED,
            UNRECONCILED_BILLED_ACCOUNT_WIDE,
        }
    )


#: CLO-740: the ``(resource type, waste type)`` findings no CUR row can be
#: attributed to, as plain values (see ``_resource_type_key``). Every ECS
#: finding carries the ``ecs_service`` resource type, so the type alone would
#: also catch these two, deliberately left out:
#: - ``idle_ecs_service``: a governance finding with a $0 estimate. A service
#:   with no running task bills nothing, so its zero is true.
#: - ``ecs_container_insights_waste``: id is the cluster, and its cost is
#:   CloudWatch metrics, not ECS tasks, so the reason this status gives
#:   customers would be false. It has its own status (CLO-746, see
#:   ``CUR_ACCOUNT_WIDE_WASTE_TYPES``); an empty cluster really does bill $0.
#: All three types here only produce a saving for Fargate services (the
#: detectors gate on ``launchType``); the EC2 launch type bills instances. An
#: account threshold of $0 lets ``ecs_no_autoscaling`` fire at $0 on EC2, so
#: only a non-zero estimate qualifies: there is nothing to keep at $0, and the
#: customer note would be false for that service.
CUR_NOT_ATTRIBUTABLE_RESOURCE_TYPE = "ecs_service"
CUR_NOT_ATTRIBUTABLE_WASTE_TYPES = frozenset(
    {
        "oversized_ecs_task",
        "oversized_ecs_memory",
        "ecs_no_autoscaling",
    }
)


#: CLO-746: waste types whose cost AWS bills account-wide, so the CUR holds no
#: row under the finding's resource id. Only a finding that also reports
#: running tasks qualifies (an empty cluster really bills $0). Deliberately
#: not matched against the ``/aws/ecs/containerinsights/<cluster>/performance``
#: log group: the detector prices metrics, and a log-ingest bill would cap it
#: far too low. Matched on the value, like ``CUR_NOT_ATTRIBUTABLE_WASTE_TYPES``.
CUR_ACCOUNT_WIDE_WASTE_TYPES = frozenset({"ecs_container_insights_waste"})


class CostBasis:
    """Which CUR cost column a rollup was computed from.

    Recorded rather than assumed: the ingest loop takes the *first available*
    of NetUnblendedCost → UnblendedCost → BlendedCost **per row**
    (``cur_processing.py``), so the basis of the stored ``cost`` column varies
    by account and even by row within an account.
    """

    CUR_COST = "cur_cost"  # the stored ``cost`` column, basis varies by row
    UNBLENDED = "unblended"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BilledCostRollup:
    """Trailing actual cost for a single resource id, summed over the window.

    One resource produces **multiple CUR rows per day** — the sort key is
    ``{usage_date}#{resource_id}#{usage_type}`` — so ``billed_total`` sums
    across usage types, and ``days_covered`` counts *distinct usage dates*, not
    rows.
    """

    resource_id: str
    billed_total: float
    days_covered: int
    cost_basis: str = CostBasis.CUR_COST
    has_discount_line_items: bool = False

    def monthly_equivalent(self) -> Optional[float]:
        """Normalise the windowed total to a month, or ``None`` if no coverage."""
        if self.days_covered <= 0:
            return None
        return self.billed_total * _DAYS_PER_MONTH / self.days_covered


def resource_id_aliases(resource_id: str) -> set:
    """Alternative keys the same resource may be known by.

    Detectors emit whatever the describing API returns — a DynamoDB table
    name, an instance id, a bucket name. The CUR overwhelmingly stores ARNs
    (~87% of resource-carrying rows on our own staging account). So the
    detector's ``my-table`` and the CUR's
    ``arn:aws:dynamodb:us-east-1:123456789012:table/my-table``
    are the same resource under two names.

    This matters far more than it looks: an unmatched resource would be read
    as "AWS bills nothing for this" and the finding zeroed. Naive exact
    matching would therefore have deleted most real findings on exactly the
    accounts that HAVE resource-level CUR — the ones reconciliation exists to
    serve. Aliasing is what makes the match meaningful rather than dangerous.
    """
    keys = {resource_id}
    if resource_id.startswith("arn:"):
        # arn:...:table/name, arn:...:instance/i-abc, arn:...:/restapis/xyz
        keys.add(resource_id.rsplit("/", 1)[-1])
        # arn:aws:sqs:region:acct:queue-name (no slash)
        keys.add(resource_id.rsplit(":", 1)[-1])
    return {k for k in keys if k}


#: Secrets Manager appends "-" plus six random alphanumerics to every secret
#: ARN: secret ``cwfx-unused-secret`` is billed in the CUR as
#: ``arn:aws:secretsmanager:us-east-1:123456789012:secret:cwfx-unused-secret-9kIlqu``.
_SECRET_ARN_SUFFIX = re.compile(r"^(.+)-[A-Za-z0-9]{6}$")


def _secretsmanager_secret_name(arn: str) -> Optional[str]:
    """The secret's own name from a full Secrets Manager secret ARN (CLO-736).

    Detectors emit the name ``ListSecrets`` returns; the CUR keys the secret
    by its suffixed ARN. Without this key the two never met, the finding read
    as ``confirmed_zero_billed`` and the $0.01 floor dropped it.

    Deliberately NOT part of :func:`resource_id_aliases`: a stripped secret
    name is often the name of the resource the secret belongs to (secret
    ``prod-db-AbCdEf`` next to RDS ``prod-db``). In the shared alias index it
    would make that resource's bare-name alias ambiguous, the alias would be
    dropped, and the RDS finding would be zeroed. It lives in its own index,
    ``BilledCostLookup.by_secret_name``, read only for Secrets Manager
    findings.

    - Scoped to ``secretsmanager`` + resource type ``secret``. Any partition.
    - Strips the *whole* name after ``:secret:``, so ``prod/db/password-AbCdEf``
      yields ``prod/db/password`` (names may contain ``/``, never ``:``).
    - Strips exactly once: ``foo-abc123-XyZ9qQ`` yields ``foo-abc123``.
    - Assumes the full ARN, which is what the CUR carries. A partial ARN
      (no suffix) whose name happens to end in ``-`` + 6 alphanumerics, e.g.
      ``...:secret:db-abc123``, would wrongly yield ``db``.
    """
    parts = arn.split(":", 6)
    if len(parts) != 7 or parts[2] != "secretsmanager" or parts[5] != "secret":
        return None
    match = _SECRET_ARN_SUFFIX.match(parts[6])
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Per-resource-type name indexes (CLO-737)
# ---------------------------------------------------------------------------
#
# Each deriver takes the ARN split as ``arn.split(":")`` and returns the name
# the detector for that resource type emits, or ``None`` when the ARN is not
# that kind of resource. Like ``by_secret_name`` (CLO-736), these names never
# enter the shared alias index: they are read only by findings of the one
# resource type they belong to, so they cannot make another resource's alias
# ambiguous. Every mismatch below was seen in staging CUR for the fixture
# account (see the CLO-737 PR for the evidence table).


def _elb_name(parts: list) -> Optional[str]:
    """ELB name from ``loadbalancer/app|net|gwy/<name>/<hash>`` or, for a
    Classic LB, ``loadbalancer/<name>``.

    For ALB/NLB the shared aliases are the hash (slash tail) and the whole
    ``loadbalancer/app/...`` path (colon tail), never the name the detectors
    emit (``load_balancer_name``): low_traffic_alb ``cwfx-alb-quiet`` read as
    confirmed_zero_billed beside its billed ALB ARN.

    Classic LB names are indexed too (they already match through the shared
    slash tail): ``LOAD_BALANCER`` covers CLB, ALB, NLB and GWLB, and the CLB
    and ELBv2 name spaces are separate, so a CLB and an ALB may share a name
    in one region. The finding's ``lb_type`` metadata picks the right one
    (see :func:`_elb_kind`); without it the two read as ambiguous.
    """
    if _elb_kind(parts) is None:
        return None
    segs = parts[5].split("/")
    return (segs[2] if len(segs) == 4 else segs[1]) or None


def _elb_kind(parts: list) -> Optional[str]:
    """``app`` / ``net`` / ``gwy`` / ``classic`` for a load balancer ARN."""
    if len(parts) != 6 or parts[2] != "elasticloadbalancing":
        return None
    segs = parts[5].split("/")
    if segs[0] != "loadbalancer":
        return None
    if len(segs) == 4 and segs[1] in ("app", "net", "gwy"):
        return segs[1]
    if len(segs) == 2:
        return "classic"
    return None


#: The detectors' ``metadata["lb_type"]`` (the ELB API's ``Type``, or
#: ``classic``) → the ARN's load balancer kind.
_LB_TYPE_TO_KIND = {
    "application": "app",
    "network": "net",
    "gateway": "gwy",
    "classic": "classic",
}


def _msk_cluster_name(parts: list) -> Optional[str]:
    """MSK cluster name from ``cluster/<name>/<uuid>-<n>``.

    The shared aliases are the uuid and the whole path; oversized_msk_cluster
    ``cwfx-w8b-msk`` read as confirmed_zero_billed beside its billed ARN.
    """
    if len(parts) != 6 or parts[2] != "kafka":
        return None
    segs = parts[5].split("/")
    if len(segs) == 3 and segs[0] == "cluster" and segs[1]:
        return segs[1]
    return None


def _sagemaker_endpoint_name(parts: list) -> Optional[str]:
    """SageMaker endpoint name from ``endpoint/<name>``, lower-cased.

    The shared slash tail is the name, but every endpoint also writes the log
    group ``/aws/sagemaker/Endpoints/<name>`` whose slash tail is the same
    name: the alias was ambiguous, dropped, and idle_sagemaker_endpoint
    ``cwfx-w8b-ep-idle`` read as confirmed_zero_billed beside a billed
    endpoint. Keys are lower-cased because SageMaker lower-cases the name in
    the ARN while ``EndpointName`` keeps its case.
    """
    if len(parts) != 6 or parts[2] != "sagemaker":
        return None
    segs = parts[5].split("/")
    if len(segs) == 2 and segs[0] == "endpoint" and segs[1]:
        return segs[1].lower()
    return None


def _lambda_function_name(parts: list) -> Optional[str]:
    """Lambda function name from an unqualified ``function:<name>`` ARN.

    Same collision as SageMaker: the function's log group
    ``/aws/lambda/<name>`` has the function name as its slash tail, so the
    shared alias of any Lambda that has logged is ambiguous and dropped.
    Qualified ARNs (``function:<name>:<alias|version>``) are left out: none
    appear in the evidence, and indexing them would make the function's own
    unqualified row ambiguous.
    """
    if len(parts) != 7 or parts[2] != "lambda" or parts[5] != "function":
        return None
    return parts[6] or None


def _elasticache_node_id(parts: list) -> Optional[str]:
    """ElastiCache cache cluster (node) id from ``cluster:<id>``.

    The CUR bills ElastiCache per node: a replication group ``cwfx-cache-replicas``
    appears only as ``...:cluster:cwfx-cache-replicas-001`` and ``-002``, a
    cluster-mode group ``cwfx-w8b-ec-tier`` only as ``-0001-001``,
    ``-0002-001``. The group id never appears. Per-node findings already
    reach their row through the shared colon tail; this index exists so a
    group-level finding can name its member nodes (see ``member_ids`` on
    :meth:`BilledCostLookup.match_for`).
    """
    if len(parts) != 7 or parts[2] != "elasticache" or parts[5] != "cluster":
        return None
    return parts[6] or None


def _rds_cluster_bill_key(parts: list) -> Optional[str]:
    """``db:<instance id>`` or ``cluster:<cluster resource id>``, lower-cased.

    The CUR bills an Aurora, DocumentDB or Neptune cluster as:

    - ``arn:aws:rds:<r>:<a>:db:<DBInstanceIdentifier>`` for each member
      instance's hours (and any Extended Support surcharge on them):
      ``db:cwfx-idle-documentdb-0`` for cluster ``cwfx-idle-documentdb``.
    - ``arn:aws:rds:<r>:<a>:cluster:<DbClusterResourceId>`` for the cluster's
      storage, I/O and backup. The API returns that id upper-case
      (``cluster-27ZXXCJJANJW55DPVE5GYKQ62Q``) and the CUR lower-case
      (``cluster-27zxxcjjanjw55dpve5gykq62q``).

    The cluster finding's ``DBClusterIdentifier`` is in neither, so the
    findings carry these keys as ``cur_member_ids`` (see
    :func:`rds_cluster_cur_member_ids`). The key keeps the ARN's resource
    kind, so a finding's own ``resource_id`` (a bare cluster or instance name)
    never reaches this index: only the carried member ids do, and every other
    RDS, DocumentDB and Neptune finding keeps its old path. Snapshot rows
    (``snapshot:``, ``cluster-snapshot:``) are not indexed.
    """
    # All three engines bill under ``rds`` ARNs. Written as two comparisons,
    # not a tuple of names: scripts/generate_export_keep_fields.py reads a
    # tuple of strings here as export keys the code reads.
    if (
        len(parts) != 7
        or parts[2] != "rds"
        or (parts[5] != "db" and parts[5] != "cluster")
        or not parts[6]
    ):
        return None
    return f"{parts[5]}:{parts[6]}".lower()


def rds_cluster_cur_member_ids(
    *,
    db_cluster_resource_id: Optional[str],
    instance_ids: Sequence[str],
    cluster_bill: bool,
    instance_bill: bool,
) -> Optional[list]:
    """The ``cur_member_ids`` an Aurora, DocumentDB or Neptune cluster
    finding carries (CLO-810), or ``None`` when its bill cannot be named.

    ``cluster_bill``: the saving comes out of the cluster's storage, I/O and
    backup row (``cluster:<DbClusterResourceId>``). ``instance_bill``: out of
    the member instances' rows (``db:<DBInstanceIdentifier>``). Each detector
    picks the rows its saving can come from; the billed sum only ever caps
    the estimate (``reconcile_savings``'s ``min``).

    The ids are matched authoritatively, so a partial set would cap against
    part of the bill. ``None`` (the finding keeps its pre-CLO-810 path) when:

    - ``cluster_bill`` is wanted and the cluster resource id is unknown (an
      offline export written without ``DbClusterResourceId``), or
    - only ``instance_bill`` is wanted and the cluster has no member.

    A cluster with no member instance and a known resource id is billed for
    storage only, so for ``cluster_bill`` types it yields just that key.
    """
    keys: list = []
    if instance_bill:
        keys.extend(f"db:{i}".lower() for i in instance_ids if i)
    if cluster_bill:
        if not db_cluster_resource_id:
            return None
        keys.append(f"cluster:{db_cluster_resource_id}".lower())
    return keys or None


#: ``ResourceType`` value → (deriver, normalise the finding's id for lookup).
#: The three RDS-family cluster types (CLO-810) are read only through
#: ``member_ids``; see :func:`_rds_cluster_bill_key`. Aurora cluster findings
#: are typed ``rds_instance``.
_TYPED_NAME_DERIVERS = {
    "load_balancer": (_elb_name, str),
    "msk_cluster": (_msk_cluster_name, str),
    "sagemaker_endpoint": (_sagemaker_endpoint_name, str.lower),
    "lambda_function": (_lambda_function_name, str),
    "elasticache_cluster": (_elasticache_node_id, str),
    "rds_instance": (_rds_cluster_bill_key, str.lower),
    "documentdb_cluster": (_rds_cluster_bill_key, str.lower),
    "neptune_cluster": (_rds_cluster_bill_key, str.lower),
}


def _api_gateway_rest_api_id(parts: list) -> Optional[str]:
    """REST API id from ``/restapis/<id>`` or ``/restapis/<id>/stages/<stage>``
    (CLO-740).

    unused_api_gateway emits ``api_id``. The CUR bills a REST API per stage,
    ``arn:aws:apigateway:<region>::/restapis/<id>/stages/<stage>``, whose
    shared slash tail is the stage name (``prod``, shared by every API with a
    ``prod`` stage) and whose colon tail is the whole path. Neither is the
    API id, so the finding read as confirmed_zero_billed. HTTP/WebSocket APIs
    (``/apis/<id>``) are left out: the detector reads REST APIs only.
    """
    if len(parts) != 6 or parts[2] != "apigateway":
        return None
    segs = parts[5].split("/")
    # "/restapis/<id>" -> ["", "restapis", "<id>"]
    if len(segs) < 3 or segs[0] != "" or segs[1] != "restapis" or not segs[2]:
        return None
    if len(segs) == 3:
        return segs[2]
    if len(segs) == 5 and segs[3] == "stages" and segs[4]:
        return segs[2]
    return None


#: ``ResourceType`` value -> deriver, for types whose bill is the SUM of
#: several CUR resources (CLO-740). Unlike ``_TYPED_NAME_DERIVERS``, several
#: candidates in the finding's region are not ambiguous here: they are the
#: parts of one bill (a REST API's stages), and
#: :meth:`BilledCostLookup.match_for` adds them up.
_TYPED_ROLLUP_DERIVERS = {
    "api_gateway": _api_gateway_rest_api_id,
}


def _resource_type_key(resource_type) -> Optional[str]:
    """``ResourceType`` member or plain string → its string value.

    ``ResourceType`` is a ``str`` Enum, whose hash is the member *name*'s, so
    a dict keyed by values cannot be indexed by the member directly.
    """
    if resource_type is None:
        return None
    return str(getattr(resource_type, "value", resource_type))


def _arn_region(resource_id: str) -> str:
    """The region field of an ARN, or ``""`` for a non-ARN id or an ARN with
    no region (S3, IAM)."""
    if not resource_id.startswith("arn:"):
        return ""
    parts = resource_id.split(":")
    return parts[3] if len(parts) > 3 else ""


def _sum_rollups(resource_id: str, parts: list) -> Optional[BilledCostRollup]:
    """Several CUR resources' rollups as one bill, or ``None`` for none.

    ``billed_total`` is the parts' total, ``has_discount_line_items`` is true
    if any part has them, and ``cost_basis`` is the parts' common basis
    (``UNKNOWN`` if they differ). ``days_covered`` is the largest part's,
    because a rollup does not keep the union of the parts' usage dates. The
    max can only undercount that union, which overstates the monthly figure
    and so loosens the ``min(estimate, billed)`` cap rather than tightening
    it.
    """
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    bases = {p.cost_basis for p in parts}
    return BilledCostRollup(
        resource_id=resource_id,
        billed_total=sum(p.billed_total for p in parts),
        days_covered=max(p.days_covered for p in parts),
        cost_basis=bases.pop() if len(bases) == 1 else CostBasis.UNKNOWN,
        has_discount_line_items=any(p.has_discount_line_items for p in parts),
    )


@dataclass(frozen=True)
class BilledCostMatch:
    """What :meth:`BilledCostLookup.match_for` found for one finding (CLO-739).

    ``rollup`` is the one CUR resource the finding matched, or ``None``.
    ``ambiguous`` is True only when ``rollup`` is ``None`` because the
    finding's name pointed at more than one CUR resource whose bills
    disagree: "couldn't tell which" rather than "not in the CUR". Absence is
    what proves a $0 bill; ambiguity proves nothing. ``candidates`` lists the
    CUR resource ids behind an ambiguous match, for diagnostics.

    When every candidate bills $0 (``billed_total <= 0``, the same test
    :func:`reconcile_savings` applies) and none carries discount line items,
    the bill is $0 whichever one is the finding's, so the match is reported
    as absent (``ambiguous`` False) and the finding reconciles to
    ``CONFIRMED_ZERO_BILLED`` exactly as before CLO-739.
    """

    rollup: Optional[BilledCostRollup] = None
    ambiguous: bool = False
    candidates: tuple = ()

    #: True when ``rollup`` is ``None`` because every candidate the finding's
    #: name reached bills $0 (the case above), not because the CUR has no row
    #: for it. That is positive evidence of a $0 bill, so the not-yet-billed
    #: rule (:func:`_not_yet_billed`) never applies to it.
    zero_billed_candidates: bool = False


@dataclass(frozen=True)
class BilledCostLookup:
    """Batched result of one CUR read for a whole finding set.

    ``resource_ids_present`` is the load-bearing field: it is what makes
    ``CONFIRMED_ZERO_BILLED`` *provable* rather than inferred from absence.
    Without it we could not tell a genuinely free-tier resource (rows exist,
    they sum to $0) from an account that never enabled resource-level CUR at
    all (no rows for anything) — and defaulting that ambiguity to "not billed"
    would silently delete real findings.
    """

    by_resource: Mapping[str, BilledCostRollup]

    #: True only if this account's CUR carries real resource ids for the
    #: window. False when the rows came from the Cost Explorer fallback or
    #: from a CUR configured without the ``RESOURCES`` schema element (both
    #: land as the literal ``NO_RESOURCE_ID``).
    resource_ids_present: bool

    #: Distinct usage dates covered by the account's rows in the window. Used
    #: to reject a "resource has no rows ⇒ not billed" conclusion drawn from a
    #: window the CUR has barely populated.
    account_days_covered: int = 0

    #: The latest ``usage_date`` any of the account's rows in the window
    #: carry: the last day the CUR has billed anything for. ``None`` when the
    #: adapter did not report it, which keeps the pre-existing behaviour (no
    #: resource can be shown to be younger than the CUR's coverage).
    latest_usage_date: Optional[date] = None

    #: Unambiguous alias → resource id, for the ARN/bare-name mismatch above.
    #: Built by :meth:`build`; ambiguous aliases are deliberately omitted.
    by_alias: Mapping[str, str] = field(default_factory=dict)

    #: Alias two or more CUR resources share → those resource ids, left out
    #: of ``by_alias`` (CLO-739). Kept so a finding that reaches only one of
    #: them reads as ambiguous (when their bills disagree), not as absent.
    ambiguous_aliases: Mapping[str, tuple] = field(default_factory=dict)

    #: Secret name with Secrets Manager's ARN suffix stripped → CUR resource
    #: id (CLO-736). Kept apart from ``by_alias`` so it can never make another
    #: resource's alias ambiguous; read only by Secrets Manager findings.
    #: A name two CUR secrets strip to (e.g. two regions) is omitted.
    by_secret_name: Mapping[str, str] = field(default_factory=dict)

    #: Secret name two or more CUR secrets strip to → those resource ids
    #: (CLO-739), left out of ``by_secret_name``; see ``ambiguous_aliases``.
    ambiguous_secret_names: Mapping[str, tuple] = field(default_factory=dict)

    #: ``ResourceType`` value → derived name → every CUR resource id that
    #: derives it, as ``(region, resource_id)`` pairs (CLO-737). Kept apart
    #: from ``by_alias`` for the same reason as ``by_secret_name``, read only
    #: by findings of that resource type. All candidates are kept, so
    #: :meth:`rollup_for` can narrow a name used in several regions to the
    #: finding's own region; a name still matching more than one id there is
    #: ambiguous and not used.
    by_typed_name: Mapping[str, Mapping[str, tuple]] = field(default_factory=dict)

    #: ``ResourceType`` value -> derived id -> every CUR resource id whose
    #: bill is part of it, as ``(region, resource_id)`` pairs (CLO-740; see
    #: ``_TYPED_ROLLUP_DERIVERS``). Kept apart from ``by_alias`` like
    #: ``by_typed_name``, read only by findings of that type, and summed
    #: after narrowing to the finding's region.
    by_typed_rollup: Mapping[str, Mapping[str, tuple]] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        rollups,
        *,
        resource_ids_present: bool,
        account_days_covered: int = 0,
        latest_usage_date: Optional[date] = None,
    ) -> "BilledCostLookup":
        """Index rollups by resource id AND by unambiguous alias."""
        by_resource = {r.resource_id: r for r in rollups}

        alias_hits: dict = {}
        for rid in by_resource:
            for alias in resource_id_aliases(rid):
                if alias == rid:
                    continue
                alias_hits.setdefault(alias, set()).add(rid)

        # An alias shared by two different resources tells us nothing, and
        # guessing would attach one resource's bill to another. Drop it —
        # the finding then reports "couldn't reconcile", not a wrong number.
        by_alias = {a: next(iter(v)) for a, v in alias_hits.items() if len(v) == 1}
        # CLO-739: remember what was dropped, so a finding that reaches only
        # an ambiguous alias reads as "couldn't tell which", never as "not
        # billed".
        ambiguous_aliases = {
            a: tuple(sorted(v)) for a, v in alias_hits.items() if len(v) > 1
        }

        secret_hits: dict = {}
        for rid in by_resource:
            name = _secretsmanager_secret_name(rid)
            if name:
                secret_hits.setdefault(name, set()).add(rid)
        by_secret_name = {
            n: next(iter(v)) for n, v in secret_hits.items() if len(v) == 1
        }
        ambiguous_secret_names = {
            n: tuple(sorted(v)) for n, v in secret_hits.items() if len(v) > 1
        }

        typed_hits: dict = {}
        for rid in by_resource:
            if not rid.startswith("arn:"):
                continue
            parts = rid.split(":")
            for rtype, (derive, _) in _TYPED_NAME_DERIVERS.items():
                name = derive(parts)
                if name:
                    typed_hits.setdefault(rtype, {}).setdefault(name, set()).add(
                        (parts[3], rid)
                    )
        by_typed_name = {
            rtype: {name: tuple(sorted(c)) for name, c in names.items()}
            for rtype, names in typed_hits.items()
        }

        rollup_hits: dict = {}
        for rid in by_resource:
            if not rid.startswith("arn:"):
                continue
            parts = rid.split(":")
            for rtype, derive in _TYPED_ROLLUP_DERIVERS.items():
                key = derive(parts)
                if key:
                    rollup_hits.setdefault(rtype, {}).setdefault(key, set()).add(
                        (parts[3], rid)
                    )
        by_typed_rollup = {
            rtype: {key: tuple(sorted(c)) for key, c in keys.items()}
            for rtype, keys in rollup_hits.items()
        }

        return cls(
            by_resource=by_resource,
            resource_ids_present=resource_ids_present,
            account_days_covered=account_days_covered,
            latest_usage_date=latest_usage_date,
            by_alias=by_alias,
            ambiguous_aliases=ambiguous_aliases,
            by_secret_name=by_secret_name,
            ambiguous_secret_names=ambiguous_secret_names,
            by_typed_name=by_typed_name,
            by_typed_rollup=by_typed_rollup,
        )

    def _typed_name_match(
        self,
        resource_id: str,
        resource_type,
        region: Optional[str],
        lb_type: Optional[str] = None,
    ) -> Optional[str]:
        """The resource id half of :meth:`_typed_name_candidates`."""
        return self._typed_name_candidates(
            resource_id, resource_type, region, lb_type
        )[0]

    def _typed_name_candidates(
        self,
        resource_id: str,
        resource_type,
        region: Optional[str],
        lb_type: Optional[str] = None,
    ) -> tuple:
        """The one CUR id the finding's type-specific name index points at.

        ``None`` when the type has no index, the finding has no real region
        (empty or ``global``: every indexed type is regional, so such a
        finding keeps the pre-CLO-737 path), the name is absent, or more than
        one id remains after narrowing to the finding's region and, for a
        load balancer whose ``lb_type`` is known, to its kind (ambiguous:
        never guessed).

        Returns ``(resource_id, ambiguous_ids)``. ``ambiguous_ids`` holds the
        ids when more than one remains after narrowing (CLO-739), else ``()``.
        None left after narrowing (the name exists only in another region, or
        only as another load balancer kind) is absence, not ambiguity.
        """
        rtype = _resource_type_key(resource_type)
        entry = _TYPED_NAME_DERIVERS.get(rtype) if rtype else None
        if entry is None:
            return None, ()
        _, normalise = entry
        candidates = self.by_typed_name.get(rtype, {}).get(normalise(resource_id))
        if not candidates:
            return None, ()
        if not region or region == "global":
            return None, ()
        candidates = tuple(c for c in candidates if c[0] == region)
        kind = _LB_TYPE_TO_KIND.get(str(lb_type or "").lower())
        if rtype == "load_balancer" and kind:
            candidates = tuple(
                c for c in candidates if _elb_kind(c[1].split(":")) == kind
            )
        if len(candidates) != 1:
            return None, tuple(c[1] for c in candidates)
        return candidates[0][1], ()

    def _typed_rollup(
        self, resource_id: str, resource_type, region: Optional[str]
    ) -> Optional[BilledCostRollup]:
        """The summed rollup of every CUR resource that bills part of this
        finding (CLO-740), or ``None``.

        ``None`` when the type has no rollup index, the finding has no real
        region (empty or ``global``: it keeps the pre-CLO-740 path), or no
        part is billed in the finding's region. Parts in other regions are
        never added. The sum is :func:`_sum_rollups`.
        """
        rtype = _resource_type_key(resource_type)
        if not rtype or rtype not in _TYPED_ROLLUP_DERIVERS:
            return None
        if not region or region == "global":
            return None
        parts = [
            self.by_resource[rid]
            for reg, rid in self.by_typed_rollup.get(rtype, {}).get(resource_id, ())
            if reg == region and rid in self.by_resource
        ]
        return _sum_rollups(resource_id, parts)

    def _member_match(
        self,
        resource_id: str,
        member_ids: Sequence[str],
        resource_type,
        region: str,
    ) -> BilledCostMatch:
        """The summed bill of a finding's member resources (ElastiCache
        replication group → its nodes; an RDS-family cluster → its instances
        and/or its storage row, CLO-810), each found through the type's name
        index in the finding's region.

        Authoritative, like ``cur_resource_id``: members with no CUR rows are
        absent, and the group's own id is never tried as an alias, since
        the CUR never bills it and a hit could only be another resource. A
        member that still names several CUR ids in the region (not expected:
        a node id is unique per region) makes the whole match ambiguous.
        """
        found: dict = {}
        ambiguous: set = set()
        for member in member_ids:
            rid, candidates = self._typed_name_candidates(
                member, resource_type, region
            )
            if rid is not None:
                found[rid] = self.by_resource[rid]
            ambiguous.update(candidates)
        if ambiguous:
            return BilledCostMatch(
                ambiguous=True, candidates=tuple(sorted(ambiguous))
            )
        return BilledCostMatch(
            rollup=_sum_rollups(resource_id, list(found.values()))
        )

    def rollup_for(
        self,
        resource_id: str,
        *,
        secretsmanager_secret: bool = False,
        resource_type=None,
        region: Optional[str] = None,
        lb_type: Optional[str] = None,
        cur_resource_id: Optional[str] = None,
        member_ids: Optional[Sequence[str]] = None,
    ) -> Optional[BilledCostRollup]:
        """The one CUR rollup this finding matches, or ``None``.

        ``None`` covers both "absent" and "ambiguous"; :meth:`match_for`
        tells them apart (CLO-739) and documents the matching order.
        """
        return self.match_for(
            resource_id,
            secretsmanager_secret=secretsmanager_secret,
            resource_type=resource_type,
            region=region,
            lb_type=lb_type,
            cur_resource_id=cur_resource_id,
            member_ids=member_ids,
        ).rollup

    def match_for(
        self,
        resource_id: str,
        *,
        secretsmanager_secret: bool = False,
        resource_type=None,
        region: Optional[str] = None,
        lb_type: Optional[str] = None,
        cur_resource_id: Optional[str] = None,
        member_ids: Optional[Sequence[str]] = None,
    ) -> BilledCostMatch:
        """Exact match first, then unambiguous alias in either direction.

        ``secretsmanager_secret`` (CLO-736): the finding is a Secrets Manager
        secret named the way ``ListSecrets`` names it, so the secret-name
        index is consulted before the shared aliases. Every other finding
        never sees that index.

        ``resource_type`` / ``region`` (CLO-737): for a resource type with a
        name index (``_TYPED_NAME_DERIVERS``), that index is consulted before
        the shared aliases, narrowed to the finding's region. Findings of any
        other type never see it. When it has no single answer the shared
        aliases are tried exactly as before. ``lb_type`` (the load balancer
        detectors' ``metadata["lb_type"]``) narrows a load balancer name to
        the right kind, since a CLB and an ALB may share a name.

        CLO-739: an index that has the name under more than one resource
        falls through to the next, exactly as before. Only when no stage
        finds a unique match and at least one stage found several, whose
        bills disagree, is the result ``ambiguous``. A later unique match
        still wins. See :class:`BilledCostMatch` for the all-$0 case.

        ``cur_resource_id`` (CLO-740): the id the CUR bills this resource
        under, when the detector knows it and it cannot be derived from
        ``resource_id`` (Lightsail: the finding carries the name, the CUR a
        ``...:Instance/<uuid>`` ARN). It is authoritative: when it is given
        and has no CUR rows, the resource is absent, and no name alias is
        tried, since an alias hit could only be some other resource's bill.

        Rollup types (CLO-740, ``_TYPED_ROLLUP_DERIVERS``): a REST API's
        stages in the finding's region are summed into one rollup. With no
        stage there, the remaining stages run exactly as before.

        ``member_ids``: the names of the resources AWS bills for this
        finding, when the finding names a group the CUR never bills (an
        ElastiCache replication group: the CUR bills each member node). For
        a type with a name index and a real region, each member is found in
        that index and their rollups are summed. Like ``cur_resource_id``
        this is authoritative: no member billed is absence, and the group id
        is not tried as an alias. An Aurora, DocumentDB or Neptune cluster
        (CLO-810) names its member instances as ``db:<instance id>`` and its
        storage/I/O as ``cluster:<DbClusterResourceId>``, whichever its saving
        comes out of (:func:`_rds_cluster_bill_key`).
        """
        if cur_resource_id:
            return BilledCostMatch(rollup=self.by_resource.get(cur_resource_id))

        direct = self.by_resource.get(resource_id)
        if direct is not None:
            return BilledCostMatch(rollup=direct)

        rtype = _resource_type_key(resource_type)
        if (
            member_ids
            and rtype in _TYPED_NAME_DERIVERS
            and region
            and region != "global"
        ):
            return self._member_match(resource_id, member_ids, resource_type, region)

        summed = self._typed_rollup(resource_id, resource_type, region)
        if summed is not None:
            return BilledCostMatch(rollup=summed)

        candidates: set = set()

        if secretsmanager_secret:
            secret_rid = self.by_secret_name.get(resource_id)
            if secret_rid is not None:
                return BilledCostMatch(rollup=self.by_resource.get(secret_rid))
            candidates.update(self.ambiguous_secret_names.get(resource_id, ()))

        typed_rid, typed_candidates = self._typed_name_candidates(
            resource_id, resource_type, region, lb_type
        )
        if typed_rid is not None:
            return BilledCostMatch(rollup=self.by_resource.get(typed_rid))
        candidates.update(typed_candidates)

        # Finding holds a bare name, CUR holds the ARN.
        aliased = self.by_alias.get(resource_id)
        if aliased is not None:
            return BilledCostMatch(rollup=self.by_resource.get(aliased))
        candidates.update(self.ambiguous_aliases.get(resource_id, ()))

        # Finding holds an ARN, CUR holds the bare name.
        for alias in resource_id_aliases(resource_id):
            hit = self.by_resource.get(alias)
            if hit is not None:
                return BilledCostMatch(rollup=hit)

        # The CUR query spans the whole account, so a name may collide only
        # in other regions. Those resources cannot be this finding's: drop
        # them, or a correct "not billed" verdict would turn ambiguous. Ids
        # with no ARN region (bare ids, S3, IAM) are kept.
        if region and region != "global":
            candidates = {
                rid for rid in candidates if _arn_region(rid) in ("", region)
            }
        if not candidates:
            return BilledCostMatch()
        rollups = [self.by_resource[rid] for rid in candidates if rid in self.by_resource]
        if rollups and all(
            r.billed_total <= 0 and not r.has_discount_line_items for r in rollups
        ):
            # Every candidate bills $0: whichever is the finding's, AWS is
            # not charging for it. Same verdict as an absent resource, but
            # flagged: these are rows, so "not billed yet" cannot apply.
            return BilledCostMatch(zero_billed_candidates=True)
        ordered = tuple(sorted(candidates))
        logger.debug(
            "Ambiguous CUR match for %s (region %s): candidates %s",
            resource_id,
            region,
            ordered,
        )
        return BilledCostMatch(ambiguous=True, candidates=ordered)


#: CLO-234 follow-up (not-yet-billed): resource types AWS bills by the hour
#: for as long as they exist, with no usage dimension that could leave an
#: existing resource without a CUR line. An Elastic IP bills $0.005/hour
#: allocated, attached or not (public IPv4 pricing, February 2024). Free-tier
#: hours still land as CUR rows at $0, which read as ``CONFIRMED_ZERO_BILLED``
#: through the rows branch, so for these types *absence* of rows on a
#: populated resource-level CUR means the report has not billed it yet (or
#: cannot name it), never that AWS charges nothing. This is per-type
#: knowledge, which CLO-234 otherwise avoids; it is here only because
#: ``DescribeAddresses`` returns no allocation time, so the age rule below
#: has nothing to compare for an EIP. Matched on the value, like
#: ``CUR_NOT_ATTRIBUTABLE_RESOURCE_TYPE``.
BILLED_WHILE_ALLOCATED_RESOURCE_TYPES = frozenset({"elastic_ip"})


def latest_usage_date_of(usage_dates) -> Optional[date]:
    """The latest ``YYYY-MM-DD`` usage date in ``usage_dates``, or ``None``.

    Adapters collect the account's distinct ``usage_date`` strings while
    reading the window; this turns them into
    :attr:`BilledCostLookup.latest_usage_date`. Unparseable values are
    skipped rather than raised, per the port's never-raise contract.
    """
    latest: Optional[date] = None
    for raw in usage_dates or ():
        try:
            d = date.fromisoformat(str(raw)[:10])
        except ValueError:
            continue
        if latest is None or d > latest:
            latest = d
    return latest


def _as_utc_datetime(value) -> Optional[datetime]:
    """A detector's ``resource_created_at`` (ISO string or datetime) in UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _not_yet_billed(
    *,
    lookup: "BilledCostLookup",
    match: "BilledCostMatch",
    estimated_savings: float,
    resource_type,
    resource_created_at,
) -> bool:
    """Is a finding with no CUR rows too young for the CUR to have billed it?

    The rule, applied only after every earlier branch of
    :func:`reconcile_savings` has passed (resource-level CUR present, a
    populated window, not ambiguous, no discount lines):

    - The match found **no rows at all** for the resource. Rows that sum to
      $0, and an ambiguous name whose candidates all bill $0, are positive
      evidence of a $0 bill and stay ``CONFIRMED_ZERO_BILLED`` at any age
      (the free-tier and free-trial cases CLO-234 exists for).
    - The estimate is above $0: a $0 estimate has nothing to keep.
    - And one of:

      a. The detector supplied the resource's creation time
         (``metadata["resource_created_at"]``), the lookup knows the CUR's
         latest covered usage day ``L``, and the resource was created on or
         after ``L`` 00:00 UTC. ``L`` itself counts: the CUR refreshes a day
         in several passes, so a resource created during ``L`` may not have
         a row for it yet. A resource created before ``L`` with no rows is
         old enough to have been billed, and keeps ``CONFIRMED_ZERO_BILLED``.
      b. The resource type bills by the hour while it exists
         (``BILLED_WHILE_ALLOCATED_RESOURCE_TYPES``) and so cannot be both
         present and absent from a populated CUR for any reason but lag or
         an id the CUR does not use. No creation time is needed.

    Without either, absence keeps meaning "not billed", as before: an unknown
    creation time is never read as "young".
    """
    if match.rollup is not None or match.zero_billed_candidates:
        return False
    if estimated_savings <= 0:
        return False
    if _resource_type_key(resource_type) in BILLED_WHILE_ALLOCATED_RESOURCE_TYPES:
        return True
    created = _as_utc_datetime(resource_created_at)
    if created is None or lookup.latest_usage_date is None:
        return False
    return created.date() >= lookup.latest_usage_date


@dataclass(frozen=True)
class ReconciliationOutcome:
    """What reconciliation decided for one finding.

    Mirrors the sibling fields carried on ``WasteItem``.
    """

    monthly_savings: float
    reconciliation_status: str
    billed_cost_observed: Optional[float] = None
    cost_basis: Optional[str] = None

    @property
    def is_reconciled(self) -> bool:
        return self.reconciliation_status not in ReconciliationStatus.UNRECONCILED


# ---------------------------------------------------------------------------
# The reconciliation decision (pure — no I/O, fully unit-testable)
# ---------------------------------------------------------------------------


def reconcile_savings(
    *,
    estimated_savings: float,
    resource_id: str,
    lookup: Optional[BilledCostLookup],
    min_days_covered: int = DEFAULT_MIN_DAYS_COVERED,
    secretsmanager_secret: bool = False,
    resource_type=None,
    region: Optional[str] = None,
    lb_type: Optional[str] = None,
    cur_resource_id: Optional[str] = None,
    waste_type=None,
    member_ids: Optional[Sequence[str]] = None,
    resource_created_at=None,
    running_tasks=None,
) -> ReconciliationOutcome:
    """Reconcile one finding's list-price estimate against actual billed cost.

    ``secretsmanager_secret``, ``resource_type``, ``region``, ``lb_type``,
    ``cur_resource_id``, ``member_ids``: see :meth:`BilledCostLookup.match_for`. ``waste_type``
    with ``resource_type``: see ``CUR_NOT_ATTRIBUTABLE_WASTE_TYPES``.
    ``running_tasks`` with ``waste_type``: see ``CUR_ACCOUNT_WIDE_WASTE_TYPES``.
    ``resource_created_at`` (ISO string or datetime, from the detector's
    ``metadata["resource_created_at"]``): see :func:`_not_yet_billed`.

    Order matters, and each branch is a deliberate safety choice:

    1. No lookup / no resource-level CUR → estimate stands, labelled. Never
       guess.
    2. The account's own window is too thin → labelled, *not* zeroed. Stops a
       barely-populated CUR from deleting every finding.
    3. A finding the CUR cannot attribute (an ECS service, billed by task) →
       labelled, *not* zeroed (CLO-740). Decided before any match: a row that
       happens to share its name is not its bill.
    3a. Container Insights on a cluster that is running tasks (CLO-746) →
       labelled, *not* zeroed. Its metric charges are billed account-wide
       with no per-cluster resource id, so a miss is not "not billed". An
       empty cluster skips this and takes the ordinary path below.
    4. The finding's name matched several CUR resources and none uniquely →
       labelled, *not* zeroed (CLO-739). We cannot tell which bill is its,
       so we cannot claim it has none.
    5. Discount line items → labelled. We have no amortized column, so we
       cannot say by how much the bill disagrees, only that it does.
    6. No rows at all, for a resource younger than the CUR's latest covered
       day (or of a type billed while it exists) → labelled, *not* zeroed:
       the CUR has not billed it yet. See :func:`_not_yet_billed`.
    7. No rows, or rows summing to $0, on an account that demonstrably *has*
       resource-level CUR → genuinely not billed. This is the free-tier fix.
    8. Too few days on this specific resource → labelled, not zeroed.
    9. Otherwise cap: ``min(estimate, monthly-equivalent billed)``.
    """
    if lookup is None or not lookup.resource_ids_present:
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=ReconciliationStatus.UNRECONCILED_NO_CUR,
        )

    if lookup.account_days_covered < min_days_covered:
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=(
                ReconciliationStatus.UNRECONCILED_INSUFFICIENT_DATA
            ),
        )

    # CLO-740: the CUR bills this finding's tasks, not its service, so a miss
    # here is not "not billed" and a same-named row is not its bill.
    if (
        _resource_type_key(resource_type) == CUR_NOT_ATTRIBUTABLE_RESOURCE_TYPE
        and _resource_type_key(waste_type) in CUR_NOT_ATTRIBUTABLE_WASTE_TYPES
        and estimated_savings > 0
    ):
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=(
                ReconciliationStatus.UNRECONCILED_NOT_ATTRIBUTABLE
            ),
        )

    # CLO-746: Container Insights is billed as account-wide CloudWatch metrics,
    # so a cluster that is running tasks has no row of its own. Decided before
    # any match, like CLO-740. An empty cluster takes the ordinary path.
    if (
        _resource_type_key(waste_type) in CUR_ACCOUNT_WIDE_WASTE_TYPES
        and estimated_savings > 0
        and isinstance(running_tasks, (int, float))
        and not isinstance(running_tasks, bool)
        and running_tasks > 0
    ):
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=(
                ReconciliationStatus.UNRECONCILED_BILLED_ACCOUNT_WIDE
            ),
        )

    match = lookup.match_for(
        resource_id,
        secretsmanager_secret=secretsmanager_secret,
        resource_type=resource_type,
        region=region,
        lb_type=lb_type,
        cur_resource_id=cur_resource_id,
        member_ids=member_ids,
    )

    # CLO-739: "couldn't tell which resource" is not "not billed". Keep the
    # estimate; zeroing here is what dropped a $33.87 idle SageMaker endpoint
    # whose name its own log group shared.
    if match.ambiguous:
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=ReconciliationStatus.UNRECONCILED_AMBIGUOUS,
        )

    rollup = match.rollup

    if rollup is not None and rollup.has_discount_line_items:
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=ReconciliationStatus.UNRECONCILED_DISCOUNTED,
            billed_cost_observed=rollup.monthly_equivalent(),
            cost_basis=rollup.cost_basis,
        )

    # No rows at all, and the resource is too young for the CUR to have
    # billed it (or bills while it exists). "Not in the report yet" is not
    # "AWS bills $0": keep the estimate, labelled, until the CUR catches up.
    if _not_yet_billed(
        lookup=lookup,
        match=match,
        estimated_savings=estimated_savings,
        resource_type=resource_type,
        resource_created_at=resource_created_at,
    ):
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=ReconciliationStatus.UNRECONCILED_NOT_YET_BILLED,
        )

    # No rows for this resource, or rows that sum to nothing. The account has
    # resource-level CUR over a populated window, so AWS is not charging for
    # this resource: deleting it saves the customer $0.
    if rollup is None or rollup.billed_total <= 0:
        return ReconciliationOutcome(
            monthly_savings=0.0,
            reconciliation_status=ReconciliationStatus.CONFIRMED_ZERO_BILLED,
            billed_cost_observed=0.0,
            cost_basis=rollup.cost_basis if rollup else None,
        )

    if rollup.days_covered < min_days_covered:
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=(
                ReconciliationStatus.UNRECONCILED_INSUFFICIENT_DATA
            ),
            billed_cost_observed=rollup.monthly_equivalent(),
            cost_basis=rollup.cost_basis,
        )

    billed_monthly = rollup.monthly_equivalent()
    assert billed_monthly is not None  # days_covered >= min_days_covered > 0

    return ReconciliationOutcome(
        # Cap, don't replace: a right-sizing finding claims the delta between
        # two instance sizes, which is legitimately less than the full billed
        # cost of the resource.
        monthly_savings=min(estimated_savings, billed_monthly),
        reconciliation_status=ReconciliationStatus.RECONCILED,
        billed_cost_observed=billed_monthly,
        cost_basis=rollup.cost_basis,
    )


def reconcile_commitment_savings(
    *,
    estimated_savings: float,
    covering_monthly_spend: Optional[float],
) -> ReconciliationOutcome:
    """Reconcile a commitment finding without per-resource CUR matching.

    RI/SP purchase recommendations and existing-commitment findings (unused,
    expiring or convertible RI/SP, Savings Plan coverage gaps) do not name a
    single billed resource. ``resource_id`` on these is a label the detector
    invented for display — an instance type (``m5.xlarge``), a plan class
    (``"Savings Plan"``, ``"Savings Plan Coverage"``) — or an RI/SP entity id
    (``reserved_instances_id``, a Savings Plan ARN) that AWS's CUR does not
    bill line items against: ``lineItem/ResourceId`` is blank on RIFee and
    SavingsPlan*Fee rows (the recurring-fee charge belongs to the commitment
    itself, not to one instance), so our ingest stores those rows under the
    ``NO_RESOURCE_ID`` placeholder and they never enter the per-resource CUR
    index built in ``lambdas/waste_detection_region_scanner/adapters.py``.

    Feeding either shape through :func:`reconcile_savings` therefore always
    misses, and on any account with resource-level CUR the miss reads as
    "AWS bills $0 for this" — ``CONFIRMED_ZERO_BILLED`` — silently dropping
    a real recommendation below ``min_waste_threshold_usd``. These estimates
    are not the list-price arithmetic CLO-234 was written to catch either:
    they come from AWS Cost Explorer's own utilization, coverage and
    recommendation APIs, already in actual dollars. There is nothing to
    reconcile per-resource, so we cap against whatever aggregate covering
    spend the detector itself already computed (unused fee, total
    commitment, on-demand spend covered) instead — the same "cap, don't
    replace" discipline as :func:`reconcile_savings`, at the service level
    rather than the resource level.

    ``covering_monthly_spend`` of ``None`` means the detector had no such
    figure to offer (the RI/SP purchase-recommendation types: the estimate
    is already Cost Explorer's own number, with no larger covering figure to
    check it against) — the estimate stands, labelled.
    """
    if covering_monthly_spend is None:
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=ReconciliationStatus.UNRECONCILED_COMMITMENT,
        )

    return ReconciliationOutcome(
        monthly_savings=min(estimated_savings, covering_monthly_spend),
        reconciliation_status=ReconciliationStatus.RECONCILED_COMMITMENT,
        billed_cost_observed=covering_monthly_spend,
    )


# ---------------------------------------------------------------------------
# Port Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class BilledCostPort(Protocol):
    """Batched trailing-actual-cost lookup, keyed by resource id.

    Implementations MUST:
    - swallow backend errors (log at WARNING; never raise) and return ``None``,
      which degrades findings to ``UNRECONCILED_NO_CUR`` rather than zeroing
      them,
    - read raw rows, **retaining zero-cost and negative rows** — the CUR
      readers on the normal reporting path drop ``cost <= 0``, which would make
      a free-tier resource indistinguishable from one with no CUR at all,
    - issue one batched query per (account, window), not one per resource.
    """

    def get_billed_costs(
        self,
        *,
        user_id: str,
        account_id: str,
        resource_ids: Sequence[str],
        start_date: date,
        end_date: date,
    ) -> Optional[BilledCostLookup]:  # pragma: no cover - Protocol
        ...


@runtime_checkable
class BilledCostProvider(Protocol):
    """Factory returning a ``BilledCostPort`` (or ``None`` if not configured)."""

    def __call__(self) -> Optional[BilledCostPort]:  # pragma: no cover - Protocol
        ...


class NullBilledCostLookup:
    """Default no-op adapter: every lookup is a miss.

    Findings then carry ``UNRECONCILED_NO_CUR`` and keep their list-price
    estimate — visible, not silent.
    """

    def get_billed_costs(
        self,
        *,
        user_id: str,
        account_id: str,
        resource_ids: Sequence[str],
        start_date: date,
        end_date: date,
    ) -> Optional[BilledCostLookup]:
        return None
