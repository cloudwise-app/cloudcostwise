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
from dataclasses import dataclass, field
from datetime import date
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

    #: Every status that leaves ``monthly_savings`` at the list-price estimate.
    UNRECONCILED = frozenset(
        {
            UNRECONCILED_NO_CUR,
            UNRECONCILED_DISCOUNTED,
            UNRECONCILED_INSUFFICIENT_DATA,
            UNRECONCILED_COMMITMENT,
        }
    )


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

    #: Unambiguous alias → resource id, for the ARN/bare-name mismatch above.
    #: Built by :meth:`build`; ambiguous aliases are deliberately omitted.
    by_alias: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        rollups,
        *,
        resource_ids_present: bool,
        account_days_covered: int = 0,
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

        return cls(
            by_resource=by_resource,
            resource_ids_present=resource_ids_present,
            account_days_covered=account_days_covered,
            by_alias=by_alias,
        )

    def rollup_for(self, resource_id: str) -> Optional[BilledCostRollup]:
        """Exact match first, then unambiguous alias in either direction."""
        direct = self.by_resource.get(resource_id)
        if direct is not None:
            return direct

        # Finding holds a bare name, CUR holds the ARN.
        aliased = self.by_alias.get(resource_id)
        if aliased is not None:
            return self.by_resource.get(aliased)

        # Finding holds an ARN, CUR holds the bare name.
        for alias in resource_id_aliases(resource_id):
            hit = self.by_resource.get(alias)
            if hit is not None:
                return hit
        return None


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
) -> ReconciliationOutcome:
    """Reconcile one finding's list-price estimate against actual billed cost.

    Order matters, and each branch is a deliberate safety choice:

    1. No lookup / no resource-level CUR → estimate stands, labelled. Never
       guess.
    2. The account's own window is too thin → labelled, *not* zeroed. Stops a
       barely-populated CUR from deleting every finding.
    3. Discount line items → labelled. We have no amortized column, so we
       cannot say by how much the bill disagrees, only that it does.
    4. No rows, or rows summing to $0, on an account that demonstrably *has*
       resource-level CUR → genuinely not billed. This is the free-tier fix.
    5. Too few days on this specific resource → labelled, not zeroed.
    6. Otherwise cap: ``min(estimate, monthly-equivalent billed)``.
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

    rollup = lookup.rollup_for(resource_id)

    if rollup is not None and rollup.has_discount_line_items:
        return ReconciliationOutcome(
            monthly_savings=estimated_savings,
            reconciliation_status=ReconciliationStatus.UNRECONCILED_DISCOUNTED,
            billed_cost_observed=rollup.monthly_equivalent(),
            cost_basis=rollup.cost_basis,
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
