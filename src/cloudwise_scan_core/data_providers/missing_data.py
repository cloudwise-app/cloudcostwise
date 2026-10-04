"""Aggregated "MISSING, not zero" notes for withheld idle verdicts (CLO-485).

When a provider cannot measure a resource's activity (the metric read failed,
the series is empty or under the coverage an idle claim needs, or an
air-gapped export does not carry the metric), the idle verdict is withheld
rather than read as zero activity. The scan must say so, or a withheld
verdict is indistinguishable from a busy resource.

Like CLO-479's Lambda note (#1458), this keeps ONE aggregated
``data_warnings`` note per service on the provider instance (the online
provider is built per detector batch per region; the offline provider per
upload region), with the count, the reasons and a few example ids, and logs
one WARNING per service. ``waste_detection_service`` folds ``data_warnings``
into ``WasteDetectionResult.warnings``.
"""

import logging
from collections import Counter
from typing import Dict, List

logger = logging.getLogger(__name__)

# Example resource ids kept in a note; the count covers the rest.
_MAX_EXAMPLES = 3


class MissingDataNotesMixin:
    """Provider mixin. Needs ``self.data_warnings`` (a list), ``self._region``
    and ``self._account_id``."""

    def _note_idle_verdict_missing(
        self,
        service: str,
        resource_id: str,
        reason: str,
        verdict: str = "idle",
        evidence: str = "activity metrics",
    ) -> None:
        """Record that ``service``'s idle verdict for ``resource_id`` was
        withheld for ``reason`` (a short category such as "no datapoints",
        "under 75% coverage", "read failed (ClientError:Throttling)" or "not
        in export"), and refresh the service's single aggregated note.

        ``verdict`` and ``evidence`` name the withheld claim and the data it
        needed; the defaults give the idle wording. CLO-488 reuses the
        channel for s3_empty_bucket ("empty-bucket" verdict, "object
        listings" evidence)."""
        state: Dict[str, dict] = self.__dict__.setdefault('_idle_missing_by_service', {})
        entry = state.get(service)
        if entry is None:
            entry = {'ids': [], 'reasons': Counter(), 'note': None}
            state[service] = entry
            logger.warning(
                "%s %s verdict withheld for %s in account=%s region=%s: %s "
                "(MISSING, not zero; further %s resources are aggregated into the scan warning)",
                service, verdict, resource_id, getattr(self, '_account_id', '?'), self._region, reason,
                service,
            )
        if resource_id in entry['ids']:
            return
        entry['ids'].append(resource_id)
        entry['reasons'][reason] += 1

        count = len(entry['ids'])
        examples = ', '.join(entry['ids'][:_MAX_EXAMPLES])
        if count > _MAX_EXAMPLES:
            examples += ', ...'
        reasons = ', '.join(f"{r} x{n}" for r, n in sorted(entry['reasons'].items()))
        note = (
            f"{service}: {verdict} verdict withheld for {count} resource{'s' if count != 1 else ''} "
            f"in {self._region} ({examples}) because {evidence} were missing: {reasons}; "
            f"their {verdict} findings are MISSING from this scan, not zero"
        )
        warnings: List[str] = self.data_warnings
        if entry['note'] in warnings:
            warnings[warnings.index(entry['note'])] = note
        else:
            warnings.append(note)
        entry['note'] = note
