"""The open core's waste detection service (FSL-1.1-ALv2).

The same orchestration as the hosted product (``WasteDetectionServiceBase``)
with only the open detector mixins, and the registry narrowed to the 20
service entrypoints in ``FREE_TIER_DETECTORS`` (CLO-562). The local CLI and
MCP server build on this class.
"""

from typing import Dict, List, Set

from cloudwise_scan_core.detectors.open import (
    ComputeOptimizerDetectorsMixin,
    OpenComputeDetectorsMixin,
    OpenDatabaseDetectorsMixin,
    OpenManagementDetectorsMixin,
    OpenNetworkDetectorsMixin,
    OpenStorageDetectorsMixin,
    SavingsOpportunitiesDetectorsMixin,
    SecurityPostureDetectorsMixin,
)
from cloudwise_scan_core.tier_routing import FREE_TIER_DETECTORS
from cloudwise_scan_core.waste_detection_service import (
    ALWAYS_RUN_DETECTORS,
    DETECTOR_METHODS,
    GLOBAL_SERVICE_DETECTORS,
    SERVICE_TO_DETECTORS,
    WasteDetectionServiceBase,
)

OPEN_DETECTOR_METHODS: Dict[str, str] = {
    key: method for key, method in DETECTOR_METHODS.items() if key in FREE_TIER_DETECTORS
}


class OpenWasteDetectionService(
    WasteDetectionServiceBase,
    OpenComputeDetectorsMixin,
    OpenStorageDetectorsMixin,
    OpenDatabaseDetectorsMixin,
    OpenNetworkDetectorsMixin,
    OpenManagementDetectorsMixin,
    ComputeOptimizerDetectorsMixin,
    SavingsOpportunitiesDetectorsMixin,
    SecurityPostureDetectorsMixin,
):
    """Waste detection over the open service entrypoints only."""

    DETECTOR_METHODS: Dict[str, str] = OPEN_DETECTOR_METHODS
    ALWAYS_RUN_DETECTORS: Set[str] = ALWAYS_RUN_DETECTORS & FREE_TIER_DETECTORS
    GLOBAL_SERVICE_DETECTORS: Set[str] = GLOBAL_SERVICE_DETECTORS & FREE_TIER_DETECTORS
    SERVICE_TO_DETECTORS: Dict[str, List[str]] = {
        service: [key for key in keys if key in FREE_TIER_DETECTORS]
        for service, keys in SERVICE_TO_DETECTORS.items()
        if any(key in FREE_TIER_DETECTORS for key in keys)
    }
