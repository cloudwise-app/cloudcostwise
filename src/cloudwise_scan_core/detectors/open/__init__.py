"""Open-core detectors (FSL-1.1-ALv2).

The 20 service entrypoints in ``tier_routing.FREE_TIER_DETECTORS`` and every
method they call. Nothing in this package may import a closed detector module;
``tests/test_open_core_boundary.py`` enforces it.
"""

from cloudwise_scan_core.detectors.open.compute import OpenComputeDetectorsMixin
from cloudwise_scan_core.detectors.open.storage import OpenStorageDetectorsMixin
from cloudwise_scan_core.detectors.open.database import OpenDatabaseDetectorsMixin
from cloudwise_scan_core.detectors.open.network import OpenNetworkDetectorsMixin
from cloudwise_scan_core.detectors.open.management import OpenManagementDetectorsMixin
from cloudwise_scan_core.detectors.open.optimizer import ComputeOptimizerDetectorsMixin
from cloudwise_scan_core.detectors.open.savings import SavingsOpportunitiesDetectorsMixin
from cloudwise_scan_core.detectors.open.security import SecurityPostureDetectorsMixin

__all__ = [
    'OpenComputeDetectorsMixin',
    'OpenStorageDetectorsMixin',
    'OpenDatabaseDetectorsMixin',
    'OpenNetworkDetectorsMixin',
    'OpenManagementDetectorsMixin',
    'ComputeOptimizerDetectorsMixin',
    'SavingsOpportunitiesDetectorsMixin',
    'SecurityPostureDetectorsMixin',
]
