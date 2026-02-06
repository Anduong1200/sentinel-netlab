
from abc import ABC, abstractmethod
from typing import Any

from common.detection.evidence import Finding


class AbstractDetector(ABC):
    """
    Base contract for all Controller-side detectors.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def process(self, telemetry: dict[str, Any], context: dict[str, Any] | None = None) -> list[Finding]:
        """
        Analyze telemetry data and return a list of Findings.
        
        Args:
            telemetry: Dictionary containing standard telemetry (ssid, bssid, rssi_dbm, etc.)
            context: Optional context (e.g., site_id, sensor_id)
            
        Returns:
            List[Finding]: List of potential security issues found.
        """
        pass
