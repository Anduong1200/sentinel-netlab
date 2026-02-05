
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from common.detection.evidence import Finding

class AbstractDetector(ABC):
    """
    Base contract for all Controller-side detectors.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    @abstractmethod
    def process(self, telemetry: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        """
        Analyze telemetry data and return a list of Findings.
        
        Args:
            telemetry: Dictionary containing standard telemetry (ssid, bssid, rssi_dbm, etc.)
            context: Optional context (e.g., site_id, sensor_id)
            
        Returns:
            List[Finding]: List of potential security issues found.
        """
        pass
