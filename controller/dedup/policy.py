
from datetime import datetime, UTC, timedelta
from typing import Optional
from controller.dedup.store import EventState
from common.detection.evidence import Finding
from common.scoring.types import Severity

class TriagePolicy:
    """
    Decides if a Finding should be emitted as an Alert.
    Handles Suppression and Escalation.
    """
    
    def __init__(self, suppression_window_seconds: int = 3600):
        self.suppression_window = timedelta(seconds=suppression_window_seconds)

    def should_emit(self, finding: Finding, state: Optional[EventState], current_severity: Severity, current_risk: float) -> bool:
        """
        Decision Logic:
        1. New Event (No state) -> EMIT
        2. Escalation (Risk > Max Risk seen) -> EMIT
        3. Suppression (In window) -> SUPPRESS
        4. Re-occur (Outside window) -> EMIT
        """
        
        if not state:
            return True # New event
            
        # Check Escalation
        if current_risk > state.max_risk_score:
            return True # Severity increased (e.g. Medium -> Critical)
            
        # Check Suppression Window
        time_since_emit = datetime.now(UTC) - state.last_emitted
        if time_since_emit < self.suppression_window:
            return False # Suppressed
            
        return True # Window expired
