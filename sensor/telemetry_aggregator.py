import threading
import time


class TelemetryAggregator:
    """
    Aggregates telemetry for stateful analysis (sliding windows).
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self.deauth_counts: dict[str, int] = {}
        self.last_cleanup = time.time()
        self._lock = threading.Lock()

    def record_frame(self, frame_type: str, subtype: str, source: str):
        """Record frame occurrence"""
        with self._lock:
            if subtype == "deauth":
                self.deauth_counts[source] = self.deauth_counts.get(source, 0) + 1

            # Cleanup old windows periodically
            if time.time() - self.last_cleanup > self.window_seconds:
                self.deauth_counts.clear()
                self.last_cleanup = time.time()

    def get_context(self) -> dict:
        """Get current aggregation context for risk engine"""
        with self._lock:
            return {"deauth_counts": self.deauth_counts.copy()}
