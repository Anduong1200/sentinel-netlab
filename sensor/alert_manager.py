"""
Sentinel NetLab - Alert Manager
Handles alert deduplication, aggregation, and triage before transmission.
"""

import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Manages alert lifecycle:
    - Deduplication (suppress duplicate alerts within time window)
    - Aggregation (group related events) [Future]
    """

    def __init__(self, dedup_window: int = 600):
        """
        Args:
            dedup_window: Time in seconds to suppress identical alerts (default 10 mins)
        """
        self.dedup_window = dedup_window
        self._dedup_cache: dict[str, float] = {}
        self._lock = threading.Lock()

    def process(self, alert: dict[str, Any]) -> bool:
        """
        Process an alert.
        Returns True if alert should be sent, False if suppressed.
        """
        # Generate stable key
        # Key components: Type, Severity, Title, BSSID (if wireless)
        key_parts = [
            str(alert.get("alert_type", "unknown")),
            str(alert.get("severity", "unknown")),
            str(alert.get("bssid", "global")),
            str(alert.get("title", ""))
        ]
        key = "|".join(key_parts)

        with self._lock:
            now = time.time()
            last_seen = self._dedup_cache.get(key, 0)

            # Cleanup old entries periodically (lazy cleanup)
            if len(self._dedup_cache) > 1000:
                self._cleanup(now)

            if now - last_seen < self.dedup_window:
                # Suppress
                logger.debug(f"Suppressed duplicate alert: {key}")
                return False

            # Allow and update timestamp
            self._dedup_cache[key] = now
            return True

    def _cleanup(self, now: float):
        """Remove expired entries."""
        expired = [k for k, v in self._dedup_cache.items() if now - v > self.dedup_window]
        for k in expired:
            del self._dedup_cache[k]
