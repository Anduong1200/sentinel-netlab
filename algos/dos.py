#!/usr/bin/env python3
"""
Sentinel NetLab - Deauth Flood Detector
"""

import logging
import time
from datetime import datetime, timezone
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeauthFloodAlert:
    """Alert for deauth flood detection"""
    alert_id: str
    timestamp: str
    target_bssid: str
    target_client: Optional[str]
    frame_count: int
    window_seconds: float
    rate_per_sec: float
    evidence: Dict


class DeauthFloodDetector:
    """
    Detects deauthentication flood attacks by:
    1. Tracking deauth frame rate per BSSID/client
    2. Sliding window analysis
    3. Burst pattern detection
    """

    def __init__(self,
                 threshold_per_sec: float = 10.0,
                 window_seconds: float = 2.0,
                 cooldown_seconds: float = 60.0):
        self.threshold_per_sec = threshold_per_sec
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        # Track deauth frames: (bssid, client) -> [timestamps]
        self.deauth_history: Dict[Tuple[str, str],
                                  List[float]] = defaultdict(list)

        # Cooldown tracking
        self.last_alert: Dict[Tuple[str, str], float] = {}

        self.alert_count = 0

    def record_deauth(self,
                      bssid: str,
                      client_mac: str = "ff:ff:ff:ff:ff:ff",
                      sensor_id: str = "") -> Optional[DeauthFloodAlert]:
        """
        Record a deauth frame and check for flood.
        Returns alert if flood detected.
        """
        now = time.time()
        key = (bssid, client_mac)

        # Add timestamp
        self.deauth_history[key].append(now)

        # Clean old entries
        self._cleanup(key, now)

        # Check for flood
        return self._check_flood(key, bssid, client_mac, sensor_id, now)

    def _cleanup(self, key: Tuple[str, str], now: float):
        """Remove entries outside the window"""
        cutoff = now - self.window_seconds * 2  # Keep 2x window for analysis
        self.deauth_history[key] = [
            t for t in self.deauth_history[key] if t >= cutoff
        ]

    def _check_flood(self,
                     key: Tuple[str, str],
                     bssid: str,
                     client_mac: str,
                     sensor_id: str,
                     now: float) -> Optional[DeauthFloodAlert]:
        """Check if current rate exceeds threshold"""
        # Check cooldown
        if key in self.last_alert:
            if now - self.last_alert[key] < self.cooldown_seconds:
                return None

        # Count frames in window
        window_start = now - self.window_seconds
        frames_in_window = [
            t for t in self.deauth_history[key] if t >= window_start]
        count = len(frames_in_window)

        # Calculate rate
        rate = count / self.window_seconds

        if rate >= self.threshold_per_sec:
            self.last_alert[key] = now
            return self._create_alert(
                bssid, client_mac, count, rate, sensor_id)

        return None

    def _create_alert(self,
                      bssid: str,
                      client_mac: str,
                      count: int,
                      rate: float,
                      sensor_id: str) -> DeauthFloodAlert:
        """Create deauth flood alert"""
        self.alert_count += 1

        return DeauthFloodAlert(
            alert_id=f"DF-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self.alert_count:04d}",
            timestamp=datetime.now(
                timezone.utc).isoformat(),
            target_bssid=bssid,
            target_client=client_mac if client_mac != "ff:ff:ff:ff:ff:ff" else None,
            frame_count=count,
            window_seconds=self.window_seconds,
            rate_per_sec=rate,
            evidence={
                'sensor_id': sensor_id,
                'threshold_per_sec': self.threshold_per_sec,
                'is_broadcast': client_mac == "ff:ff:ff:ff:ff:ff"})

    def get_stats(self) -> Dict:
        """Get current detection statistics"""
        total_tracked = sum(len(v) for v in self.deauth_history.values())
        return {
            'tracked_pairs': len(self.deauth_history),
            'total_recent_frames': total_tracked,
            'alerts_generated': self.alert_count
        }
