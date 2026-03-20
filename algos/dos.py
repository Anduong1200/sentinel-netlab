#!/usr/bin/env python3
"""
Sentinel NetLab - Deauth Flood Detector
"""

import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from common.ttl_dict import TTLDict

logger = logging.getLogger(__name__)


@dataclass
class DeauthFloodAlert:
    """Alert for deauth flood detection"""

    alert_id: str
    timestamp: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    target_bssid: str
    target_client: str | None
    frame_count: int
    window_seconds: float
    rate_per_sec: float
    evidence: dict
    reason_codes: list[str]  # Human-readable codes
    mitre_attack: str = "T1499.001"


class DeauthFloodDetector:
    """
    Detects deauthentication flood attacks by:
    1. Tracking deauth frame rate per BSSID/client
    2. Sliding window analysis
    3. Burst pattern detection
    """

    def __init__(
        self,
        threshold_per_sec: float = 10.0,
        window_seconds: float = 2.0,
        cooldown_seconds: float = 60.0,
        state_file: str = ".dos_state.json",
    ):
        self.threshold_per_sec = threshold_per_sec
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        self.state_file = state_file

        # Track deauth frames: (bssid, client) -> [timestamps]
        # Bounded to prevent OOM on edge devices (Pi 1-2GB RAM)
        self.deauth_history: TTLDict = TTLDict(maxsize=5000, ttl=300.0)

        # Cooldown tracking — TTL = 2x cooldown to allow natural expiry
        self.last_alert: TTLDict = TTLDict(
            maxsize=5000, ttl=cooldown_seconds * 2
        )
        self._load_state()

        self.alert_count = 0

    def record_deauth(
        self, bssid: str, client_mac: str = "ff:ff:ff:ff:ff:ff", sensor_id: str = ""
    ) -> DeauthFloodAlert | None:
        """
        Record a deauth frame and check for flood.
        Returns alert if flood detected.
        """
        now = time.time()
        key = (bssid, client_mac)

        # Add timestamp (setdefault returns existing list or creates new)
        history = self.deauth_history.setdefault(key, [])
        history.append(now)
        self.deauth_history[key] = history  # refresh TTL

        # Clean old entries
        self._cleanup(key, now)

        # Check for flood
        return self._check_flood(key, bssid, client_mac, sensor_id, now)

    def _cleanup(self, key: tuple[str, str], now: float):
        """Remove entries outside the window"""
        history = self.deauth_history.get(key, [])
        cutoff = now - self.window_seconds * 2  # Keep 2x window for analysis
        filtered = [t for t in history if t >= cutoff]
        if filtered:
            self.deauth_history[key] = filtered
        elif key in self.deauth_history:
            del self.deauth_history[key]

    def _check_flood(
        self,
        key: tuple[str, str],
        bssid: str,
        client_mac: str,
        sensor_id: str,
        now: float,
    ) -> DeauthFloodAlert | None:
        """Check if current rate exceeds threshold"""
        # Check cooldown
        last = self.last_alert.get(key)
        if last is not None:
            if now - last < self.cooldown_seconds:
                return None

        # Count frames in window
        window_start = now - self.window_seconds
        history = self.deauth_history.get(key, [])
        frames_in_window = [t for t in history if t >= window_start]
        count = len(frames_in_window)

        # Calculate rate
        rate = count / self.window_seconds

        if rate >= self.threshold_per_sec:
            self.last_alert[key] = now
            self._save_state()
            return self._create_alert(bssid, client_mac, count, rate, sensor_id)

        return None

    def _create_alert(
        self, bssid: str, client_mac: str, count: int, rate: float, sensor_id: str
    ) -> DeauthFloodAlert:
        """Create deauth flood alert"""
        self.alert_count += 1

        # Determine severity based on rate
        if rate >= self.threshold_per_sec * 5:
            severity = "CRITICAL"
        elif rate >= self.threshold_per_sec * 2:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        # Build reason codes
        is_broadcast = client_mac == "ff:ff:ff:ff:ff:ff"
        reason_codes = [
            "DEAUTH_FLOOD",
            f"RATE_{int(rate)}_PER_SEC",
        ]
        if is_broadcast:
            reason_codes.append("BROADCAST_TARGET")
        else:
            reason_codes.append("TARGETED_CLIENT")

        return DeauthFloodAlert(
            alert_id=f"DF-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{self.alert_count:04d}",
            timestamp=datetime.now(UTC).isoformat(),
            severity=severity,
            target_bssid=bssid,
            target_client=client_mac if not is_broadcast else None,
            frame_count=count,
            window_seconds=self.window_seconds,
            rate_per_sec=rate,
            evidence={
                "sensor_id": sensor_id,
                "threshold_per_sec": self.threshold_per_sec,
                "is_broadcast": is_broadcast,
            },
            reason_codes=reason_codes,
        )

    def get_stats(self) -> dict:
        """Get current detection statistics"""
        total_tracked = sum(len(v) for v in self.deauth_history.values())
        return {
            "tracked_pairs": len(self.deauth_history),
            "total_recent_frames": total_tracked,
            "alerts_generated": self.alert_count,
        }

    def _save_state(self):
        """Persist cooldown state to file"""
        try:
            # Convert keys from tuple to string for JSON
            state = {f"{k[0]}|{k[1]}": v for k, v in self.last_alert.items()}
            with open(self.state_file, "w") as f:
                json.dump(state, f)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")

    def _load_state(self):
        """Load cooldown state from file"""
        if not os.path.exists(self.state_file):
            return

        try:
            with open(self.state_file) as f:
                state = json.load(f)

            now = time.time()
            for k_str, timestamp in state.items():
                # Only load if still in cooldown window (plus buffer)
                if now - timestamp < self.cooldown_seconds:
                    parts = k_str.split("|")
                    if len(parts) == 2:
                        self.last_alert[(parts[0], parts[1])] = timestamp
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
