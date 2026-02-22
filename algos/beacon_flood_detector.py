#!/usr/bin/env python3
"""
Sentinel NetLab - Beacon Flood Detector

Detects beacon flood (fake AP) attacks where an attacker broadcasts
hundreds/thousands of fake SSIDs to confuse WiFi clients.
Tools: mdk3/mdk4 beacon flood, Fluxion, WiFi Pumpkin.

Detection approach:
- Track unique SSIDs seen in a sliding time window
- Track BSSID diversity (randomized MACs from attack tools)
- Alert when unique SSID count exceeds threshold in window

MITRE ATT&CK: T1498.001 - Network Denial of Service: Direct Network Flood
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BeaconFloodConfig:
    """Configuration for beacon flood detection."""

    unique_ssid_threshold: int = 50  # Unique SSIDs in window to trigger
    time_window: int = 30  # Analysis window in seconds
    min_unique_bssids: int = 10  # Min random BSSIDs to confirm attack tool
    cooldown_seconds: int = 120  # Seconds between alerts
    beacon_rate_threshold: float = 100.0  # Beacons/sec from same OUI prefix


@dataclass
class BeaconFloodState:
    """Per-window tracking state."""

    ssid_timestamps: dict[str, float] = field(
        default_factory=dict
    )  # ssid -> first_seen
    bssid_set: set[str] = field(default_factory=set)
    beacon_timestamps: list[float] = field(default_factory=list)
    oui_prefixes: set[str] = field(default_factory=set)


class BeaconFloodDetector:
    """
    Detects beacon flood attacks by tracking:
    1. Unique SSID count in sliding window
    2. BSSID diversity (randomized MACs)
    3. Beacon frame rate (high rate from attack tools)
    """

    def __init__(self, config: BeaconFloodConfig | None = None):
        self.config = config or BeaconFloodConfig()
        self.state = BeaconFloodState()
        self.last_alert_time: float = 0.0
        self.alert_count = 0

    def ingest(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        """
        Process a beacon frame for flood detection.

        Args:
            frame: Parsed frame dict from sensor

        Returns:
            Alert dict if flood detected, else None
        """
        ftype = frame.get("frame_type", "")
        subtype = frame.get("frame_subtype", "")

        # Only process beacon frames
        if ftype != "beacon" and subtype != "beacon":
            return None

        ssid = frame.get("ssid", "")
        bssid = frame.get("bssid", "").upper()
        if not bssid:
            return None

        now = time.time()

        # Cleanup old entries
        self._cleanup(now)

        # Track SSID (only non-empty, non-hidden)
        if ssid and ssid not in self.state.ssid_timestamps:
            self.state.ssid_timestamps[ssid] = now

        # Track BSSID diversity
        self.state.bssid_set.add(bssid)

        # Track OUI prefix (first 3 octets)
        if len(bssid) >= 8:
            self.state.oui_prefixes.add(bssid[:8])

        # Track beacon timestamps for rate
        self.state.beacon_timestamps.append(now)

        # Evaluate
        return self._evaluate(now)

    def _cleanup(self, now: float):
        """Remove entries outside the analysis window."""
        cutoff = now - self.config.time_window

        # Cleanup SSIDs older than window
        self.state.ssid_timestamps = {
            ssid: ts for ssid, ts in self.state.ssid_timestamps.items() if ts >= cutoff
        }

        # Cleanup beacon timestamps
        self.state.beacon_timestamps = [
            t for t in self.state.beacon_timestamps if t >= cutoff
        ]

    def _evaluate(self, now: float) -> dict[str, Any] | None:
        """Evaluate current state against thresholds."""
        # Cooldown check
        if now - self.last_alert_time < self.config.cooldown_seconds:
            return None

        unique_ssids = len(self.state.ssid_timestamps)
        unique_bssids = len(self.state.bssid_set)

        # Primary: unique SSID count exceeds threshold
        if unique_ssids < self.config.unique_ssid_threshold:
            return None

        # Confirmed: we have a flood
        self.last_alert_time = now
        self.alert_count += 1

        # Calculate beacon rate
        beacon_count = len(self.state.beacon_timestamps)
        beacon_rate = beacon_count / self.config.time_window

        # Severity based on scale and BSSID diversity
        if (
            unique_ssids >= self.config.unique_ssid_threshold * 5
            and unique_bssids >= self.config.min_unique_bssids
        ):
            severity = "CRITICAL"
        elif (
            unique_ssids >= self.config.unique_ssid_threshold * 2
            or unique_bssids >= self.config.min_unique_bssids
        ):
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        return {
            "alert_type": "beacon_flood",
            "severity": severity,
            "title": f"Beacon Flood: {unique_ssids} fake SSIDs detected",
            "description": (
                f"Beacon flood attack detected: {unique_ssids} unique SSIDs from "
                f"{unique_bssids} BSSIDs in {self.config.time_window}s window "
                f"(rate: {beacon_rate:.0f} beacons/sec). "
                f"Likely mdk3/mdk4 beacon flood attack."
            ),
            "timestamp": datetime.now(UTC).isoformat(),
            "evidence": {
                "unique_ssid_count": unique_ssids,
                "unique_bssid_count": unique_bssids,
                "beacon_rate_per_sec": round(beacon_rate, 1),
                "oui_prefix_count": len(self.state.oui_prefixes),
                "window_seconds": self.config.time_window,
                "sample_ssids": list(self.state.ssid_timestamps.keys())[:10],
            },
            "mitre_attack": "T1498.001",
        }

    def get_stats(self) -> dict:
        """Get current detection statistics."""
        return {
            "tracked_ssids": len(self.state.ssid_timestamps),
            "tracked_bssids": len(self.state.bssid_set),
            "recent_beacons": len(self.state.beacon_timestamps),
            "alerts_generated": self.alert_count,
        }

    def reset(self):
        """Reset all state."""
        self.state = BeaconFloodState()
        self.last_alert_time = 0.0
        self.alert_count = 0
