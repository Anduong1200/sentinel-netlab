#!/usr/bin/env python3
"""
Sentinel NetLab - Disassociation Flood Detector

Detects disassociation frame floods used for DoS attacks.
Disassociation frames (type 0, subtype 10) are functionally similar
to deauthentication frames but use a different management subtype.
Many attack tools (mdk3/mdk4, aireplay-ng) use both frame types.

MITRE ATT&CK: T1499.001 - Endpoint Denial of Service: OS Exhaustion Flood
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DisassocConfig:
    """Configuration for disassociation flood detection."""

    rate_threshold: float = 10.0  # Frames per second to trigger alert
    window_seconds: float = 5.0  # Sliding window for rate calculation
    cooldown_seconds: float = 60.0  # Seconds between alerts for same pair
    min_unique_clients: int = 3  # Unique clients targeted to escalate severity


@dataclass
class DisassocFloodAlert:
    """Alert output for disassociation flood detection."""

    alert_type: str
    severity: str
    title: str
    description: str
    bssid: str
    timestamp: str
    evidence: dict
    mitre_attack: str = "T1499.001"


class DisassocFloodDetector:
    """
    Detects disassociation flood attacks by tracking disassoc frame rate.

    Detection approach:
    1. Track disassoc frame timestamps per (BSSID, client) pair
    2. Sliding-window rate analysis
    3. Severity escalation when multiple clients are targeted
    """

    def __init__(self, config: DisassocConfig | None = None):
        self.config = config or DisassocConfig()

        # (bssid, client) -> [timestamps]
        self.frame_history: dict[tuple[str, str], list[float]] = defaultdict(list)

        # Track unique clients per BSSID for severity escalation
        self.bssid_clients: dict[str, set[str]] = defaultdict(set)

        # Cooldown tracking
        self.last_alert: dict[tuple[str, str], float] = {}

        self.alert_count = 0

    def ingest(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        """
        Process a frame for disassociation flood indicators.

        Args:
            frame: Parsed frame dict from sensor

        Returns:
            Alert dict if flood detected, else None
        """
        ftype = frame.get("frame_type", "")
        subtype = frame.get("frame_subtype", "")

        # Only process disassociation frames
        if ftype != "disassoc" and subtype != "disassoc":
            return None

        bssid = frame.get("bssid", "").upper()
        if not bssid:
            return None

        client = frame.get(
            "mac_dst", frame.get("dst_addr", "ff:ff:ff:ff:ff:ff")
        ).upper()
        now = time.time()
        key = (bssid, client)

        # Record frame
        self.frame_history[key].append(now)
        self.bssid_clients[bssid].add(client)

        # Cleanup old entries
        self._cleanup(key, now)

        # Check for flood
        return self._check_flood(key, bssid, client, now)

    def _cleanup(self, key: tuple[str, str], now: float):
        """Remove entries outside the analysis window."""
        cutoff = now - self.config.window_seconds * 2
        self.frame_history[key] = [t for t in self.frame_history[key] if t >= cutoff]

    def _check_flood(
        self,
        key: tuple[str, str],
        bssid: str,
        client: str,
        now: float,
    ) -> dict[str, Any] | None:
        """Check if current rate exceeds threshold."""
        # Check cooldown
        if key in self.last_alert:
            if now - self.last_alert[key] < self.config.cooldown_seconds:
                return None

        # Count frames in window
        window_start = now - self.config.window_seconds
        frames_in_window = [t for t in self.frame_history[key] if t >= window_start]
        count = len(frames_in_window)

        # Calculate rate
        rate = count / self.config.window_seconds

        if rate >= self.config.rate_threshold:
            self.last_alert[key] = now
            return self._create_alert(bssid, client, count, rate)

        return None

    def _create_alert(
        self, bssid: str, client: str, count: int, rate: float
    ) -> dict[str, Any]:
        """Create disassociation flood alert."""
        self.alert_count += 1

        # Determine severity based on rate and targeted client count
        unique_clients = len(self.bssid_clients.get(bssid, set()))
        is_broadcast = client == "FF:FF:FF:FF:FF:FF"

        if rate >= self.config.rate_threshold * 5 or (
            unique_clients >= self.config.min_unique_clients
            and rate >= self.config.rate_threshold * 2
        ):
            severity = "CRITICAL"
        elif (
            rate >= self.config.rate_threshold * 2
            or unique_clients >= self.config.min_unique_clients
        ):
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        return {
            "alert_type": "disassoc_flood",
            "severity": severity,
            "title": f"Disassociation Flood: {bssid}",
            "description": (
                f"Disassociation flood detected targeting BSSID {bssid} "
                f"at {rate:.1f} frames/sec ({count} frames in {self.config.window_seconds}s window). "
                f"{'Broadcast' if is_broadcast else f'Targeted client: {client}'}."
            ),
            "bssid": bssid,
            "timestamp": datetime.now(UTC).isoformat(),
            "evidence": {
                "frame_count": count,
                "rate_per_sec": round(rate, 1),
                "window_seconds": self.config.window_seconds,
                "target_client": client if not is_broadcast else None,
                "is_broadcast": is_broadcast,
                "unique_clients_targeted": unique_clients,
            },
            "mitre_attack": "T1499.001",
        }

    def get_stats(self) -> dict:
        """Get current detection statistics."""
        total_frames = sum(len(v) for v in self.frame_history.values())
        return {
            "tracked_pairs": len(self.frame_history),
            "total_recent_frames": total_frames,
            "unique_bssids": len(self.bssid_clients),
            "alerts_generated": self.alert_count,
        }

    def reset(self):
        """Reset all state."""
        self.frame_history.clear()
        self.bssid_clients.clear()
        self.last_alert.clear()
        self.alert_count = 0
