#!/usr/bin/env python3
"""
Sentinel NetLab - Wardriving Detector
Detects active wardriving behavior by analyzing probe request patterns.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class WardriveConfig:
    """Configuration for wardriving detection"""

    # Thresholds
    unique_ssid_threshold: int = 5  # Number of unique SSIDs probed within window
    probe_rate_threshold: int = 20  # Total probes from a single MAC in window
    window_seconds: int = 60

    # Severity Thresholds
    threshold_critical: int = 15  # Unique SSIDs
    threshold_high: int = 10
    threshold_medium: int = 5


@dataclass
class SourceStats:
    """Statistics for a single source MAC"""

    first_seen: float
    last_seen: float
    probe_count: int = 0
    unique_ssids: set[str] = field(default_factory=set)
    burst_detected: bool = False


class WardriveDetector:
    """
    Detects active wardriving/probing by tracking probe requests.

    A wardriver's device (or a smartphone's background scan) sends
    Probe Requests for "hidden" or "remembered" networks.
    An excessive amount of unique SSIDs from a single MAC indicates
    either an active scan or a device looking for many networks.
    """

    def __init__(self, config: WardriveConfig | None = None):
        self.config = config or WardriveConfig()
        self.sources: dict[str, SourceStats] = {}  # MAC -> Stats
        self.alerted_macs: set[str] = set()  # MACs that already fired
        self.last_cleanup = time.time()

    def ingest(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        """
        Process a probe request frame.

        Args:
            frame: Parsed frame from sensor (must be probe_req)

        Returns:
            Alert if wardriving detected, else None
        """
        if frame.get("frame_type") != "probe_req":
            return None

        src = frame.get("src_addr", "").upper()
        if not src:
            return None

        ssid = frame.get("ssid")
        now = time.time()

        # Periodic cleanup
        self._cleanup(now)

        # Update source stats
        if src not in self.sources:
            self.sources[src] = SourceStats(first_seen=now, last_seen=now)

        st = self.sources[src]
        st.last_seen = now
        st.probe_count += 1
        if ssid:
            st.unique_ssids.add(ssid)

        # Evaluate for alert
        if len(st.unique_ssids) >= self.config.unique_ssid_threshold:
            if src not in self.alerted_macs:
                self.alerted_macs.add(src)
                return self._create_alert(src, st)

        return None

    def _create_alert(self, mac: str, st: SourceStats) -> dict[str, Any]:
        """Build a wardriving alert"""
        count = len(st.unique_ssids)

        if count >= self.config.threshold_critical:
            severity = "CRITICAL"
        elif count >= self.config.threshold_high:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        return {
            "alert_type": "wardrive_detected",
            "severity": severity,
            "title": "Active Wardriving / Network Scavenging Detected",
            "description": (
                f"Source MAC {mac} is probing for {count} unique networks. "
                "This indicates an active scanning device or wardriver in range."
            ),
            "source_mac": mac,
            "timestamp": datetime.now(UTC).isoformat(),
            "evidence": {
                "unique_ssid_count": count,
                "total_probes": st.probe_count,
                "ssids_probed": list(st.unique_ssids),
                "duration_seconds": round(st.last_seen - st.first_seen, 1),
            },
            "mitre_attack": "T1595.002",  # Active Scanning: IP Addresses (closest for Wireless)
        }

    def _cleanup(self, now: float):
        """Remove old source stats"""
        if now - self.last_cleanup < 30:
            return

        self.last_cleanup = now
        cutoff = now - self.config.window_seconds

        expired = [mac for mac, st in self.sources.items() if st.last_seen < cutoff]
        for mac in expired:
            del self.sources[mac]
            self.alerted_macs.discard(mac)


if __name__ == "__main__":
    # Smoke test
    detector = WardriveDetector()
    for i in range(10):
        detector.ingest(
            {
                "frame_type": "probe_req",
                "src_addr": "AA:BB:CC:DD:EE:FF",
                "ssid": f"Network-{i}",
            }
        )
    result = detector.ingest(
        {"frame_type": "probe_req", "src_addr": "AA:BB:CC:DD:EE:FF", "ssid": "FinalNet"}
    )
    if result:
        print(
            f"Detected: {result['title']} (SSIDs: {result['evidence']['unique_ssid_count']})"
        )
