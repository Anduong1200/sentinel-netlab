#!/usr/bin/env python3
"""
Sentinel NetLab - WEP IV Detector
Detects IV reuse and injection attacks on WEP networks.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class WEPConfig:
    """Configuration for WEP detection"""

    # Thresholds
    iv_collision_threshold: int = 5  # Same IV repeated
    injection_rate_threshold: int = 50  # Small packets per second
    small_packet_max_len: int = 150  # ARP/Small packet size
    window_seconds: int = 60


@dataclass
class BSSIDWEPStats:
    """Statistics for WEP on a specific BSSID"""

    iv_history: dict[str, int] = field(default_factory=dict)  # IV -> count
    small_packet_count: int = 0
    last_reset: float = 0.0
    is_wep: bool = False


class WEPIVDetector:
    """
    Detects WEP IV attacks.

    Attacks:
    1. IV Collision: Using the same IV multiple times (increases cracking speed).
    2. Packet Injection: Sending many small packets (ARP request) to generate IVs.
    """

    def __init__(self, config: WEPConfig | None = None):
        self.config = config or WEPConfig()
        self.bssid_stats: dict[str, BSSIDWEPStats] = {}

    def ingest(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        """
        Process a frame for WEP indicators.
        """
        bssid = frame.get("bssid", "").upper()
        if not bssid:
            return None

        ftype = frame.get("frame_type")

        # Track if network is WEP
        if ftype in ["beacon", "probe_resp"]:
            is_wep = frame.get("privacy", False) and not (
                frame.get("rsn_info") or frame.get("wpa_info")
            )
            if bssid not in self.bssid_stats:
                self.bssid_stats[bssid] = BSSIDWEPStats(last_reset=time.time())
            self.bssid_stats[bssid].is_wep = is_wep

        # Only process Data frames for WEP networks
        if ftype != "data":
            return None

        st = self.bssid_stats.get(bssid)
        if not st or not st.is_wep:
            return None

        now = time.time()
        if now - st.last_reset > self.config.window_seconds:
            st.iv_history.clear()
            st.small_packet_count = 0
            st.last_reset = now

        # 1. Track IV Collision
        iv = frame.get("wep_iv")
        if iv:
            st.iv_history[iv] = st.iv_history.get(iv, 0) + 1
            if st.iv_history[iv] >= self.config.iv_collision_threshold:
                return self._create_alert(
                    bssid, "iv_collision", {"iv": iv, "count": st.iv_history[iv]}
                )

        # 2. Track Injection (many small packets)
        frame_len = frame.get("frame_len", 0)
        if frame_len > 0 and frame_len <= self.config.small_packet_max_len:
            st.small_packet_count += 1
            if st.small_packet_count >= self.config.injection_rate_threshold:
                # Only alert once per window
                st.small_packet_count = -1000  # Cooldown
                return self._create_alert(
                    bssid,
                    "packet_injection",
                    {"small_packets": self.config.injection_rate_threshold},
                )

        return None

    def _create_alert(self, bssid: str, sub_type: str, details: dict) -> dict[str, Any]:
        """Build a WEP alert"""
        title = (
            "WEP IV Collision Detected"
            if sub_type == "iv_collision"
            else "WEP Packet Injection Detected"
        )
        severity = "CRITICAL" if sub_type == "iv_collision" else "HIGH"

        return {
            "alert_type": "wep_attack",
            "severity": severity,
            "title": title,
            "description": f"Potential WEP cracking attempt on BSSID {bssid}.",
            "bssid": bssid,
            "timestamp": datetime.now(UTC).isoformat(),
            "evidence": {"attack_subtype": sub_type, "details": details},
            "mitre_attack": "T1600.001",  # Reduce Encryption Strength: IV Modification
        }


if __name__ == "__main__":
    # Smoke test
    detector = WEPIVDetector()
    # Mock WEP AP
    detector.ingest(
        {"frame_type": "beacon", "bssid": "00:11:22:33:44:55", "privacy": True}
    )
    # Mock IV collision
    for _ in range(5):
        detector.ingest(
            {"frame_type": "data", "bssid": "00:11:22:33:44:55", "wep_iv": "ABCDEF"}
        )
    result = detector.ingest(
        {"frame_type": "data", "bssid": "00:11:22:33:44:55", "wep_iv": "ABCDEF"}
    )
    if result:
        print(f"Detected: {result['title']}")
