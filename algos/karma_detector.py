#!/usr/bin/env python3
"""
Sentinel NetLab - Karma Detector
Detects Karma/Pineapple attacks where an AP responds to multiple different SSIDs.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class KarmaConfig:
    """Configuration for Karma detection"""

    # Thresholds
    ssid_threshold: int = 3  # Number of unique SSIDs an AP responds to
    window_seconds: int = 60

    # Severity
    threshold_critical: int = 5


@dataclass
class APResponderStats:
    """Statistics for an AP responding to probes"""

    first_seen: float
    last_seen: float
    responded_ssids: set[str] = field(default_factory=set)


class KarmaDetector:
    """
    Detects Karma attacks.

    A Karma hotspot (like WiFi Pineapple) listens for Probe Requests
    from clients and responds to ANY SSID the client is looking for.
    If we see a single BSSID sending Probe Responses/Beacons for
    multiple unrelated SSIDs, it's highly suspicious.
    """

    def __init__(self, config: KarmaConfig | None = None):
        self.config = config or KarmaConfig()
        self.responders: dict[str, APResponderStats] = {}  # BSSID -> Stats
        self.alerted_bssids: set[str] = set()  # BSSIDs that already fired
        self.last_cleanup = time.time()

    def ingest(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        """
        Process a frame (Beacon or Probe Response).
        """
        ftype = frame.get("frame_type")
        if ftype not in ["beacon", "probe_resp"]:
            return None

        bssid = frame.get("bssid", "").upper()
        if not bssid:
            return None

        ssid = frame.get("ssid")
        if not ssid or ssid == "<Hidden>":
            return None

        now = time.time()
        self._cleanup(now)

        if bssid not in self.responders:
            self.responders[bssid] = APResponderStats(first_seen=now, last_seen=now)

        st = self.responders[bssid]
        st.last_seen = now

        # Check if we've seen this BSSID with a different SSID before
        if ssid not in st.responded_ssids:
            st.responded_ssids.add(ssid)

            # Evaluate for Karma
            if len(st.responded_ssids) >= self.config.ssid_threshold:
                if bssid not in self.alerted_bssids:
                    self.alerted_bssids.add(bssid)
                    return self._create_alert(bssid, st)

        return None

    def _create_alert(self, bssid: str, st: APResponderStats) -> dict[str, Any]:
        """Build a Karma alert"""
        count = len(st.responded_ssids)
        severity = "CRITICAL" if count >= self.config.threshold_critical else "HIGH"

        return {
            "alert_type": "karma_attack",
            "severity": severity,
            "title": "Karma / Rogue AP Detected",
            "description": f"BSSID {bssid} is advertising multiple unique SSIDs, suggesting a Karma-style rogue AP.",
            "bssid": bssid,
            "timestamp": datetime.now(UTC).isoformat(),
            "evidence": {
                "unique_ssids_probed": list(st.responded_ssids),
                "count": count,
                "duration_seconds": round(st.last_seen - st.first_seen, 1),
            },
            "mitre_attack": "T1557.002",  # Adversary-in-the-Middle: Rogue AP
        }

    def _cleanup(self, now: float):
        """Clean up old responder state"""
        if now - self.last_cleanup < 30:
            return

        self.last_cleanup = now
        cutoff = now - self.config.window_seconds

        expired = [
            bssid for bssid, st in self.responders.items() if st.last_seen < cutoff
        ]
        for bssid in expired:
            del self.responders[bssid]
            self.alerted_bssids.discard(bssid)


if __name__ == "__main__":
    # Smoke test
    detector = KarmaDetector()
    for i in range(5):
        detector.ingest(
            {
                "frame_type": "probe_resp",
                "bssid": "DE:AD:BE:EF:00:01",
                "ssid": f"FakeNet-{i}",
            }
        )
    result = detector.ingest(
        {"frame_type": "probe_resp", "bssid": "DE:AD:BE:EF:00:01", "ssid": "TriggerNet"}
    )
    if result:
        print(f"Detected: {result['title']} (SSIDs: {result['evidence']['count']})")
