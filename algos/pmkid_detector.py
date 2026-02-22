#!/usr/bin/env python3
"""
Sentinel NetLab - PMKID Harvesting Attack Detector

Detects hcxdumptool-style PMKID harvesting attacks by monitoring:
1. Authentication/Association Request floods from random MACs targeting one AP.
2. EAPOL Message 1 floods with no Message 2 follow-up ("orphaned handshakes").

When both indicators fire simultaneously, confidence is near-100%.

References:
- https://hashcat.net/forum/thread-7717.html
- MITRE ATT&CK T1110.002 (Password Cracking)
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================


@dataclass
class PMKIDConfig:
    """Configuration for PMKID harvesting detection"""

    # EAPOL M1 thresholds
    eapol_m1_threshold: int = 15
    eapol_time_window: int = 10  # seconds

    # Auth flood thresholds (hcxdumptool sends rapid Auth frames)
    auth_flood_threshold: int = 50
    auth_time_window: int = 5  # seconds

    # Minimum unique source MACs in auth flood (random MAC indicator)
    min_unique_sources: int = 5

    # Cooldown to avoid duplicate alerts per BSSID (seconds)
    cooldown_seconds: int = 60


# =============================================================================
# STATE TRACKING
# =============================================================================


@dataclass
class APAttackState:
    """Tracks attack indicators for a single AP (BSSID)"""

    # EAPOL M1 timestamps (orphaned handshakes)
    eapol_m1_timestamps: list[float] = field(default_factory=list)

    # Authentication frame tracking
    auth_timestamps: list[float] = field(default_factory=list)
    auth_source_macs: set[str] = field(default_factory=set)

    # EAPOL M2 counter (if we see M2, it's not an attack)
    eapol_m2_count: int = 0


# =============================================================================
# PMKID ATTACK DETECTOR
# =============================================================================


class PMKIDAttackDetector:
    """
    Detects PMKID harvesting attacks (hcxdumptool, hcxpcapngtool).

    Attack Behavior:
    1. Attacker sends rapid Authentication/Association frames from random MACs.
    2. AP responds with EAPOL Message 1 containing PMKID.
    3. Attacker never sends Message 2 — captures PMKID and moves on.

    Detection Strategy:
    - Layer 1: Track EAPOL M1 floods per BSSID with no M2 follow-up.
    - Layer 2: Track Authentication frame floods from diverse source MACs.
    - Combined: When both layers trigger → CRITICAL (hcxdumptool confirmed).
    """

    def __init__(self, config: PMKIDConfig | None = None):
        self.config = config or PMKIDConfig()

        # Per-AP state: BSSID -> APAttackState
        self.ap_states: dict[str, APAttackState] = defaultdict(APAttackState)

        # Cooldown tracking: BSSID -> last alert timestamp
        self.last_alert_time: dict[str, float] = {}

        self.alert_count = 0

    def ingest(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        """
        Process a single frame from the sensor pipeline.

        Relevant frame types:
        - frame_type "auth" / frame_subtype "auth": Authentication frame
        - frame_type "assoc_req": Association Request
        - frame_type "eapol": EAPOL Authentication frame
          - eapol_message: 1 or 2 (Message number in 4-way handshake)

        Returns:
            Alert dict if attack detected, else None.
        """
        ftype = frame.get("frame_type", "")
        subtype = frame.get("frame_subtype", "")
        bssid = frame.get("bssid", "").upper()

        if not bssid:
            return None

        now = frame.get("timestamp", time.time())
        # Ensure numeric timestamp
        if isinstance(now, str):
            now = time.time()

        state = self.ap_states[bssid]

        # ─── Layer 1: EAPOL Tracking ──────────────────────────────────
        if self._is_eapol(ftype, subtype, frame):
            msg_num = frame.get("eapol_message", 0)

            if msg_num == 1:
                # AP sent M1 — record it
                state.eapol_m1_timestamps.append(now)
                self._cleanup_timestamps(
                    state.eapol_m1_timestamps, now, self.config.eapol_time_window
                )

            elif msg_num == 2:
                # Client responded with M2 — this is legitimate
                state.eapol_m2_count += 1
                # Remove one M1 from the orphan tracker (paired)
                if state.eapol_m1_timestamps:
                    state.eapol_m1_timestamps.pop(0)
                return None

        # ─── Layer 2: Auth/Assoc Flood Tracking ───────────────────────
        if ftype in ("auth", "assoc_req") or subtype in ("auth", "assoc_req"):
            src_mac = frame.get("src_addr", frame.get("source_mac", "")).upper()
            if src_mac:
                state.auth_timestamps.append(now)
                state.auth_source_macs.add(src_mac)
                self._cleanup_timestamps(
                    state.auth_timestamps, now, self.config.auth_time_window
                )

        # ─── Evaluate ─────────────────────────────────────────────────
        return self._evaluate(bssid, state, now)

    def _is_eapol(self, ftype: str, subtype: str, frame: dict) -> bool:
        """Check if frame is an EAPOL authentication frame."""
        if ftype == "eapol":
            return True
        if frame.get("has_eapol", False):
            return True
        # Scapy-based: check for EAPOL layer marker
        if frame.get("eapol_message") is not None:
            return True
        return False

    def _evaluate(
        self, bssid: str, state: APAttackState, now: float
    ) -> dict[str, Any] | None:
        """Evaluate current state and decide if an alert should fire."""

        # Check cooldown
        if bssid in self.last_alert_time:
            if now - self.last_alert_time[bssid] < self.config.cooldown_seconds:
                return None

        # Count indicators
        m1_count = len(state.eapol_m1_timestamps)
        auth_count = len(state.auth_timestamps)
        unique_sources = len(state.auth_source_macs)

        eapol_triggered = m1_count >= self.config.eapol_m1_threshold
        auth_triggered = (
            auth_count >= self.config.auth_flood_threshold
            and unique_sources >= self.config.min_unique_sources
        )

        if not eapol_triggered and not auth_triggered:
            return None

        # Determine severity
        if eapol_triggered and auth_triggered:
            severity = "CRITICAL"
            description = (
                f"PMKID harvesting attack confirmed (hcxdumptool pattern). "
                f"AP {bssid} received {auth_count} Auth frames from "
                f"{unique_sources} unique MACs and emitted {m1_count} orphaned "
                f"EAPOL M1 with no M2 response."
            )
        elif eapol_triggered:
            severity = "HIGH"
            description = (
                f"Suspected PMKID harvesting: {m1_count} EAPOL Message 1 "
                f"packets from AP {bssid} with no Message 2 follow-up."
            )
        else:
            severity = "HIGH"
            description = (
                f"Authentication flood targeting AP {bssid}: "
                f"{auth_count} Auth frames from {unique_sources} different MACs "
                f"in {self.config.auth_time_window}s."
            )

        # Fire alert
        self.last_alert_time[bssid] = now
        return self._create_alert(
            bssid=bssid,
            severity=severity,
            description=description,
            m1_count=m1_count,
            auth_count=auth_count,
            unique_sources=unique_sources,
            eapol_triggered=eapol_triggered,
            auth_triggered=auth_triggered,
        )

    def _create_alert(
        self,
        bssid: str,
        severity: str,
        description: str,
        m1_count: int,
        auth_count: int,
        unique_sources: int,
        eapol_triggered: bool,
        auth_triggered: bool,
    ) -> dict[str, Any]:
        """Create a PMKID harvesting alert."""
        self.alert_count += 1

        indicators = []
        if eapol_triggered:
            indicators.append("EAPOL_M1_FLOOD")
        if auth_triggered:
            indicators.append("AUTH_FLOOD_RANDOM_MAC")

        return {
            "alert_type": "pmkid_harvesting",
            "severity": severity,
            "title": "PMKID Harvesting Attack Detected",
            "description": description,
            "bssid": bssid,
            "timestamp": datetime.now(UTC).isoformat(),
            "evidence": {
                "orphaned_eapol_m1": m1_count,
                "auth_frame_count": auth_count,
                "unique_source_macs": unique_sources,
                "indicators": indicators,
                "eapol_threshold": self.config.eapol_m1_threshold,
                "auth_threshold": self.config.auth_flood_threshold,
            },
            "mitre_attack": "T1110.002",  # Password Cracking
            "action_recommended": (
                "Verify WPA2/3 passphrase strength. "
                "Disable PMKID caching on router if supported (hostapd: disable_pmksa_caching=1). "
                "Consider WPA3-SAE which is immune to PMKID attacks."
            ),
        }

    @staticmethod
    def _cleanup_timestamps(timestamps: list[float], now: float, window: int) -> None:
        """Remove timestamps older than the time window (in-place)."""
        cutoff = now - window
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

    def get_stats(self) -> dict[str, Any]:
        """Get detector statistics."""
        return {
            "tracked_aps": len(self.ap_states),
            "alerts_generated": self.alert_count,
            "active_cooldowns": len(self.last_alert_time),
        }

    def reset(self) -> None:
        """Reset all state (useful for testing)."""
        self.ap_states.clear()
        self.last_alert_time.clear()
        self.alert_count = 0


if __name__ == "__main__":
    # Smoke test
    detector = PMKIDAttackDetector(
        config=PMKIDConfig(eapol_m1_threshold=5, auth_flood_threshold=10)
    )

    bssid = "AA:BB:CC:DD:EE:FF"

    # Simulate auth flood from random MACs
    for i in range(15):
        detector.ingest(
            {
                "frame_type": "auth",
                "bssid": bssid,
                "src_addr": f"DE:AD:BE:EF:00:{i:02X}",
            }
        )

    # Simulate EAPOL M1 flood with no M2
    result = None
    for _ in range(10):
        result = detector.ingest(
            {
                "frame_type": "eapol",
                "bssid": bssid,
                "eapol_message": 1,
            }
        )

    if result:
        print(f"🚨 {result['title']}")
        print(f"   Severity: {result['severity']}")
        print(f"   {result['description']}")
    else:
        print("No alert (adjust thresholds for smoke test)")
