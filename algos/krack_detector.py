#!/usr/bin/env python3
"""
Sentinel NetLab - KRACK Attack Detector

Detects Key Reinstallation Attacks (KRACK, CVE-2017-13077).
KRACK exploits the 4-way handshake by replaying EAPOL Message 3
to force nonce reuse in the client, enabling traffic decryption.

Detection signals:
1. Excessive EAPOL M3 retransmissions for a single (AP, client) pair
2. M3 appearing after M4 (replay indicator)
3. Abnormal handshake reset patterns

MITRE ATT&CK: T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning
               (closest mapping for WiFi key reinstallation)
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class KRACKConfig:
    """Configuration for KRACK detection."""

    m3_retransmit_threshold: int = 3  # M3 retransmissions to trigger alert
    time_window: int = 30  # Analysis window in seconds
    cooldown_seconds: int = 120  # Seconds between alerts per pair
    m3_after_m4_alert: bool = True  # Alert on M3 after M4 (replay)


@dataclass
class HandshakeState:
    """Tracks the 4-way handshake state for an (AP, client) pair."""

    m1_timestamps: list[float] = field(default_factory=list)
    m2_timestamps: list[float] = field(default_factory=list)
    m3_timestamps: list[float] = field(default_factory=list)
    m4_timestamps: list[float] = field(default_factory=list)
    m4_completed: bool = False  # True after M4 is seen


class KRACKDetector:
    """
    Detects KRACK attacks by monitoring EAPOL handshake anomalies.

    Detection approach:
    1. Track each (BSSID, client) handshake independently
    2. Count M3 retransmissions — normal: 0-1, KRACK: 3+
    3. Detect M3 after M4 — definitive replay indicator
    """

    def __init__(self, config: KRACKConfig | None = None):
        self.config = config or KRACKConfig()

        # (bssid, client) -> HandshakeState
        self.handshake_states: dict[tuple[str, str], HandshakeState] = defaultdict(
            HandshakeState
        )

        # Cooldown tracking
        self.last_alert: dict[tuple[str, str], float] = {}

        self.alert_count = 0

    def ingest(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        """
        Process a frame for KRACK attack indicators.

        Args:
            frame: Parsed frame dict from sensor

        Returns:
            Alert dict if KRACK detected, else None
        """
        ftype = frame.get("frame_type", "")

        # Only process EAPOL frames
        if not self._is_eapol(ftype, frame):
            return None

        bssid = frame.get("bssid", "").upper()
        src = frame.get("src_addr", frame.get("mac_src", "")).upper()
        dst = frame.get("dst_addr", frame.get("mac_dst", "")).upper()
        eapol_msg = frame.get("eapol_message")

        if not bssid or eapol_msg is None:
            return None

        now = time.time()

        # Determine client MAC (client is the non-AP party)
        # M1/M3 are AP->Client, M2/M4 are Client->AP
        if eapol_msg in (1, 3):
            client = dst
        else:
            client = src

        if not client:
            return None

        key = (bssid, client)
        state = self.handshake_states[key]

        # Cleanup old entries
        self._cleanup(state, now)

        # Record message
        if eapol_msg == 1:
            state.m1_timestamps.append(now)
            state.m4_completed = False  # New handshake starting
        elif eapol_msg == 2:
            state.m2_timestamps.append(now)
        elif eapol_msg == 3:
            state.m3_timestamps.append(now)
            return self._evaluate(key, bssid, client, state, now)
        elif eapol_msg == 4:
            state.m4_timestamps.append(now)
            state.m4_completed = True

        return None

    def _is_eapol(self, ftype: str, frame: dict) -> bool:
        """Check if frame is an EAPOL authentication frame."""
        if ftype == "eapol":
            return True
        if frame.get("has_eapol", False):
            return True
        if frame.get("eapol_message") is not None:
            return True
        return False

    def _cleanup(self, state: HandshakeState, now: float):
        """Remove entries outside the analysis window."""
        cutoff = now - self.config.time_window
        state.m1_timestamps = [t for t in state.m1_timestamps if t >= cutoff]
        state.m2_timestamps = [t for t in state.m2_timestamps if t >= cutoff]
        state.m3_timestamps = [t for t in state.m3_timestamps if t >= cutoff]
        state.m4_timestamps = [t for t in state.m4_timestamps if t >= cutoff]

    def _evaluate(
        self,
        key: tuple[str, str],
        bssid: str,
        client: str,
        state: HandshakeState,
        now: float,
    ) -> dict[str, Any] | None:
        """Evaluate handshake state for KRACK indicators."""
        # Cooldown check
        if key in self.last_alert:
            if now - self.last_alert[key] < self.config.cooldown_seconds:
                return None

        m3_count = len(state.m3_timestamps)

        # Detection 1: M3 after M4 (clear replay)
        if self.config.m3_after_m4_alert and state.m4_completed:
            self.last_alert[key] = now
            self.alert_count += 1
            return self._create_alert(
                bssid,
                client,
                m3_count,
                severity="CRITICAL",
                attack_subtype="m3_replay_after_m4",
                description=(
                    f"KRACK replay detected: EAPOL M3 received AFTER M4 completion "
                    f"for client {client} on AP {bssid}. This is a definitive "
                    f"key reinstallation attack indicator."
                ),
            )

        # Detection 2: Excessive M3 retransmissions
        if m3_count >= self.config.m3_retransmit_threshold:
            self.last_alert[key] = now
            self.alert_count += 1

            severity = (
                "CRITICAL"
                if m3_count >= self.config.m3_retransmit_threshold * 2
                else "HIGH"
            )

            return self._create_alert(
                bssid,
                client,
                m3_count,
                severity=severity,
                attack_subtype="excessive_m3_retransmission",
                description=(
                    f"Potential KRACK attack: {m3_count} EAPOL M3 retransmissions "
                    f"detected for client {client} on AP {bssid} in "
                    f"{self.config.time_window}s window (threshold: "
                    f"{self.config.m3_retransmit_threshold})."
                ),
            )

        return None

    def _create_alert(
        self,
        bssid: str,
        client: str,
        m3_count: int,
        severity: str,
        attack_subtype: str,
        description: str,
    ) -> dict[str, Any]:
        """Create KRACK alert."""
        state = self.handshake_states.get((bssid, client), HandshakeState())

        return {
            "alert_type": "krack_attack",
            "severity": severity,
            "title": f"KRACK Attack: {bssid} → {client}",
            "description": description,
            "bssid": bssid,
            "timestamp": datetime.now(UTC).isoformat(),
            "evidence": {
                "attack_subtype": attack_subtype,
                "client_mac": client,
                "m3_count": m3_count,
                "m1_count": len(state.m1_timestamps),
                "m2_count": len(state.m2_timestamps),
                "m4_count": len(state.m4_timestamps),
                "m4_completed": state.m4_completed,
                "window_seconds": self.config.time_window,
                "cve": "CVE-2017-13077",
            },
            "mitre_attack": "T1557.002",
        }

    def get_stats(self) -> dict:
        """Get current detection statistics."""
        return {
            "tracked_handshakes": len(self.handshake_states),
            "alerts_generated": self.alert_count,
        }

    def reset(self):
        """Reset all state."""
        self.handshake_states.clear()
        self.last_alert.clear()
        self.alert_count = 0
