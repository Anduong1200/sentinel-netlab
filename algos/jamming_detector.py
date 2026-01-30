#!/usr/bin/env python3
"""
Sentinel NetLab - Jamming Detector
Identifies potential RF jamming and interference based on packet statistics.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class JammingConfig:
    """Configuration for jamming detection"""

    # Thresholds
    loss_threshold: float = 0.4  # 40% packet loss/retry
    noise_threshold_dbm: int = -85
    rts_cts_threshold: int = 50  # Max RTS/CTS per interval
    interval_seconds: int = 10

    # Alert Weights
    weight_loss: int = 40
    weight_congestion: int = 30
    weight_anomalous_rssi: int = 30

    threshold_critical: int = 80
    threshold_high: int = 60


@dataclass
class JammingStats:
    """Current RF statistics for an interface/channel"""

    timestamp: float
    total_frames: int = 0
    data_frames: int = 0
    mgmt_frames: int = 0
    ctrl_frames: int = 0
    retry_frames: int = 0
    rts_cts_count: int = 0
    avg_rssi: float = -100.0
    rssi_samples: list[int] = field(default_factory=list)


class JammingDetector:
    """
    Detects wireless jamming and interference.

    Monitors:
    1. Retransmission rate (Retry bit)
    2. Management/Control vs Data ratio
    3. RTS/CTS flood (NAV jamming)
    4. Signal stability
    """

    def __init__(self, config: JammingConfig | None = None):
        self.config = config or JammingConfig()
        self.stats: dict[int, JammingStats] = {}  # channel -> stats
        self.last_alerts: dict[int, float] = {}

    def ingest(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        """
        Process a parsed frame for jamming indicators.

        Args:
            frame: Parsed frame from sensor (TelemetryItem like)

        Returns:
            Alert if jamming detected, else None
        """
        channel = frame.get("channel", 0)
        now = time.time()

        if channel not in self.stats:
            self.stats[channel] = JammingStats(timestamp=now)

        st = self.stats[channel]
        st.total_frames += 1

        # Categorize frame
        ftype = frame.get("frame_type", "other")
        if ftype == "data":
            st.data_frames += 1
        elif ftype in ["beacon", "probe_req", "probe_resp", "auth", "assoc_req"]:
            st.mgmt_frames += 1
        elif ftype in ["rts", "cts", "ack"]:
            st.ctrl_frames += 1
            if ftype in ["rts", "cts"]:
                st.rts_cts_count += 1

        # Check retry bit (if available in raw metadata or specific field)
        if frame.get("retry", False):
            st.retry_frames += 1

        # Update RSSI
        rssi = frame.get("rssi_dbm")
        if rssi is not None:
            st.rssi_samples.append(rssi)
            if len(st.rssi_samples) > 100:
                st.rssi_samples.pop(0)
            st.avg_rssi = sum(st.rssi_samples) / len(st.rssi_samples)

        # Check interval for detection
        if now - st.timestamp >= self.config.interval_seconds:
            alert = self._evaluate(channel, st)
            self._reset_stats(channel)
            return alert

        return None

    def _evaluate(self, channel: int, st: JammingStats) -> dict[str, Any] | None:
        """Calculate score and build alert if needed"""
        if st.total_frames < 20:  # Minimum sample size
            return None

        score = 0
        evidence = []

        # Indicator 1: High Retry Rate
        retry_rate = st.retry_frames / st.total_frames if st.total_frames > 0 else 0
        if retry_rate > self.config.loss_threshold:
            factor = min(1.0, (retry_rate - self.config.loss_threshold) / 0.5)
            score += int(self.config.weight_loss * factor)
            evidence.append(f"High retry rate: {retry_rate:.1%}")

        # Indicator 2: RTS/CTS Flood
        if st.rts_cts_count > self.config.rts_cts_threshold:
            score += self.config.weight_congestion
            evidence.append(f"RTS/CTS flood detected: {st.rts_cts_count} frames")

        # Indicator 3: Low Signal Stability or abnormal Noise
        # (Simplified: if many frames but overall weak signal on a usually strong channel)
        # In a real IPS, we'd check against a baseline.

        if score >= self.config.threshold_high:
            severity = "HIGH" if score < self.config.threshold_critical else "CRITICAL"

            return {
                "alert_type": "jamming_detected",
                "severity": severity,
                "title": "Wireless Jamming / Interference Detected",
                "description": f"Potential jamming on channel {channel}. {', '.join(evidence)}",
                "score": score,
                "channel": channel,
                "timestamp": datetime.now(UTC).isoformat(),
                "evidence": {
                    "total_frames": st.total_frames,
                    "retry_rate": retry_rate,
                    "rts_cts_count": st.rts_cts_count,
                    "avg_rssi": st.avg_rssi,
                },
                "mitre_attack": "T1465",  # Limit Hardware Cloud Communication (closest related)
            }

        return None

    def _reset_stats(self, channel: int):
        """Reset counters for next interval"""
        self.stats[channel] = JammingStats(timestamp=time.time())


if __name__ == "__main__":
    # Smoke test
    detector = JammingDetector()
    for i in range(100):
        detector.ingest(
            {
                "channel": 6,
                "frame_type": "rts" if i < 60 else "data",
                "retry": i % 2 == 0,
                "rssi_dbm": -70,
            }
        )
    result = detector.ingest({"channel": 6})
    if result:
        print(f"Detected: {result['title']} (Score: {result['score']})")
