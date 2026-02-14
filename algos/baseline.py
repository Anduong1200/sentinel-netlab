#!/usr/bin/env python3
"""
Sentinel NetLab - Time-Series Baseline
"""

import logging
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


class TimeSeriesBaseline:
    """
    Builds behavioral baseline over configurable period.
    Tracks normal patterns for anomaly detection.
    """

    def __init__(self, learning_hours: int = 72, min_observations: int = 100):
        self.learning_hours = learning_hours
        self.min_observations = min_observations

        # Baselines per BSSID
        self.baselines: dict[str, dict] = {}

        # Learning state
        self.learning_start = datetime.now(UTC)
        self.is_learning = True

    def update(self, bssid: str, data: dict) -> dict | None:
        """
        Update baseline with new observation.
        Returns anomaly dict if deviation detected.
        """
        now = datetime.now(UTC)

        # Check if still in learning period
        learning_elapsed = (now - self.learning_start).total_seconds() / 3600
        self.is_learning = learning_elapsed < self.learning_hours

        # Initialize baseline for BSSID
        if bssid not in self.baselines:
            self.baselines[bssid] = self._init_baseline()

        baseline = self.baselines[bssid]

        # Update statistics
        self._update_stats(baseline, data)

        # Check for anomalies (only after learning period)
        if not self.is_learning and baseline["observations"] >= self.min_observations:
            return self._check_anomalies(baseline, data)

        return None

    def _init_baseline(self) -> dict:
        """Initialize baseline structure"""
        return {
            "observations": 0,
            "first_seen": datetime.now(UTC).isoformat(),
            "last_seen": None,
            # RSSI statistics
            "rssi_sum": 0,
            "rssi_sum_sq": 0,
            "rssi_min": None,
            "rssi_max": None,
            # Channel tracking
            "channels_seen": [],
            # Beacon interval
            "beacon_sum": 0,
            "beacon_count": 0,
            # Hourly activity pattern (24 buckets)
            "hourly_activity": [0] * 24,
        }

    def _update_stats(self, baseline: dict, data: dict):
        """Update baseline statistics"""
        baseline["observations"] += 1
        baseline["last_seen"] = datetime.now(UTC).isoformat()

        # RSSI
        rssi = data.get("rssi_dbm")
        if rssi is not None:
            baseline["rssi_sum"] += rssi
            baseline["rssi_sum_sq"] += rssi * rssi

            if baseline["rssi_min"] is None or rssi < baseline["rssi_min"]:
                baseline["rssi_min"] = rssi
            if baseline["rssi_max"] is None or rssi > baseline["rssi_max"]:
                baseline["rssi_max"] = rssi

        # Channel
        channel = data.get("channel")
        if channel is not None and channel not in baseline["channels_seen"]:
            baseline["channels_seen"].append(channel)

        # Beacon interval
        beacon = data.get("beacon_interval_ms")
        if beacon is not None:
            baseline["beacon_sum"] += beacon
            baseline["beacon_count"] += 1

        # Hourly activity
        hour = datetime.now(UTC).hour
        baseline["hourly_activity"][hour] += 1

    def _check_anomalies(self, baseline: dict, data: dict) -> dict | None:
        """Check for deviations from baseline"""
        anomalies = []
        n = baseline["observations"]

        # Calculate RSSI mean and std
        rssi_mean = baseline["rssi_sum"] / n
        rssi_variance = (baseline["rssi_sum_sq"] / n) - (rssi_mean**2)
        rssi_std = rssi_variance**0.5 if rssi_variance > 0 else 1.0

        # Check RSSI anomaly (> 2 std from mean)
        current_rssi = data.get("rssi_dbm")
        if current_rssi is not None:
            z_score = (current_rssi - rssi_mean) / rssi_std if rssi_std > 0 else 0
            if abs(z_score) > 2.5:
                anomalies.append(
                    {
                        "type": "rssi_anomaly",
                        "expected": rssi_mean,
                        "actual": current_rssi,
                        "z_score": z_score,
                    }
                )

        # Check channel anomaly
        current_channel = data.get("channel")
        if (
            current_channel is not None
            and current_channel not in baseline["channels_seen"]
        ):
            anomalies.append(
                {
                    "type": "new_channel",
                    "expected_channels": list(baseline["channels_seen"]),
                    "actual": current_channel,
                }
            )

        if anomalies:
            return {
                "bssid": data.get("bssid"),
                "timestamp": datetime.now(UTC).isoformat(),
                "anomalies": anomalies,
                "baseline_observations": n,
            }

        return None

    def get_status(self) -> dict:
        """Get baseline learning status"""
        elapsed = (datetime.now(UTC) - self.learning_start).total_seconds() / 3600
        return {
            "is_learning": self.is_learning,
            "learning_hours": self.learning_hours,
            "elapsed_hours": elapsed,
            "progress_pct": min(100, (elapsed / self.learning_hours) * 100),
            "networks_tracked": len(self.baselines),
            "total_observations": sum(
                b["observations"] for b in self.baselines.values()
            ),
        }
