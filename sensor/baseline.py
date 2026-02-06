"""
Sentinel NetLab - Baseline Manager
Establishes "Normal" behavior profiles for networks to enable deviation-based detection.

Features:
- Learning Mode: Learns BSSIDs, Vendors, Channels, and Signal Stats.
- Monitor Mode: Detects deviations from baseline (Vendor Spoofing, Signal Spikes).
- Persistent Storage: SQLite backed.
"""

import json
import logging
import math
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BaselineEntry:
    """Represents a baseline profile for a BSSID."""
    bssid: str
    ssid: str | None
    vendor: str | None
    channel_history: list[int]
    rssi_avg: float
    rssi_std: float
    rssi_samples: int
    capabilities: dict[str, Any]
    first_seen: datetime
    last_seen: datetime

    def is_vendor_match(self, observed_vendor: str | None) -> bool:
        """Check if observed vendor matches baseline."""
        if not self.vendor or not observed_vendor:
            return True # Not enough info
        # Simple string match, could be improved with normalization
        return self.vendor.lower().startswith(observed_vendor.lower()) or \
               observed_vendor.lower().startswith(self.vendor.lower())

    def check_signal_deviation(self, rssi: int, threshold_sigma: float = 3.0) -> float:
        """
        Calculate signal deviation score (Z-score).
        Returns deviation magnitude (0.0 to 1.0+).
        """
        if self.rssi_samples < 10:
            return 0.0 # Not enough samples

        diff = rssi - self.rssi_avg
        if diff <= 0:
            return 0.0 # Weaker signal is usually fine (moving away)

        # If signal is significantly stronger than average + sigma
        # It implies the source is much closer than expected -> Potential Evil Twin

        sigma = max(self.rssi_std, 5.0) # Min sigma 5dB to avoid noise sensitivity
        z_score = diff / sigma

        if z_score > threshold_sigma:
            # Map z_score 3.0 -> 0.6, 5.0 -> 1.0
            return min(1.0, (z_score - threshold_sigma) / 2.0 + 0.5)

        return 0.0


class BaselineManager:
    """
    Manages operational baselines for WiFi networks.
    """

    DEFAULT_DB_PATH = "data/baseline.db"

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self.learning_mode = False

        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path, check_same_thread=False, timeout=30.0
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    bssid TEXT PRIMARY KEY,
                    ssid TEXT,
                    vendor TEXT,
                    channel_history TEXT, -- JSON list
                    rssi_sum REAL DEFAULT 0,
                    rssi_sq_sum REAL DEFAULT 0,
                    rssi_samples INTEGER DEFAULT 0,
                    capabilities TEXT, -- JSON dict
                    first_seen TEXT,
                    last_seen TEXT
                )
            """)
            conn.commit()

    def set_learning_mode(self, enabled: bool) -> None:
        """Enable or disable learning mode."""
        self.learning_mode = enabled
        logger.info(f"Baseline Learning Mode: {'ENABLED' if enabled else 'DISABLED'}")

    def learn(self, frame_data: dict[str, Any]) -> None:
        """
        Update baseline stats from observed frame.
        Used in both Learning Mode (active) and Monitor Mode (passive update).
        """
        bssid = frame_data.get("bssid")
        if not bssid:
            return

        with self._lock:
            conn = self._get_conn()

            # Fetch existing
            cursor = conn.execute("SELECT * FROM baselines WHERE bssid = ?", (bssid,))
            row = cursor.fetchone()

            now_iso = datetime.now(UTC).isoformat()
            rssi = frame_data.get("rssi_dbm", -100)
            channel = frame_data.get("channel")
            ssid = frame_data.get("ssid")
            vendor = frame_data.get("vendor_oui") # Assumes normalizer provides this

            if row:
                # Update Stats (Welford's/Running sums)
                new_sum = row["rssi_sum"] + rssi
                new_sq_sum = row["rssi_sq_sum"] + (rssi * rssi)
                new_samples = row["rssi_samples"] + 1

                # Update Channels
                channels = json.loads(row["channel_history"] or "[]")
                if channel and channel not in channels:
                    channels.append(channel)
                    channels.sort()

                # Identity updates (Snapshot if not set)
                curr_ssid = row["ssid"] or ssid
                curr_vendor = row["vendor"] or vendor

                conn.execute("""
                    UPDATE baselines SET
                        rssi_sum = ?, rssi_sq_sum = ?, rssi_samples = ?,
                        channel_history = ?,
                        last_seen = ?,
                        ssid = ?, vendor = ?
                    WHERE bssid = ?
                """, (new_sum, new_sq_sum, new_samples, json.dumps(channels), now_iso, curr_ssid, curr_vendor, bssid))

            else:
                # New Entry
                conn.execute("""
                    INSERT INTO baselines (
                        bssid, ssid, vendor, channel_history, 
                        rssi_sum, rssi_sq_sum, rssi_samples, 
                        first_seen, last_seen, capabilities
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    bssid, ssid, vendor,
                    json.dumps([channel] if channel else []),
                    rssi, rssi * rssi, 1,
                    now_iso, now_iso, "{}"
                ))

            conn.commit()

    def check_deviation(self, frame_data: dict[str, Any]) -> dict[str, Any] | None:
        """
        Check frame against baseline.
        Returns deviation dict if anomalies found, else None.
        """
        if self.learning_mode:
            self.learn(frame_data)
            return None # Suppress alerts in learning mode

        bssid = frame_data.get("bssid")
        if not bssid:
            return None

        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("SELECT * FROM baselines WHERE bssid = ?", (bssid,))
            row = cursor.fetchone()

            if not row:
                # Unknown Device
                # In strict mode, this might be an alert.
                # For now, we auto-learn new devices conservatively or return "New Device" info.
                self.learn(frame_data)
                return None

        # Parse Baseline
        rssi_samples = row["rssi_samples"]
        if rssi_samples < 5:
             self.learn(frame_data) # Keep learning
             return None

        avg = row["rssi_sum"] / rssi_samples
        variance = (row["rssi_sq_sum"] / rssi_samples) - (avg * avg)
        std_dev = math.sqrt(max(0, variance))

        baseline = BaselineEntry(
            bssid=row["bssid"],
            ssid=row["ssid"],
            vendor=row["vendor"],
            channel_history=json.loads(row["channel_history"]),
            rssi_avg=avg,
            rssi_std=std_dev,
            rssi_samples=rssi_samples,
            capabilities={},
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=None # Not needed here
        )

        deviations = []
        score = 0.0

        # 1. Vendor Check
        observed_vendor = frame_data.get("vendor_oui")
        if baseline.vendor and observed_vendor:
            if not baseline.is_vendor_match(observed_vendor):
                deviations.append(f"Vendor Mismatch: Expected {baseline.vendor}, Got {observed_vendor}")
                score += 1.0 # Critical

        # 2. Signal Check
        sig_score = baseline.check_signal_deviation(frame_data.get("rssi_dbm", -100))
        if sig_score > 0:
            deviations.append(f"Signal Anomaly: RSSI {frame_data.get('rssi_dbm')} vs Avg {avg:.1f} (Z={sig_score:.1f})")
            score += sig_score

        # 3. Channel Check
        # Optional: Evil Twin on different channel?
        curr_channel = frame_data.get("channel")
        if curr_channel and curr_channel not in baseline.channel_history:
             # Weak evidence, APs can switch. But if fixed infra...
             # deviations.append(f"New Channel: {curr_channel}")
             pass

        # Always passive learn to update stats slowly
        self.learn(frame_data)

        if deviations:
            return {
                "score": min(1.0, score),
                "reasons": deviations,
                "baseline": {
                    "vendor": baseline.vendor,
                    "avg_rssi": round(avg, 1)
                }
            }

        return None

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
