"""
Sentinel NetLab - Event Aggregator

Collapses high-frequency identical events into summary records before
they reach the buffer/transport layer. This prevents API flooding during
Deauth Floods, Beacon Floods, or in high-density environments (500+ devices).

Example: 1000 deauth frames from the same MAC in 1 second become a single
summary: {"event_type": "deauth", "bssid": "AA:BB:CC", "count": 1000,
          "rate_per_sec": 1000, "first_seen": ..., "last_seen": ...}
"""

import logging
import threading
import time
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


class EventAggregator:
    """
    Thread-safe event aggregator with configurable window and rate cap.

    Usage:
        agg = EventAggregator(window_sec=5.0, max_events_per_key=100)

        # In the hot loop:
        agg.ingest(telemetry_dict)

        # Periodically (e.g. every window_sec):
        summaries = agg.flush()
        for summary in summaries:
            buffer.append(summary)
    """

    def __init__(
        self,
        window_sec: float = 5.0,
        max_events_per_key: int = 100,
        enabled: bool = True,
    ):
        """
        Args:
            window_sec: Aggregation window in seconds. Events with the same
                        key within this window are collapsed.
            max_events_per_key: Maximum events tracked per key per window.
                                Excess events are counted but samples are
                                capped to save memory.
            enabled: If False, ingest() returns the item immediately (passthrough).
        """
        self.window_sec = window_sec
        self.max_events_per_key = max_events_per_key
        self.enabled = enabled

        # Internal state: key -> bucket
        self._buckets: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()

        # Stats
        self._total_ingested = 0
        self._total_collapsed = 0

    @staticmethod
    def _make_key(telemetry: dict[str, Any]) -> str:
        """
        Build aggregation key from telemetry.

        Key = (event_type, bssid_or_src_mac).
        This groups identical attack frames from the same source.
        """
        event_type = (
            telemetry.get("event_type")
            or telemetry.get("frame_type")
            or "unknown"
        )
        mac = (
            telemetry.get("bssid")
            or telemetry.get("src_addr")
            or telemetry.get("source_mac")
            or "unknown"
        )
        return f"{event_type}|{mac}"

    def ingest(self, telemetry: dict[str, Any]) -> dict[str, Any] | None:
        """
        Ingest a single telemetry event.

        In passthrough mode (enabled=False), returns the telemetry immediately.
        In aggregation mode, returns None (events are batched internally
        and flushed via flush()).

        Returns:
            The telemetry dict in passthrough mode, or None when aggregating.
        """
        if not self.enabled:
            return telemetry

        key = self._make_key(telemetry)
        now = time.monotonic()

        with self._lock:
            self._total_ingested += 1

            if key not in self._buckets:
                self._buckets[key] = {
                    "event_type": (
                        telemetry.get("event_type")
                        or telemetry.get("frame_type")
                        or "unknown"
                    ),
                    "bssid": telemetry.get("bssid", ""),
                    "src_mac": (
                        telemetry.get("src_addr")
                        or telemetry.get("source_mac")
                        or ""
                    ),
                    "count": 0,
                    "first_seen": now,
                    "last_seen": now,
                    "sample": telemetry,  # Keep first event as sample
                    "extra_fields": {},
                }

            bucket = self._buckets[key]
            bucket["count"] += 1
            bucket["last_seen"] = now

            # Capture specific fields from latest event
            for field in ("rssi_dbm", "channel", "ssid", "sensor_id"):
                val = telemetry.get(field)
                if val is not None:
                    bucket["extra_fields"][field] = val

            # Auto-flush if window exceeded
            if now - self._last_flush >= self.window_sec:
                return None  # Caller should call flush()

        return None

    def flush(self) -> list[dict[str, Any]]:
        """
        Flush all accumulated buckets and return summary telemetry dicts.

        Each summary contains:
        - Original fields from the first sample event
        - count: total events in window
        - rate_per_sec: events per second
        - aggregated: True (marker for downstream to recognize)
        - first_seen / last_seen timestamps

        Returns:
            List of aggregated summary dicts. Empty if nothing accumulated.
        """
        with self._lock:
            if not self._buckets:
                self._last_flush = time.monotonic()
                return []

            summaries: list[dict[str, Any]] = []
            now = time.monotonic()

            for key, bucket in self._buckets.items():
                count = bucket["count"]
                duration = max(bucket["last_seen"] - bucket["first_seen"], 0.001)
                rate = count / duration if duration > 0 else float(count)

                # Start from the sample event (preserves all original fields)
                summary = dict(bucket["sample"])

                # Override / add aggregation metadata
                summary.update({
                    "aggregated": True,
                    "agg_count": count,
                    "agg_rate_per_sec": round(rate, 2),
                    "agg_window_sec": self.window_sec,
                    "agg_first_seen": bucket["first_seen"],
                    "agg_last_seen": bucket["last_seen"],
                })

                # Merge latest extra fields
                summary.update(bucket["extra_fields"])

                if count > 1:
                    self._total_collapsed += count - 1

                summaries.append(summary)

            self._buckets.clear()
            self._last_flush = now

            return summaries

    def should_flush(self) -> bool:
        """Check if enough time has passed to warrant a flush."""
        return (time.monotonic() - self._last_flush) >= self.window_sec

    def get_stats(self) -> dict[str, Any]:
        """Return aggregator statistics."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "window_sec": self.window_sec,
                "max_events_per_key": self.max_events_per_key,
                "active_buckets": len(self._buckets),
                "total_ingested": self._total_ingested,
                "total_collapsed": self._total_collapsed,
                "compression_ratio": (
                    round(
                        self._total_collapsed / self._total_ingested, 3
                    )
                    if self._total_ingested > 0
                    else 0
                ),
            }
