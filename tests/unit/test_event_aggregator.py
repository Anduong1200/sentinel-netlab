"""
Sentinel NetLab - Unit Tests for EventAggregator

Tests the sensor-side event aggregation that collapses high-frequency
identical events into summaries to prevent API flooding.
"""

import threading
import time

from sensor.event_aggregator import EventAggregator


class TestEventAggregatorBasic:
    """Core aggregation behavior."""

    def test_passthrough_when_disabled(self):
        """Disabled aggregator returns events immediately."""
        agg = EventAggregator(enabled=False)
        event = {"event_type": "beacon", "bssid": "AA:BB:CC:11:22:33"}
        result = agg.ingest(event)
        assert result == event

    def test_ingest_returns_none_when_enabled(self):
        """Enabled aggregator buffers events, returns None."""
        agg = EventAggregator(window_sec=5.0)
        event = {"event_type": "deauth", "bssid": "AA:BB:CC:11:22:33"}
        result = agg.ingest(event)
        assert result is None

    def test_single_event_flush(self):
        """One event produces one summary."""
        agg = EventAggregator(window_sec=5.0)
        agg.ingest({"event_type": "deauth", "bssid": "AA:BB:CC:11:22:33"})
        summaries = agg.flush()
        assert len(summaries) == 1
        assert summaries[0]["aggregated"] is True
        assert summaries[0]["agg_count"] == 1

    def test_burst_collapses(self):
        """1000 identical events collapse into 1 summary."""
        agg = EventAggregator(window_sec=5.0)
        for _ in range(1000):
            agg.ingest(
                {
                    "event_type": "deauth",
                    "bssid": "AA:BB:CC:11:22:33",
                    "rssi_dbm": -65,
                }
            )
        summaries = agg.flush()
        assert len(summaries) == 1
        assert summaries[0]["agg_count"] == 1000
        assert summaries[0]["agg_rate_per_sec"] > 0

    def test_different_keys_tracked_independently(self):
        """Events with different keys produce separate summaries."""
        agg = EventAggregator(window_sec=5.0)
        for _ in range(10):
            agg.ingest({"event_type": "deauth", "bssid": "AA:AA:AA:AA:AA:AA"})
        for _ in range(5):
            agg.ingest({"event_type": "beacon", "bssid": "BB:BB:BB:BB:BB:BB"})
        summaries = agg.flush()
        assert len(summaries) == 2
        counts = {s["bssid"]: s["agg_count"] for s in summaries}
        assert counts.get("AA:AA:AA:AA:AA:AA") == 10
        assert counts.get("BB:BB:BB:BB:BB:BB") == 5

    def test_same_mac_different_event_types(self):
        """Same MAC but different event types are separate keys."""
        agg = EventAggregator(window_sec=5.0)
        agg.ingest({"event_type": "deauth", "bssid": "AA:BB:CC:11:22:33"})
        agg.ingest({"event_type": "beacon", "bssid": "AA:BB:CC:11:22:33"})
        summaries = agg.flush()
        assert len(summaries) == 2

    def test_flush_clears_state(self):
        """Flush empties all buckets."""
        agg = EventAggregator(window_sec=5.0)
        agg.ingest({"event_type": "deauth", "bssid": "AA:BB:CC:11:22:33"})
        agg.flush()
        summaries = agg.flush()
        assert summaries == []

    def test_summary_preserves_sample_fields(self):
        """Summary preserves original fields from the first event."""
        agg = EventAggregator(window_sec=5.0)
        agg.ingest(
            {
                "event_type": "deauth",
                "bssid": "AA:BB:CC:11:22:33",
                "channel": 6,
                "rssi_dbm": -65,
                "custom_field": "preserved",
            }
        )
        summaries = agg.flush()
        assert summaries[0]["custom_field"] == "preserved"
        assert summaries[0]["bssid"] == "AA:BB:CC:11:22:33"


class TestEventAggregatorTiming:
    """Window and timing behavior."""

    def test_should_flush_after_window(self):
        agg = EventAggregator(window_sec=0.05)  # 50ms
        assert not agg.should_flush()
        time.sleep(0.1)
        assert agg.should_flush()

    def test_flush_resets_timer(self):
        agg = EventAggregator(window_sec=0.05)
        time.sleep(0.1)
        assert agg.should_flush()
        agg.flush()
        assert not agg.should_flush()


class TestEventAggregatorStats:
    """Statistics tracking."""

    def test_stats_initial(self):
        agg = EventAggregator(window_sec=5.0)
        stats = agg.get_stats()
        assert stats["enabled"] is True
        assert stats["total_ingested"] == 0
        assert stats["total_collapsed"] == 0
        assert stats["active_buckets"] == 0

    def test_stats_after_burst(self):
        agg = EventAggregator(window_sec=5.0)
        for _ in range(100):
            agg.ingest({"event_type": "deauth", "bssid": "AA:BB:CC:11:22:33"})
        stats = agg.get_stats()
        assert stats["total_ingested"] == 100
        assert stats["active_buckets"] == 1

    def test_compression_ratio(self):
        agg = EventAggregator(window_sec=5.0)
        for _ in range(1000):
            agg.ingest({"event_type": "deauth", "bssid": "AA:BB:CC:11:22:33"})
        agg.flush()
        stats = agg.get_stats()
        assert stats["compression_ratio"] > 0.99  # 999/1000


class TestEventAggregatorThreadSafety:
    """Concurrent access should not cause errors."""

    def test_concurrent_ingest(self):
        agg = EventAggregator(window_sec=5.0)
        errors = []

        def ingester(thread_id):
            try:
                for _i in range(100):
                    agg.ingest(
                        {
                            "event_type": "deauth",
                            "bssid": f"AA:BB:{thread_id:02X}:00:00:00",
                        }
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=ingester, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        summaries = agg.flush()
        assert len(summaries) == 10
        total = sum(s["agg_count"] for s in summaries)
        assert total == 1000
