"""
Tests for the Sentinel NetLab TUI state manager and helpers.
"""

import threading
import time

from sensor.tui.state_manager import AlertEntry, AppState, NetworkEntry, TUILogHandler


class TestAppState:
    """Test the thread-safe AppState data store."""

    def test_initial_state(self):
        state = AppState()
        assert state.running is False
        assert state.mode == "idle"
        assert state.total_networks == 0
        assert state.uptime == "—"

    def test_uptime_calculation(self):
        state = AppState()
        state.start_time = time.time() - 65  # 1 min 5 sec ago
        uptime = state.uptime
        assert uptime.startswith("00:01:")

    def test_push_log_queue(self):
        state = AppState()
        state.push_log("Hello TUI")
        msg = state.log_queue.get_nowait()
        assert msg == "Hello TUI"

    def test_push_log_overflow(self):
        """When queue is full, oldest message is dropped."""
        state = AppState()
        # Fill queue
        for i in range(500):
            state.push_log(f"msg-{i}")
        # Push one more—should not raise
        state.push_log("overflow-msg")
        # Queue should still be at max_size
        assert state.log_queue.qsize() <= 500

    def test_push_network(self):
        state = AppState()
        net = NetworkEntry(
            timestamp="10:00:00",
            bssid="AA:BB:CC:DD:EE:FF",
            ssid="TestNet",
            rssi=-45,
            channel=6,
            security="WPA2",
        )
        state.push_network(net)
        result = state.network_queue.get_nowait()
        assert result.ssid == "TestNet"
        assert result.rssi == -45

    def test_push_alert(self):
        state = AppState()
        alert = AlertEntry(
            timestamp="10:00:00",
            severity="Critical",
            title="Evil Twin",
            description="Detected evil twin AP",
        )
        state.push_alert(alert)
        result = state.alert_queue.get_nowait()
        assert result.severity == "Critical"

    def test_update_spool(self):
        state = AppState()
        state.update_spool({"queued": 10, "inflight": 2})
        assert state.spool_queued == 10
        assert state.spool_inflight == 2

    def test_thread_safety(self):
        """Multiple threads pushing data concurrently."""
        state = AppState()
        errors = []

        def push_logs():
            try:
                for i in range(100):
                    state.push_log(f"thread-msg-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=push_logs) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


class TestTUILogHandler:
    """Test the custom logging handler."""

    def test_handler_pushes_to_state(self):
        import logging

        state = AppState()
        handler = TUILogHandler(state)
        handler.setLevel(logging.INFO)

        logger = logging.getLogger("test.tui.handler")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        logger.info("Test log message")

        msg = state.log_queue.get_nowait()
        assert "Test log message" in msg
        assert "INFO" in msg

        # Cleanup
        logger.removeHandler(handler)
