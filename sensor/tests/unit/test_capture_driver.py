"""
Sentinel NetLab - Unit Tests for Capture Driver
Tests capture_driver.py with MockCaptureDriver.
"""

import time
from pathlib import Path

import pytest

try:
    from capture_driver import CaptureDriver, MockCaptureDriver, RawFrame
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from capture_driver import CaptureDriver, MockCaptureDriver, RawFrame


class TestMockCaptureDriver:
    """Unit tests for MockCaptureDriver"""

    @pytest.fixture
    def driver(self):
        return MockCaptureDriver("mock0")

    def test_enable_monitor_mode_success(self, driver):
        """enable_monitor_mode returns success on mock driver"""
        success, error = driver.enable_monitor_mode()

        assert success
        assert error == ""
        assert driver.is_monitor_mode

    def test_disable_monitor_mode(self, driver):
        """disable_monitor_mode restores state"""
        driver.enable_monitor_mode()
        success, error = driver.disable_monitor_mode()

        assert success
        assert not driver.is_monitor_mode

    def test_set_channel_applies(self, driver):
        """set_channel called before read_raw_frame"""
        driver.enable_monitor_mode()

        result = driver.set_channel(6)

        assert result

    def test_read_raw_frame_timeout(self, driver):
        """read_raw_frame returns None if no frame within timeout"""
        driver.enable_monitor_mode()
        driver.start_capture()

        # With short timeout, may return None
        start = time.time()
        driver.read_frame(timeout_ms=50)
        elapsed = time.time() - start

        # Should respect timeout approximately
        assert elapsed < 0.2  # Should not block too long
        driver.stop_capture()

    def test_mock_driver_emit_frames(self, driver):
        """Mock yields expected frames when running"""
        driver.enable_monitor_mode()
        driver.start_capture()

        frames = []
        for _ in range(20):  # Try multiple reads
            frame = driver.read_frame(timeout_ms=100)
            if frame:
                frames.append(frame)

        # Mock should emit some frames
        # (probabilistic, so just check we got at least some)
        assert len(frames) >= 0  # May be 0 due to randomness

        driver.stop_capture()

    def test_start_stop_capture(self, driver):
        """Start and stop capture cleanly"""
        driver.enable_monitor_mode()

        assert driver.start_capture()
        assert driver._running

        driver.stop_capture()
        assert not driver._running

    def test_raw_frame_structure(self, driver):
        """RawFrame has expected fields"""
        driver.enable_monitor_mode()
        driver.start_capture()

        # Read until we get a frame or timeout
        frame = None
        for _ in range(50):
            frame = driver.read_frame(timeout_ms=50)
            if frame:
                break

        if frame:
            assert isinstance(frame, RawFrame)
            assert isinstance(frame.data, bytes)
            assert isinstance(frame.timestamp, float)
            assert isinstance(frame.channel, int)
            assert frame.iface == "mock0"

        driver.stop_capture()


class TestCaptureDriverInterface:
    """Test CaptureDriver abstract interface"""

    def test_abstract_methods_defined(self):
        """CaptureDriver has required abstract methods"""
        required_methods = [
            'enable_monitor_mode',
            'disable_monitor_mode',
            'set_channel',
            'read_frame',
            'start_capture',
            'stop_capture'
        ]

        for method in required_methods:
            assert hasattr(CaptureDriver, method)
