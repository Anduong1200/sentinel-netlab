import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock

# Add path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sensor.capture_driver import MockCaptureDriver, RawFrame
from sensor.sensor_controller import SensorController


class TestCaptureDriver(MockCaptureDriver):
    """Custom driver that yields a fixed sequence of frames"""

    def __init__(self, iface="test0", frames=None):
        super().__init__(iface)
        self.frames_to_send = frames or []
        self.sent_count = 0

    def read_frame(self, timeout_ms=100):
        if not self._running:
            return None

        time.sleep(timeout_ms / 1000.0)

        if self.sent_count < len(self.frames_to_send):
            frame = self.frames_to_send[self.sent_count]
            self.sent_count += 1
            return frame
        return None


class TestIntegrationFlow(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.storage_path = os.path.join(self.test_dir, "journal")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_end_to_end_flow(self):
        """
        Verify that frames are captured, processed, and buffered.
        """
        # Create a mock beacon frame
        # Scapy-like byte construction for a beacon
        # simple beacon: FC, Duration, Addrs, Seq, Timestamp, Interval, Caps, SSIDs
        # minimal valid frame for parser
        # Radiotap Header (8 bytes): Ver(1), Pad(1), Len(2), Present(4)
        radiotap_header = b"\x00\x00\x08\x00\x00\x00\x00\x00"

        dot11_header = (
            b"\x80\x00"  # Frame Control (Beacon)
            + b"\x00\x00"  # Duration
            + b"\xff\xff\xff\xff\xff\xff"  # DA (Broadcast)
            + b"\xaa\xbb\xcc\xdd\xee\xff"  # SA (BSSID)
            + b"\xaa\xbb\xcc\xdd\xee\xff"  # BSSID
            + b"\x00\x00"  # Sequence
            + b"\x00" * 8  # Timestamp
            + b"\x64\x00"  # Interval
            + b"\x11\x04"  # Capabilities
            + b"\x00\x07"
            + b"TestNet"  # SSID IE (Tag 0, Len 7, "TestNet")
        )

        frame_data = radiotap_header + dot11_header

        test_frame = RawFrame(
            data=frame_data, timestamp=time.monotonic(), channel=6, iface="test0"
        )

        from sensor.config import (
            APIConfig,
            CaptureConfig,
            Config,
            PrivacyConfig,
            SensorConfig,
            StorageConfig,
        )

        config = Config(
            sensor=SensorConfig(id="test-sensor-integration"),
            capture=CaptureConfig(interface="test0", channels=[6], dwell_time=0.1),
            api=APIConfig(
                host="mock-controller", port=80, api_key="test-key", ssl_enabled=False
            ),
            storage=StorageConfig(pcap_dir=self.storage_path),
            privacy=PrivacyConfig(),
            mock_mode=True,
        )

        # Initialize controller in mock mode
        controller = SensorController(config=config)

        # Override driver with our test driver
        test_driver = TestCaptureDriver(frames=[test_frame])
        controller.driver = test_driver

        # Mock TransportClient to avoid network errors
        controller.transport = MagicMock()
        controller.transport.upload.return_value = {"success": True}
        controller.transport.heartbeat.return_value = {"success": True}

        # Start
        print("Starting controller...")
        controller.start()

        # Wait for processing
        # 1 second should be enough for 1 frame
        time.sleep(2)

        # Stop
        print("Stopping controller...")
        controller.stop()

        # Verify Stats
        stats = controller.status()
        print("Controller Status:", stats)

        self.assertGreater(
            stats["frames_captured"], 0, "Should have captured at least 1 frame"
        )
        self.assertGreater(
            stats["frames_parsed"], 0, "Should have parsed at least 1 frame"
        )

        # Verify Buffer
        # The buffer might have been flushed to 'disk' (journal file) or uploaded
        # Since we mocked transport, upload succeeds, so buffer might be empty?
        # But 'frames_parsed' confirms processing.
        # Let's check if 'upload' was called on transport
        controller.transport.upload.assert_called()

        # Check if we can see what was uploaded
        uploaded_batch = controller.transport.upload.call_args[0][0]
        self.assertEqual(uploaded_batch["sensor_id"], "test-sensor-integration")
        self.assertTrue(len(uploaded_batch["items"]) > 0)

        item = uploaded_batch["items"][0]
        print("Uploaded Item:", item)
        self.assertEqual(item["ssid"], "TestNet")
        self.assertEqual(
            uploaded_batch["items"][0]["bssid"], "AA:BB:CC:00:00:00"
        )  # Privacy enabled by default


if __name__ == "__main__":
    unittest.main()
