#!/usr/bin/env python3
"""
Sentinel NetLab - Sensor Controller
Main orchestrator for capture, processing, and upload.
"""

import sys
import time
import signal
import logging
import threading
import argparse
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))  # noqa: E402

from transport import BufferManager, TransportClient  # noqa: E402
from telemetry import TelemetryNormalizer  # noqa: E402
from capture import CaptureDriver, IwCaptureDriver, MockCaptureDriver, FrameParser  # noqa: E402


logger = logging.getLogger(__name__)


class ChannelHopper:
    """
    Manages channel hopping with configurable dwell time.
    Supports adaptive channel selection based on activity.
    """

    def __init__(
        self,
        driver: CaptureDriver,
        channels: Optional[List[int]] = None,
        dwell_ms: int = 200,
        settle_ms: int = 50,
        adaptive: bool = False
    ):
        self.driver = driver
        # Default 2.4GHz non-overlapping
        self.channels = channels or [1, 6, 11]
        self.dwell_ms = dwell_ms
        self.settle_ms = settle_ms
        self.adaptive = adaptive

        self._current_idx = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._channel_activity: Dict[int, float] = {
            ch: 1.0 for ch in self.channels}

    def start(self) -> None:
        """Start channel hopping thread"""
        self._running = True
        self._thread = threading.Thread(
            target=self._hop_loop,
            daemon=True,
            name="ChannelHopper"
        )
        self._thread.start()
        logger.info(
            f"Channel hopping started: {self.channels}, dwell={self.dwell_ms}ms")

    def stop(self) -> None:
        """Stop channel hopping"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def get_current_channel(self) -> int:
        """Get current channel"""
        if self._current_idx < len(self.channels):
            return self.channels[self._current_idx]
        return 0

    def record_activity(self, channel: int, count: int) -> None:
        """Record frame activity on channel for adaptive mode"""
        if channel in self._channel_activity:
            # Exponential moving average
            alpha = 0.3
            self._channel_activity[channel] = (
                alpha * count + (1 - alpha) * self._channel_activity[channel]
            )

    def _hop_loop(self) -> None:
        """Main hopping loop"""
        while self._running:
            try:
                # Select next channel
                if self.adaptive:
                    channel = self._select_adaptive()
                else:
                    channel = self._select_round_robin()

                # Switch channel
                if self.driver.set_channel(channel):
                    time.sleep(self.settle_ms / 1000.0)

                # Dwell
                time.sleep(self.dwell_ms / 1000.0)

            except Exception as e:
                logger.error(f"Channel hop error: {e}")
                time.sleep(1)

    def _select_round_robin(self) -> int:
        """Simple round-robin selection"""
        self._current_idx = (self._current_idx + 1) % len(self.channels)
        return self.channels[self._current_idx]

    def _select_adaptive(self) -> int:
        """Select channel weighted by activity"""
        import random
        total = sum(self._channel_activity.values())
        r = random.random() * total
        cumulative = 0
        for ch in self.channels:
            cumulative += self._channel_activity[ch]
            if r <= cumulative:
                return ch
        return self.channels[0]


class SensorController:
    """
    Main sensor orchestrator.
    Coordinates capture, parsing, normalization, buffering, and upload.
    """

    def __init__(
        self,
        sensor_id: str,
        iface: str,
        channels: Optional[List[int]] = None,
        dwell_ms: int = 200,
        upload_url: str = "http://localhost:5000/api/v1/telemetry",
        auth_token: str = "sentinel-dev-2024",
        storage_path: str = "/var/lib/sentinel/journal",
        buffer_size: int = 10000,
        batch_size: int = 200,
        upload_interval: float = 5.0,
        mock_mode: bool = False,
        anonymize_ssid: bool = False
    ):
        """
        Initialize sensor controller.

        Args:
            sensor_id: Unique sensor identifier
            iface: Network interface
            channels: Channel list for hopping
            dwell_ms: Dwell time per channel
            upload_url: Controller telemetry endpoint
            auth_token: Authentication token
            storage_path: Journal storage path
            buffer_size: Max buffer items
            batch_size: Items per upload batch
            upload_interval: Seconds between uploads
            mock_mode: Use mock capture driver
            anonymize_ssid: Hash SSIDs for privacy
        """
        self.sensor_id = sensor_id
        self.iface = iface
        self.upload_interval = upload_interval
        self.batch_size = batch_size

        # Initialize components
        if mock_mode:
            self.driver = MockCaptureDriver(iface)
        else:
            self.driver = IwCaptureDriver(iface)

        self.parser = FrameParser()

        self.normalizer = TelemetryNormalizer(
            sensor_id=sensor_id,
            capture_method="scapy" if not mock_mode else "mock",
            anonymize_ssid=anonymize_ssid
        )

        self.buffer = BufferManager(
            max_memory_items=buffer_size,
            storage_path=storage_path
        )

        self.transport = TransportClient(
            upload_url=upload_url,
            auth_token=auth_token
        )

        self.hopper = ChannelHopper(
            driver=self.driver,
            channels=channels,
            dwell_ms=dwell_ms
        )

        # State
        self._running = False
        self._capture_thread: Optional[threading.Thread] = None
        self._upload_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._start_time: Optional[datetime] = None

        # Stats
        self._frames_captured = 0
        self._frames_parsed = 0
        self._frames_duplicates = 0

    def start(self) -> bool:
        """
        Start sensor capture and upload loops.

        Returns:
            True if started successfully
        """
        logger.info(f"Starting sensor {self.sensor_id} on {self.iface}")

        # Enable monitor mode
        success, error = self.driver.enable_monitor_mode()
        if not success:
            logger.error(f"Failed to enable monitor mode: {error}")
            return False

        # Start capture
        if not self.driver.start_capture():
            logger.error("Failed to start capture")
            return False

        self._running = True
        self._start_time = datetime.now(timezone.utc)

        # Start channel hopping
        self.hopper.start()

        # Start capture processing thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="CaptureProcessor"
        )
        self._capture_thread.start()

        # Start upload thread
        self._upload_thread = threading.Thread(
            target=self._upload_loop,
            daemon=True,
            name="Uploader"
        )
        self._upload_thread.start()

        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="Heartbeat"
        )
        self._heartbeat_thread.start()

        logger.info("Sensor started successfully")
        return True

    def stop(self) -> None:
        """Stop sensor gracefully"""
        logger.info("Stopping sensor...")

        self._running = False

        # Stop components
        self.hopper.stop()
        self.driver.stop_capture()

        # Wait for threads
        for thread in [
                self._capture_thread,
                self._upload_thread,
                self._heartbeat_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=5)

        # Flush remaining buffer
        self.buffer.flush_to_disk()

        # Restore interface
        self.driver.disable_monitor_mode()

        logger.info("Sensor stopped")

    def status(self) -> Dict[str, Any]:
        """Get sensor status"""
        uptime = 0
        if self._start_time:
            uptime = (
                datetime.now(
                    timezone.utc) -
                self._start_time).total_seconds()

        return {
            'sensor_id': self.sensor_id,
            'interface': self.iface,
            'running': self._running,
            'monitor_mode': self.driver.is_monitor_mode,
            'current_channel': self.hopper.get_current_channel(),
            'uptime_seconds': uptime,
            'frames_captured': self._frames_captured,
            'frames_parsed': self._frames_parsed,
            'frames_duplicates': self._frames_duplicates,
            'buffer': self.buffer.get_stats(),
            'transport': self.transport.get_stats(),
            'normalizer': self.normalizer.get_stats()
        }

    def _capture_loop(self) -> None:
        """Process captured frames"""
        while self._running:
            try:
                # Read frame from driver
                raw_frame = self.driver.read_frame(timeout_ms=100)
                if raw_frame is None:
                    continue

                self._frames_captured += 1

                # Parse frame
                parsed = self.parser.parse(raw_frame.data, raw_frame.timestamp)
                if parsed is None or parsed.frame_type == "other":
                    continue

                # Check duplicate
                if self.parser.is_duplicate(parsed):
                    self._frames_duplicates += 1
                    continue

                self._frames_parsed += 1

                # Normalize to telemetry
                telemetry = self.normalizer.normalize(parsed)

                # Add to buffer
                self.buffer.append(telemetry.to_dict())

                # Record activity for adaptive hopping
                self.hopper.record_activity(parsed.channel, 1)

            except Exception as e:
                logger.error(f"Capture loop error: {e}")

    def _upload_loop(self) -> None:
        """Upload batches to controller"""
        while self._running:
            try:
                time.sleep(self.upload_interval)

                # Get batch
                batch = self.buffer.get_batch(max_count=self.batch_size)
                if batch is None:
                    continue

                # Upload
                result = self.transport.upload(batch)

                if result.get('success'):
                    logger.debug(
                        f"Uploaded batch {batch['batch_id']}: {batch['item_count']} items")
                else:
                    logger.warning(f"Upload failed: {result.get('error')}")

            except Exception as e:
                logger.error(f"Upload loop error: {e}")

    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats"""
        while self._running:
            try:
                time.sleep(60)

                status = self.status()
                result = self.transport.heartbeat(status)

                if result.get('success'):
                    # Process commands
                    for cmd in result.get('commands', []):
                        self._handle_command(cmd)

            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")

    def _handle_command(self, cmd: Dict[str, Any]) -> None:
        """Handle command from controller"""
        cmd_type = cmd.get('type')

        if cmd_type == 'set_channels':
            channels = cmd.get('channels', [])
            if channels:
                self.hopper.channels = channels
                logger.info(f"Updated channels: {channels}")

        elif cmd_type == 'set_dwell':
            dwell = cmd.get('dwell_ms')
            if dwell:
                self.hopper.dwell_ms = dwell
                logger.info(f"Updated dwell time: {dwell}ms")

        elif cmd_type == 'force_upload':
            batch = self.buffer.get_batch(max_count=1000)
            if batch:
                self.transport.upload(batch)


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Sentinel NetLab Sensor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic capture
  %(prog)s --sensor-id rpi-01 --iface wlan0mon

  # With specific channels
  %(prog)s --sensor-id rpi-01 --iface wlan0mon --channels 1,6,11

  # Mock mode (no hardware)
  %(prog)s --sensor-id test-01 --iface mock0 --mock-mode
        """
    )

    # Required
    parser.add_argument('--sensor-id', required=True, help='Unique sensor ID')
    parser.add_argument('--iface', required=True, help='Network interface')

    # Channel options
    parser.add_argument(
        '--channels',
        help='Comma-separated channel list (default: 1,6,11)')
    parser.add_argument(
        '--dwell-ms',
        type=int,
        default=200,
        help='Channel dwell time (ms)')

    # Batch options
    parser.add_argument(
        '--batch-size',
        type=int,
        default=200,
        help='Max frames per batch')
    parser.add_argument(
        '--batch-bytes',
        type=int,
        default=256 * 1024,
        help='Max batch size bytes')
    parser.add_argument(
        '--upload-interval',
        type=float,
        default=5.0,
        help='Upload interval (sec)')

    # Controller
    parser.add_argument(
        '--upload-url',
        default='http://localhost:5000/api/v1/telemetry',
        help='Controller telemetry endpoint')
    parser.add_argument('--auth-token', default='sentinel-dev-2024',
                        help='Auth token for controller')

    # Storage
    parser.add_argument('--storage-path', default='/var/lib/sentinel/journal',
                        help='Journal storage path')
    parser.add_argument(
        '--max-disk-usage',
        type=int,
        default=100,
        help='Max disk MB')

    # Mode
    parser.add_argument(
        '--mock-mode',
        action='store_true',
        help='Use mock capture')
    parser.add_argument(
        '--anonymize-ssid',
        action='store_true',
        help='Hash SSIDs')

    # Logging
    parser.add_argument('--log-level', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])

    # Config file
    parser.add_argument('--config-file', help='JSON/YAML config file')

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )

    # Parse channels
    channels = None
    if args.channels:
        channels = [int(c.strip()) for c in args.channels.split(',')]

    # Create controller
    controller = SensorController(
        sensor_id=args.sensor_id,
        iface=args.iface,
        channels=channels,
        dwell_ms=args.dwell_ms,
        upload_url=args.upload_url,
        auth_token=args.auth_token,
        storage_path=args.storage_path,
        batch_size=args.batch_size,
        upload_interval=args.upload_interval,
        mock_mode=args.mock_mode,
        anonymize_ssid=args.anonymize_ssid
    )

    # Signal handlers
    def signal_handler(sig, frame):
        logger.info("Received shutdown signal")
        controller.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start
    print("=" * 50)
    print("Sentinel NetLab Sensor")
    print("=" * 50)
    print(f"Sensor ID: {args.sensor_id}")
    print(f"Interface: {args.iface}")
    print(f"Channels: {channels or 'auto'}")
    print(f"Mock Mode: {args.mock_mode}")
    print("=" * 50)

    if controller.start():
        print("Sensor running. Press Ctrl+C to stop.")

        # Keep running
        while controller._running:
            time.sleep(1)
    else:
        print("Failed to start sensor")
        sys.exit(1)


if __name__ == '__main__':
    main()
