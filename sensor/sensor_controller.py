#!/usr/bin/env python3
"""
Sentinel NetLab - Sensor Controller
Main orchestrator for capture, processing, and upload.
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))  # noqa: E402

from buffer_manager import BufferManager
from capture_driver import CaptureDriver, IwCaptureDriver, MockCaptureDriver
from config import Config, get_config, init_config  # noqa: E402
from frame_parser import FrameParser
from normalizer import TelemetryNormalizer  # noqa: E402
from transport_client import TransportClient

# Import Advanced Logic
sys.path.insert(0, str(Path(__file__).parent.parent))  # Add root to path
from algos.evil_twin import AdvancedEvilTwinDetector
from algos.risk import RiskScorer
from common.metrics import MetricsCollector

logger = logging.getLogger(__name__)


class ChannelHopper:
    """
    Manages channel hopping with configurable dwell time.
    Supports adaptive channel selection based on activity.
    """

    def __init__(
        self,
        driver: CaptureDriver,
        channels: list[int] | None = None,
        dwell_ms: int = 200,
        settle_ms: int = 50,
        adaptive: bool = False,
    ):
        self.driver = driver
        # Default 2.4GHz non-overlapping
        self.channels = channels or [1, 6, 11]
        self.dwell_ms = dwell_ms
        self.settle_ms = settle_ms
        self.adaptive = adaptive

        self._current_idx = 0
        self._running = False
        self._thread: threading.Thread | None = None
        self._channel_activity: dict[int, float] = dict.fromkeys(self.channels, 1.0)

    def start(self) -> None:
        """Start channel hopping thread"""
        self._running = True
        self._thread = threading.Thread(
            target=self._hop_loop, daemon=True, name="ChannelHopper"
        )
        self._thread.start()
        logger.info(
            f"Channel hopping started: {self.channels}, dwell={self.dwell_ms}ms"
        )

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
        r = random.random() * total  # nosec B311
        cumulative = 0
        for ch in self.channels:
            cumulative += self._channel_activity[ch]
            if r <= cumulative:
                return ch
        return self.channels[0]


class TelemetryAggregator:
    """
    Aggregates telemetry for stateful analysis (sliding windows).
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self.deauth_counts: dict[str, int] = {}
        self.last_cleanup = time.time()
        self._lock = threading.Lock()

    def record_frame(self, frame_type: str, subtype: str, source: str):
        """Record frame occurrence"""
        with self._lock:
            if subtype == "deauth":
                self.deauth_counts[source] = self.deauth_counts.get(source, 0) + 1

            # Cleanup old windows periodically
            if time.time() - self.last_cleanup > self.window_seconds:
                self.deauth_counts.clear()
                self.last_cleanup = time.time()

    def get_context(self) -> dict:
        """Get current aggregation context for risk engine"""
        with self._lock:
            return {"deauth_counts": self.deauth_counts.copy()}


class SensorController:
    """
    Main sensor orchestrator.
    Coordinates capture, parsing, normalization, buffering, and upload.
    """

    def __init__(
        self,
        config: Config = None,
    ):
        """
        Initialize sensor controller.

        Args:
            config: Configuration object
        """
        if config is None:
            config = get_config()

        self.config = config
        self.sensor_id = config.sensor.id

        self.iface = config.capture.interface
        self.upload_interval = 5.0
        self.batch_size = 200

        # Initialize components
        if config.mock_mode:
            self.driver = MockCaptureDriver(self.iface)
        else:
            self.driver = IwCaptureDriver(self.iface)

        self.parser = FrameParser()

        self.normalizer = TelemetryNormalizer(
            sensor_id=self.sensor_id,
            capture_method="scapy" if not config.mock_mode else "mock",
            anonymize_ssid=config.privacy.anonymize_ssid,
            store_raw_mac=config.privacy.store_raw_mac,
            privacy_mode=config.privacy.mode,
        )

        self.buffer = BufferManager(
            max_memory_items=10000,
            storage_path=config.storage.pcap_dir.replace(
                "pcaps", "journal"
            ),  # Hacky but ok
        )

        # HACK: Retrieve HMAC secret from env since it's not in Config struct yet (or I missed it)
        # It was implicit.
        hmac_secret = os.environ.get("SENSOR_HMAC_SECRET")

        self.transport = TransportClient(
            upload_url=f"http://{config.api.host}:{config.api.port}/api/v1/telemetry",  # Construct URL
            auth_token=config.api.api_key,
            verify_ssl=config.api.ssl_enabled,
            hmac_secret=hmac_secret,
        )

        self.hopper = ChannelHopper(
            driver=self.driver,
            channels=config.capture.channels,
            dwell_ms=int(config.capture.dwell_time * 1000),
        )

        # Stateful Aggregator
        self.aggregator = TelemetryAggregator(window_seconds=60)

        # Load Risk Engine (Lazy load to avoid circular imports if any)

        # Risk Engine
        self.risk_engine = RiskScorer()

        # Advanced Detection Engines
        self.et_detector = AdvancedEvilTwinDetector()

        # Metrics
        self.metrics = MetricsCollector(self.sensor_id)

        # State
        self._running = False
        self._capture_thread: threading.Thread | None = None
        self._upload_thread: threading.Thread | None = None
        self._heartbeat_thread: threading.Thread | None = None
        self._start_time: datetime | None = None

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
        self._start_time = datetime.now(UTC)

        # Start channel hopping
        self.hopper.start()

        # Start capture processing thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="CaptureProcessor"
        )
        self._capture_thread.start()

        # Start upload thread
        self._upload_thread = threading.Thread(
            target=self._upload_loop, daemon=True, name="Uploader"
        )
        self._upload_thread.start()

        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="Heartbeat"
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
            self._heartbeat_thread,
        ]:
            if thread and thread.is_alive():
                thread.join(timeout=5)

        # Flush remaining buffer
        self.buffer.flush_to_disk()

        # Restore interface
        self.driver.disable_monitor_mode()

        logger.info("Sensor stopped")

    def status(self) -> dict[str, Any]:
        """Get sensor status"""
        uptime = 0
        if self._start_time:
            uptime = (datetime.now(UTC) - self._start_time).total_seconds()

        return {
            "sensor_id": self.sensor_id,
            "interface": self.iface,
            "running": self._running,
            "monitor_mode": self.driver.is_monitor_mode,
            "current_channel": self.hopper.get_current_channel(),
            "uptime_seconds": uptime,
            "frames_captured": self._frames_captured,
            "frames_parsed": self._frames_parsed,
            "frames_duplicates": self._frames_duplicates,
            "buffer": self.buffer.get_stats(),
            "transport": self.transport.get_stats(),
            "normalizer": self.normalizer.get_stats(),
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
                self.buffer.append(telemetry.model_dump(mode="json", exclude_none=True))

                # Feed Aggregator
                self.aggregator.record_frame(
                    telemetry.frame_type, telemetry.frame_subtype, telemetry.mac_src
                )

                # Record Metrics
                self.metrics.record_frame(telemetry.frame_type)

                # Feed Evil Twin Detector
                et_alerts = self.et_detector.ingest(telemetry.dict())
                for alert in et_alerts:
                    logger.warning(
                        f"Evil Twin Detected: {alert.ssid} ({alert.score}/100)"
                    )
                    # Convert dataclass to dict for upload
                    alert_dict = {
                        "alert_type": "evil_twin",
                        "severity": alert.severity,
                        "title": f"Evil Twin Detected: {alert.ssid}",
                        "description": alert.recommendation,
                        "evidence": alert.evidence,
                        "sensor_id": self.sensor_id,
                        "risk_score": alert.score,
                    }
                    self.buffer.append_alert(
                        alert_dict
                    )  # Assuming buffer has this or we upload direct

                # Real-time Risk Assessment (Sampled)
                # Real-time Risk Assessment
                if self._frames_captured % 10 == 0:
                    # Convert telemetry to dict for risk scoring
                    net_dict = telemetry.model_dump(mode="json", exclude_none=True)
                    risk_result = self.risk_engine.calculate_risk(net_dict)

                    if risk_result.get("risk_score", 0) > 70:
                        logger.warning(
                            f"High Risky Network: {telemetry.ssid} (Score: {risk_result['risk_score']})"
                        )
                        # Generate alert
                        self.metrics.set_risk_score(
                            telemetry.bssid, risk_result["risk_score"]
                        )

                # Record activity for adaptive hopping
                self.hopper.record_activity(parsed.channel, 1)

            except TimeoutError:
                logger.warning("Frame read timeout")
            except Exception as e:
                logger.error(f"Capture loop error: {e}", exc_info=True)
                time.sleep(0.1)  # Backoff to avoid spinning

    def _upload_loop(self) -> None:
        """Upload batches to controller"""
        while self._running:
            try:
                time.sleep(self.upload_interval)

                # Get batch
                batch = self.buffer.get_batch(max_count=self.batch_size)
                if batch is None:
                    continue

                # Add sensor_id to batch
                batch["sensor_id"] = self.sensor_id

                # Upload
                result = self.transport.upload(batch)

                if result.get("success"):
                    logger.debug(
                        f"Uploaded batch {batch['batch_id']}: {len(batch['records'])} items"
                    )
                    self.metrics.record_upload(True)
                else:
                    logger.warning(f"Upload failed: {result.get('error')}")
                    self.metrics.record_upload(
                        False, reason=result.get("error", "Unknown")
                    )

            except Exception as e:
                logger.error(f"Upload loop error: {e}")

    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats"""
        while self._running:
            try:
                time.sleep(60)

                status = self.status()
                result = self.transport.heartbeat(status)

                if result.get("success"):
                    # Process commands
                    for cmd in result.get("commands", []):
                        self._handle_command(cmd)

            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")

    def _handle_command(self, cmd: dict[str, Any]) -> None:
        """Handle command from controller"""
        cmd_type = cmd.get("type")

        if cmd_type == "set_channels":
            channels = cmd.get("channels", [])
            if channels:
                self.hopper.channels = channels
                logger.info(f"Updated channels: {channels}")

        elif cmd_type == "set_dwell":
            dwell = cmd.get("dwell_ms")
            if dwell:
                self.hopper.dwell_ms = dwell
                logger.info(f"Updated dwell time: {dwell}ms")

        elif cmd_type == "force_upload":
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
        """,
    )

    parser.add_argument("--config-file", help="Path to config file")
    parser.add_argument("--sensor-id", help="Sensor ID override")
    parser.add_argument("--iface", help="Capture interface")
    parser.add_argument("--channels", help="Comma-separated channels")
    parser.add_argument("--mock-mode", action="store_true", help="Enable mock mode")

    args = parser.parse_args()

    # Init Config
    if args.config_file:
        config = init_config(args.config_file)
    else:
        config = init_config()  # defaults + env

    # CLI Overrides (only if explicit)
    if args.iface:
        config.capture.interface = args.iface
    if args.sensor_id:
        os.environ["SENSOR_ID"] = args.sensor_id  # Store in ENV for controller
    if args.mock_mode:
        config.mock_mode = True

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Create controller
    controller = SensorController(config=config)

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
    print(f"Sensor ID: {controller.sensor_id}")
    print(f"Interface: {config.capture.interface}")
    print(f"Channels: {config.capture.channels}")
    print(f"Mock Mode: {config.mock_mode}")
    print("=" * 50)

    if controller.start():
        print("Sensor running. Press Ctrl+C to stop.")

        # Keep running
        while controller._running:
            time.sleep(1)
    else:
        print("Failed to start sensor")
        sys.exit(1)


if __name__ == "__main__":
    main()
