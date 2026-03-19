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
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

# Import Advanced Logic
from algos.exploit_chain_analyzer import ExploitChainAnalyzer
from algos.risk import RiskScorer
from common.metrics import MetricsCollector
from common.privacy import anonymize_mac
from sensor.alert_manager import AlertManager
from sensor.baseline import BaselineManager
from sensor.buffer_manager import BufferManager
from sensor.capture_driver import IwCaptureDriver, MockCaptureDriver, PcapCaptureDriver
from sensor.channel_hopper import ChannelHopper
from sensor.config import Config, get_config, init_config
from sensor.detection import SensorDetectionOrchestrator
from sensor.detection.analysis_orchestrator import SensorAnalysisOrchestrator
from sensor.frame_parser import FrameParser
from sensor.monitor import SensorMonitor
from sensor.normalizer import TelemetryNormalizer
from sensor.spool import SqliteQueue
from sensor.telemetry_aggregator import TelemetryAggregator
from sensor.transport import TransportClient
from sensor.worker import TransportWorker

logger = logging.getLogger(__name__)


class SensorController:
    """
    Main sensor orchestrator.
    Coordinates capture, parsing, normalization, buffering, and upload.
    """

    def __init__(
        self,
        config: Config = None,
        on_network: Callable[[dict[str, Any]], None] | None = None,
        on_alert: Callable[[dict[str, Any]], None] | None = None,
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
        self.on_network = on_network
        self.on_alert = on_alert

        self.iface = config.capture.interface
        self.upload_interval = float(getattr(config.upload, "interval_sec", 5.0))
        self.batch_size = int(getattr(config.upload, "batch_size", 200))

        # Initialize components
        if getattr(config.capture, "pcap_file", None):
            self.driver = PcapCaptureDriver(self.iface, config.capture.pcap_file)
        elif config.mock_mode:
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

        upload_url = config.api.upload_url or (
            f"http://{config.api.host}:{config.api.port}/api/v1/telemetry"
        )
        self.transport = TransportClient(
            upload_url=upload_url,
            auth_token=config.api.api_key,
            verify_ssl=config.api.ssl_enabled,
            hmac_secret=config.api.hmac_secret,
        )

        # Persistent Queue (Spool) for reliable delivery
        spool_path = os.path.join(
            config.storage.pcap_dir.replace("pcaps", "data"), "spool.db"
        )
        self.queue = SqliteQueue(db_path=spool_path)

        # Background upload worker
        self.upload_worker = TransportWorker(
            queue=self.queue,
            client=self.transport,
            on_success=self._on_upload_success,
            on_failure=self._on_upload_failure,
        )

        # Baseline Manager
        baseline_path = os.path.join(
            config.storage.pcap_dir.replace("pcaps", "data"), "baseline.db"
        )
        self.baseline = BaselineManager(db_path=baseline_path)

        self.hopper = ChannelHopper(
            driver=self.driver,
            channels=config.capture.channels,
            dwell_ms=int(config.capture.dwell_time * 1000),
        )

        # Stateful Aggregator
        self.aggregator = TelemetryAggregator(window_seconds=60)

        # Load Risk Engine (Lazy load to avoid circular imports if any)

        # Risk Engine
        ml_model = config.ml.model_path if config.ml.enabled else None
        self.risk_engine = RiskScorer(ml_model_path=ml_model)

        # Advanced Detection - Unified Orchestrator
        self.detector_orchestrator = SensorDetectionOrchestrator.from_config(
            config, sensor_id=self.sensor_id
        )
        self.chain_analyzer = ExploitChainAnalyzer()

        # Analysis Orchestrator (baseline, risk, chain correlation)
        self.analysis = SensorAnalysisOrchestrator(
            risk_engine=self.risk_engine,
            baseline=self.baseline,
            chain_analyzer=self.chain_analyzer,
            sensor_id=self.sensor_id,
        )

        # Metrics
        self.metrics = MetricsCollector(self.sensor_id)

        # Helper Managers
        from sensor.health import HealthServer

        self.health_server = HealthServer(port=8000, get_status_callback=self.status)
        self.alert_manager = AlertManager(dedup_window=600)
        self.monitor = SensorMonitor(self.sensor_id, self.queue)

        # State
        self._running = False
        self._capture_thread: threading.Thread | None = None
        self._upload_thread: threading.Thread | None = None
        self._heartbeat_thread: threading.Thread | None = None
        self._self_check_thread: threading.Thread | None = None
        self._start_time: datetime | None = None
        self._stop_lock = threading.Lock()
        self._shutdown_complete = False
        self._fatal_exit_code: int | None = None

        # Stats
        self._frames_captured = 0
        self._frames_parsed = 0
        self._frames_duplicates = 0
        self._last_packet_ts = time.monotonic()
        self._self_check_failures = 0

        # Geo pipeline (optional)
        self.geo_mapper = None
        self._geo_sample_cls = None
        self._last_heatmap_export_ts = 0.0
        self._init_geo_pipeline()
        self._usb_watchdog = None

    def _init_geo_pipeline(self) -> None:
        """Initialize geo-mapping dependencies and sensor position."""
        geo_cfg = getattr(self.config, "geo", None)
        if not geo_cfg or not geo_cfg.enabled:
            return

        if geo_cfg.sensor_x_m is None or geo_cfg.sensor_y_m is None:
            raise ValueError(
                "Geo pipeline enabled but sensor position missing. "
                "Set SENSOR_GEO_X_M and SENSOR_GEO_Y_M."
            )

        try:
            from sensor.geo_mapping import GeoMapper, RSSISample
        except ImportError as e:
            raise RuntimeError(
                "Geo pipeline enabled but geo dependencies are unavailable"
            ) from e

        self.geo_mapper = GeoMapper(environment=geo_cfg.environment)
        self.geo_mapper.register_sensor(
            self.sensor_id,
            x=float(geo_cfg.sensor_x_m),
            y=float(geo_cfg.sensor_y_m),
            z=float(geo_cfg.sensor_z_m),
        )

        if geo_cfg.heatmap_enabled:
            self.geo_mapper.init_heatmap(
                width_m=float(geo_cfg.heatmap_width_m),
                height_m=float(geo_cfg.heatmap_height_m),
                resolution=float(geo_cfg.heatmap_resolution_m),
            )

        self._geo_sample_cls = RSSISample
        logger.info(
            "Geo pipeline enabled for sensor %s at (%.2f, %.2f)",
            self.sensor_id,
            float(geo_cfg.sensor_x_m),
            float(geo_cfg.sensor_y_m),
        )

    def _geo_ingest_sample(self, net_dict: dict[str, Any]) -> None:
        """Feed telemetry into geo-mapping pipeline."""
        if not self.geo_mapper or not self._geo_sample_cls:
            return

        bssid = net_dict.get("bssid")
        rssi = net_dict.get("rssi_dbm")
        if not bssid or rssi is None:
            return

        frequency = net_dict.get("frequency_mhz") or 2412
        try:
            sample = self._geo_sample_cls(
                sensor_id=self.sensor_id,
                bssid=str(bssid),
                rssi_dbm=float(rssi),
                timestamp_utc=str(
                    net_dict.get("timestamp_utc") or datetime.now(UTC).isoformat()
                ),
                frequency_mhz=int(frequency),
            )
            estimate = self.geo_mapper.process_samples([sample])
        except Exception as e:
            logger.debug("Geo sample ingestion failed: %s", e)
            return

        if estimate:
            net_dict["geo_local"] = {
                "method": estimate.method,
                "x_m": round(float(estimate.x), 3),
                "y_m": round(float(estimate.y), 3),
                "confidence": round(float(estimate.confidence), 4),
                "error_radius_m": round(float(estimate.error_radius_m), 3),
            }

        geo_cfg = self.config.geo
        if (
            geo_cfg.heatmap_enabled
            and self.geo_mapper.heatmap
            and geo_cfg.heatmap_export_interval_sec > 0
        ):
            now = time.monotonic()
            if (
                now - self._last_heatmap_export_ts
                >= geo_cfg.heatmap_export_interval_sec
            ):
                try:
                    export_path = geo_cfg.heatmap_export_path
                    export_dir = os.path.dirname(export_path)
                    if export_dir:
                        os.makedirs(export_dir, exist_ok=True)
                    self.geo_mapper.heatmap.export_json(export_path)
                    self._last_heatmap_export_ts = now
                except Exception as e:
                    logger.debug("Heatmap export failed: %s", e)

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
        self._shutdown_complete = False
        self._fatal_exit_code = None
        self._start_time = datetime.now(UTC)
        self._last_packet_ts = time.monotonic()

        # Start channel hopping
        self.hopper.start()

        # Recover stuck inflight items on startup
        self.queue.recover_stuck_inflight()

        # Start capture processing thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="CaptureProcessor"
        )
        self._capture_thread.start()

        # Start upload worker (consumes from queue)
        self.upload_worker.start()

        # Start batch preparation thread (pushes to queue)
        self._upload_thread = threading.Thread(
            target=self._upload_loop, daemon=True, name="BatchPreparer"
        )
        self._upload_thread.start()

        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="Heartbeat"
        )
        self._heartbeat_thread.start()

        # Start lightweight self-check loop for live capture.
        if not self.config.mock_mode and not getattr(
            self.config.capture, "pcap_file", None
        ):
            self._start_usb_watchdog()
            self._self_check_thread = threading.Thread(
                target=self._self_check_loop,
                daemon=True,
                name="SelfCheck",
            )
            self._self_check_thread.start()

        # Start health server
        self.health_server.start()

        # Start observability monitor
        self.monitor.start()

        logger.info("Sensor started successfully")
        return True

    def stop(self) -> None:
        """Stop sensor gracefully"""
        with self._stop_lock:
            if self._shutdown_complete:
                return

            logger.info("Stopping sensor...")
            self._running = False
            current_thread = threading.current_thread()

            # Stop components
            if self._usb_watchdog:
                self._usb_watchdog.stop()
            self.hopper.stop()
            self.health_server.stop()
            self.monitor.stop()
            self.driver.stop_capture()

            # Stop upload worker (graceful - finishes current upload)
            self.upload_worker.stop(timeout=10.0)

            # Wait for threads
            for thread in [
                self._capture_thread,
                self._upload_thread,
                self._heartbeat_thread,
                self._self_check_thread,
            ]:
                if thread and thread.is_alive() and thread is not current_thread:
                    thread.join(timeout=5)

            # Flush remaining buffer to queue
            self.buffer.flush_to_disk()

            # Close queue (persists any remaining data)
            self.queue.close()
            # Close baseline DB connection
            self.baseline.close()

            # Restore interface
            self.driver.disable_monitor_mode()
            self._shutdown_complete = True

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
            "fatal_exit_code": self._fatal_exit_code,
            "last_packet_age_sec": round(time.monotonic() - self._last_packet_ts, 2),
            "frames_captured": self._frames_captured,
            "frames_parsed": self._frames_parsed,
            "buffer": self.buffer.get_stats(),
            "transport": self.transport.get_stats(),
            "queue": self.queue.stats(),
            "upload_worker": self.upload_worker.stats(),
            "threads": {
                "capture": self._capture_thread.is_alive()
                if self._capture_thread
                else False,
                "upload": self._upload_thread.is_alive()
                if self._upload_thread
                else False,
                "worker": self.upload_worker.is_healthy(),
            },
            "baseline": {
                "learning_mode": self.baseline.learning_mode,
            },
            "usb_watchdog": self._get_usb_watchdog_status(),
        }

    def _capture_loop(self) -> None:
        """Process captured frames: Ingestor -> Analyzer -> Exporter"""
        while self._running:
            try:
                # 1. Ingestor
                ingested = self._ingest_frame()
                if not ingested:
                    continue
                parsed, telemetry, net_dict = ingested

                # 2. Analyzer
                self._analyze_threats(net_dict)

                # 3. Exporter
                self._export_telemetry(parsed, telemetry, net_dict)

            except TimeoutError:
                logger.warning("Frame read timeout")
            except Exception as e:
                logger.error(f"Capture loop error: {e}", exc_info=True)
                time.sleep(0.1)  # Backoff to avoid spinning

    def _ingest_frame(self) -> tuple[Any, Any, dict] | None:
        """Read, parse, and normalize frame. (Ingestor)"""
        raw_frame = self.driver.read_frame(timeout_ms=100)
        if raw_frame is None:
            return None

        self._frames_captured += 1
        self._last_packet_ts = time.monotonic()

        parsed = self.parser.parse(raw_frame.data, raw_frame.timestamp)
        if parsed is None or parsed.frame_type == "other":
            return None

        if self.parser.is_duplicate(parsed):
            self._frames_duplicates += 1
            return None

        self._frames_parsed += 1

        telemetry = self.normalizer.normalize(parsed)
        base_dict = telemetry.model_dump(mode="json", exclude_none=True)

        if not self.config.privacy.store_raw_mac:
            for field in ["mac_src", "mac_dst", "bssid"]:
                if field in base_dict:
                    base_dict[field] = anonymize_mac(
                        base_dict[field], self.config.privacy.mode
                    )

        return parsed, telemetry, base_dict

    def _analyze_threats(self, net_dict: dict) -> None:
        """Run all threat detection engines via unified orchestrator. (Analyzer)"""
        alerts = self.detector_orchestrator.process(
            net_dict, context={"sensor_id": self.sensor_id}
        )
        for alert in alerts:
            self._handle_alert(alert)

    def _export_telemetry(self, parsed: Any, telemetry: Any, net_dict: dict) -> None:
        """Route data to buffers, metrics, risk, and geo enrichment. (Exporter)"""
        net_dict.setdefault("security", self._derive_security(parsed, net_dict))
        self._geo_ingest_sample(net_dict)
        self.buffer.append(net_dict)
        self._emit_network(net_dict)

        self.aggregator.record_frame(
            telemetry.frame_type,
            telemetry.frame_subtype,
            net_dict.get("mac_src", telemetry.mac_src),
        )

        self.metrics.record_frame(telemetry.frame_type)

        if self._frames_captured % 10 == 0:
            risk_dict = telemetry.model_dump(mode="json", exclude_none=True)
            analysis_alerts = self.analysis.analyze_telemetry(
                telemetry_dict=risk_dict,
                bssid=telemetry.bssid,
                ssid=telemetry.ssid,
                frame_count=10,  # always a multiple of 10 here
            )
            for alert in analysis_alerts:
                self._handle_alert(alert)

            # Update metrics risk score regardless of alerts.
            if not self.baseline.learning_mode:
                dev = self.baseline.check_deviation(risk_dict)
                dev_score = dev["score"] if dev else 0.0
                rr = self.risk_engine.calculate_risk(
                    risk_dict, deviation_score=dev_score
                )
                self.metrics.set_risk_score(telemetry.bssid, rr.get("risk_score", 0))

        self.hopper.record_activity(parsed.channel, 1)

    def _upload_loop(self) -> None:
        """Prepare batches and push to persistent queue (worker handles upload)"""
        while self._running:
            try:
                time.sleep(self.upload_interval)

                # Get batch from buffer
                batch = self.buffer.get_batch(max_count=self.batch_size)
                if batch is None:
                    continue

                # Add sensor_id to batch
                batch["sensor_id"] = self.sensor_id

                # Generate persistent batch_id
                seq = self.queue.next_seq(self.sensor_id)
                batch_id = f"{self.sensor_id}:{seq}"
                batch["batch_id"] = batch_id

                # Push to persistent queue (worker will handle upload)
                if self.queue.push(batch, batch_id):
                    logger.debug(
                        f"Spooled batch {batch_id}: {len(batch.get('items', []))} items"
                    )
                else:
                    logger.warning("Failed to spool batch (queue full or disk issue)")

            except Exception as e:
                logger.error(f"Batch preparation error: {e}")

    def _on_upload_success(self, batch_id: str, response: dict) -> None:
        """Callback when upload worker succeeds"""
        self.metrics.record_upload(True)
        logger.debug(f"Upload success: {batch_id} -> ack_id={response.get('ack_id')}")

    def _on_upload_failure(self, batch_id: str, error: str) -> None:
        """Callback when upload worker fails"""
        self.metrics.record_upload(False, reason=error)
        logger.warning(f"Upload failed: {batch_id} -> {error}")

    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats"""
        while self._running:
            try:
                time.sleep(60)

                full_status = self.status()
                # Build payload matching HeartbeatRequest schema (extra="forbid")
                heartbeat_payload = {
                    "sensor_id": self.sensor_id,
                    "status": "online" if self._running else "offline",
                    "metrics": {
                        "frames_captured": full_status.get("frames_captured", 0),
                        "frames_parsed": full_status.get("frames_parsed", 0),
                        "uptime_seconds": full_status.get("uptime_seconds", 0),
                    },
                }
                result = self.transport.heartbeat(heartbeat_payload)

                if result.get("success"):
                    # Process commands
                    for cmd in result.get("commands", []):
                        self._handle_command(cmd)

            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")

    def _handle_alert(self, alert_dict: dict[str, Any]) -> None:
        """Process an alert, check for chains, and upload"""

        # 1. Deduplication / Triage
        if not self.alert_manager.process(alert_dict):
            return

        self._emit_alert(alert_dict)
        logger.warning(
            f"Detection: [{alert_dict.get('severity')}] {alert_dict.get('title')}"
        )

        # Add sensor info
        alert_dict["sensor_id"] = self.sensor_id

        # Upload individual alert
        self.transport.upload_alert(alert_dict)

        # Check for exploit chains via analysis orchestrator
        chain_alert = self.analysis.correlate_alert(alert_dict)
        if chain_alert:
            self.transport.upload_alert(chain_alert)

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

    def force_channel_hop(self) -> bool:
        """Advance to the next configured channel immediately."""
        channels = self.hopper.channels
        if not channels:
            return False

        next_idx = (self.hopper._current_idx + 1) % len(channels)
        channel = channels[next_idx]
        if self.driver.set_channel(channel):
            self.hopper._current_idx = next_idx
            logger.info("Forced channel hop to %s", channel)
            return True
        return False

    def request_fail_fast(self, reason: str, exit_code: int = 2) -> None:
        """Stop the controller and signal the wrapper to exit non-zero."""
        if self._fatal_exit_code is not None:
            return

        self._fatal_exit_code = exit_code
        logger.error("Fail-fast triggered: %s", reason)
        self._emit_alert(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "severity": "High",
                "title": "Sensor Fail-Fast",
                "description": reason,
                "sensor_id": self.sensor_id,
                "alert_type": "sensor_health",
            }
        )
        self.stop()

    def _self_check_loop(self) -> None:
        """Verify live capture integrity and request restart on persistent failure."""
        while self._running:
            time.sleep(5)
            if not self._running:
                break

            try:
                self._run_live_self_check()
            except Exception as e:
                logger.debug("Self-check error: %s", e)

    def _run_live_self_check(self) -> None:
        """Check monitor mode and packet freshness for live capture."""
        uptime_seconds = 0.0
        if self._start_time:
            uptime_seconds = (datetime.now(UTC) - self._start_time).total_seconds()

        monitor_ok = self.driver.is_monitor_mode
        if self._usb_watchdog:
            usb_status = self._usb_watchdog.get_status()
            monitor_ok = usb_status.get("connected", monitor_ok) and usb_status.get(
                "in_monitor_mode", monitor_ok
            )

        if not monitor_ok:
            self._self_check_failures += 1
            logger.warning("Self-check: interface left monitor mode")
            if self._self_check_failures == 1:
                success, error = self.driver.enable_monitor_mode()
                if success:
                    logger.info("Self-check recovered monitor mode")
                    self._self_check_failures = 0
                    return
                logger.warning("Monitor mode recovery failed: %s", error)
            if self._self_check_failures >= 2:
                self.request_fail_fast("Interface left monitor mode repeatedly")
            return

        last_packet_age = time.monotonic() - self._last_packet_ts
        if uptime_seconds > 60 and last_packet_age > 30:
            self._self_check_failures += 1
            logger.warning(
                "Self-check: no packets seen for %.1fs on %s",
                last_packet_age,
                self.iface,
            )
            if self._self_check_failures >= 2:
                self.request_fail_fast(
                    f"No packets captured for {int(last_packet_age)}s on {self.iface}"
                )
            return

        self._self_check_failures = 0

    def _start_usb_watchdog(self) -> None:
        """Attach USB adapter monitoring for live captures."""
        if self._usb_watchdog is not None:
            return

        try:
            from sensor.usb_watchdog import USBWatchdog

            self._usb_watchdog = USBWatchdog(
                interface=self.iface,
                on_disconnect=lambda: logger.warning(
                    "USB watchdog: adapter disconnected"
                ),
                on_reconnect=lambda: logger.info("USB watchdog: adapter reconnected"),
            )
            self._usb_watchdog.start()
        except Exception as e:
            logger.warning("USB watchdog unavailable: %s", e)
            self._usb_watchdog = None

    def _get_usb_watchdog_status(self) -> dict[str, Any]:
        if not self._usb_watchdog:
            return {}

        try:
            return self._usb_watchdog.get_status()
        except Exception as e:
            logger.debug("USB watchdog status failed: %s", e)
            return {}

    def _emit_network(self, net_dict: dict[str, Any]) -> None:
        if self.on_network is None:
            return

        try:
            self.on_network(dict(net_dict))
        except Exception as e:
            logger.debug("Network callback failed: %s", e)

    def _emit_alert(self, alert_dict: dict[str, Any]) -> None:
        if self.on_alert is None:
            return

        try:
            self.on_alert(dict(alert_dict))
        except Exception as e:
            logger.debug("Alert callback failed: %s", e)

    @staticmethod
    def _derive_security(parsed: Any, net_dict: dict[str, Any]) -> str:
        security = str(net_dict.get("security") or "").upper()
        if security:
            return security
        if getattr(parsed, "rsn_info", None):
            return "WPA3" if getattr(parsed, "pmf_required", False) else "WPA2"
        if getattr(parsed, "wpa_info", None):
            return "WPA"
        if getattr(parsed, "privacy", False):
            return "WEP"
        return "OPEN"


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
    parser.add_argument("--pcap", help="Replay PCAP file instead of live capture")
    parser.add_argument(
        "--enable-ml", action="store_true", help="Enable ML Risk Scoring Boost"
    )
    parser.add_argument(
        "--enable-geo", action="store_true", help="Enable Geo-Location triangulation"
    )
    parser.add_argument(
        "--learning-mode", action="store_true", help="Enable Baseline Learning Mode"
    )
    parser.add_argument(
        "--detector-profile",
        help="Detector profile (lite_realtime, full_wids, audit_offline)",
    )

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
    if args.pcap:
        config.capture.pcap_file = args.pcap
    if args.enable_ml:
        config.ml.enabled = True
    if args.enable_geo:
        config.geo.enabled = True
    if args.detector_profile:
        config.detectors.default_profile = args.detector_profile

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Create controller
    controller = SensorController(config=config)

    if args.learning_mode:
        controller.baseline.set_learning_mode(True)

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
        if controller._fatal_exit_code is not None:
            sys.exit(controller._fatal_exit_code)
    else:
        print("Failed to start sensor")
        sys.exit(1)


if __name__ == "__main__":
    main()
