import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from shutil import copyfile
from typing import cast
from unittest.mock import MagicMock, patch

import pytest

from sensor.capture_driver import PcapCaptureDriver
from sensor.config import init_config

# Import modules to test
from sensor.sensor_controller import SensorController

GOLDEN_PCAPS = {
    "evil_twin": Path("data/pcap_annotated/sample_evil_twin.pcap"),
    "normal": Path("data/pcap_annotated/sample_benign.pcap"),
    "deauth": Path("data/pcap_annotated/sample_deauth.pcap"),
}


class TestScenarioReplay:
    """
    Integration tests replaying PCAP files through the Sensor Controller.
    Verifies detection logic (Evil Twin, etc.) triggers alerts.
    """

    @pytest.fixture
    def setup_pcap(self, tmp_path: Path) -> Callable[[str], str]:
        """Copy committed golden PCAPs into the per-test tmp directory."""

        def _generate(scenario: str) -> str:
            source = GOLDEN_PCAPS[scenario]
            if not source.exists():
                pytest.skip(f"Golden PCAP not found: {source}")
            path = tmp_path / f"{scenario}.pcap"
            copyfile(source, path)
            return str(path)

        return _generate

    def _wait_for_replay_completion(
        self, controller: SensorController, timeout_sec: float = 10.0
    ) -> None:
        start_wait = time.time()
        while time.time() - start_wait < timeout_sec:
            driver = controller.driver
            if isinstance(driver, PcapCaptureDriver) and driver._packets:
                if driver._current_idx >= len(driver._packets):
                    return
            time.sleep(0.1)

    @pytest.fixture
    def mock_transport(self) -> Iterator[MagicMock]:
        with patch("sensor.sensor_controller.TransportClient") as mock_transport_cls:
            client_instance = cast(MagicMock, mock_transport_cls.return_value)
            client_instance.upload.return_value = {"success": True, "ack_id": "123"}
            client_instance.upload_alert.return_value = {
                "success": True,
                "alert_id": "alert_123",
            }
            yield client_instance

    @pytest.fixture
    def test_env(self, tmp_path: Path) -> Iterator[Path]:
        """Setup test environment with config overrides"""
        env = {
            "SENSOR_ID": "test-sensor-01",
            "SENSOR_HMAC_SECRET": "test_secret_long_enough_12345678",
            "CONTROLLER_URL": "http://localhost:5000/api/v1/telemetry",
            "SENSOR_AUTH_TOKEN": "test_token_long_enough_1234",
            "SENSOR_PRIVACY_STORE_RAW_MAC": "true",
            "BUFFER_STORAGE_PATH": str(tmp_path / "journal"),
            "STORAGE_PATH": str(tmp_path / "journal"),
            "ENVIRONMENT": "development",  # Use dev mode to avoid strict checks
        }
        with patch.dict(os.environ, env):
            yield tmp_path

    def test_replay_evil_twin_detection(
        self,
        setup_pcap: Callable[[str], str],
        mock_transport: MagicMock,
        test_env: Path,
    ) -> None:
        """
        Scenario: Replay PCAP containing Evil Twin attack.
        Expected: Sensor detects Evil Twin and calls upload_alert.
        """
        pcap_path = setup_pcap("evil_twin")

        config = init_config()
        config.capture.interface = "test_mon"
        config.capture.pcap_file = pcap_path
        config.storage.pcap_dir = str(test_env / "pcaps")
        config.storage.db_path = str(test_env / "test.db")
        config.buffer.storage_path = str(test_env / "journal")
        config.privacy.mode = "normal"
        config.privacy.store_raw_mac = True
        config.capture.enable_channel_hop = False  # Disable hopper for PCAP replay
        config.detectors.enabled = ["evil_twin"]
        config.detectors.thresholds = {
            "evil_twin": {"confirmation_window_seconds": 0, "threshold_medium": 10}
        }

        controller = SensorController(config=config)

        try:
            controller.start()
            self._wait_for_replay_completion(controller)
        finally:
            controller.stop()

        assert mock_transport.upload_alert.called, (
            "upload_alert should be called for Evil Twin"
        )
        calls = mock_transport.upload_alert.call_args_list
        assert any("Evil Twin" in str(c) for c in calls)

    def test_replay_normal_traffic_no_alerts(
        self,
        setup_pcap: Callable[[str], str],
        mock_transport: MagicMock,
        test_env: Path,
    ) -> None:
        """
        Scenario: Replay PCAP containing only Normal traffic.
        Expected: No alerts generated.
        """
        pcap_path = setup_pcap("normal")

        config = init_config()
        config.capture.interface = "test_mon"
        config.capture.pcap_file = pcap_path
        config.storage.pcap_dir = str(test_env / "pcaps_normal")
        config.storage.db_path = str(test_env / "test_normal.db")
        config.buffer.storage_path = str(test_env / "journal")
        config.privacy.mode = "normal"
        config.privacy.store_raw_mac = True
        config.capture.enable_channel_hop = False  # Disable hopper for PCAP replay

        controller = SensorController(config=config)

        try:
            controller.start()
            self._wait_for_replay_completion(controller)
        finally:
            controller.stop()

        # EXPECTATION: No alerts
        assert not mock_transport.upload_alert.called, (
            "No alerts should be triggered for normal traffic"
        )

        # Also check frames parsed
        assert controller._frames_parsed > 0
        print("Scenario passed: Normal traffic processed without false positives.")

    def test_replay_deauth_flood_detection(
        self,
        setup_pcap: Callable[[str], str],
        mock_transport: MagicMock,
        test_env: Path,
    ) -> None:
        """
        Scenario: Replay PCAP containing a Deauth flood attack.
        Expected: Sensor detects Deauth Flood and calls upload_alert.
        """
        pcap_path = setup_pcap("deauth")

        config = init_config()
        config.capture.interface = "test_mon"
        config.capture.pcap_file = pcap_path
        config.storage.pcap_dir = str(test_env / "pcaps_deauth")
        config.storage.db_path = str(test_env / "test_deauth.db")
        config.buffer.storage_path = str(test_env / "journal")
        config.privacy.mode = "normal"
        config.privacy.store_raw_mac = True
        config.capture.enable_channel_hop = False
        config.detectors.enabled = ["deauth_flood"]
        config.detectors.thresholds = {
            "deauth_flood": {
                "threshold_per_sec": 2.0,
                "window_seconds": 1.0,
                "cooldown_seconds": 0.0,
                "state_file": str(test_env / "dos_state.json"),
            }
        }

        controller = SensorController(config=config)

        try:
            controller.start()
            self._wait_for_replay_completion(controller)
        finally:
            controller.stop()

        # Verify that Deauth flood was detected
        assert mock_transport.upload_alert.called, (
            "upload_alert should be called for Deauth Flood"
        )

        calls = mock_transport.upload_alert.call_args_list
        assert any(
            "Deauth Flood" in str(c) or "deauth" in str(c).lower() for c in calls
        )
        print("Scenario passed: Deauth flood correctly triggered an alert.")
