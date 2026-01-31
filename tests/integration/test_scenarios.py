import os
import time
from unittest.mock import patch

import pytest

from sensor.capture_driver import PcapCaptureDriver

# Import modules to test
from sensor.sensor_controller import SensorController
from tests.data.generate_pcap import (
    main as generate_pcap_main,
)


class TestScenarioReplay:
    """
    Integration tests replaying PCAP files through the Sensor Controller.
    Verifies detection logic (Evil Twin, etc.) triggers alerts.
    """

    @pytest.fixture
    def setup_pcap(self, tmp_path):
        """Helper to generate specific pcaps"""
        def _generate(scenario):
            path = tmp_path / f"{scenario}.pcap"
            with patch("sys.argv", ["generate_pcap.py", "--scenario", scenario, "--output", str(path)]):
                generate_pcap_main()
            return str(path)
        return _generate

    @pytest.fixture
    def mock_transport(self):
        with patch("sensor.sensor_controller.TransportClient") as mock:
            client_instance = mock.return_value
            client_instance.upload.return_value = {"success": True, "ack_id": "123"}
            client_instance.upload_alert.return_value = {
                "success": True,
                "alert_id": "alert_123",
            }
            yield client_instance

    @pytest.fixture
    def test_env(self, tmp_path):
        """Setup test environment with config overrides"""
        env = {
            "SENSOR_ID": "test-sensor-01",
            "SENSOR_HMAC_SECRET": "test-secret",
            "CONTROLLER_URL": "http://localhost:5000/api/v1/telemetry",
            "SENSOR_AUTH_TOKEN": "test-token",
            "SENSOR_PRIVACY_STORE_RAW_MAC": "true",
            "STORAGE_PATH": str(tmp_path / "journal"),
        }
        with patch.dict(os.environ, env):
            yield tmp_path


    def test_replay_evil_twin_detection(self, setup_pcap, mock_transport, test_env):
        """
        Scenario: Replay PCAP containing Evil Twin attack.
        Expected: Sensor detects Evil Twin and calls upload_alert.
        """
        pcap_path = setup_pcap("evil_twin")
        from sensor.config import get_config

        config = get_config()
        config.storage.pcap_dir = str(test_env / "pcaps")
        config.storage.db_path = str(test_env / "test.db")
        config.privacy.mode = "normal"
        config.privacy.store_raw_mac = True
        config.capture.enable_channel_hop = False  # Disable hopper for PCAP replay

        controller = SensorController(config=config)
        controller.driver = PcapCaptureDriver(
            iface="test_mon", pcap_path=pcap_path, realtime=False
        )

        from algos.evil_twin import EvilTwinConfig
        new_conf = EvilTwinConfig()
        new_conf.confirmation_window_seconds = 0
        new_conf.threshold_medium = 10
        controller.et_detector.config = new_conf

        controller.start()

        # Wait for pcap (25 frames: 5 legit + 20 evil)
        max_wait = 10
        start_wait = time.time()
        while controller._frames_parsed < 25 and time.time() - start_wait < max_wait:
            time.sleep(0.1)

        controller.stop()

        assert mock_transport.upload_alert.called, "upload_alert should be called for Evil Twin"
        calls = mock_transport.upload_alert.call_args_list
        assert any("Evil Twin" in str(c) for c in calls)

    def test_replay_normal_traffic_no_alerts(self, setup_pcap, mock_transport, test_env):
        """
        Scenario: Replay PCAP containing only Normal traffic.
        Expected: No alerts generated.
        """
        pcap_path = setup_pcap("normal")
        from sensor.config import get_config

        config = get_config()
        config.storage.pcap_dir = str(test_env / "pcaps_normal")
        config.storage.db_path = str(test_env / "test_normal.db")
        config.privacy.mode = "normal"
        config.privacy.store_raw_mac = True
        config.capture.enable_channel_hop = False  # Disable hopper for PCAP replay

        controller = SensorController(config=config)
        controller.driver = PcapCaptureDriver(
            iface="test_mon", pcap_path=pcap_path, realtime=False
        )

        controller.start()

        # Wait for pcap (11 frames: 10 beacons + 1 probe)
        max_wait = 10
        start_wait = time.time()
        while controller._frames_parsed < 11 and time.time() - start_wait < max_wait:
            time.sleep(0.1)

        controller.stop()

        # EXPECTATION: No alerts
        assert not mock_transport.upload_alert.called, "No alerts should be triggered for normal traffic"

        # Also check frames parsed
        assert controller._frames_parsed >= 10
        print("Scenario passed: Normal traffic processed without false positives.")

