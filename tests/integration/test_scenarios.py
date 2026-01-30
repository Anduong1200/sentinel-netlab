
import os
import time
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
import shutil

import logging

# Import modules to test
from sensor.sensor_controller import SensorController
from sensor.capture_driver import PcapCaptureDriver
from tests.data.generate_pcap import main as generate_pcap_main, OUTPUT_FILE as PCAP_FILE

class TestScenarioReplay:
    """
    Integration tests replaying PCAP files through the Sensor Controller.
    Verifies detection logic (Evil Twin, etc.) triggers alerts.
    """

    @pytest.fixture
    def setup_pcap(self):
        """Generate golden pcap if missing"""
        # Always regenerate to be safe/fresh
        generate_pcap_main()
        yield PCAP_FILE
        # Cleanup? Keep for inspection if failed?
        # os.remove(PCAP_FILE)

    @pytest.fixture
    def mock_transport(self):
        with patch("sensor.sensor_controller.TransportClient") as mock:
            client_instance = mock.return_value
            client_instance.upload.return_value = {"success": True, "ack_id": "123"}
            client_instance.upload_alert.return_value = {"success": True, "alert_id": "alert_123"}
            yield client_instance

    @pytest.fixture
    def test_env(self, tmp_path):
        """Setup test environment with config overrides"""
        env = {
            "SENSOR_ID": "test-sensor-01",
            "SENSOR_HMAC_SECRET": "test-secret",
            "CONTROLLER_URL": "http://localhost:5000/api/v1/telemetry",
            "SENSOR_AUTH_TOKEN": "test-token",
            "SENSOR_PRIVACY_STORE_RAW_MAC": "true"
        }
        with patch.dict(os.environ, env):
            yield tmp_path

    def test_replay_evil_twin_detection(self, setup_pcap, mock_transport, test_env):
        """
        Scenario: Replay Golden PCAP containing Evil Twin attack.
        Expected: Sensor detects Evil Twin and calls upload_alert.
        """
        # Patch init_config to avoid loading real config files or failing mandatory envs if missing
        # We rely on os.environ patch above for minimal config.
        # But SensorController loads config via get_config().
        
        # Instantiate Controller
        # We can pass a mock config or let it load from env
        controller = SensorController()
        
        # Override Driver with PcapCaptureDriver
        controller.driver = PcapCaptureDriver(
            iface="test_mon",
            pcap_path=setup_pcap,
            realtime=False # Fast replay
        )
        
        # Override Transport (already mocked by decorator/fixture?)
        # Since SensorController instantiates TransportClient inside __init__, 
        # the 'mock_transport' fixture which patches the CLASS needs to be active BEFORE init.
        # It is active because it's passed as arg (pytest executes fixture setup first).
        
        # We also need to make sure buffer uses tmp_path to avoids polluting /var/lib
        controller.buffer.storage_path = Path(test_env) / "journal"
        controller.buffer.storage_path.mkdir(parents=True)

        print(f"Starting replay of {setup_pcap}...")
        
        # Run Capture Loop manually or verify thread?
        # Threaded is harder to sync.
        # We can call _capture_loop logic directly or start() and wait.
        # Since PcapDriver finishes, we need _capture_loop to be robust to 'None' or handle stop.
        # Pcap driver returns None when done (if loop=False).
        # SensorController._capture_loop continues on None?
        # Line 356: if raw_frame is None: continue.
        # It loops forever.
        # We should modify driver to signal stop, or run _capture_loop in a thread and stop controller after X seconds.
        
        # Approach: Run in thread, wait for driver to exhaust (or timeout), then stop.
        # Disable confirmation window for immediate alert
        from algos.evil_twin import EvilTwinConfig
        new_conf = EvilTwinConfig()
        new_conf.confirmation_window_seconds = 0
        new_conf.threshold_medium = 10
        
        # Override config
        controller.et_detector.config = new_conf
        
        controller.start()
        
        # Wait for pcap processing
        # 130 frames, fast replay. Should be instant.
        # But _capture_loop sleeps 0.1s on error or empty?
        # Driver returns None, loop continues.
        # We need to know when pcap is done.
        
        # Hack: Poll controller._frames_captured until it matches pcap length (~130)
        max_wait = 5 # seconds
        start_wait = time.time()
        while controller._frames_captured < 130 and time.time() - start_wait < max_wait:
            time.sleep(0.1)
            
        print(f"Captured {controller._frames_captured} frames.")
        
        controller.stop()
        
        # Verify Alerts
        # Evil Twin logic runs in _capture_loop.
        # Check mock_transport.upload_alert call args.
        
        assert mock_transport.upload_alert.called, "upload_alert should be called for Evil Twin"
        
        # Verify content
        calls = mock_transport.upload_alert.call_args_list
        evil_twin_calls = [c for c in calls if "Evil Twin" in str(c)]
        
        assert len(evil_twin_calls) > 0, "Should have specific Evil Twin alerts"
        
        args, _ = evil_twin_calls[0]
        alert_data = args[0]
        assert alert_data["alert_type"] == "evil_twin"
        assert alert_data["risk_score"] >= 40 
        
        print("Scenario passed: Evil Twin detected and uploaded.")
