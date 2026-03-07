import argparse
import unittest
from unittest.mock import MagicMock, patch

from sensor.cli import load_config, main


class TestCLI(unittest.TestCase):

    @patch("sensor.cli.Path.exists", return_value=True)
    @patch("builtins.open", unittest.mock.mock_open(read_data="sensor_id: test-id"))
    def test_load_config(self, mock_exists):
        config = load_config("fake.yaml")
        self.assertEqual(config.get("sensor_id"), "test-id")

    @patch("sensor.sensor_controller.SensorController")
    @patch("sensor.cli.argparse.ArgumentParser.parse_args")
    def test_main_startup(self, mock_parse_args, mock_controller):
        # Test normal startup flow
        mock_args = argparse.Namespace(
            iface="wlan0",
            interface="wlan0",
            engine="tshark",
            channels="1,6,11",
            config_file=None,
            log_level="INFO",
            api_url="http://test",
            offline=False,
            wardrive=False,
            audit=False,
            mock_mode=True,
            verify_ssl=False,
            buffer_size=1000,
            upload_url=None,
            dwell_ms=200,
            buffered_storage=False,
            storage_path="/tmp",
            watchdog=False,
            auth_token=None,
            batch_size=50,
            upload_interval=1,
            anonymize_ssid=False,
            anonymize_mac=False,
            mac_salt="test",
            store_raw_mac=False,
            store_raw_ssid=False,
            privacy_mode="disabled",
            sensor_id="test-sensor",
            skip_health_check=True,
            health_check_retries=1,
            health_check_interval=1,
            upload=False,
            gps=None,
            out="wardrive.json",
            profile="home",
        )
        mock_parse_args.return_value = mock_args

        mock_instance = MagicMock()
        # Mocking the _running property
        mock_instance._running = True
        mock_controller.return_value = mock_instance

        # Prevent actual infinite loop if any, or run components
        # We need to mock sys.exit if needed, or allow it to return
        def side_effect(*args, **kwargs):
            mock_instance._running = False

        with patch("sys.exit"):
            with patch("time.sleep", side_effect=side_effect):
                main()

        # Check controller started
        mock_controller.assert_called_once()
        mock_instance.start.assert_called_once()
