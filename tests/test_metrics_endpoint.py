
# Add path to import modules
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sensor.sensor_cli import SensorCLI


class TestMetricsEndpoint(unittest.TestCase):
    def setUp(self):
        # Mock args
        self.args = MagicMock()
        self.args.api = True
        self.args.host = "127.0.0.1"
        self.args.port = 5050
        self.args.interface = "wlan0"
        self.args.engine = "scapy"
        self.args.buffered_storage = False
        self.args.watchdog = False

        # Instantiate CLI
        self.cli = SensorCLI(self.args)

        # Mock dependencies to prevent actual startup
        self.cli.capture_engine = MagicMock()
        self.cli.parser = MagicMock()
        self.cli.parser.security_events = []
        self.cli.parser.networks = {}

    def test_metrics_endpoint(self):
        """Test that /metrics endpoint returns 200 and prometheus content"""
        # We need to extract the app from start_api.
        # Since start_api creates the app internally and runs it, we might need to patch Flask.
        # Alternatively, we can refactor start_api to return the app, but let's try patching first
        # to avoid changing production code structure if not needed.

        with patch('flask.Flask') as mock_flask:
             # create a real Flask app for testing routes
            real_app = Flask(__name__)
            mock_flask.return_value = real_app

            # Prevent app.run from blocking
            with patch.object(real_app, 'run', return_value=None):
                self.cli.start_api()

            # Now we can test the client
            client = real_app.test_client()
            response = client.get('/metrics')

            self.assertEqual(response.status_code, 200)
            # ContentType might vary based on prometheus client version but should be text/plain
            self.assertIn('text/plain', response.content_type)

            # Check for content (even if empty, it should be bytes)
            self.assertIsInstance(response.data, bytes)
            print("Successfully hit /metrics endpoint")

if __name__ == "__main__":
    unittest.main()
