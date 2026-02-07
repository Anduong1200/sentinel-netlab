import hashlib
import os
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

# Mock Env
os.environ["SENTINEL_ENV"] = "test"
os.environ["CONTROLLER_SECRET_KEY"] = "test-secret-key-32-chars-minimum"
os.environ["CONTROLLER_HMAC_SECRET"] = "test-hmac"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from controller.api.auth import Role
from controller.api.models import Token
from controller.api_server import app


class TestDeduplication(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()

        # Mock DB
        self.mock_db_session = MagicMock()
        self.db_patcher = patch("controller.api.deps.db.session", self.mock_db_session)
        self.db_patcher.start()

        # Mock Token Query
        self.token_patcher = patch("controller.api.auth.Token.query")
        self.mock_token_query = self.token_patcher.start()

        # Setup Valid Token
        token_hash = hashlib.sha256(b"test-token").hexdigest()
        mock_token = MagicMock(spec=Token)
        mock_token.token_hash = token_hash
        mock_token.role = Role.SENSOR
        mock_token.sensor_id = "sensor-01"
        mock_token.is_active = True
        mock_token.expires_at = datetime.now(UTC) + timedelta(hours=1)
        self.mock_token_query.filter_by.return_value.first.return_value = mock_token

    def tearDown(self):
        self.db_patcher.stop()
        self.token_patcher.stop()
        self.ctx.pop()

    @patch("controller.api.auth.verify_hmac")
    @patch("controller.api.auth.verify_timestamp")
    @patch("controller.api.telemetry.IngestQueue.enqueue")
    def test_deduplication_batch_id(
        self, mock_enqueue, mock_verify_ts, mock_verify_hmac
    ):
        """Test that submitting the same batch_id twice returns 200 (idempotent) but doesn't process"""

        # Bypass Auth Checks
        mock_verify_ts.return_value = True
        mock_verify_hmac.return_value = True

        batch_id = "uniq-batch-001"
        sensor_id = "sensor-01"

        # Scenario 1: New Batch
        mock_enqueue.return_value = (batch_id, False)  # (ack_id, is_duplicate=False)

        # Payload
        # Payload
        items = [
            {
                "sensor_id": sensor_id,
                "timestamp_utc": datetime.now(UTC).isoformat(),
                "sequence_id": 1,
                "frame_type": "beacon",
                "frame_subtype": None,
                "mac_src": "00:11:22:33:44:55",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "ssid": "TestSSID",
                "rssi_dbm": -50,
                "channel": 6,
                "frequency_mhz": 2412,
                "security": "wpa2",
            }
        ]

        payload = {"sensor_id": sensor_id, "batch_id": batch_id, "items": items}

        headers = {
            "Authorization": "Bearer test-token",
            "Content-Encoding": "identity",
            "X-Timestamp": datetime.now(UTC).isoformat(),
            "X-Signature": "dummy",
            "X-Sensor-ID": sensor_id,
        }

        # Send 1
        resp1 = self.client.post("/api/v1/telemetry", json=payload, headers=headers)
        self.assertEqual(resp1.status_code, 202)
        mock_enqueue.assert_called_once()

        # Scenario 2: Duplicate Batch
        mock_enqueue.return_value = ("ack-old-123", True)  # (ack_id, is_duplicate=True)

        # Send 2
        resp2 = self.client.post("/api/v1/telemetry", json=payload, headers=headers)

        # Should be 200 OK (Idempotent success)
        self.assertEqual(resp2.status_code, 200)
        data = resp2.json
        self.assertEqual(data["ack_id"], batch_id)
        self.assertEqual(data["status"], "duplicate")

        # Should call enqueue again?
        # Telemetry.py calls enqueue every time.
        # IngestQueue.enqueue handles the check.
        # So yes, it should be called again.
        self.assertEqual(mock_enqueue.call_count, 2)


if __name__ == "__main__":
    unittest.main()
