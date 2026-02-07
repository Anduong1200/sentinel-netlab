
import gzip
import hashlib
import hmac
import json
import logging
import os
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch, MagicMock

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Mock environment variables BEFORE any imports
os.environ["SENTINEL_ENV"] = "test"
os.environ["CONTROLLER_SECRET_KEY"] = "test-secret-key-32-chars-minimum-length"
os.environ["CONTROLLER_HMAC_SECRET"] = "test-hmac-secret"
os.environ["DATABASE_URL"] = "sqlite:///:memory:" 
os.environ["REDIS_URL"] = "redis://mock"
os.environ["REQUIRE_HMAC"] = "true"

# We must import deps first to mock before they are used
with patch("controller.api.deps.db.create_all"), \
     patch("controller.api.deps.db.init_app"), \
     patch("controller.api.deps.limiter.init_app"):
     
    # Import app factory
    from controller.api_server import app, create_app
    from controller.api.deps import db
    from controller.api.models import Token 
    from controller.api.auth import Role

class TestIngestGzip(unittest.TestCase):
    def setUp(self):
        # Use the app instance from api_server which has blueprints registered
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()

        # Mock DB session for token verification
        self.mock_db_session = MagicMock()
        
        # We need to make sure db.session points to our mock
        # But db is a global SQLAlchemy object.
        # We can patch db.session using unittest.mock.patch.object
        # OR just assign it if scoped_session allows (it's tricky with Flask-SQLAlchemy)
        
        # Better: Patch Token.query again, which we already do in the test method.
        # But api/auth.py uses db.session.commit/rollback.
        # We should mock db.session in the auth module or deps module.
        
        self.db_patcher = patch("controller.api.auth.db.session", self.mock_db_session)
        self.db_patcher.start()
        
    def tearDown(self):
        self.db_patcher.stop()
        self.ctx.pop()

    @patch("controller.api.auth.Token.query")
    @patch("controller.api.telemetry.IngestQueue.enqueue")
    def test_gzip_hmac_ingest(self, mock_enqueue, mock_token_query):
        """Test that GZIP + HMAC ingestion works end-to-end through the API decorators"""
        # specialized setup for this test
        token_hash = hashlib.sha256("test-token".encode()).hexdigest()
        
        mock_token = MagicMock(spec=Token)
        mock_token.token_hash = token_hash
        mock_token.name = "Test Sensor"
        mock_token.role = Role.SENSOR
        mock_token.sensor_id = "sensor-01"
        mock_token.is_active = True
        mock_token.expires_at = datetime.now(UTC) + timedelta(hours=1)
        mock_token.last_sequence = 0
        
        mock_token_query.filter_by.return_value.first.return_value = mock_token
        
        mock_enqueue.return_value = "ack-123"

        # Telemetry Batch
        batch = {
            "sensor_id": "sensor-01",
            "batch_id": "batch-123",
            "items": [
                {
                    "sensor_id": "sensor-01",
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                    "sequence_id": 1,
                    "frame_type": "beacon",
                    "bssid": "00:11:22:33:44:55",
                    "ssid": "Test",
                    "rssi_dbm": -50,
                    "channel": 6
                }
            ]
        }
        
        payload_str = json.dumps(batch)
        payload_bytes = gzip.compress(payload_str.encode()) # COMPRESSED
        
        # Headers
        timestamp = datetime.now(UTC).isoformat()
        path = "/api/v1/telemetry"
        method = "POST"
        content_encoding = "gzip"
        
        # Build Canonical String for HMAC
        # Method\nPath\nTimestamp\nSensorID\nEncoding
        parts = [
            method,
            path,
            timestamp,
            "sensor-01", # sensor_id
            content_encoding
        ]
        canonical_meta = "\n".join(parts) + "\n"
        
        h = hmac.new(
            os.environ["CONTROLLER_HMAC_SECRET"].encode(), 
            digestmod=hashlib.sha256
        )
        h.update(canonical_meta.encode())
        h.update(payload_bytes)
        signature = h.hexdigest()
        
        headers = {
            "Authorization": "Bearer test-token",
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
            "X-Timestamp": timestamp,
            "X-Signature": signature,
            "X-Sensor-ID": "sensor-01",
            "X-Forwarded-Proto": "https" 
        }
        
        # Send Request
        response = self.client.post(
            path,
            data=payload_bytes,
            headers=headers
        )
        
        print(f"Response: {response.status_code} {response.data.decode()}")
        
        # We expect 202 usage
        self.assertEqual(response.status_code, 202)
        mock_enqueue.assert_called_once()

if __name__ == "__main__":
    unittest.main()
