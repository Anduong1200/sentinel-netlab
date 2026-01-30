#!/usr/bin/env python3
"""
Sentinel NetLab - Centralized Test Fixtures
All shared fixtures for unit and integration tests.

Usage:
    # pytest automatically discovers conftest.py
    def test_example(mock_networks, mock_controller_client):
        ...
"""

import hashlib
import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

# Set Default Test Environment Variables BEFORE any imports that might use config
os.environ["CONTROLLER_SECRET_KEY"] = "test-secret-key-for-integration"
os.environ["CONTROLLER_HMAC_SECRET"] = "test-hmac-secret-for-integration"
# os.environ["CONTROLLER_DATABASE_URL"] = "sqlite:///:memory:"
# Use file based DB for persistence across contexts in tests
os.environ["CONTROLLER_DATABASE_URL"] = (
    f"sqlite:///{os.path.abspath('test_sentinel.db')}"
)
os.environ["FLASK_ENV"] = "testing"
os.environ["REQUIRE_HMAC"] = "false"
os.environ["REQUIRE_TLS"] = "false"

# =============================================================================
# NETWORK DATA FIXTURES
# =============================================================================


@pytest.fixture
def mock_networks():
    """Sample network data for testing"""
    return [
        {
            "bssid": "AA:BB:CC:11:22:33",
            "ssid": "CorpNet",
            "channel": 6,
            "rssi_dbm": -55,
            "security": "WPA2",
            "capabilities": {"privacy": True, "pmf": True, "wps": False},
        },
        {
            "bssid": "AA:BB:CC:44:55:66",
            "ssid": "GuestWiFi",
            "channel": 1,
            "rssi_dbm": -65,
            "security": "Open",
            "capabilities": {"privacy": False},
        },
        {
            "bssid": "DE:AD:BE:EF:00:01",
            "ssid": "CorpNet",  # Evil twin!
            "channel": 6,
            "rssi_dbm": -30,
            "security": "WPA2",
            "capabilities": {"privacy": True},
        },
    ]


@pytest.fixture
def mock_benign_network():
    """Single benign network"""
    return {
        "bssid": "AA:BB:CC:11:22:33",
        "ssid": "SafeNetwork",
        "channel": 11,
        "rssi_dbm": -50,
        "security": "WPA3",
        "capabilities": {"privacy": True, "pmf": True},
    }


@pytest.fixture
def mock_wep_network():
    """Insecure WEP network"""
    return {
        "bssid": "AA:BB:CC:77:88:99",
        "ssid": "OldRouter",
        "channel": 6,
        "rssi_dbm": -70,
        "security": "WEP",
        "capabilities": {"privacy": True},
    }


# =============================================================================
# TELEMETRY FIXTURES
# =============================================================================


@pytest.fixture
def mock_telemetry_batch():
    """Sample telemetry batch"""
    return {
        "sensor_id": "test-sensor-01",
        "batch_id": f"batch-{secrets.token_hex(4)}",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "sequence_number": 1,
        "items": [
            {
                "bssid": "AA:BB:CC:11:22:33",
                "ssid": "TestNet",
                "rssi_dbm": -55,
                "channel": 6,
            },
            {
                "bssid": "AA:BB:CC:44:55:66",
                "ssid": "SecondNet",
                "rssi_dbm": -65,
                "channel": 1,
            },
        ],
    }


@pytest.fixture
def mock_deauth_events():
    """Sample deauth events for flood detection"""
    base_time = time.time()
    return [
        {
            "timestamp": base_time + (i * 0.02),
            "bssid": "AA:BB:CC:11:22:33",
            "client_mac": "FF:FF:FF:FF:FF:FF",
            "reason_code": 3,
        }
        for i in range(50)
    ]


# =============================================================================
# ALERT FIXTURES
# =============================================================================


@pytest.fixture
def mock_alert():
    """Sample alert"""
    return {
        "alert_type": "evil_twin",
        "severity": "High",
        "title": "Evil Twin Detected",
        "description": "Same SSID with different BSSID detected",
        "bssid": "DE:AD:BE:EF:00:01",
        "evidence": {"frame_count": 10},
    }


# =============================================================================
# CONTROLLER API FIXTURES
# =============================================================================


@pytest.fixture
def app_client():
    """Flask test client for Controller API"""
    try:
        from controller.api.deps import config, db
        from controller.api.models import Role, Token
        from controller.api_server import app

        # Force strict security OFF for tests
        config.security.require_tls = False
        config.security.require_hmac = False

        app.config["TESTING"] = True

        with app.app_context():
            # Ensure fresh DB
            db.drop_all()
            db.create_all()

            # Create Admin Token
            admin_token = Token(
                token_id="admin-test",
                token_hash=hashlib.sha256(b"admin-token-dev").hexdigest(),
                name="Admin Test",
                role=Role.ADMIN,
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=365),
                is_active=True,
            )
            db.session.add(admin_token)

            # Create Sensor Token
            sensor_token = Token(
                token_id="sensor-test",
                token_hash=hashlib.sha256(b"sensor-01-token").hexdigest(),
                name="Sensor Test",
                role=Role.SENSOR,
                sensor_id="sensor-01",
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=365),
                is_active=True,
            )
            db.session.add(sensor_token)
            db.session.commit()

            # Debug DB content
            # print(f"DEBUG: Fixture DB Tokens: {[t.token_hash for t in Token.query.all()]}")

            db.session.add(sensor_token)
            db.session.commit()

            # Debug DB content
            # print(f"DEBUG: Fixture DB Tokens: {[t.token_hash for t in Token.query.all()]}")

        with app.test_client() as client:
            yield client

        # Cleanup
        with app.app_context():
            db.session.remove()
            db.drop_all()
        if os.path.exists("test_sentinel.db"):
            os.remove("test_sentinel.db")

    except ImportError:
        pytest.skip("Controller not available")


@pytest.fixture
def auth_headers():
    """Authorization headers for API tests"""
    return {
        "Authorization": "Bearer admin-token-dev",
        "X-Timestamp": datetime.now(UTC).isoformat(),
    }


@pytest.fixture
def sensor_auth_headers():
    """Sensor authorization headers"""
    return {
        "Authorization": "Bearer sensor-01-token",
        "X-Timestamp": datetime.now(UTC).isoformat(),
    }


# =============================================================================
# MOCK SERVICES
# =============================================================================


@pytest.fixture
def mock_controller_url():
    """Mock controller URL"""
    return "http://localhost:5000"


@pytest.fixture
def mock_transport():
    """Mock secure transport client"""
    transport = MagicMock()
    transport.send_telemetry.return_value = {"success": True, "ack_id": "test-ack"}
    transport.send_alert.return_value = {"success": True, "alert_id": "alert-001"}
    transport.heartbeat.return_value = {"success": True}
    return transport


# =============================================================================
# DETECTOR FIXTURES
# =============================================================================


@pytest.fixture
def risk_scorer():
    """RiskScorer instance"""
    try:
        from algos.risk import RiskScorer

        return RiskScorer()
    except ImportError:
        pytest.skip("RiskScorer not available")


@pytest.fixture
def evil_twin_detector():
    """EvilTwinDetector instance"""
    try:
        from algos.evil_twin import AdvancedEvilTwinDetector as EvilTwinDetector

        # Use simpler config for tests if needed, or default
        return EvilTwinDetector()
    except ImportError:
        pytest.skip("EvilTwinDetector not available")


@pytest.fixture
def deauth_detector():
    """DeauthFloodDetector instance"""
    try:
        from algos.dos import DeauthFloodDetector

        return DeauthFloodDetector(threshold_per_sec=10, window_seconds=5)
    except ImportError:
        pytest.skip("DeauthFloodDetector not available")


# =============================================================================
# ENVIRONMENT FIXTURES
# =============================================================================


@pytest.fixture
def env_vars(monkeypatch):
    """Set common environment variables for tests"""
    monkeypatch.setenv("CONTROLLER_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("CONTROLLER_HMAC_SECRET", "test-hmac-secret")
    monkeypatch.setenv("REQUIRE_HMAC", "false")
    monkeypatch.setenv("REQUIRE_TLS", "false")
    monkeypatch.setenv("FLASK_ENV", "testing")


@pytest.fixture
def temp_data_dir(tmp_path):
    """Temporary data directory"""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir


# =============================================================================
# UTILITY FIXTURES
# =============================================================================


@pytest.fixture
def freeze_time():
    """Fixture to freeze time for deterministic tests"""
    fixed_time = datetime(2026, 1, 28, 12, 0, 0, tzinfo=UTC)

    with patch("datetime.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_time
        mock_dt.fromisoformat = datetime.fromisoformat
        yield fixed_time


@pytest.fixture(scope="session")
def sample_pcap_path():
    """Path to sample PCAP for testing"""
    pcap_path = "data/pcap_annotated/sample_benign.pcap"
    if os.path.exists(pcap_path):
        return pcap_path
    return None
