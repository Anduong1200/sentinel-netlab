#!/usr/bin/env python3
"""
Sentinel NetLab - Centralized Test Fixtures
All shared fixtures for unit and integration tests.

Usage:
    # pytest automatically discovers conftest.py
    def test_example(mock_networks, mock_controller_client):
        ...
"""

import os
import json
import time
import pytest
import secrets
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


# =============================================================================
# NETWORK DATA FIXTURES
# =============================================================================

@pytest.fixture
def mock_networks():
    """Sample network data for testing"""
    return [
        {
            'bssid': 'AA:BB:CC:11:22:33',
            'ssid': 'CorpNet',
            'channel': 6,
            'rssi_dbm': -55,
            'security': 'WPA2',
            'capabilities': {'privacy': True, 'pmf': True, 'wps': False}
        },
        {
            'bssid': 'AA:BB:CC:44:55:66',
            'ssid': 'GuestWiFi',
            'channel': 1,
            'rssi_dbm': -65,
            'security': 'Open',
            'capabilities': {'privacy': False}
        },
        {
            'bssid': 'DE:AD:BE:EF:00:01',
            'ssid': 'CorpNet',  # Evil twin!
            'channel': 6,
            'rssi_dbm': -30,
            'security': 'WPA2',
            'capabilities': {'privacy': True}
        }
    ]


@pytest.fixture
def mock_benign_network():
    """Single benign network"""
    return {
        'bssid': 'AA:BB:CC:11:22:33',
        'ssid': 'SafeNetwork',
        'channel': 11,
        'rssi_dbm': -50,
        'security': 'WPA3',
        'capabilities': {'privacy': True, 'pmf': True}
    }


@pytest.fixture
def mock_wep_network():
    """Insecure WEP network"""
    return {
        'bssid': 'AA:BB:CC:77:88:99',
        'ssid': 'OldRouter',
        'channel': 6,
        'rssi_dbm': -70,
        'security': 'WEP',
        'capabilities': {'privacy': True}
    }


# =============================================================================
# TELEMETRY FIXTURES
# =============================================================================

@pytest.fixture
def mock_telemetry_batch():
    """Sample telemetry batch"""
    return {
        'sensor_id': 'test-sensor-01',
        'batch_id': f'batch-{secrets.token_hex(4)}',
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'sequence_number': 1,
        'items': [
            {
                'bssid': 'AA:BB:CC:11:22:33',
                'ssid': 'TestNet',
                'rssi_dbm': -55,
                'channel': 6
            },
            {
                'bssid': 'AA:BB:CC:44:55:66',
                'ssid': 'SecondNet',
                'rssi_dbm': -65,
                'channel': 1
            }
        ]
    }


@pytest.fixture
def mock_deauth_events():
    """Sample deauth events for flood detection"""
    base_time = time.time()
    return [
        {
            'timestamp': base_time + (i * 0.02),
            'bssid': 'AA:BB:CC:11:22:33',
            'client_mac': 'FF:FF:FF:FF:FF:FF',
            'reason_code': 3
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
        'alert_type': 'evil_twin',
        'severity': 'High',
        'title': 'Evil Twin Detected',
        'description': 'Same SSID with different BSSID detected',
        'bssid': 'DE:AD:BE:EF:00:01',
        'evidence': {'frame_count': 10}
    }


# =============================================================================
# CONTROLLER API FIXTURES
# =============================================================================

@pytest.fixture
def app_client():
    """Flask test client for Controller API"""
    try:
        from controller.api_server import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    except ImportError:
        pytest.skip("Controller not available")


@pytest.fixture
def auth_headers():
    """Authorization headers for API tests"""
    return {
        'Authorization': 'Bearer admin-token-dev',
        'X-Timestamp': datetime.now(timezone.utc).isoformat(),
    }


@pytest.fixture
def sensor_auth_headers():
    """Sensor authorization headers"""
    return {
        'Authorization': 'Bearer sensor-01-token',
        'X-Timestamp': datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# MOCK SERVICES
# =============================================================================

@pytest.fixture
def mock_controller_url():
    """Mock controller URL"""
    return 'http://localhost:5000'


@pytest.fixture
def mock_transport():
    """Mock secure transport client"""
    transport = MagicMock()
    transport.send_telemetry.return_value = {'success': True, 'ack_id': 'test-ack'}
    transport.send_alert.return_value = {'success': True, 'alert_id': 'alert-001'}
    transport.heartbeat.return_value = {'success': True}
    return transport


# =============================================================================
# DETECTOR FIXTURES
# =============================================================================

@pytest.fixture
def risk_scorer():
    """RiskScorer instance"""
    try:
        from sensor.risk import RiskScorer
        return RiskScorer()
    except ImportError:
        pytest.skip("RiskScorer not available")


@pytest.fixture
def evil_twin_detector():
    """EvilTwinDetector instance"""
    try:
        from sensor.wids_detectors import EvilTwinDetector
        return EvilTwinDetector(ssid_similarity_threshold=0.8)
    except ImportError:
        pytest.skip("EvilTwinDetector not available")


@pytest.fixture
def deauth_detector():
    """DeauthFloodDetector instance"""
    try:
        from sensor.wids_detectors import DeauthFloodDetector
        return DeauthFloodDetector(threshold=10, window_seconds=5)
    except ImportError:
        pytest.skip("DeauthFloodDetector not available")


# =============================================================================
# ENVIRONMENT FIXTURES
# =============================================================================

@pytest.fixture
def env_vars(monkeypatch):
    """Set common environment variables for tests"""
    monkeypatch.setenv('CONTROLLER_SECRET_KEY', 'test-secret-key')
    monkeypatch.setenv('CONTROLLER_HMAC_SECRET', 'test-hmac-secret')
    monkeypatch.setenv('REQUIRE_HMAC', 'false')
    monkeypatch.setenv('REQUIRE_TLS', 'false')
    monkeypatch.setenv('FLASK_ENV', 'testing')


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
    fixed_time = datetime(2026, 1, 28, 12, 0, 0, tzinfo=timezone.utc)
    
    with patch('datetime.datetime') as mock_dt:
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
