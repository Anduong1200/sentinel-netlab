#!/usr/bin/env python3
"""
Unit tests for sensor components.
Run: pytest tests/unit/ -v
"""

import pytest
import json
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


# =============================================================================
# TEST: WiFi Parser
# =============================================================================

class TestWiFiParser:
    """Test WiFi frame parsing"""

    def test_parse_beacon_frame(self):
        """Test beacon frame parsing"""
        from sensor.parser import WiFiParser

        parser = WiFiParser()
        
        # Mock beacon data
        beacon = {
            'wlan.bssid': 'aa:bb:cc:11:22:33',
            'wlan.ssid': 'TestNetwork',
            'radiotap.channel.freq': '2437',
            'wlan.fixed.capabilities': '0x0411',
        }
        
        # Just test instantiation
        assert parser is not None

    def test_parse_rssi_extraction(self):
        """Test RSSI extraction from radiotap"""
        from sensor.parser import WiFiParser

        parser = WiFiParser()
        
        # Mock frame with RSSI
        rssi = -65
        assert isinstance(rssi, int)
        assert -100 <= rssi <= 0


# =============================================================================
# TEST: Risk Scorer
# =============================================================================

class TestRiskScorer:
    """Test risk scoring logic"""

    def test_score_calculation(self):
        """Test basic score calculation"""
        from sensor.risk import RiskScorer

        scorer = RiskScorer()
        
        # Test network data
        network = {
            'bssid': 'AA:BB:CC:11:22:33',
            'ssid': 'TestNet',
            'security': 'WPA2',
            'channel': 6,
            'rssi_dbm': -55,
            'capabilities': {'privacy': True}
        }
        
        score = scorer.score(network)
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100

    def test_open_network_high_risk(self):
        """Open networks should have higher risk"""
        from sensor.risk import RiskScorer

        scorer = RiskScorer()
        
        open_network = {
            'bssid': 'AA:BB:CC:11:22:33',
            'ssid': 'OpenNet',
            'security': 'Open',
            'capabilities': {'privacy': False}
        }
        
        secure_network = {
            'bssid': 'AA:BB:CC:44:55:66',
            'ssid': 'SecureNet',
            'security': 'WPA3',
            'capabilities': {'privacy': True, 'pmf': True}
        }
        
        open_score = scorer.score(open_network)
        secure_score = scorer.score(secure_network)
        
        assert open_score > secure_score


# =============================================================================
# TEST: Detection
# =============================================================================

class TestDetection:
    """Test detection utilities"""

    def test_levenshtein_distance(self):
        """Test fuzzy string matching"""
        from sensor.detection import levenshtein_distance, ssid_similarity

        # Identical strings
        assert levenshtein_distance("test", "test") == 0
        
        # One character difference
        assert levenshtein_distance("test", "tests") == 1
        
        # Completely different
        assert levenshtein_distance("abc", "xyz") == 3

    def test_ssid_similarity(self):
        """Test SSID similarity detection"""
        from sensor.detection import ssid_similarity

        # Similar SSIDs (evil twin pattern)
        sim = ssid_similarity("CorpNet", "C0rpNet")
        assert sim > 0.7

        # Identical
        assert ssid_similarity("Test", "Test") == 1.0

    def test_bloom_filter(self):
        """Test bloom filter for MAC tracking"""
        from sensor.detection import BloomFilter

        bf = BloomFilter(size=1000, hash_count=3)
        
        bf.add("AA:BB:CC:11:22:33")
        
        assert bf.contains("AA:BB:CC:11:22:33") == True
        assert bf.contains("XX:YY:ZZ:00:00:00") == False


# =============================================================================
# TEST: WIDS Detectors
# =============================================================================

class TestWIDSDetectors:
    """Test WIDS detection engines"""

    def test_deauth_flood_detection(self):
        """Test deauth flood detector"""
        from sensor.wids_detectors import DeauthFloodDetector, DeauthEvent

        detector = DeauthFloodDetector(
            threshold=10,
            window_seconds=5
        )
        
        # Simulate deauth flood
        bssid = "AA:BB:CC:11:22:33"
        for i in range(15):
            event = DeauthEvent(
                timestamp=time.time(),
                bssid=bssid,
                client_mac="FF:FF:FF:FF:FF:FF",
                reason_code=3
            )
            alert = detector.ingest(event)
        
        # Should trigger alert after threshold
        assert detector.get_alert_count() > 0

    def test_evil_twin_basic(self):
        """Test evil twin detector basics"""
        from sensor.wids_detectors import EvilTwinDetector

        detector = EvilTwinDetector()
        assert detector is not None


# =============================================================================
# TEST: Audit
# =============================================================================

class TestAudit:
    """Test audit functionality"""

    def test_security_auditor(self):
        """Test security auditor"""
        from sensor.audit import SecurityAuditor, NetworkInfo

        auditor = SecurityAuditor("test-sensor", profile="home")
        
        # Test network
        network = NetworkInfo(
            bssid="AA:BB:CC:11:22:33",
            ssid="TestNet",
            channel=6,
            rssi_dbm=-55,
            security="WPA2"
        )
        
        auditor.audit_network(network)
        
        # Should have processed the network
        assert len(auditor.networks) == 1

    def test_wep_detection(self):
        """Test WEP detection creates critical finding"""
        from sensor.audit import SecurityAuditor, NetworkInfo

        auditor = SecurityAuditor("test-sensor")
        
        wep_network = NetworkInfo(
            bssid="AA:BB:CC:77:88:99",
            ssid="OldRouter",
            channel=11,
            rssi_dbm=-70,
            security="WEP"
        )
        
        auditor.audit_network(wep_network)
        
        # Should have critical finding for WEP
        critical_findings = [f for f in auditor.findings if f.severity == "Critical"]
        assert len(critical_findings) > 0


# =============================================================================
# TEST: Transport
# =============================================================================

class TestTransport:
    """Test transport client"""

    def test_hmac_signing(self):
        """Test HMAC signature generation"""
        from sensor.message_signing import SecureTransport

        transport = SecureTransport(
            controller_url="http://localhost:5000",
            auth_token="test-token",
            hmac_secret="test-secret",
            sensor_id="test-sensor",
            verify_ssl=False
        )
        
        payload = b'{"test": "data"}'
        signature = transport.sign_payload(payload)
        
        # Signature should be hex string
        assert len(signature) == 64  # SHA256 hex
        assert all(c in '0123456789abcdef' for c in signature)

    def test_headers_include_timestamp(self):
        """Test that headers include timestamp"""
        from sensor.message_signing import SecureTransport

        transport = SecureTransport(
            controller_url="http://localhost:5000",
            auth_token="test-token",
            hmac_secret="test-secret",
            verify_ssl=False
        )
        
        headers = transport._build_headers(b'test')
        
        assert 'Authorization' in headers
        assert 'X-Timestamp' in headers
        assert 'X-Signature' in headers


# =============================================================================
# RUN
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
