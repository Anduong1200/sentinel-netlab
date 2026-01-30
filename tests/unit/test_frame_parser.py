"""
Sentinel NetLab - Unit Tests for Frame Parser
Tests frame_parser.py with sample pcap data.
"""


import pytest

# Import will work when tests run from sensor directory
try:
    from sensor.frame_parser import FrameParser, ParsedFrame
except ImportError:
    import os
    import sys

    # Add root to path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    from sensor.frame_parser import FrameParser, ParsedFrame


class TestFrameParser:
    """Unit tests for FrameParser"""

    @pytest.fixture
    def parser(self):
        return FrameParser()

    def test_parse_beacon_extracts_ssid_bssid_rssi_channel(self, parser):
        """Given beacon sample, fields match expected"""
        # Mock beacon frame (simplified for testing)
        # Real tests would use actual pcap samples
        mock_beacon = self._create_mock_beacon(
            bssid=b"\xaa\xbb\xcc\xdd\xee\xff", ssid=b"TestNetwork"
        )

        result = parser.parse(mock_beacon, timestamp=1000.0)

        assert result is not None
        assert result.frame_type == "beacon"
        assert result.bssid == "AA:BB:CC:DD:EE:FF"
        assert result.ssid == "TestNetwork"

    def test_parse_probe_req_handles_hidden_ssid(self, parser):
        """SSID null and proper flag set for hidden networks"""
        mock_probe = self._create_mock_probe_req(ssid=b"")

        result = parser.parse(mock_probe, timestamp=1000.0)

        assert result is not None
        # Empty SSID should be handled
        assert result.ssid is None or result.ssid == ""

    def test_parse_vendor_ie_detection(self, parser):
        """Detect WPS/RSN/Vendor IEs correctly"""
        # This would use real pcap with vendor IEs
        # Placeholder for now
        pass

    def test_parse_corrupt_frame_returns_parse_error(self, parser):
        """Parser returns parse_error flag not exception"""
        corrupt_frame = b"\x00\x01\x02"  # Too short to be valid

        result = parser.parse(corrupt_frame, timestamp=1000.0)

        # Should return result with error, not raise exception
        assert result is not None
        assert result.parse_error is not None

    def test_parse_empty_frame_returns_none(self, parser):
        """Empty frame returns error object"""
        result = parser.parse(b"", timestamp=1000.0)
        assert result is not None
        assert result.parse_error is not None

    def test_is_duplicate_within_window(self, parser):
        """Duplicate detection within time window"""
        frame1 = ParsedFrame(
            timestamp=1000.0,
            bssid="AA:BB:CC:DD:EE:FF",
            seq_num=100,
            frame_type="beacon",
            ssid="Test",
        )
        frame2 = ParsedFrame(
            timestamp=1001.0,
            bssid="AA:BB:CC:DD:EE:FF",
            seq_num=100,
            frame_type="beacon",
            ssid="Test",
        )

        # First frame should not be duplicate
        assert not parser.is_duplicate(frame1)

        # Second frame (same key) should be duplicate
        assert parser.is_duplicate(frame2)

    def test_is_duplicate_after_window_expires(self, parser):
        """Duplicate cache expires after window"""
        frame1 = ParsedFrame(
            timestamp=1000.0,
            bssid="AA:BB:CC:DD:EE:FF",
            seq_num=100,
            frame_type="beacon",
            ssid="Test",
        )
        frame2 = ParsedFrame(
            timestamp=1010.0,
            bssid="AA:BB:CC:DD:EE:FF",
            seq_num=100,
            frame_type="beacon",
            ssid="Test",
        )

        parser.is_duplicate(frame1)

        # After 10 seconds (> 5s default window), should not be duplicate
        assert not parser.is_duplicate(frame2, window_sec=5.0)

    def _create_mock_beacon(self, bssid: bytes, ssid: bytes) -> bytes:
        """Create simplified mock beacon frame"""
        import struct

        # Radiotap header (simplified - 8 bytes)
        radiotap = struct.pack("<BBHI", 0, 0, 8, 0)

        # 802.11 header
        frame_control = 0x0080  # Beacon
        duration = 0
        da = b"\xff" * 6  # Broadcast
        sa = bssid
        bssid_field = bssid
        seq_ctrl = 0

        dot11_header = struct.pack("<HH", frame_control, duration)
        dot11_header += da + sa + bssid_field
        dot11_header += struct.pack("<H", seq_ctrl)

        # Fixed fields
        timestamp = b"\x00" * 8
        beacon_interval = struct.pack("<H", 100)
        capabilities = struct.pack("<H", 0x0411)

        # SSID IE
        ssid_ie = b"\x00" + bytes([len(ssid)]) + ssid

        return (
            radiotap
            + dot11_header
            + timestamp
            + beacon_interval
            + capabilities
            + ssid_ie
        )

    def _create_mock_probe_req(self, ssid: bytes) -> bytes:
        """Create simplified mock probe request"""
        import struct

        radiotap = struct.pack("<BBHI", 0, 0, 8, 0)

        frame_control = 0x0040  # Probe Request
        duration = 0
        da = b"\xff" * 6
        sa = b"\x11\x22\x33\x44\x55\x66"
        bssid = b"\xff" * 6
        seq_ctrl = 0

        dot11_header = struct.pack("<HH", frame_control, duration)
        dot11_header += da + sa + bssid
        dot11_header += struct.pack("<H", seq_ctrl)

        ssid_ie = b"\x00" + bytes([len(ssid)]) + ssid

        return radiotap + dot11_header + ssid_ie


class TestParserEdgeCases:
    """Edge case tests for parser"""

    @pytest.fixture
    def parser(self):
        return FrameParser()

    def test_very_long_ssid(self, parser):
        """Handle maximum length SSID (32 bytes)"""
        pass  # Placeholder

    def test_unicode_ssid(self, parser):
        """Handle UTF-8 encoded SSID"""
        pass  # Placeholder

    def test_malformed_ie_length(self, parser):
        """Handle IE with invalid length field"""
        pass  # Placeholder
