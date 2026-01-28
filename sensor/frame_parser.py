"""
Sentinel NetLab - Frame Parser
Parses raw 802.11 management frames and extracts fields.
"""

import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ParsedFrame:
    """Parsed 802.11 management frame"""
    # Radio metadata
    timestamp: float
    rssi_dbm: int = -100
    channel: int = 0
    frequency_mhz: int = 0

    # Frame header
    frame_type: str = "other"
    frame_subtype: int = 0

    # Addresses
    bssid: str = ""
    src_addr: str = ""
    dst_addr: str = ""

    # Management frame fields
    ssid: Optional[str] = None
    ssid_raw: Optional[bytes] = None
    ssid_decoding_error: bool = False

    # Beacon/Probe specific
    beacon_interval: int = 0
    capability_flags: int = 0
    seq_num: int = 0

    # Capability booleans
    privacy: bool = False
    ess: bool = True
    ibss: bool = False

    # Information Elements
    ies: dict[str, Any] = field(default_factory=dict)
    ies_present: list[str] = field(default_factory=list)

    # HT/VHT/HE
    ht_capable: bool = False
    vht_capable: bool = False
    he_capable: bool = False

    # Security
    wps_enabled: bool = False
    pmf_required: bool = False
    pmf_capable: bool = False
    rsn_info: dict[str, Any] = field(default_factory=dict)
    wpa_info: dict[str, Any] = field(default_factory=dict)

    # Raw data
    raw_radiotap: Optional[bytes] = None

    # Parse status
    parse_error: Optional[str] = None


class FrameParser:
    """
    Parses raw 802.11 frames from radiotap format.
    Extracts management frame fields, IEs, and security info.
    """

    # Frame type/subtype constants
    TYPE_MGMT = 0
    SUBTYPE_ASSOC_REQ = 0
    SUBTYPE_ASSOC_RESP = 1
    SUBTYPE_REASSOC_REQ = 2
    SUBTYPE_REASSOC_RESP = 3
    SUBTYPE_PROBE_REQ = 4
    SUBTYPE_PROBE_RESP = 5
    SUBTYPE_BEACON = 8
    SUBTYPE_DISASSOC = 10
    SUBTYPE_AUTH = 11
    SUBTYPE_DEAUTH = 12
    SUBTYPE_ACTION = 13

    # IE element IDs
    IE_SSID = 0
    IE_SUPPORTED_RATES = 1
    IE_DS_PARAM = 3
    IE_TIM = 5
    IE_RSN = 48
    IE_HT_CAPABILITIES = 45
    IE_HT_OPERATION = 61
    IE_VHT_CAPABILITIES = 191
    IE_VHT_OPERATION = 192
    IE_VENDOR = 221
    IE_EXT = 255

    # Vendor OUIs
    OUI_WPA = b'\x00\x50\xf2\x01'
    OUI_WPS = b'\x00\x50\xf2\x04'
    OUI_MICROSOFT = b'\x00\x50\xf2'

    FRAME_TYPE_MAP = {
        (0, 0): "assoc_req",
        (0, 1): "assoc_resp",
        (0, 2): "reassoc_req",
        (0, 3): "reassoc_resp",
        (0, 4): "probe_req",
        (0, 5): "probe_resp",
        (0, 8): "beacon",
        (0, 10): "disassoc",
        (0, 11): "auth",
        (0, 12): "deauth",
        (0, 13): "action",
    }

    def __init__(self, oui_db: Optional[dict[str, str]] = None):
        """
        Initialize parser.

        Args:
            oui_db: Optional OUI database for vendor lookup
        """
        self.oui_db = oui_db or {}
        self._dedup_cache: dict[str, float] = {}
        self._dedup_window = 5.0  # seconds

    def parse(
            self,
            raw_frame: bytes,
            timestamp: float = 0.0) -> Optional[ParsedFrame]:
        """
        Parse raw radiotap + 802.11 frame.

        Args:
            raw_frame: Raw bytes including radiotap header
            timestamp: Capture timestamp

        Returns:
            ParsedFrame object or None on error
        """
        result = ParsedFrame(timestamp=timestamp)

        if len(raw_frame) < 8:
            result.parse_error = "Frame too short (< 8 bytes)"
            return result

        try:
            # Parse radiotap header
            radiotap_len = self._parse_radiotap(raw_frame, result)
            if radiotap_len < 0:
                result.parse_error = "Invalid radiotap header"
                return result

            # Store raw radiotap for optional use
            result.raw_radiotap = raw_frame[:radiotap_len]

            # Parse 802.11 header
            dot11_start = radiotap_len
            if len(raw_frame) < dot11_start + 24:
                result.parse_error = "Frame too short for 802.11 header"
                return result

            frame_control = struct.unpack(
                '<H', raw_frame[dot11_start:dot11_start + 2])[0]
            frame_type = (frame_control >> 2) & 0x03
            frame_subtype = (frame_control >> 4) & 0x0f

            result.frame_subtype = frame_subtype
            result.frame_type = self.FRAME_TYPE_MAP.get(
                (frame_type, frame_subtype), "other"
            )

            # Only parse management frames
            if frame_type != self.TYPE_MGMT:
                result.frame_type = "other"
                return result

            # Extract addresses
            result.dst_addr = self._format_mac(
                raw_frame[dot11_start + 4:dot11_start + 10])
            result.src_addr = self._format_mac(
                raw_frame[dot11_start + 10:dot11_start + 16])
            result.bssid = self._format_mac(
                raw_frame[dot11_start + 16:dot11_start + 22])

            # Sequence number
            seq_ctrl = struct.unpack(
                '<H', raw_frame[dot11_start + 22:dot11_start + 24])[0]
            result.seq_num = seq_ctrl >> 4

            # Parse management frame body based on subtype
            body_start = dot11_start + 24

            if frame_subtype in [self.SUBTYPE_BEACON, self.SUBTYPE_PROBE_RESP]:
                self._parse_beacon_probe_resp(raw_frame, body_start, result)
            elif frame_subtype == self.SUBTYPE_PROBE_REQ:
                self._parse_probe_req(raw_frame, body_start, result)
            elif frame_subtype in [self.SUBTYPE_DEAUTH, self.SUBTYPE_DISASSOC]:
                self._parse_deauth_disassoc(raw_frame, body_start, result)
            elif frame_subtype == self.SUBTYPE_AUTH:
                self._parse_auth(raw_frame, body_start, result)

            return result

        except Exception as e:
            logger.error(f"Parse error: {e}")
            result.parse_error = str(e)
            return result

    def _parse_radiotap(self, data: bytes, result: ParsedFrame) -> int:
        """Parse radiotap header and extract RSSI/channel"""
        if len(data) < 8:
            return -1

        # Radiotap header
        version, pad, length = struct.unpack('<BBH', data[:4])
        if version != 0:
            return -1

        if len(data) < length:
            return -1

        # Parse present flags and extract common fields
        present = struct.unpack('<I', data[4:8])[0]

        # Simplified extraction - real implementation would
        # parse all present fields according to bitmap
        # For now, try to find RSSI in common locations

        try:
            # Try to extract antenna signal (common radiotap field)
            if present & 0x20:  # DBM_ANTSIGNAL
                # Find the field (simplified)
                if len(data) > 14:
                    # Common location for RSSI
                    rssi_byte = data[14] if data[14] < 128 else data[14] - 256
                    result.rssi_dbm = rssi_byte
        except Exception:
            pass

        return length

    def _parse_beacon_probe_resp(
            self,
            data: bytes,
            start: int,
            result: ParsedFrame) -> None:
        """Parse beacon or probe response fixed fields and IEs"""
        if len(data) < start + 12:
            return

        # Fixed fields: timestamp (8) + beacon interval (2) + capabilities (2)
        result.beacon_interval = struct.unpack(
            '<H', data[start + 8:start + 10])[0]
        result.capability_flags = struct.unpack(
            '<H', data[start + 10:start + 12])[0]

        # Parse capability flags
        result.ess = bool(result.capability_flags & 0x0001)
        result.ibss = bool(result.capability_flags & 0x0002)
        result.privacy = bool(result.capability_flags & 0x0010)

        # Parse IEs
        self._parse_ies(data, start + 12, result)

    def _parse_probe_req(
            self,
            data: bytes,
            start: int,
            result: ParsedFrame) -> None:
        """Parse probe request IEs"""
        self._parse_ies(data, start, result)

    def _parse_deauth_disassoc(
            self,
            data: bytes,
            start: int,
            result: ParsedFrame) -> None:
        """Parse deauth/disassoc reason code"""
        if len(data) >= start + 2:
            reason = struct.unpack('<H', data[start:start + 2])[0]
            result.ies['reason_code'] = reason

    def _parse_auth(
            self,
            data: bytes,
            start: int,
            result: ParsedFrame) -> None:
        """Parse authentication frame"""
        if len(data) >= start + 6:
            algo = struct.unpack('<H', data[start:start + 2])[0]
            seq = struct.unpack('<H', data[start + 2:start + 4])[0]
            status = struct.unpack('<H', data[start + 4:start + 6])[0]
            result.ies['auth_algo'] = algo
            result.ies['auth_seq'] = seq
            result.ies['auth_status'] = status

    def _parse_ies(self, data: bytes, start: int, result: ParsedFrame) -> None:
        """Parse Information Elements"""
        offset = start

        while offset + 2 <= len(data):
            ie_id = data[offset]
            ie_len = data[offset + 1]

            if offset + 2 + ie_len > len(data):
                break

            ie_data = data[offset + 2:offset + 2 + ie_len]

            if ie_id == self.IE_SSID:
                result.ies_present.append("SSID")
                try:
                    result.ssid = ie_data.decode('utf-8')
                    result.ssid_raw = ie_data
                except UnicodeDecodeError:
                    result.ssid = ie_data.decode('latin-1', errors='replace')
                    result.ssid_decoding_error = True
                    result.ssid_raw = ie_data

            elif ie_id == self.IE_DS_PARAM:
                result.ies_present.append("DS")
                if ie_len >= 1:
                    result.channel = ie_data[0]

            elif ie_id == self.IE_RSN:
                result.ies_present.append("RSN")
                self._parse_rsn_ie(ie_data, result)

            elif ie_id == self.IE_HT_CAPABILITIES:
                result.ies_present.append("HT")
                result.ht_capable = True

            elif ie_id == self.IE_VHT_CAPABILITIES:
                result.ies_present.append("VHT")
                result.vht_capable = True

            elif ie_id == self.IE_VENDOR:
                self._parse_vendor_ie(ie_data, result)

            offset += 2 + ie_len

    def _parse_rsn_ie(self, data: bytes, result: ParsedFrame) -> None:
        """Parse RSN (WPA2/WPA3) IE"""
        if len(data) < 8:
            return

        try:
            version = struct.unpack('<H', data[0:2])[0]
            group_cipher = data[2:6]

            # Parse pairwise ciphers
            pairwise_count = struct.unpack('<H', data[6:8])[0]
            offset = 8
            pairwise_ciphers = []
            for _ in range(pairwise_count):
                if offset + 4 <= len(data):
                    pairwise_ciphers.append(data[offset:offset + 4].hex())
                    offset += 4

            # Parse AKM suites
            if offset + 2 <= len(data):
                akm_count = struct.unpack('<H', data[offset:offset + 2])[0]
                offset += 2
                akm_suites = []
                for _ in range(akm_count):
                    if offset + 4 <= len(data):
                        akm_suites.append(data[offset:offset + 4].hex())
                        offset += 4

            # RSN capabilities
            if offset + 2 <= len(data):
                rsn_caps = struct.unpack('<H', data[offset:offset + 2])[0]
                result.pmf_capable = bool(rsn_caps & 0x80)
                result.pmf_required = bool(rsn_caps & 0x40)

            result.rsn_info = {
                'version': version,
                'group_cipher': group_cipher.hex(),
                'pairwise_ciphers': pairwise_ciphers
            }
        except Exception:
            pass

    def _parse_vendor_ie(self, data: bytes, result: ParsedFrame) -> None:
        """Parse vendor-specific IE"""
        if len(data) < 4:
            return

        data[:3]
        data[3] if len(data) > 3 else 0

        # WPA IE (Microsoft OUI + type 1)
        if data[:4] == self.OUI_WPA:
            result.ies_present.append("WPA")
            result.wpa_info['present'] = True

        # WPS IE (Microsoft OUI + type 4)
        elif data[:4] == self.OUI_WPS:
            result.ies_present.append("WPS")
            result.wps_enabled = True

    def _format_mac(self, mac_bytes: bytes) -> str:
        """Format MAC address as string"""
        return ':'.join(f'{b:02X}' for b in mac_bytes)

    def is_duplicate(
            self,
            frame: ParsedFrame,
            window_sec: float = 5.0) -> bool:
        """Check if frame is duplicate within time window"""
        key = f"{frame.bssid}_{frame.seq_num}_{frame.frame_type}_{frame.ssid}"
        now = frame.timestamp

        if key in self._dedup_cache:
            if now - self._dedup_cache[key] < window_sec:
                return True

        # Clean old entries
        self._dedup_cache = {
            k: v for k, v in self._dedup_cache.items()
            if now - v < window_sec
        }

        self._dedup_cache[key] = now
        return False
