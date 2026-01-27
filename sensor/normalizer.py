"""
Sentinel NetLab - Telemetry Normalizer
Converts parsed frames to canonical telemetry format.
"""

import logging
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from .schema import TelemetryFrame, Capabilities

logger = logging.getLogger(__name__)


class TelemetryNormalizer:
    """
    Normalizes parsed 802.11 frames to canonical telemetry JSON.
    Handles SSID encoding, vendor lookup, and field standardization.
    """

    # Common OUI database (subset)
    DEFAULT_OUI_DB = {
        "00:1A:2B": "Cisco",
        "00:0C:29": "VMware",
        "00:50:F2": "Microsoft",
        "00:1E:58": "D-Link",
        "00:14:BF": "Linksys",
        "00:1B:63": "Apple",
        "00:17:C4": "Netgear",
        "00:22:6B": "Cisco-Linksys",
        "00:25:9C": "Cisco-Linksys",
        "00:03:7F": "Atheros",
        "00:0F:B5": "Netgear",
        "14:91:82": "TP-Link",
        "18:D6:C7": "TP-Link",
        "50:C7:BF": "TP-Link",
        "AC:84:C6": "TP-Link",
        "00:26:5A": "D-Link",
        "1C:7E:E5": "D-Link",
        "C8:D7:19": "Cisco-Linksys",
        "E4:F4:C6": "Netgear",
        "00:24:B2": "Netgear",
        "20:AA:4B": "Cisco-Linksys",
        "58:6D:8F": "Cisco-Linksys",
        "C0:C1:C0": "Cisco-Linksys",
    }

    # Channel to frequency mapping
    CHANNEL_FREQ_2G = {
        1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432,
        6: 2437, 7: 2442, 8: 2447, 9: 2452, 10: 2457,
        11: 2462, 12: 2467, 13: 2472, 14: 2484
    }

    def __init__(
        self,
        sensor_id: str,
        capture_method: str = "scapy",
        oui_db: Optional[Dict[str, str]] = None,
        anonymize_ssid: bool = False
    ):
        """
        Initialize normalizer.

        Args:
            sensor_id: Unique sensor identifier
            capture_method: Capture method identifier
            oui_db: OUI database for vendor lookup
            anonymize_ssid: Hash SSIDs for privacy
        """
        self.sensor_id = sensor_id
        self.capture_method = capture_method
        self.oui_db = oui_db or self.DEFAULT_OUI_DB
        self.anonymize_ssid = anonymize_ssid

        self._sequence_id = 0
        self._start_time = datetime.now(timezone.utc)

    def normalize(self, parsed_frame: Any) -> TelemetryFrame:
        """
        Convert parsed frame to TelemetryFrame.

        Args:
            parsed_frame: ParsedFrame from FrameParser

        Returns:
            TelemetryFrame with canonical fields
        """
        self._sequence_id += 1

        # Get vendor info
        vendor_oui = self._extract_oui(parsed_frame.bssid)
        vendor_name = self._lookup_vendor(vendor_oui)

        # Calculate frequency
        frequency = self._channel_to_freq(parsed_frame.channel)

        # Handle SSID
        ssid = parsed_frame.ssid
        if self.anonymize_ssid and ssid:
            ssid = self._anonymize(ssid)

        # Build capabilities
        caps = Capabilities(
            privacy=parsed_frame.privacy,
            ht=parsed_frame.ht_capable,
            vht=parsed_frame.vht_capable,
            he=parsed_frame.he_capable,
            pmf=parsed_frame.pmf_capable or parsed_frame.pmf_required,
            wps=parsed_frame.wps_enabled,
            ess=parsed_frame.ess,
            ibss=parsed_frame.ibss,
            ies_present=parsed_frame.ies_present
        )

        # Build IE dictionary
        ie = {}
        if parsed_frame.rsn_info:
            ie['rsn'] = parsed_frame.rsn_info
        if parsed_frame.wpa_info:
            ie['wpa'] = parsed_frame.wpa_info
        if parsed_frame.beacon_interval:
            ie['beacon_interval'] = parsed_frame.beacon_interval
        if parsed_frame.ies:
            ie.update(parsed_frame.ies)

        # Calculate uptime
        uptime = (
            datetime.now(
                timezone.utc) -
            self._start_time).total_seconds()

        return TelemetryFrame(
            sensor_id=self.sensor_id,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            sequence_id=self._sequence_id,
            capture_method=self.capture_method,
            frame_type=parsed_frame.frame_type,
            bssid=parsed_frame.bssid,
            ssid=ssid,
            rssi_dbm=parsed_frame.rssi_dbm,
            channel=parsed_frame.channel,
            frequency_mhz=frequency,
            vendor_oui=vendor_oui,
            vendor_name=vendor_name,
            capabilities=caps,
            ie=ie,
            local_uptime_seconds=uptime,
            time_sync=True,
            parse_error=parsed_frame.parse_error,
            ssid_decoding_error=parsed_frame.ssid_decoding_error
        )

    def _extract_oui(self, mac: str) -> Optional[str]:
        """Extract OUI from MAC address"""
        if not mac:
            return None
        parts = mac.split(':')
        if len(parts) >= 3:
            return ':'.join(parts[:3]).upper()
        return None

    def _lookup_vendor(self, oui: Optional[str]) -> Optional[str]:
        """Lookup vendor name from OUI"""
        if not oui:
            return None
        return self.oui_db.get(oui.upper())

    def _channel_to_freq(self, channel: int) -> int:
        """Convert channel number to frequency in MHz"""
        if channel in self.CHANNEL_FREQ_2G:
            return self.CHANNEL_FREQ_2G[channel]
        elif 36 <= channel <= 165:
            # 5 GHz bands (simplified)
            return 5000 + (channel * 5)
        return 0

    def _anonymize(self, ssid: str) -> str:
        """Hash SSID for privacy"""
        hash_val = hashlib.sha256(ssid.encode()).hexdigest()[:8]
        return f"ANON_{len(ssid)}_{hash_val}"

    def get_stats(self) -> Dict[str, Any]:
        """Get normalizer statistics"""
        return {
            'sensor_id': self.sensor_id,
            'sequence_id': self._sequence_id,
            'uptime_seconds': (
                datetime.now(
                    timezone.utc) -
                self._start_time).total_seconds(),
            'capture_method': self.capture_method,
            'anonymize_ssid': self.anonymize_ssid}
