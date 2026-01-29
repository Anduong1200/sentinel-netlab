"""
Sentinel NetLab - Telemetry Normalizer
Converts parsed frames to canonical telemetry format.
"""

import logging
from datetime import UTC, datetime
from typing import Any

from schema import Capabilities, TelemetryItem

from common.oui import OUI_DATABASE
from common.privacy import anonymize_mac_oui, get_oui, hash_mac
from common.privacy import anonymize_ssid as priv_anonymize_ssid

logger = logging.getLogger(__name__)


class TelemetryNormalizer:
    """
    Normalizes parsed 802.11 frames to canonical telemetry JSON.
    Handles SSID encoding, vendor lookup, and field standardization.
    """

    # Common OUI database (subset)
    # Common OUI database (subset)
    # DEPRECATED: Use common.oui.OUI_DATABASE
    # Removed local duplicate to prevent inconsistency

    # Channel to frequency mapping
    CHANNEL_FREQ_2G = {
        1: 2412,
        2: 2417,
        3: 2422,
        4: 2427,
        5: 2432,
        6: 2437,
        7: 2442,
        8: 2447,
        9: 2452,
        10: 2457,
        11: 2462,
        12: 2467,
        13: 2472,
        14: 2484,
    }

    def __init__(
        self,
        sensor_id: str,
        capture_method: str = "scapy",
        oui_db: dict[str, str] | None = None,
        anonymize_ssid: bool = False,
        store_raw_mac: bool = False,
        privacy_mode: str = "anonymized",
    ):
        """
        Initialize normalizer.

        Args:
            sensor_id: Unique sensor identifier
            capture_method: Capture method identifier
            oui_db: OUI database for vendor lookup
            anonymize_ssid: Hash SSIDs for privacy
            store_raw_mac: If True, keep raw MAC. If False, apply privacy mode.
            privacy_mode: 'normal', 'anonymized' (OUI kept), or 'private' (full hash)
        """
        self.sensor_id = sensor_id
        self.capture_method = capture_method
        self.oui_db = oui_db or OUI_DATABASE
        self.anonymize_ssid = anonymize_ssid
        self.store_raw_mac = store_raw_mac
        self.privacy_mode = privacy_mode

        self._sequence_id = 0
        self._start_time = datetime.now(UTC)

    def normalize(self, parsed_frame: Any) -> TelemetryItem:
        """
        Convert parsed frame to TelemetryItem.

        Args:
            parsed_frame: ParsedFrame from FrameParser

        Returns:
            TelemetryItem with canonical fields
        """
        self._sequence_id += 1

        # Handle Privacy (MAC Address)
        bssid = parsed_frame.bssid
        if not self.store_raw_mac:
            if self.privacy_mode == "private":
                bssid = hash_mac(bssid)
            else:
                # Default to anonymized (keep OUI)
                bssid = anonymize_mac_oui(bssid)

        # Get vendor info (use original BSSID for lookup if possible, or extract from anonymized if OUI preserved)
        # Note: If we anonymized getting OUI might still work if we kept it.
        # But if we fully hashed, we can't get OUI.
        # Get vendor info
        # Note: If we anonymized getting OUI might still work if we kept it.
        # But if we fully hashed, we can't get OUI.
        vendor_oui = get_oui(parsed_frame.bssid)  # Use original BSSID for lookup
        self._lookup_vendor(vendor_oui)

        # Calculate frequency
        frequency = self._channel_to_freq(parsed_frame.channel)

        # Handle SSID
        ssid = parsed_frame.ssid
        if self.anonymize_ssid:
            ssid = priv_anonymize_ssid(ssid)

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
            ies_present=parsed_frame.ies_present,
        )

        # Build IE dictionary
        ie = {}
        if parsed_frame.rsn_info:
            ie["rsn"] = parsed_frame.rsn_info
        if parsed_frame.wpa_info:
            ie["wpa"] = parsed_frame.wpa_info
        if parsed_frame.beacon_interval:
            ie["beacon_interval"] = parsed_frame.beacon_interval
        if parsed_frame.ies:
            ie.update(parsed_frame.ies)

        # Calculate uptime
        (datetime.now(UTC) - self._start_time).total_seconds()

        return TelemetryItem(
            bssid=bssid,
            ssid=ssid,
            channel=parsed_frame.channel,
            rssi_dbm=parsed_frame.rssi_dbm,
            frequency_mhz=frequency,
            capabilities=caps,
            vendor_oui=vendor_oui,
            # Map IE dict to count
            ie_count=len(ie) if ie else 0,
            beacon_interval=parsed_frame.beacon_interval,
            # Use current timestamp
            timestamp=datetime.now(UTC).isoformat(),
        )

    def _lookup_vendor(self, oui: str | None) -> str | None:
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

    def get_stats(self) -> dict[str, Any]:
        """Get normalizer statistics"""
        return {
            "sensor_id": self.sensor_id,
            "sequence_id": self._sequence_id,
            "uptime_seconds": (
                datetime.now(UTC) - self._start_time
            ).total_seconds(),
            "capture_method": self.capture_method,
            "anonymize_ssid": self.anonymize_ssid,
        }
