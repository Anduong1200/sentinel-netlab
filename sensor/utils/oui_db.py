"""
Sentinel NetLab - OUI Database Utilities
Lookup vendor names from MAC address OUI prefixes.
"""

import json
import logging
from typing import Optional, Dict
from pathlib import Path

logger = logging.getLogger(__name__)


class OUIDatabase:
    """
    OUI (Organizationally Unique Identifier) database for vendor lookup.
    Supports loading from local JSON file and updates.
    """

    # Embedded common OUIs (subset for offline use)
    EMBEDDED_OUI = {
        "00:00:0C": "Cisco",
        "00:01:42": "Cisco",
        "00:0C:29": "VMware",
        "00:0C:41": "Cisco-Linksys",
        "00:0E:35": "Intel",
        "00:0F:B5": "Netgear",
        "00:14:BF": "Linksys",
        "00:17:C4": "Netgear",
        "00:18:E7": "Cameo",
        "00:1A:2B": "Cisco",
        "00:1B:63": "Apple",
        "00:1C:B3": "Apple",
        "00:1E:58": "D-Link",
        "00:1F:3A": "Hon Hai",
        "00:22:6B": "Cisco-Linksys",
        "00:24:B2": "Netgear",
        "00:25:00": "Apple",
        "00:25:9C": "Cisco-Linksys",
        "00:26:5A": "D-Link",
        "00:27:0E": "Intel",
        "00:50:F2": "Microsoft",
        "08:00:27": "PCS",
        "14:91:82": "TP-Link",
        "18:D6:C7": "TP-Link",
        "1C:7E:E5": "D-Link",
        "20:AA:4B": "Cisco-Linksys",
        "24:0A:C4": "Espressif",
        "30:AE:A4": "Espressif",
        "3C:D9:2B": "HP",
        "40:16:7E": "ASUSTek",
        "50:C7:BF": "TP-Link",
        "58:6D:8F": "Cisco-Linksys",
        "60:A4:4C": "ASUSTek",
        "68:B6:B3": "Netgear",
        "70:85:C2": "ASRock",
        "74:DA:38": "Edimax",
        "78:8A:20": "Ubiquiti",
        "80:2A:A8": "Ubiquiti",
        "84:D4:7E": "Aruba",
        "88:15:44": "Cisco",
        "94:10:3E": "Belkin",
        "A4:08:F5": "Apple",
        "AC:84:C6": "TP-Link",
        "B0:39:56": "Netgear",
        "B8:27:EB": "Raspberry Pi Foundation",
        "C0:C1:C0": "Cisco-Linksys",
        "C8:D7:19": "Cisco-Linksys",
        "CC:32:E5": "TP-Link",
        "D4:3D:7E": "Micro-Star",
        "DC:A6:32": "Raspberry Pi",
        "E4:F4:C6": "Netgear",
        "E8:DE:27": "TP-Link",
        "F0:9F:C2": "Ubiquiti",
        "F4:F2:6D": "TP-Link"
    }

    # Trusted enterprise vendors (lower risk)
    TRUSTED_VENDORS = [
        "cisco", "aruba", "juniper", "fortinet", "meraki",
        "ruckus", "ubiquiti", "hp", "arista"
    ]

    # Consumer vendors (moderate risk)
    CONSUMER_VENDORS = [
        "tp-link", "netgear", "linksys", "d-link", "asus", "belkin",
        "edimax", "tenda", "zyxel"
    ]

    def __init__(self, oui_file: Optional[str] = None):
        """
        Initialize OUI database.

        Args:
            oui_file: Path to JSON OUI database file
        """
        self._db: Dict[str, str] = dict(self.EMBEDDED_OUI)

        if oui_file and Path(oui_file).exists():
            self._load_file(oui_file)

    def _load_file(self, path: str) -> None:
        """Load OUI database from JSON file"""
        try:
            with open(path) as f:
                data = json.load(f)
                self._db.update(data)
                logger.info(f"Loaded {len(data)} OUIs from {path}")
        except Exception as e:
            logger.warning(f"Failed to load OUI file: {e}")

    def lookup(self, mac: str) -> Optional[str]:
        """
        Lookup vendor name from MAC address.

        Args:
            mac: MAC address (any format)

        Returns:
            Vendor name or None
        """
        if not mac:
            return None

        # Normalize: extract first 3 octets
        mac = mac.upper().replace('-', ':')
        parts = mac.split(':')
        if len(parts) >= 3:
            oui = ':'.join(parts[:3])
            return self._db.get(oui)

        return None

    def get_oui(self, mac: str) -> Optional[str]:
        """Extract OUI prefix from MAC address"""
        if not mac:
            return None
        mac = mac.upper().replace('-', ':')
        parts = mac.split(':')
        if len(parts) >= 3:
            return ':'.join(parts[:3])
        return None

    def is_trusted_vendor(self, vendor: Optional[str]) -> bool:
        """Check if vendor is enterprise/trusted"""
        if not vendor:
            return False
        vendor_lower = vendor.lower()
        return any(t in vendor_lower for t in self.TRUSTED_VENDORS)

    def is_consumer_vendor(self, vendor: Optional[str]) -> bool:
        """Check if vendor is consumer-grade"""
        if not vendor:
            return False
        vendor_lower = vendor.lower()
        return any(c in vendor_lower for c in self.CONSUMER_VENDORS)

    def get_vendor_risk(self, vendor: Optional[str]) -> float:
        """
        Get vendor risk score (0.0 = trusted, 1.0 = unknown).

        Returns:
            0.0: Trusted enterprise vendor
            0.3: Consumer vendor
            0.5: Unknown vendor
        """
        if not vendor:
            return 0.5
        if self.is_trusted_vendor(vendor):
            return 0.0
        if self.is_consumer_vendor(vendor):
            return 0.3
        return 0.5

    def update_from_url(self, url: str) -> bool:
        """
        Update OUI database from remote URL.

        Args:
            url: URL to JSON OUI database

        Returns:
            True if updated successfully
        """
        try:
            import requests
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            self._db.update(data)
            logger.info(f"Updated OUI database with {len(data)} entries")
            return True
        except Exception as e:
            logger.error(f"Failed to update OUI database: {e}")
            return False

    def save(self, path: str) -> bool:
        """Save current database to file"""
        try:
            with open(path, 'w') as f:
                json.dump(self._db, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save OUI database: {e}")
            return False

    def __len__(self) -> int:
        return len(self._db)


# Default instance
_default_db = None

def get_oui_database() -> OUIDatabase:
    """Get default OUI database instance"""
    global _default_db
    if _default_db is None:
        _default_db = OUIDatabase()
    return _default_db
