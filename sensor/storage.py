#!/usr/bin/env python3
"""
WiFi Storage Module - SQLite database and PCAP file management
Handles persistence of network data and packet captures
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Default paths
DEFAULT_DB_PATH = "/var/lib/wifi-scanner/wifi_scans.db"
DEFAULT_PCAP_DIR = "/var/lib/wifi-scanner/pcaps"


class WiFiStorage:
    """
    Handles persistent storage of WiFi scan data.
    - SQLite for network metadata
    - PCAP files for raw captures
    """

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        pcap_dir: str = DEFAULT_PCAP_DIR,
        pcap_max_age_days: int = 7,
        pcap_max_size_mb: int = 100
    ):
        """
        Initialize storage manager.

        Args:
            db_path: Path to SQLite database file
            pcap_dir: Directory to store PCAP files
            pcap_max_age_days: Max age of PCAP files before rotation
            pcap_max_size_mb: Max total size of PCAP files in MB
        """
        self.db_path = db_path
        self.pcap_dir = Path(pcap_dir)
        self.pcap_max_age_days = pcap_max_age_days
        self.pcap_max_size_mb = pcap_max_size_mb

        # Initialize
        self._init_database()
        self._init_pcap_dir()

    def _init_database(self):
        """Create database and tables if they don't exist."""
        # Ensure directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Networks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT UNIQUE NOT NULL,
                ssid TEXT,
                channel INTEGER,
                encryption TEXT,
                vendor TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                beacon_count INTEGER DEFAULT 1,
                best_rssi INTEGER DEFAULT -100
            )
        """)

        # Scans table (for history)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                duration_seconds INTEGER,
                network_count INTEGER,
                pcap_file TEXT
            )
        """)

        # Scan results (many-to-many between scans and networks)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                bssid TEXT,
                rssi INTEGER,
                channel INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                FOREIGN KEY (bssid) REFERENCES networks(bssid)
            )
        """)

        # Indexes
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id)
        """)

        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")

    def _init_pcap_dir(self):
        """Create PCAP directory if it doesn't exist."""
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"PCAP directory: {self.pcap_dir}")

    def store_networks(self, networks: list[dict[str, Any]]) -> int:
        """
        Store or update network records in database.

        Args:
            networks: List of network dictionaries

        Returns:
            Number of networks stored/updated
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        count = 0

        for net in networks:
            try:
                cursor.execute("""
                    INSERT INTO networks (bssid, ssid, channel, encryption, vendor,
                                         first_seen, last_seen, beacon_count, best_rssi)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid = COALESCE(excluded.ssid, networks.ssid),
                        channel = COALESCE(excluded.channel, networks.channel),
                        encryption = COALESCE(excluded.encryption, networks.encryption),
                        last_seen = excluded.last_seen,
                        beacon_count = networks.beacon_count + excluded.beacon_count,
                        best_rssi = MAX(networks.best_rssi, excluded.best_rssi)
                """, (
                    net.get("bssid"),
                    net.get("ssid"),
                    net.get("channel"),
                    net.get("encryption"),
                    net.get("vendor"),
                    net.get("first_seen", datetime.now().isoformat()),
                    net.get("last_seen", datetime.now().isoformat()),
                    net.get("beacon_count", 1),
                    net.get("rssi", -100)
                ))
                count += 1
            except Exception as e:
                logger.warning(
                    f"Failed to store network {net.get('bssid')}: {e}")

        conn.commit()
        conn.close()
        return count

    def get_networks(
        self,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "last_seen DESC"
    ) -> list[dict[str, Any]]:
        """
        Retrieve networks from database.

        Args:
            limit: Maximum number of networks to return
            offset: Pagination offset
            order_by: SQL ORDER BY clause

        Returns:
            List of network dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Sanitize order_by to prevent SQL injection
        allowed_orders = [
            "last_seen DESC",
            "first_seen DESC",
            "best_rssi DESC",
            "ssid ASC"]
        if order_by not in allowed_orders:
            order_by = "last_seen DESC"

        cursor.execute(f"""
            SELECT * FROM networks
            ORDER BY {order_by}
            LIMIT ? OFFSET ?
        """, (limit, offset))  # noqa: S608

        networks = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return networks

    def get_network_by_bssid(self, bssid: str) -> Optional[dict[str, Any]]:
        """Get a single network by BSSID."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM networks WHERE bssid = ?", (bssid.upper(),))
        row = cursor.fetchone()
        conn.close()

        return dict(row) if row else None

    def get_network_count(self) -> int:
        """Get total count of unique networks."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM networks")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def create_scan_record(
        self,
        duration_seconds: int,
        network_count: int,
        pcap_file: Optional[str] = None
    ) -> int:
        """
        Create a new scan record.

        Returns:
            Scan ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scans (duration_seconds, network_count, pcap_file)
            VALUES (?, ?, ?)
        """, (duration_seconds, network_count, pcap_file))

        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def get_scan_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get recent scan history."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM scans
            ORDER BY scan_time DESC
            LIMIT ?
        """, (limit,))

        scans = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return scans

    def export_csv(self, filepath: str = None) -> str:
        """
        Export all networks to CSV format.

        Args:
            filepath: Optional file path to write CSV

        Returns:
            CSV string content
        """
        networks = self.get_networks(limit=10000)

        # CSV header
        csv_lines = [
            "SSID,BSSID,Channel,Encryption,Vendor,First Seen,Last Seen,Beacon Count,Best RSSI"]

        for net in networks:
            line = ",".join([
                f'"{net.get("ssid", "")}"',
                net.get("bssid", ""),
                str(net.get("channel", "")),
                net.get("encryption", ""),
                f'"{net.get("vendor", "")}"',
                net.get("first_seen", ""),
                net.get("last_seen", ""),
                str(net.get("beacon_count", 0)),
                str(net.get("best_rssi", -100))
            ])
            csv_lines.append(line)

        csv_content = "\n".join(csv_lines)

        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(csv_content)
            logger.info(f"Exported {len(networks)} networks to {filepath}")

        return csv_content

    def export_json(self) -> str:
        """Export all networks as JSON string."""
        networks = self.get_networks(limit=10000)
        return json.dumps(networks, indent=2, default=str)

    # ========================
    # PCAP Management
    # ========================

    def generate_pcap_filename(self) -> str:
        """Generate a unique PCAP filename based on timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return str(self.pcap_dir / f"capture_{timestamp}.pcap")

    def rotate_pcaps(self):
        """
        Rotate PCAP files based on age and total size.
        Deletes old files to stay within limits.
        """
        if not self.pcap_dir.exists():
            return

        pcap_files = list(self.pcap_dir.glob("*.pcap"))

        if not pcap_files:
            return

        # Sort by modification time (oldest first)
        pcap_files.sort(key=lambda f: f.stat().st_mtime)

        # Remove files older than max age
        cutoff = datetime.now() - timedelta(days=self.pcap_max_age_days)
        for pcap in pcap_files[:]:
            mtime = datetime.fromtimestamp(pcap.stat().st_mtime)
            if mtime < cutoff:
                try:
                    pcap.unlink()
                    pcap_files.remove(pcap)
                    logger.info(f"Deleted old PCAP: {pcap.name}")
                except Exception as e:
                    logger.warning(f"Failed to delete {pcap}: {e}")

        # Remove files if total size exceeds limit
        total_size_mb = sum(
            f.stat().st_size for f in pcap_files) / (1024 * 1024)
        while total_size_mb > self.pcap_max_size_mb and pcap_files:
            oldest = pcap_files.pop(0)
            try:
                oldest.unlink()
                total_size_mb = sum(
                    f.stat().st_size for f in pcap_files) / (1024 * 1024)
                logger.info(f"Deleted PCAP for size limit: {oldest.name}")
            except Exception as e:
                logger.warning(f"Failed to delete {oldest}: {e}")

    def get_pcap_stats(self) -> dict[str, Any]:
        """Get statistics about stored PCAP files."""
        if not self.pcap_dir.exists():
            return {
                "count": 0,
                "total_size_mb": 0,
                "oldest": None,
                "newest": None}

        pcap_files = list(self.pcap_dir.glob("*.pcap"))

        if not pcap_files:
            return {
                "count": 0,
                "total_size_mb": 0,
                "oldest": None,
                "newest": None}

        pcap_files.sort(key=lambda f: f.stat().st_mtime)
        total_size = sum(f.stat().st_size for f in pcap_files)

        return {
            "count": len(pcap_files),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "oldest": pcap_files[0].name,
            "newest": pcap_files[-1].name
        }

    def clear_all(self):
        """Clear all data (for testing)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_results")
        cursor.execute("DELETE FROM scans")
        cursor.execute("DELETE FROM networks")
        conn.commit()
        conn.close()

        # Clear PCAPs
        for pcap in self.pcap_dir.glob("*.pcap"):
            try:
                pcap.unlink()
            except OSError:
                pass

        logger.info("All data cleared")


# In-memory storage for quick access (no disk I/O)
class MemoryStorage:
    """
    Simple in-memory storage for real-time scanning.
    Use WiFiStorage for persistence.
    """

    def __init__(self):
        self.networks: dict[str, dict[str, Any]] = {}
        self.scan_start: Optional[datetime] = None

    def update(self, network: dict[str, Any]):
        """Update or add a network."""
        bssid = network.get("bssid", "").upper()
        if bssid:
            self.networks[bssid] = network

    def get_all(self) -> list[dict[str, Any]]:
        """Get all networks."""
        return list(self.networks.values())

    def count(self) -> int:
        return len(self.networks)

    def clear(self):
        self.networks.clear()
        self.scan_start = None


if __name__ == "__main__":
    # Test with temporary paths
    print("=" * 50)
    print("WiFi Storage Module Test")
    print("=" * 50)

    # Use temp paths for testing
    storage = WiFiStorage(
        db_path="./test_wifi.db",
        pcap_dir="./test_pcaps"
    )

    # Test storing networks
    test_networks = [
        {
            "bssid": "AA:BB:CC:11:22:33",
            "ssid": "TestNetwork1",
            "channel": 6,
            "encryption": "WPA2-PSK",
            "vendor": "Test Corp",
            "rssi": -55
        },
        {
            "bssid": "11:22:33:44:55:66",
            "ssid": "OpenNetwork",
            "channel": 1,
            "encryption": "Open",
            "vendor": "Unknown",
            "rssi": -70
        }
    ]

    stored = storage.store_networks(test_networks)
    print(f"Stored {stored} networks")

    # Retrieve
    networks = storage.get_networks()
    print(f"Retrieved {len(networks)} networks")

    # Export
    csv = storage.export_csv()
    print(f"CSV export ({len(csv)} bytes)")

    # Stats
    print(f"Total networks: {storage.get_network_count()}")
    print(f"PCAP stats: {storage.get_pcap_stats()}")

    # Cleanup
    os.remove("./test_wifi.db")
    print("\nTest complete!")
