"""
Sentinel NetLab - Storage Shim
Shim module for backward compatibility with legacy tests.
"""

import logging

from sensor.storage_buffered import BufferedStorage as DBStorage

logger = logging.getLogger(__name__)


class MemoryStorage:
    """
    Simple in-memory storage for testing compatibility.
    """

    def __init__(self):
        self.networks = {}
        self.events = []

    def add_network(self, network: dict):
        bssid = network.get("bssid")
        if bssid:
            if bssid in self.networks:
                self.networks[bssid].update(network)
                self.networks[bssid]["beacon_count"] = (
                    self.networks[bssid].get("beacon_count", 0) + 1
                )
            else:
                self.networks[bssid] = network.copy()
                self.networks[bssid]["beacon_count"] = 1

    def add_event(self, event: dict):
        self.events.append(event)

    def get_networks(self) -> list:
        return list(self.networks.values())

    def get_events(self) -> list:
        return self.events

    def clear(self):
        self.networks.clear()
        self.events.clear()


# Expose SQLiteStorage for S608 task if needed, but primarily tests ask for MemoryStorage
class SQLiteStorage:
    """
    Wrapper around BufferedStorage for compatibility if accessed as SQLiteStorage.
    Also implements S608 checks if raw queries are used.
    """

    def __init__(self, db_path="wifi_scanner.db"):
        self.impl = DBStorage(db_path=db_path)

    def save_network(self, network):
        self.impl.add_network(network)
        self.impl.flush()  # Sync for old tests

    def get_networks(self, limit=100, offset=0, order_by="last_seen"):
        # This is where S608 was reported in USER_REQUEST
        # "cursor.execute(f'SELECT * FROM networks ORDER BY {order_by} LIMIT ? OFFSET ?', ...)"

        # Whitelist for order_by
        allowed_columns = {"last_seen", "rssi", "ssid", "bssid", "first_seen"}
        if order_by not in allowed_columns:
            logger.warning(f"Invalid order_by '{order_by}', defaulting to last_seen")
            order_by = "last_seen"

        conn = self.impl._init_db()  # Re-init returns nothing but ensures table exists.
        # Actually _init_db creates tables. We need a connection.
        import sqlite3

        conn = sqlite3.connect(self.impl.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Mitigation for S608: static query construction based on validated input
        # But f-string for column name is flagged by Bandit unless trusted.
        # Since we validated against whitelist, it is safe.
        query = (
            f"SELECT * FROM networks ORDER BY {order_by} DESC LIMIT ? OFFSET ?"  # nosec
        )

        cursor.execute(query, (limit, offset))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
