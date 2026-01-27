#!/usr/bin/env python3
"""
Buffered Storage - High Performance SQLite with Batch Writes
Reduces I/O overhead by buffering packets before bulk insert.
"""

import sqlite3
import threading
import time
import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from queue import Queue, Empty

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BufferedStorage:
    """
    High-performance SQLite storage with write buffering.
    Collects packets in memory and performs bulk inserts.
    """
    
    def __init__(
        self,
        db_path: str = "wifi_scanner.db",
        buffer_size: int = 100,
        flush_interval: float = 5.0
    ):
        """
        Initialize buffered storage.
        
        Args:
            db_path: Path to SQLite database
            buffer_size: Number of records to buffer before flush
            flush_interval: Seconds between auto-flush (even if buffer not full)
        """
        self.db_path = db_path
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        
        self.buffer: List[Dict[str, Any]] = []
        self.buffer_lock = threading.Lock()
        
        self.flush_thread: Optional[threading.Thread] = None
        self.running = False
        
        self.stats = {
            "total_buffered": 0,
            "total_flushed": 0,
            "flush_count": 0,
            "last_flush": None
        }
        
        # Initialize database
        self._init_db()
        
    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL,
                ssid TEXT,
                channel INTEGER,
                rssi INTEGER,
                encryption TEXT,
                vendor TEXT,
                wps INTEGER DEFAULT 0,
                handshake_captured INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                beacon_count INTEGER DEFAULT 1,
                risk_score INTEGER,
                UNIQUE(bssid, ssid)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                severity TEXT,
                sender TEXT,
                target TEXT,
                bssid TEXT,
                details TEXT,
                timestamp TEXT
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_bssid ON networks(bssid)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON security_events(timestamp)")
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")
    
    def start(self):
        """Start background flush thread."""
        if self.running:
            return
            
        self.running = True
        self.flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self.flush_thread.start()
        logger.info(f"Buffered storage started (buffer={self.buffer_size}, interval={self.flush_interval}s)")
    
    def stop(self):
        """Stop and flush remaining buffer."""
        self.running = False
        self.flush()
        logger.info("Buffered storage stopped")
    
    def _flush_loop(self):
        """Background thread for periodic flushing."""
        while self.running:
            time.sleep(self.flush_interval)
            self.flush()
    
    def add_network(self, network: Dict[str, Any]):
        """Add network to buffer."""
        with self.buffer_lock:
            self.buffer.append({
                "type": "network",
                "data": network,
                "timestamp": datetime.now().isoformat()
            })
            self.stats["total_buffered"] += 1
            
            if len(self.buffer) >= self.buffer_size:
                self._do_flush()
    
    def add_event(self, event: Dict[str, Any]):
        """Add security event to buffer."""
        with self.buffer_lock:
            self.buffer.append({
                "type": "event",
                "data": event,
                "timestamp": datetime.now().isoformat()
            })
            self.stats["total_buffered"] += 1
            
            if len(self.buffer) >= self.buffer_size:
                self._do_flush()
    
    def flush(self):
        """Force flush buffer to database."""
        with self.buffer_lock:
            self._do_flush()
    
    def _do_flush(self):
        """Internal flush (must hold lock)."""
        if not self.buffer:
            return
            
        networks = [item for item in self.buffer if item["type"] == "network"]
        events = [item for item in self.buffer if item["type"] == "event"]
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Bulk upsert networks
            for item in networks:
                net = item["data"]
                cursor.execute("""
                    INSERT INTO networks (bssid, ssid, channel, rssi, encryption, vendor, wps, handshake_captured, first_seen, last_seen, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid, ssid) DO UPDATE SET
                        rssi = excluded.rssi,
                        last_seen = excluded.last_seen,
                        beacon_count = beacon_count + 1,
                        wps = MAX(wps, excluded.wps),
                        handshake_captured = MAX(handshake_captured, excluded.handshake_captured),
                        risk_score = excluded.risk_score
                """, (
                    net.get("bssid"),
                    net.get("ssid"),
                    net.get("channel"),
                    net.get("rssi"),
                    net.get("encryption"),
                    net.get("vendor"),
                    1 if net.get("wps") else 0,
                    1 if net.get("handshake_captured") else 0,
                    net.get("first_seen", item["timestamp"]),
                    net.get("last_seen", item["timestamp"]),
                    net.get("risk_score")
                ))
            
            # Bulk insert events
            for item in events:
                evt = item["data"]
                cursor.execute("""
                    INSERT INTO security_events (event_type, severity, sender, target, bssid, details, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    evt.get("type"),
                    evt.get("severity"),
                    evt.get("sender"),
                    evt.get("target"),
                    evt.get("bssid"),
                    json.dumps(evt),
                    evt.get("timestamp", item["timestamp"])
                ))
            
            conn.commit()
            conn.close()
            
            flushed = len(self.buffer)
            self.buffer.clear()
            
            self.stats["total_flushed"] += flushed
            self.stats["flush_count"] += 1
            self.stats["last_flush"] = datetime.now().isoformat()
            
            logger.debug(f"Flushed {flushed} records to database")
            
        except Exception as e:
            logger.error(f"Flush error: {e}")
    
    def get_networks(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get networks from database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM networks ORDER BY last_seen DESC LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get security events from database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get buffer statistics."""
        with self.buffer_lock:
            return {
                **self.stats,
                "current_buffer_size": len(self.buffer),
                "buffer_capacity": self.buffer_size
            }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Buffered Storage CLI")
    parser.add_argument("--db", default="wifi_scanner.db", help="Database path")
    parser.add_argument("--buffer", type=int, default=100, help="Buffer size")
    parser.add_argument("--interval", type=float, default=5.0, help="Flush interval (seconds)")
    parser.add_argument("--test", action="store_true", help="Run test insert")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--list", action="store_true", help="List networks")
    
    args = parser.parse_args()
    
    storage = BufferedStorage(
        db_path=args.db,
        buffer_size=args.buffer,
        flush_interval=args.interval
    )
    
    if args.test:
        print("Running test: Adding 500 networks...")
        storage.start()
        
        start = time.time()
        for i in range(500):
            storage.add_network({
                "ssid": f"TestNet_{i}",
                "bssid": f"AA:BB:CC:{i%256:02X}:{(i//256)%256:02X}:00",
                "channel": (i % 13) + 1,
                "rssi": -50 - (i % 40),
                "encryption": "WPA2-PSK"
            })
        
        storage.stop()
        elapsed = time.time() - start
        print(f"Completed in {elapsed:.2f}s ({500/elapsed:.0f} records/sec)")
        print(f"Stats: {storage.get_stats()}")
        
    elif args.stats:
        print(f"Stats: {json.dumps(storage.get_stats(), indent=2)}")
        
    elif args.list:
        networks = storage.get_networks(limit=20)
        print(f"Networks ({len(networks)}):")
        for net in networks:
            print(f"  {net['ssid'][:20]:20} | {net['bssid']} | {net['rssi']}dBm")
    
    else:
        print("Use --test, --stats, or --list")
