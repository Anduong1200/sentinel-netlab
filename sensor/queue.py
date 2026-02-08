"""
Sentinel NetLab - Persistent Queue (Spool)
SQLite-backed queue for reliable telemetry delivery.
Implementation follows 'Sensor local spool' specification.
"""

import json
import logging
import random
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.observability.metrics import create_counter

logger = logging.getLogger(__name__)

SPOOL_DROPS = create_counter(
    "spool_drops_total", "Dropped batches due to full spool", ["reason"]
)


@dataclass
class SpoolEntry:
    """Represents a spooled telemetry batch."""

    id: int
    batch_id: str
    payload: dict[str, Any]
    created_at: int
    attempts: int
    last_error: str | None


class SqliteQueue:
    """
    Persistent queue backed by SQLite (Spool).
    """

    DEFAULT_DB_PATH = "data/spool.db"
    MAX_SIZE = 10000
    MAX_BYTES = 100 * 1024 * 1024  # 100MB

    MAX_BYTES = 100 * 1024 * 1024  # 100MB

    def __init__(
        self,
        db_path: str | None = None,
        max_size: int = MAX_SIZE,
        max_bytes: int = MAX_BYTES,
    ):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self.max_size = max_size
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_db()
        self.recover_stuck_inflight()  # Reset stuck inflight items on startup

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0,
            )
            # Optimization & Reliability settings
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()

            # Key-Value store for Sequences
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kv (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                )
            """)

            # Spool Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS spool (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('queued', 'inflight', 'acked', 'dead')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                )
            """)

            # Indexes
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_spool_state_next ON spool(state, next_attempt_at)"
            )

            # Migration: Drop old 'batches' table if exists from previous version
            conn.execute("DROP TABLE IF EXISTS batches")

            conn.commit()
            logger.info(f"Spool DB initialized: {self.db_path}")

    def next_seq(self, sensor_id: str) -> int:
        """Get next sequence number for sensor_id."""
        with self._lock:
            conn = self._get_conn()
            key = f"seq:{sensor_id}"
            cursor = conn.execute(
                "INSERT INTO kv(key, value) VALUES(?, 1) ON CONFLICT(key) DO UPDATE SET value=value+1 RETURNING value",
                (key,),
            )
            val = cursor.fetchone()[0]
            conn.commit()
            return int(val)

    def push(self, payload: dict[str, Any], batch_id: str) -> bool:
        """Enqueue a batch."""
        payload_json = json.dumps(payload)

        with self._lock:
            conn = self._get_conn()

            # Size check (Approximate count)
            # Check size limits
            cursor = conn.execute(
                "SELECT COUNT(*), SUM(LENGTH(payload_json)) FROM spool WHERE state != 'acked'"
            )
            row = cursor.fetchone()
            count = row[0] or 0
            total_bytes = row[1] or 0

            if count >= self.max_size:
                logger.warning("Spool full (count)")
                SPOOL_DROPS.labels(reason="count_limit").inc()
                return False

            if total_bytes + len(payload_json) > self.max_bytes:
                logger.warning("Spool full (bytes)")
                SPOOL_DROPS.labels(reason="bytes_limit").inc()
                return False

            try:
                conn.execute(
                    """
                    INSERT INTO spool (batch_id, created_at, payload_json, state, next_attempt_at)
                    VALUES (?, ?, ?, 'queued', 0)
                """,
                    (batch_id, int(time.time()), payload_json),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                logger.warning(f"Duplicate batch_id pushed: {batch_id}")
                return True  # Treat as success (idempotent)

    def get_pending(self) -> SpoolEntry | None:
        """
        Get one pending batch to process.
        Transitions state from 'queued' -> 'inflight'.
        """
        with self._lock:
            conn = self._get_conn()
            now = int(time.time())

            # Find one eligible batch
            # Priority: Queued items, or failed items ready for retry
            cursor = conn.execute(
                """
                SELECT id, batch_id, payload_json, created_at, attempts
                FROM spool
                WHERE state = 'queued' AND next_attempt_at <= ?
                ORDER BY created_at ASC
                LIMIT 1
            """,
                (now,),
            )

            row = cursor.fetchone()
            if not row:
                return None

            # Mark inflight
            conn.execute(
                """
                UPDATE spool SET state = 'inflight' WHERE id = ?
            """,
                (row["id"],),
            )
            conn.commit()

            return SpoolEntry(
                id=row["id"],
                batch_id=row["batch_id"],
                payload=json.loads(row["payload_json"]),
                created_at=row["created_at"],
                attempts=row["attempts"],
                last_error=None,
            )

    def ack(self, batch_id: str) -> None:
        """Mark batch as successfully delivered (delete it)."""
        with self._lock:
            conn = self._get_conn()
            # We delete on ACK to keep spool small, per user implication "acked (hoặc xoá record)"
            # Deleting is safer for disk usage.
            conn.execute("DELETE FROM spool WHERE batch_id = ?", (batch_id,))
            conn.commit()
            logger.debug(f"ACK: Deleted {batch_id}")

    def nack(self, batch_id: str, error: str) -> None:
        """Handle failure: schedule retry."""
        with self._lock:
            conn = self._get_conn()

            # Get current attempts
            cursor = conn.execute(
                "SELECT attempts FROM spool WHERE batch_id = ?", (batch_id,)
            )
            row = cursor.fetchone()
            if not row:
                return  # Gone?

            attempts = row["attempts"] + 1

            # Backoff calculation
            backoff = self._calculate_backoff(attempts)
            next_attempt = int(time.time() + backoff)

            state = "queued"
            # Optional: Dead letter if too many attempts? User didn't specify strict max,
            # but backoff cap is 60s. Let's keep retrying indefinitely or set a high limit logic if needed.
            # User doc implies "Backoff chuẩn", doesn't explicitly say "Dead letter after X".
            # But the schema has 'dead' state. I'll define a reasonable max (e.g. 50 attempts) or just keep queued.
            # I will just keep queued for now as "Mất mạng... -> không mất".

            conn.execute(
                """
                UPDATE spool
                SET state = ?, attempts = ?, next_attempt_at = ?, last_error = ?
                WHERE batch_id = ?
            """,
                (state, attempts, next_attempt, error, batch_id),
            )
            conn.commit()
            logger.warning(
                f"NACK: {batch_id} retry #{attempts} in {backoff:.1f}s. Error: {error}"
            )

    def mark_dead(self, batch_id: str, error: str) -> None:
        """Mark batch as dead (non-retryable failure)."""
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "UPDATE spool SET state = 'dead', last_error = ? WHERE batch_id = ?",
                (error, batch_id),
            )
            conn.commit()
            logger.error(f"MARKED DEAD: {batch_id}. Error: {error}")

    def _calculate_backoff(self, attempts: int, base=1.0, cap=60.0) -> float:
        # 1, 2, 4, 8... capped + jitter 0.5-1.5x
        raw = min(cap, base * (2 ** max(0, attempts - 1)))
        return float(raw * random.uniform(0.5, 1.5))  # noqa: S311

    def recover_stuck_inflight(self, age_seconds=60) -> None:
        """Reset stuck inflight items to queued on startup."""
        with self._lock:
            conn = self._get_conn()
            # If we just started, anything 'inflight' was interrupted.
            # User suggested "inflight quá lâu -> revert queued".
            # Simplest is to just reset ALL inflight on startup.
            conn.execute("""
                UPDATE spool SET state = 'queued' WHERE state = 'inflight'
            """)
            count = conn.total_changes
            conn.commit()
            if count > 0:
                logger.warning(f"Recovered {count} stuck inflight batches")

    def stats(self) -> dict[str, Any]:
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN state='queued' THEN 1 ELSE 0 END) as queued,
                    SUM(CASE WHEN state='inflight' THEN 1 ELSE 0 END) as inflight,
                    SUM(LENGTH(payload_json)) as bytes
                FROM spool
            """)
            row = cursor.fetchone()
            return {
                "total": row["total"] or 0,
                "queued": row["queued"] or 0,
                "inflight": row["inflight"] or 0,
                "bytes": row["bytes"] or 0,
            }

    def close(self):
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
