"""
Sentinel NetLab - TTLDict
A dictionary with automatic TTL-based expiry and max-size eviction.

Designed for bounded in-memory state on resource-constrained edge devices
(Raspberry Pi with 1-2GB RAM). Prevents OOM by enforcing both a hard cap
on entries and lazy expiration of stale data.

Usage:
    from common.ttl_dict import TTLDict

    state = TTLDict(maxsize=5000, ttl=600)  # 10 min TTL, 5K entries max
    state["AA:BB:CC"] = some_object
    val = state.get("AA:BB:CC")  # Returns None if expired
"""

import threading
import time
from collections import OrderedDict
from collections.abc import Iterator
from typing import Any

_SENTINEL = object()


class TTLDict:
    """
    Thread-safe dictionary with:
    - Per-entry TTL (time-to-live) expiration
    - Hard max-size cap with LRU eviction
    - Lazy cleanup on access + periodic bulk purge
    """

    __slots__ = ("_store", "_timestamps", "_maxsize", "_ttl", "_lock")

    def __init__(self, maxsize: int = 10000, ttl: float = 600.0):
        """
        Args:
            maxsize: Maximum number of entries. When exceeded, oldest entries
                     are evicted first (LRU order).
            ttl: Time-to-live in seconds for each entry. Entries older than
                 this are treated as expired and lazily removed.
        """
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        if ttl <= 0:
            raise ValueError("ttl must be > 0")

        self._store: OrderedDict[Any, Any] = OrderedDict()
        self._timestamps: dict[Any, float] = {}
        self._maxsize = maxsize
        self._ttl = ttl
        self._lock = threading.Lock()

    # ── Core dict API ───────────────────────────────────────────────────

    def __setitem__(self, key: Any, value: Any) -> None:
        with self._lock:
            now = time.monotonic()

            # If key exists, remove it first so it moves to end (refresh)
            if key in self._store:
                del self._store[key]

            # Evict if at capacity
            while len(self._store) >= self._maxsize:
                self._evict_one()

            self._store[key] = value
            self._timestamps[key] = now

    def __getitem__(self, key: Any) -> Any:
        with self._lock:
            if key not in self._store:
                raise KeyError(key)

            if self._is_expired(key):
                self._remove_key(key)
                raise KeyError(key)

            # Move to end (mark as recently used)
            self._store.move_to_end(key)
            return self._store[key]

    def __delitem__(self, key: Any) -> None:
        with self._lock:
            if key not in self._store:
                raise KeyError(key)
            self._remove_key(key)

    def __contains__(self, key: Any) -> bool:
        with self._lock:
            if key not in self._store:
                return False
            if self._is_expired(key):
                self._remove_key(key)
                return False
            return True

    def __len__(self) -> int:
        with self._lock:
            self._purge_expired()
            return len(self._store)

    def __iter__(self) -> Iterator:
        with self._lock:
            self._purge_expired()
            return iter(list(self._store.keys()))

    def __repr__(self) -> str:
        return f"TTLDict(maxsize={self._maxsize}, ttl={self._ttl}, len={len(self._store)})"

    # ── dict-compatible methods ─────────────────────────────────────────

    def get(self, key: Any, default: Any = None) -> Any:
        """Get value by key, returning default if missing or expired."""
        try:
            return self[key]
        except KeyError:
            return default

    def setdefault(self, key: Any, default: Any = None) -> Any:
        """If key is not present or expired, set it to default and return it."""
        with self._lock:
            if key in self._store and not self._is_expired(key):
                self._store.move_to_end(key)
                return self._store[key]

            # Key missing or expired — clean up and set
            if key in self._store:
                self._remove_key(key)

            while len(self._store) >= self._maxsize:
                self._evict_one()

            self._store[key] = default
            self._timestamps[key] = time.monotonic()
            return default

    def pop(self, key: Any, *args: Any) -> Any:
        """Remove and return value. Raises KeyError if not found (unless default given)."""
        with self._lock:
            if key not in self._store or self._is_expired(key):
                if key in self._store:
                    self._remove_key(key)
                if args:
                    return args[0]
                raise KeyError(key)

            value = self._store[key]
            self._remove_key(key)
            return value

    def keys(self) -> list:
        """Return list of non-expired keys."""
        with self._lock:
            self._purge_expired()
            return list(self._store.keys())

    def values(self) -> list:
        """Return list of non-expired values."""
        with self._lock:
            self._purge_expired()
            return list(self._store.values())

    def items(self) -> list[tuple]:
        """Return list of non-expired (key, value) tuples."""
        with self._lock:
            self._purge_expired()
            return list(self._store.items())

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._store.clear()
            self._timestamps.clear()

    def update(self, other: dict | None = None, **kwargs: Any) -> None:
        """Update from dict and/or keyword arguments."""
        if other:
            for k, v in other.items():
                self[k] = v
        for k, v in kwargs.items():
            self[k] = v

    # ── Convenience ─────────────────────────────────────────────────────

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @property
    def ttl(self) -> float:
        return self._ttl

    def stats(self) -> dict[str, Any]:
        """Return statistics about the dict state."""
        with self._lock:
            total = len(self._store)
            now = time.monotonic()
            expired = sum(
                1 for k in self._store if now - self._timestamps.get(k, 0) > self._ttl
            )
            return {
                "size": total,
                "maxsize": self._maxsize,
                "ttl": self._ttl,
                "expired_pending": expired,
                "live": total - expired,
            }

    def purge(self) -> int:
        """Force purge all expired entries. Returns count of entries removed."""
        with self._lock:
            return self._purge_expired()

    # ── Internal ────────────────────────────────────────────────────────
    # All internal methods assume the lock is already held.

    def _is_expired(self, key: Any) -> bool:
        ts = self._timestamps.get(key)
        if ts is None:
            return True
        return (time.monotonic() - ts) > self._ttl

    def _remove_key(self, key: Any) -> None:
        del self._store[key]
        self._timestamps.pop(key, None)

    def _evict_one(self) -> None:
        """Evict the oldest entry (front of OrderedDict)."""
        if self._store:
            oldest_key = next(iter(self._store))
            self._remove_key(oldest_key)

    def _purge_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        now = time.monotonic()
        expired_keys = [
            k for k in self._store if now - self._timestamps.get(k, 0) > self._ttl
        ]
        for k in expired_keys:
            self._remove_key(k)
        return len(expired_keys)
