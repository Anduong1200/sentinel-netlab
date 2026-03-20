"""
Sentinel NetLab - Unit Tests for TTLDict

Tests the TTL-based eviction dictionary used by edge detectors
to prevent OOM on resource-constrained devices.
"""

import threading
import time

import pytest

from common.ttl_dict import TTLDict


class TestTTLDictBasic:
    """Core dictionary operations."""

    def test_basic_set_get(self):
        d = TTLDict(maxsize=100, ttl=60)
        d["key1"] = "value1"
        assert d["key1"] == "value1"

    def test_get_missing_key_raises(self):
        d = TTLDict(maxsize=100, ttl=60)
        with pytest.raises(KeyError):
            _ = d["nonexistent"]

    def test_get_with_default(self):
        d = TTLDict(maxsize=100, ttl=60)
        assert d.get("missing") is None
        assert d.get("missing", "default") == "default"

    def test_contains(self):
        d = TTLDict(maxsize=100, ttl=60)
        d["x"] = 42
        assert "x" in d
        assert "y" not in d

    def test_delete(self):
        d = TTLDict(maxsize=100, ttl=60)
        d["key"] = "val"
        del d["key"]
        assert "key" not in d

    def test_delete_missing_raises(self):
        d = TTLDict(maxsize=100, ttl=60)
        with pytest.raises(KeyError):
            del d["nope"]

    def test_len(self):
        d = TTLDict(maxsize=100, ttl=60)
        for i in range(10):
            d[f"k{i}"] = i
        assert len(d) == 10

    def test_clear(self):
        d = TTLDict(maxsize=100, ttl=60)
        for i in range(10):
            d[f"k{i}"] = i
        d.clear()
        assert len(d) == 0

    def test_update(self):
        d = TTLDict(maxsize=100, ttl=60)
        d.update({"a": 1, "b": 2})
        assert d["a"] == 1
        assert d["b"] == 2

    def test_keys_values_items(self):
        d = TTLDict(maxsize=100, ttl=60)
        d["a"] = 1
        d["b"] = 2
        assert set(d.keys()) == {"a", "b"}
        assert set(d.values()) == {1, 2}
        assert set(d.items()) == {("a", 1), ("b", 2)}

    def test_setdefault(self):
        d = TTLDict(maxsize=100, ttl=60)
        val = d.setdefault("x", [])
        assert val == []
        val.append(1)
        d["x"] = val  # re-set to refresh
        assert d["x"] == [1]

    def test_pop(self):
        d = TTLDict(maxsize=100, ttl=60)
        d["k"] = "v"
        assert d.pop("k") == "v"
        assert d.pop("k", "default") == "default"

    def test_pop_missing_raises(self):
        d = TTLDict(maxsize=100, ttl=60)
        with pytest.raises(KeyError):
            d.pop("nope")

    def test_iter(self):
        d = TTLDict(maxsize=100, ttl=60)
        d["a"] = 1
        d["b"] = 2
        assert set(d) == {"a", "b"}


class TestTTLDictExpiration:
    """TTL-based expiration behavior."""

    def test_expired_key_raises_keyerror(self):
        d = TTLDict(maxsize=100, ttl=0.05)  # 50ms TTL
        d["key"] = "value"
        time.sleep(0.1)
        with pytest.raises(KeyError):
            _ = d["key"]

    def test_expired_key_get_returns_default(self):
        d = TTLDict(maxsize=100, ttl=0.05)
        d["key"] = "value"
        time.sleep(0.1)
        assert d.get("key") is None
        assert d.get("key", "fallback") == "fallback"

    def test_expired_key_not_in_contains(self):
        d = TTLDict(maxsize=100, ttl=0.05)
        d["key"] = "value"
        time.sleep(0.1)
        assert "key" not in d

    def test_len_excludes_expired(self):
        d = TTLDict(maxsize=100, ttl=0.05)
        d["a"] = 1
        d["b"] = 2
        time.sleep(0.1)
        assert len(d) == 0

    def test_purge_removes_expired(self):
        d = TTLDict(maxsize=100, ttl=0.05)
        for i in range(10):
            d[f"k{i}"] = i
        time.sleep(0.1)
        removed = d.purge()
        assert removed == 10
        assert len(d) == 0

    def test_items_skips_expired(self):
        d = TTLDict(maxsize=100, ttl=0.05)
        d["old"] = 1
        time.sleep(0.1)
        d["new"] = 2
        assert d.items() == [("new", 2)]

    def test_refresh_on_set(self):
        """Re-setting a key should refresh its TTL."""
        d = TTLDict(maxsize=100, ttl=0.1)
        d["key"] = "v1"
        time.sleep(0.06)
        d["key"] = "v2"  # refresh
        time.sleep(0.06)
        # Should still be alive (0.06 < 0.1 TTL)
        assert d["key"] == "v2"


class TestTTLDictMaxSize:
    """Max-size eviction behavior."""

    def test_maxsize_evicts_oldest(self):
        d = TTLDict(maxsize=3, ttl=600)
        d["a"] = 1
        d["b"] = 2
        d["c"] = 3
        d["d"] = 4  # should evict "a"
        assert "a" not in d
        assert d["d"] == 4
        assert len(d) == 3

    def test_maxsize_preserves_newest(self):
        d = TTLDict(maxsize=5, ttl=600)
        for i in range(20):
            d[f"k{i}"] = i
        assert len(d) == 5
        # Last 5 should be present
        for i in range(15, 20):
            assert d[f"k{i}"] == i

    def test_maxsize_one(self):
        d = TTLDict(maxsize=1, ttl=600)
        d["a"] = 1
        d["b"] = 2
        assert "a" not in d
        assert d["b"] == 2

    def test_invalid_maxsize(self):
        with pytest.raises(ValueError):
            TTLDict(maxsize=0, ttl=60)

    def test_invalid_ttl(self):
        with pytest.raises(ValueError):
            TTLDict(maxsize=100, ttl=-1)

    def test_ttl_zero_no_expiration(self):
        """ttl=0 should disable expiration."""
        d = TTLDict(maxsize=100, ttl=0)
        d["key"] = "value"
        time.sleep(0.1)
        assert "key" in d
        assert d["key"] == "value"
        assert d.get("key") == "value"
        assert len(d) == 1


class TestTTLDictStats:
    """Stats reporting."""

    def test_stats_empty(self):
        d = TTLDict(maxsize=100, ttl=60)
        stats = d.stats()
        assert stats["size"] == 0
        assert stats["maxsize"] == 100
        assert stats["ttl"] == 60
        assert stats["live"] == 0

    def test_stats_with_entries(self):
        d = TTLDict(maxsize=100, ttl=60)
        d["a"] = 1
        d["b"] = 2
        stats = d.stats()
        assert stats["size"] == 2
        assert stats["live"] == 2
        assert stats["expired_pending"] == 0

    def test_stats_with_expired(self):
        d = TTLDict(maxsize=100, ttl=0.05)
        d["a"] = 1
        time.sleep(0.1)
        d["b"] = 2  # still alive
        stats = d.stats()
        assert stats["expired_pending"] == 1
        assert stats["live"] == 1


class TestTTLDictThreadSafety:
    """Concurrent access should not cause errors."""

    def test_concurrent_writes(self):
        d = TTLDict(maxsize=1000, ttl=60)
        errors = []

        def writer(start):
            try:
                for i in range(100):
                    d[f"t{start}_{i}"] = i
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(d) <= 1000

    def test_concurrent_read_write(self):
        d = TTLDict(maxsize=500, ttl=60)
        errors = []

        def writer():
            try:
                for i in range(200):
                    d[f"w_{i}"] = i
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for i in range(200):
                    d.get(f"w_{i}")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
