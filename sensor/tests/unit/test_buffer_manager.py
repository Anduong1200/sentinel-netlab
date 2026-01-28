"""
Sentinel NetLab - Unit Tests for Buffer Manager
Tests buffer_manager.py ring buffer and journal.
"""

import shutil
import tempfile
from pathlib import Path

import pytest

try:
    from buffer_manager import BufferManager
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from buffer_manager import BufferManager


class TestBufferManager:
    """Unit tests for BufferManager"""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests"""
        path = tempfile.mkdtemp()
        yield path
        shutil.rmtree(path, ignore_errors=True)

    @pytest.fixture
    def buffer(self, temp_dir):
        return BufferManager(
            max_memory_items=100,
            storage_path=temp_dir,
            max_disk_mb=10
        )

    def test_append_and_get_batch_simple(self, buffer):
        """Append N items, get_batch returns first N"""
        # Append items
        for i in range(10):
            buffer.append({'id': i, 'data': f'item_{i}'})

        # Get batch
        batch = buffer.get_batch(max_count=5)

        assert batch is not None
        assert batch['item_count'] == 5
        assert len(batch['items']) == 5
        assert batch['items'][0]['id'] == 0

    def test_ring_buffer_overflow_drop_oldest(self, temp_dir):
        """When capacity exceeded, oldest dropped per policy"""
        buffer = BufferManager(
            max_memory_items=5,
            storage_path=temp_dir,
            drop_policy="oldest"
        )

        # Append more than capacity
        for i in range(10):
            buffer.append({'id': i})

        # Check stats
        stats = buffer.get_stats()
        assert stats['buffer_current_size'] == 5
        assert stats['dropped_count'] == 5

        # Get batch - should have newest items
        batch = buffer.get_batch(max_count=10)
        assert len(batch['items']) == 5
        # First item should be id=5 (oldest remaining)
        assert batch['items'][0]['id'] == 5

    def test_spill_to_disk_and_replay(self, temp_dir):
        """Persisted batch replayed after flush"""
        buffer = BufferManager(
            max_memory_items=100,
            storage_path=temp_dir
        )

        # Add items
        for i in range(20):
            buffer.append({'id': i})

        # Flush to disk
        journal_path = buffer.flush_to_disk()
        assert journal_path is not None
        assert Path(journal_path).exists()

        # Buffer should be empty
        assert buffer.get_stats()['buffer_current_size'] == 0

        # Load pending journals
        journals = buffer.load_pending_journals()
        assert len(journals) == 1
        assert len(journals[0]['items']) == 20

    def test_get_batch_respects_max_count(self, buffer):
        """get_batch respects max_count parameter"""
        for i in range(50):
            buffer.append({'id': i})

        batch = buffer.get_batch(max_count=10)
        assert len(batch['items']) == 10

    def test_get_batch_respects_max_bytes(self, buffer):
        """get_batch respects max_bytes parameter"""
        # Add items with known size
        for i in range(100):
            buffer.append({'id': i, 'data': 'x' * 100})

        # Request small batch by bytes
        batch = buffer.get_batch(max_count=100, max_bytes=500)

        # Should get fewer items due to size limit
        assert len(batch['items']) < 100

    def test_empty_buffer_returns_none(self, buffer):
        """get_batch on empty buffer returns None"""
        batch = buffer.get_batch()
        assert batch is None

    def test_batch_has_metadata(self, buffer):
        """Batch includes required metadata fields"""
        buffer.append({'test': 'data'})
        batch = buffer.get_batch()

        assert 'batch_id' in batch
        assert 'batch_timestamp' in batch
        assert 'item_count' in batch
        assert 'items' in batch

    def test_stats_accuracy(self, buffer):
        """get_stats returns accurate values"""
        for i in range(25):
            buffer.append({'id': i})

        stats = buffer.get_stats()

        assert stats['buffer_current_size'] == 25
        assert stats['total_appended'] == 25
        assert stats['dropped_count'] == 0
        assert 0 <= stats['buffer_occupancy_pct'] <= 100


class TestBufferManagerDiskCleanup:
    """Test disk cleanup policies"""

    @pytest.fixture
    def temp_dir(self):
        path = tempfile.mkdtemp()
        yield path
        shutil.rmtree(path, ignore_errors=True)

    def test_disk_cleanup_enforces_limit(self, temp_dir):
        """Old journals deleted when over disk limit"""
        # Very small disk limit
        buffer = BufferManager(
            max_memory_items=100,
            storage_path=temp_dir,
            max_disk_mb=0.001  # ~1KB limit
        )

        # Create multiple journals
        for batch in range(5):
            for i in range(100):
                buffer.append({'batch': batch, 'id': i, 'data': 'x' * 100})
            buffer.flush_to_disk()

        # Check that oldest journals were cleaned up
        journals = list(Path(temp_dir).glob("journal_*.json.gz"))
        # Some should have been deleted
        assert len(journals) < 5
