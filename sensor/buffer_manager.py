"""
Sentinel NetLab - Buffer Manager
In-memory ring buffer with disk journal for telemetry batching.
"""

import os
import gzip
import json
import time
import logging
import threading
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from collections import deque
from pathlib import Path
import uuid

logger = logging.getLogger(__name__)


class BufferManager:
    """
    Manages telemetry buffering with:
    - In-memory ring buffer (bounded)
    - Disk journal for persistence (rotating)
    - Batch selection for upload
    - Drop policies on overflow
    """
    
    def __init__(
        self,
        max_memory_items: int = 10000,
        storage_path: str = "/var/lib/sentinel/journal",
        max_disk_mb: int = 100,
        drop_policy: str = "oldest"  # "oldest" or "spill_to_disk"
    ):
        """
        Initialize buffer manager.
        
        Args:
            max_memory_items: Max items in memory ring buffer
            storage_path: Path for disk journal files
            max_disk_mb: Max disk usage for journals
            drop_policy: Policy when buffer full
        """
        self.max_memory_items = max_memory_items
        self.storage_path = Path(storage_path)
        self.max_disk_bytes = max_disk_mb * 1024 * 1024
        self.drop_policy = drop_policy
        
        self._buffer: deque = deque(maxlen=max_memory_items)
        self._lock = threading.Lock()
        self._dropped_count = 0
        self._total_appended = 0
        self._batch_counter = 0
        
        # Create storage directory
        self.storage_path.mkdir(parents=True, exist_ok=True)
    
    def append(self, telemetry: Dict[str, Any]) -> bool:
        """
        Add telemetry item to buffer.
        
        Args:
            telemetry: Telemetry dict to add
            
        Returns:
            True if added, False if dropped
        """
        with self._lock:
            if len(self._buffer) >= self.max_memory_items:
                if self.drop_policy == "oldest":
                    self._buffer.popleft()
                    self._dropped_count += 1
                elif self.drop_policy == "spill_to_disk":
                    # Spill oldest batch to disk
                    self._spill_to_disk(100)
            
            self._buffer.append(telemetry)
            self._total_appended += 1
            return True
    
    def append_batch(self, telemetry_list: List[Dict[str, Any]]) -> int:
        """
        Add multiple items.
        
        Returns:
            Number of items added
        """
        added = 0
        for item in telemetry_list:
            if self.append(item):
                added += 1
        return added
    
    def get_batch(
        self,
        max_count: int = 200,
        max_bytes: int = 256 * 1024
    ) -> Optional[Dict[str, Any]]:
        """
        Get batch of items for upload.
        
        Args:
            max_count: Maximum items in batch
            max_bytes: Maximum batch size in bytes
            
        Returns:
            Batch dict with metadata and items, or None if empty
        """
        with self._lock:
            if not self._buffer:
                return None
            
            batch_items = []
            batch_size = 0
            
            while self._buffer and len(batch_items) < max_count:
                item = self._buffer[0]
                item_json = json.dumps(item)
                item_size = len(item_json.encode())
                
                if batch_size + item_size > max_bytes and batch_items:
                    break
                
                batch_items.append(self._buffer.popleft())
                batch_size += item_size
            
            if not batch_items:
                return None
            
            self._batch_counter += 1
            batch_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{self._batch_counter:06d}"
            
            return {
                'batch_id': batch_id,
                'batch_timestamp': datetime.now(timezone.utc).isoformat(),
                'item_count': len(batch_items),
                'items': batch_items
            }
    
    def peek_batch(self, max_count: int = 200) -> List[Dict[str, Any]]:
        """
        Peek at items without removing.
        """
        with self._lock:
            items = list(self._buffer)[:max_count]
            return items
    
    def flush_to_disk(self) -> Optional[str]:
        """
        Write current buffer to disk journal.
        
        Returns:
            Journal file path or None if empty
        """
        with self._lock:
            if not self._buffer:
                return None
            
            items = list(self._buffer)
            self._buffer.clear()
        
        return self._write_journal(items)
    
    def _spill_to_disk(self, count: int) -> None:
        """Spill oldest items to disk"""
        items = []
        for _ in range(min(count, len(self._buffer))):
            items.append(self._buffer.popleft())
        
        if items:
            self._write_journal(items)
    
    def _write_journal(self, items: List[Dict]) -> str:
        """Write items to gzipped journal file"""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        unique = uuid.uuid4().hex[:8]
        filename = f"journal_{timestamp}_{unique}.json.gz"
        filepath = self.storage_path / filename
        
        try:
            data = json.dumps({
                'created': datetime.now(timezone.utc).isoformat(),
                'count': len(items),
                'items': items
            }).encode()
            
            with gzip.open(filepath, 'wb') as f:
                f.write(data)
            
            # Enforce disk limit
            self._cleanup_old_journals()
            
            logger.info(f"Written journal: {filename} ({len(items)} items)")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Failed to write journal: {e}")
            return ""
    
    def load_pending_journals(self) -> List[Dict]:
        """
        Load all pending journal files.
        
        Returns:
            List of batch dicts ready for upload
        """
        batches = []
        
        for jfile in sorted(self.storage_path.glob("journal_*.json.gz")):
            try:
                with gzip.open(jfile, 'rb') as f:
                    data = json.loads(f.read().decode())
                    batches.append({
                        'batch_id': jfile.stem,
                        'source_file': str(jfile),
                        'items': data.get('items', [])
                    })
            except Exception as e:
                logger.error(f"Failed to load journal {jfile}: {e}")
        
        return batches
    
    def delete_journal(self, filepath: str) -> bool:
        """Delete journal file after successful upload"""
        try:
            os.remove(filepath)
            return True
        except Exception as e:
            logger.error(f"Failed to delete journal: {e}")
            return False
    
    def _cleanup_old_journals(self) -> None:
        """Remove oldest journals if over disk limit"""
        total_size = 0
        files = []
        
        for jfile in self.storage_path.glob("journal_*.json.gz"):
            try:
                size = jfile.stat().st_size
                total_size += size
                files.append((jfile, jfile.stat().st_mtime, size))
            except Exception:
                pass
        
        # Sort by modification time (oldest first)
        files.sort(key=lambda x: x[1])
        
        while total_size > self.max_disk_bytes and files:
            oldest_file, _, size = files.pop(0)
            try:
                oldest_file.unlink()
                total_size -= size
                logger.info(f"Cleaned up old journal: {oldest_file.name}")
            except Exception:
                pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get buffer statistics"""
        with self._lock:
            buffer_size = len(self._buffer)
        
        # Calculate disk usage
        disk_usage = 0
        journal_count = 0
        for jfile in self.storage_path.glob("journal_*.json.gz"):
            try:
                disk_usage += jfile.stat().st_size
                journal_count += 1
            except Exception:
                pass
        
        return {
            'buffer_current_size': buffer_size,
            'buffer_max_size': self.max_memory_items,
            'buffer_occupancy_pct': (buffer_size / self.max_memory_items) * 100,
            'total_appended': self._total_appended,
            'dropped_count': self._dropped_count,
            'batch_counter': self._batch_counter,
            'journal_count': journal_count,
            'journal_disk_bytes': disk_usage,
            'journal_disk_mb': disk_usage / (1024 * 1024)
        }
