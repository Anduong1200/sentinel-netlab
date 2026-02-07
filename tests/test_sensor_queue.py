
import os
import sqlite3
import time
import unittest
import shutil
from tempfile import mkdtemp

from sensor.queue import SqliteQueue

class TestSqliteQueue(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "spool_test.db")
        self.queue = SqliteQueue(db_path=self.db_path)

    def tearDown(self):
        self.queue.close()
        shutil.rmtree(self.tmp_dir)

    def test_push_pop_ack(self):
        """Test the standard lifecycle: Push -> Pending -> Ack (Delete)"""
        batch_id = "test-01"
        payload = {"foo": "bar"}
        
        # 1. Push
        success = self.queue.push(payload, batch_id)
        self.assertTrue(success)
        
        # Verify in DB
        stats = self.queue.stats()
        self.assertEqual(stats["queued"], 1)
        
        # 2. Get Pending (Inflight)
        entry = self.queue.get_pending()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.batch_id, batch_id)
        self.assertEqual(entry.payload, payload)
        
        # Verify state
        stats = self.queue.stats()
        self.assertEqual(stats["queued"], 0)
        self.assertEqual(stats["inflight"], 1)
        
        # 3. Ack (Delete)
        self.queue.ack(batch_id)
        
        # Verify gone
        stats = self.queue.stats()
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["inflight"], 0)

    def test_nack_retry(self):
        """Test NACK mechanism and backoff"""
        batch_id = "test-retry"
        self.queue.push({"data": 1}, batch_id)
        
        # 1. Get
        entry = self.queue.get_pending()
        self.assertIsNotNone(entry)
        
        # 2. Nack
        self.queue.nack(batch_id, "Simulated Error")
        
        # Verify state: Queued again?
        stats = self.queue.stats()
        # Should be queued but with next_attempt_at in future
        self.assertEqual(stats["total"], 1)
        
        # 3. Get again (should be None due to backoff)
        entry_retry = self.queue.get_pending()
        self.assertIsNone(entry_retry)
        
        # Manually force next_attempt_at in DB for test
        with self.queue._lock:
            self.queue._get_conn().execute(
                "UPDATE spool SET next_attempt_at = 0 WHERE batch_id = ?", 
                (batch_id,)
            )
            self.queue._get_conn().commit()
            
        # 4. Get again (should be available)
        entry_retry = self.queue.get_pending()
        self.assertIsNotNone(entry_retry)
        self.assertEqual(entry_retry.attempts, 1)

    def test_recover_stuck_inflight(self):
        """Test recovery of crashed inflight items"""
        batch_id = "test-crash"
        self.queue.push({"data": "important"}, batch_id)
        
        # 1. Get (Inflight)
        self.queue.get_pending()
        
        # 2. Simulate Crash (Close and Re-open)
        self.queue.close()
        
        # Re-open
        new_queue = SqliteQueue(db_path=self.db_path)
        
        # Verify it was recovered to Queued
        stats = new_queue.stats()
        self.assertEqual(stats["queued"], 1)
        self.assertEqual(stats["inflight"], 0)
        
        # Can get it again
        entry = new_queue.get_pending()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.batch_id, batch_id)
        
        new_queue.close()

if __name__ == "__main__":
    unittest.main()
