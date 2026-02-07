import os
import time

from sensor.queue import SqliteQueue

DB_PATH = "data/test_spool.db"
if os.path.exists("data"):
    # Clean up previous test
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            os.remove(DB_PATH + "-wal")
            os.remove(DB_PATH + "-shm")
        except:
            pass
else:
    os.makedirs("data")


def test_spool():
    print("Initializing Queue...")
    q = SqliteQueue(db_path=DB_PATH)

    # 1. Push
    print("Pushing batch-1...")
    q.push({"val": 1}, "batch-1")

    stats = q.stats()
    print(f"Stats after push: {stats}")
    assert stats["queued"] == 1

    # 2. Get Pending
    print("Getting pending...")
    item = q.get_pending()
    assert item is not None
    assert item.batch_id == "batch-1"
    print(f"Got item: {item.batch_id}")

    stats = q.stats()
    assert stats["inflight"] == 1
    assert stats["queued"] == 0

    # 3. Get Pending again (should be empty)
    item2 = q.get_pending()
    assert item2 is None
    print("Get pending again: None (Correct)")

    # 4. NACK (Simulate failure)
    print("Nacking batch-1...")
    q.nack("batch-1", "Simulated network error")

    stats = q.stats()
    assert stats["inflight"] == 0
    assert stats["queued"] == 1

    # 5. Get Pending (should be backoff)
    item3 = q.get_pending()
    if item3 is None:
        print("Get pending (backoff): None (Correct)")
    else:
        print(f"Error: Got item during backoff! {item3}")

    # 6. Simulate time travel (Wait 2s - backoff is ~1-2s for 1st retry? Base=1.0)
    # _calculate_backoff(1) -> 1.0 * (2^0) * jitter(0.5-1.5) -> 0.5 - 1.5s
    print("Waiting 2s...")
    time.sleep(2.1)

    item4 = q.get_pending()
    assert item4 is not None
    assert item4.batch_id == "batch-1"
    assert item4.attempts == 1
    print(f"Got item after backoff: {item4.batch_id}, attempts={item4.attempts}")

    # 7. ACK
    print("Acking batch-1...")
    q.ack("batch-1")

    stats = q.stats()
    assert stats["total"] == 0
    print("Stats after ACK:", stats)

    q.close()
    print("Test Passed!")


if __name__ == "__main__":
    test_spool()
