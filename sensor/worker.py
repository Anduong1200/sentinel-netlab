"""
Sentinel NetLab - Transport Worker
Background worker that consumes from persistent spool (queue) and uploads to controller.

Features:
- Producer-Consumer pattern (decoupled from capture)
- Reliable delivery with persistent state
- Graceful shutdown handling
"""

import logging
import signal
import threading
import time
from collections.abc import Callable
from typing import Any

from .queue import SpoolEntry, SqliteQueue
from .transport import TransportClient

logger = logging.getLogger(__name__)


class TransportWorker:
    """
    Background worker that uploads batches from the persistent spool.

    Runs in a separate thread and handles:
    - Consuming batches from SqliteQueue (get_pending)
    - Uploading via TransportClient
    - ACK/NACK based on response
    """

    def __init__(
        self,
        queue: SqliteQueue,
        client: TransportClient,
        poll_interval: float = 1.0,
        on_success: Callable[[str, dict], None] | None = None,
        on_failure: Callable[[str, str], None] | None = None,
    ):
        """
        Initialize the worker.

        Args:
            queue: Persistent queue to consume from
            client: Transport client for uploads
            poll_interval: Seconds between queue polls when idle
            on_success: Callback(batch_id, response) on successful upload
            on_failure: Callback(batch_id, error) on failed upload
        """
        self.queue = queue
        self.client = client
        self.poll_interval = poll_interval
        self.on_success = on_success
        self.on_failure = on_failure

        self._running = False
        self._thread: threading.Thread | None = None
        self._shutdown_event = threading.Event()
        self._consecutive_failures = 0

        # Stats
        self._uploads_attempted = 0
        self._uploads_success = 0
        self._uploads_failed = 0
        self._last_upload_time: float | None = None

    def start(self) -> None:
        """Start the worker thread."""
        if self._running:
            logger.warning("Worker already running")
            return

        self._running = True
        self._shutdown_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Transport worker started")

    def stop(self, timeout: float = 20.0) -> None:
        """
        Stop the worker gracefully.

        Args:
            timeout: Maximum seconds to wait for thread to stop (User req: 20s)
        """
        if not self._running:
            return

        logger.info("Stopping transport worker...")
        self._running = False
        self._shutdown_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("Worker thread did not stop cleanly")

        logger.info("Transport worker stopped")

    def _run_loop(self) -> None:
        """Main worker loop."""
        logger.info("Worker loop started")

        while self._running:
            try:
                # Check for shutdown
                if self._shutdown_event.is_set():
                    break

                # Get next pending batch (already marked inflight by queue)
                entry = self.queue.get_pending()

                if entry is None:
                    # Queue empty or all items backing off
                    # Wait before polling again
                    self._shutdown_event.wait(timeout=self.poll_interval)
                    continue

                # Attempt upload
                self._process_entry(entry)

            except Exception as e:
                logger.error(f"Worker loop error: {e}", exc_info=True)
                self._shutdown_event.wait(timeout=5.0)

        logger.info("Worker loop exited")

    def _process_entry(self, entry: SpoolEntry) -> None:
        """Process a single spool entry."""
        self._uploads_attempted += 1

        try:
            # Upload via transport client
            response = self.client.upload(entry.payload, compress=True)

            if response.get("success"):
                # Success - ACK (delete from spool)
                self.queue.ack(entry.batch_id)
                self._uploads_success += 1
                self._consecutive_failures = 0
                self._last_upload_time = time.time()

                logger.info(
                    f"Uploaded batch {entry.batch_id}: "
                    f"ack_id={response.get('ack_id')}, accepted={response.get('accepted')}"
                )

                if self.on_success:
                    self.on_success(entry.batch_id, response)

            else:
                # Failure
                error_msg = response.get("error", "Unknown error")
                self._handle_failure(entry, error_msg)

        except Exception as e:
            self._handle_failure(entry, str(e))

    def _handle_failure(self, entry: SpoolEntry, error: str) -> None:
        """Handle upload failure."""
        self._uploads_failed += 1
        self._consecutive_failures += 1

        # NACK - increment retry count and schedule next attempt
        self.queue.nack(entry.batch_id, error)

        logger.warning(
            f"Upload failed for batch {entry.batch_id} "
            f"(attempt {entry.attempts + 1}): {error}"
        )

        if self.on_failure:
            self.on_failure(entry.batch_id, error)

        # Add a small global backoff if failures are consecutive to avoid rapid spinning
        # if the network is down and many items are ready for initial attempt.
        # Max 1s just to be polite to CPU.
        if self._consecutive_failures > 5:
             self._shutdown_event.wait(timeout=1.0)


    def stats(self) -> dict[str, Any]:
        """Get worker statistics."""
        return {
            "running": self._running,
            "uploads_attempted": self._uploads_attempted,
            "uploads_success": self._uploads_success,
            "uploads_failed": self._uploads_failed,
            "consecutive_failures": self._consecutive_failures,
            "last_upload_time": self._last_upload_time,
            "queue_stats": self.queue.stats(),
        }

    def is_healthy(self) -> bool:
        """Check if worker is healthy."""
        # Unhealthy if strictly stuck?
        # Actually, with persistent queue, "unhealthy" is weird.
        # Maybe if thread died?
        return self._running


class GracefulShutdown:
    """
    Context manager for graceful shutdown handling.
    """

    def __init__(self, worker: TransportWorker, stop_method: Callable | None = None):
        self.worker = worker
        self.stop_method = stop_method
        self.running = True
        self._original_handlers: dict[int, Any] = {}

    def __enter__(self):
        # Register signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                self._original_handlers[sig] = signal.signal(sig, self._handle_signal)
            except (ValueError, OSError):
                pass
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.stop_method:
             self.stop_method()
        else:
             self.worker.stop()

        # Restore original handlers
        for sig, handler in self._original_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass

        return False

    def _handle_signal(self, signum, frame):
        """Handle shutdown signal."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown")
        self.running = False
        if self.stop_method:
             self.stop_method()
        else:
             self.worker.stop()

