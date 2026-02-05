"""
Sensor Monitor: Background thread for System and Spool metrics.
"""

import threading
import time
import logging
from typing import Any

import psutil

from common.observability.metrics import create_gauge
from sensor.queue import SqliteQueue

logger = logging.getLogger(__name__)

# Metrics
SPOOL_BACKLOG = create_gauge("spool_backlog_batches", "Batches in spool", ["sensor_id"])
SPOOL_BYTES = create_gauge("spool_backlog_bytes", "Bytes in spool", ["sensor_id"])
SYSTEM_CPU = create_gauge("system_cpu_usage", "CPU Usage Percent", ["sensor_id"])
SYSTEM_MEMORY = create_gauge("system_memory_usage", "Memory Usage Percent", ["sensor_id"])


class SensorMonitor:
    """
    Monitors system health and queue status.
    Updates Prometheus metrics periodically.
    """

    def __init__(self, sensor_id: str, queue: SqliteQueue, interval: int = 15):
        self.sensor_id = sensor_id
        self.queue = queue
        self.interval = interval
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="SensorMonitor")
        self._thread.start()
        logger.info("Sensor monitor started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        while self._running:
            try:
                # 1. System Metrics
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
                
                SYSTEM_CPU.labels(sensor_id=self.sensor_id).set(cpu)
                SYSTEM_MEMORY.labels(sensor_id=self.sensor_id).set(mem)

                # 2. Spool Metrics
                q_stats = self.queue.stats()
                # stats returns {'total':..., 'queued':..., 'inflight':..., 'bytes':...}
                # P0 wants "backlog size" -> 'queued' + 'inflight' (total items waiting)
                # But typically 'backlog' means what is waiting to be sent. Inflight is also waiting for ACK.
                backlog = q_stats.get("total", 0) # total in table
                bytes_total = q_stats.get("bytes", 0)

                SPOOL_BACKLOG.labels(sensor_id=self.sensor_id).set(backlog)
                SPOOL_BYTES.labels(sensor_id=self.sensor_id).set(bytes_total)

            except Exception as e:
                logger.error(f"Monitor error: {e}")
            
            time.sleep(self.interval)
