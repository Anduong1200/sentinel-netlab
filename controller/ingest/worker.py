import logging
import signal
import time
from datetime import UTC, datetime

from controller.api.deps import create_app, db
from controller.db.models import Telemetry
from controller.ingest.queue import IngestQueue
from controller.metrics import WORKER_PROCESSED

# Setup Logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


class IngestWorker:
    def __init__(self, worker_id: str = "worker-1", poll_interval: float = 1.0):
        self.worker_id = worker_id
        self.poll_interval = poll_interval
        self.running = True
        self.app = create_app()

    def start(self):
        logger.info(f"Starting IngestWorker {self.worker_id}...")

        # Signal Handlers
        signal.signal(signal.SIGINT, self._handle_exit)
        signal.signal(signal.SIGTERM, self._handle_exit)

        with self.app.app_context():
            while self.running:
                try:
                    self._loop()
                except Exception as e:
                    logger.error(f"Worker loop crashed: {e}", exc_info=True)
                    time.sleep(5)  # Backoff if DB dead

    def _handle_exit(self, signum, frame):
        logger.info("Shutdown signal received. Stopping...")
        self.running = False

    def _loop(self):
        # 1. Claim Jobs
        jobs = IngestQueue.claim_jobs(self.worker_id, limit=50)

        if not jobs:
            time.sleep(self.poll_interval)
            return

        logger.info(f"Claimed {len(jobs)} jobs.")

        for job in jobs:
            self._process_job(job)

    def _process_job(self, job):
        try:
            logger.debug(f"Processing Job {job.job_id} ({job.sensor_id})")

            payload = job.payload or {}
            items = payload.get("items", [])

            # Bulk Insert Logic (P1 Scale: bulk_insert_mappings)
            telemetry_mappings = []
            for item in items:
                # Standardize timestamp
                ts_str = item.get("timestamp")
                ts = datetime.fromisoformat(ts_str) if ts_str else datetime.now(UTC)

                # Dict not Object
                t = {
                    "sensor_id": job.sensor_id,
                    "batch_id": job.job_id,
                    "timestamp": ts,
                    "ingested_at": datetime.now(UTC),
                    "bssid": item.get("bssid"),
                    "ssid": item.get("ssid"),
                    "channel": item.get("channel"),
                    "rssi_dbm": item.get("rssi_dbm"),
                    "frequency_mhz": item.get("frequency_mhz"),
                    "security": item.get("security"),
                    "raw_data": item,
                    # capabilities optional if needed
                }
                telemetry_mappings.append(t)

            if telemetry_mappings:
                db.session.bulk_insert_mappings(Telemetry, telemetry_mappings)

            # Commit processing
            IngestQueue.ack_job(
                job.job_id
            )  # This commits the transaction (ack modifies job status)

            # Separate commit for telemetry if ack logic didn't commit everything?
            # IngestQueue.ack_job uses db.session.commit() which commits EVERYTHING in session.
            # So the add_all above is committed there. Correct.

            logger.info(f"Job {job.job_id} Done. ({len(items)} items)")
            WORKER_PROCESSED.labels(result="success").inc()

        except Exception as e:
            logger.error(f"Job {job.job_id} Failed: {e}")
            db.session.rollback()
            IngestQueue.fail_job(job.job_id, str(e))
            WORKER_PROCESSED.labels(result="retry").inc()


if __name__ == "__main__":
    worker = IngestWorker()
    worker.start()
