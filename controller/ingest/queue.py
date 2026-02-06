
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, select, update
from sqlalchemy.exc import IntegrityError

from controller.api.deps import db
from controller.api.models import IngestJob


@dataclass
class QueueStats:
    queue_depth: int
    lag_seconds: float

class IngestQueue:
    """DB-Backed Queue for Ingest Jobs"""

    @staticmethod
    def enqueue(sensor_id: str, batch_id: str, payload: dict) -> str:
        """
        Enqueue a batch for processing.
        Returns batch_id if successful (or if already exists).
        """
        # 1. Idempotency Check (Optimistic)
        job = db.session.get(IngestJob, batch_id)
        if job:
            return job.job_id

        # 2. Insert
        try:
            job = IngestJob(
                job_id=batch_id,
                sensor_id=sensor_id,
                status="queued",
                payload=payload,
                attempts=0,
                next_attempt_at=datetime.now(UTC)
            )
            db.session.add(job)
            db.session.commit()
            return batch_id
        except IntegrityError:
            db.session.rollback()
            # Race condition, it exists now
            return batch_id
        except Exception as e:
            db.session.rollback()
            raise e

    @staticmethod
    def claim_jobs(worker_id: str, limit: int = 10) -> list[IngestJob]:
        """
        Claim pending jobs for a worker.
        Uses 'SKIP LOCKED' via simple status update for now (SQLite compat).
        For Postgres P1 Scale, we'd use SELECT ... FOR UPDATE SKIP LOCKED.
        """
        now = datetime.now(UTC)

        # Simple update-returning fetch for now (P1 basic)
        # Find candidate jobs
        candidates = db.session.scalars(
            select(IngestJob)
            .where(
                and_(
                    IngestJob.status == "queued",
                    IngestJob.next_attempt_at <= now
                )
            )
            .limit(limit)
            .with_for_update(skip_locked=True) # Postgres only feature usually
        ).all()

        claimed = []
        for job in candidates:
            job.status = "processing"
            job.attempts += 1
            # job.worker_id = worker_id # If we added column
            claimed.append(job)

        try:
            db.session.commit()
            return claimed
        except Exception:
            db.session.rollback()
            return []

    @staticmethod
    def ack_job(job_id: str):
        """Mark job as done."""
        db.session.execute(
            update(IngestJob)
            .where(IngestJob.job_id == job_id)
            .values(status="done", payload=None) # Clear payload to save space? Retention policy handles rows.
        )
        db.session.commit()

    @staticmethod
    def fail_job(job_id: str, error: str):
        """Mark job as failed with backoff."""
        # Exponential backoff: 5s, 30s, 5m, 1h
        # Simplified: linear 10s for now
        next_time = datetime.now(UTC) + timedelta(seconds=10)

        db.session.execute(
            update(IngestJob)
            .where(IngestJob.job_id == job_id)
            .values(
                status="queued", # Retry
                error_msg=error,
                next_attempt_at=next_time
            )
        )
        db.session.commit()

    @staticmethod
    def get_stats() -> QueueStats:
        """Get estimate of queue depth."""
        # This can be slow on count(*), so we might want estimate.
        # But for backpressure < 1000 items, exact count is fast enough.

        count = db.session.scalar(
            select(db.func.count()).select_from(IngestJob).where(IngestJob.status == "queued")
        )

        # Lag: Difference between now and oldest queued item received_at
        oldest = db.session.scalar(
             select(IngestJob.received_at)
             .where(IngestJob.status == "queued")
             .order_by(IngestJob.received_at.asc())
             .limit(1)
        )

        lag = 0.0
        if oldest:
             lag = (datetime.now(UTC) - oldest).total_seconds()

        return QueueStats(queue_depth=count or 0, lag_seconds=lag)
