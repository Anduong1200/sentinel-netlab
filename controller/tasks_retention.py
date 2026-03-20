"""
Sentinel NetLab - Data Retention Tasks

Celery periodic task that prunes old data from the database to prevent
storage exhaustion. Runs every N hours (configurable) and deletes:

- Telemetry rows older than retention_telemetry_days (default 30)
- Completed IngestJob rows older than retention_jobs_days (default 7)
- AuditLog rows older than retention_audit_days (default 90)

Environment Variables:
    RETENTION_TELEMETRY_DAYS: Days to keep telemetry (default 30)
    RETENTION_JOBS_DAYS: Days to keep completed ingest jobs (default 7)
    RETENTION_AUDIT_DAYS: Days to keep audit logs (default 90)
    RETENTION_ALERTS_DAYS: Days to keep resolved alerts (default 365)
    RETENTION_INTERVAL_HOURS: How often to run pruning (default 6)
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete

from controller.api.deps import create_app, db
from controller.celery_app import celery
from controller.db.models import AuditLog, IngestJob, Telemetry

logger = logging.getLogger(__name__)

# Initialize App Context
app = create_app()


def _get_retention_config() -> dict:
    """Load retention config from environment or use defaults."""
    import os

    return {
        "telemetry_days": int(os.getenv("RETENTION_TELEMETRY_DAYS", "30")),
        "jobs_days": int(os.getenv("RETENTION_JOBS_DAYS", "7")),
        "audit_days": int(os.getenv("RETENTION_AUDIT_DAYS", "90")),
        "alerts_days": int(os.getenv("RETENTION_ALERTS_DAYS", "365")),
    }


@celery.task(bind=True, max_retries=2, soft_time_limit=300)
def prune_old_data(self):
    """
    Prune old data from the database.

    This task is designed to be run periodically via Celery Beat.
    It deletes data older than the configured retention periods.
    """
    config = _get_retention_config()
    now = datetime.now(UTC)

    with app.app_context():
        total_deleted = 0

        # 1. Prune old telemetry
        try:
            telemetry_cutoff = now - timedelta(days=config["telemetry_days"])
            result = db.session.execute(
                delete(Telemetry).where(Telemetry.ingested_at < telemetry_cutoff)
            )
            telemetry_deleted = result.rowcount
            db.session.commit()
            total_deleted += telemetry_deleted
            logger.info(
                f"Retention: pruned {telemetry_deleted} telemetry rows "
                f"(older than {config['telemetry_days']} days)"
            )
        except Exception as e:
            db.session.rollback()
            logger.error(f"Retention: failed to prune telemetry: {e}")

        # 2. Prune completed ingest jobs
        try:
            jobs_cutoff = now - timedelta(days=config["jobs_days"])
            result = db.session.execute(
                delete(IngestJob).where(
                    and_(
                        IngestJob.status == "done",
                        IngestJob.received_at < jobs_cutoff,
                    )
                )
            )
            jobs_deleted = result.rowcount
            db.session.commit()
            total_deleted += jobs_deleted
            logger.info(
                f"Retention: pruned {jobs_deleted} completed ingest jobs "
                f"(older than {config['jobs_days']} days)"
            )
        except Exception as e:
            db.session.rollback()
            logger.error(f"Retention: failed to prune ingest jobs: {e}")

        # 3. Prune old audit logs
        try:
            audit_cutoff = now - timedelta(days=config["audit_days"])
            result = db.session.execute(
                delete(AuditLog).where(AuditLog.timestamp < audit_cutoff)
            )
            audit_deleted = result.rowcount
            db.session.commit()
            total_deleted += audit_deleted
            logger.info(
                f"Retention: pruned {audit_deleted} audit log entries "
                f"(older than {config['audit_days']} days)"
            )
        except Exception as e:
            db.session.rollback()
            logger.error(f"Retention: failed to prune audit logs: {e}")

        # 4. Prune old resolved alerts (keep open alerts forever)
        try:
            from controller.db.models import Alert

            alerts_cutoff = now - timedelta(days=config["alerts_days"])
            result = db.session.execute(
                delete(Alert).where(
                    and_(
                        Alert.status == "resolved",
                        Alert.created_at < alerts_cutoff,
                    )
                )
            )
            alerts_deleted = result.rowcount
            db.session.commit()
            total_deleted += alerts_deleted
            logger.info(
                f"Retention: pruned {alerts_deleted} resolved alerts "
                f"(older than {config['alerts_days']} days)"
            )
        except Exception as e:
            db.session.rollback()
            logger.error(f"Retention: failed to prune alerts: {e}")

        logger.info(f"Retention: total {total_deleted} rows pruned")
        return {
            "total_deleted": total_deleted,
            "timestamp": now.isoformat(),
        }
