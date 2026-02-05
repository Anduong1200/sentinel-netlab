import logging
from datetime import UTC, datetime

from sqlalchemy.exc import IntegrityError
from celery.exceptions import SoftTimeLimitExceeded

from controller.celery_app import celery
from controller.api.deps import create_app, db
from controller.api.models import IngestBatch, Telemetry

logger = logging.getLogger(__name__)

# Initialize App Context (Lazy load per worker process)
app = create_app()

@celery.task(bind=True, max_retries=3, soft_time_limit=30)
def process_telemetry_batch(self, batch_id: str, sensor_id: str, items: list[dict]):
    """
    Process a telemetry batch asynchronously.
    """
    with app.app_context():
        logger.info(f"Processing batch {batch_id} for {sensor_id} ({len(items)} items)")
        
        # 1. Idempotency Check (Persistent)
        existing_batch = db.session.get(IngestBatch, batch_id)
        if existing_batch:
            logger.info(f"Idempotency hit (Worker): {batch_id}")
            return {"status": "duplicate", "accepted": existing_batch.item_count}

        # 2. Register Batch (Lock)
        try:
            new_batch = IngestBatch(
                batch_id=batch_id,
                sensor_id=sensor_id,
                item_count=len(items),
                status="processing"
            )
            db.session.add(new_batch)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            logger.info(f"Idempotency hit (race/worker): {batch_id}")
            # If it exists now, it's a duplicate
            return {"status": "duplicate", "accepted": len(items)}
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to register batch: {e}")
            raise self.retry(exc=e, countdown=5)

        # 3. Process Items
        accepted = 0
        try:
            for item in items:
                # Enrich happens here (or could happen in API, but better here to offload CPU)
                 # Note: _ingested_at should ideally be "now" or preserved if passed from API?
                 # Implementation in API used datetime.now(UTC), so we do the same here.
                item["_ingested_at"] = datetime.now(UTC).isoformat()
                
                # Align with Schema: Extract indexed fields
                db_item = Telemetry(
                    sensor_id=sensor_id, 
                    batch_id=batch_id,
                    timestamp=datetime.fromisoformat(item.get("timestamp")) if item.get("timestamp") else datetime.now(UTC),
                    
                    bssid=item.get("bssid"),
                    ssid=item.get("ssid"),
                    channel=item.get("channel"),
                    rssi_dbm=item.get("rssi_dbm"),
                    frequency_mhz=item.get("frequency_mhz"), # Optional if exists
                    security=item.get("security"),
                    
                    raw_data=item # Store full payload
                )
                db.session.add(db_item)
                accepted += 1
            
            # Update batch status
            new_batch.status = "processed"
            db.session.commit()
            
            logger.info(f"Batch {batch_id} processed successfully ({accepted} items)")
            return {"status": "success", "accepted": accepted}

        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to process items for {batch_id}: {e}")
            # Mark batch as failed? Or just retry?
            # If we retry, we need to handle partial insertions?
            # Telemetry inserts are atomic with the transaction above.
            raise self.retry(exc=e, countdown=10)


@celery.task(bind=True, max_retries=3, soft_time_limit=10)
def process_alert(self, alert_data: dict, sensor_id: str):
    """
    Process an alert asynchronously.
    """
    from controller.api.models import DBAlert
    from common.observability.metrics import create_counter

    ALERTS_EMITTED_WORKER = create_counter(
        "alerts_emitted_total", "Alerts emissions", ["severity", "detector"]
    )

    with app.app_context():
        alert_id = alert_data.get("id")
        logger.info(f"Processing alert {alert_id} for {sensor_id}")
        
        try:
            alert = DBAlert(
                id=alert_id,
                sensor_id=sensor_id,
                alert_type=alert_data.get("alert_type"),
                severity=alert_data.get("severity"),
                title=alert_data.get("title"),
                description=alert_data.get("description"),
                evidence=alert_data.get("evidence"),
            )
            
            db.session.add(alert)
            db.session.commit()
            
            # Metrics (Note: PromMetrics in multiprocess worker is tricky, but we try)
            ALERTS_EMITTED_WORKER.labels(
                severity=alert.severity or "unknown",
                detector=alert.alert_type or "unknown"
            ).inc()
            
            logger.info(f"Alert {alert_id} persisted")
            return {"status": "success", "alert_id": alert_id}
            
        except IntegrityError:
            db.session.rollback()
            logger.info(f"Duplicate alert: {alert_id}")
            return {"status": "duplicate", "alert_id": alert_id}
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to process alert {alert_id}: {e}")
            raise self.retry(exc=e, countdown=5)
