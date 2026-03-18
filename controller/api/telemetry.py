import secrets
from datetime import UTC, datetime

from flask import Blueprint, g, jsonify, request

from common.schemas.telemetry import TelemetryBatch  # noqa: E402
from controller.db.models import Telemetry
from controller.geo import DistributedGeoService
from controller.ingest.queue import IngestQueue
from controller.metrics import (
    BACKPRESSURE,
    INGEST_FAILURES,
    INGEST_LATENCY,
    INGEST_REQUESTS,
    INGEST_SUCCESS,
)

from .auth import Permission, require_auth, require_signed
from .deps import config, limiter, logger, validate_json

bp = Blueprint("telemetry", __name__)


@bp.route("/telemetry", methods=["POST"])
@require_auth(Permission.WRITE_TELEMETRY)
@require_signed()
@limiter.limit(config.security.rate_limit_telemetry)
@validate_json(TelemetryBatch)
@INGEST_LATENCY.time()
def ingest_telemetry():
    """Batch telemetry ingestion with full validation"""

    sensor_id = "unknown"  # Default for metrics if parsing fails early

    # 1. Parse Data
    # Handled by @validate_json decorator (including gzip)
    if not hasattr(g, "validated_data"):
        return jsonify({"error": "Validation failed internally"}), 500

    if hasattr(g.validated_data, "model_dump"):
        data = g.validated_data.model_dump(mode="json")
    else:
        data = g.validated_data.dict()

    sensor_id = data.get("sensor_id", "unknown")
    # items = data.get("items", []) # Unused
    batch_id = data.get("batch_id")

    # Fallback to header if empty in body
    if not batch_id:
        batch_id = request.headers.get("X-Idempotency-Key") or secrets.token_hex(8)

    if g.token.sensor_id and g.token.sensor_id != sensor_id:
        INGEST_REQUESTS.labels(status="403").inc()
        INGEST_FAILURES.labels(reason="sensor_mismatch").inc()
        return jsonify({"error": "Sensor ID mismatch"}), 403

    # Backpressure Check
    # Stop enqueueing if system is overloaded
    try:
        stats = IngestQueue.get_stats()
        if stats.queue_depth > 1000:  # Threshold should be in config
            logger.warning(f"Backpressure active: queue_depth={stats.queue_depth}")
            INGEST_REQUESTS.labels(status="503").inc()
            INGEST_FAILURES.labels(reason="backpressure").inc()
            BACKPRESSURE.inc()
            return (
                jsonify({"error": "System overloaded, retry later"}),
                503,
                {"Retry-After": "30"},
            )
    except Exception as e:
        logger.error(f"Failed to check queue stats: {e}")
        # Proceed with caution or fail open/closed? Fail open (try to enqueue)
        pass

    # 2. Idempotency & Enqueue (DB-Backed)
    # The queue handles idempotency internally via PK check

    try:
        ack_id, is_duplicate = IngestQueue.enqueue(sensor_id, batch_id, data)
    except Exception as e:
        logger.error(f"Failed to enqueue: {e}")
        INGEST_REQUESTS.labels(status="500").inc()
        INGEST_FAILURES.labels(reason="queue_error").inc()
        return jsonify({"error": "Internal Queue Error"}), 500

    # ... (registry update omitted for brevity, logic remains same)

    # Update Registry (Last Seen)
    try:
        from controller.db.models import Sensor
        from controller.db.extensions import db

        sensor = Sensor.query.get(sensor_id)
        if not sensor:
            sensor = Sensor(id=sensor_id, name=sensor_id)
            db.session.add(sensor)

        sensor.status = "online"
        config_dict = dict(sensor.config or {})
        config_dict["last_seen"] = datetime.now(UTC).isoformat()
        config_dict["last_batch"] = batch_id
        sensor.config = config_dict

        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to update sensor state: {e}")
        db.session.rollback()

    if is_duplicate:
        INGEST_REQUESTS.labels(status="200").inc()
        # Return batch_id as ack_id (protocol contract), not the internal scoped ID
        return jsonify(
            {"success": True, "status": "duplicate", "ack_id": batch_id}
        ), 200

    INGEST_REQUESTS.labels(status="202").inc()
    INGEST_SUCCESS.inc()
    return jsonify({"success": True, "status": "queued", "ack_id": batch_id}), 202


@bp.route("/telemetry", methods=["GET"])
@require_auth(Permission.READ_TELEMETRY)
def get_telemetry():
    limit = min(int(request.args.get("limit", 100)), 1000)
    sensor_id = request.args.get("sensor_id")

    query = Telemetry.query.order_by(Telemetry.ingested_at.desc())
    if sensor_id:
        query = query.filter_by(sensor_id=sensor_id)

    records = query.limit(limit).all()
    results = [r.data for r in records]

    return jsonify({"count": len(results), "items": results})


@bp.route("/networks", methods=["GET"])
@require_auth(Permission.READ_TELEMETRY)
def get_networks():
    """Get summarized view of recently seen networks"""
    limit = min(int(request.args.get("limit", 500)), 2000)

    # Get recent telemetry
    records = Telemetry.query.order_by(Telemetry.ingested_at.desc()).limit(limit).all()

    geo_estimates: dict[str, dict] = {}
    if config.geo.enabled:
        try:
            geo_service = DistributedGeoService(config.geo)
            geo_estimates = geo_service.estimate_by_bssid(records)
        except Exception as e:
            logger.warning(f"Geo enrichment failed: {e}")

    networks = {}
    for r in records:
        if not r.data:
            continue
        bssid = r.data.get("bssid")
        if not bssid:
            continue

        # Only keep the FIRST occurrence (which is the latest due to sort)
        if bssid not in networks:
            # Flatten/Transform for dashboard
            net = r.data.copy()
            net["sensor_id"] = r.sensor_id
            net["last_seen"] = r.ingested_at.isoformat()

            # Preserve GPS projection if present in payload
            if "gps" in net:
                net["lat"] = net["gps"].get("lat")
                net["lon"] = net["gps"].get("lon")

            # Geo enrichment from distributed controller estimation
            geo_data = geo_estimates.get(bssid)
            if geo_data:
                net["geo"] = geo_data.get("geo")
                geo_lat = geo_data.get("lat")
                geo_lon = geo_data.get("lon")
                if geo_lat is not None and geo_lon is not None:
                    net["lat"] = geo_lat
                    net["lon"] = geo_lon
                else:
                    net.setdefault("lat", geo_lat)
                    net.setdefault("lon", geo_lon)

            networks[bssid] = net

    results = list(networks.values())
    return jsonify({"count": len(results), "networks": results})
