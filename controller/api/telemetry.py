import secrets
from datetime import UTC, datetime
from flask import Blueprint, jsonify, request, g
from .deps import db, config, logger, limiter, validate_json, PYDANTIC_AVAILABLE
from .auth import require_auth, require_signed, Permission, SENSOR_REGISTRY
from .models import Telemetry

from common.schemas.telemetry import TelemetryBatch  # noqa: E402

bp = Blueprint("telemetry", __name__)

@bp.route("/telemetry", methods=["POST"])
@require_auth(Permission.WRITE_TELEMETRY)
@require_signed()
@limiter.limit(config.security.token_expiry_hours) # Dynamic limit based on config? Kept from original
@validate_json(TelemetryBatch) if PYDANTIC_AVAILABLE else lambda f: f
def ingest_telemetry():
    """Batch telemetry ingestion with full validation"""
    if PYDANTIC_AVAILABLE and hasattr(g, "validated_data"):
        if hasattr(g.validated_data, "model_dump"):
            data = g.validated_data.model_dump(mode="json")
        else:
            data = g.validated_data.dict()
    else:
        data = request.get_json()

    sensor_id = data.get("sensor_id")
    items = data.get("items", [])
    batch_id = data.get("batch_id", secrets.token_hex(8))

    if g.token.sensor_id and g.token.sensor_id != sensor_id:
        return jsonify({"error": "Sensor ID mismatch"}), 403

    accepted = 0
    for item in items:
        if isinstance(item, dict):
            # Enrich
            item["_ingested_at"] = datetime.now(UTC).isoformat()

            db_item = Telemetry(sensor_id=sensor_id, batch_id=batch_id, data=item)
            db.session.add(db_item)
            accepted += 1

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"DB Commit failed: {e}")
        return jsonify({"error": "Database error"}), 500

    SENSOR_REGISTRY[sensor_id] = {
        "last_seen": datetime.now(UTC).isoformat(),
        "status": "online",
        "last_batch": batch_id,
    }

    logger.info(f"Ingested {accepted} items from {sensor_id}")

    return jsonify({"success": True, "ack_id": batch_id, "accepted": accepted})


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

            # Ensure Dashboard expects: lat, lon, ssid, risk_score
            if "gps" in net:
                net["lat"] = net["gps"].get("lat")
                net["lon"] = net["gps"].get("lon")

            networks[bssid] = net

    results = list(networks.values())
    return jsonify({"count": len(results), "networks": results})
