from datetime import UTC, datetime

from flask import Blueprint, g, jsonify, request

from common.schemas.sensor import HeartbeatRequest
from controller.db.extensions import db
from controller.db.models import Sensor

from .auth import Permission, require_auth, require_signed
from .deps import PYDANTIC_AVAILABLE, logger, validate_json

bp = Blueprint("sensors", __name__)


@bp.route("/sensors", methods=["GET"])
@require_auth(Permission.MANAGE_SENSORS)
def list_sensors():
    sensors = Sensor.query.all()
    results = {}
    for s in sensors:
        results[s.id] = {
            "last_heartbeat": s.last_heartbeat.isoformat() if s.last_heartbeat else None,
            "status": s.status,
            "metrics": s.config.get("metrics", {}) if s.config else {},
            "last_seen": s.config.get("last_seen") if s.config else None,
            "last_batch": s.config.get("last_batch") if s.config else None,
        }
    return jsonify({"count": len(results), "sensors": results})


@bp.route("/sensors/heartbeat", methods=["POST"])
@require_auth(Permission.WRITE_TELEMETRY)
@require_signed()
@validate_json(HeartbeatRequest) if PYDANTIC_AVAILABLE else lambda f: f
def sensor_heartbeat():
    if PYDANTIC_AVAILABLE and hasattr(g, "validated_data"):
        if hasattr(g.validated_data, "model_dump"):
            data = g.validated_data.model_dump(mode="json")
        else:
            data = g.validated_data.dict()
    else:
        data = request.get_json() or {}

    sensor_id = data.get("sensor_id") or g.token.sensor_id or "unknown"

    sensor = Sensor.query.get(sensor_id)
    if not sensor:
        sensor = Sensor(id=sensor_id, name=sensor_id)
        db.session.add(sensor)

    sensor.last_heartbeat = datetime.now(UTC)
    sensor.status = data.get("status", "online")

    config_dict = dict(sensor.config or {})
    config_dict["metrics"] = data.get("metrics", {})
    sensor.config = config_dict

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update sensor heartbeat: {e}")

    return jsonify({"success": True, "server_time": datetime.now(UTC).isoformat()})
