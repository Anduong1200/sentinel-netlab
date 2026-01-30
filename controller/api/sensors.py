from datetime import UTC, datetime

from flask import Blueprint, g, jsonify, request

from common.schemas.sensor import HeartbeatRequest  # noqa: E402

from .auth import SENSOR_REGISTRY, Permission, require_auth, require_signed
from .deps import PYDANTIC_AVAILABLE, validate_json

bp = Blueprint("sensors", __name__)


@bp.route("/sensors", methods=["GET"])
@require_auth(Permission.MANAGE_SENSORS)
def list_sensors():
    return jsonify({"count": len(SENSOR_REGISTRY), "sensors": SENSOR_REGISTRY})


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

    SENSOR_REGISTRY[sensor_id] = {
        "last_heartbeat": datetime.now(UTC).isoformat(),
        "status": data.get("status", "online"),
        "metrics": data.get("metrics", {}),
    }

    return jsonify({"success": True, "server_time": datetime.now(UTC).isoformat()})
