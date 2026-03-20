"""
Sentinel NetLab - Sensor Key Provisioning API

Endpoints for enrolling sensors with unique per-sensor HMAC keys,
rotating keys, checking key status, and revoking keys.

This replaces the shared-secret model where all sensors derive keys
from a single CONTROLLER_HMAC_SECRET, reducing blast radius when a
sensor is compromised.
"""

import hashlib
import logging
import secrets
from datetime import UTC, datetime

from flask import Blueprint, jsonify, request

from controller.api.auth import Permission, require_permission
from controller.api.deps import db
from controller.db.models import AuditLog, Sensor, SensorKey

logger = logging.getLogger(__name__)

provisioning_bp = Blueprint("provisioning", __name__, url_prefix="/api/v1/sensors")


def _generate_sensor_key() -> tuple[str, str]:
    """Generate a cryptographically secure sensor key.

    Returns:
        Tuple of (plaintext_key, key_hash).
        The plaintext is returned to the admin exactly once.
    """
    plaintext = secrets.token_urlsafe(32)  # 256-bit key
    key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
    return plaintext, key_hash


def _audit(event_type: str, sensor_id: str, details: dict | None = None):
    """Record an audit log entry."""
    try:
        entry = AuditLog(
            event_type=event_type,
            actor=request.remote_addr or "unknown",
            resource=f"sensor:{sensor_id}",
            action=event_type,
            details=details or {},
            ip_address=request.remote_addr,
        )
        db.session.add(entry)
    except Exception as e:
        logger.warning(f"Failed to create audit log: {e}")


@provisioning_bp.route("/enroll", methods=["POST"])
@require_permission(Permission.ADMIN)
def enroll_sensor():
    """
    Enroll a sensor with a unique HMAC key.

    Request Body:
        {"sensor_id": "sensor-01"}

    Response:
        {"sensor_id": "...", "hmac_key": "...(plaintext, shown once)...",
         "message": "Store this key securely. It will not be shown again."}
    """
    data = request.get_json(silent=True) or {}
    sensor_id = data.get("sensor_id", "").strip()

    if not sensor_id:
        return jsonify({"error": "sensor_id is required"}), 400

    # Check sensor exists
    sensor = db.session.get(Sensor, sensor_id)
    if not sensor:
        return jsonify({"error": f"Sensor '{sensor_id}' not found"}), 404

    # Check if already enrolled
    existing = db.session.get(SensorKey, sensor_id)
    if existing and existing.is_active:
        return jsonify(
            {
                "error": f"Sensor '{sensor_id}' already has an active key. "
                "Use rotate-key to generate a new one.",
            }
        ), 409

    # Generate key
    plaintext, key_hash = _generate_sensor_key()

    if existing:
        existing.key_hash = key_hash
        existing.created_at = datetime.now(UTC)
        existing.rotated_at = None
        existing.last_used = None
        existing.is_active = True
    else:
        sensor_key = SensorKey(
            sensor_id=sensor_id,
            key_hash=key_hash,
            is_active=True,
        )
        db.session.add(sensor_key)

    _audit("sensor.enroll", sensor_id)
    db.session.commit()

    logger.info(f"Sensor '{sensor_id}' enrolled with per-sensor key")

    return jsonify(
        {
            "sensor_id": sensor_id,
            "hmac_key": plaintext,
            "message": "Store this key securely. It will not be shown again.",
        }
    ), 201


@provisioning_bp.route("/<sensor_id>/rotate-key", methods=["POST"])
@require_permission(Permission.ADMIN)
def rotate_key(sensor_id: str):
    """
    Rotate a sensor's HMAC key.

    The old key is immediately invalidated.
    Returns the new plaintext key exactly once.
    """
    sensor_key = db.session.get(SensorKey, sensor_id)
    if not sensor_key:
        return jsonify({"error": f"Sensor '{sensor_id}' has no provisioned key"}), 404

    # Generate new key
    plaintext, key_hash = _generate_sensor_key()

    sensor_key.key_hash = key_hash
    sensor_key.rotated_at = datetime.now(UTC)
    sensor_key.is_active = True

    _audit("sensor.rotate_key", sensor_id, {"previous_hash": sensor_key.key_hash[:8]})
    db.session.commit()

    logger.info(f"Sensor '{sensor_id}' key rotated")

    return jsonify(
        {
            "sensor_id": sensor_id,
            "hmac_key": plaintext,
            "message": "Old key invalidated. Store this new key securely.",
        }
    ), 200


@provisioning_bp.route("/<sensor_id>/key-status", methods=["GET"])
@require_permission(Permission.ADMIN)
def key_status(sensor_id: str):
    """Get key metadata for a sensor (no secrets returned)."""
    sensor_key = db.session.get(SensorKey, sensor_id)
    if not sensor_key:
        return jsonify({"error": f"Sensor '{sensor_id}' has no provisioned key"}), 404

    return jsonify(
        {
            "sensor_id": sensor_id,
            "is_active": sensor_key.is_active,
            "created_at": sensor_key.created_at.isoformat()
            if sensor_key.created_at
            else None,
            "rotated_at": sensor_key.rotated_at.isoformat()
            if sensor_key.rotated_at
            else None,
            "last_used": sensor_key.last_used.isoformat()
            if sensor_key.last_used
            else None,
            "key_hash_prefix": sensor_key.key_hash[:8] + "...",
        }
    ), 200


@provisioning_bp.route("/<sensor_id>/key", methods=["DELETE"])
@require_permission(Permission.ADMIN)
def revoke_key(sensor_id: str):
    """
    Revoke a sensor's HMAC key.

    The sensor will fall back to the shared master secret (if configured)
    or be blocked entirely.
    """
    sensor_key = db.session.get(SensorKey, sensor_id)
    if not sensor_key:
        return jsonify({"error": f"Sensor '{sensor_id}' has no provisioned key"}), 404

    sensor_key.is_active = False

    _audit("sensor.revoke_key", sensor_id)
    db.session.commit()

    logger.info(f"Sensor '{sensor_id}' key revoked")

    return jsonify(
        {
            "sensor_id": sensor_id,
            "message": "Key revoked. Sensor will use shared secret or be blocked.",
        }
    ), 200
