import hashlib
import secrets
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from flask import Blueprint, jsonify, request

from .auth import Permission, Role, require_auth
from .deps import config, db
from .models import Token as APIToken  # Use DB model alias

bp = Blueprint("admin", __name__)


@bp.route("/tokens", methods=["GET"])
@require_auth(Permission.ADMIN)
def list_tokens():
    tokens = APIToken.query.all()
    results = []
    for t in tokens:
        d = asdict(t)
        d["token_hash"] = "***"  # noqa: S105
        results.append(d)
    return jsonify({"tokens": results})


@bp.route("/tokens", methods=["POST"])
@require_auth(Permission.ADMIN)
def create_token():
    data = request.get_json() or {}

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    role_str = data.get("role", "sensor")
    try:
        role_enum = Role(role_str)
    except ValueError:
        return jsonify({"error": f"Invalid role: {role_str}"}), 400

    token_obj = APIToken(
        token_id=secrets.token_hex(8),
        token_hash=token_hash,
        name=data.get("name", "Token"),
        role=role_enum,
        sensor_id=data.get("sensor_id"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC)
        + timedelta(hours=config.security.token_expiry_hours),
        is_active=True,
    )

    db.session.add(token_obj)
    db.session.commit()

    return jsonify(
        {
            "success": True,
            "token": raw_token,
            "token_id": token_obj.token_id,
            "expires_at": token_obj.expires_at.isoformat(),
        }
    )
