import secrets
import hashlib
from datetime import UTC, datetime, timedelta
from dataclasses import asdict
from flask import Blueprint, jsonify, request
from .deps import config
from .auth import require_auth, Permission, TOKEN_STORE, APIToken, Role

bp = Blueprint("admin", __name__)

@bp.route("/tokens", methods=["GET"])
@require_auth(Permission.ADMIN)
def list_tokens():
    tokens = []
    for t in TOKEN_STORE.values():
        d = asdict(t)
        d["token_hash"] = "***"  # nosec B105 # noqa: S105
        tokens.append(d)
    return jsonify({"tokens": tokens})


@bp.route("/tokens", methods=["POST"])
@require_auth(Permission.ADMIN)
def create_token():
    data = request.get_json() or {}

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    role = data.get("role", "sensor")
    try:
        role_enum = Role(role)
    except ValueError:
        return jsonify({"error": f"Invalid role: {role}"}), 400

    token_obj = APIToken(
        token_id=secrets.token_hex(8),
        token_hash=token_hash,
        name=data.get("name", "Token"),
        role=role_enum,
        sensor_id=data.get("sensor_id"),
        created_at=datetime.now(UTC).isoformat(),
        expires_at=(
            datetime.now(UTC) + timedelta(hours=config.security.token_expiry_hours)
        ).isoformat(),
    )
    TOKEN_STORE[token_hash] = token_obj

    return jsonify(
        {
            "success": True,
            "token": raw_token,
            "token_id": token_obj.token_id,
            "expires_at": token_obj.expires_at,
        }
    )
