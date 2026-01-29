import hashlib
import hmac
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from functools import wraps
from flask import jsonify, request, g
from .deps import config, logger

# =============================================================================
# RBAC & AUTHENTICATION
# =============================================================================

class Permission(str, Enum):
    READ_TELEMETRY = "telemetry:read"
    WRITE_TELEMETRY = "telemetry:write"
    READ_ALERTS = "alerts:read"
    WRITE_ALERTS = "alerts:write"
    MANAGE_SENSORS = "sensors:manage"
    ADMIN = "admin:all"


class Role(str, Enum):
    SENSOR = "sensor"
    OPERATOR = "operator"
    ANALYST = "analyst"
    ADMIN = "admin"


ROLE_PERMISSIONS = {
    Role.SENSOR: [Permission.WRITE_TELEMETRY, Permission.WRITE_ALERTS],
    Role.OPERATOR: [Permission.READ_TELEMETRY, Permission.READ_ALERTS],
    Role.ANALYST: [
        Permission.READ_TELEMETRY,
        Permission.READ_ALERTS,
        Permission.MANAGE_SENSORS,
    ],
    Role.ADMIN: list(Permission),
}


@dataclass
class APIToken:
    token_id: str
    token_hash: str
    name: str
    role: Role
    sensor_id: str | None = None
    created_at: str = ""
    expires_at: str = ""
    last_used: str | None = None
    is_active: bool = True
    last_sequence: int = 0  # For replay protection


TOKEN_STORE: dict[str, APIToken] = {}

def init_default_tokens():
    """Initialize default tokens (dev only)"""
    if config.environment == "production":
        return

    tokens = [
        ("admin-token-dev", "Admin Token", Role.ADMIN, None),  # noqa: S105
        ("sensor-01-token", "Sensor 01", Role.SENSOR, "sensor-01"),  # noqa: S105
        ("analyst-token", "Analyst Token", Role.ANALYST, None),  # noqa: S105
    ]

    for token, name, role, sensor_id in tokens:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        TOKEN_STORE[token_hash] = APIToken(
            token_id=secrets.token_hex(8),
            token_hash=token_hash,
            name=name,
            role=role,
            sensor_id=sensor_id,
            created_at=datetime.now(UTC).isoformat(),
            expires_at=(
                datetime.now(UTC) + timedelta(hours=config.security.token_expiry_hours)
            ).isoformat(),
        )

# Initialize defaults
init_default_tokens()


def verify_token(token: str) -> APIToken | None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    token_obj = TOKEN_STORE.get(token_hash)

    if not token_obj or not token_obj.is_active:
        return None

    expires = datetime.fromisoformat(token_obj.expires_at.replace("Z", "+00:00"))
    if datetime.now(UTC) > expires:
        return None

    token_obj.last_used = datetime.now(UTC).isoformat()
    return token_obj


def verify_timestamp(timestamp_str: str) -> bool:
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        drift = abs((datetime.now(UTC) - ts).total_seconds())
        return drift <= config.security.time_drift_max
    except Exception:
        return False


def verify_hmac(payload: bytes, signature: str) -> bool:
    expected = hmac.new(
        config.security.hmac_secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_sequence(token: APIToken, sequence: int) -> bool:
    """Verify monotonic sequence number for replay protection"""
    if sequence is None:
        return True  # Optional
    if sequence <= token.last_sequence:
        return False
    token.last_sequence = sequence
    return True


def require_auth(permission: Permission = None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # TLS check
            if config.security.require_tls and not request.is_secure:
                if request.headers.get("X-Forwarded-Proto") != "https":
                    return jsonify({"error": "HTTPS required"}), 403

            # Token auth
            auth_header = request.headers.get("Authorization", "")
            token = (
                auth_header[7:]
                if auth_header.startswith("Bearer ")
                else request.headers.get("X-API-Key")
            )

            if not token:
                return jsonify({"error": "Missing authentication"}), 401

            token_obj = verify_token(token)
            if not token_obj:
                return jsonify({"error": "Invalid or expired token"}), 401

            g.token = token_obj
            g.role = token_obj.role

            # Permission check
            if permission:
                perms = ROLE_PERMISSIONS.get(token_obj.role, [])
                if permission not in perms and Permission.ADMIN not in perms:
                    return jsonify({"error": "Insufficient permissions"}), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_signed():
    """Require HMAC signature + timestamp + sequence validation"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not config.security.require_hmac:
                return f(*args, **kwargs)

            signature = request.headers.get("X-Signature")
            timestamp = request.headers.get("X-Timestamp")
            sequence = request.headers.get("X-Sequence")

            if not signature:
                return jsonify({"error": "Missing signature"}), 400

            if not timestamp or not verify_timestamp(timestamp):
                return jsonify({"error": "Invalid/expired timestamp"}), 400

            if not verify_hmac(request.get_data(), signature):
                return jsonify({"error": "Invalid signature"}), 401

            # Sequence check (replay protection)
            if sequence and hasattr(g, "token"):
                try:
                    seq_num = int(sequence)
                    if not verify_sequence(g.token, seq_num):
                        return jsonify({"error": "Invalid sequence (replay?)"}), 400
                except ValueError:
                    pass

            return f(*args, **kwargs)

        return decorated_function

    return decorator
