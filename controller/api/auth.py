from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from functools import wraps

from flask import g, jsonify, request

from controller.metrics import AUTH_FAILURES, HMAC_FAILURES
from controller.models import APIToken

from .deps import config, db, logger

# =============================================================================
# RBAC & AUTHENTICATION
# =============================================================================


class Permission(StrEnum):
    READ_TELEMETRY = "telemetry:read"
    WRITE_TELEMETRY = "telemetry:write"
    READ_ALERTS = "alerts:read"
    WRITE_ALERTS = "alerts:write"
    MANAGE_SENSORS = "sensors:manage"
    ADMIN = "admin:all"


class Role(StrEnum):
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


# TOKEN_STORE removed - using DB
SENSOR_REGISTRY: dict[str, dict] = {}  # In-memory registry


def init_default_tokens():
    """Initialize default tokens (dev only)"""
    if (
        config.environment == "production"
        or os.environ.get("ALLOW_DEV_TOKENS", "false").lower() != "true"
    ):
        return

    tokens = [
        ("admin-token-dev", "Admin Token", Role.ADMIN, None),  # noqa: S105
        ("sensor-01-token", "Sensor 01", Role.SENSOR, "sensor-01"),  # noqa: S105
        ("analyst-token", "Analyst Token", Role.ANALYST, None),  # noqa: S105
    ]

    # Check if we can connect to DB (might be during build/init)
    try:
        # Create tables if not exist (quick loose check)
        # In prod, use migrations.
        # db.create_all()

        for token_plain, name, role, sensor_id in tokens:
            token_hash = hashlib.sha256(token_plain.encode()).hexdigest()

            # Check exist
            if APIToken.query.filter_by(token_hash=token_hash).first():
                continue

            new_token = APIToken(
                token_id=secrets.token_hex(8),
                token_hash=token_hash,
                name=name,
                role=role.value,
                sensor_id=sensor_id,
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC)
                + timedelta(hours=config.security.token_expiry_hours),
                is_active=True,
            )
            db.session.add(new_token)

        db.session.commit()
    except Exception as e:
        logger.warning(f"Failed to init default tokens: {e}")


# Initialize defaults
# Note: In a real app this should be a CLI command, not on import
# But keeping semantics for now
# init_default_tokens() # Moved to create_app or manual call?
# The original called it here. To avoid circular import/app context issues,
# we should probably NOT call it at module level, but the original did.
# However, db operations require app context.
# We'll rely on the app factory to call this or lazy load.
# For now, let's remove the auto-call at module level to prevent "working outside of application context" errors.


def verify_token(token_plain: str) -> APIToken | None:
    token_hash = hashlib.sha256(token_plain.encode()).hexdigest()

    token_obj = APIToken.query.filter_by(token_hash=token_hash).first()

    if not token_obj or not token_obj.is_active:
        return None

    if datetime.now(UTC) > token_obj.expires_at.replace(tzinfo=UTC):
        return None

    token_obj.last_used = datetime.now(UTC)
    try:
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to update token last_used: {e}")
        db.session.rollback()

    return token_obj


def verify_timestamp(timestamp_str: str) -> bool:
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        drift = abs((datetime.now(UTC) - ts).total_seconds())
        return drift <= config.security.time_drift_max
    except Exception:
        return False


def verify_hmac(
    method: str,
    path: str,
    payload: bytes,
    signature: str,
    timestamp: str,
    sensor_id: str,
    sequence: str | None = None,
    content_encoding: str = "identity",
) -> bool:
    """Verify HMAC signature using V1 Canonical Format"""
    # V1 Canonical String Format (newline delimited)
    parts = [method, path, timestamp, sensor_id, content_encoding]

    canonical_meta = "\n".join(parts) + "\n"

    h = hmac.new(config.security.hmac_secret.encode(), digestmod=hashlib.sha256)
    h.update(canonical_meta.encode())
    h.update(payload)

    expected = h.hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_sequence(token: APIToken, sequence: int) -> bool:
    """Verify monotonic sequence number for replay protection"""
    if sequence is None:
        return True  # Optional
    if sequence <= token.last_sequence:
        return False
    token.last_sequence = sequence
    try:
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to update sequence: {e}")
        db.session.rollback()
        return False
    return True


def require_auth(permission: Permission = None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # TLS check
            # TLS check
            # TLS check
            if config.security.require_tls and not request.is_secure:
                # With TrustedProxyMiddleware, request.is_secure is correctly determined
                # based on X-Forwarded-Proto from TRUSTED sources only.
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
                AUTH_FAILURES.labels(type="token_invalid").inc()
                return jsonify({"error": "Invalid or expired token"}), 401

            g.token = token_obj
            # Role stored as string in DB, convert to Enum for logic comparison?
            # Or just use string in logic. ROLE_PERMISSIONS keys are Enum.
            try:
                g.role = Role(token_obj.role)
            except ValueError:
                # Fallback or error if invalid role in DB
                return jsonify({"error": "Invalid role configuration"}), 403

            # Permission check
            if permission:
                perms = ROLE_PERMISSIONS.get(g.role, [])
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

            # Verify HMAC on RAW WIRE BYTES (whether compressed or not)
            # This prevents zip-bombs: we only decompress AFTER signature is verified.
            payload = request.get_data()
            content_encoding = request.headers.get("Content-Encoding", "identity")

            # Fail-closed check for encoding
            if content_encoding not in ["gzip", "identity", ""]:
                AUTH_FAILURES.labels(type="bad_encoding").inc()
                return jsonify({"error": "Unsupported Content-Encoding"}), 415

            sensor_id = request.headers.get("X-Sensor-ID", "unknown")

            if not verify_hmac(
                request.method,
                request.path,
                payload,
                signature,
                timestamp,
                sensor_id,
                sequence,
                content_encoding=content_encoding,
            ):
                HMAC_FAILURES.labels(reason="signature_mismatch").inc() if hasattr(
                    HMAC_FAILURES, "labels"
                ) else HMAC_FAILURES.inc()
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
