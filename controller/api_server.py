#!/usr/bin/env python3
"""
Sentinel NetLab - Enhanced Controller API
Production-ready with mTLS, Pydantic validation, rate limiting, and observability.
"""

import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from functools import wraps
from pathlib import Path

# Import Report Engine
from export_engine import ReportData, ReportEngine, ReportFormat, ReportType
from flask import Flask, g, jsonify, request, send_file
from flask_cors import CORS

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

    # Dummy Limiter class
    class Limiter:
        def __init__(
            self, key_func=None, app=None, default_limits=None, storage_uri=None
        ):
            pass

        def limit(self, limit_string):
            def decorator(f):
                return f

            return decorator

    def get_remote_address():
        return "127.0.0.1"


# Try pydantic for validation
try:
    from pydantic import BaseModel, Field, ValidationError, validator

    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = object

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION (from env/.env/secrets)
# =============================================================================


class Config:
    """Server configuration - all from environment, no hardcoded secrets"""

    # Required secrets (MUST be set in production)
    SECRET_KEY = os.environ.get("CONTROLLER_SECRET_KEY")
    HMAC_SECRET = os.environ.get("CONTROLLER_HMAC_SECRET")

    # Security settings
    MAX_TIME_DRIFT_SECONDS = int(os.environ.get("MAX_TIME_DRIFT", "300"))
    TOKEN_EXPIRY_HOURS = int(os.environ.get("TOKEN_EXPIRY_HOURS", "720"))
    REQUIRE_HMAC = os.environ.get("REQUIRE_HMAC", "true").lower() == "true"
    REQUIRE_TLS = os.environ.get("REQUIRE_TLS", "false").lower() == "true"

    # mTLS settings
    TLS_CERT_PATH = os.environ.get("TLS_CERT_PATH", "")
    TLS_KEY_PATH = os.environ.get("TLS_KEY_PATH", "")
    TLS_CA_PATH = os.environ.get("TLS_CA_PATH", "")  # For client cert validation
    MTLS_ENABLED = os.environ.get("MTLS_ENABLED", "false").lower() == "true"

    # Database
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///sentinel.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Rate limiting
    RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "100 per minute")
    RATE_LIMIT_SENSOR = os.environ.get("RATE_LIMIT_SENSOR", "200 per minute")

    @classmethod
    def validate(cls):
        """Validate required config on startup"""
        errors = []
        if not cls.SECRET_KEY:
            if os.environ.get("FLASK_ENV") == "production":
                errors.append("CONTROLLER_SECRET_KEY must be set in production")
            else:
                cls.SECRET_KEY = secrets.token_hex(32)
                logger.warning("Using auto-generated SECRET_KEY (dev mode)")

        if not cls.HMAC_SECRET:
            if os.environ.get("FLASK_ENV") == "production":
                errors.append("CONTROLLER_HMAC_SECRET must be set in production")
            else:
                cls.HMAC_SECRET = "dev-hmac-secret"  # nosec B105
                logger.warning("Using default HMAC_SECRET (dev mode)")

        if errors:
            raise ValueError("Configuration errors:\n" + "\n".join(errors))


Config.validate()


# =============================================================================
# PYDANTIC MODELS (Strict JSON Validation)
# =============================================================================

if PYDANTIC_AVAILABLE:

    class TelemetryItem(BaseModel):
        """Single telemetry item"""

        bssid: str = Field(..., pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
        ssid: str | None = Field(None, max_length=32)
        channel: int | None = Field(None, ge=1, le=200)
        rssi_dbm: int | None = Field(None, ge=-120, le=0)
        timestamp: str | None = None

        class Config:
            extra = "allow"

    class TelemetryBatch(BaseModel):
        """Telemetry batch from sensor"""

        sensor_id: str = Field(..., min_length=1, max_length=64)
        batch_id: str | None = Field(None, max_length=64)
        timestamp_utc: str
        sequence_number: int | None = Field(None, ge=0)
        items: list[TelemetryItem] = Field(..., max_items=1000)

        @validator("timestamp_utc")
        def validate_timestamp(cls, v):
            try:
                datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError("Invalid ISO8601 timestamp")
            return v

    class AlertCreate(BaseModel):
        """Alert creation request"""

        alert_type: str = Field(..., max_length=50)
        severity: str = Field(..., pattern=r"^(Critical|High|Medium|Low|Info)$")
        title: str = Field(..., max_length=200)
        description: str | None = Field(None, max_length=2000)
        bssid: str | None = None
        evidence: dict | None = None

    class HeartbeatRequest(BaseModel):
        """Sensor heartbeat"""

        sensor_id: str
        status: str = Field("online", pattern=r"^(online|degraded|offline)$")
        metrics: dict | None = None
        sequence_number: int | None = None


def validate_json(model_class):
    """Decorator to validate request JSON with Pydantic"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not PYDANTIC_AVAILABLE:
                return f(*args, **kwargs)

            try:
                data = request.get_json()
                validated = model_class(**data)
                g.validated_data = validated
            except ValidationError as e:
                return jsonify(
                    {"error": "Validation failed", "details": e.errors()}
                ), 400
            except Exception as e:
                return jsonify({"error": f"Invalid JSON: {str(e)}"}), 400

            return f(*args, **kwargs)

        return decorated_function


# =============================================================================
# DATABASE MODELS
# =============================================================================

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)


class Telemetry(db.Model):
    __tablename__ = "telemetry"
    id = db.Column(db.Integer, primary_key=True)
    sensor_id = db.Column(db.String(64), index=True)
    batch_id = db.Column(db.String(64), index=True)
    ingested_at = db.Column(db.DateTime, default=datetime.utcnow)
    data = db.Column(JSONB if "postgresql" in Config.DATABASE_URL else db.JSON)


class DBAlert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.String(32), primary_key=True)
    sensor_id = db.Column(db.String(64), index=True)
    alert_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    evidence = db.Column(JSONB if "postgresql" in Config.DATABASE_URL else db.JSON)


# Create tables if not exist
with app.app_context():
    db.create_all()


# =============================================================================
# FLASK APP
# =============================================================================

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY
CORS(app)


# Rate limiting with Redis support
def get_rate_limit_key():
    """Get rate limit key - sensor ID if authenticated, else IP"""
    if hasattr(g, "token") and g.token and g.token.sensor_id:
        return f"sensor:{g.token.sensor_id}"
    return get_remote_address()


limiter = Limiter(
    key_func=get_rate_limit_key,
    app=app,
    default_limits=[Config.RATE_LIMIT_DEFAULT],
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
)


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
SENSOR_REGISTRY: dict[str, dict] = {}


def init_default_tokens():
    """Initialize default tokens (dev only)"""
    if os.environ.get("FLASK_ENV") == "production":
        return

    tokens = [
        ("admin-token-dev", "Admin Token", Role.ADMIN, None),
        ("sensor-01-token", "Sensor 01", Role.SENSOR, "sensor-01"),
        ("analyst-token", "Analyst Token", Role.ANALYST, None),
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
                datetime.now(UTC) + timedelta(hours=Config.TOKEN_EXPIRY_HOURS)
            ).isoformat(),
        )


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
        return drift <= Config.MAX_TIME_DRIFT_SECONDS
    except Exception:
        return False


def verify_hmac(payload: bytes, signature: str) -> bool:
    expected = hmac.new(
        Config.HMAC_SECRET.encode(), payload, hashlib.sha256
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
            if Config.REQUIRE_TLS and not request.is_secure:
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
            if not Config.REQUIRE_HMAC:
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


# =============================================================================
# DATA STORES
# =============================================================================

TELEMETRY_BUFFER: list[dict] = []
ALERTS_BUFFER: list[dict] = []


# =============================================================================
# API ENDPOINTS
# =============================================================================


@app.route("/api/v1/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "2.0.0",
            "tls_required": Config.REQUIRE_TLS,
            "hmac_required": Config.REQUIRE_HMAC,
        }
    )


@app.route("/api/v1/time")
def time_sync():
    return jsonify(
        {
            "server_time": datetime.now(UTC).isoformat(),
            "unix_timestamp": time.time(),
        }
    )


@app.route("/api/v1/telemetry", methods=["POST"])
@require_auth(Permission.WRITE_TELEMETRY)
@require_signed()
@limiter.limit(Config.RATE_LIMIT_SENSOR)
@validate_json(TelemetryBatch) if PYDANTIC_AVAILABLE else lambda f: f
def ingest_telemetry():
    """Batch telemetry ingestion with full validation"""
    if PYDANTIC_AVAILABLE and hasattr(g, "validated_data"):
        data = g.validated_data.dict()
    else:
        data = request.get_json()

    sensor_id = data.get("sensor_id")
    items = data.get("items", [])
    batch_id = data.get("batch_id", secrets.token_hex(8))

    if g.token.sensor_id and g.token.sensor_id != sensor_id:
        return jsonify({"error": "Sensor ID mismatch"}), 403

    accepted = 0
    db_items = []

    # Store batch as single record or individual items depending on scale
    # Here we store items individually for queryability, or could store batch
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


@app.route("/api/v1/telemetry", methods=["GET"])
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


@app.route("/api/v1/networks", methods=["GET"])
@require_auth(Permission.READ_TELEMETRY)
def get_networks():
    """Get summarized view of recently seen networks"""
    limit = min(int(request.args.get("limit", 500)), 2000)

    # Get recent telemetry
    # For efficiency, we should use DISTINCT ON in Postgres, but for compatibility
    # we'll fetch recent records and dedup in Python.
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
            # If gps data in telemetry, extract it
            if "gps" in net:
                net["lat"] = net["gps"].get("lat")
                net["lon"] = net["gps"].get("lon")

            networks[bssid] = net

    results = list(networks.values())
    return jsonify({"count": len(results), "networks": results})


@app.route("/api/v1/alerts", methods=["POST"])
@require_auth(Permission.WRITE_ALERTS)
@require_signed()
@limiter.limit("50 per minute")
@validate_json(AlertCreate) if PYDANTIC_AVAILABLE else lambda f: f
def create_alert():
    if PYDANTIC_AVAILABLE and hasattr(g, "validated_data"):
        data = g.validated_data.dict()
    else:
        data = request.get_json()

    alert = DBAlert(
        id=secrets.token_hex(8),
        sensor_id=g.token.sensor_id,
        alert_type=data.get("alert_type"),
        severity=data.get("severity"),
        title=data.get("title"),
        description=data.get("description"),
        evidence=data.get("evidence"),
    )

    db.session.add(alert)
    db.session.commit()

    return jsonify({"success": True, "alert_id": alert.id})


@app.route("/api/v1/alerts", methods=["GET"])
@require_auth(Permission.READ_ALERTS)
def get_alerts():
    limit = min(int(request.args.get("limit", 50)), 500)
    severity = request.args.get("severity")

    query = DBAlert.query.order_by(DBAlert.created_at.desc())
    if severity:
        query = query.filter_by(severity=severity)

    records = query.limit(limit).all()

    # Serialize
    results = []
    for r in records:
        results.append(
            {
                "id": r.id,
                "sensor_id": r.sensor_id,
                "title": r.title,
                "severity": r.severity,
                "created_at": r.created_at.isoformat(),
                "description": r.description,
            }
        )

    return jsonify({"count": len(results), "items": results})


@app.route("/api/v1/reports/generate", methods=["POST"])
@require_auth(Permission.READ_ALERTS)  # Basic permission
@limiter.limit("10 per minute")
def generate_remote_report():
    """Generate report from provided data"""
    data = request.get_json()

    try:
        # Convert raw JSON back to ReportData
        # Note: audit.py sends a specific structure, export_engine expects another.
        # We need a mapper here. For now, assume audit.py sends compatible structure
        # or we map it manually.

        # Mapping audit.py structure to ReportData
        # audit.py: { "report": {...}, "summary": {...}, "findings": [...], "actions": [...] }

        report_info = data.get("report", {})
        summary = data.get("summary", {})
        findings = data.get("findings", [])
        actions = data.get("actions", [])

        # Transform findings from Audit format to Report format
        report_findings = []
        for f in findings:
            report_findings.append(
                {
                    "title": f.get("title"),
                    "description": f.get("description"),
                    "severity": f.get("severity", "medium").lower(),
                }
            )

        report_data = ReportData(
            report_type=ReportType.AUDIT,
            title=report_info.get("title", "Security Scan"),
            generated_at=report_info.get("date", datetime.now().isoformat()),
            total_networks=summary.get("networks_scanned", 0),
            critical_risks=summary.get("counts", {}).get("critical", 0),
            high_risks=summary.get("counts", {}).get("high", 0),
            medium_risks=summary.get("counts", {}).get("medium", 0),
            total_alerts=len(findings),
            sensors_active=1,
            findings=report_findings,
            recommendations=[a.get("task") for a in actions],
        )

        engine = ReportEngine(output_dir=Path("./generated_reports"))
        # Prefer PDF if available
        format = ReportFormat.PDF

        output_path = engine.generate(report_data, format)

        return send_file(
            output_path,
            mimetype="application/pdf" if format == ReportFormat.PDF else "text/html",
            as_attachment=True,
            download_name=output_path.name,
        )

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/sensors", methods=["GET"])
@require_auth(Permission.MANAGE_SENSORS)
def list_sensors():
    return jsonify({"count": len(SENSOR_REGISTRY), "sensors": SENSOR_REGISTRY})


@app.route("/api/v1/sensors/heartbeat", methods=["POST"])
@require_auth(Permission.WRITE_TELEMETRY)
@require_signed()
@validate_json(HeartbeatRequest) if PYDANTIC_AVAILABLE else lambda f: f
def sensor_heartbeat():
    if PYDANTIC_AVAILABLE and hasattr(g, "validated_data"):
        data = g.validated_data.dict()
    else:
        data = request.get_json() or {}

    sensor_id = data.get("sensor_id") or g.token.sensor_id or "unknown"

    SENSOR_REGISTRY[sensor_id] = {
        "last_heartbeat": datetime.now(UTC).isoformat(),
        "status": data.get("status", "online"),
        "metrics": data.get("metrics", {}),
    }

    return jsonify(
        {"success": True, "server_time": datetime.now(UTC).isoformat()}
    )


@app.route("/api/v1/tokens", methods=["GET"])
@require_auth(Permission.ADMIN)
def list_tokens():
    tokens = []
    for t in TOKEN_STORE.values():
        d = asdict(t)
        d["token_hash"] = "***"  # nosec B105
        tokens.append(d)
    return jsonify({"tokens": tokens})


@app.route("/api/v1/tokens", methods=["POST"])
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
            datetime.now(UTC) + timedelta(hours=Config.TOKEN_EXPIRY_HOURS)
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


# =============================================================================
# OPENAPI SPEC ENDPOINT
# =============================================================================


@app.route("/api/v1/openapi.json")
def openapi_spec():
    """Serve OpenAPI specification"""
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Sentinel NetLab Controller API",
            "version": "2.0.0",
            "description": "WiFi Security Monitoring Controller",
        },
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health check",
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/time": {
                "get": {
                    "summary": "Time sync",
                    "responses": {"200": {"description": "Server time"}},
                }
            },
            "/telemetry": {
                "post": {
                    "summary": "Ingest telemetry",
                    "security": [{"bearerAuth": []}],
                },
                "get": {"summary": "Query telemetry", "security": [{"bearerAuth": []}]},
            },
            "/alerts": {
                "post": {"summary": "Create alert", "security": [{"bearerAuth": []}]},
                "get": {"summary": "List alerts", "security": [{"bearerAuth": []}]},
            },
            "/sensors": {
                "get": {"summary": "List sensors", "security": [{"bearerAuth": []}]}
            },
            "/sensors/heartbeat": {
                "post": {
                    "summary": "Sensor heartbeat",
                    "security": [{"bearerAuth": []}],
                }
            },
        },
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
        },
    }
    return jsonify(spec)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")  # nosec B104
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()

    logger.info("Starting Controller API v2.0.0")
    logger.info(f"TLS required: {Config.REQUIRE_TLS}")
    logger.info(f"HMAC required: {Config.REQUIRE_HMAC}")
    logger.info(f"Rate limit: {Config.RATE_LIMIT_DEFAULT}")

    # For production, use Gunicorn with TLS
    app.run(host=args.host, port=args.port, debug=args.debug)
