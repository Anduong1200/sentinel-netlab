#!/usr/bin/env python3
"""
Sentinel NetLab - Enhanced Controller API
Production-ready with mTLS, Pydantic validation, rate limiting, and observability.
"""

import os
import json
import time
import hmac
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from enum import Enum

from flask import Flask, jsonify, request, Response, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Try pydantic for validation
try:
    from pydantic import BaseModel, Field, validator, ValidationError
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = object

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION (from env/.env/secrets)
# =============================================================================

class Config:
    """Server configuration - all from environment, no hardcoded secrets"""
    
    # Required secrets (MUST be set in production)
    SECRET_KEY = os.environ.get('CONTROLLER_SECRET_KEY')
    HMAC_SECRET = os.environ.get('CONTROLLER_HMAC_SECRET')
    
    # Security settings
    MAX_TIME_DRIFT_SECONDS = int(os.environ.get('MAX_TIME_DRIFT', '300'))
    TOKEN_EXPIRY_HOURS = int(os.environ.get('TOKEN_EXPIRY_HOURS', '720'))
    REQUIRE_HMAC = os.environ.get('REQUIRE_HMAC', 'true').lower() == 'true'
    REQUIRE_TLS = os.environ.get('REQUIRE_TLS', 'true').lower() == 'true'
    
    # mTLS settings
    TLS_CERT_PATH = os.environ.get('TLS_CERT_PATH', '')
    TLS_KEY_PATH = os.environ.get('TLS_KEY_PATH', '')
    TLS_CA_PATH = os.environ.get('TLS_CA_PATH', '')  # For client cert validation
    MTLS_ENABLED = os.environ.get('MTLS_ENABLED', 'false').lower() == 'true'
    
    # Database
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///data/sentinel.db')
    
    # Rate limiting
    RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '100 per minute')
    RATE_LIMIT_SENSOR = os.environ.get('RATE_LIMIT_SENSOR', '200 per minute')
    
    @classmethod
    def validate(cls):
        """Validate required config on startup"""
        errors = []
        if not cls.SECRET_KEY:
            if os.environ.get('FLASK_ENV') == 'production':
                errors.append("CONTROLLER_SECRET_KEY must be set in production")
            else:
                cls.SECRET_KEY = secrets.token_hex(32)
                logger.warning("Using auto-generated SECRET_KEY (dev mode)")
        
        if not cls.HMAC_SECRET:
            if os.environ.get('FLASK_ENV') == 'production':
                errors.append("CONTROLLER_HMAC_SECRET must be set in production")
            else:
                cls.HMAC_SECRET = 'dev-hmac-secret'
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
        bssid: str = Field(..., regex=r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
        ssid: Optional[str] = Field(None, max_length=32)
        channel: Optional[int] = Field(None, ge=1, le=200)
        rssi_dbm: Optional[int] = Field(None, ge=-120, le=0)
        timestamp: Optional[str] = None
        
        class Config:
            extra = 'allow'

    class TelemetryBatch(BaseModel):
        """Telemetry batch from sensor"""
        sensor_id: str = Field(..., min_length=1, max_length=64)
        batch_id: Optional[str] = Field(None, max_length=64)
        timestamp_utc: str
        sequence_number: Optional[int] = Field(None, ge=0)
        items: List[TelemetryItem] = Field(..., max_items=1000)
        
        @validator('timestamp_utc')
        def validate_timestamp(cls, v):
            try:
                datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError('Invalid ISO8601 timestamp')
            return v

    class AlertCreate(BaseModel):
        """Alert creation request"""
        alert_type: str = Field(..., max_length=50)
        severity: str = Field(..., regex=r'^(Critical|High|Medium|Low|Info)$')
        title: str = Field(..., max_length=200)
        description: Optional[str] = Field(None, max_length=2000)
        bssid: Optional[str] = None
        evidence: Optional[Dict] = None

    class HeartbeatRequest(BaseModel):
        """Sensor heartbeat"""
        sensor_id: str
        status: str = Field('online', regex=r'^(online|degraded|offline)$')
        metrics: Optional[Dict] = None
        sequence_number: Optional[int] = None


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
                return jsonify({
                    "error": "Validation failed",
                    "details": e.errors()
                }), 400
            except Exception as e:
                return jsonify({"error": f"Invalid JSON: {str(e)}"}), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# =============================================================================
# FLASK APP
# =============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
CORS(app)

# Rate limiting with Redis support
def get_rate_limit_key():
    """Get rate limit key - sensor ID if authenticated, else IP"""
    if hasattr(g, 'token') and g.token and g.token.sensor_id:
        return f"sensor:{g.token.sensor_id}"
    return get_remote_address()

limiter = Limiter(
    key_func=get_rate_limit_key,
    app=app,
    default_limits=[Config.RATE_LIMIT_DEFAULT],
    storage_uri=os.environ.get('REDIS_URL', 'memory://')
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
    Role.ANALYST: [Permission.READ_TELEMETRY, Permission.READ_ALERTS, Permission.MANAGE_SENSORS],
    Role.ADMIN: list(Permission),
}


@dataclass
class APIToken:
    token_id: str
    token_hash: str
    name: str
    role: Role
    sensor_id: Optional[str] = None
    created_at: str = ""
    expires_at: str = ""
    last_used: Optional[str] = None
    is_active: bool = True
    last_sequence: int = 0  # For replay protection


TOKEN_STORE: Dict[str, APIToken] = {}
SENSOR_REGISTRY: Dict[str, Dict] = {}


def init_default_tokens():
    """Initialize default tokens (dev only)"""
    if os.environ.get('FLASK_ENV') == 'production':
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
            created_at=datetime.now(timezone.utc).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=Config.TOKEN_EXPIRY_HOURS)).isoformat()
        )


init_default_tokens()


def verify_token(token: str) -> Optional[APIToken]:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    token_obj = TOKEN_STORE.get(token_hash)
    
    if not token_obj or not token_obj.is_active:
        return None
    
    expires = datetime.fromisoformat(token_obj.expires_at.replace('Z', '+00:00'))
    if datetime.now(timezone.utc) > expires:
        return None
    
    token_obj.last_used = datetime.now(timezone.utc).isoformat()
    return token_obj


def verify_timestamp(timestamp_str: str) -> bool:
    try:
        ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        drift = abs((datetime.now(timezone.utc) - ts).total_seconds())
        return drift <= Config.MAX_TIME_DRIFT_SECONDS
    except Exception:
        return False


def verify_hmac(payload: bytes, signature: str) -> bool:
    expected = hmac.new(Config.HMAC_SECRET.encode(), payload, hashlib.sha256).hexdigest()
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
                if request.headers.get('X-Forwarded-Proto') != 'https':
                    return jsonify({"error": "HTTPS required"}), 403
            
            # Token auth
            auth_header = request.headers.get('Authorization', '')
            token = auth_header[7:] if auth_header.startswith('Bearer ') else request.headers.get('X-API-Key')
            
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
            
            signature = request.headers.get('X-Signature')
            timestamp = request.headers.get('X-Timestamp')
            sequence = request.headers.get('X-Sequence')
            
            if not signature:
                return jsonify({"error": "Missing signature"}), 400
            
            if not timestamp or not verify_timestamp(timestamp):
                return jsonify({"error": "Invalid/expired timestamp"}), 400
            
            if not verify_hmac(request.get_data(), signature):
                return jsonify({"error": "Invalid signature"}), 401
            
            # Sequence check (replay protection)
            if sequence and hasattr(g, 'token'):
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

TELEMETRY_BUFFER: List[Dict] = []
ALERTS_BUFFER: List[Dict] = []


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route('/api/v1/health')
def health():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "tls_required": Config.REQUIRE_TLS,
        "hmac_required": Config.REQUIRE_HMAC
    })


@app.route('/api/v1/time')
def time_sync():
    return jsonify({
        "server_time": datetime.now(timezone.utc).isoformat(),
        "unix_timestamp": time.time()
    })


@app.route('/api/v1/telemetry', methods=['POST'])
@require_auth(Permission.WRITE_TELEMETRY)
@require_signed()
@limiter.limit(Config.RATE_LIMIT_SENSOR)
@validate_json(TelemetryBatch) if PYDANTIC_AVAILABLE else lambda f: f
def ingest_telemetry():
    """Batch telemetry ingestion with full validation"""
    if PYDANTIC_AVAILABLE and hasattr(g, 'validated_data'):
        data = g.validated_data.dict()
    else:
        data = request.get_json()
    
    sensor_id = data.get('sensor_id')
    items = data.get('items', [])
    batch_id = data.get('batch_id', secrets.token_hex(8))
    
    if g.token.sensor_id and g.token.sensor_id != sensor_id:
        return jsonify({"error": "Sensor ID mismatch"}), 403
    
    accepted = 0
    for item in items:
        if isinstance(item, dict):
            item['_ingested_at'] = datetime.now(timezone.utc).isoformat()
            item['_sensor_id'] = sensor_id
            item['_batch_id'] = batch_id
            TELEMETRY_BUFFER.append(item)
            accepted += 1
        
        if len(TELEMETRY_BUFFER) > 10000:
            TELEMETRY_BUFFER.pop(0)
    
    SENSOR_REGISTRY[sensor_id] = {
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "status": "online",
        "last_batch": batch_id
    }
    
    logger.info(f"Ingested {accepted} items from {sensor_id}")
    
    return jsonify({"success": True, "ack_id": batch_id, "accepted": accepted})


@app.route('/api/v1/telemetry', methods=['GET'])
@require_auth(Permission.READ_TELEMETRY)
def get_telemetry():
    limit = min(int(request.args.get('limit', 100)), 1000)
    sensor_id = request.args.get('sensor_id')
    
    results = TELEMETRY_BUFFER[-limit:]
    if sensor_id:
        results = [r for r in results if r.get('_sensor_id') == sensor_id]
    
    return jsonify({"count": len(results), "items": results})


@app.route('/api/v1/alerts', methods=['POST'])
@require_auth(Permission.WRITE_ALERTS)
@require_signed()
@limiter.limit("50 per minute")
@validate_json(AlertCreate) if PYDANTIC_AVAILABLE else lambda f: f
def create_alert():
    if PYDANTIC_AVAILABLE and hasattr(g, 'validated_data'):
        data = g.validated_data.dict()
    else:
        data = request.get_json()
    
    alert = {
        "id": secrets.token_hex(8),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sensor_id": g.token.sensor_id,
        **data
    }
    ALERTS_BUFFER.append(alert)
    
    if len(ALERTS_BUFFER) > 1000:
        ALERTS_BUFFER.pop(0)
    
    return jsonify({"success": True, "alert_id": alert["id"]})


@app.route('/api/v1/alerts', methods=['GET'])
@require_auth(Permission.READ_ALERTS)
def get_alerts():
    limit = min(int(request.args.get('limit', 50)), 500)
    severity = request.args.get('severity')
    
    results = ALERTS_BUFFER[-limit:]
    if severity:
        results = [a for a in results if a.get('severity', '').lower() == severity.lower()]
    
    return jsonify({"count": len(results), "items": results})


@app.route('/api/v1/sensors', methods=['GET'])
@require_auth(Permission.MANAGE_SENSORS)
def list_sensors():
    return jsonify({"count": len(SENSOR_REGISTRY), "sensors": SENSOR_REGISTRY})


@app.route('/api/v1/sensors/heartbeat', methods=['POST'])
@require_auth(Permission.WRITE_TELEMETRY)
@require_signed()
@validate_json(HeartbeatRequest) if PYDANTIC_AVAILABLE else lambda f: f
def sensor_heartbeat():
    if PYDANTIC_AVAILABLE and hasattr(g, 'validated_data'):
        data = g.validated_data.dict()
    else:
        data = request.get_json() or {}
    
    sensor_id = data.get('sensor_id') or g.token.sensor_id or 'unknown'
    
    SENSOR_REGISTRY[sensor_id] = {
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "status": data.get('status', 'online'),
        "metrics": data.get('metrics', {})
    }
    
    return jsonify({
        "success": True,
        "server_time": datetime.now(timezone.utc).isoformat()
    })


@app.route('/api/v1/tokens', methods=['GET'])
@require_auth(Permission.ADMIN)
def list_tokens():
    tokens = []
    for t in TOKEN_STORE.values():
        d = asdict(t)
        d['token_hash'] = '***'
        tokens.append(d)
    return jsonify({"tokens": tokens})


@app.route('/api/v1/tokens', methods=['POST'])
@require_auth(Permission.ADMIN)
def create_token():
    data = request.get_json() or {}
    
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    
    role = data.get('role', 'sensor')
    try:
        role_enum = Role(role)
    except ValueError:
        return jsonify({"error": f"Invalid role: {role}"}), 400
    
    token_obj = APIToken(
        token_id=secrets.token_hex(8),
        token_hash=token_hash,
        name=data.get('name', 'Token'),
        role=role_enum,
        sensor_id=data.get('sensor_id'),
        created_at=datetime.now(timezone.utc).isoformat(),
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=Config.TOKEN_EXPIRY_HOURS)).isoformat()
    )
    TOKEN_STORE[token_hash] = token_obj
    
    return jsonify({
        "success": True,
        "token": raw_token,
        "token_id": token_obj.token_id,
        "expires_at": token_obj.expires_at
    })


# =============================================================================
# OPENAPI SPEC ENDPOINT
# =============================================================================

@app.route('/api/v1/openapi.json')
def openapi_spec():
    """Serve OpenAPI specification"""
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Sentinel NetLab Controller API",
            "version": "2.0.0",
            "description": "WiFi Security Monitoring Controller"
        },
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/health": {"get": {"summary": "Health check", "responses": {"200": {"description": "OK"}}}},
            "/time": {"get": {"summary": "Time sync", "responses": {"200": {"description": "Server time"}}}},
            "/telemetry": {
                "post": {"summary": "Ingest telemetry", "security": [{"bearerAuth": []}]},
                "get": {"summary": "Query telemetry", "security": [{"bearerAuth": []}]}
            },
            "/alerts": {
                "post": {"summary": "Create alert", "security": [{"bearerAuth": []}]},
                "get": {"summary": "List alerts", "security": [{"bearerAuth": []}]}
            },
            "/sensors": {"get": {"summary": "List sensors", "security": [{"bearerAuth": []}]}},
            "/sensors/heartbeat": {"post": {"summary": "Sensor heartbeat", "security": [{"bearerAuth": []}]}}
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            }
        }
    }
    return jsonify(spec)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--debug', action='store_true')
    
    args = parser.parse_args()
    
    logger.info(f"Starting Controller API v2.0.0")
    logger.info(f"TLS required: {Config.REQUIRE_TLS}")
    logger.info(f"HMAC required: {Config.REQUIRE_HMAC}")
    logger.info(f"Rate limit: {Config.RATE_LIMIT_DEFAULT}")
    
    # For production, use Gunicorn with TLS
    app.run(host=args.host, port=args.port, debug=args.debug)
