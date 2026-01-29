#!/usr/bin/env python3
"""
Sentinel NetLab - Enhanced Controller API
Production-ready with mTLS, Pydantic validation, rate limiting, and observability.
"""
import time
from datetime import UTC, datetime
from flask import jsonify

# Import Core Dependencies (Config, DB, Limiter)
from controller.api.deps import create_app, config, db

# Import Blueprints
from controller.api.telemetry import bp as telemetry_bp
from controller.api.alerts import bp as alerts_bp
from controller.api.sensors import bp as sensors_bp
from controller.api.admin import bp as admin_bp

# Initialize App
app = create_app()

# Register Blueprints
app.register_blueprint(telemetry_bp, url_prefix="/api/v1")
app.register_blueprint(alerts_bp, url_prefix="/api/v1")
app.register_blueprint(sensors_bp, url_prefix="/api/v1")
app.register_blueprint(admin_bp, url_prefix="/api/v1")

# Create tables
with app.app_context():
    db.create_all()

# System Endpoints
@app.route("/api/v1/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "2.0.0",
            "tls_required": config.security.require_tls,
            "hmac_required": config.security.require_hmac,
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
    }
    return jsonify(spec)

if __name__ == "__main__":
    app.run(host=config.host, port=config.port, debug=config.debug)
