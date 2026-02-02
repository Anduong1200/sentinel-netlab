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
from controller.api.auth import init_default_tokens

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
    init_default_tokens()


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
    import yaml
    import os
    spec_path = os.path.join(os.path.dirname(__file__), "openapi.yaml")

    try:
        with open(spec_path, encoding="utf-8") as f:
            spec = yaml.safe_load(f)
        return jsonify(spec)
    except FileNotFoundError:
        return jsonify({"error": "OpenAPI spec not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/metrics")
def metrics():
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


if __name__ == "__main__":
    app.run(host=config.host, port=config.port, debug=config.debug)
