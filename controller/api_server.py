#!/usr/bin/env python3
"""
Sentinel NetLab - Enhanced Controller API
Production-ready with mTLS, Pydantic validation, rate limiting, and observability.
"""

import time
from datetime import UTC, datetime
from flask import jsonify

# Import Core Dependencies (Config, DB, Limiter)
from controller.api.deps import create_app, config
from controller.api.auth import init_default_tokens

# Import Blueprints
from controller.api.telemetry import bp as telemetry_bp  # noqa: E402
from controller.api.alerts import bp as alerts_bp  # noqa: E402
from controller.api.sensors import bp as sensors_bp  # noqa: E402
from controller.api.admin import bp as admin_bp  # noqa: E402

# Initialize App
app = create_app()

# Observability & Security Middleware
from controller.api.middleware import ObservabilityMiddleware, TrustedProxyMiddleware  # noqa: E402
from common.observability.metrics import HTTPMetricsMiddleware  # noqa: E402

app.wsgi_app = ObservabilityMiddleware(app.wsgi_app)
app.wsgi_app = HTTPMetricsMiddleware(app.wsgi_app)
app.wsgi_app = TrustedProxyMiddleware(
    app.wsgi_app,
    trusted_cidrs=config.security.trusted_proxies,
    x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1
)

# Register Blueprints
app.register_blueprint(telemetry_bp, url_prefix="/api/v1")
app.register_blueprint(alerts_bp, url_prefix="/api/v1")
app.register_blueprint(sensors_bp, url_prefix="/api/v1")
app.register_blueprint(admin_bp, url_prefix="/api/v1")

# Create tables
with app.app_context():
    # In production, we assume DB is initialized via ops/init-db.sql or Alembic
    # db.create_all()
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
    import yaml  # type: ignore
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
    from common.observability.metrics import metrics_endpoint
    data, content_type = metrics_endpoint()
    return data, 200, {"Content-Type": content_type}


if __name__ == "__main__":
    app.run(host=config.host, port=config.port, debug=config.debug)
