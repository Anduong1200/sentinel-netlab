#!/usr/bin/env python3
"""
Controller Configuration Module
Centralized, type-safe configuration with strict secrets management.
"""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SecurityConfig:
    """Security-sensitive configuration."""

    secret_key: str
    hmac_secret: str
    require_hmac: bool = True
    require_tls: bool = True
    time_drift_max: int = 300
    token_expiry_hours: int = 720
    mtls_enabled: bool = False
    cors_origins: str | list[str] = (
        "http://localhost:8050"  # Dashboard default; set CORS_ORIGINS in prod
    )
    rate_limit_telemetry: str = "200 per minute"
    rate_limit_alerts: str = "50 per minute"
    trusted_proxies: list = field(default_factory=list)

    # Redacted representation for logging
    def safe_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["secret_key"] = "***"  # noqa: S105
        d["hmac_secret"] = "***"  # noqa: S105
        return d


@dataclass
class DatabaseConfig:
    """Database configuration."""

    url: str

    def safe_dict(self) -> dict[str, Any]:
        return {"url": self.url.split("@")[-1] if "@" in self.url else "sqlite://..."}


@dataclass
class GeoConfig:
    """Distributed geo-location settings for multi-sensor estimation."""

    enabled: bool = False
    sensor_positions: dict[str, dict[str, float]] = field(default_factory=dict)
    origin_lat: float | None = None
    origin_lon: float | None = None
    sample_window_sec: int = 30

    def safe_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "sensor_count": len(self.sensor_positions),
            "sensor_positions": self.sensor_positions,
            "origin_lat": self.origin_lat,
            "origin_lon": self.origin_lon,
            "sample_window_sec": self.sample_window_sec,
        }


@dataclass
class ControllerConfig:
    """Main controller configuration."""

    environment: str
    security: SecurityConfig
    database: DatabaseConfig
    geo: GeoConfig = field(default_factory=GeoConfig)
    redis_url: str = "redis://localhost:6379/0"
    host: str = "0.0.0.0"  # nosec B104 # noqa: S104
    port: int = 5000
    debug: bool = False

    def safe_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "security": self.security.safe_dict(),
            "database": self.database.safe_dict(),
            "geo": self.geo.safe_dict(),
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
        }


def _parse_sensor_positions(raw_json: str) -> dict[str, dict[str, float]]:
    """Parse and validate SENSOR_POSITIONS_JSON."""
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid SENSOR_POSITIONS_JSON: {e}") from e

    if not isinstance(payload, dict):
        raise RuntimeError("Invalid SENSOR_POSITIONS_JSON: expected object mapping")

    parsed: dict[str, dict[str, float]] = {}
    for sensor_id, pos in payload.items():
        if not isinstance(sensor_id, str) or not sensor_id.strip():
            raise RuntimeError(
                "Invalid SENSOR_POSITIONS_JSON: sensor_id must be non-empty"
            )
        if not isinstance(pos, dict):
            raise RuntimeError(
                f"Invalid SENSOR_POSITIONS_JSON for '{sensor_id}': position must be object"
            )

        try:
            x_val = float(pos["x"])
            y_val = float(pos["y"])
        except KeyError as e:
            raise RuntimeError(
                f"Invalid SENSOR_POSITIONS_JSON for '{sensor_id}': missing {e.args[0]}"
            ) from e
        except (TypeError, ValueError) as e:
            raise RuntimeError(
                f"Invalid SENSOR_POSITIONS_JSON for '{sensor_id}': x/y must be numeric"
            ) from e

        pos_out: dict[str, float] = {"x": x_val, "y": y_val}
        if "z" in pos and pos["z"] is not None:
            try:
                pos_out["z"] = float(pos["z"])
            except (TypeError, ValueError) as e:
                raise RuntimeError(
                    f"Invalid SENSOR_POSITIONS_JSON for '{sensor_id}': z must be numeric"
                ) from e

        parsed[sensor_id] = pos_out

    return parsed


def init_config() -> ControllerConfig:
    """
    Initialize configuration from environment variables.
    """
    env = os.getenv("ENVIRONMENT", "production").lower()
    is_prod = env == "production"

    # Load Secrets (Fail-Fast)
    from common.security.secrets import require_secret

    secret_key = require_secret(
        "Controller Secret Key",
        "CONTROLLER_SECRET_KEY",
        min_len=16,
        allow_dev_autogen=True,
        env=env,
    )

    hmac_secret = require_secret(
        "HMAC Signing Key",
        "CONTROLLER_HMAC_SECRET",
        min_len=32,
        allow_dev_autogen=True,
        env=env,
    )

    db_url = os.getenv("CONTROLLER_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not db_url:
        if is_prod:
            raise RuntimeError("CRITICAL: Missing DATABASE_URL in production.")
        else:
            # use absolute path to avoid "unable to open database file" in different CWDs
            import pathlib

            base_dir = pathlib.Path(__file__).parent.parent
            data_dir = base_dir / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = data_dir / "sentinel.db"
            db_url = f"sqlite:///{db_path}"
            logger.info(f"Using default SQLite database (Dev Mode): {db_url}")

    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        # Redis is critical for Celery now
        if is_prod:
            raise RuntimeError("CRITICAL: Missing REDIS_URL in production.")
        else:
            redis_url = "redis://localhost:6379/0"
            logger.info("Using default Redis URL (Dev Mode)")

    # Security Config
    security = SecurityConfig(
        secret_key=secret_key,
        hmac_secret=hmac_secret,
        require_hmac=os.getenv("REQUIRE_HMAC", "true").lower() == "true",
        require_tls=os.getenv("REQUIRE_TLS", "true").lower() == "true",
        time_drift_max=int(os.getenv("MAX_TIME_DRIFT_SECONDS", "300")),
        token_expiry_hours=int(os.getenv("TOKEN_EXPIRY_HOURS", "720")),
        mtls_enabled=os.getenv("MTLS_ENABLED", "false").lower() == "true",
        cors_origins=(
            os.getenv("CORS_ORIGINS", "http://localhost:8050").split(",")
            if "," in os.getenv("CORS_ORIGINS", "http://localhost:8050")
            else os.getenv("CORS_ORIGINS", "http://localhost:8050")
        ),
        rate_limit_telemetry=os.getenv("RATE_LIMIT_TELEMETRY", "200 per minute"),
        rate_limit_alerts=os.getenv("RATE_LIMIT_ALERTS", "50 per minute"),
        trusted_proxies=os.getenv(
            "TRUSTED_PROXIES",
            "127.0.0.1,172.28.0.0/16",  # Compose sentinel-net only; set explicitly in prod
        ).split(","),
    )

    # Database Config
    database = DatabaseConfig(url=db_url)

    # Distributed Geo Config
    geo_enabled = os.getenv("GEO_ENABLED", "false").lower() == "true"
    sensor_positions_raw = os.getenv("SENSOR_POSITIONS_JSON", "").strip()
    sensor_positions: dict[str, dict[str, float]] = {}

    if geo_enabled:
        if not sensor_positions_raw:
            raise RuntimeError(
                "GEO_ENABLED is true but SENSOR_POSITIONS_JSON is missing or empty."
            )
        sensor_positions = _parse_sensor_positions(sensor_positions_raw)
        if not sensor_positions:
            raise RuntimeError(
                "GEO_ENABLED is true but SENSOR_POSITIONS_JSON has no sensors."
            )
    elif sensor_positions_raw:
        # Allow preloading positions while GEO_ENABLED=false; ignore malformed values.
        try:
            sensor_positions = _parse_sensor_positions(sensor_positions_raw)
        except RuntimeError as e:
            logger.warning(
                "Ignoring malformed SENSOR_POSITIONS_JSON because GEO_ENABLED=false: %s",
                e,
            )
            sensor_positions = {}

    origin_lat: float | None = None
    origin_lon: float | None = None

    origin_lat_raw = os.getenv("GEO_ORIGIN_LAT")
    origin_lon_raw = os.getenv("GEO_ORIGIN_LON")
    if origin_lat_raw is not None:
        try:
            origin_lat = float(origin_lat_raw)
        except ValueError as e:
            raise RuntimeError("Invalid GEO_ORIGIN_LAT: must be numeric") from e

    if origin_lon_raw is not None:
        try:
            origin_lon = float(origin_lon_raw)
        except ValueError as e:
            raise RuntimeError("Invalid GEO_ORIGIN_LON: must be numeric") from e

    if (origin_lat is None) != (origin_lon is None):
        logger.warning(
            "Incomplete GEO_ORIGIN configuration detected; lat/lon projection disabled."
        )
        origin_lat = None
        origin_lon = None

    sample_window_sec = int(os.getenv("GEO_SAMPLE_WINDOW_SEC", "30"))
    if sample_window_sec <= 0:
        raise RuntimeError("Invalid GEO_SAMPLE_WINDOW_SEC: must be > 0")

    geo = GeoConfig(
        enabled=geo_enabled,
        sensor_positions=sensor_positions,
        origin_lat=origin_lat,
        origin_lon=origin_lon,
        sample_window_sec=sample_window_sec,
    )

    cfg = ControllerConfig(
        environment=env,
        security=security,
        database=database,
        geo=geo,
        redis_url=redis_url,
        host=os.getenv("CONTROLLER_HOST", os.getenv("HOST", "0.0.0.0")),  # nosec B104 # noqa: S104
        port=int(os.getenv("CONTROLLER_PORT", os.getenv("PORT", "5000"))),
        debug=os.getenv("CONTROLLER_DEBUG", os.getenv("FLASK_DEBUG", "false")).lower()
        == "true"
        or not is_prod,
    )

    return cfg
