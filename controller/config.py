#!/usr/bin/env python3
"""
Controller Configuration Module
Centralized, type-safe configuration with strict secrets management.
"""

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
    cors_origins: str | list[str] = "*"
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
class ControllerConfig:
    """Main controller configuration."""

    environment: str
    security: SecurityConfig
    database: DatabaseConfig
    redis_url: str = "redis://localhost:6379/0"
    host: str = "0.0.0.0"  # nosec B104 # noqa: S104
    port: int = 5000
    debug: bool = False

    def safe_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "security": self.security.safe_dict(),
            "database": self.database.safe_dict(),
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
        }


def init_config(strict_production: bool = True) -> ControllerConfig:
    """
    Initialize configuration from environment variables.

    Args:
        strict_production: If True, raises RuntimeError if secrets are missing in production.
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
        env=env
    )
    
    hmac_secret = require_secret(
        "HMAC Signing Key", 
        "CONTROLLER_HMAC_SECRET", 
        min_len=32, 
        allow_dev_autogen=True, 
        env=env
    )
    
    db_url = os.getenv("CONTROLLER_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not db_url:
        if is_prod:
            raise RuntimeError("CRITICAL: Missing DATABASE_URL in production.")
        else:
            db_url = "sqlite:///data/sentinel.db"
            logger.info("Using default SQLite database (Dev Mode)")
    
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
            os.getenv("CORS_ORIGINS", "*").split(",")
            if "," in os.getenv("CORS_ORIGINS", "*")
            else os.getenv("CORS_ORIGINS", "*")
        ),
        rate_limit_telemetry=os.getenv("RATE_LIMIT_TELEMETRY", "200 per minute"),
        rate_limit_alerts=os.getenv("RATE_LIMIT_ALERTS", "50 per minute"),
        trusted_proxies=os.getenv("TRUSTED_PROXIES", "127.0.0.1,172.16.0.0/12,172.17.0.0/12,172.18.0.0/12,172.19.0.0/12,172.20.0.0/12,172.21.0.0/12,172.22.0.0/12,172.23.0.0/12,172.24.0.0/12,172.25.0.0/12,172.26.0.0/12,172.27.0.0/12,172.28.0.0/12,172.29.0.0/12,172.30.0.0/12,172.31.0.0/12").split(","),
    )

    # Database Config
    database = DatabaseConfig(url=db_url)

    cfg = ControllerConfig(
        environment=env,
        security=security,
        database=database,
        redis_url=redis_url,
        host=os.getenv("CONTROLLER_HOST", os.getenv("HOST", "0.0.0.0")),  # nosec B104 # noqa: S104
        port=int(os.getenv("CONTROLLER_PORT", os.getenv("PORT", "5000"))),
        debug=os.getenv("CONTROLLER_DEBUG", os.getenv("FLASK_DEBUG", "false")).lower()
        == "true"
        or not is_prod,
    )

    return cfg
