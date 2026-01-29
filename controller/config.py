#!/usr/bin/env python3
"""
Controller Configuration Module
Centralized, type-safe configuration with strict secrets management.
"""

import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict

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
    
    # Redacted representation for logging
    def safe_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["secret_key"] = "***"
        d["hmac_secret"] = "***"
        return d


@dataclass
class DatabaseConfig:
    """Database configuration."""
    url: str
    
    def safe_dict(self) -> Dict[str, Any]:
        return {"url": self.url.split("@")[-1] if "@" in self.url else "sqlite://..."}


@dataclass
class ControllerConfig:
    """Main controller configuration."""
    environment: str
    security: SecurityConfig
    database: DatabaseConfig
    host: str = "0.0.0.0"  # nosec B104
    port: int = 5000
    debug: bool = False
    
    def safe_dict(self) -> Dict[str, Any]:
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

    # Load Secrets
    secret_key = os.getenv("CONTROLLER_SECRET_KEY")
    hmac_secret = os.getenv("CONTROLLER_HMAC_SECRET")
    db_url = os.getenv("CONTROLLER_DATABASE_URL") or os.getenv("DATABASE_URL")

    # Strict Validation for Production
    missing = []
    
    if not secret_key:
        if is_prod and strict_production:
            missing.append("CONTROLLER_SECRET_KEY")
        elif not is_prod:
            secret_key = "dev-secret-unsafe-do-not-use-in-prod"
            logger.warning("Using default INSECURE secret key (Dev Mode)")

    if not hmac_secret:
        if is_prod and strict_production:
            missing.append("CONTROLLER_HMAC_SECRET")
        elif not is_prod:
            hmac_secret = "dev-hmac-unsafe-do-not-use-in-prod"
            logger.warning("Using default INSECURE hmac secret (Dev Mode)")
    
    if not db_url:
        if is_prod and strict_production:
            missing.append("CONTROLLER_DATABASE_URL")
        elif not is_prod:
            db_url = "sqlite:///data/sentinel.db"
            logger.info("Using default SQLite database (Dev Mode)")

    if missing:
        msg = (
            f"CRITICAL: Missing required production secrets: {', '.join(missing)}. "
            "Application refused to start in PRODUCTION mode without these secrets. "
            "Set them in environment or switch ENVIRONMENT != production."
        )
        logger.critical(msg)
        raise RuntimeError(msg)

    # Security Config
    security = SecurityConfig(
        secret_key=secret_key,
        hmac_secret=hmac_secret,
        require_hmac=os.getenv("REQUIRE_HMAC", "true").lower() == "true",
        require_tls=os.getenv("REQUIRE_TLS", "true").lower() == "true",
        time_drift_max=int(os.getenv("MAX_TIME_DRIFT", "300")),
        token_expiry_hours=int(os.getenv("TOKEN_EXPIRY_HOURS", "720")),
        mtls_enabled=os.getenv("MTLS_ENABLED", "false").lower() == "true",
    )

    # Database Config
    database = DatabaseConfig(url=db_url)

    cfg = ControllerConfig(
        environment=env,
        security=security,
        database=database,
        host=os.getenv("CONTROLLER_HOST", os.getenv("HOST", "0.0.0.0")),  # nosec B104
        port=int(os.getenv("CONTROLLER_PORT", os.getenv("PORT", "5000"))),
        debug=os.getenv("CONTROLLER_DEBUG", os.getenv("FLASK_DEBUG", "false")).lower() == "true" or not is_prod,
    )

    return cfg
