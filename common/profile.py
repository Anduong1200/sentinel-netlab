#!/usr/bin/env python3
"""
Sentinel NetLab - Profile Management

Provides profile-based behavior switching between Lab and Production modes.
"""
import os
from enum import StrEnum

# =============================================================================
# PROFILE DEFINITION
# =============================================================================


class Profile(StrEnum):
    """Deployment profile."""
    LAB = "lab"
    PROD = "prod"


# Read profile from environment (default: lab for safety)
SENTINEL_PROFILE = Profile(os.getenv("SENTINEL_PROFILE", "lab").lower())


def is_lab() -> bool:
    """Check if running in Lab mode."""
    return SENTINEL_PROFILE == Profile.LAB


def is_production() -> bool:
    """Check if running in Production mode."""
    return SENTINEL_PROFILE == Profile.PROD


# =============================================================================
# FEATURE FLAGS BY PROFILE
# =============================================================================


def allow_mock_sensor() -> bool:
    """Mock sensor only allowed in Lab."""
    return is_lab()


def allow_seed_reset() -> bool:
    """Seed/Reset only allowed in Lab."""
    return is_lab()


def allow_sqlite() -> bool:
    """SQLite only allowed in Lab (prod requires Postgres)."""
    return is_lab()


def require_tls() -> bool:
    """TLS required in Production."""
    return is_production()


def require_explicit_secrets() -> bool:
    """Secrets must be explicit in Production (no auto-gen)."""
    return is_production()


# =============================================================================
# PROFILE INFO
# =============================================================================


def get_profile_info() -> dict:
    """Get current profile information for API/health endpoints."""
    return {
        "profile": SENTINEL_PROFILE.value,
        "is_lab": is_lab(),
        "is_production": is_production(),
        "features": {
            "mock_sensor_allowed": allow_mock_sensor(),
            "seed_reset_allowed": allow_seed_reset(),
            "sqlite_allowed": allow_sqlite(),
            "tls_required": require_tls(),
        }
    }
