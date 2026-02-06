import logging
import os
import secrets

logger = logging.getLogger(__name__)

# Known weak/default passwords to reject in production
WEAK_PASSWORDS = {
    "admin", "password", "123456", "sentinel",
    "admin123", "secret", "changeme", "sentinel-dev-2024"
}  # noqa: S105

def require_secret(
    name: str,
    env_var: str,
    *,
    min_len: int = 8,
    allow_dev_autogen: bool = False,
    env: str = "production"
) -> str:
    """
    Retrieve a secret from environment variables with fail-fast enforcement.

    Args:
        name: Human-readable name of the secret (e.g. "Database Password")
        env_var: The environment variable key (e.g. "DB_PASS")
        min_len: Minimum acceptable length for the secret
        allow_dev_autogen: If True and env != 'production', generate a random secret if missing
        env: Current environment ('production', 'development', 'lab')

    Returns:
        The secret string.

    Raises:
        RuntimeError: If secret is missing or weak in production.
    """
    val = os.getenv(env_var)
    is_prod = env.lower() == "production"

    # 1. Check Presence
    if not val:
        if is_prod:
            msg = f"CRITICAL: Missing required production secret '{env_var}' ({name}). Application refused to start."
            logger.critical(msg)
            raise RuntimeError(msg)

        if allow_dev_autogen:
            val = secrets.token_hex(min_len)
            logger.warning(f"DEV MODE: Auto-generated ephemeral secret for '{env_var}'. Do not use in production.")
        else:
            # Even in dev, if allow_dev_autogen is False, we might want to fail or just warn and return empty?
            # Typically if it's required, we should fail or return a known dev default if provided.
            # But here we assume if it's not autogen-able, it might be strictly required or user forgot.
            # Let's fallback to strict fail if no autogen allowed, unless user handles it.
            # For this utility, we'll raise if missing and no autogen strategy.
            msg = f"Missing secret '{env_var}' ({name}). Set it in .env or environment."
            logger.warning(msg)
            raise RuntimeError(msg)

    # 2. Validate Strength (Prod Only or High Security)
    # We check blacklist for everyone to discourage bad habits, but only hard fail in prod
    validation_error = _validate_strength(val, min_len)

    if validation_error:
        if is_prod:
            safe_msg = f"CRITICAL: Weak production secret '{env_var}': {validation_error}. Application refused to start."
            logger.critical(safe_msg)
            raise RuntimeError(safe_msg)
        else:
            logger.warning(f"Weak secret for '{env_var}': {validation_error} (Allowed in {env})")

    return val

def _validate_strength(val: str, min_len: int) -> str | None:
    if len(val) < min_len:
        return f"Length {len(val)} < {min_len}"

    if val.lower() in WEAK_PASSWORDS:
        return "Value is in blacklist of common weak passwords"

    return None

def redact(val: str) -> str:
    """Return redacted string for logging"""
    if not val:
        return "<empty>"
    if len(val) < 4:
        return "*" * len(val)
    return val[:2] + "*" * (len(val) - 4) + val[-2:]
