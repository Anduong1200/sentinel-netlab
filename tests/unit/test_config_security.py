import os
from unittest.mock import patch

import pytest

from controller.config import init_config


class TestConfigSecurity:
    """Verify configuration security policies"""

    def test_production_fail_fast_missing_secrets(self):
        """Test A: strict production check fails if secrets missing"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}, clear=True):
            with pytest.raises(RuntimeError) as excinfo:
                init_config(strict_production=True)
            # Check for key components of error message
            assert "CONTROLLER_SECRET_KEY" in str(excinfo.value)
            assert "production" in str(excinfo.value).lower()

    def test_development_fallback_defaults(self):
        """Test B: development mode allows defaults with warning"""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}, clear=True):
            config = init_config()
            # In dev mode, auto-generated secrets are used instead of hardcoded defaults
            assert config.security.secret_key is not None
            assert len(config.security.secret_key) >= 16  # Auto-generated hex string
            assert config.debug is True

    def test_safe_logging_redaction(self):
        """Test C: safe_dict does not leak secrets"""
        # Use secrets long enough to pass validation (>= 32 chars for HMAC, >= 16 for secret)
        with patch.dict(
            os.environ,
            {
                "ENVIRONMENT": "production",
                "CONTROLLER_SECRET_KEY": "super_secret_key_long_enough_1234",
                "CONTROLLER_HMAC_SECRET": "super_hmac_secret_long_enough_12345678",
                "CONTROLLER_DATABASE_URL": "postgresql://user:pass@localhost/db",
                "REDIS_URL": "redis://localhost:6379/0",
            },
            clear=True,
        ):
            config = init_config()
            safe = config.safe_dict()

            # Check secrets are NOT present
            assert safe["security"]["secret_key"] == "***"
            assert safe["security"]["hmac_secret"] == "***"
            assert "super_secret_key" not in str(safe)

            # Check DB URL safety (should mask password if implemented, or at least structure)
            # Implementation simple specific: "url": self.url.split("@")[-1]...
            assert "pass" not in safe["database"]["url"]

    def test_env_precedence(self):
        """Verify explicit variables override defaults"""
        # Use secrets long enough to pass validation
        with patch.dict(
            os.environ,
            {
                "ENVIRONMENT": "production",
                "CONTROLLER_SECRET_KEY": "my_secret_key_long_enough_1234",
                "CONTROLLER_HMAC_SECRET": "my_hmac_secret_long_enough_12345678",
                "CONTROLLER_DATABASE_URL": "sqlite:///prod.db",
                "CONTROLLER_PORT": "9000",
                "REDIS_URL": "redis://localhost:6379/0",
            },
            clear=True,
        ):
            config = init_config()
            assert config.port == 9000
            assert config.security.secret_key == "my_secret_key_long_enough_1234"
