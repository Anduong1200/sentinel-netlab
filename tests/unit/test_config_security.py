
import os
import pytest
from unittest.mock import patch
from controller.config import init_config, ControllerConfig

class TestConfigSecurity:
    """Verify configuration security policies"""
    
    def test_production_fail_fast_missing_secrets(self):
        """Test A: strict production check fails if secrets missing"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}, clear=True):
            with pytest.raises(RuntimeError) as excinfo:
                init_config(strict_production=True)
            assert "Missing required production secrets" in str(excinfo.value)
            assert "CONTROLLER_SECRET_KEY" in str(excinfo.value)

    def test_development_fallback_defaults(self):
        """Test B: development mode allows defaults with warning"""
        with patch.dict(os.environ, {"ENVIRONMENT": "development"}, clear=True):
            config = init_config()
            assert config.security.secret_key == "dev-secret-unsafe-do-not-use-in-prod"
            assert config.debug is True

    def test_safe_logging_redaction(self):
        """Test C: safe_dict does not leak secrets"""
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "CONTROLLER_SECRET_KEY": "super_secret_key",
            "CONTROLLER_HMAC_SECRET": "super_hmac_secret",
            "CONTROLLER_DATABASE_URL": "postgresql://user:pass@localhost/db"
        }, clear=True):
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
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "CONTROLLER_SECRET_KEY": "my-secret",
            "CONTROLLER_HMAC_SECRET": "my-hmac",
            "CONTROLLER_DATABASE_URL": "sqlite:///prod.db",
            "CONTROLLER_PORT": "9000"
        }, clear=True):
            config = init_config()
            assert config.port == 9000
            assert config.security.secret_key == "my-secret"
