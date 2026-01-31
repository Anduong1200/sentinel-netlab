# tests/test_config.py
import importlib

import pytest

from controller import config as config_mod


def test_init_config_production_missing_secrets(monkeypatch):
    """Verify that accessing config in production without secrets raises RuntimeError"""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("CONTROLLER_SECRET_KEY", raising=False)
    monkeypatch.delenv("CONTROLLER_HMAC_SECRET", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("CONTROLLER_DATABASE_URL", raising=False)

    # Force reload to pick up env change if it was module-level cached (it's not, but good practice)
    importlib.reload(config_mod)

    with pytest.raises(RuntimeError) as excinfo:
        config_mod.init_config(strict_production=True)

    assert "Application refused to start in PRODUCTION mode without these secrets" in str(excinfo.value)


def test_init_config_dev_allows_missing(monkeypatch):
    """Verify that development mode allows missing secrets with warnings"""
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("CONTROLLER_SECRET_KEY", raising=False)

    importlib.reload(config_mod)
    cfg = config_mod.init_config(strict_production=True)

    assert cfg.environment == "development"
    assert cfg.security.secret_key == "dev-secret-unsafe-do-not-use-in-prod"


def test_safe_dict_redaction():
    """Verify that secrets are redacted in safe_dict()"""
    cfg = config_mod.ControllerConfig(
        environment="test",
        security=config_mod.SecurityConfig(secret_key="SECRET", hmac_secret="HMAC"),
        database=config_mod.DatabaseConfig(url="sqlite:///"),
    )

    safe = cfg.safe_dict()
    assert safe["security"]["secret_key"] == "***"
    assert safe["security"]["hmac_secret"] == "***"
    assert safe["security"]["secret_key"] != "SECRET"
