import os
from unittest.mock import patch

import pytest

from common.security.secrets import redact, require_secret


def test_require_secret_prod_missing():
    """Verify require_secret raises RuntimeError in prod if missing"""
    with pytest.raises(RuntimeError, match="CRITICAL"):
        require_secret("Test Secret", "TEST_SECRET_MISSING", env="production")


def test_require_secret_prod_weak():
    """Verify require_secret raises RuntimeError in prod if weak"""
    with patch.dict(os.environ, {"TEST_WEAK": "123456"}):
        with pytest.raises(RuntimeError, match="CRITICAL: Weak production secret"):
            require_secret("Test Secret", "TEST_WEAK", env="production")


def test_require_secret_dev_autogen():
    """Verify require_secret generates secret in dev if missing"""
    val = require_secret(
        "Test Secret", "TEST_MISSING_DEV", allow_dev_autogen=True, env="development"
    )
    assert len(val) >= 8


def test_require_secret_dev_weak_warns(caplog):
    """Verify require_secret warns (not raises) in dev if weak"""
    with patch.dict(os.environ, {"TEST_WEAK": "password"}):
        val = require_secret("Test Secret", "TEST_WEAK", env="development")
        assert val == "password"
        assert "Weak secret" in caplog.text


def test_redact():
    val = "supersecretpassword"
    stars = "*" * (len(val) - 4)
    expected = val[:2] + stars + val[-2:]
    assert redact(val) == expected
    assert redact("short") == "sh*rt"
    assert redact("123") == "***"
    assert redact("") == "<empty>"
