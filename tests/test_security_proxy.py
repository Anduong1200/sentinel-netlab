from unittest.mock import Mock

import pytest

from controller.security.proxy import TrustedProxyMiddleware


@pytest.fixture
def mock_app():
    app = Mock()
    app.return_value = ["OK"]
    return app


def test_trusted_proxy_passthrough(mock_app):
    """Verify headers are preserved for trusted IPs."""
    middleware = TrustedProxyMiddleware(
        mock_app, trusted_cidrs=["10.0.0.1", "172.16.0.0/12"]
    )

    environ = {
        "REMOTE_ADDR": "10.0.0.1",
        "HTTP_X_FORWARDED_FOR": "203.0.113.5",
        "HTTP_X_FORWARDED_PROTO": "https",
    }

    middleware(environ, Mock())

    assert "HTTP_X_FORWARDED_FOR" in environ
    assert environ["HTTP_X_FORWARDED_FOR"] == "203.0.113.5"
    assert "HTTP_X_FORWARDED_PROTO" in environ


def test_untrusted_proxy_stripping(mock_app):
    """Verify headers are STRIPPED for untrusted IPs."""
    middleware = TrustedProxyMiddleware(mock_app, trusted_cidrs=["10.0.0.1"])

    environ = {
        "REMOTE_ADDR": "192.168.1.100",  # Untrusted
        "HTTP_X_FORWARDED_FOR": "spoofed-ip",
        "HTTP_X_FORWARDED_PROTO": "https",
    }

    middleware(environ, Mock())

    assert "HTTP_X_FORWARDED_FOR" not in environ
    assert "HTTP_X_FORWARDED_PROTO" not in environ


def test_subnet_matching(mock_app):
    """Verify CIDR matching logic."""
    middleware = TrustedProxyMiddleware(mock_app, trusted_cidrs=["172.16.0.0/12"])

    # 172.16... is trusted
    environ = {
        "REMOTE_ADDR": "172.20.0.5",
        "HTTP_X_FORWARDED_FOR": "real-ip",
    }
    middleware(environ, Mock())
    assert "HTTP_X_FORWARDED_FOR" in environ

    # 192.168... is untrusted
    environ = {
        "REMOTE_ADDR": "192.168.1.5",
        "HTTP_X_FORWARDED_FOR": "real-ip",
    }
    middleware(environ, Mock())
    assert "HTTP_X_FORWARDED_FOR" not in environ


def test_tls_enforcement_pass(mock_app):
    """Verify HTTPS allowed."""
    middleware = TrustedProxyMiddleware(
        mock_app, trusted_cidrs=["10.0.0.1"], require_tls=True
    )

    environ = {
        "REMOTE_ADDR": "10.0.0.1",
        "HTTP_X_FORWARDED_PROTO": "https",
        "PATH_INFO": "/api/v1/data",
    }

    resp = middleware(environ, Mock())
    assert resp == ["OK"]


def test_tls_enforcement_block(mock_app):
    """Verify HTTP blocked."""
    middleware = TrustedProxyMiddleware(
        mock_app, trusted_cidrs=["10.0.0.1"], require_tls=True
    )

    environ = {
        "REMOTE_ADDR": "10.0.0.1",
        "HTTP_X_FORWARDED_PROTO": "http",  # Not HTTPS
        "PATH_INFO": "/api/v1/data",
    }

    start_response = Mock()
    middleware(environ, start_response)

    # Expect 403 or redirect? We implemented 403 "HTTPS Required"
    # The middleware calls start_response with 403
    start_response.assert_called()
    args, _ = start_response.call_args
    assert args[0] == "403 FORBIDDEN" or args[0].startswith("403")


def test_tls_healthcheck_bypass(mock_app):
    """Verify Healthcheck bypasses TLS check."""
    middleware = TrustedProxyMiddleware(
        mock_app, trusted_cidrs=["10.0.0.1"], require_tls=True
    )

    environ = {
        "REMOTE_ADDR": "10.0.0.1",
        "HTTP_X_FORWARDED_PROTO": "http",  # HTTP
        "PATH_INFO": "/api/v1/health",  # Allowed Path
    }

    resp = middleware(environ, Mock())
    assert resp == ["OK"]
