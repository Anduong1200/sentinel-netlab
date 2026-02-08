import pytest
from flask import Flask, jsonify, request
from controller.api.middleware import TrustedProxyMiddleware

# Helper to create a minimal app with the middleware
@pytest.fixture
def proxy_app():
    app = Flask(__name__)
    
    # Configure Middleware trusting 127.0.0.1 and 10.0.0.0/8
    # We use x_for=1, x_proto=1 (standard Nginx setup)
    app.wsgi_app = TrustedProxyMiddleware(
        app.wsgi_app,
        trusted_cidrs=["127.0.0.1", "10.0.0.0/8"],
        x_for=1,
        x_proto=1
    )
    
    @app.route("/debug")
    def debug():
        return jsonify({
            "remote_addr": request.remote_addr,
            "is_secure": request.is_secure,
            "scheme": request.scheme,
            "x_forwarded_proto": request.headers.get("X-Forwarded-Proto"),
            "x_forwarded_for": request.headers.get("X-Forwarded-For"),
        })

    return app

def test_direct_untrusted_spoofing(proxy_app):
    """
    Scenario: Attacker connects directly (simulated IP 1.2.3.4).
    Sends spoofed XFP: https.
    
    Expected:
    - Middleware sees 1.2.3.4 (Not active).
    - ProxyFix is NOT applied.
    - is_secure = False (http).
    - remote_addr = 1.2.3.4.
    """
    client = proxy_app.test_client()
    
    # Simulate request from untrusted IP
    environ_overrides = {"REMOTE_ADDR": "1.2.3.4"}
    
    headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-For": "5.6.7.8"
    }
    
    resp = client.get("/debug", headers=headers, environ_base=environ_overrides)
    data = resp.json
    
    assert data["remote_addr"] == "1.2.3.4"
    assert data["is_secure"] is False, "Should ignore XFP from untrusted IP"
    assert data["scheme"] == "http"

def test_trusted_proxy_handling(proxy_app):
    """
    Scenario: Request comes from Trusted Proxy (10.0.0.1).
    Proxy adds XFP: https, XFF: real_client.
    
    Expected:
    - Middleware sees 10.0.0.1 (Trusted).
    - ProxyFix IS applied.
    - is_secure = True.
    - remote_addr = real_client.
    """
    client = proxy_app.test_client()
    
    # Simulate request from Trusted IP
    environ_overrides = {"REMOTE_ADDR": "10.0.0.1"}
    
    headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-For": "203.0.113.55"  # Valid public IP
    }
    
    resp = client.get("/debug", headers=headers, environ_base=environ_overrides)
    data = resp.json
    
    assert data["remote_addr"] == "203.0.113.55"
    assert data["is_secure"] is True
    assert data["scheme"] == "https"

def test_trusted_proxy_double_spoof(proxy_app):
    """
    Scenario: Attacker (1.2.3.4) sends XFF: spoofed.
    Proxy (10.0.0.1) appends client IP.
    Header: spoofed, 1.2.3.4
    
    Expected (x_for=1):
    - remote_addr = 1.2.3.4 (The last IP, which is the actual client connecting to proxy).
    - spoofed IP is ignored/left in header but not used for remote_addr.
    """
    client = proxy_app.test_client()
    
    environ_overrides = {"REMOTE_ADDR": "10.0.0.1"}
    
    # Nginx would append: "spoofed, real_ip"
    headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-For": "192.168.1.5, 1.2.3.4" 
    }
    
    resp = client.get("/debug", headers=headers, environ_base=environ_overrides)
    data = resp.json
    
    # With x_for=1, it takes the LAST one.
    assert data["remote_addr"] == "1.2.3.4"
    assert data["is_secure"] is True
