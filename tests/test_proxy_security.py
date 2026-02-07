
import unittest
from unittest.mock import patch, MagicMock
from flask import Flask, jsonify
import os

# Import the middleware and related configs
from controller.api.middleware import TrustedProxyMiddleware
from controller.api import auth

class TestProxySecurity(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        
        # Configure App defaults
        self.app.config["SECURITY_REQUIRE_TLS"] = True
        
        # Mock config
        self.config_patcher = patch("controller.api.auth.config")
        self.mock_config = self.config_patcher.start()
        self.mock_config.security.require_tls = True
        self.mock_config.security.trusted_proxies = ["10.0.0.1/32"] # Trust only this IP
        
        # Setup route with auth.require_auth (which checks TLS)
        @self.app.route("/secure")
        @auth.require_auth()
        def secure_endpoint():
            return jsonify({"status": "ok"})
            
        # Apply Middleware
        # We simulate the production setup where middleware is wrapping the app
        self.app.wsgi_app = TrustedProxyMiddleware(
            self.app.wsgi_app,
            trusted_cidrs=["10.0.0.1/32"],
            x_for=1, x_proto=1
        )

    def tearDown(self):
        self.config_patcher.stop()

    def test_untrusted_proxy_spoofing(self):
        """Test that untrusted IP cannot spoof X-Forwarded-Proto"""
        with self.app.test_client() as client:
            # Attacker IP: 1.2.3.4 (Untrusted)
            # Headers: X-Forwarded-Proto: https
            # Middlewares: TrustedProxyMiddleware checks REMOTE_ADDR
            # Expectation: Middleware sees 1.2.3.4 != 10.0.0.1 -> Does NOT apply ProxyFix.
            # WSGI environ['wsgi.url_scheme'] remains 'http'.
            # auth.require_auth checks request.is_secure -> False -> 403
            
            resp = client.get(
                "/secure",
                environ_base={"REMOTE_ADDR": "1.2.3.4"},
                headers={"X-Forwarded-Proto": "https"}
            )
            self.assertEqual(resp.status_code, 403)
            self.assertIn("HTTPS required", resp.json["error"])

    def test_trusted_proxy_success(self):
        """Test that trusted IP CAN set X-Forwarded-Proto"""
        with self.app.test_client() as client:
            # Proxy IP: 10.0.0.1 (Trusted)
            # Headers: X-Forwarded-Proto: https
            # Expectation: Middleware applies ProxyFix. url_scheme -> https.
            # auth.require_auth -> request.is_secure=True.
            # Then it might fail on Token (401) or succeed if we mock token.
            # We didn't mock token verify, so it should return 401 (Missing auth) NOT 403 (HTTPS).
            
            resp = client.get(
                "/secure",
                environ_base={"REMOTE_ADDR": "10.0.0.1"},
                headers={"X-Forwarded-Proto": "https"}
            )
            # 401 means it passed TLS check and hit Token check
            self.assertEqual(resp.status_code, 401)
            self.assertIn("Missing authentication", resp.json["error"])

    def test_trusted_proxy_requires_header(self):
        """Test that even trusted proxy must send HTTPS header"""
        with self.app.test_client() as client:
            # Trusted IP but NO header (or http)
            resp = client.get(
                "/secure",
                environ_base={"REMOTE_ADDR": "10.0.0.1"},
                headers={"X-Forwarded-Proto": "http"}
            )
            self.assertEqual(resp.status_code, 403)
            self.assertIn("HTTPS required", resp.json["error"])

if __name__ == "__main__":
    unittest.main()
