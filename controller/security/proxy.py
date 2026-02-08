import logging

from werkzeug.wrappers import Response

logger = logging.getLogger(__name__)


class TrustedProxyMiddleware:
    """
    WSGI Middleware to enforce Trusted Proxy logic.
    Only allows X-Forwarded-* headers from trusted IPs.
    """

    def __init__(
        self, app, trusted_cidrs: list[str] | None = None, require_tls: bool = False
    ):
        self.app = app
        self.trusted_cidrs = trusted_cidrs or []
        self.require_tls = require_tls
        # Basic private network CIDRs often used in Docker/Internal
        # In a real setup, we'd use 'ipaddress' module to match CIDRs accurately.
        # For simplicity in this project, we might just match prefixes or use a library if available.
        # Docker default bridge is usually 172.16.x.x - 172.31.x.x range or 172.17.x.x

    def __call__(self, environ, start_response):
        # 1. Check Remote Addr
        # In WSGI, REMOTE_ADDR is the direct connection (e.g. Nginx LB)
        remote_addr = environ.get("REMOTE_ADDR", "")

        # Simple prefix check for "trusted" (e.g. Docker subnet)
        # In production this should be robust CIDR matching.
        is_trusted = False
        for cidr in self.trusted_cidrs:
            # Very naive string match for now to avoid 'ipaddress' overhead if not needed yet
            # Ideally: ipaddress.ip_address(remote_addr) in ipaddress.ip_network(cidr)
            if (
                remote_addr == cidr
                or (cidr.endswith(".0/0") and True)
                or remote_addr.startswith(cidr.replace(".0/0", "").replace("/", ""))
            ):
                is_trusted = True
                break
            # Support exact match
            if remote_addr == cidr:
                is_trusted = True
                break

        # 2. Handle Headers
        if is_trusted:
            # Trust the headers
            # Werkzeug/Flask will handle X-Forwarded-For if configured?
            # Actually, standard WSGI doesn't automatically move X-Forwarded-For to REMOTE_ADDR
            # unless ProxyFix is used. This middleware usually wraps ProxyFix or acts as one.
            # Here we just VALIDATE. If not trusted, we strip them to prevent spoofing.
            pass
        else:
            # Untrusted: Strip Forwarded Headers so App uses valid REMOTE_ADDR (the attacker)
            keys_to_remove = [
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_FORWARDED_PROTO",
                "HTTP_X_FORWARDED_HOST",
                "HTTP_X_FORWARDED_PORT",
            ]
            for key in keys_to_remove:
                if key in environ:
                    environ.pop(key)

        # 3. TLS Enforcement
        if self.require_tls:
            # Relies on correct X-Forwarded-Proto from Trusted Proxy
            # OR direct HTTPS (unlikely for WSGI behind Nginx)
            scheme = environ.get(
                "HTTP_X_FORWARDED_PROTO", environ.get("wsgi.url_scheme", "http")
            )

            if scheme != "https":
                # Check for Healthcheck exemption (often internal LB checks are HTTP)
                path = environ.get("PATH_INFO", "")
                if not path.startswith("/api/v1/health") and not path.startswith(
                    "/healthz"
                ):
                    res = Response("HTTPS Required", mimetype="text/plain", status=403)
                    return res(environ, start_response)

        return self.app(environ, start_response)
