"""
Controller Middleware for Observability.
Handles:
- Request ID generation/propagation
- Context binding (sensor_id, batch_id)
- Structured Access Logging
"""

import logging
import time
import uuid
from ipaddress import ip_address, ip_network

from werkzeug.middleware.proxy_fix import ProxyFix

from common.observability import context

logger = logging.getLogger("controller.access")


class ObservabilityMiddleware:
    """
    WSGI Middleware to initialize observability context and log requests.
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # 1. Start Timing
        start_time = time.time()

        # 2. Extract/Generate Request ID
        request_id = environ.get("HTTP_X_REQUEST_ID")
        if not request_id:
            request_id = str(uuid.uuid4())

        # 3. Extract other context headers
        sensor_id = environ.get("HTTP_X_SENSOR_ID")
        batch_id = environ.get("HTTP_X_BATCH_ID")

        # 4. Set Context (Thread-local / Async-local)
        context.set_context(
            request_id=request_id, sensor_id=sensor_id, batch_id=batch_id
        )

        # 5. Capture Response Status for Logging
        status_info = {"code": "500"}  # Default if app crashes

        def custom_start_response(status, headers, exc_info=None):
            status_info["code"] = status.split()[0]

            # Echo X-Request-ID
            headers.append(("X-Request-ID", request_id))

            return start_response(status, headers, exc_info)

        # 6. Execute App
        try:
            response_chunks = self.app(environ, custom_start_response)
            return response_chunks
        finally:
            # 7. Access Logging (Structured)
            duration_ms = (time.time() - start_time) * 1000

            # Extract request details safely
            method = environ.get("REQUEST_METHOD")
            path = environ.get("PATH_INFO")
            query = environ.get("QUERY_STRING")
            if query:
                path = f"{path}?{query}"

            # Log event if not health check (optional noise reduction)
            # User didn't request filtering, but usually /health is noisy.
            # Keeping it for now as per "Access Log" requirement.

            log_data = {
                "event": "http.request",
                "method": method,
                "path": path,
                "status": status_info["code"],
                "duration_ms": round(duration_ms, 2),
                "ip": environ.get("REMOTE_ADDR"),
                "user_agent": environ.get("HTTP_USER_AGENT"),
            }

            logger.info("Access Log", extra={"data": log_data})

            context.clear_context()





class TrustedProxyMiddleware:
    """
    Conditionally apply ProxyFix only if the request comes from a trusted proxy.
    This prevents header spoofing from untrusted sources while allowing
    correct IP/Proto resolution from Nginx/LoadBalancer.
    """

    def __init__(
        self,
        app,
        trusted_cidrs: list[str],
        x_for: int = 1,
        x_proto: int = 1,
        x_host: int = 1,
        x_port: int = 1,
        x_prefix: int = 1,
    ):
        self.app = app
        self.trusted_cidrs = [
            ip_network(cidr, strict=False) for cidr in trusted_cidrs if cidr.strip()
        ]
        # Configure ProxyFix to trust the specified number of proxies
        self.proxy_fix = ProxyFix(
            app,
            x_for=x_for,
            x_proto=x_proto,
            x_host=x_host,
            x_port=x_port,
            x_prefix=x_prefix,
        )

    def __call__(self, environ, start_response):
        remote_addr = environ.get("REMOTE_ADDR")
        is_trusted = False

        if remote_addr:
            try:
                ip = ip_address(remote_addr)
                for net in self.trusted_cidrs:
                    if ip in net:
                        is_trusted = True
                        break
            except ValueError:
                # Invalid IP in REMOTE_ADDR? Treat as untrusted.
                pass

        if is_trusted:
            # Apply ProxyFix (trust headers)
            return self.proxy_fix(environ, start_response)
        else:
            # Untrusted: Do NOT apply ProxyFix (ignore headers)
            return self.app(environ, start_response)
