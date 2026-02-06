"""
Sentinel NetLab - Health Server
Simple HTTP server for health checks (e.g. Docker, systemd).
"""

import http.server
import json
import logging
import threading
from collections.abc import Callable
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


class HealthHandler(http.server.BaseHTTPRequestHandler):
    """Handles health check requests"""

    def do_GET(self):
        if self.path == "/healthz":
            try:
                # specific health check logic
                # The server instance has the callback attached
                status = self.server.get_status_callback()

                # Determine overall health
                # Basic rules: capturing? uploading not stuck?
                is_healthy = True
                if not status.get("running"):
                    is_healthy = False

                # Prepare response
                import time

                # Derive metrics
                queue_stats = status.get("queue", {})
                worker_stats = status.get("upload_worker", {})
                threads = status.get("threads", {})

                # Calculate offsets
                last_upload = worker_stats.get("last_upload_time")
                age_sec = -1
                if last_upload:
                    if isinstance(last_upload, str):
                        # Parse if string (ISO)
                        try:
                            t_iso = datetime.fromisoformat(last_upload).timestamp()
                            age_sec = round(time.time() - t_iso, 1)
                        except (ValueError, TypeError):
                            pass
                    elif isinstance(last_upload, (int, float)):
                        age_sec = round(time.time() - last_upload, 1)

                response = {
                    "ok": is_healthy,
                    "backlog": queue_stats.get("queued", 0), # Correct key 'queued' from queue.stats()
                    "last_send_success_age_sec": age_sec,
                    "capture_alive": threads.get("capture", False),
                    "sender_alive": threads.get("worker", False),
                    "sensor_id": status.get("sensor_id"),
                    "uptime": status.get("uptime_seconds"),
                }

                self.send_response(200 if is_healthy else 503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())

            except Exception as e:
                logger.error(f"Health check failed: {e}")
                self.send_error(500, str(e))

        elif self.path == "/metrics":
            from common.observability.metrics import metrics_endpoint
            data, content_type = metrics_endpoint()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(data)

        else:
            self.send_error(404)

    def log_message(self, format, *args):
        # Suppress request logging to avoid cluttering main logs
        pass


class HealthServer:
    """
    Background thread running a simple HTTP server.
    """

    def __init__(self, port: int, get_status_callback: Callable[[], dict[str, Any]]):
        self.port = port
        self.get_status_callback = get_status_callback
        self._thread: threading.Thread | None = None
        self._httpd: http.server.HTTPServer | None = None

    def start(self):
        """Start the server in a background thread."""
        try:
            # Bind to localhost only for security
            self._httpd = http.server.HTTPServer(("127.0.0.1", self.port), HealthHandler)
            # Attach callback to server instance so handler can access it
            self._httpd.get_status_callback = self.get_status_callback # type: ignore

            self._thread = threading.Thread(target=self._run, daemon=True, name="HealthServer")
            self._thread.start()
            logger.info(f"Health server started on 127.0.0.1:{self.port}")
        except Exception as e:
            logger.error(f"Failed to start health server: {e}")

    def _run(self):
        if self._httpd:
            self._httpd.serve_forever()

    def stop(self):
        """Stop the server."""
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
