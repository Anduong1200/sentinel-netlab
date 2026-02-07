"""
Sentinel NetLab - Transport Client
Uploads telemetry batches to controller with retry and backoff.

Security Notes:
- All secrets (auth_token, hmac_secret) should be loaded from environment variables
- TLS is enabled by default (verify_ssl=True); disable only for testing
- HMAC signing provides payload integrity verification

Environment Variables:
- SENSOR_AUTH_TOKEN: Bearer token for API authentication
- SENSOR_HMAC_SECRET: Optional HMAC-SHA256 secret for payload signing
- CONTROLLER_URL: Controller API endpoint (https://...)
- SENSOR_VERIFY_SSL: Set to 'false' only for self-signed certs in dev
"""

import gzip
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def load_config_from_env() -> dict[str, Any]:
    """Load transport configuration from environment variables."""
    return {
        "upload_url": os.environ.get(
            "CONTROLLER_URL", "https://localhost:5000/api/v1/telemetry"
        ),
        "auth_token": os.environ.get("SENSOR_AUTH_TOKEN"),
        "hmac_secret": os.environ.get("SENSOR_HMAC_SECRET"),
        "verify_ssl": os.environ.get("SENSOR_VERIFY_SSL", "true").lower() == "true",
    }


class TransportClient:
    """
    Uploads telemetry to controller API.
    Features:
    - TLS support
    - Retry with exponential backoff
    - Circuit breaker for failure protection
    - Batch compression
    """

    def __init__(
        self,
        upload_url: str,
        auth_token: str,
        timeout: int = 30,
        max_retries: int = 5,
        initial_delay: float = 1.0,
        backoff_factor: float = 2.0,
        max_delay: float = 60.0,
        verify_ssl: bool = True,
        hmac_secret: str | None = None,
    ):
        """
        Initialize transport client.

        Args:
            upload_url: Controller telemetry endpoint
            auth_token: Bearer token for authentication
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            initial_delay: Initial retry delay
            backoff_factor: Exponential backoff factor
            max_delay: Maximum retry delay
            verify_ssl: Verify SSL certificates
            hmac_secret: Optional HMAC secret for payload signing
        """
        self.upload_url = upload_url
        self.auth_token = auth_token
        self.timeout = timeout
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.backoff_factor = backoff_factor
        self.max_delay = max_delay
        self.verify_ssl = verify_ssl
        self.hmac_secret = hmac_secret

        # Stats
        self._uploads_total = 0
        self._uploads_success = 0
        self._uploads_failed = 0
        self._last_upload_time: datetime | None = None
        self._last_error: str | None = None

        # Circuit breaker
        self._circuit_open = False
        self._circuit_failures = 0
        self._circuit_threshold = 5
        self._circuit_reset_time: float | None = None
        self._circuit_reset_delay = 60.0  # seconds

        self._lock = threading.Lock()

        # Time sync state
        self._time_offset = 0.0
        self._last_sync = 0.0
        self._sync_interval = 300  # 5 minutes

    def sync_time(self) -> bool:
        """Sync time with controller"""
        try:
            # Use a lightweight endpoint for sync
            sync_url = self.upload_url.replace("/telemetry", "/time").replace(
                "/api/v1/time", "/api/v1/time"
            )
            # If replacement didn't work (url structure diff), try explicit base
            if "/time" not in sync_url:
                base = self.upload_url.rsplit("/", 3)[0]  # remove /api/v1/telemetry
                sync_url = f"{base}/api/v1/time"

            import requests

            response = requests.get(sync_url, timeout=10, verify=self.verify_ssl)

            if response.status_code == 200:
                data = response.json()
                server_time = data.get("unix_timestamp", time.time())
                local_time = time.time()
                self._time_offset = server_time - local_time
                self._last_sync = local_time
                logger.info(f"Time sync: offset={self._time_offset:.3f}s")
                return True
        except Exception as e:
            logger.debug(f"Time sync failed: {e}")
        return False

    def get_server_time(self) -> datetime:
        """Get estimated server time"""
        # Sync if needed
        if time.time() - self._last_sync > self._sync_interval:
            self.sync_time()

        adjusted = time.time() + self._time_offset
        return datetime.fromtimestamp(adjusted, tz=UTC)

    def upload(self, batch: dict[str, Any], compress: bool = True) -> dict[str, Any]:
        """
        Upload batch to controller.

        Args:
            batch: Batch dict with items
            compress: Compress payload with gzip

        Returns:
            Response dict with success status and ack_id
        """
        import requests

        # Validation
        try:
            # We import here to avoid circular or early import issues if sys.path isn't ready at module level
            from pydantic import ValidationError

            from common.schemas.telemetry import TelemetryBatch

            # Validate
            # Note: batch dict might need adjustment if schema expects strict types
            TelemetryBatch(**batch)
        except ImportError:
            pass  # Pydantic/Schemas not available (e.g. running outside prod env), skip validation
        except ValidationError as e:
            logger.error(f"Schema Validation Failed: {e}")
            return {"success": False, "error": f"Schema Validation Failed: {str(e)}"}

        # Check circuit breaker
        if self._circuit_open:
            if time.time() < self._circuit_reset_time:
                return {
                    "success": False,
                    "error": "Circuit breaker open",
                    "retry_after": self._circuit_reset_time - time.time(),
                }
            else:
                # Try to reset circuit
                self._circuit_open = False
                self._circuit_failures = 0

        self._uploads_total += 1

        # Prepare payload
        payload_str = json.dumps(batch)
        headers = {}  # Initialize headers

        # Compress first
        if compress:
            payload_bytes = gzip.compress(payload_str.encode())
            headers["Content-Encoding"] = "gzip"
            content_encoding = "gzip"
        else:
            payload_bytes = payload_str.encode()
            content_encoding = "identity"

        # Sign if HMAC configured
        # Headers
        import uuid

        request_id = str(uuid.uuid4())
        timestamp = self.get_server_time().isoformat()

        headers.update(
            {
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/json",
                "User-Agent": "Sentinel-Sensor/1.0",
                "X-Idempotency-Key": batch.get("batch_id") or str(time.time()),
                "X-Timestamp": timestamp,
                "X-Request-ID": request_id,
                "X-Sensor-ID": batch.get("sensor_id", "unknown"),
            }
        )

        if self.hmac_secret:
            from urllib.parse import urlparse

            path = urlparse(self.upload_url).path

            # Sign the WIRE BYTES (compressed or not)
            sensor_id = batch.get("sensor_id", "unknown")
            signature = self._sign_payload(
                "POST",
                path,
                payload_bytes,
                timestamp,
                sensor_id=sensor_id,
                content_encoding=content_encoding,
            )
            headers["X-Signature"] = signature

        # Retry loop
        delay = self.initial_delay
        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                response = requests.post(
                    self.upload_url,
                    data=payload_bytes,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )

                if response.status_code in (200, 202):
                    self._on_success()
                    result = response.json()
                    return {
                        "success": True,
                        "ack_id": result.get("ack_id"),
                        "accepted": result.get(
                            "accepted", len(batch.get("items", []))
                        ),  # Use items
                    }

                elif response.status_code == 429:
                    # Rate limit - retry
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        try:
                            delay = float(retry_after)
                        except (ValueError, TypeError):
                            pass
                    last_error = "HTTP 429 (Rate Limit)"
                    logger.warning(f"Upload attempt {attempt + 1} rate limited. Retry after {delay}s")

                elif response.status_code >= 400 and response.status_code < 500:
                    # Client error - don't retry
                    self._on_failure(f"HTTP {response.status_code}")
                    return {
                        "success": False,
                        "error": f"Client error: {response.status_code}",
                        "response": response.text[:500],
                    }

                elif response.status_code == 503:
                    # Backpressure - retry
                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        try:
                            delay = float(retry_after)
                        except (ValueError, TypeError):
                            pass
                    last_error = "HTTP 503 (Backpressure)"
                    logger.warning(f"Upload attempt {attempt + 1} backpressure. Retry after {delay}s")

                else:
                    # Server error - retry
                    last_error = f"HTTP {response.status_code}"
                    logger.warning(f"Upload attempt {attempt + 1} failed: {last_error}")

            except requests.exceptions.Timeout:
                last_error = "Request timeout"
                logger.warning(f"Upload timeout on attempt {attempt + 1}")

            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection error: {str(e)[:100]}"
                logger.warning(f"Connection error on attempt {attempt + 1}")

            except Exception as e:
                last_error = str(e)[:100]
                logger.error(f"Unexpected upload error: {e}")

            # Wait before retry
            if attempt < self.max_retries:
                jitter = delay * 0.1 * (2 * (0.5 - time.time() % 1))  # Simple jitter
                sleep_time = min(delay + jitter, self.max_delay)
                time.sleep(sleep_time)
                delay *= self.backoff_factor

        # All retries failed
        self._on_failure(last_error)
        return {"success": False, "error": last_error, "retries_exhausted": True}

    def _sign_payload(
        self,
        method: str,
        path: str,
        payload: bytes | str,
        timestamp: str,
        sensor_id: str,
        sequence: str | None = None,
        content_encoding: str = "identity",
    ) -> str:
        """Sign payload with HMAC-SHA256 (Canonical: method\npath\ntimestamp\nsensor_id\nencoding\nbody)"""
        # V1 Canonical String Format (newline delimited)
        parts = [method, path, timestamp, sensor_id, content_encoding]

        # We process payload separately to avoid large string copies if possible,
        # but hmac.update needs bytes.

        # Build layout:
        # method\n
        # path\n
        # timestamp\n
        # sensor_id\n
        # content_encoding\n
        # body_bytes

        canonical_meta = "\n".join(parts) + "\n"

        h = hmac.new(self.hmac_secret.encode(), digestmod=hashlib.sha256)
        h.update(canonical_meta.encode())

        if isinstance(payload, str):
            h.update(payload.encode())
        else:
            h.update(payload)

        return h.hexdigest()

    def _on_success(self) -> None:
        """Called on successful upload"""
        with self._lock:
            self._uploads_success += 1
            self._last_upload_time = datetime.now(UTC)
            self._circuit_failures = 0

    def _on_failure(self, error: str) -> None:
        """Called on failed upload"""
        with self._lock:
            self._uploads_failed += 1
            self._last_error = error
            self._circuit_failures += 1

            # Open circuit breaker if threshold exceeded
            if self._circuit_failures >= self._circuit_threshold:
                self._circuit_open = True
                self._circuit_reset_time = time.time() + self._circuit_reset_delay
                logger.warning("Circuit breaker opened due to repeated failures")

    def upload_alert(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """
        Upload alert to controller immediately.

        Args:
            alert_data: Alert dict matching AlertCreate schema

        Returns:
            Response dict with success status
        """
        import requests

        # Construct alerts URL (replace /telemetry with /alerts)
        alerts_url = self.upload_url.replace("/telemetry", "/alerts")
        if "/alerts" not in alerts_url:  # fallback if url structure differs
            base = self.upload_url.rsplit("/", 3)[0]
            alerts_url = f"{base}/api/v1/alerts"

        # Headers with Auth and Signing
        timestamp = self.get_server_time().isoformat()
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
            "User-Agent": "Sentinel-Sensor/1.0",
            "X-Timestamp": timestamp,
        }

        payload = json.dumps(alert_data)

        if self.hmac_secret:
            from urllib.parse import urlparse

            path = urlparse(alerts_url).path
            # For alerts, sensor_id might be inside payload or context.
            # We should probably pass it if available.
            # Assuming alert_data has 'sensor_id' is risky if not ensured.
            # But the header X-Sensor-ID isn't set above in upload_alert?
            # Let's add X-Sensor-ID to headers first.
            s_id = alert_data.get("sensor_id", "unknown")
            headers["X-Sensor-ID"] = s_id

            headers["X-Signature"] = self._sign_payload(
                "POST", path, payload, timestamp, sensor_id=s_id
            )

        try:
            response = requests.post(
                alerts_url,
                data=payload,
                headers=headers,
                timeout=10,
                verify=self.verify_ssl,
            )

            if response.status_code == 200:
                logger.info(f"Alert uploaded successfully: {alert_data.get('title')}")
                return {"success": True, "alert_id": response.json().get("alert_id")}
            else:
                logger.error(
                    f"Alert upload failed: HTTP {response.status_code} {response.text}"
                )
                return {"success": False, "error": f"HTTP {response.status_code}"}

        except Exception as e:
            logger.error(f"Alert upload error: {e}")
            return {"success": False, "error": str(e)}

    def heartbeat(self, status: dict[str, Any]) -> dict[str, Any]:
        """
        Send heartbeat to controller.

        Args:
            status: Sensor status dict

        Returns:
            Response with optional commands
        """
        import requests

        heartbeat_url = self.upload_url.replace("/telemetry", "/heartbeat")

        try:
            response = requests.post(
                heartbeat_url,
                json=status,
                headers={"Authorization": f"Bearer {self.auth_token}"},
                timeout=10,
                verify=self.verify_ssl,
            )

            if response.status_code == 200:
                return {
                    "success": True,
                    "commands": response.json().get("commands", []),
                }

        except Exception as e:
            logger.debug(f"Heartbeat failed: {e}")

        return {"success": False, "commands": []}

    def get_stats(self) -> dict[str, Any]:
        """Get transport statistics"""
        with self._lock:
            return {
                "uploads_total": self._uploads_total,
                "uploads_success": self._uploads_success,
                "uploads_failed": self._uploads_failed,
                "success_rate": (
                    self._uploads_success / self._uploads_total * 100
                    if self._uploads_total > 0
                    else 0
                ),
                "last_upload": (
                    self._last_upload_time.isoformat()
                    if self._last_upload_time
                    else None
                ),
                "last_error": self._last_error,
                "circuit_open": self._circuit_open,
                "circuit_failures": self._circuit_failures,
            }
