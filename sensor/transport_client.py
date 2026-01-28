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
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


def load_config_from_env() -> dict[str, Any]:
    """Load transport configuration from environment variables."""
    return {
        'upload_url': os.environ.get('CONTROLLER_URL', 'https://localhost:5000/api/v1/telemetry'),
        'auth_token': os.environ.get('SENSOR_AUTH_TOKEN'),
        'hmac_secret': os.environ.get('SENSOR_HMAC_SECRET'),
        'verify_ssl': os.environ.get('SENSOR_VERIFY_SSL', 'true').lower() == 'true',
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
        hmac_secret: Optional[str] = None
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
        self._last_upload_time: Optional[datetime] = None
        self._last_error: Optional[str] = None

        # Circuit breaker
        self._circuit_open = False
        self._circuit_failures = 0
        self._circuit_threshold = 5
        self._circuit_reset_time: Optional[float] = None
        self._circuit_reset_delay = 60.0  # seconds

        self._lock = threading.Lock()

    def upload(
        self,
        batch: dict[str, Any],
        compress: bool = True
    ) -> dict[str, Any]:
        """
        Upload batch to controller.

        Args:
            batch: Batch dict with items
            compress: Compress payload with gzip

        Returns:
            Response dict with success status and ack_id
        """
        import requests

        # Check circuit breaker
        if self._circuit_open:
            if time.time() < self._circuit_reset_time:
                return {
                    'success': False,
                    'error': 'Circuit breaker open',
                    'retry_after': self._circuit_reset_time - time.time()
                }
            else:
                # Try to reset circuit
                self._circuit_open = False
                self._circuit_failures = 0

        self._uploads_total += 1

        # Prepare payload
        payload = json.dumps(batch)

        # Sign if HMAC configured
        headers = {
            'Authorization': f'Bearer {self.auth_token}',
            'Content-Type': 'application/json',
            'User-Agent': 'Sentinel-Sensor/1.0',
            'X-Idempotency-Key': batch.get('batch_id') or str(time.time())
        }

        if self.hmac_secret:
            signature = self._sign_payload(payload)
            headers['X-Signature'] = signature

        # Compress
        if compress:
            payload_bytes = gzip.compress(payload.encode())
            headers['Content-Encoding'] = 'gzip'
        else:
            payload_bytes = payload.encode()

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
                    verify=self.verify_ssl
                )

                if response.status_code == 200:
                    self._on_success()
                    result = response.json()
                    return {
                        'success': True, 'ack_id': result.get('ack_id'), 'accepted': result.get(
                            'accepted', len(
                                batch.get(
                                    'items', [])))}

                elif response.status_code >= 400 and response.status_code < 500:
                    # Client error - don't retry
                    self._on_failure(f"HTTP {response.status_code}")
                    return {
                        'success': False,
                        'error': f"Client error: {response.status_code}",
                        'response': response.text[:500]
                    }

                else:
                    # Server error - retry
                    last_error = f"HTTP {response.status_code}"
                    logger.warning(
                        f"Upload attempt {attempt + 1} failed: {last_error}")

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
                jitter = delay * 0.1 * \
                    (2 * (0.5 - time.time() % 1))  # Simple jitter
                sleep_time = min(delay + jitter, self.max_delay)
                time.sleep(sleep_time)
                delay *= self.backoff_factor

        # All retries failed
        self._on_failure(last_error)
        return {
            'success': False,
            'error': last_error,
            'retries_exhausted': True
        }

    def _sign_payload(self, payload: str) -> str:
        """Sign payload with HMAC-SHA256"""
        signature = hmac.new(
            self.hmac_secret.encode(),
            payload.encode(),
            hashlib.sha256
        )
        return signature.hexdigest()

    def _on_success(self) -> None:
        """Called on successful upload"""
        with self._lock:
            self._uploads_success += 1
            self._last_upload_time = datetime.now(timezone.utc)
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
                logger.warning(
                    "Circuit breaker opened due to repeated failures")

    def heartbeat(self, status: dict[str, Any]) -> dict[str, Any]:
        """
        Send heartbeat to controller.

        Args:
            status: Sensor status dict

        Returns:
            Response with optional commands
        """
        import requests

        heartbeat_url = self.upload_url.replace('/telemetry', '/heartbeat')

        try:
            response = requests.post(
                heartbeat_url,
                json=status,
                headers={'Authorization': f'Bearer {self.auth_token}'},
                timeout=10,
                verify=self.verify_ssl
            )

            if response.status_code == 200:
                return {
                    'success': True,
                    'commands': response.json().get('commands', [])
                }

        except Exception as e:
            logger.debug(f"Heartbeat failed: {e}")

        return {'success': False, 'commands': []}

    def get_stats(self) -> dict[str, Any]:
        """Get transport statistics"""
        with self._lock:
            return {
                'uploads_total': self._uploads_total,
                'uploads_success': self._uploads_success,
                'uploads_failed': self._uploads_failed,
                'success_rate': (
                    self._uploads_success / self._uploads_total * 100
                    if self._uploads_total > 0 else 0
                ),
                'last_upload': (
                    self._last_upload_time.isoformat()
                    if self._last_upload_time else None
                ),
                'last_error': self._last_error,
                'circuit_open': self._circuit_open,
                'circuit_failures': self._circuit_failures
            }
