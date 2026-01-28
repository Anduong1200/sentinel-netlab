#!/usr/bin/env python3
"""
Sentinel NetLab - Secure Message Signing Client
HMAC-SHA256 signing for sensor→controller messages.

Usage:
    from message_signing import SecureTransport

    transport = SecureTransport(
        controller_url='https://controller:5000',
        auth_token='sensor-token',
        hmac_secret='shared-secret'
    )
    transport.send_telemetry(batch)
"""

import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import requests

logger = logging.getLogger(__name__)


class SecureTransport:
    """
    Secure transport client with:
    - HMAC-SHA256 payload signing
    - Timestamp validation (anti-replay)
    - Time sync with controller
    """

    def __init__(
        self,
        controller_url: str,
        auth_token: str,
        hmac_secret: str,
        sensor_id: str = None,
        verify_ssl: bool = True,
        timeout: int = 30
    ):
        self.controller_url = controller_url.rstrip('/')
        self.auth_token = auth_token
        self.hmac_secret = hmac_secret
        self.sensor_id = sensor_id or os.environ.get('SENSOR_ID', 'unknown')
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # Time offset from server
        self._time_offset = 0.0
        self._last_sync = 0

    def sync_time(self) -> bool:
        """Sync time with controller"""
        try:
            response = requests.get(
                f"{self.controller_url}/api/v1/time",
                timeout=10,
                verify=self.verify_ssl
            )
            if response.status_code == 200:
                data = response.json()
                server_time = data.get('unix_timestamp', time.time())
                self._time_offset = server_time - time.time()
                self._last_sync = time.time()
                logger.info(f"Time sync: offset={self._time_offset:.3f}s")
                return True
        except Exception as e:
            logger.warning(f"Time sync failed: {e}")
        return False

    def get_server_time(self) -> datetime:
        """Get estimated server time"""
        # Sync every 5 minutes
        if time.time() - self._last_sync > 300:
            self.sync_time()

        adjusted = time.time() + self._time_offset
        return datetime.fromtimestamp(adjusted, tz=timezone.utc)

    def sign_payload(self, payload: bytes) -> str:
        """Sign payload with HMAC-SHA256"""
        signature = hmac.new(
            self.hmac_secret.encode(),
            payload,
            hashlib.sha256
        )
        return signature.hexdigest()

    def _build_headers(self, payload: bytes) -> dict[str, str]:
        """Build request headers with auth and signature"""
        timestamp = self.get_server_time().isoformat()

        headers = {
            'Authorization': f'Bearer {self.auth_token}',
            'Content-Type': 'application/json',
            'X-Timestamp': timestamp,
            'X-Signature': self.sign_payload(payload),
            'X-Sensor-ID': self.sensor_id
        }
        return headers

    def send_telemetry(self, batch: dict[str, Any]) -> dict[str, Any]:
        """
        Send telemetry batch with signing.

        Args:
            batch: {sensor_id, items, ...}

        Returns:
            {success, ack_id, accepted} or {success:False, error}
        """
        payload = json.dumps(batch).encode()
        headers = self._build_headers(payload)

        try:
            response = requests.post(
                f"{self.controller_url}/api/v1/telemetry",
                data=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text[:200]}"
                }

        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timeout'}
        except requests.exceptions.ConnectionError as e:
            return {'success': False, 'error': f'Connection error: {str(e)[:100]}'}
        except Exception as e:
            return {'success': False, 'error': str(e)[:100]}

    def send_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Send alert to controller"""
        payload = json.dumps(alert).encode()
        headers = self._build_headers(payload)

        try:
            response = requests.post(
                f"{self.controller_url}/api/v1/alerts",
                data=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            return response.json() if response.status_code == 200 else {'success': False}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def heartbeat(self, status: dict[str, Any] = None) -> dict[str, Any]:
        """Send heartbeat to controller"""
        data = {
            'sensor_id': self.sensor_id,
            'status': 'online',
            'metrics': status or {}
        }
        payload = json.dumps(data).encode()
        headers = self._build_headers(payload)

        try:
            response = requests.post(
                f"{self.controller_url}/api/v1/sensors/heartbeat",
                data=payload,
                headers=headers,
                timeout=10,
                verify=self.verify_ssl
            )
            return response.json() if response.status_code == 200 else {'success': False}
        except Exception:
            return {'success': False}


def create_from_env() -> SecureTransport:
    """Create SecureTransport from environment variables"""
    return SecureTransport(
        controller_url=os.environ.get('CONTROLLER_URL', 'https://localhost:5000'),
        auth_token=os.environ.get('SENSOR_AUTH_TOKEN', ''),
        hmac_secret=os.environ.get('SENSOR_HMAC_SECRET', ''),
        sensor_id=os.environ.get('SENSOR_ID', 'sensor-01'),
        verify_ssl=os.environ.get('VERIFY_SSL', 'true').lower() == 'true'
    )


# =============================================================================
# CLI
# =============================================================================

def main():
    """Test secure transport"""
    import argparse

    parser = argparse.ArgumentParser(description='Test Secure Transport')
    parser.add_argument('--url', default='http://localhost:5000', help='Controller URL')
    parser.add_argument('--token', default='sensor-01-token', help='Auth token')
    parser.add_argument('--secret', default='dev-hmac-secret', help='HMAC secret')

    args = parser.parse_args()

    transport = SecureTransport(
        controller_url=args.url,
        auth_token=args.token,
        hmac_secret=args.secret,
        sensor_id='test-sensor',
        verify_ssl=False
    )

    print("[+] Syncing time...")
    transport.sync_time()

    print("[+] Sending test telemetry...")
    result = transport.send_telemetry({
        'sensor_id': 'test-sensor',
        'items': [
            {'bssid': 'AA:BB:CC:11:22:33', 'ssid': 'TestNet', 'rssi_dbm': -65}
        ]
    })
    print(f"    Result: {result}")

    print("[+] Sending heartbeat...")
    result = transport.heartbeat({'cpu': 15, 'memory': 45})
    print(f"    Result: {result}")


if __name__ == '__main__':
    main()
