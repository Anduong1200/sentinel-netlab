"""
Sentinel NetLab - Message Signing
Handles HMAC signature generation and verification for API requests.
"""

import hashlib
import hmac
from datetime import UTC


class MessageSigner:
    """Helper for generating HMAC signatures"""

    def __init__(self, secret: str):
        self.secret = secret

    def derive_sensor_key(self, sensor_id: str) -> bytes:
        """Derive a per-sensor HMAC key from master secret using HKDF-SHA256."""
        # HKDF-Extract: PRK = HMAC(salt, IKM)
        salt = b"sentinel-netlab-hmac-v1"  # Fixed salt for reproducibility
        prk = hmac.new(salt, self.secret.encode(), hashlib.sha256).digest()

        # HKDF-Expand: OKM = HMAC(PRK, info || 0x01)
        info = f"sensor-hmac|{sensor_id}".encode()
        okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
        return okm

    def sign_request(
        self,
        method: str,
        path: str,
        payload: bytes,
        sensor_id: str = "unknown",
        timestamp: str | None = None,
        sequence: int | None = None,
        content_encoding: str = "identity",
    ) -> dict[str, str]:
        if not timestamp:
            from datetime import datetime

            timestamp = datetime.now(UTC).isoformat()

        # V1 Canonical String Format (newline delimited)
        parts = [method, path, timestamp, sensor_id, content_encoding]
        canonical_meta = "\n".join(parts) + "\n"

        sensor_key = self.derive_sensor_key(sensor_id)

        h = hmac.new(sensor_key, digestmod=hashlib.sha256)
        h.update(canonical_meta.encode())
        h.update(payload)

        signature = h.hexdigest()

        headers = {
            "X-Signature": signature,
            "X-Timestamp": timestamp,
            "X-Sensor-ID": sensor_id,
            "Content-Type": "application/json",
        }

        if sequence is not None:
            headers["X-Sequence"] = str(sequence)

        # Note: Caller must set Content-Encoding header if not identity,
        # but the signature header itself doesn't contain it (it verifies it).

        return headers
