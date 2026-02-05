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

    def sign_request(
        self,
        method: str,
        path: str,
        payload: bytes,
        timestamp: str | None = None,
        sequence: int | None = None,
        content_encoding: str = "identity",
    ) -> dict[str, str]:
        """
        Generate headers for signed request.

        Args:
            method: HTTP method (e.g. POST)
            path: request path (e.g. /api/v1/telemetry)
            payload: Request body bytes (JSON)
            timestamp: ISO timestamp (optional, defaults to now)
            sequence: Sequence number (optional)
            content_encoding: Content-Encoding header value (default: identity)

        Returns:
            Dictionary of headers (X-Signature, X-Timestamp, etc)
        """
        if not timestamp:
            from datetime import datetime

            timestamp = datetime.now(UTC).isoformat()

        # Canonical string: method + path + timestamp + sequence + payload + encoding
        data_to_sign = method.encode() + path.encode() + timestamp.encode()
        if sequence is not None:
            data_to_sign += str(sequence).encode()

        data_to_sign += payload
        data_to_sign += content_encoding.encode()

        signature = hmac.new(
            self.secret.encode("utf-8"), data_to_sign, hashlib.sha256
        ).hexdigest()

        headers = {
            "X-Signature": signature,
            "X-Timestamp": timestamp,
            "Content-Type": "application/json",
        }

        if sequence is not None:
            headers["X-Sequence"] = str(sequence)
        
        # Note: Caller must set Content-Encoding header if not identity, 
        # but the signature header itself doesn't contain it (it verifies it).
        
        return headers
