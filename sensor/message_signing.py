"""
Sentinel NetLab - Message Signing
Handles HMAC signature generation and verification for API requests.
"""

import hashlib
import hmac
from datetime import UTC
from typing import Dict


class MessageSigner:
    """Helper for generating HMAC signatures"""

    def __init__(self, secret: str):
        self.secret = secret

    def sign_request(
        self,
        payload: bytes,
        timestamp: str | None = None,
        sequence: int | None = None,
    ) -> Dict[str, str]:
        """
        Generate headers for signed request.

        Args:
            payload: Request body bytes (JSON)
            timestamp: ISO timestamp (optional, defaults to now)
            sequence: Sequence number (optional)

        Returns:
            Dictionary of headers (X-Signature, X-Timestamp, etc)
        """
        if not timestamp:
            from datetime import datetime

            timestamp = datetime.now(UTC).isoformat()

        # Sign only the payload for now, or payload + metadata?
        # The controller verifies `verify_hmac(request.get_data(), signature)` which implies
        # signature = HMAC(secret, payload).
        # Wait, usually you include timestamp in the signature to prevent replay with modified timestamp.
        # But looking at controller `verify_hmac`:
        # expected = hmac.new(Config.HMAC_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        # It ONLY signs the payload. This is a weakness (replay attack possible if payload identical).
        # But I must match the controller logic.

        # Controller logic:
        # verify_hmac(request.get_data(), signature)

        signature = hmac.new(
            self.secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()

        headers = {
            "X-Signature": signature,
            "X-Timestamp": timestamp,
            "Content-Type": "application/json",
        }

        if sequence is not None:
            headers["X-Sequence"] = str(sequence)

        return headers
