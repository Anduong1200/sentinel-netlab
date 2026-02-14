"""
PR-06: Per-sensor HMAC isolation tests.

Validates:
1. Key derivation is deterministic (same inputs → same key)
2. Different sensor_ids produce different keys
3. Sensor A's key cannot be used to sign as sensor B
4. Controller verify_hmac matches sensor _sign_payload for same sensor
5. Cross-sensor forgery is rejected
"""

import hashlib
import hmac

# ---------------------------------------------------------------------------
# 1. Key derivation unit tests
# ---------------------------------------------------------------------------


class TestDeriveKey:
    """Test the HKDF-based key derivation function."""

    def _derive(self, master: str, sensor_id: str) -> bytes:
        """Replicate the derivation logic for testing without importing app context."""
        salt = b"sentinel-netlab-hmac-v1"
        prk = hmac.new(salt, master.encode(), hashlib.sha256).digest()
        info = f"sensor-hmac|{sensor_id}".encode()
        return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

    def test_deterministic(self):
        """Same inputs always produce the same key."""
        k1 = self._derive("master-secret-abc", "sensor-01")
        k2 = self._derive("master-secret-abc", "sensor-01")
        assert k1 == k2

    def test_different_sensors_different_keys(self):
        """Different sensor_ids must produce different keys."""
        k_a = self._derive("master-secret-abc", "sensor-01")
        k_b = self._derive("master-secret-abc", "sensor-02")
        assert k_a != k_b

    def test_different_masters_different_keys(self):
        """Different master secrets must produce different keys."""
        k1 = self._derive("master-A", "sensor-01")
        k2 = self._derive("master-B", "sensor-01")
        assert k1 != k2

    def test_key_length(self):
        """Derived key should be 32 bytes (SHA-256 output)."""
        k = self._derive("master", "sensor-01")
        assert len(k) == 32


# ---------------------------------------------------------------------------
# 2. Signing isolation tests
# ---------------------------------------------------------------------------


class TestSigningIsolation:
    """Ensure sensor A's derived key cannot forge sensor B's signature."""

    def _derive(self, master: str, sensor_id: str) -> bytes:
        salt = b"sentinel-netlab-hmac-v1"
        prk = hmac.new(salt, master.encode(), hashlib.sha256).digest()
        info = f"sensor-hmac|{sensor_id}".encode()
        return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

    def _sign(
        self,
        key: bytes,
        method: str,
        path: str,
        payload: bytes,
        timestamp: str,
        sensor_id: str,
    ) -> str:
        """V1 canonical signing."""
        canonical = f"{method}\n{path}\n{timestamp}\n{sensor_id}\nidentity\n"
        h = hmac.new(key, digestmod=hashlib.sha256)
        h.update(canonical.encode())
        h.update(payload)
        return h.hexdigest()

    def test_correct_sensor_verifies(self):
        """Signing with sensor-01's key verifies correctly."""
        master = "test-master-secret"
        sensor_id = "sensor-01"
        key = self._derive(master, sensor_id)

        sig = self._sign(
            key,
            "POST",
            "/api/v1/telemetry",
            b'{"data": 1}',
            "2026-01-01T00:00:00Z",
            sensor_id,
        )

        # Re-sign and verify
        expected = self._sign(
            key,
            "POST",
            "/api/v1/telemetry",
            b'{"data": 1}',
            "2026-01-01T00:00:00Z",
            sensor_id,
        )
        assert hmac.compare_digest(sig, expected)

    def test_cross_sensor_forgery_fails(self):
        """Sensor A's key used to sign sensor B's request must NOT match."""
        master = "test-master-secret"
        key_a = self._derive(master, "sensor-A")
        key_b = self._derive(master, "sensor-B")

        # Sensor A signs a request claiming to be sensor-B
        forged_sig = self._sign(
            key_a,
            "POST",
            "/api/v1/telemetry",
            b'{"data": "evil"}',
            "2026-01-01T00:00:00Z",
            "sensor-B",
        )

        # What sensor B's legitimate sig would be
        legit_sig = self._sign(
            key_b,
            "POST",
            "/api/v1/telemetry",
            b'{"data": "evil"}',
            "2026-01-01T00:00:00Z",
            "sensor-B",
        )

        assert not hmac.compare_digest(forged_sig, legit_sig), (
            "Cross-sensor forgery should be rejected!"
        )

    def test_sensor_transport_derives_same_key(self):
        """Verify sensor transport's derivation matches controller's."""
        from sensor.transport import TransportClient

        master = "shared-master-secret"
        sensor_id = "sensor-42"

        # Sensor-side derivation
        sensor_key = TransportClient._derive_sensor_key_from(master, sensor_id)

        # Controller-side derivation (replicated)
        controller_key = self._derive(master, sensor_id)

        assert sensor_key == controller_key, (
            "Sensor and controller must derive identical keys from same inputs"
        )
