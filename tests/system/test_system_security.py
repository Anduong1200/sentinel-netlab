
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import requests

from sensor.message_signing import MessageSigner
from tests.system.conftest import _free_port, _wait_http, make_telemetry_batch


@pytest.mark.system
def test_auth_enforced_on_telemetry(controller_handle, telemetry_batch):
    base = controller_handle.base_url

    # Missing auth should fail (401)
    r = requests.post(f"{base}/api/v1/telemetry", json=telemetry_batch, timeout=3)
    assert r.status_code in (401, 403)


@pytest.mark.system
def test_tls_gating_when_enabled(tmp_path: Path, tokens):
    """
    REQUIRE_TLS=true should reject plain HTTP unless behind TLS terminator
    and X-Forwarded-Proto=https is present.
    """
    port = _free_port()
    db_path = tmp_path / "tls.db"
    log_path = tmp_path / "controller_tls.log"

    env = os.environ.copy()
    env.update(
        {
            "ENVIRONMENT": "testing",
            "ALLOW_DEV_TOKENS": "true",
            "REQUIRE_TLS": "true",
            "REQUIRE_HMAC": "false",
            "CONTROLLER_SECRET_KEY": "test-secret-key",
            "CONTROLLER_HMAC_SECRET": "test-hmac-secret",
            "CONTROLLER_DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
            "CONTROLLER_HOST": "127.0.0.1",
            "CONTROLLER_PORT": str(port),
            "CONTROLLER_DEBUG": "false",
        }
    )

    with log_path.open("wb") as lf:
        proc = subprocess.Popen(
            [sys.executable, "-m", "controller.api_server"],
            stdout=lf,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(Path(__file__).resolve().parents[2]),
        )

    base = f"http://127.0.0.1:{port}"
    try:
        _wait_http(f"{base}/api/v1/health", timeout_s=20)

        # Plain HTTP should be blocked
        # Note: /health is public, so we verify against /telemetry which is guarded
        r = requests.post(f"{base}/api/v1/telemetry", json={}, timeout=3)
        assert r.status_code == 403
        assert "HTTPS required" in r.text

        # Simulate reverse proxy TLS termination
        r2 = requests.post(
            f"{base}/api/v1/telemetry",
            json={},
            headers={"X-Forwarded-Proto": "https"},
            timeout=3
        )
        # Should be 401 (Missing auth) NOT 403, proving TLS check passed
        assert r2.status_code == 401
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.system
def test_hmac_required_allows_signed_requests(tmp_path: Path, tokens):
    """
    REQUIRE_HMAC=true should require X-Signature + X-Timestamp.
    Signed request must succeed.
    """
    port = _free_port()
    db_path = tmp_path / "hmac.db"
    log_path = tmp_path / "controller_hmac.log"

    env = os.environ.copy()
    env.update(
        {
            "ENVIRONMENT": "testing",
            "ALLOW_DEV_TOKENS": "true",
            "REQUIRE_TLS": "false",
            "REQUIRE_HMAC": "true",
            "CONTROLLER_SECRET_KEY": "test-secret-key",
            "CONTROLLER_HMAC_SECRET": "test-hmac-secret",
            "CONTROLLER_DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
            "CONTROLLER_HOST": "127.0.0.1",
            "CONTROLLER_PORT": str(port),
            "CONTROLLER_DEBUG": "false",
        }
    )

    with log_path.open("wb") as lf:
        proc = subprocess.Popen(
            [sys.executable, "-m", "controller.api_server"],
            stdout=lf,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(Path(__file__).resolve().parents[2]),
        )

    base = f"http://127.0.0.1:{port}"
    try:
        _wait_http(f"{base}/api/v1/health", timeout_s=20)
        batch = make_telemetry_batch()

        # Without signature -> 400
        r0 = requests.post(
            f"{base}/api/v1/telemetry",
            headers={"Authorization": f"Bearer {tokens['sensor']}"},
            json=batch,
            timeout=3,
        )
        assert r0.status_code == 400

        # With signature -> 200
        signer = MessageSigner("test-hmac-secret")
        payload = json.dumps(batch, separators=(",", ":"), sort_keys=True).encode("utf-8")
        sig_headers = signer.sign_request("POST", "/api/v1/telemetry", payload)

        headers = {"Authorization": f"Bearer {tokens['sensor']}", **sig_headers}
        r1 = requests.post(f"{base}/api/v1/telemetry", headers=headers, data=payload, timeout=3)
        assert r1.status_code == 200
        j = r1.json()
        assert j["success"] is True
        assert j["accepted"] == len(batch["items"])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.system
def test_rate_limit_telemetry(tmp_path: Path, tokens):
    """
    Set a tiny RATE_LIMIT_TELEMETRY to ensure limiter is working end-to-end.
    """
    port = _free_port()
    db_path = tmp_path / "ratelimit.db"
    log_path = tmp_path / "controller_rl.log"

    env = os.environ.copy()
    env.update(
        {
            "ENVIRONMENT": "testing",
            "ALLOW_DEV_TOKENS": "true",
            "REQUIRE_TLS": "false",
            "REQUIRE_HMAC": "false",
            "RATE_LIMIT_TELEMETRY": "2 per minute",
            "CONTROLLER_SECRET_KEY": "test-secret-key",
            "CONTROLLER_HMAC_SECRET": "test-hmac-secret",
            "CONTROLLER_DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
            "CONTROLLER_HOST": "127.0.0.1",
            "CONTROLLER_PORT": str(port),
        }
    )

    with log_path.open("wb") as lf:
        proc = subprocess.Popen(
            [sys.executable, "-m", "controller.api_server"],
            stdout=lf,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(Path(__file__).resolve().parents[2]),
        )

    base = f"http://127.0.0.1:{port}"
    try:
        _wait_http(f"{base}/api/v1/health", timeout_s=20)
        batch = make_telemetry_batch(batch_id="rl-1", n=1)

        h = {"Authorization": f"Bearer {tokens['sensor']}"}
        r1 = requests.post(f"{base}/api/v1/telemetry", headers=h, json=batch, timeout=3)
        r2 = requests.post(f"{base}/api/v1/telemetry", headers=h, json=batch, timeout=3)
        r3 = requests.post(f"{base}/api/v1/telemetry", headers=h, json=batch, timeout=3)

        assert r1.status_code == 200
        assert r2.status_code in (200, 429)  # depending on limiter window start
        assert r3.status_code in (429, 200)
        assert any(code == 429 for code in (r1.status_code, r2.status_code, r3.status_code))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
