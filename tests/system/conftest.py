
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, Optional

import pytest
import requests


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_http(url: str, timeout_s: float = 15.0) -> None:
    deadline = time.time() + timeout_s
    last_err: Optional[Exception] = None
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1.0)
            if r.status_code < 500:
                return
        except Exception as e:
            last_err = e
        time.sleep(0.2)
    raise RuntimeError(f"Service not ready: {url} (last_err={last_err})")


@dataclass(frozen=True)
class ControllerHandle:
    base_url: str
    proc: subprocess.Popen
    log_path: Path
    env: Dict[str, str]


@pytest.fixture
def controller_handle(tmp_path: Path) -> Iterator[ControllerHandle]:
    """
    Spawns a real Controller process on a random local port.
    Uses sqlite file DB so restart/persistence tests can work.
    """
    port = _free_port()
    db_path = tmp_path / "controller.db"
    log_path = tmp_path / "controller.log"

    env = os.environ.copy()
    env.update(
        {
            # Important: set env BEFORE controller imports config
            "ENVIRONMENT": "testing",
            "ALLOW_DEV_TOKENS": "true",  # allow admin-token-dev, sensor-01-token, analyst-token
            "REQUIRE_TLS": "false",
            "REQUIRE_HMAC": "false",
            "RATE_LIMIT_TELEMETRY": "200 per minute",
            "RATE_LIMIT_ALERTS": "50 per minute",
            "CONTROLLER_SECRET_KEY": "test-secret-key",
            "CONTROLLER_HMAC_SECRET": "test-hmac-secret",
            "CONTROLLER_DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
            "CONTROLLER_HOST": "127.0.0.1",
            "CONTROLLER_PORT": str(port),
            "CONTROLLER_DEBUG": "false",
        }
    )

    # Run module so imports resolve in repo layout
    with log_path.open("wb") as lf:
        proc = subprocess.Popen(
            [sys.executable, "-m", "controller.api_server"],
            stdout=lf,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(Path(__file__).resolve().parents[2]),  # repo root
        )

    base_url = f"http://127.0.0.1:{port}"
    _wait_http(f"{base_url}/api/v1/health", timeout_s=20.0)

    handle = ControllerHandle(base_url=base_url, proc=proc, log_path=log_path, env=env)
    try:
        yield handle
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def tokens() -> Dict[str, str]:
    """Default dev tokens created when ALLOW_DEV_TOKENS=true (testing mode)."""
    return {
        "admin": "admin-token-dev",
        "sensor": "sensor-01-token",
        "analyst": "analyst-token",
    }


@pytest.fixture
def auth_header(tokens: Dict[str, str]) -> Dict[str, str]:
    return {"Authorization": f"Bearer {tokens['admin']}"}


@pytest.fixture
def sensor_auth_header(tokens: Dict[str, str]) -> Dict[str, str]:
    return {"Authorization": f"Bearer {tokens['sensor']}"}


def make_telemetry_batch(sensor_id: str = "sensor-01", batch_id: str = "batch-1", n: int = 3, start_seq: int = 1):
    """Generate a schema-valid TelemetryBatch."""
    import datetime as _dt

    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    items = []
    for i in range(n):
        items.append(
            {
                "sensor_id": sensor_id,
                "timestamp_utc": now,
                "sequence_id": start_seq + i,
                "frame_type": "beacon",
                "frame_subtype": None,
                "mac_src": "AA:BB:CC:11:22:33",
                "bssid": "AA:BB:CC:11:22:33",
                "ssid": f"TestNet-{i}",
                "rssi_dbm": -55,
                "channel": 6,
                "schema_version": "1.0",
            }
        )

    return {"batch_id": batch_id, "sensor_id": sensor_id, "items": items}


@pytest.fixture
def telemetry_batch():
    return make_telemetry_batch()
