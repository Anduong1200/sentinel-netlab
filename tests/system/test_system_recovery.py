import os
import subprocess
import sys
from pathlib import Path

import pytest
import requests

from tests.system.conftest import _free_port, _wait_http, make_telemetry_batch


@pytest.mark.system
def test_controller_persists_data_across_restart(tmp_path: Path, tokens):
    """
    Crash/restart simulation: send telemetry -> restart controller using same sqlite file -> data still queryable.
    """
    port1 = _free_port()
    db_path = tmp_path / "persist.db"
    log1 = tmp_path / "ctrl1.log"
    log2 = tmp_path / "ctrl2.log"

    env = os.environ.copy()
    env.update(
        {
            "ENVIRONMENT": "testing",
            "ALLOW_DEV_TOKENS": "true",
            "REQUIRE_TLS": "false",
            "REQUIRE_HMAC": "false",
            "CONTROLLER_SECRET_KEY": "test-secret-key",
            "CONTROLLER_HMAC_SECRET": "test-hmac-secret",
            "CONTROLLER_DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
            "CONTROLLER_HOST": "127.0.0.1",
            "CONTROLLER_PORT": str(port1),
        }
    )

    def start_controller(port: int, log_path: Path):
        env2 = dict(env)
        env2["CONTROLLER_PORT"] = str(port)
        lf = log_path.open("wb")
        proc = subprocess.Popen(
            [sys.executable, "-m", "controller.api_server"],
            stdout=lf,
            stderr=subprocess.STDOUT,
            env=env2,
            cwd=str(Path(__file__).resolve().parents[2]),
        )
        return proc, lf, env2

    proc1, lf1, env1 = start_controller(port1, log1)
    base1 = f"http://127.0.0.1:{port1}"
    try:
        _wait_http(f"{base1}/api/v1/health", timeout_s=20)

        batch = make_telemetry_batch(batch_id="persist-1", n=2)
        r = requests.post(
            f"{base1}/api/v1/telemetry",
            headers={"Authorization": f"Bearer {tokens['sensor']}"},
            json=batch,
            timeout=3,
        )
        assert r.status_code == 200

        # Stop controller 1
        proc1.terminate()
        proc1.wait(timeout=8)
        lf1.close()

        # Start controller 2 on another port but same DB
        port2 = _free_port()
        proc2, lf2, env2 = start_controller(port2, log2)
        base2 = f"http://127.0.0.1:{port2}"
        try:
            _wait_http(f"{base2}/api/v1/health", timeout_s=20)

            # Query telemetry as admin/analyst
            rr = requests.get(
                f"{base2}/api/v1/telemetry?limit=50",
                headers={"Authorization": f"Bearer {tokens['admin']}"},
                timeout=3,
            )
            assert rr.status_code == 200
            items = rr.json()["items"]
            ssids = {i.get("ssid") for i in items}
            assert "TestNet-0" in ssids
        finally:
            proc2.terminate()
            try:
                proc2.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc2.kill()
            lf2.close()
    finally:
        if proc1.poll() is None:
            proc1.terminate()
            try:
                proc1.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc1.kill()
        if not lf1.closed:
            lf1.close()
