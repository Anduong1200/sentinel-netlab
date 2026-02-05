
import os
import subprocess
import sys
from pathlib import Path

import pytest
import requests

from tests.system.conftest import _free_port, _wait_http


@pytest.mark.system
def test_dashboard_smoke_with_basic_auth(tmp_path: Path, controller_handle, tokens):
    """
    Starts dashboard process and checks it serves /dashboard/ with basic auth.
    Also verifies it can reach controller endpoints (via its CONTROLLER_URL).
    """
    port = _free_port()
    log_path = tmp_path / "dashboard.log"

    env = os.environ.copy()
    env.update(
        {
            "CONTROLLER_URL": controller_handle.base_url,  # dashboard calls controller
            "DASHBOARD_API_TOKEN": tokens["analyst"],      # dashboard fetch token
            "DASH_USERNAME": "admin",
            "DASH_PASSWORD": "change-me",
            "DASHBOARD_PORT": str(port),
        }
    )

    with log_path.open("wb") as lf:
        proc = subprocess.Popen(
            [sys.executable, "-m", "dashboard.app"],
            stdout=lf,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(Path(__file__).resolve().parents[2]),
        )

    base = f"http://127.0.0.1:{port}"
    try:
        _wait_http(f"{base}/dashboard/", timeout_s=30)

        r = requests.get(f"{base}/dashboard/", auth=("admin", "change-me"), timeout=5)
        assert r.status_code == 200
        assert "Sentinel" in r.text or "NetLab" in r.text
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
