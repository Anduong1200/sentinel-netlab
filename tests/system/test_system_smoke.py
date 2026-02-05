
import pytest
import requests


@pytest.mark.system
def test_controller_health_and_metrics(controller_handle):
    base = controller_handle.base_url

    r = requests.get(f"{base}/api/v1/health", timeout=3)
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "ok"
    assert "version" in j

    m = requests.get(f"{base}/metrics", timeout=3)
    assert m.status_code == 200
    # Prometheus text format
    assert "python" in m.text.lower() or "process_" in m.text.lower()
