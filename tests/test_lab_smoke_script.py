from pathlib import Path
import runpy


def test_lab_smoke_uses_proxy_urls() -> None:
    payload = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "tools" / "ci" / "lab_smoke.py"),
        run_name="lab_smoke_test",
    )

    assert payload["PROXY_BASE_URL"] == "http://127.0.0.1:8080"
    assert payload["HEALTH_URL"] == "http://127.0.0.1:8080/api/v1/health"
    assert payload["TELEMETRY_URL"] == "http://127.0.0.1:8080/api/v1/telemetry"
