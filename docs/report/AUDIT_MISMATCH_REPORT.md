# 📉 Mismatch Report: Code vs Documentation

## 1. Missing Files Referenced in Docs
- **`sensor/risk.py`**:
    - Referenced in: `dashboard/README.md`, `sensor/README.md`, `docs/architecture/system-design.md`, `README.md`.
    - Actual status: File does not exist.
    - Likely replacements: `algos/risk.py` (Algorithm logic) or `common/risk_engine.py` (Core logic).
    - Impact: Developers following the guide will fail to find the core risk logic.

## 2. API Versioning
- **Docs**: `docs/reference/api_ingest.md` implies a specific contract.
- **Code**: `sensor/transport_client.py` and `controller/api_server.py` use `/api/v1/telemetry`.
- **Mismatch**: No formal OpenAPI/Swagger spec exists in code to enforce this contract (implied only). Docs mention `v1` but code doesn't strictly validate versions in all endpoints.

## 3. Deployment Instructions
- **Docs**: `README.md` mentions `docker-compose.yml` and `docker-compose.light.yml`.
- **Code**: Files exist in `ops/` but `README.md` root references might be misleading if paths aren't explicit (e.g., `ops/docker-compose.yml`).
- **Gap**: No "Production" deployment guide (e.g., k8s, systemd hardening) is present in `docs/operations/`, despite being mentioned as a goal.

## 4. Wardriving vs WIDS
- **Docs**: Describe the system primarily as a WIDS (`README.md`).
- **Code**: `sensor/wardrive.py` is a completely standalone script, not integrated into the main `sensor/monitoring.py` or `sensor_controller.py` loop.
- **Ambiguity**: Users might expect "Wardriving" to be a mode they can switch to dynamically via the API, but it appears to be a separate CLI tool requiring a restart or separate process.

## 5. Testing
- **Docs**: `README.md` claims "Tests present".
- **Code**: `tests/` folder exists but heavily skewed towards `unit/` for sensor. Integration tests for the full pipeline (Sensor -> Controller -> DB) are minimal or missing.

## Recommendations
1.  **Rename/Alias**: Update docs to point to `common/risk_engine.py` or create a facade `sensor/risk.py` that imports it.
2.  **Unify Docs**: Move deployment guides to `docs/deployment/` and refer to `ops/` scripts explicitly.
3.  **Clarify Modes**: Explicitly document that "Wardriving" is a standalone tool in `sensor/README.md`.
