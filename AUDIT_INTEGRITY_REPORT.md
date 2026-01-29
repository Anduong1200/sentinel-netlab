# 🛡️ Integrity Report: Logic & Algorithms

## 1. Risk Logic Duplication
- **Issue**: Logic for risk scoring is split between `algos/risk.py` (Weighted scoring, ML readiness) and `common/risk_engine.py` (Rule-based detection).
- **Risk**: Inconsistent scoring. `sensor_controller.py` imports `risk` but it's unclear which one is the "primary" source of truth in the absence of `sensor/risk.py`.
- **Verdict**: **CRITICAL**. The project has two "brains" for risk. Accessing one might miss features of the other (e.g., ML anomalies vs Rule detections).

## 2. Wardriving Isolation
- **Issue**: `sensor/wardrive.py` operates completely independently of the `sensor/sensor_controller.py`.
- **Risk**: Data collected during Wardriving (saved to JSON) is NOT automatically ingested into the Controller/DB. It requires manual upload or a separate script.
- **Verdict**: **HIGH**. This disconnect limits the "Assessment" capability mentioned in the goals.

## 3. Data Pipeline Fragility
- **Issue**: `sensor/transport_client.py` has retry logic, but if the local buffer (`sensor/buffer_manager.py`) fills up (e.g., long outage), data is dropped or potential OOM occurs if not strictly capped.
- **Risk**: Data loss during extended disconnected operations (e.g., mobile wardriving without immediate upload).
- **Verdict**: **MEDIUM**. "Store-and-forward" needs to be robustly tested.

## 4. Active Defense Safety
- **Issue**: `sensor/attacks.py` contains deauth logic. While wrapped in "Lab Only" warnings, there is no hard-coded "kill switch" based on GPS geofence or signed cryptographic authorization.
- **Risk**: Accidental activation in unauthorized areas.
- **Verdict**: **HIGH**. Requires a "Safety Interlock" (e.g., refuse to run if GPS coordinates are not within a whitelist or if a specific hardware dongle isn't present).

## 5. ML Integration
- **Issue**: `algos/risk.py` references `ml/anomaly_model.py`.
- **Status**: The integration seems "optional" via `try-import`. If ML model is missing, it falls back silently.
- **Verdict**: **LOW**. Good for stability, but might mislead users thinking ML is active when it's not.

## Recommendations
1.  **Merge Risk Engines**: Combine `algos/risk.py` and `common/risk_engine.py` into a single `sensor/risk_engine.py` that implements both Rule-based and Weighted/ML scoring.
2.  **Integrate Wardriving**: Make `Wardrive` a "mode" within `SensorController` so it reuses the `TransportClient` to upload data when connectivity is restored.
3.  **Safety Lock**: Implement a mandatory `SAFE_MODE` environment variable that defaults to `TRUE` (disabling attacks) and requires explicit override `I_AM_AUTHORIZED=1` alongside a valid `config.yaml` whitelist.
