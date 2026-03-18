
# Developer Guide: Adding Detectors

## Architecture Overview

Sentinel NetLab uses a **Unified Detection Orchestrator** on the sensor side. Detectors are registered via adapters and selected through detector profiles — no edits to `sensor_controller.py` are needed.

## Detector Interface

All sensor-side detectors are wrapped by an adapter that implements `BaseSensorDetector`:

```python
from sensor.detection.interface import BaseSensorDetector

class MyDetectorAdapter(BaseSensorDetector):
    detector_id = "my_detector"

    def __init__(self, config=None):
        super().__init__(config)
        from algos.my_detector import MyDetector
        self._det = MyDetector()

    def process(self, telemetry, context=None):
        result = self._det.ingest(telemetry)
        if result is None:
            return []
        from sensor.detection.normalizer import normalize_alert
        ctx = context or {}
        return [normalize_alert(result, {"sensor_id": ctx.get("sensor_id", "")})]
```

## Creating an Alert

Alerts are normalized dicts with these **required** fields:

| Field | Type | Description |
|-------|------|-------------|
| `alert_type` | str | e.g. `"my_attack"` |
| `severity` | str | `MEDIUM`, `HIGH`, `CRITICAL` |
| `title` | str | Human-readable title |
| `description` | str | Detailed description |
| `sensor_id` | str | Reporting sensor |

Optional fields: `bssid`, `ssid`, `evidence`, `risk_score`, `mitre_attack`, `timestamp`.

## Integration Steps (New Workflow)

1. **Create your detector** in `algos/my_detector.py`
2. **Create an adapter** in `sensor/detection/adapters.py` (see example above)
3. **Register it** in `sensor/detection/registry.py`:
   ```python
   DETECTOR_REGISTRY["my_detector"] = MyDetectorAdapter
   ```
4. **Add to profiles** in `sensor/detection/profiles.py` as appropriate
5. **Done** — the orchestrator will pick it up automatically

> **No edits to `sensor_controller.py` are required.**

## Detector Profiles

| Profile | Description |
|---------|-------------|
| `lite_realtime` | Default. Low-latency, low-FP: deauth, disassoc, beacon, KRACK, PMKID, WEP, rules |
| `full_wids` | All detectors including evil twin, karma, jamming, wardrive |
| `audit_offline` | Same as full_wids (extensible for replay-only enrichments) |

Select via config, env var (`SENSOR_DETECTOR_PROFILE`), or CLI (`--detector-profile`).

## Detection Stages

Detectors execute in order by stage:

1. **fast_path** — Low-latency frame-driven: deauth, disassoc, beacon, KRACK, PMKID, WEP
2. **stateful_path** — Heuristic/state-heavy: evil twin, karma, jamming, wardrive
3. **correlation_path** — Alert-level: rules engine

## Unit Testing

Create `tests/unit/test_my_detector.py`:

```python
class TestMyDetector:
    def test_no_alert_below_threshold(self): ...
    def test_alert_on_attack(self): ...
    def test_cooldown_prevents_duplicates(self): ...
    def test_ignores_irrelevant_frames(self): ...
```

Run: `pytest tests/unit/test_my_detector.py -v`

## Existing Detectors (11 Total)

| Detector | Module | MITRE | Stage |
|----------|--------|-------|-------|
| Deauth Flood | `dos.py` | T1499.001 | fast_path |
| Disassoc Flood | `disassoc_detector.py` | T1499.001 | fast_path |
| Beacon Flood | `beacon_flood_detector.py` | T1498.001 | fast_path |
| KRACK | `krack_detector.py` | T1557.002 | fast_path |
| PMKID Harvesting | `pmkid_detector.py` | T1110.002 | fast_path |
| WEP IV | `wep_iv_detector.py` | T1600.001 | fast_path |
| Evil Twin | `evil_twin.py` | T1557.002 | stateful_path |
| Karma | `karma_detector.py` | T1583.008 | stateful_path |
| RF Jamming | `jamming_detector.py` | T1465 | stateful_path |
| Wardriving | `wardrive_detector.py` | T1595.002 | stateful_path |
| Rule Engine | `rule_engine.py` | various | correlation_path |
| Exploit Chain | `exploit_chain_analyzer.py` | TA0001 | post-alert (in _handle_alert) |
