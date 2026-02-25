
# Developer Guide: Adding Detectors

## Detector Interface

All sensor-side detectors follow the `ingest()` pattern. Each detector tracks its own state and returns alerts when thresholds are exceeded.

```python
class MyDetector:
    """Stateful detector with sliding-window analysis."""

    def __init__(self, config: MyConfig | None = None):
        self.config = config or MyConfig()
        # Internal state

    def ingest(self, frame: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single frame. Returns alert dict or None."""
        # 1. Filter: Only process relevant frame types
        # 2. Track: Update internal state
        # 3. Evaluate: Check thresholds, apply cooldown
        # 4. Return alert dict or None

    def get_stats(self) -> dict:
        """Return current detection statistics."""

    def reset(self):
        """Clear all state."""
```

## Creating an Alert

Alerts are plain dicts returned by `ingest()`:

```python
return {
    "alert_type": "my_attack",
    "severity": "HIGH",  # MEDIUM, HIGH, CRITICAL
    "title": "Attack Detected: <details>",
    "description": "Human-readable description",
    "timestamp": datetime.now(UTC).isoformat(),
    "evidence": {
        "key_metric": value,
        "window_seconds": self.config.time_window,
    },
    "mitre_attack": "T1234.001",  # MITRE ATT&CK ID
}
```

## Integration Steps

1. Create `algos/my_detector.py` with your detector class
2. Add export to `algos/__init__.py`
3. In `sensor/sensor_controller.py`:
   - Import the detector
   - Instantiate in `__init__`
   - Call `ingest()` in the capture loop
   - Pass non-None results to `_handle_alert()`

## Unit Testing

Create `tests/unit/test_my_detector.py` with tests covering:

```python
class TestMyDetector:
    def test_no_alert_below_threshold(self): ...
    def test_alert_on_attack(self): ...
    def test_cooldown_prevents_duplicates(self): ...
    def test_ignores_irrelevant_frames(self): ...
    def test_severity_escalation(self): ...
    def test_alert_evidence_fields(self): ...
    def test_stats(self): ...
    def test_reset(self): ...
```

Run: `pytest tests/unit/test_my_detector.py -v`

## Existing Detectors (11 Total)

| Detector | Module | MITRE |
|----------|--------|-------|
| Evil Twin | `evil_twin.py` | T1557.002 |
| Deauth Flood | `dos.py` | T1499.001 |
| Disassoc Flood | `disassoc_detector.py` | T1499.001 |
| Beacon Flood | `beacon_flood_detector.py` | T1498.001 |
| KRACK | `krack_detector.py` | T1557.002 |
| PMKID Harvesting | `pmkid_detector.py` | T1110.002 |
| Karma | `karma_detector.py` | T1583.008 |
| RF Jamming | `jamming_detector.py` | T1465 |
| Wardriving | `wardrive_detector.py` | T1595.002 |
| WEP IV | `wep_iv_detector.py` | T1600.001 |
| Exploit Chain | `exploit_chain_analyzer.py` | TA0001 |
