
# Developer Guide: Adding Detectors

## Interface
All detectors must implement `AbstractDetector` (`controller/detection/interface.py`).

```python
class MyDetector(AbstractDetector):
    def process(self, telemetry: Dict, context: Dict) -> List[Finding]:
        # Logic
        return [Finding(...)]
```

## Creating a Finding
Findings are the intermediate unit of detection.

```python
f = Finding(
    detector_id="my_detector",
    entity_key="my_target_entity",
    confidence_raw=0.8
)
f.add_reason(ReasonCodes.SOME_REASON)
f.evidence_list.append(Evidence(type="raw", description="...", data={}))
```

## Adding Reason Codes
If your detector needs a new reason, add it to `common/detection/reason_codes.py`.
Ensure you select the correct `ReasonCategory` (THREAT, BEHAVIOR, etc.).

## Regression Testing (Golden PCAPs)
We require regression tests for all detectors to prevent false positives.

1. Create a test file in `tests/detectors/test_my_detector.py`.
2. Use `sensor/replay/pcap_reader.py` and `common/detection/pipeline.py`.
3. If possible, use `scapy` to generate a lightweight synthetic PCAP in the test setup.

```python
def test_my_detector_logic(tmp_path):
    pcap = generate_synthetic_pcap(tmp_path / "test.pcap")
    pipeline = DetectionPipeline()
    pipeline.register(MyDetector())
    findings = pipeline.run(PcapStream(pcap).stream())
    assert len(findings) > 0
```
