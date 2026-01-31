from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from common.schemas import (
    AlertCreate,
    TelemetryBatch,
    TelemetryRecord,
)
from common.schemas.telemetry import FrameType


def test_telemetry_roundtrip():
    """Verify TelemetryRecord -> JSON -> TelemetryRecord roundtrip"""
    original = TelemetryRecord(
        sensor_id="test-sensor-01",
        timestamp_utc=datetime.now(UTC),
        sequence_id=1001,
        frame_type=FrameType.BEACON,
        bssid="00:11:22:33:44:55",
        ssid="Test Network",
        rssi_dbm=-50,
        channel=6,
    )

    # Serialize (simulate wire transmission)
    # Using exclude_none=True as enforced in sensor
    json_data = original.model_dump(mode="json", exclude_none=True)

    # Assert JSON structure
    assert json_data["frame_type"] == "beacon"  # Enum value check
    assert "schema_version" in json_data

    # Deserialize (simulate controller ingestion)
    reconstructed = TelemetryRecord(**json_data)

    assert original.sensor_id == reconstructed.sensor_id
    assert original.sequence_id == reconstructed.sequence_id
    assert original.frame_type == reconstructed.frame_type
    assert original.bssid == reconstructed.bssid


def test_telemetry_batch_structure():
    """Verify TelemetryBatch structure and strictness"""
    record = TelemetryRecord(
        sensor_id="test-sensor-01",
        timestamp_utc=datetime.now(UTC),
        sequence_id=1,
        frame_type=FrameType.PROBE_REQ,
        bssid="AA:BB:CC:DD:EE:FF",
        rssi_dbm=-80,
        channel=1,
    )

    batch = TelemetryBatch(
        batch_id="batch-001", sensor_id="test-sensor-01", items=[record]
    )

    json_batch = batch.model_dump(mode="json", exclude_none=True)
    assert len(json_batch["items"]) == 1

    # Test 'extra=forbid' behavior
    with pytest.raises(ValidationError):
        TelemetryBatch(**{**json_batch, "extra_field": "should_fail"})


def test_alert_schema_version():
    """Verify AlertCreate has schema version"""
    alert = AlertCreate(
        alert_type="evil_twin",
        severity="High",
        title="Detected Evil Twin",
        description="SSID mismatch",
        bssid="00:11:22:33:44:55",
    )
    assert alert.schema_version == "1.0"

    json_alert = alert.model_dump(mode="json")
    assert json_alert["severity"] == "High"


if __name__ == "__main__":
    # Mini runner for manual verification
    try:
        test_telemetry_roundtrip()
        test_telemetry_batch_structure()
        test_alert_schema_version()
        print("All schema roundtrip tests passed!")
    except Exception as e:
        print(f"Test failed: {e}")
        exit(1)
