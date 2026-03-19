from pathlib import Path

from sensor.config import init_config


def test_init_config_reads_yaml_sections(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("SENSOR_INTERFACE", raising=False)
    monkeypatch.delenv("SENSOR_ID", raising=False)

    config_path = tmp_path / "sensor-config.yaml"
    config_path.write_text(
        """
sensor:
  id: yaml-sensor
  interface: wlan5mon
capture:
  channels: [1, 11]
  dwell_ms: 250
transport:
  upload_url: http://controller:5000/api/v1/telemetry
  auth_token: yaml-token
upload:
  batch_size: 64
  interval_sec: 2.5
privacy:
  anonymize_ssid: true
ml:
  enabled: true
geo:
  enabled: true
logging:
  level: DEBUG
mock_mode: false
"""
    )

    config = init_config(str(config_path))

    assert config.sensor.id == "yaml-sensor"
    assert config.capture.interface == "wlan5mon"
    assert config.capture.channels == [1, 11]
    assert config.capture.dwell_time == 0.25
    assert config.api.upload_url == "http://controller:5000/api/v1/telemetry"
    assert config.upload.batch_size == 64
    assert config.upload.interval_sec == 2.5
    assert config.privacy.anonymize_ssid is True
    assert config.ml.enabled is True
    assert config.geo.enabled is True
    assert config.log_level == "DEBUG"


def test_init_config_supports_json_compat(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("ENVIRONMENT", "development")

    config_path = tmp_path / "sensor-config.json"
    config_path.write_text(
        '{"sensor":{"id":"json-sensor"},"capture":{"interface":"wlan2mon"}}'
    )

    config = init_config(str(config_path))

    assert config.sensor.id == "json-sensor"
    assert config.capture.interface == "wlan2mon"
