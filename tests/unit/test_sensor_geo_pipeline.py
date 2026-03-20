from __future__ import annotations

from types import SimpleNamespace

import pytest

from sensor.config import Config
from sensor.sensor_controller import SensorController


class _DummyBuffer:
    def __init__(self):
        self.items = []

    def append(self, item):
        self.items.append(item)


class _DummyAggregator:
    def __init__(self):
        self.calls = []

    def record_frame(self, frame_type, frame_subtype, mac_src):
        self.calls.append((frame_type, frame_subtype, mac_src))


class _DummyMetrics:
    def __init__(self):
        self.frame_types = []

    def record_frame(self, frame_type):
        self.frame_types.append(frame_type)

    def set_risk_score(self, bssid, score):
        _ = (bssid, score)


class _DummyHopper:
    def __init__(self):
        self.calls = []

    def record_activity(self, channel, count):
        self.calls.append((channel, count))


class _DummyBaseline:
    learning_mode = True

    def check_deviation(self, _risk_dict):
        return None


class _DummyRiskEngine:
    def calculate_risk(self, *_args, **_kwargs):
        return {"risk_score": 0}


def test_sensor_export_calls_geo_hook_and_keeps_buffer_path():
    controller = SensorController.__new__(SensorController)

    called = {"geo": 0}

    def _geo_hook(net_dict):
        called["geo"] += 1
        net_dict["_geo_hook_called"] = True

    controller._geo_ingest_sample = _geo_hook
    controller.buffer = _DummyBuffer()
    controller.aggregator = _DummyAggregator()
    controller.metrics = _DummyMetrics()
    controller.hopper = _DummyHopper()
    controller.baseline = _DummyBaseline()
    controller.risk_engine = _DummyRiskEngine()
    controller._frames_captured = 1
    controller.on_network = None

    parsed = SimpleNamespace(channel=6)

    telemetry = SimpleNamespace(
        frame_type="beacon",
        frame_subtype="beacon",
        mac_src="AA:BB:CC:11:22:33",
        bssid="AA:BB:CC:11:22:33",
        ssid="GeoNet",
        model_dump=lambda **_kwargs: {},
    )

    net_dict = {
        "bssid": "AA:BB:CC:11:22:33",
        "rssi_dbm": -52,
        "mac_src": "AA:BB:CC:11:22:33",
    }

    controller._export_telemetry(parsed, telemetry, net_dict)

    assert called["geo"] == 1
    assert controller.buffer.items == [net_dict]
    assert controller.buffer.items[0]["_geo_hook_called"] is True
    assert controller.aggregator.calls
    assert controller.metrics.frame_types == ["beacon"]
    assert controller.hopper.calls == [(6, 1)]


def test_sensor_geo_init_fail_fast_when_position_missing():
    cfg = Config()
    cfg.sensor.id = "sensor-01"
    cfg.geo.enabled = True
    cfg.geo.sensor_x_m = None
    cfg.geo.sensor_y_m = None

    controller = SensorController.__new__(SensorController)
    controller.config = cfg
    controller.sensor_id = cfg.sensor.id

    with pytest.raises(ValueError, match="sensor position missing"):
        controller._init_geo_pipeline()
