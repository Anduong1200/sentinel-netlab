from __future__ import annotations

import math
import os
from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from controller.config import GeoConfig, init_config
from controller.geo.service import DistributedGeoService


@pytest.fixture
def geo_config_three_sensors() -> GeoConfig:
    return GeoConfig(
        enabled=True,
        sensor_positions={
            "sensor-01": {"x": 0.0, "y": 0.0},
            "sensor-02": {"x": 20.0, "y": 0.0},
            "sensor-03": {"x": 10.0, "y": 17.3},
        },
        origin_lat=10.776889,
        origin_lon=106.700806,
        sample_window_sec=60,
    )


def test_distributed_geo_trilateration_success(geo_config_three_sensors: GeoConfig):
    service = DistributedGeoService(geo_config_three_sensors)
    if service._geo_mapper is None:
        pytest.skip("GeoMapper dependencies unavailable")

    target_x, target_y = 8.0, 6.0
    bssid = "AA:BB:CC:11:22:33"
    now = datetime.now(UTC)

    records = []
    for sensor_id, pos in geo_config_three_sensors.sensor_positions.items():
        distance = math.sqrt((target_x - pos["x"]) ** 2 + (target_y - pos["y"]) ** 2)
        rssi = service._geo_mapper.path_loss.distance_to_rssi(distance)
        records.append(
            SimpleNamespace(
                sensor_id=sensor_id,
                ingested_at=now,
                data={
                    "bssid": bssid,
                    "timestamp_utc": now.isoformat(),
                    "rssi_dbm": rssi,
                    "frequency_mhz": 2412,
                },
            )
        )

    estimates = service.estimate_by_bssid(records)
    assert bssid in estimates

    result = estimates[bssid]
    geo = result["geo"]
    assert geo["method"].startswith("trilateration")
    assert geo["sample_sensor_count"] == 3
    assert result["lat"] is not None
    assert result["lon"] is not None
    assert isinstance(geo["x_m"], float)
    assert isinstance(geo["y_m"], float)
    assert geo["error_radius_m"] >= 0


def test_distributed_geo_fallback_strongest_rssi():
    cfg = GeoConfig(
        enabled=True,
        sensor_positions={
            "sensor-01": {"x": 0.0, "y": 0.0},
            "sensor-02": {"x": 25.0, "y": 5.0},
        },
        origin_lat=10.776889,
        origin_lon=106.700806,
        sample_window_sec=60,
    )

    service = DistributedGeoService(cfg)
    now = datetime.now(UTC)
    bssid = "AA:BB:CC:44:55:66"

    records = [
        SimpleNamespace(
            sensor_id="sensor-01",
            ingested_at=now,
            data={
                "bssid": bssid,
                "timestamp_utc": now.isoformat(),
                "rssi_dbm": -80,
                "frequency_mhz": 2412,
            },
        ),
        SimpleNamespace(
            sensor_id="sensor-02",
            ingested_at=now,
            data={
                "bssid": bssid,
                "timestamp_utc": now.isoformat(),
                "rssi_dbm": -45,
                "frequency_mhz": 2412,
            },
        ),
    ]

    estimates = service.estimate_by_bssid(records)
    result = estimates[bssid]
    geo = result["geo"]

    assert geo["method"] == "strongest_rssi"
    assert geo["x_m"] == 25.0
    assert geo["y_m"] == 5.0
    assert geo["sample_sensor_count"] == 2
    assert geo["source_sensor_ids"] == ["sensor-01", "sensor-02"]


def test_invalid_geo_config_malformed_sensor_positions_json():
    env = {
        "ENVIRONMENT": "development",
        "GEO_ENABLED": "true",
        "SENSOR_POSITIONS_JSON": "{broken-json}",
    }

    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(RuntimeError, match="SENSOR_POSITIONS_JSON"):
            init_config()


def test_geo_config_safe_dict_has_sensor_count(geo_config_three_sensors: GeoConfig):
    safe = deepcopy(geo_config_three_sensors).safe_dict()
    assert safe["sensor_count"] == 3
    assert safe["enabled"] is True
