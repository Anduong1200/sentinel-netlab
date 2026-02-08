from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from controller.baseline.builder import BaselineBuilder
from controller.baseline.models import BaselineProfile
from controller.baseline.store import BaselineStore


# Mock Session
@pytest.fixture
def mock_session():
    return MagicMock()


@pytest.fixture
def store(mock_session):
    return BaselineStore(session=mock_session)


@pytest.fixture
def builder(store):
    return BaselineBuilder(store)


def test_warmup_logic(builder):
    """Verify is_warmed_up logic."""
    # 1. New Profile -> False
    profile = BaselineProfile(first_seen=datetime.now(UTC), sample_count=50)
    assert builder.is_warmed_up(profile) is False

    # 2. Old enough but low samples -> False
    profile.first_seen = datetime.now(UTC) - timedelta(days=4)
    profile.sample_count = 50
    assert builder.is_warmed_up(profile) is False

    # 3. Old enough AND high samples -> True
    profile.sample_count = 150
    assert builder.is_warmed_up(profile) is True


def test_stats_update(builder, store):
    """Verify feature statistics update correctly."""
    # Setup Mock
    profile = BaselineProfile(
        id="test_id",
        sample_count=0,  # Initialize to avoid None
        features={
            "channels": {},
            "rssi": {"min": 999, "max": -999, "sum": 0, "count": 0},
        },
    )
    store.get_or_create_profile = MagicMock(return_value=profile)

    # Telemetry
    telemetry = [
        {"ssid": "TestNet", "security": "WPA2", "channel": 6, "rssi_dbm": -60},
        {"ssid": "TestNet", "security": "WPA2", "channel": 6, "rssi_dbm": -55},
        {"ssid": "TestNet", "security": "WPA2", "channel": 1, "rssi_dbm": -70},
    ]

    builder.update_from_telemetry("site_1", telemetry)

    # Verify Channels
    # Channel 6: 2 counts, Channel 1: 1 count
    assert profile.features["channels"]["6"] == 2
    assert profile.features["channels"]["1"] == 1

    # Verify RSSI
    # Min: -70, Max: -55, Count: 3
    rssi = profile.features["rssi"]
    assert rssi["min"] == -70
    assert rssi["max"] == -55
    assert rssi["count"] == 3
