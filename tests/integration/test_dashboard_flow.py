import os

import pytest

# Skip entire module if dashboard credentials are not configured
pytestmark = pytest.mark.skipif(
    not os.environ.get("DASH_USERNAME"),
    reason="Dashboard secrets (DASH_USERNAME) not configured - skipping dashboard integration tests"
)

# Only import dashboard.app if we're actually going to run the tests
if os.environ.get("DASH_USERNAME"):
    from dashboard.app import update_metrics
else:
    update_metrics = None  # Placeholder

from unittest.mock import MagicMock, patch  # noqa: E402


def test_dashboard_metrics_update():
    """
    Integration Test: Dashboard Metrics Update
    Verifies that `update_metrics` correctly transforms API data into Dash components.
    Mocks `requests.get` to simulate Controller responses.
    """

    # Mock Data
    mock_networks = [
        {
            "bssid": "AA:11",
            "ssid": "Net1",
            "sensor_id": "s1",
            "risk_score": 10,
            "lat": 10.0,
            "lon": 10.0,
        },
        {
            "bssid": "BB:22",
            "ssid": "Net2",
            "sensor_id": "s2",
            "risk_score": 5,
            "lat": 10.1,
            "lon": 10.1,
        },
    ]

    mock_alerts = [
        {
            "timestamp": "2024-01-01T12:00:00",
            "severity": "Critical",
            "message": "Alert!",
            "recommendation": "Fix it",
        }
    ]

    # Mock Response Objects
    mock_resp_net = MagicMock()
    mock_resp_net.status_code = 200
    mock_resp_net.json.return_value = {"networks": mock_networks}

    mock_resp_alerts = MagicMock()
    mock_resp_alerts.status_code = 200
    mock_resp_alerts.json.return_value = {"alerts": mock_alerts}

    mock_resp_sensors = MagicMock()
    mock_resp_sensors.status_code = 200
    mock_resp_sensors.json.return_value = {
        "sensors": {"s1": {"status": "online"}, "s2": {"status": "online"}}
    }

    # Patch requests.get
    with patch("requests.get") as mock_get:
        # Side effect to return different responses based on URL (simple FIFO or match)
        # We'll use side_effect with a list (Net, Alerts, Sensors)
        mock_get.side_effect = [mock_resp_net, mock_resp_alerts, mock_resp_sensors]

        # Call the Dash callback logic directly
        # Inputs: n_intervals (int)
        # update_metrics returns 8 values now
        (
            fig,
            sensor_count,
            alert_count,
            network_count,
            alerts_comp,
            timestamp,
            sensor_tbl,
            pie_fig,
        ) = update_metrics(1)

        # Verify Interactions
        assert mock_get.call_count == 3

        # Verify Counts
        assert sensor_count == "2"  # s1, s2
        assert alert_count == "1"
        assert network_count == "2"

        # Verify Figure Data (Plotly Express returns a Figure object)
        # Check if latitude data is present
        assert "lat" in fig["data"][0]
        assert len(fig["data"][0]["lat"]) == 2

        # Verify Table Data
        # Dash Table is a complex component, verifying type or children presence
        assert hasattr(alerts_comp, "children")


def test_dashboard_error_handling():
    """Verify graceful handling of API failures"""

    with patch("requests.get", side_effect=Exception("Connection Failed")):
        (
            fig,
            sensor_count,
            alert_count,
            table,
            alerts_comp,
            timestamp,
            sensor_tbl,
            pie_fig,
        ) = update_metrics(1)

        # Should return error states (Graceful degradation -> 0)
        assert sensor_count == "0"
        assert alert_count == "0"
        # Table should be an Alert component (Danger)
        assert hasattr(alerts_comp, "children")
