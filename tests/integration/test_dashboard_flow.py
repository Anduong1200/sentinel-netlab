import pytest
from unittest.mock import MagicMock, patch
from dashboard.app import update_metrics, app


def test_dashboard_metrics_update():
    """
    Integration Test: Dashboard Metrics Update
    Verifies that `update_metrics` correctly transforms API data into Dash components.
    Mocks `requests.get` to simulate Controller responses.
    """
    
    # Mock Data
    mock_networks = [
        {"bssid": "AA:11", "ssid": "Net1", "sensor_id": "s1", "risk_score": 10, "lat": 10.0, "lon": 10.0},
        {"bssid": "BB:22", "ssid": "Net2", "sensor_id": "s2", "risk_score": 5, "lat": 10.1, "lon": 10.1},
    ]
    
    mock_alerts = [
        {"timestamp": "2024-01-01T12:00:00", "severity": "Critical", "message": "Alert!", "recommendation": "Fix it"}
    ]
    
    # Mock Response Objects
    mock_resp_net = MagicMock()
    mock_resp_net.status_code = 200
    mock_resp_net.json.return_value = {"networks": mock_networks}
    
    mock_resp_alerts = MagicMock()
    mock_resp_alerts.status_code = 200
    mock_resp_alerts.json.return_value = {"alerts": mock_alerts}
    
    # Patch requests.get
    with patch("requests.get") as mock_get:
        # Side effect to return different responses based on URL (simple FIFO or match)
        # We'll use side_effect with a list (Net, Alerts)
        mock_get.side_effect = [mock_resp_net, mock_resp_alerts]
        
        # Call the Dash callback logic directly
        # Inputs: n_intervals (int)
        fig, sensor_count, alert_count, table = update_metrics(1)
        
        # Verify Interactions
        assert mock_get.call_count == 2
        
        # Verify Counts
        assert sensor_count == "2"  # s1, s2
        assert alert_count == "1"
        
        # Verify Figure Data (Plotly Express returns a Figure object)
        # Check if latitude data is present
        assert "lat" in fig["data"][0]
        assert len(fig["data"][0]["lat"]) == 2
        
        # Verify Table Data
        # Dash Table is a complex component, verifying type or children presence
        assert hasattr(table, "children")

def test_dashboard_error_handling():
    """Verify graceful handling of API failures"""
    
    with patch("requests.get", side_effect=Exception("Connection Failed")):
        fig, sensor_count, alert_count, table = update_metrics(1)
        
        # Should return error states
        assert sensor_count == "ERR"
        assert alert_count == "ERR"
        # Table should be an Alert component (Danger)
        assert hasattr(table, "color")
