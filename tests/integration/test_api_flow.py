def test_telemetry_ingestion_flow(
    app_client, auth_headers, sensor_auth_headers, mock_telemetry_batch
):
    """
    Integration Test: Telemetry Ingestion Flow
    1. POST /telemetry (Sensor Role) -> Success
    2. GET /telemetry (Analyst Role) -> Verify Data
    3. GET /networks (Dashboard Role) -> Verify Aggregation
    """

    # 1. Ingest Telemetry (as Sensor)
    resp = app_client.post(
        "/api/v1/telemetry", headers=sensor_auth_headers, json=mock_telemetry_batch
    )
    assert resp.status_code == 200
    assert resp.json["success"] is True
    assert resp.json["accepted"] == len(mock_telemetry_batch["items"])

    # 2. Query Telemetry (as Admin/Analyst)
    resp = app_client.get("/api/v1/telemetry", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json["items"]
    assert len(items) >= 2

    # Verify content
    ssids = [i["ssid"] for i in items]
    assert "TestNet" in ssids
    assert "SecondNet" in ssids

    # 3. Verify Networks Aggregation (Snapshot)
    resp = app_client.get("/api/v1/networks", headers=auth_headers)
    assert resp.status_code == 200
    networks = resp.json["networks"]

    # Should be deduplicated by BSSID
    assert len(networks) >= 2
    network_ssids = {n["ssid"] for n in networks}
    assert "TestNet" in network_ssids


def test_alert_creation_flow(app_client, sensor_auth_headers, auth_headers, mock_alert):
    """
    Integration Test: Alert Lifecycle
    1. POST /alerts (Sensor) -> Success
    2. GET /alerts (Analyst) -> Verify Created
    """

    # 1. Create Alert
    resp = app_client.post(
        "/api/v1/alerts", headers=sensor_auth_headers, json=mock_alert
    )
    assert resp.status_code == 200
    assert "alert_id" in resp.json
    alert_id = resp.json["alert_id"]

    # 2. List Alerts
    resp = app_client.get("/api/v1/alerts", headers=auth_headers)
    assert resp.status_code == 200
    alerts = resp.json["items"]

    # Verify our alert is present
    found = False
    for a in alerts:
        if a["id"] == alert_id:
            found = True
            assert a["title"] == mock_alert["title"]
            assert a["severity"] == mock_alert["severity"]
            break
    assert found


def test_unauthorized_access(app_client):
    """Verify security controls"""
    # No token
    resp = app_client.get("/api/v1/telemetry")
    assert resp.status_code == 401

    # Invalid token
    resp = app_client.get(
        "/api/v1/telemetry", headers={"Authorization": "Bearer invalid-token"}
    )
    assert resp.status_code == 401
