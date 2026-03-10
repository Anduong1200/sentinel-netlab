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
    import time

    mock_telemetry_batch["batch_id"] = f"unique-flow-{time.time()}"
    resp = app_client.post(
        "/api/v1/telemetry", headers=sensor_auth_headers, json=mock_telemetry_batch
    )
    if resp.status_code != 202:
        print(f"Validation Error: {resp.json}")
    assert resp.status_code == 202
    assert resp.json["success"] is True

    # Manually process queue
    from controller.ingest.worker import IngestWorker

    worker = IngestWorker()
    worker.app = app_client.application
    with worker.app.app_context():
        worker._loop()

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
    assert resp.status_code == 202
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


def test_networks_geo_enrichment(app_client, auth_headers):
    """GET /networks includes distributed geo metadata when geo is enabled."""
    from copy import deepcopy
    from datetime import UTC, datetime

    from controller.api.deps import db
    from controller.api.telemetry import config as telemetry_config
    from controller.db.models import Sensor, Telemetry

    original_geo = deepcopy(telemetry_config.geo)

    try:
        telemetry_config.geo.enabled = True
        telemetry_config.geo.sensor_positions = {
            "sensor-01": {"x": 0.0, "y": 0.0},
            "sensor-02": {"x": 20.0, "y": 0.0},
            "sensor-03": {"x": 10.0, "y": 17.3},
        }
        telemetry_config.geo.origin_lat = 10.776889
        telemetry_config.geo.origin_lon = 106.700806
        telemetry_config.geo.sample_window_sec = 120

        now = datetime.now(UTC)
        target_bssid = "AA:BB:CC:11:22:33"
        legacy_bssid = "AA:BB:CC:99:99:99"

        with app_client.application.app_context():
            for sensor_id in ["sensor-01", "sensor-02", "sensor-03", "sensor-99"]:
                db.session.merge(Sensor(id=sensor_id, name=sensor_id, status="online"))
            db.session.flush()

            db.session.add_all(
                [
                    Telemetry(
                        sensor_id="sensor-01",
                        batch_id="geo-it-1",
                        timestamp=now,
                        ingested_at=now,
                        bssid=target_bssid,
                        ssid="GeoNet",
                        channel=1,
                        rssi_dbm=-48,
                        frequency_mhz=2412,
                        raw_data={
                            "sensor_id": "sensor-01",
                            "bssid": target_bssid,
                            "ssid": "GeoNet",
                            "rssi_dbm": -48,
                            "frequency_mhz": 2412,
                            "timestamp_utc": now.isoformat(),
                        },
                    ),
                    Telemetry(
                        sensor_id="sensor-02",
                        batch_id="geo-it-2",
                        timestamp=now,
                        ingested_at=now,
                        bssid=target_bssid,
                        ssid="GeoNet",
                        channel=6,
                        rssi_dbm=-55,
                        frequency_mhz=2412,
                        raw_data={
                            "sensor_id": "sensor-02",
                            "bssid": target_bssid,
                            "ssid": "GeoNet",
                            "rssi_dbm": -55,
                            "frequency_mhz": 2412,
                            "timestamp_utc": now.isoformat(),
                        },
                    ),
                    Telemetry(
                        sensor_id="sensor-03",
                        batch_id="geo-it-3",
                        timestamp=now,
                        ingested_at=now,
                        bssid=target_bssid,
                        ssid="GeoNet",
                        channel=11,
                        rssi_dbm=-51,
                        frequency_mhz=2412,
                        raw_data={
                            "sensor_id": "sensor-03",
                            "bssid": target_bssid,
                            "ssid": "GeoNet",
                            "rssi_dbm": -51,
                            "frequency_mhz": 2412,
                            "timestamp_utc": now.isoformat(),
                        },
                    ),
                    # Unknown sensor position -> should still return record, no forced geo failure
                    Telemetry(
                        sensor_id="sensor-99",
                        batch_id="geo-it-4",
                        timestamp=now,
                        ingested_at=now,
                        bssid=legacy_bssid,
                        ssid="LegacyNet",
                        channel=1,
                        rssi_dbm=-70,
                        frequency_mhz=2412,
                        raw_data={
                            "sensor_id": "sensor-99",
                            "bssid": legacy_bssid,
                            "ssid": "LegacyNet",
                            "rssi_dbm": -70,
                            "frequency_mhz": 2412,
                            "timestamp_utc": now.isoformat(),
                        },
                    ),
                ]
            )
            db.session.commit()

        resp = app_client.get("/api/v1/networks", headers=auth_headers)
        assert resp.status_code == 200

        networks_by_bssid = {n["bssid"]: n for n in resp.json["networks"]}
        assert target_bssid in networks_by_bssid
        assert legacy_bssid in networks_by_bssid

        geo_net = networks_by_bssid[target_bssid]
        assert "geo" in geo_net
        assert geo_net["geo"]["method"] in {"trilateration+kalman", "strongest_rssi"}
        assert "lat" in geo_net and geo_net["lat"] is not None
        assert "lon" in geo_net and geo_net["lon"] is not None
        assert "sample_sensor_count" in geo_net["geo"]

        legacy_net = networks_by_bssid[legacy_bssid]
        assert legacy_net["ssid"] == "LegacyNet"
        assert "geo" not in legacy_net

    finally:
        telemetry_config.geo = original_geo

