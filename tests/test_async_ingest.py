from unittest.mock import patch

import pytest

from controller.db.models import IngestJob, Telemetry


# Use fixtures from conftest.py
def test_ingest_telemetry_async_contract(app_client, sensor_auth_headers):
    """Verify API returns 202 and enqueues task"""
    if app_client is None:
        pytest.skip("Client fixture not available")

    payload = {
        "sensor_id": "sensor-01",
        "batch_id": "test-batch-async-01",
        "items": [
            {
                "sensor_id": "sensor-01",
                "timestamp_utc": "2026-02-26T12:00:00Z",
                "sequence_id": 1,
                "frame_type": "beacon",
                "bssid": "AA:BB:CC:11:22:33",
                "rssi_dbm": -50,
                "channel": 6,
            }
        ],
    }

    # Mock the Queue
    with patch("controller.api.telemetry.IngestQueue.enqueue") as mock_enqueue:
        mock_enqueue.return_value = ("test-batch-async-01", False)

        response = app_client.post(
            "/api/v1/telemetry", json=payload, headers=sensor_auth_headers
        )

        if response.status_code != 202:
            print(f"FAIL: {response.json}")
        assert response.status_code == 202
        assert response.json["status"] == "queued"
        assert response.json["ack_id"] == "test-batch-async-01"

        # Verify enqueue
        mock_enqueue.assert_called_once()
        args = mock_enqueue.call_args[0]
        assert args[0] == "sensor-01"
        assert args[1] == "test-batch-async-01"
        assert len(args[2]["items"]) == 1


def test_worker_task_logic():
    """Verify the worker task actually writes to DB"""
    from controller.api.deps import create_app, db
    from controller.tasks import process_telemetry_batch

    # Setup temp app
    app = create_app()
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    # Or reuse the file DB from conftest if we want, but memory is cleaner if isolation works.
    # However, create_app might load from Environment.

    with app.app_context():
        db.create_all()

        # Data
        batch_id = "worker-test-batch-01"
        sensor_id = "sensor-worker-01"
        items = [{"temp": 100}, {"humidity": 50}]

        # Patch the 'app' inside tasks.py to use OUR app instance
        # tasks.py imports create_app, and initializes `app = create_app()`.
        # We need to ensure that the task uses the CURRENT setup logic or mock it.
        # Actually `controller.tasks.app` is the one used in `with app.app_context():`.

        with patch("controller.tasks.app", app):
            result = process_telemetry_batch(batch_id, sensor_id, items)

            assert result["status"] == "success"
            assert result["accepted"] == 2

            # Verify DB (using our session)
            batch = db.session.get(IngestJob, batch_id)
            assert batch is not None
            assert batch.status == "processed"

            telem = Telemetry.query.filter_by(batch_id=batch_id).all()
            assert len(telem) == 2
