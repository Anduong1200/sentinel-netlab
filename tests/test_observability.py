
import pytest
from unittest.mock import MagicMock, patch
from common.observability.ingest_logger import IngestLogger
from common.observability.metrics import INGEST_TOTAL, INGEST_SUCCESS, INGEST_LATENCY
from controller.tasks import process_telemetry_batch
import logging

class TestObservability:
    def test_ingest_logger_context(self):
        """Verify IngestLogger sets and clears context"""
        logger = MagicMock()
        ingest_logger = IngestLogger(logger)
        
        with patch("common.observability.ingest_logger.set_context") as mock_set:
            with patch("common.observability.ingest_logger.clear_context") as mock_clear:
                ingest_logger.info("Test message", "s1", "b1")
                
                mock_set.assert_called_with(sensor_id="s1", batch_id="b1")
                mock_clear.assert_called_once()
                logger.log.assert_called_once()
                call_args = logger.log.call_args
                assert call_args[1].get("extra", {}).get("data", {}).get("sensor_id") == "s1"

    def test_metrics_instrumentation(self):
        """Verify process_telemetry_batch records metrics"""
        # Mock DB and App Context
        with patch("controller.tasks.app.app_context"):
            with patch("controller.tasks.db.session"):
                with patch("controller.tasks.IngestJob") as MockJob:
                    # Setup: No existing batch
                    from controller.tasks import db
                    db.session.get.return_value = None
                    new_batch = MagicMock()
                    MockJob.return_value = new_batch
                    
                    # Mock Metrics
                    with patch.object(INGEST_TOTAL, "labels") as mock_total:
                        with patch.object(INGEST_SUCCESS, "labels") as mock_success:
                            with patch.object(INGEST_LATENCY, "labels") as mock_latency:
                                
                                # Execute
                                items = [{"timestamp": "2024-01-01T00:00:00", "bssid": "aa:bb:cc:dd:ee:ff"}]
                                process_telemetry_batch(batch_id="b1", sensor_id="s1", items=items)
                                
                                # Verify
                                mock_total.assert_called_with(sensor_id="s1")
                                mock_total.return_value.inc.assert_called_once()
                                
                                mock_success.assert_called_with(sensor_id="s1")
                                mock_success.return_value.inc.assert_called_once()
                                
                                mock_latency.assert_called_with(sensor_id="s1")
                                mock_latency.return_value.observe.assert_called_once()
