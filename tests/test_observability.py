import json
import logging
import io
import pytest
from common.observability import context
from common.observability.logging import JSONFormatter, configure_logging
from common.observability import metrics

def test_context_storage():
    """Verify thread-local context storage"""
    context.clear_context()
    assert context.get_context() == {"request_id": None, "sensor_id": None, "batch_id": None}
    
    context.set_context(request_id="req-123", sensor_id="sensor-007")
    ctx = context.get_context()
    assert ctx["request_id"] == "req-123"
    assert ctx["sensor_id"] == "sensor-007"
    assert ctx["batch_id"] is None
    
    context.clear_context()
    assert context.get_context()["request_id"] is None

def test_json_formatter():
    """Verify JSON formatter includes context and structure"""
    context.set_context(request_id="req-test", batch_id="batch-99")
    
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="Test message",
        args=(),
        exc_info=None
    )
    
    formatter = JSONFormatter(service_name="test-service", env="test")
    log_output = formatter.format(record)
    log_dict = json.loads(log_output)
    
    assert log_dict["component"] == "test-service"
    assert log_dict["env"] == "test"
    assert log_dict["message"] == "Test message"
    assert log_dict["request_id"] == "req-test"
    assert log_dict["batch_id"] == "batch-99"
    assert "ts" in log_dict

def test_pii_redaction():
    """Verify sensitive fields are redacted"""
    formatter = JSONFormatter(service_name="test-service")
    
    # 1. SSID Redaction
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="x", lineno=1,
        msg="Found network", args=(), exc_info=None
    )
    record.data = {"ssid": "PrivateWifi", "rssi": -50}
    
    log_dict = json.loads(formatter.format(record))
    assert log_dict["ssid"] != "PrivateWifi"
    assert log_dict["ssid"].startswith("*********") or len(log_dict["ssid"]) > 0
    assert log_dict["rssi"] == -50
    
    # 2. Secret Redaction
    record.data = {"password": "supersecret", "api_token": "abcdef"}
    log_dict = json.loads(formatter.format(record))
    assert log_dict["password"] == "[REDACTED]"

def test_metrics_creation():
    """Verify metrics helpers"""
    if not metrics.PROMETHEUS_AVAILABLE:
        pytest.skip("Prometheus client not installed")
        
    c = metrics.create_counter("test_counter", "Test desc", ["label1"])
    assert c is not None
    assert c._name == "sentinel_test_counter"
