"""
Monitoring Module for Sentinel NetLab
Handles Prometheus metrics and JSON logging configuration.
"""

import logging

from flask import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from pythonjsonlogger import jsonlogger

# -----------------------------------------------------------------------------
# Prometheus Metrics Definitions
# -----------------------------------------------------------------------------

# Request counters
REQUESTS = Counter(
    'wifi_api_requests_total',
    'Total API requests',
    ['endpoint', 'method', 'status']
)

# Latency histogram
LATENCY = Histogram(
    'wifi_api_request_latency_seconds',
    'Request latency in seconds',
    ['endpoint']
)

# Operational Gauges
SCAN_DURATION = Gauge(
    'wifi_scan_duration_seconds',
    'Duration of the last WiFi scan'
)

NETWORKS_FOUND = Gauge(
    'wifi_networks_found_count',
    'Number of networks found in the last scan'
)

ACTIVE_ALERTS = Gauge(
    'wifi_active_security_alerts',
    'Number of active security alerts (e.g. Rogue APs)'
)

SYSTEM_INFO = Gauge(
    'wifi_sensor_info',
    'Sensor information',
    ['version', 'interface', 'engine']
)

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------


def setup_json_logging(app_name='sentinel-sensor'):
    """
    Configure structured JSON logging for ELK stack integration.
    """
    logger = logging.getLogger()
    logHandler = logging.StreamHandler()

    # Custom JSON formatter
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(levelname)s %(name)s %(message)s %(module)s %(funcName)s'
    )
    logHandler.setFormatter(formatter)

    # Reset handlers and add JSON handler
    logger.handlers = []
    logger.addHandler(logHandler)
    logger.setLevel(logging.INFO)

    return logger

# -----------------------------------------------------------------------------
# Metrics Endpoint Handler
# -----------------------------------------------------------------------------


def prometheus_metrics_endpoint():
    """
    Flask route handler for /metrics
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
