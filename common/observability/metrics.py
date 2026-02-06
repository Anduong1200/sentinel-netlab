"""
Metrics Infrastructure (Prometheus).
Standardizes metric naming and registration.
"""

import time

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        REGISTRY,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
        multiprocess,
        start_http_server,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    generate_latest = None
    REGISTRY = None
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"


def init_metrics(component: str):
    """
    Initialize metrics subsystem for a component.
    If using multiprocess (e.g. Gunicorn), setups multiprocess collector.
    """
    if not PROMETHEUS_AVAILABLE:
        return

    # In multiprocess environments (like Gunicorn), we need special handling
    # Use PROMETHEUS_MULTIPROC_DIR env var
    pass


def metrics_endpoint():
    """Returns (body, content_type) for /metrics endpoint"""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
    return b"", "text/plain"


# Standard Metrics Factories (enforce prefix)
PREFIX = "sentinel"


# Dummy Classes for safe fallback
class DummyMetric:
    def labels(self, **kwargs): return self
    def inc(self, amount=1): pass
    def set(self, value): pass
    def observe(self, value): pass
    def time(self): return _DummyTimer()

def create_counter(name: str, desc: str, labels: list[str]) -> Counter:
    if not PROMETHEUS_AVAILABLE: return DummyMetric()
    return Counter(f"{PREFIX}_{name}", desc, labels, registry=REGISTRY)

def create_gauge(name: str, desc: str, labels: list[str]) -> Gauge:
    if not PROMETHEUS_AVAILABLE: return DummyMetric()
    return Gauge(f"{PREFIX}_{name}", desc, labels, registry=REGISTRY)

def create_histogram(name: str, desc: str, labels: list[str], buckets=None) -> Histogram:
    if not PROMETHEUS_AVAILABLE: return DummyMetric()
    kwargs = {"registry": REGISTRY}
    if buckets: kwargs["buckets"] = buckets
    return Histogram(f"{PREFIX}_{name}", desc, labels, **kwargs)


# =============================================================================
# HTTP METRICS
# =============================================================================

HTTP_REQUEST_DURATION_SECONDS = create_histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint", "status_code"],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0),
)


class HTTPMetricsMiddleware:
    """
    WSGI/Flask Middleware for HTTP metrics.
    Measures latency and counts requests.
    """

    def __init__(self, app, exclude_paths: list[str] = None):
        self.app = app
        self.exclude_paths = exclude_paths or ["/metrics", "/health", "/healthz"]

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path in self.exclude_paths:
            return self.app(environ, start_response)

        start_time = time.time()
        method = environ.get("REQUEST_METHOD", "UNKNOWN")

        def status_start_response(status, headers, *args):
            # Extract status code (e.g. "200 OK" -> "200")
            status_code = status.split()[0]
            duration = time.time() - start_time

            if HTTP_REQUEST_DURATION_SECONDS:
                HTTP_REQUEST_DURATION_SECONDS.labels(
                    method=method, endpoint=path, status_code=status_code
                ).observe(duration)

            return start_response(status, headers, *args)

        return self.app(environ, status_start_response)


# =============================================================================
# SLO METRICS
# =============================================================================

INGEST_TOTAL = create_counter(
    "ingest_total", "Total telemetry batches ingested", ["sensor_id"]
)

INGEST_SUCCESS = create_counter(
    "ingest_success_total", "Successful telemetry ingests", ["sensor_id"]
)

INGEST_FAILURE = create_counter(
    "ingest_failure_total", "Failed telemetry ingests", ["sensor_id", "reason"]
)

INGEST_LATENCY = create_histogram(
    "ingest_latency_seconds",
    "End-to-end ingest latency (sensor upload to controller ACK)",
    ["sensor_id"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


class _DummyTimer:
    """Dummy context manager for timer when prometheus is not available."""
    def __enter__(self): return self
    def __exit__(self, *args): pass

