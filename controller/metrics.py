from prometheus_client import Counter, Gauge, Histogram

# =============================================================================
# CONTROLLER METRICS (P0 Contract)
# =============================================================================

# Ingest Throughput & Status
INGEST_REQUESTS = Counter(
    "sentinel_controller_ingest_requests_total",
    "Total ingest requests received",
    ["status"],  # 2xx, 4xx, 5xx
)

INGEST_SUCCESS = Counter(
    "sentinel_controller_ingest_success_total",
    "Total successful ingest batches processed",
)

INGEST_FAILURES = Counter(
    "sentinel_controller_ingest_fail_total",
    "Total failed ingest batches",
    ["reason"],  # auth, validation, schema, throttle, internal
)

# Latency
INGEST_LATENCY = Histogram(
    "sentinel_controller_ingest_latency_seconds",
    "End-to-end ingest processing latency",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# Backpressure
BACKPRESSURE = Counter(
    "sentinel_controller_backpressure_total",
    "Total backpressure throttling events (503)",
)

# Queue Metrics (Exposed via Controller or Worker depending on architecture)
QUEUE_BACKLOG = Gauge(
    "sentinel_queue_backlog_size",
    "Current number of items in the queue",
    ["queue_name"],
)

QUEUE_AGE = Gauge(
    "sentinel_queue_oldest_age_seconds",
    "Age of the oldest item in the queue",
    ["queue_name"],
)

# Worker Metrics
WORKER_PROCESSED = Counter(
    "sentinel_worker_processed_total",
    "Total jobs processed by worker",
    ["result"],  # success, retry, dead
)

# Legacy aliases (to minimize code churn, verify if these are still needed)
# AUTH_FAILURES = Counter("auth_failures_total", "Authentication failures", ["type"])
# HMAC_FAILURES = Counter("hmac_failures_total", "HMAC verification failures", ["reason"])
# We should migrate usages to INGEST_FAILURES where appropriate, but kept for now compatibility?
# Actually, let's map them to new metrics in the usage sites.
