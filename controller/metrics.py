from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

AUTH_FAILURES = Counter("auth_failures_total", "Authentication failures", ["type"])
HMAC_FAILURES = Counter("hmac_failures_total", "HMAC verification failures")
REQUESTS = Counter(
    "http_requests_total", "HTTP Requests", ["method", "endpoint", "status"]
)
