from prometheus_client import Counter

AUTH_FAILURES = Counter("auth_failures_total", "Authentication failures", ["type"])
HMAC_FAILURES = Counter("hmac_failures_total", "HMAC verification failures", ["reason"])
REQUESTS = Counter(
    "http_requests_total", "HTTP Requests", ["method", "endpoint", "status"]
)
