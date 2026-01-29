"""
Sentinel NetLab - Metrics Collector
====================================
Prometheus-compatible metrics for monitoring sensor and controller.

Exports:
- Capture metrics (frames/sec, dropped)
- Parser metrics (errors, latency)
- Detection metrics (alerts by type)
- Transport metrics (upload success/failure)
"""

import time
from dataclasses import dataclass, field

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Gauge,
        Histogram,
        Info,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    generate_latest = None
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"


# =============================================================================
# PROMETHEUS METRICS (if available)
# =============================================================================

if PROMETHEUS_AVAILABLE:
    # Capture metrics
    FRAMES_CAPTURED = Counter(
        "sentinel_frames_captured_total",
        "Total frames captured",
        ["sensor_id", "frame_type"],
    )
    FRAMES_DROPPED = Counter(
        "sentinel_frames_dropped_total",
        "Total frames dropped",
        ["sensor_id", "reason"],
    )
    FRAMES_PER_SECOND = Gauge(
        "sentinel_frames_per_second",
        "Current frames per second",
        ["sensor_id"],
    )

    # Parser metrics
    PARSE_ERRORS = Counter(
        "sentinel_parse_errors_total",
        "Total frame parse errors",
        ["sensor_id", "error_type"],
    )
    PARSE_LATENCY = Histogram(
        "sentinel_parse_latency_seconds",
        "Frame parsing latency",
        ["sensor_id"],
        buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1),
    )

    # Detection metrics
    ALERTS_GENERATED = Counter(
        "sentinel_alerts_total",
        "Total alerts generated",
        ["sensor_id", "alert_type", "severity"],
    )
    RISK_SCORE = Gauge(
        "sentinel_risk_score",
        "Current risk score for network",
        ["sensor_id", "bssid"],
    )

    # Transport metrics
    UPLOAD_SUCCESS = Counter(
        "sentinel_upload_success_total",
        "Successful uploads to controller",
        ["sensor_id"],
    )
    UPLOAD_FAILURE = Counter(
        "sentinel_upload_failure_total",
        "Failed uploads to controller",
        ["sensor_id", "reason"],
    )
    UPLOAD_LATENCY = Histogram(
        "sentinel_upload_latency_seconds",
        "Upload latency to controller",
        ["sensor_id"],
        buckets=(0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10),
    )

    # System metrics
    SENSOR_INFO = Info(
        "sentinel_sensor",
        "Sensor information",
    )
    SENSOR_UPTIME = Gauge(
        "sentinel_sensor_uptime_seconds",
        "Sensor uptime in seconds",
        ["sensor_id"],
    )
    CPU_USAGE = Gauge(
        "sentinel_cpu_percent",
        "CPU usage percentage",
        ["sensor_id"],
    )
    MEMORY_USAGE = Gauge(
        "sentinel_memory_percent",
        "Memory usage percentage",
        ["sensor_id"],
    )

    # Network metrics
    NETWORKS_SEEN = Gauge(
        "sentinel_networks_seen_total",
        "Total unique networks seen",
        ["sensor_id"],
    )
    ACTIVE_NETWORKS = Gauge(
        "sentinel_networks_active",
        "Currently active networks",
        ["sensor_id"],
    )


# =============================================================================
# LOCAL METRICS (fallback when Prometheus not available)
# =============================================================================


@dataclass
class LocalMetrics:
    """In-memory metrics when Prometheus not available"""

    # Counters
    frames_captured: int = 0
    frames_dropped: int = 0
    parse_errors: int = 0
    alerts_generated: int = 0
    upload_success: int = 0
    upload_failure: int = 0

    # Gauges
    frames_per_second: float = 0.0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    networks_seen: int = 0

    # Timing
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)

    # History for rates
    _frame_times: list = field(default_factory=list)

    def record_frame(self) -> None:
        """Record a captured frame"""
        self.frames_captured += 1
        now = time.time()
        self._frame_times.append(now)

        # Keep last 100 frames for rate calculation
        cutoff = now - 10  # 10 second window
        self._frame_times = [t for t in self._frame_times if t > cutoff]

        # Calculate rate
        if len(self._frame_times) > 1:
            duration = self._frame_times[-1] - self._frame_times[0]
            if duration > 0:
                self.frames_per_second = len(self._frame_times) / duration

    def record_drop(self) -> None:
        """Record a dropped frame"""
        self.frames_dropped += 1

    def record_alert(self) -> None:
        """Record a generated alert"""
        self.alerts_generated += 1

    def record_parse_error(self) -> None:
        """Record a parse error"""
        self.parse_errors += 1

    @property
    def uptime_seconds(self) -> float:
        """Get uptime in seconds"""
        return time.time() - self.start_time

    def to_dict(self) -> dict:
        """Export metrics as dictionary"""
        return {
            "frames_captured": self.frames_captured,
            "frames_dropped": self.frames_dropped,
            "parse_errors": self.parse_errors,
            "alerts_generated": self.alerts_generated,
            "upload_success": self.upload_success,
            "upload_failure": self.upload_failure,
            "frames_per_second": round(self.frames_per_second, 2),
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "networks_seen": self.networks_seen,
            "uptime_seconds": round(self.uptime_seconds, 2),
        }


# =============================================================================
# METRICS COLLECTOR
# =============================================================================


class MetricsCollector:
    """
    Unified metrics collector.
    Uses Prometheus when available, falls back to local metrics.

    Usage:
        collector = MetricsCollector(sensor_id="sensor-01")
        collector.record_frame("beacon")
        collector.record_alert("evil_twin", "High")

        # Get metrics dict
        stats = collector.get_stats()
    """

    def __init__(self, sensor_id: str):
        self.sensor_id = sensor_id
        self.local = LocalMetrics()
        self.use_prometheus = PROMETHEUS_AVAILABLE

        # Initialize sensor info if Prometheus available
        if self.use_prometheus:
            SENSOR_INFO.info(
                {
                    "sensor_id": sensor_id,
                    "version": "1.0.0",
                }
            )

    def record_frame(self, frame_type: str = "unknown") -> None:
        """Record a captured frame"""
        self.local.record_frame()
        if self.use_prometheus:
            FRAMES_CAPTURED.labels(
                sensor_id=self.sensor_id, frame_type=frame_type
            ).inc()
            FRAMES_PER_SECOND.labels(sensor_id=self.sensor_id).set(
                self.local.frames_per_second
            )

    def record_drop(self, reason: str = "buffer_full") -> None:
        """Record a dropped frame"""
        self.local.record_drop()
        if self.use_prometheus:
            FRAMES_DROPPED.labels(sensor_id=self.sensor_id, reason=reason).inc()

    def record_parse_error(self, error_type: str = "unknown") -> None:
        """Record a parse error"""
        self.local.record_parse_error()
        if self.use_prometheus:
            PARSE_ERRORS.labels(sensor_id=self.sensor_id, error_type=error_type).inc()

    def record_alert(self, alert_type: str, severity: str) -> None:
        """Record a generated alert"""
        self.local.record_alert()
        if self.use_prometheus:
            ALERTS_GENERATED.labels(
                sensor_id=self.sensor_id,
                alert_type=alert_type,
                severity=severity,
            ).inc()

    def record_upload(self, success: bool, reason: str = "") -> None:
        """Record upload result"""
        if success:
            self.local.upload_success += 1
            if self.use_prometheus:
                UPLOAD_SUCCESS.labels(sensor_id=self.sensor_id).inc()
        else:
            self.local.upload_failure += 1
            if self.use_prometheus:
                UPLOAD_FAILURE.labels(sensor_id=self.sensor_id, reason=reason).inc()

    def set_risk_score(self, bssid: str, score: float) -> None:
        """Set risk score for a network"""
        if self.use_prometheus:
            RISK_SCORE.labels(sensor_id=self.sensor_id, bssid=bssid).set(score)

    def set_networks_count(self, total: int, active: int) -> None:
        """Set network counts"""
        self.local.networks_seen = total
        if self.use_prometheus:
            NETWORKS_SEEN.labels(sensor_id=self.sensor_id).set(total)
            ACTIVE_NETWORKS.labels(sensor_id=self.sensor_id).set(active)

    def set_system_metrics(self, cpu: float, memory: float) -> None:
        """Set system resource metrics"""
        self.local.cpu_percent = cpu
        self.local.memory_percent = memory
        if self.use_prometheus:
            CPU_USAGE.labels(sensor_id=self.sensor_id).set(cpu)
            MEMORY_USAGE.labels(sensor_id=self.sensor_id).set(memory)
            SENSOR_UPTIME.labels(sensor_id=self.sensor_id).set(
                self.local.uptime_seconds
            )

    def get_stats(self) -> dict:
        """Get current metrics as dictionary"""
        return self.local.to_dict()

    def time_parse(self):
        """Context manager for timing parse operations"""
        if self.use_prometheus:
            return PARSE_LATENCY.labels(sensor_id=self.sensor_id).time()
        return _DummyTimer()

    def time_upload(self):
        """Context manager for timing upload operations"""
        if self.use_prometheus:
            return UPLOAD_LATENCY.labels(sensor_id=self.sensor_id).time()
        return _DummyTimer()


class _DummyTimer:
    """Dummy context manager when Prometheus not available"""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def generate_latest_metrics():
    """Generate latest Prometheus metrics"""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(), CONTENT_TYPE_LATEST
    return b"", "text/plain"
