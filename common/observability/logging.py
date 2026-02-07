"""
Structured Logging with Correlation Context.
"""

import json
import logging
import os
import sys
from typing import Any

from common.observability.context import get_context
from common.privacy import anonymize_ssid


class JSONFormatter(logging.Formatter):
    """
    JSON formatter that includes correlation IDs from context
    and enforces PII redaction.
    """

    def __init__(self, service_name: str, version: str = "1.0", env: str = "dev"):
        super().__init__()
        self.service_name = service_name
        self.version = version
        self.env = env
        self.hostname = os.uname().nodename if hasattr(os, "uname") else "unknown"

    def format(self, record: logging.LogRecord) -> str:
        ctx = get_context()

        # Base log object
        log_obj: dict[str, Any] = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "component": self.service_name,
            "logger": record.name,
            "message": record.getMessage(),
            "env": self.env,
            "host": self.hostname,
            # Correlation IDs
            "request_id": ctx.get("request_id"),
            "sensor_id": ctx.get("sensor_id"),
            "batch_id": ctx.get("batch_id"),
            # Code location (optional in prod/info, good for debug)
            "code_path": f"{record.pathname}:{record.lineno}",
        }

        # Add event if present in extra args (e.g., logger.info(..., extra={"event": "ingest.success"}))
        if hasattr(record, "event"):
            log_obj["event"] = record.event  # type: ignore

        # Merge other extra fields
        if hasattr(record, "data"):
            data = record.data  # type: ignore
            if isinstance(data, dict):
                # Redact known PII keys in data dict
                self._redact_pii(data)
                log_obj.update(data)

        # Exception info
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj, default=str)

    def _redact_pii(self, data: dict):
        """In-place PII redaction for common sensitive keys"""
        # Dictionary of keys to redact and the function to use
        # This is simple; for deep nesting, need recursion

        # SSID
        if "ssid" in data and isinstance(data["ssid"], str):
            data["ssid"] = anonymize_ssid(data["ssid"])

        # Secrets - should be filtered before logging, but catch obvious ones
        for key in ["password", "token", "secret", "key"]:
            if key in data:
                data[key] = "[REDACTED]"


def configure_logging(
    component: str,
    level: str = "INFO",
    log_dir: str | None = None,
    json_mode: bool = True,
) -> logging.Logger:
    """
    Configure root logger with JSON formatter.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # Stream Handler (Stdout)
    stream_handler = logging.StreamHandler(sys.stdout)
    if json_mode:
        formatter = JSONFormatter(service_name=component)
        stream_handler.setFormatter(formatter)
    else:
        # Dev-friendly plain text
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        )
        stream_handler.setFormatter(formatter)

    root_logger.addHandler(stream_handler)

    # File Handler (Optional) with Rotation
    if log_dir:
        from logging.handlers import RotatingFileHandler

        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"{component}.log")
        # Rotate at 50MB, keep 5 backups (250MB total max per component)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=50 * 1024 * 1024, backupCount=5
        )
        file_formatter = JSONFormatter(service_name=component)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    return logging.getLogger(component)
