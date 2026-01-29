import json
import logging
import os
from typing import Any


class StructuredFormatter(logging.Formatter):
    """
    JSON log formatter for structured logging.
    """

    def __init__(self, service_name: str = "sentinel", version: str = "1.0"):
        super().__init__()
        self.service_name = service_name
        self.version = version
        self.hostname = os.uname().nodename if hasattr(os, "uname") else "unknown"

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
            "version": self.version,
            "host": self.hostname,
            "path": record.pathname,
            "line": record.lineno,
            "thread": record.threadName,
        }

        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        # Add extra fields provided in extra={}
        if hasattr(record, "data"):
            log_obj["data"] = record.data  # type: ignore

        return json.dumps(log_obj)


def setup_logger(
    name: str, level: str = "INFO", service_name: str = "sentinel"
) -> logging.Logger:
    """
    Configure structured logger.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    handler = logging.StreamHandler()
    formatter = StructuredFormatter(service_name=service_name)
    handler.setFormatter(formatter)

    # Remove existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()

    logger.addHandler(handler)
    return logger
