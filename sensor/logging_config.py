#!/usr/bin/env python3
"""
Sentinel NetLab - Centralized Logging Configuration
Single source of truth for all logging across sensor and controller.

Usage:
    from sensor.logging_config import get_logger, setup_logging
    
    # Setup at application start
    setup_logging(level="INFO", json_format=True)
    
    # Get logger in any module
    logger = get_logger(__name__)
    logger.info("Message", extra={"trace_id": "abc123"})
"""

import os
import sys
import json
import logging
import logging.handlers
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from functools import lru_cache


# =============================================================================
# JSON FORMATTER (Structured Logging)
# =============================================================================

class JSONFormatter(logging.Formatter):
    """JSON structured log formatter with trace ID support"""
    
    def __init__(self, service_name: str = "sentinel"):
        super().__init__()
        self.service_name = service_name
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }
        
        # Add trace ID if present
        if hasattr(record, 'trace_id'):
            log_data["trace_id"] = record.trace_id
        
        # Add sensor ID if present
        if hasattr(record, 'sensor_id'):
            log_data["sensor_id"] = record.sensor_id
        
        # Add extra fields
        if hasattr(record, 'extra_data'):
            log_data.update(record.extra_data)
        
        # Add exception info
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add location info for debug
        if record.levelno >= logging.DEBUG:
            log_data["location"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName
            }
        
        return json.dumps(log_data, default=str)


class ColoredFormatter(logging.Formatter):
    """Colored console formatter for development"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, '')
        
        # Format timestamp
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Build message
        msg = f"{color}[{timestamp}] {record.levelname:8}{self.RESET} "
        msg += f"\033[90m{record.name}:\033[0m {record.getMessage()}"
        
        # Add trace_id if present
        if hasattr(record, 'trace_id'):
            msg += f" \033[90m[trace:{record.trace_id}]\033[0m"
        
        # Add exception
        if record.exc_info:
            msg += f"\n{self.formatException(record.exc_info)}"
        
        return msg


# =============================================================================
# LOGGING SETUP
# =============================================================================

_logging_configured = False


def setup_logging(
    level: str = None,
    json_format: bool = None,
    log_file: str = None,
    service_name: str = "sentinel",
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
):
    """
    Configure logging for the application.
    
    Environment variables:
        LOG_LEVEL: DEBUG, INFO, WARNING, ERROR
        LOG_FORMAT: json, text
        LOG_FILE: path to log file
    """
    global _logging_configured
    
    if _logging_configured:
        return
    
    # Get settings from env or params
    level = level or os.environ.get('LOG_LEVEL', 'INFO')
    json_format = json_format if json_format is not None else (
        os.environ.get('LOG_FORMAT', 'text') == 'json'
    )
    log_file = log_file or os.environ.get('LOG_FILE')
    
    # Get root logger
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root.handlers.clear()
    
    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG)
    
    if json_format:
        console.setFormatter(JSONFormatter(service_name))
    else:
        console.setFormatter(ColoredFormatter())
    
    root.addHandler(console)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JSONFormatter(service_name))
        root.addHandler(file_handler)
    
    # Reduce noise from libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('flask').setLevel(logging.WARNING)
    
    _logging_configured = True


@lru_cache(maxsize=128)
def get_logger(name: str) -> logging.Logger:
    """Get a logger instance. Cached for performance."""
    return logging.getLogger(name)


# =============================================================================
# CONTEXT MANAGERS
# =============================================================================

class LogContext:
    """
    Context manager for adding trace ID to all logs in a scope.
    
    Usage:
        with LogContext(trace_id="req-123", sensor_id="sensor-01"):
            logger.info("Processing request")  # Will include trace_id
    """
    
    def __init__(self, **context):
        self.context = context
        self.old_factory = None
    
    def __enter__(self):
        self.old_factory = logging.getLogRecordFactory()
        context = self.context
        
        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in context.items():
                setattr(record, key, value)
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, *args):
        logging.setLogRecordFactory(self.old_factory)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def log_with_context(logger: logging.Logger, level: str, message: str, **context):
    """Log a message with additional context fields"""
    record = logger.makeRecord(
        logger.name,
        getattr(logging, level.upper()),
        "(unknown file)",
        0,
        message,
        (),
        None
    )
    record.extra_data = context
    logger.handle(record)


# =============================================================================
# INITIALIZE ON IMPORT (Development)
# =============================================================================

if os.environ.get('FLASK_ENV') == 'development' or os.environ.get('DEV_MODE'):
    setup_logging(level='DEBUG', json_format=False)
