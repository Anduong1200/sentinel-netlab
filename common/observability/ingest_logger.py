
import logging
from typing import Any
from common.observability.context import set_context, clear_context

class IngestLogger:
    """
    Context-aware logger for Ingest pipeline.
    Ensures sensor_id and batch_id are always present in logs.
    """
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def info(self, msg: str, sensor_id: str, batch_id: str, **kwargs):
        self._log(logging.INFO, msg, sensor_id, batch_id, **kwargs)

    def error(self, msg: str, sensor_id: str, batch_id: str, **kwargs):
        self._log(logging.ERROR, msg, sensor_id, batch_id, **kwargs)

    def warning(self, msg: str, sensor_id: str, batch_id: str, **kwargs):
        self._log(logging.WARNING, msg, sensor_id, batch_id, **kwargs)

    def _log(self, level: int, msg: str, sensor_id: str, batch_id: str, **kwargs):
        # Set context for this log operation
        # (This updates the ContextVar which JSONFormatter reads)
        set_context(sensor_id=sensor_id, batch_id=batch_id)
        
        try:
            # Pass extra fields
            extra = kwargs.get("extra", {})
            if "data" not in extra:
                extra["data"] = {}
            
            # Add implicit data
            extra["data"].update({
                "sensor_id": sensor_id,
                "batch_id": batch_id
            })
            
            self.logger.log(level, msg, extra=extra)
        finally:
            # Clear context to avoid leaking IDs to subsequent requests in same thread
            # (Though in WSGI this is reset by middleware, this is safer for async tasks)
            clear_context()
