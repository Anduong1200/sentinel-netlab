"""
Context Management for Observability (Correlation IDs).
Uses contextvars to manage request-scoped data (thread-safe and async-safe).
"""

from contextvars import ContextVar

# Define context variables with default values
_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_sensor_id: ContextVar[str | None] = ContextVar("sensor_id", default=None)
_batch_id: ContextVar[str | None] = ContextVar("batch_id", default=None)


def set_context(
    request_id: str | None = None,
    sensor_id: str | None = None,
    batch_id: str | None = None,
) -> None:
    """
    Set correlation parameters for the current context.
    Only explicit non-None values update the context.
    """
    if request_id:
        _request_id.set(request_id)
    if sensor_id:
        _sensor_id.set(sensor_id)
    if batch_id:
        _batch_id.set(batch_id)


def get_context() -> dict[str, str | None]:
    """
    Retrieve current correlation parameters.
    """
    return {
        "request_id": _request_id.get(),
        "sensor_id": _sensor_id.get(),
        "batch_id": _batch_id.get(),
    }


def clear_context() -> None:
    """
    Reset context variables to None.
    Note: In a framework like Flask/FastAPI, this often happens
    automatically at request end if the context is destroyed,
    but explicit clearing is good for pooled threads.
    """
    _request_id.set(None)
    _sensor_id.set(None)
    _batch_id.set(None)
