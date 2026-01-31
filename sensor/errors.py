#!/usr/bin/env python3
"""
Sentinel NetLab - Domain-Specific Error Classes
Provides clear separation between domain errors and system errors.

Usage:
    from sensor.errors import (
        SensorError, FrameParseError, RadioFailure, NetworkSendError
    )

    try:
        parse_frame(data)
    except FrameParseError as e:
        logger.warning(f"Malformed frame: {e}")
"""

from typing import Any

# =============================================================================
# BASE ERRORS
# =============================================================================


class SentinelError(Exception):
    """Base exception for all Sentinel NetLab errors"""

    def __init__(
        self,
        message: str,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code or self.__class__.__name__
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.code, "message": str(self), "details": self.details}


class SensorError(SentinelError):
    """Base error for sensor-related issues"""

    pass


class ControllerError(SentinelError):
    """Base error for controller-related issues"""

    pass


# =============================================================================
# FRAME & PARSING ERRORS
# =============================================================================


class FrameParseError(SensorError):
    """Error parsing WiFi frame data"""

    def __init__(
        self, message: str, frame_type: str | None = None, offset: int | None = None
    ):
        super().__init__(message, details={"frame_type": frame_type, "offset": offset})
        self.frame_type = frame_type
        self.offset = offset


class MalformedFrameError(FrameParseError):
    """Frame structure is invalid"""

    pass


class UnsupportedFrameError(FrameParseError):
    """Frame type not supported"""

    pass


class CorruptedDataError(FrameParseError):
    """Data appears corrupted"""

    pass


# =============================================================================
# RADIO/HARDWARE ERRORS
# =============================================================================


class RadioFailure(SensorError):
    """WiFi radio/adapter failure"""

    def __init__(
        self, message: str, interface: str | None = None, driver: str | None = None
    ):
        super().__init__(message, details={"interface": interface, "driver": driver})
        self.interface = interface
        self.driver = driver


class InterfaceNotFoundError(RadioFailure):
    """WiFi interface not found"""

    pass


class MonitorModeError(RadioFailure):
    """Failed to enable monitor mode"""

    pass


class ChannelHopError(RadioFailure):
    """Failed to change channel"""

    pass


class CaptureError(RadioFailure):
    """Frame capture failed"""

    pass


# =============================================================================
# NETWORK/TRANSPORT ERRORS
# =============================================================================


class NetworkSendError(SensorError):
    """Failed to send data to controller"""

    def __init__(
        self, message: str, url: str | None = None, status_code: int | None = None
    ):
        super().__init__(message, details={"url": url, "status_code": status_code})
        self.url = url
        self.status_code = status_code


class ConnectionError(NetworkSendError):
    """Network connection failed"""

    pass


class TimeoutError(NetworkSendError):
    """Request timed out"""

    pass


class AuthenticationError(NetworkSendError):
    """Authentication failed"""

    pass


class RateLimitError(NetworkSendError):
    """Rate limit exceeded"""

    pass


class SignatureError(NetworkSendError):
    """HMAC signature validation failed"""

    pass


# =============================================================================
# DETECTION ERRORS
# =============================================================================


class DetectionError(SensorError):
    """Error in detection logic"""

    pass


class DetectorConfigError(DetectionError):
    """Invalid detector configuration"""

    pass


class WhitelistError(DetectionError):
    """Error loading or processing whitelist"""

    pass


# =============================================================================
# CONFIGURATION ERRORS
# =============================================================================


class ConfigurationError(SentinelError):
    """Configuration-related error"""

    pass


class MissingConfigError(ConfigurationError):
    """Required configuration missing"""

    pass


class InvalidConfigError(ConfigurationError):
    """Configuration value is invalid"""

    pass


class SecretNotFoundError(ConfigurationError):
    """Required secret not found"""

    pass


# =============================================================================
# CONTROLLER ERRORS
# =============================================================================


class ValidationError(ControllerError):
    """Request validation failed"""

    def __init__(self, message: str, field: str | None = None, value: Any = None):
        super().__init__(
            message,
            details={"field": field, "value": str(value)[:100] if value else None},
        )
        self.field = field
        self.value = value


class DatabaseError(ControllerError):
    """Database operation failed"""

    pass


class TokenExpiredError(ControllerError):
    """API token has expired"""

    pass


class PermissionDeniedError(ControllerError):
    """Insufficient permissions"""

    def __init__(
        self, message: str, required: str | None = None, actual: str | None = None
    ):
        super().__init__(message, details={"required": required, "actual": actual})


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def wrap_exception(
    exc: Exception, wrapper_class: type = SentinelError
) -> SentinelError:
    """Wrap a generic exception in a Sentinel error"""
    if isinstance(exc, SentinelError):
        return exc
    return wrapper_class(str(exc), details={"original_type": type(exc).__name__})


def is_retryable(exc: Exception) -> bool:
    """Check if an error is retryable"""
    retryable_types = (
        TimeoutError,
        ConnectionError,
        RateLimitError,
    )
    return isinstance(exc, retryable_types)
