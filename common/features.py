"""
Sentinel NetLab - Feature Extraction
Standardizes feature engineering for both streaming inference and offline training.
"""

from typing import Any


def extract_features(telemetry_item: dict[str, Any]) -> dict[str, float]:
    """
    Extract numerical features from a telemetry item dict.

    Args:
        telemetry_item: Dictionary representing a network telemetry object.

    Returns:
        Dictionary of numerical features ready for model input.
    """
    # Defensive extraction
    caps = telemetry_item.get("capabilities", {})
    if isinstance(caps, str):
        # Handle case where capabilities might be a JSON string?
        # Or just support dict.
        caps = {}

    # One-hot encoding logic for encryption
    # Determines roughly the security level based on flags
    privacy = caps.get("privacy", False)
    pmf = caps.get("pmf", False)
    wps = caps.get("wps", False)

    # 1. Encryption Type OHE
    enc_open = 1.0 if not privacy else 0.0
    enc_wep = 0.0  # WEP hard to detect just from these flags without parser info, defaulting 0
    enc_wpa2 = 1.0 if privacy and not pmf else 0.0
    enc_wpa3 = 1.0 if privacy and pmf else 0.0

    # 2. Risk Indicators
    is_hidden = 1.0 if not telemetry_item.get("ssid") else 0.0
    wps_enabled = 1.0 if wps else 0.0

    # 3. Signal
    rssi = float(telemetry_item.get("rssi_dbm", -100))
    channel = float(telemetry_item.get("channel", 0))

    return {
        "rssi_dbm": rssi,
        "channel": channel,
        "enc_open": enc_open,
        "enc_wep": enc_wep,
        "enc_wpa2": enc_wpa2,
        "enc_wpa3": enc_wpa3,
        "is_hidden": is_hidden,
        "wps_enabled": wps_enabled,
    }


def get_feature_names() -> list[str]:
    """Return the ordered list of feature names"""
    return [
        "rssi_dbm",
        "channel",
        "enc_open",
        "enc_wep",
        "enc_wpa2",
        "enc_wpa3",
        "is_hidden",
        "wps_enabled",
    ]
