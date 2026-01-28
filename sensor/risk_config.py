import logging
import os

import yaml

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS = {
    "base": 50,
    "encryption_open": 40,
    "encryption_wep": 30,
    "encryption_wpa2": 10,
    "encryption_wpa3": -20,
    "rssi_strong": 15,
    "rssi_medium": 5,
    "common_ssid_penalty": 5,
    "crowded_channel": 5
}


def load_weights(path="config/risk_weights.yaml"):
    """Load scoring weights from YAML config"""
    try:
        if os.path.exists(path):
            with open(path) as f:
                return yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"Failed to load risk weights: {e}, using defaults")
    return DEFAULT_WEIGHTS
