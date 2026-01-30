#!/usr/bin/env python3
"""
WiFi Scanner Configuration Module
Centralized configuration settings for the sensor
"""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Default paths
DEFAULT_CONFIG_PATH = "/etc/wifi-scanner/config.json"
DEFAULT_DATA_DIR = "/var/lib/wifi-scanner"


@dataclass
class CaptureConfig:
    """Capture engine settings."""

    interface: str = "wlan0"
    channels: list = field(default_factory=lambda: [1, 6, 11])
    dwell_time: float = 0.4  # seconds per channel
    enable_channel_hop: bool = True
    scan_duration: int = 10  # seconds for single scan
    packet_filter: str = "type mgt"  # Scapy BPF filter


@dataclass
class SensorConfig:
    """Sensor identity settings."""

    id: str = "sensor-01"
    hostname: str = "localhost"
    group: str = "default"


@dataclass
class StorageConfig:
    """Storage settings."""

    db_path: str = "/var/lib/wifi-scanner/wifi_scans.db"
    pcap_dir: str = "/var/lib/wifi-scanner/pcaps"
    pcap_enabled: bool = True
    pcap_max_age_days: int = 7
    pcap_max_size_mb: int = 100
    history_retention_days: int = 30


@dataclass
class APIConfig:
    """API server settings."""

    host: str = "0.0.0.0"  # nosec B104
    port: int = 5000
    debug: bool = False
    api_key: str = "student-project-2024"
    rate_limit: str = "60/minute"
    cors_enabled: bool = True
    ssl_enabled: bool = False
    ssl_cert: str | None = None
    ssl_key: str | None = None


@dataclass
class RiskConfig:
    """Risk scoring settings."""

    encryption_weight: float = 0.45
    signal_weight: float = 0.20
    ssid_weight: float = 0.15
    vendor_weight: float = 0.10
    channel_weight: float = 0.10
    high_risk_threshold: int = 70
    critical_risk_threshold: int = 90


@dataclass
class MLConfig:
    """Analysis and ML settings."""

    enabled: bool = False
    model_path: str = "models/anomaly_v1.pth"
    threshold: float = 0.05
    training_enabled: bool = False


@dataclass
class PrivacyConfig:
    """Privacy and data retention settings."""

    mode: str = "anonymized"  # normal, anonymized, private
    store_raw_mac: bool = False
    anonymize_ssid: bool = False
    retention_days: int = 30


@dataclass
class Config:
    """Main configuration container."""

    sensor: SensorConfig = field(default_factory=SensorConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    api: APIConfig = field(default_factory=APIConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    mock_mode: bool = False  # Use mock data when hardware unavailable
    log_level: str = "INFO"


class ConfigManager:
    """
    Manages configuration loading, saving, and access.
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to JSON config file
        """
        self.config_path = Path(config_path)
        self.config = Config()
        self._load_config()

    def _load_config(self):
        """Load configuration from file or use defaults."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    data = json.load(f)
                self._apply_dict(data)
                logger.info(f"Config loaded from {self.config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}, using defaults")
        else:
            logger.info("No config file found, using defaults")

        # Also check for environment variables
        self._apply_env_vars()

    def _apply_dict(self, data: dict[str, Any]):
        """Apply dictionary values to config."""
        if "sensor" in data:
            for key, value in data["sensor"].items():
                if hasattr(self.config.sensor, key):
                    setattr(self.config.sensor, key, value)

        if "capture" in data:
            for key, value in data["capture"].items():
                if hasattr(self.config.capture, key):
                    setattr(self.config.capture, key, value)

        if "storage" in data:
            for key, value in data["storage"].items():
                if hasattr(self.config.storage, key):
                    setattr(self.config.storage, key, value)

        if "api" in data:
            for key, value in data["api"].items():
                if hasattr(self.config.api, key):
                    setattr(self.config.api, key, value)

        if "risk" in data:
            for key, value in data["risk"].items():
                if hasattr(self.config.risk, key):
                    setattr(self.config.risk, key, value)

        if "mock_mode" in data:
            self.config.mock_mode = data["mock_mode"]

        if "log_level" in data:
            self.config.log_level = data["log_level"]

    def _apply_env_vars(self):
        """Override config with environment variables."""
        env_mappings = {
            # Legacy Prefixes
            "WIFI_SCANNER_INTERFACE": ("capture", "interface"),
            # Docker Standard Prefixes (from docker-compose.yml)
            "SENSOR_INTERFACE": ("capture", "interface"),
            "SENSOR_ID": ("sensor", "id"),
            "SENSOR_AUTH_TOKEN": ("api", "api_key"),
            "WIFI_SCANNER_PORT": ("api", "port", int),
            "SERVER_PORT": ("api", "port", int),
            "WIFI_SCANNER_API_KEY": ("api", "api_key"),
            "WIFI_SCANNER_MOCK_MODE": (
                "mock_mode",
                None,
                lambda x: x.lower() == "true",
            ),
            "SENSOR_MOCK_MODE": ("mock_mode", None, lambda x: x.lower() == "true"),
            "WIFI_SCANNER_DEBUG": ("api", "debug", lambda x: x.lower() == "true"),
            "WIFI_SCANNER_DB_PATH": ("storage", "db_path"),
            "WIFI_SCANNER_LOG_LEVEL": ("log_level", None),
            "LOG_LEVEL": ("log_level", None),
            # Privacy
            "SENSOR_PRIVACY_MODE": ("privacy", "mode"),
            "SENSOR_PRIVACY_STORE_RAW_MAC": (
                "privacy",
                "store_raw_mac",
                lambda x: x.lower() == "true",
            ),
            "SENSOR_PRIVACY_ANONYMIZE_SSID": (
                "privacy",
                "anonymize_ssid",
                lambda x: x.lower() == "true",
            ),
        }

        for env_var, mapping in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                try:
                    if len(mapping) == 2:
                        section, key = mapping
                        converter = str
                    else:
                        section, key, converter = mapping

                    converted_value = converter(value)

                    if key is None:
                        setattr(self.config, section, converted_value)
                    else:
                        section_obj = getattr(self.config, section)
                        setattr(section_obj, key, converted_value)

                    logger.debug(f"Applied {env_var}={value}")
                except Exception as e:
                    logger.warning(f"Failed to apply {env_var}: {e}")

    def save_config(self, path: str | None = None):
        """
        Save current configuration to file.

        Args:
            path: Optional path (uses default if not specified)
        """
        save_path = Path(path) if path else self.config_path

        # Ensure directory exists
        save_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dictionary
        data = {
            "capture": asdict(self.config.capture),
            "storage": asdict(self.config.storage),
            "api": asdict(self.config.api),
            "risk": asdict(self.config.risk),
            "mock_mode": self.config.mock_mode,
            "log_level": self.config.log_level,
        }

        with open(save_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Config saved to {save_path}")

    def to_dict(self) -> dict[str, Any]:
        """Export configuration as dictionary."""
        return {
            "capture": asdict(self.config.capture),
            "storage": asdict(self.config.storage),
            "api": asdict(self.config.api),
            "risk": asdict(self.config.risk),
            "mock_mode": self.config.mock_mode,
            "log_level": self.config.log_level,
        }

    def get_safe_dict(self) -> dict[str, Any]:
        """Export configuration without sensitive values (for logging/API)."""
        data = self.to_dict()
        # Mask API key
        if "api" in data and "api_key" in data["api"]:
            key = data["api"]["api_key"]
            data["api"]["api_key"] = (
                key[:4] + "****" + key[-4:] if len(key) > 8 else "****"
            )
        return data


# Global configuration instance
_config_manager: ConfigManager | None = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.config


def get_config_manager() -> ConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def init_config(config_path: str = DEFAULT_CONFIG_PATH) -> Config:
    """
    Initialize configuration from file.

    Args:
        config_path: Path to configuration JSON file

    Returns:
        Configuration object
    """
    global _config_manager
    _config_manager = ConfigManager(config_path)
    return _config_manager.config


# Sample configuration generation
def generate_sample_config(output_path: str = "./sample_config.json"):
    """Generate a sample configuration file."""
    config = Config()
    data = {
        "capture": asdict(config.capture),
        "storage": asdict(config.storage),
        "api": asdict(config.api),
        "risk": asdict(config.risk),
        "mock_mode": False,
        "log_level": "INFO",
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Sample config written to {output_path}")


if __name__ == "__main__":
    # Test configuration
    print("=" * 50)
    print("WiFi Scanner Configuration Module Test")
    print("=" * 50)

    # Initialize with defaults
    config = get_config()

    print("\nCapture Settings:")
    print(f"  Interface: {config.capture.interface}")
    print(f"  Channels: {config.capture.channels}")
    print(f"  Dwell Time: {config.capture.dwell_time}s")

    print("\nAPI Settings:")
    print(f"  Host: {config.api.host}")
    print(f"  Port: {config.api.port}")
    print(f"  Debug: {config.api.debug}")

    print("\nStorage Settings:")
    print(f"  DB Path: {config.storage.db_path}")
    print(f"  PCAP Dir: {config.storage.pcap_dir}")

    print(f"\nMock Mode: {config.mock_mode}")
    print(f"Log Level: {config.log_level}")

    # Generate sample config
    generate_sample_config("./sample_config.json")
