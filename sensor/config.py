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

import yaml

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
    pcap_file: str | None = None


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
    api_key: str = ""  # Enforced via require_secret in ConfigManager
    rate_limit: str = "60/minute"
    cors_enabled: bool = True
    ssl_enabled: bool = False
    ssl_cert: str | None = None
    ssl_key: str | None = None
    hmac_secret: str | None = None
    upload_url: str | None = None


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
class GeoConfig:
    """Geo-location and heatmap settings."""

    enabled: bool = False
    environment: str = "indoor_los"
    sensor_x_m: float | None = None
    sensor_y_m: float | None = None
    sensor_z_m: float = 0.0
    origin_lat: float | None = None
    origin_lon: float | None = None
    heatmap_enabled: bool = False
    heatmap_width_m: float = 50.0
    heatmap_height_m: float = 50.0
    heatmap_resolution_m: float = 1.0
    heatmap_export_path: str = "/var/lib/wifi-scanner/geo_heatmap.json"
    heatmap_export_interval_sec: int = 60


@dataclass
class UploadConfig:
    """Batch upload pacing settings."""

    batch_size: int = 200
    interval_sec: float = 5.0


@dataclass
class DetectorsConfig:
    """Detector orchestration settings."""

    default_profile: str = "lite_realtime"
    enabled: list[str] = field(default_factory=list)
    profiles: dict[str, list[str]] = field(default_factory=dict)
    fast_path: list[str] = field(default_factory=list)
    stateful_path: list[str] = field(default_factory=list)
    correlation_path: list[str] = field(default_factory=list)
    thresholds: dict[str, dict[str, Any]] = field(default_factory=dict)


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
    geo: GeoConfig = field(default_factory=GeoConfig)
    upload: UploadConfig = field(default_factory=UploadConfig)
    detectors: DetectorsConfig = field(default_factory=DetectorsConfig)
    mock_mode: bool = False  # Use mock data when hardware unavailable
    log_level: str = "INFO"


class ConfigManager:
    """
    Manages configuration loading, saving, and access.
    """

    def __init__(self, config_path: str | None = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to JSON config file
        """
        if config_path is None:
            config_path = DEFAULT_CONFIG_PATH
        self.config_path = Path(config_path)
        self.config = Config()
        self._load_config()

    def _load_config(self):
        """Load configuration from file or use defaults."""
        if self.config_path.exists():
            try:
                data = self._read_config_file()
                self._apply_dict(data)
                logger.info(f"Config loaded from {self.config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}, using defaults")
        else:
            logger.info("No config file found, using defaults")

        # Also check for environment variables
        self._apply_env_vars()

    def _read_config_file(self) -> dict[str, Any]:
        """Read JSON or YAML config from disk."""
        suffix = self.config_path.suffix.lower()
        with open(self.config_path) as f:
            if suffix in {".yaml", ".yml"}:
                data = yaml.safe_load(f) or {}
            else:
                data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError("Configuration file must contain a mapping object")
        return data

    def _apply_dict(self, data: dict[str, Any]):
        """Apply dictionary values to config."""
        def apply_section(
            target: Any,
            values: dict[str, Any],
            aliases: dict[str, str | tuple[str, Any]] | None = None,
        ) -> None:
            aliases = aliases or {}
            for key, value in values.items():
                alias = aliases.get(key)
                if isinstance(alias, tuple):
                    target_key, converter = alias
                    value = converter(value)
                else:
                    target_key = alias or key

                if hasattr(target, target_key):
                    setattr(target, target_key, value)

        if "sensor" in data:
            sensor_values = dict(data["sensor"])
            legacy_interface = sensor_values.pop("interface", None)
            apply_section(self.config.sensor, sensor_values)
            if legacy_interface is not None:
                self.config.capture.interface = legacy_interface

        if "capture" in data:
            apply_section(
                self.config.capture,
                data["capture"],
                aliases={
                    "dwell_ms": ("dwell_time", lambda v: float(v) / 1000.0),
                },
            )

        if "storage" in data:
            apply_section(self.config.storage, data["storage"])

        if "api" in data:
            apply_section(self.config.api, data["api"])

        if "transport" in data and isinstance(data["transport"], dict):
            apply_section(
                self.config.api,
                data["transport"],
                aliases={
                    "auth_token": "api_key",
                },
            )

        if "risk" in data:
            apply_section(self.config.risk, data["risk"])

        if "ml" in data:
            apply_section(self.config.ml, data["ml"])

        if "privacy" in data:
            apply_section(self.config.privacy, data["privacy"])

        if "geo" in data:
            apply_section(self.config.geo, data["geo"])

        if "upload" in data:
            apply_section(self.config.upload, data["upload"])

        if "detectors" in data:
            apply_section(self.config.detectors, data["detectors"])

        if "mock_mode" in data:
            self.config.mock_mode = data["mock_mode"]

        if "log_level" in data:
            self.config.log_level = data["log_level"]
        elif "logging" in data and isinstance(data["logging"], dict):
            level = data["logging"].get("level")
            if level:
                self.config.log_level = level

    def _apply_env_vars(self):
        """Override config with environment variables."""
        env_mappings = {
            # Legacy Prefixes
            "WIFI_SCANNER_INTERFACE": ("capture", "interface"),
            # Docker Standard Prefixes (from docker-compose.yml)
            "SENSOR_INTERFACE": ("capture", "interface"),
            "SENSOR_ID": ("sensor", "id"),
            "SENSOR_AUTH_TOKEN": ("api", "api_key"),
            "SENSOR_CONTROLLER_HOST": ("api", "host"),
            "SENSOR_CONTROLLER_PORT": ("api", "port", int),
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
            "SENSOR_HMAC_SECRET": ("api", "hmac_secret"),
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
            # Geo
            "SENSOR_GEO_ENABLED": ("geo", "enabled", lambda x: x.lower() == "true"),
            "SENSOR_GEO_ENVIRONMENT": ("geo", "environment"),
            "SENSOR_GEO_X_M": ("geo", "sensor_x_m", float),
            "SENSOR_GEO_Y_M": ("geo", "sensor_y_m", float),
            "SENSOR_GEO_Z_M": ("geo", "sensor_z_m", float),
            "SENSOR_GEO_HEATMAP_ENABLED": (
                "geo",
                "heatmap_enabled",
                lambda x: x.lower() == "true",
            ),
            "SENSOR_GEO_HEATMAP_WIDTH_M": ("geo", "heatmap_width_m", float),
            "SENSOR_GEO_HEATMAP_HEIGHT_M": ("geo", "heatmap_height_m", float),
            "SENSOR_GEO_HEATMAP_RESOLUTION_M": ("geo", "heatmap_resolution_m", float),
            "SENSOR_GEO_HEATMAP_EXPORT_PATH": ("geo", "heatmap_export_path"),
            "SENSOR_GEO_HEATMAP_EXPORT_INTERVAL_SEC": (
                "geo",
                "heatmap_export_interval_sec",
                int,
            ),
            "GEO_ORIGIN_LAT": ("geo", "origin_lat", float),
            "GEO_ORIGIN_LON": ("geo", "origin_lon", float),
            # Detectors
            "SENSOR_DETECTOR_PROFILE": ("detectors", "default_profile"),
        }

        # Environment check
        env = os.getenv("ENVIRONMENT", "production").lower()
        from common.security.secrets import require_secret

        for env_var, mapping in env_mappings.items():
            value = os.environ.get(env_var)

            # Special handling for Fail-Fast Secrets
            if env_var in [
                "WIFI_SCANNER_API_KEY",
                "SENSOR_AUTH_TOKEN",
                "SENSOR_HMAC_SECRET",
            ]:
                # Use require_secret to validate/enforce
                secret_name = (
                    "HMAC Secret"
                    if env_var == "SENSOR_HMAC_SECRET"
                    else "Sensor API Key"
                )
                try:
                    value = require_secret(
                        secret_name,
                        env_var,
                        min_len=16,
                        allow_dev_autogen=True,
                        env=env,
                    )
                except RuntimeError as e:
                    # ConfigManager usually shouldn't crash the app on init unless critical,
                    # but for this specific "fail-fast" requirement, we propagate the error.
                    raise e

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

                    logger.debug(f"Applied {env_var} to config")
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
            "geo": asdict(self.config.geo),
            "upload": asdict(self.config.upload),
            "detectors": asdict(self.config.detectors),
            "sensor": asdict(self.config.sensor),
            "privacy": asdict(self.config.privacy),
            "ml": asdict(self.config.ml),
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
            "geo": asdict(self.config.geo),
            "upload": asdict(self.config.upload),
            "detectors": asdict(self.config.detectors),
            "sensor": asdict(self.config.sensor),
            "privacy": asdict(self.config.privacy),
            "ml": asdict(self.config.ml),
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
        # Mask HMAC secret
        if (
            "api" in data
            and "hmac_secret" in data["api"]
            and data["api"]["hmac_secret"]
        ):
            key = data["api"]["hmac_secret"]
            data["api"]["hmac_secret"] = (
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


def init_config(config_path: str | None = None) -> Config:
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
        "geo": asdict(config.geo),
        "upload": asdict(config.upload),
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

    print("\nGeo Settings:")
    print(f"  Enabled: {config.geo.enabled}")
    print(f"  Position: ({config.geo.sensor_x_m}, {config.geo.sensor_y_m})")
    print(f"  Heatmap Enabled: {config.geo.heatmap_enabled}")

    print(f"\nMock Mode: {config.mock_mode}")
    print(f"Log Level: {config.log_level}")

    # Generate sample config
    generate_sample_config("./sample_config.json")
