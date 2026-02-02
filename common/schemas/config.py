from pydantic import BaseModel, Field


class CaptureConfig(BaseModel):
    interface: str = "wlan0"
    channels: list[int] = [1, 6, 11]
    dwell_time: float = 0.4
    enable_channel_hop: bool = True


class ApiConfig(BaseModel):
    host: str = "0.0.0.0"  # nosec B104 # noqa: S104
    port: int = 5000
    api_key: str = Field(min_length=8)
    ssl_enabled: bool = True
    ssl_cert: str = "/etc/ssl/certs/sentinel.crt"
    ssl_key: str = "/etc/ssl/private/sentinel.key"


class StorageConfig(BaseModel):
    db_path: str = "./data/wifi_scans.db"
    retention_days: int = 30


class Config(BaseModel):
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    log_level: str = "INFO"
