from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator


class FrameType(StrEnum):
    BEACON = "beacon"
    PROBE_REQ = "probe_req"
    PROBE_RESP = "probe_resp"
    AUTH = "auth"
    ASSOC_REQ = "assoc_req"
    ASSOC_RESP = "assoc_resp"
    REASSOC_REQ = "reassoc_req"
    REASSOC_RESP = "reassoc_resp"
    DISASSOC = "disassoc"
    ACTION = "action"
    DEAUTH = "deauth"


class SecurityType(StrEnum):
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"


class TelemetryRecord(BaseModel):
    sensor_id: str
    timestamp_utc: datetime
    sequence_id: int
    frame_type: FrameType
    frame_subtype: str | None = None
    mac_src: str | None = Field(None, pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    bssid: str = Field(pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    ssid: str | None = None
    rssi_dbm: int = Field(ge=-120, le=0)
    channel: int = Field(ge=0, le=173)

    @field_validator("ssid")
    @classmethod
    def sanitize_ssid(cls, v: str | None) -> str | None:
        if v:
            # Basic sanitization for display
            return v.replace("\x00", "")
        return v

    schema_version: str = "1.0"

    model_config = {
        "use_enum_values": True,
        "extra": "forbid",
        "validate_assignment": True,
    }


class TelemetryBatch(BaseModel):
    batch_id: str
    sensor_id: str
    items: list[TelemetryRecord] = Field(default=[])

    model_config = {"extra": "forbid", "validate_assignment": True}
