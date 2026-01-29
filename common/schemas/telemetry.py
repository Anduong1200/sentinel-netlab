from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class FrameType(str, Enum):
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


class SecurityType(str, Enum):
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
    bssid: str = Field(pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    ssid: Optional[str] = None
    rssi_dbm: int = Field(ge=-120, le=0)
    channel: int = Field(ge=1, le=173)

    @field_validator("ssid")
    @classmethod
    def sanitize_ssid(cls, v: Optional[str]) -> Optional[str]:
        if v:
             # Basic sanitization for display
            return v.replace("\x00", "")
        return v

    schema_version: str = "1.0"

    model_config = {
        "use_enum_values": True,
        "extra": "forbid",
        "validate_assignment": True
    }


class TelemetryBatch(BaseModel):
    batch_id: str
    sensor_id: str
    records: List[TelemetryRecord]

    model_config = {
        "extra": "forbid",
        "validate_assignment": True
    }
