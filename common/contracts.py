"""
Sentinel NetLab - Data Contracts
================================
Pydantic models defining standardized data formats between all system components.
These are the SINGLE SOURCE OF TRUTH for data exchange.

Pipeline: Capture → Parser → Normalizer → Controller → Storage
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# =============================================================================
# ENUMS
# =============================================================================

class FrameType(str, Enum):
    """802.11 frame types"""
    MANAGEMENT = "management"
    CONTROL = "control"
    DATA = "data"
    EXTENSION = "extension"
    UNKNOWN = "unknown"


class FrameSubtype(str, Enum):
    """802.11 management frame subtypes"""
    # Management frames (type 0)
    ASSOCIATION_REQUEST = "assoc_req"
    ASSOCIATION_RESPONSE = "assoc_resp"
    REASSOCIATION_REQUEST = "reassoc_req"
    REASSOCIATION_RESPONSE = "reassoc_resp"
    PROBE_REQUEST = "probe_req"
    PROBE_RESPONSE = "probe_resp"
    BEACON = "beacon"
    ATIM = "atim"
    DISASSOCIATION = "disassoc"
    AUTHENTICATION = "auth"
    DEAUTHENTICATION = "deauth"
    ACTION = "action"
    # Control frames (type 1)
    BLOCK_ACK_REQ = "block_ack_req"
    BLOCK_ACK = "block_ack"
    PS_POLL = "ps_poll"
    RTS = "rts"
    CTS = "cts"
    ACK = "ack"
    CF_END = "cf_end"
    # Data frames (type 2)
    DATA = "data"
    NULL = "null"
    QOS_DATA = "qos_data"
    # Unknown
    UNKNOWN = "unknown"


class SecurityType(str, Enum):
    """WiFi security types"""
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2_TKIP = "wpa2_tkip"
    WPA2_CCMP = "wpa2_ccmp"
    WPA3 = "wpa3"
    UNKNOWN = "unknown"


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AlertType(str, Enum):
    """Detection alert types"""
    EVIL_TWIN = "evil_twin"
    DEAUTH_FLOOD = "deauth_flood"
    ROGUE_AP = "rogue_ap"
    PROBE_FLOOD = "probe_flood"
    WPS_ATTACK = "wps_attack"
    KARMA_ATTACK = "karma_attack"
    KRACK_ATTACK = "krack_attack"
    CHANNEL_SWITCH = "channel_switch"
    SEQUENCE_ANOMALY = "sequence_anomaly"
    RSSI_ANOMALY = "rssi_anomaly"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk assessment levels"""
    CLEAN = "clean"
    LOW = "low"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"


# =============================================================================
# RAW FRAME (Parser output)
# =============================================================================

class RawFrame(BaseModel):
    """
    Raw 802.11 frame as output by the parser.
    Minimal processing, close to wire format.
    """
    # Timing
    timestamp: float = Field(description="Capture timestamp (epoch)")

    # Addresses
    mac_src: str | None = Field(None, pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    mac_dst: str | None = Field(None, pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    bssid: str | None = Field(None, pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

    # Frame classification
    frame_type: FrameType = FrameType.UNKNOWN
    frame_subtype: FrameSubtype = FrameSubtype.UNKNOWN
    type_code: int = Field(0, ge=0, le=3)
    subtype_code: int = Field(0, ge=0, le=15)

    # Radio info
    channel: int | None = Field(None, ge=1, le=200)
    frequency_mhz: int | None = Field(None, ge=2400, le=6000)
    rssi_dbm: int | None = Field(None, ge=-120, le=0)

    # Beacon/Probe specific
    ssid: str | None = Field(None, max_length=32)

    # Sequence
    sequence_number: int | None = Field(None, ge=0, le=4095)
    fragment_number: int | None = Field(None, ge=0, le=15)

    # Flags
    is_encrypted: bool = False
    is_retry: bool = False
    is_more_fragments: bool = False

    # Raw data
    frame_length: int = 0
    raw_bytes: bytes | None = Field(None, exclude=True)

    class Config:
        use_enum_values = True


# =============================================================================
# NORMALIZED FRAME (Normalizer output)
# =============================================================================

class NormalizedFrame(BaseModel):
    """
    Normalized frame ready for analysis.
    All fields validated, enriched with OUI info, privacy-safe.
    """
    # Identifiers
    frame_id: str = Field(description="Unique frame identifier")
    sensor_id: str = Field(description="Source sensor ID")

    # Timing
    timestamp: float
    timestamp_iso: str = Field(description="ISO8601 timestamp")

    # Addresses (can be hashed for privacy)
    mac_src: str
    mac_dst: str
    bssid: str | None = None

    # Privacy-safe hashed versions
    mac_src_hash: str | None = None
    bssid_hash: str | None = None

    # OUI enrichment
    vendor_src: str | None = None
    vendor_bssid: str | None = None

    # Classification
    frame_type: FrameType
    frame_subtype: FrameSubtype

    # Radio
    channel: int | None = None
    rssi_dbm: int | None = None

    # Network info
    ssid: str | None = None
    security: SecurityType = SecurityType.UNKNOWN

    # Sequence tracking
    sequence_number: int | None = None

    # Metadata
    is_encrypted: bool = False
    frame_length: int = 0

    @classmethod
    def from_raw(
        cls,
        raw: RawFrame,
        sensor_id: str,
        hash_macs: bool = False,
        salt: str = ""
    ) -> NormalizedFrame:
        """Create normalized frame from raw frame"""
        import uuid

        frame_id = str(uuid.uuid4())[:8]
        timestamp_iso = datetime.utcfromtimestamp(raw.timestamp).isoformat() + "Z"

        # Hash MACs if privacy mode enabled
        mac_src_hash = None
        bssid_hash = None
        if hash_macs:
            if raw.mac_src:
                mac_src_hash = hashlib.sha256(
                    (salt + raw.mac_src).encode()
                ).hexdigest()[:16]
            if raw.bssid:
                bssid_hash = hashlib.sha256(
                    (salt + raw.bssid).encode()
                ).hexdigest()[:16]

        return cls(
            frame_id=frame_id,
            sensor_id=sensor_id,
            timestamp=raw.timestamp,
            timestamp_iso=timestamp_iso,
            mac_src=raw.mac_src or "00:00:00:00:00:00",
            mac_dst=raw.mac_dst or "ff:ff:ff:ff:ff:ff",
            bssid=raw.bssid,
            mac_src_hash=mac_src_hash,
            bssid_hash=bssid_hash,
            frame_type=raw.frame_type,
            frame_subtype=raw.frame_subtype,
            channel=raw.channel,
            rssi_dbm=raw.rssi_dbm,
            ssid=raw.ssid,
            sequence_number=raw.sequence_number,
            is_encrypted=raw.is_encrypted,
            frame_length=raw.frame_length,
        )

    class Config:
        use_enum_values = True


# =============================================================================
# NETWORK STATE (Controller aggregation)
# =============================================================================

class NetworkInfo(BaseModel):
    """Aggregated network information"""
    bssid: str
    ssid: str | None = None
    channel: int | None = None
    security: SecurityType = SecurityType.UNKNOWN

    # Metrics
    first_seen: float
    last_seen: float
    frame_count: int = 0
    beacon_count: int = 0
    probe_count: int = 0

    # Signal stats
    rssi_min: int | None = None
    rssi_max: int | None = None
    rssi_avg: float | None = None

    # Risk
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.CLEAN
    risk_factors: list[str] = Field(default_factory=list)

    # Clients
    associated_clients: list[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True


# =============================================================================
# ALERT (Detection output)
# =============================================================================

class Alert(BaseModel):
    """Security alert from detection engine"""
    # Identifiers
    alert_id: str
    sensor_id: str

    # Timing
    created_at: float = Field(default_factory=time.time)
    created_at_iso: str | None = None

    # Classification
    alert_type: AlertType
    severity: AlertSeverity
    title: str = Field(max_length=200)
    description: str = Field(max_length=2000)

    # Target
    bssid: str | None = None
    ssid: str | None = None
    mac_src: str | None = None
    channel: int | None = None

    # Evidence
    evidence: dict[str, Any] = Field(default_factory=dict)
    frame_ids: list[str] = Field(default_factory=list)

    # Risk
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1, default=0.5)

    # MITRE ATT&CK mapping
    mitre_attack: str | None = None

    # Status
    status: str = "open"  # open, acknowledged, resolved
    resolved_at: float | None = None

    class Config:
        use_enum_values = True


# =============================================================================
# TELEMETRY BATCH (Sensor → Controller)
# =============================================================================

class TelemetryBatch(BaseModel):
    """Batch of telemetry data sent from sensor to controller"""
    # Metadata
    sensor_id: str
    batch_id: str
    timestamp_utc: str
    sequence_number: int = Field(ge=0)

    # Payload
    frames: list[NormalizedFrame] = Field(default_factory=list)
    networks: list[NetworkInfo] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)

    # Metrics
    frames_captured: int = 0
    frames_dropped: int = 0
    capture_duration_sec: float = 0.0

    class Config:
        use_enum_values = True


# =============================================================================
# SENSOR STATUS (Heartbeat)
# =============================================================================

class SensorStatus(BaseModel):
    """Sensor status for heartbeat"""
    sensor_id: str
    status: str = "online"  # online, degraded, offline
    timestamp: float = Field(default_factory=time.time)

    # Version
    version: str = "1.0.0"

    # Metrics
    uptime_seconds: float = 0
    frames_per_second: float = 0
    cpu_percent: float = 0
    memory_percent: float = 0
    disk_percent: float = 0

    # Interface
    interface: str | None = None
    channel_current: int | None = None

    # Errors
    error_count: int = 0
    last_error: str | None = None


# =============================================================================
# UTILITIES
# =============================================================================

def hash_mac(mac: str, salt: str = "") -> str:
    """Hash MAC address for privacy (one-way, salted)"""
    return hashlib.sha256((salt + mac.upper()).encode()).hexdigest()[:16]


def anonymize_mac(mac: str) -> str:
    """Anonymize MAC by zeroing last 3 octets (keep OUI)"""
    parts = mac.split(":")
    if len(parts) == 6:
        return ":".join(parts[:3] + ["XX", "XX", "XX"])
    return mac
