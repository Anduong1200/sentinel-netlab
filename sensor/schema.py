#!/usr/bin/env python3
"""
Sentinel NetLab - Unified Schema Definitions
Single source of truth: Pydantic models → JSON Schema generation

Usage:
    from sensor.schema import TelemetryItem, AlertCreate, SensorHeartbeat

Generate JSON Schema:
    python sensor/schema.py --generate-json
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any

try:
    from pydantic import BaseModel, Field, validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

    class BaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def dict(self, **kwargs):
            d = {}
            for k, v in self.__dict__.items():
                if hasattr(v, 'dict'):
                    d[k] = v.dict()
                elif isinstance(v, list):
                    d[k] = [x.dict() if hasattr(x, 'dict') else (x.value if hasattr(x, 'value') else x) for x in v]
                elif hasattr(v, 'value'):
                    d[k] = v.value
                else:
                    d[k] = v
            return d

    def Field(*a, **k):
        return None

    def validator(*a, **k):
        return lambda f: f


# =============================================================================
# ENUMS
# =============================================================================

class SecurityType(str, Enum):
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2_TKIP = "wpa2_tkip"
    WPA2_CCMP = "wpa2_ccmp"
    WPA3 = "wpa3"


class AlertSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AlertType(str, Enum):
    EVIL_TWIN = "evil_twin"
    DEAUTH_FLOOD = "deauth_flood"
    ROGUE_AP = "rogue_ap"
    WPS_ATTACK = "wps_attack"
    PROBE_FLOOD = "probe_flood"
    UNKNOWN = "unknown"


class SensorStatus(str, Enum):
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"


class LabelSource(str, Enum):
    MANUAL = "manual"
    AUTOMATED = "automated"
    GROUND_TRUTH = "ground_truth"
    INFERRED = "inferred"


# =============================================================================
# TELEMETRY SCHEMAS
# =============================================================================

class Capabilities(BaseModel):
    """WiFi AP capabilities"""
    privacy: bool = False
    pmf: bool = False
    wps: bool = False
    ht: bool = False
    vht: bool = False
    he: bool = False

    class Config:
        extra = 'allow'

class RSNInfo(BaseModel):
    """RSN/WPA2 information"""
    akm: list[str] = Field(default_factory=list)
    pairwise: list[str] = Field(default_factory=list)
    group: str | None = None

class TelemetryItem(BaseModel):
    """Single telemetry data point from sensor"""
    bssid: str = Field(..., regex=r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$',
                       description="AP MAC address")
    ssid: str | None = Field(None, max_length=32, description="Network name")
    channel: int | None = Field(None, ge=1, le=200, description="WiFi channel")
    rssi_dbm: int | None = Field(None, ge=-120, le=0, description="Signal strength")
    frequency_mhz: int | None = Field(None, ge=2400, le=6000)

    security: SecurityType | None = None
    capabilities: Capabilities | None = None
    rsn_info: RSNInfo | None = None

    vendor_oui: str | None = Field(None, max_length=8)
    beacon_interval: int | None = Field(None, ge=0)
    ie_count: int | None = Field(None, ge=0)

    timestamp: str | None = None

    class Config:
        extra = 'allow'
        use_enum_values = True

class TelemetryBatch(BaseModel):
    """Batch of telemetry from sensor"""
    sensor_id: str = Field(..., min_length=1, max_length=64)
    batch_id: str | None = Field(None, max_length=64)
    timestamp_utc: str = Field(..., description="ISO8601 timestamp")
    sequence_number: int | None = Field(None, ge=0, description="Monotonic counter for replay protection")
    items: list[TelemetryItem] = Field(..., max_items=1000)

    @validator('timestamp_utc')
    def validate_iso8601(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
        except ValueError:
            raise ValueError('Must be ISO8601 format')
        return v

# =========================================================================
# ALERT SCHEMAS
# =========================================================================

class AlertEvidence(BaseModel):
    """Evidence attached to alert"""
    frame_count: int | None = None
    pcap_reference: str | None = None
    screenshot: str | None = None
    raw_data: dict[str, Any] | None = None

class AlertCreate(BaseModel):
    """Request to create an alert"""
    alert_type: AlertType
    severity: AlertSeverity
    title: str = Field(..., max_length=200)
    description: str | None = Field(None, max_length=2000)

    bssid: str | None = None
    ssid: str | None = None

    evidence: AlertEvidence | None = None
    mitre_attack: str | None = Field(None, regex=r'^T\d{4}(\.\d{3})?$')

    confidence: float | None = Field(None, ge=0, le=1)

    class Config:
        use_enum_values = True

class Alert(AlertCreate):
    """Full alert object"""
    id: str
    sensor_id: str
    created_at: str
    status: str = "open"
    resolved_at: str | None = None
    resolved_by: str | None = None

# =========================================================================
# SENSOR SCHEMAS
# =========================================================================

class SensorMetrics(BaseModel):
    """Runtime metrics from sensor"""
    cpu_percent: float | None = Field(None, ge=0, le=100)
    memory_percent: float | None = Field(None, ge=0, le=100)
    frames_captured: int | None = Field(None, ge=0)
    uptime_seconds: int | None = Field(None, ge=0)

class SensorHeartbeat(BaseModel):
    """Sensor heartbeat request"""
    sensor_id: str = Field(..., min_length=1, max_length=64)
    status: SensorStatus = SensorStatus.ONLINE
    metrics: SensorMetrics | None = None
    sequence_number: int | None = Field(None, ge=0)

    class Config:
        use_enum_values = True

class SensorRegistration(BaseModel):
    """Sensor registration request"""
    sensor_id: str = Field(..., min_length=1, max_length=64)
    name: str | None = Field(None, max_length=128)
    location: str | None = None
    capabilities: dict[str, Any] | None = None

# =========================================================================
# ML DATASET SCHEMAS
# =========================================================================

class MLFeatures(BaseModel):
    """Computed features for ML"""
    rssi_zscore: float | None = None
    duplicate_ssid_count: int | None = None
    vendor_mismatch: bool | None = None
    security_mismatch: bool | None = None
    beacon_jitter: float | None = None
    is_new_appearance: bool | None = None
    ie_anomaly_score: float | None = None

class MLLabeledRecord(BaseModel):
    """Labeled record for ML training"""
    id: str
    timestamp_utc: str
    sensor_id: str | None = None

    bssid: str = Field(..., regex=r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    ssid: str | None = None
    channel: int | None = None
    rssi_dbm: int | None = None
    security: SecurityType | None = None

    label: AlertType
    label_confidence: float | None = Field(None, ge=0, le=1)
    label_source: LabelSource | None = None
    label_notes: str | None = None

    features: MLFeatures | None = None

    class Config:
        use_enum_values = True


# =============================================================================
# JSON SCHEMA GENERATION
# =============================================================================

def generate_json_schemas(output_dir: str = "sensor/schema"):
    """Generate JSON Schema files from Pydantic models"""
    from pathlib import Path

    if not PYDANTIC_AVAILABLE:
        print("Error: pydantic required for schema generation")
        return

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    schemas = {
        "telemetry_item": TelemetryItem,
        "telemetry_batch": TelemetryBatch,
        "alert_create": AlertCreate,
        "alert": Alert,
        "sensor_heartbeat": SensorHeartbeat,
        "ml_labeled_record": MLLabeledRecord,
    }

    for name, model in schemas.items():
        schema = model.schema()
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'

        filepath = output_path / f"{name}.schema.json"
        with open(filepath, 'w') as f:
            json.dump(schema, f, indent=2)
        print(f"Generated: {filepath}")


# =============================================================================
# CLI
# =============================================================================

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--generate-json', action='store_true', help='Generate JSON schemas')
    parser.add_argument('--output', default='sensor/schema', help='Output directory')

    args = parser.parse_args()

    if args.generate_json:
        generate_json_schemas(args.output)
    else:
        parser.print_help()
