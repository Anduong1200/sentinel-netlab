# Data Schema Reference

> Canonical data models for the Sentinel NetLab pipeline

---

## Overview

All data exchange uses Pydantic models defined in `common/contracts.py`.

```
Pipeline: Capture → RawFrame → NormalizedFrame → TelemetryBatch → Controller
```

---

## Frame Types

### RawFrame

Output from parser, minimal processing.

```python
from common.contracts import RawFrame

frame = RawFrame(
    timestamp=1706431800.123,
    mac_src="AA:BB:CC:11:22:33",
    mac_dst="FF:FF:FF:FF:FF:FF",
    bssid="AA:BB:CC:11:22:33",
    frame_type="management",
    frame_subtype="beacon",
    type_code=0,
    subtype_code=8,
    channel=6,
    rssi_dbm=-55,
    ssid="MyNetwork",
    sequence_number=1234,
    is_encrypted=False,
    frame_length=256,
)
```

**Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | float | Yes | Unix epoch (seconds.microseconds) |
| `mac_src` | str | No | Source MAC (XX:XX:XX:XX:XX:XX) |
| `mac_dst` | str | No | Destination MAC |
| `bssid` | str | No | AP MAC address |
| `frame_type` | FrameType | Yes | management/control/data/extension |
| `frame_subtype` | FrameSubtype | Yes | beacon/probe_req/deauth/etc |
| `type_code` | int | Yes | 0-3 |
| `subtype_code` | int | Yes | 0-15 |
| `channel` | int | No | 1-200 |
| `rssi_dbm` | int | No | -120 to 0 |
| `ssid` | str | No | Network name (max 32 chars) |
| `sequence_number` | int | No | 0-4095 |
| `is_encrypted` | bool | Yes | Frame encrypted flag |
| `frame_length` | int | Yes | Bytes |

---

### NormalizedFrame

Enriched, validated frame ready for analysis.

```python
from common.contracts import NormalizedFrame

normalized = NormalizedFrame.from_raw(
    raw=raw_frame,
    sensor_id="sensor-01",
    hash_macs=True,  # Privacy mode
    salt="secret-salt",
)
```

**Additional Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `frame_id` | str | Unique 8-char ID |
| `sensor_id` | str | Source sensor |
| `timestamp_iso` | str | ISO8601 format |
| `mac_src_hash` | str | Privacy-safe hash (16 chars) |
| `bssid_hash` | str | Privacy-safe hash |
| `vendor_src` | str | OUI vendor lookup |
| `security` | SecurityType | open/wep/wpa/wpa2_*/wpa3 |

---

### NetworkInfo

Aggregated network state.

```python
from common.contracts import NetworkInfo

network = NetworkInfo(
    bssid="AA:BB:CC:11:22:33",
    ssid="MyNetwork",
    channel=6,
    security="wpa2_ccmp",
    first_seen=1706431800.0,
    last_seen=1706435400.0,
    frame_count=1500,
    beacon_count=1200,
    rssi_avg=-52.5,
    risk_score=15.0,
    risk_level="low",
)
```

---

### Alert

Detection alert.

```python
from common.contracts import Alert

alert = Alert(
    alert_id="alert-abc123",
    sensor_id="sensor-01",
    alert_type="evil_twin",
    severity="High",
    title="Evil Twin Detected",
    description="SSID 'CorpNet' broadcast by multiple BSSIDs",
    bssid="DE:AD:BE:EF:00:01",
    ssid="CorpNet",
    evidence={"bssid_count": 2, "bssids": ["AA:...", "DE:..."]},
    risk_score=85.0,
    confidence=0.9,
    mitre_attack="T1557.001",
)
```

**Severity Levels**: Critical, High, Medium, Low, Info

**Alert Types**:
- `evil_twin` - Rogue AP impersonation
- `deauth_flood` - DoS attack
- `rogue_ap` - Unauthorized access point
- `probe_flood` - Client enumeration
- `sequence_anomaly` - Replay detection
- `rssi_anomaly` - Signal manipulation

---

### TelemetryBatch

Container for sensor → controller transport.

```python
from common.contracts import TelemetryBatch

batch = TelemetryBatch(
    sensor_id="sensor-01",
    batch_id="batch-xyz",
    timestamp_utc="2026-01-28T10:30:00Z",
    sequence_number=42,
    frames=[normalized_frame],
    networks=[network],
    alerts=[alert],
    frames_captured=150,
    frames_dropped=0,
    capture_duration_sec=60.0,
)
```

---

## Enums

### FrameType

```python
class FrameType(str, Enum):
    MANAGEMENT = "management"  # Type 0
    CONTROL = "control"        # Type 1
    DATA = "data"              # Type 2
    EXTENSION = "extension"    # Type 3
    UNKNOWN = "unknown"
```

### FrameSubtype

```python
# Management (Type 0)
BEACON = "beacon"              # Subtype 8
PROBE_REQUEST = "probe_req"    # Subtype 4
PROBE_RESPONSE = "probe_resp"  # Subtype 5
DEAUTHENTICATION = "deauth"    # Subtype 12
DISASSOCIATION = "disassoc"    # Subtype 10
AUTHENTICATION = "auth"        # Subtype 11
# ... see common/contracts.py for full list
```

### SecurityType

```python
class SecurityType(str, Enum):
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2_TKIP = "wpa2_tkip"
    WPA2_CCMP = "wpa2_ccmp"   # Recommended minimum
    WPA3 = "wpa3"             # Best
    UNKNOWN = "unknown"
```

---

## Privacy Modes

### Hash Mode (Recommended)

```python
from common.privacy import hash_mac

# One-way hash, irreversible
hashed = hash_mac("AA:BB:CC:11:22:33", salt="secret")
# → "a1b2c3d4e5f67890"
```

### Anonymize Mode

```python
from common.privacy import anonymize_mac_oui

# Preserves vendor prefix
anon = anonymize_mac_oui("AA:BB:CC:11:22:33")
# → "AA:BB:CC:XX:XX:XX"
```

### Forensic Mode

Full MAC stored (requires explicit opt-in in config).

---

## JSON Schema Generation

Generate JSON Schema from Pydantic models:

```bash
python sensor/schema.py --generate-json --output sensor/schema
```

Output files:
- `sensor/schema/normalized_frame.json`
- `sensor/schema/alert.json`
- `sensor/schema/telemetry_batch.json`

---

## Validation

All data is validated at:
1. **Sensor** - Before sending
2. **Controller** - On receipt

```python
from pydantic import ValidationError

try:
    frame = NormalizedFrame(**data)
except ValidationError as e:
    logger.error(f"Invalid frame: {e}")
```

---

## See Also

- [Source Code: common/contracts.py](../common/contracts.py)
- [Frame Constants: common/frame_constants.py](../common/frame_constants.py)
- [API Ingest](api_ingest.md)
