from typing import Any

from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    """Alert creation request"""

    alert_type: str = Field(..., max_length=50)
    severity: str = Field(..., pattern=r"(?i)^(Critical|High|Medium|Low|Info)$")
    title: str = Field(..., max_length=200)
    description: str | None = Field(None, max_length=2000)
    bssid: str | None = None
    ssid: str | None = None
    details: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None
    risk_score: float | None = Field(None, ge=0, le=100)
    confidence: float | None = Field(None, ge=0, le=1)
    impact: float | None = Field(None, ge=0, le=100)
    reason_codes: list[str] | None = None
    mitre_attack: str | None = None
    sensor_id: str | None = None

    schema_version: str = "1.0"

    model_config = {
        "use_enum_values": True,
        "extra": "ignore",
        "validate_assignment": True,
    }
