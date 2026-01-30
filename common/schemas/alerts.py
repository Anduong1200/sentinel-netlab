from typing import Dict, Optional
from pydantic import BaseModel, Field


class AlertCreate(BaseModel):
    """Alert creation request"""

    alert_type: str = Field(..., max_length=50)
    severity: str = Field(..., pattern=r"^(Critical|High|Medium|Low|Info)$")
    title: str = Field(..., max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    bssid: Optional[str] = None
    evidence: Optional[Dict] = None

    schema_version: str = "1.0"

    model_config = {
        "use_enum_values": True,
        "extra": "forbid",
        "validate_assignment": True,
    }
