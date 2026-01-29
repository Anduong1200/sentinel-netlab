from typing import Dict, Optional
from pydantic import BaseModel, Field

class HeartbeatRequest(BaseModel):
    """Sensor heartbeat"""
    sensor_id: str
    status: str = Field("online", pattern=r"^(online|degraded|offline)$")
    metrics: Optional[Dict] = None
    sequence_number: Optional[int] = None

    schema_version: str = "1.0"

    model_config = {
        "use_enum_values": True,
        "extra": "forbid",
        "validate_assignment": True
    }
