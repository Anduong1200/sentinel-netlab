from dataclasses import dataclass, field
from typing import Any

from common.detection.reason_codes import ReasonCode
from common.scoring.types import Confidence


@dataclass
class Evidence:
    """Base class for any evidentiary fact."""

    type: str
    description: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "description": self.description, "data": self.data}


@dataclass
class Finding:
    """
    Standardized output from a Detector.
    Represents a potential security issue before it becomes a full Alert.
    """

    detector_id: str
    entity_key: str  # Unique identifier for the subject (e.g., "evil_twin|MyCorpWiFi|11:22:33:44:55:66")
    confidence_raw: Confidence  # Initial confidence from detector (0.0-1.0)

    evidence_list: list[Evidence] = field(default_factory=list)
    reason_codes: list[ReasonCode] = field(default_factory=list)

    context: dict[str, Any] = field(
        default_factory=dict
    )  # Extra metadata (channel, rssi, etc.)

    def add_evidence(self, ev: Evidence):
        self.evidence_list.append(ev)

    def add_reason(self, reason: ReasonCode):
        self.reason_codes.append(reason)
