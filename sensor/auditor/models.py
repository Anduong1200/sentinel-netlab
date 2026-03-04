from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class CheckStatus(StrEnum):
    PASS = "Pass"  # noqa: S105
    FAIL = "Fail"
    WARN = "Warn"
    SKIP = "Skip"
    OPEN = "Open"


SEVERITY_SCORES = {"Critical": 90, "High": 70, "Medium": 40, "Low": 10, "Info": 0}


@dataclass
class Finding:
    """Security finding from audit"""

    id: str
    title: str
    severity: str
    score: int
    status: str
    description: str
    evidence_summary: str = ""
    evidence: list[str] = field(default_factory=list)
    evidence_raw: str | None = None
    remediation: str = ""
    remediation_summary: str = ""
    remediation_commands: list[str] = field(default_factory=list)
    timeline: str = ""
    references: list[dict[str, str]] = field(default_factory=list)


@dataclass
class NetworkInfo:
    """Network information for audit"""

    bssid: str
    ssid: str | None
    channel: int
    rssi_dbm: int
    security: str
    wps_enabled: bool = False
    pmf_enabled: bool = False
    hidden: bool = False
    vendor_oui: str | None = None
    rsn_info: dict = field(default_factory=dict)
    capabilities: dict = field(default_factory=dict)
