from dataclasses import dataclass
from datetime import datetime


@dataclass
class NetworkRecord:
    """Standardized network data structure"""

    ssid: str
    bssid: str
    signal: int | None
    channel: int | None
    encryption: str
    vendor: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None

    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat()
