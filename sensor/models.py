from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class NetworkRecord:
    """Standardized network data structure"""
    ssid: str
    bssid: str
    signal: Optional[int]
    channel: Optional[int]
    encryption: str
    vendor: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat()
