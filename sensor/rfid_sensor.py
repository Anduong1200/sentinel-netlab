#!/usr/bin/env python3
"""
Sentinel NetLab - RFID Sensor
Monitors RFID/NFC activity for unauthorized access or cloning.
"""

import logging
import time
import json
from dataclasses import dataclass, asdict
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class RFIDTag:
    tag_id: str
    tag_type: str  # MIFARE, HID, etc.
    timestamp: str
    authorized: bool = False


class RFIDSensor:
    """
    Interface for RFID/NFC readers.
    Supports MFRC522, PN532, or Proxmark3.
    """

    def __init__(self, sensor_id: str, mock: bool = False):
        self.sensor_id = sensor_id
        self.mock = mock
        self.authorized_tags: set[str] = set()

    def add_authorized_tag(self, tag_id: str):
        self.authorized_tags.add(tag_id.upper())

    def read_tag(self) -> RFIDTag | None:
        """Poll for a tag"""
        if self.mock:
            return self._mock_read()

        try:
            # Placeholder for real hardware integration
            # Example: from mfrc522 import SimpleMFRC522
            pass
        except Exception as e:
            logger.error(f"RFID reader error: {e}")

        return None

    def _mock_read(self) -> RFIDTag | None:
        """Simulate random RFID tag reads"""
        import random

        if random.random() > 0.1:  # 10% chance to read a tag
            return None

        tag_id = f"TAG-{random.randint(1000, 9999):04x}".upper()
        return RFIDTag(
            tag_id=tag_id,
            tag_type="MIFARE Classic",
            timestamp=datetime.now(UTC).isoformat(),
            authorized=(tag_id in self.authorized_tags),
        )


if __name__ == "__main__":
    sensor = RFIDSensor(sensor_id="test-sensor", mock=True)
    sensor.add_authorized_tag("TAG-ABCD")

    print("Monitoring RFID tags (Press Ctrl+C to stop)...")
    try:
        while True:
            tag = sensor.read_tag()
            if tag:
                status = "AUTHORIZED" if tag.authorized else "⚠️ UNAUTHORIZED"
                print(f"[{tag.timestamp}] {status} Tag: {tag.tag_id} ({tag.tag_type})")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nRFID Monitoring stopped.")
