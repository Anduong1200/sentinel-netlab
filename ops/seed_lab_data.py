#!/usr/bin/env python3
"""
Seed Lab Data
-------------
Populates the Lab database with sample data from `examples/`.
Ensures the dashboard has visible content immediately after reset.
"""

import json
import logging
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from controller.config import init_config
from controller.db.models import Alert, Sensor

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("seed_lab_data")


def seed_data():
    logger.info("Seeding Lab Data...")

    # Initialize session
    init_config()
    session = get_session()

    # Paths
    root_dir = Path(__file__).parent.parent
    telemetry_path = root_dir / "examples" / "sample_telemetry_output.json"
    alert_path = root_dir / "examples" / "sample_alert_output.json"

    # 1. Ensure Sensor Exists
    sensor_id = "sensor-01"
    sensor = session.query(Sensor).filter_by(id=sensor_id).first()
    if not sensor:
        logger.info(f"Creating sensor: {sensor_id}")
        sensor = Sensor(
            id=sensor_id,
            name="Lab Demo Sensor",
            status="online",
            created_at=datetime.now(UTC),
            last_heartbeat=datetime.now(UTC),
            config={"mode": "monitor", "channel_hop": True},
        )
        session.add(sensor)

    # 2. Seed Telemetry
    if telemetry_path.exists():
        logger.info(f"Loading telemetry from {telemetry_path}...")
        with open(telemetry_path) as f:
            data = json.load(f)
    else:
        # Fallback: Deterministic Generation
        logger.warning(
            f"Scenario file {alert_path} not found. Generating deterministic mock data."
        )
        random.seed(42)  # Ensure every student gets the same "random" data

        # specific "Evil Twin" alert for consistency with Quickstart
        alert = Alert(
            id="generated-evil-twin-001",
            sensor_id=sensor_id,
            created_at=datetime.now(UTC) - timedelta(minutes=5),
            alert_type="evil_twin",
            severity="high",
            title="Evil Twin Access Point Detected",
            description="A rogue Access Point is broadcasting a trusted SSID (Corporate-WiFi) with a mismatched BSSID.",
            ssid="Corporate-WiFi",
            bssid="AA:BB:CC:DD:EE:FF",
            confidence=0.95,
            status="open",
        )
        session.merge(alert)
        logger.info("Seeded 1 generated alert.")

    session.commit()
    logger.info("Seeding complete.")


if __name__ == "__main__":
    try:
        seed_data()
    except Exception as e:
        logger.error(f"Seeding failed: {e}")
        sys.exit(1)
