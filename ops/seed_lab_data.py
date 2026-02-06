#!/usr/bin/env python3
"""
Seed Lab Data
-------------
Populates the Lab database with sample data from `examples/`.
Ensures the dashboard has visible content immediately after reset.
"""
import sys
import json
import logging
from pathlib import Path
from datetime import datetime, UTC

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from controller.models import Base, get_session, get_engine, Sensor, Telemetry, Alert
from controller.config import init_config

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
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
            config={"mode": "monitor", "channel_hop": True}
        )
        session.add(sensor)
    
    # 2. Seed Telemetry
    if telemetry_path.exists():
        logger.info(f"Loading telemetry from {telemetry_path}...")
        with open(telemetry_path, "r") as f:
            data = json.load(f)
            
        frames = data.get("frames", [])
        batch_id = data.get("batch_id", "demo-batch-001")
        
        count = 0
        for frame in frames:
            # Check for dupe implicitly by ID if we wanted, but for seed we just add
            # Ideally clear DB first, but lab-reset does that.
            
            # Timestamp conversion
            ts = datetime.fromtimestamp(frame["timestamp"], UTC)
            
            t = Telemetry(
                sensor_id=sensor_id,
                batch_id=batch_id,
                timestamp=ts,
                ingested_at=datetime.now(UTC),
                
                bssid=frame.get("bssid"),
                ssid=frame.get("ssid"),
                channel=frame.get("channel"),
                rssi_dbm=frame.get("rssi_dbm"),
                frequency_mhz=frame.get("frequency_mhz", 2412),
                
                security=frame.get("security"),
                raw_data=frame
            )
            session.add(t)
            count += 1
            
        logger.info(f"Seeded {count} telemetry records.")
    
    # 3. Seed Alerts
    if alert_path.exists():
        logger.info(f"Loading alerts from {alert_path}...")
        with open(alert_path, "r") as f:
            alert_data = json.load(f)
            
        # Example file contains a single object, but let's handle list if it changes
        alerts = [alert_data] if isinstance(alert_data, dict) else alert_data
        
        count = 0
        for a in alerts:
            ts = datetime.fromtimestamp(a.get("created_at", datetime.now(UTC).timestamp()), UTC)
            
            alert = Alert(
                id=a.get("alert_id", "demo-alert-001"),
                sensor_id=sensor_id,
                created_at=ts,
                
                alert_type=a.get("alert_type"),
                severity=a.get("severity"),
                title=a.get("title"),
                description=a.get("description"),
                
                bssid=a.get("bssid"),
                ssid=a.get("ssid"),
                
                evidence=a.get("evidence", {}),
                confidence=a.get("confidence", 0.0),
                risk_score=a.get("risk_score", 0.0),
                mitre_attack=a.get("mitre_attack"),
                
                status=a.get("status", "open")
            )
            session.merge(alert) # Merge to update if exists
            count += 1

        logger.info(f"Seeded {count} alerts.")

    session.commit()
    logger.info("Seeding complete.")

if __name__ == "__main__":
    try:
        seed_data()
    except Exception as e:
        logger.error(f"Seeding failed: {e}")
        sys.exit(1)
