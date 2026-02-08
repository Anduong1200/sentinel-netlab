#!/usr/bin/env python3
"""
Initialize Lab Database (SQLite)
--------------------------------
Creates tables and seeds initial data for the Lab environment.
Uses SQLAlchemy models directly, ensuring compatibility with SQLite.
"""

import hashlib
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

# Add parent directory to path so we can import controller
sys.path.append(str(Path(__file__).parent.parent))

from controller.api.deps import create_app, db
from controller.db.models import APIToken

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("init_lab_db")


def main():
    logger.info("Initializing Lab Database (SQLite)...")

    print("Initializing Lab Database...")

    app = create_app()
    with app.app_context():
        # Create Tables
        db.create_all()
        print("Tables created.")

        session = db.session
        try:
            # Check/Create Admin Token
            admin_token_hash = hashlib.sha256(b"admin-token-dev").hexdigest()  # noqa: S106
            if (
                not session.query(APIToken)
                .filter_by(token_hash=admin_token_hash)
                .first()
            ):
                admin_token = APIToken(
                    token_id="admin-dev",  # noqa: S106
                    token_hash=admin_token_hash,
                    name="Lab Admin",
                    role="admin",
                    is_active=True,
                    created_at=datetime.now(UTC),
                    # expires_at=None # indefinite
                )
                session.add(admin_token)
                print("Created admin-token-dev")

            # Check/Create Sensor Token
            sensor_token_hash = hashlib.sha256(b"sensor-01-token").hexdigest()  # noqa: S106
            if (
                not session.query(APIToken)
                .filter_by(token_hash=sensor_token_hash)
                .first()
            ):
                sensor_token = APIToken(
                    token_id="sensor-01",  # noqa: S106
                    token_hash=sensor_token_hash,
                    name="Lab Sensor 01",
                    role="sensor",
                    sensor_id="lab-sensor-01",
                    is_active=True,
                    created_at=datetime.now(UTC),
                )
                session.add(sensor_token)
                print("Created sensor-01-token")

            session.commit()
            print("Lab DB Initialization Complete.")

        except Exception as e:
            print(f"Error initializing DB: {e}")
            session.rollback()
    return 0


if __name__ == "__main__":
    sys.exit(main())
