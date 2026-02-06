#!/usr/bin/env python3
"""
Initialize Lab Database (SQLite)
--------------------------------
Creates tables and seeds initial data for the Lab environment.
Uses SQLAlchemy models directly, ensuring compatibility with SQLite.
"""
import logging
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add parent directory to path so we can import controller
sys.path.append(str(Path(__file__).parent.parent))

from controller.config import init_config
from controller.models import APIToken, Base, get_engine, get_session

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("init_lab_db")

def main():
    logger.info("Initializing Lab Database (SQLite)...")

    # Force loading of lab config (will read .env.lab if present)
    config = init_config()

    # Ensure we are using SQLite
    if "sqlite" not in config.database.url:
         logger.warning(f"Warning: Database URL is {config.database.url}, expected sqlite://...")

    engine = get_engine()
    session = get_session(engine)

    # 1. Create Tables
    logger.info("Creating tables...")
    Base.metadata.create_all(engine)

    # 2. Seed Admin Token
    # 2. Seed Admin Token
    token_hash = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"  # sha256('admin') # noqa: S105

    existing = session.query(APIToken).filter_by(token_id="admin-01").first()
    if not existing:
        logger.info("Seeding default admin token...")
        admin_token = APIToken(
            id="admin-01",
            token_hash=token_hash,
            name="Lab Admin Token",
            role="admin",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365)
        )
        session.add(admin_token)
        session.commit()
    else:
        logger.info("Admin token already exists.")

    logger.info("Database initialization complete.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
