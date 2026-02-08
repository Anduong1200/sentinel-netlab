"""
Database Health & Schema Readiness Checks
"""
import logging
from sqlalchemy import text, inspect
from controller.db.extensions import db

logger = logging.getLogger(__name__)

REQUIRED_TABLES = ["alembic_version", "telemetry", "alerts", "sensors", "api_tokens"]

def check_schema_readiness() -> tuple[bool, str]:
    """
    Verify that the database schema is migrated and ready.
    
    Checks:
    1. Connection is alive.
    2. 'alembic_version' table exists.
    3. Critical tables exist.
    
    Returns:
        (ready: bool, reason: str)
    """
    try:
        # Check connection implicitly via inspector
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Check critical tables
        missing = [t for t in REQUIRED_TABLES if t not in tables]
        if missing:
            return False, f"Missing core tables: {', '.join(missing)}"
            
        # Check alembic version (sanity check that we aren't null)
        # Note: We don't strictly check for HEAD here because that requires knowing
        # the exact revision ID in code, which changes often. 
        # Existence of 'alembic_version' implies at least one migration ran.
        # For stricter checks, we'd need to import the 'current' revision ID.
        with db.engine.connect() as conn:
            result = conn.execute(text("SELECT version_num FROM alembic_version"))
            version = result.scalar()
            if not version:
                return False, "Alembic version not found"
                
        return True, "Schema ready"
        
    except Exception as e:
        logger.error(f"Schema readiness check failed: {e}")
        return False, f"Database error: {str(e)}"
