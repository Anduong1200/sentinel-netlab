"""
DEPRECATED: Use controller.db.models instead.
This file is kept for backward compatibility during refactoring phase.
"""

from controller.db.models import (
    Alert,
    APIToken,
    AuditLog,
    IngestJob,
    Sensor,
    Telemetry,
)

# Re-export Base for compatibility if needed, 
# but preferably code should move to db.Model.
# Since we moved to Flask-SQLAlchemy, 'Base' is db.Model.
from controller.db.extensions import db

Base = db.Model
