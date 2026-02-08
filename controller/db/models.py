"""
Sentinel NetLab - Canonical Database Models
Single Source of Truth for Database Schema.
Uses Flask-SQLAlchemy (db.Model) for integration with Flask app context.
"""

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from controller.db.extensions import db


class Sensor(db.Model):
    """Registered sensor"""

    __tablename__ = "sensors"

    id = Column(String(64), primary_key=True)
    name = Column(String(128))
    status = Column(String(20), default="offline")
    last_heartbeat = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    config = Column(JSON, default={})

    telemetry = relationship("Telemetry", back_populates="sensor")
    alerts = relationship("Alert", back_populates="sensor")


class Telemetry(db.Model):
    """Telemetry data from sensors"""

    __tablename__ = "telemetry"

    # TimescaleDB requires timestamp to be part of the primary key for hypertables
    # But SQLite doesn't support AUTOINCREMENT on composite PKs easily.
    import os

    _is_sqlite = "sqlite" in (
        os.getenv("CONTROLLER_DATABASE_URL") or os.getenv("DATABASE_URL") or "sqlite"
    )

    if _is_sqlite:
        timestamp = Column(DateTime(timezone=True), index=True)
        id = Column(Integer, primary_key=True, autoincrement=True)
    else:
        timestamp = Column(DateTime(timezone=True), primary_key=True, index=True)
        id = Column(Integer, primary_key=True, autoincrement=True)

    sensor_id = Column(String(64), ForeignKey("sensors.id"), index=True)
    batch_id = Column(String(64), index=True)
    ingested_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    bssid = Column(String(17), index=True)
    ssid = Column(String(32))
    channel = Column(Integer)
    rssi_dbm = Column(Integer)
    frequency_mhz = Column(Integer)

    security = Column(String(20))
    capabilities = Column(JSON, default={})
    rsn_info = Column(JSON, default={})

    raw_data = Column(JSON, default={})

    sensor = relationship("Sensor", back_populates="telemetry")

    __table_args__ = (
        Index("ix_telemetry_bssid_timestamp", "bssid", "timestamp"),
        Index("ix_telemetry_sensor_timestamp", "sensor_id", "timestamp"),
    )


class Alert(db.Model):
    """Security alerts"""

    __tablename__ = "alerts"

    id = Column(String(32), primary_key=True)
    sensor_id = Column(String(64), ForeignKey("sensors.id"), index=True)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )

    alert_type = Column(String(50), index=True)
    severity = Column(String(20), index=True)
    title = Column(String(200))
    description = Column(Text)

    bssid = Column(String(17))
    ssid = Column(String(32))

    evidence = Column(JSON, default={})
    reason_codes = Column(JSON, default=[])  # List[str] codes

    # Scoring
    confidence = Column(Float)  # 0.0 - 1.0
    impact = Column(Float)  # 0.0 - 100.0
    risk_score = Column(Float)  # 0.0 - 100.0

    mitre_attack = Column(String(20))

    status = Column(String(20), default="open", index=True)
    resolved_at = Column(DateTime(timezone=True))
    resolved_by = Column(String(64))

    sensor = relationship("Sensor", back_populates="alerts")

    __table_args__ = (Index("ix_alerts_status_created_at", "status", "created_at"),)


class APIToken(db.Model):
    """API tokens for authentication"""

    __tablename__ = "api_tokens"

    token_id = Column(String(32), primary_key=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128))
    role = Column(String(20), nullable=False)
    sensor_id = Column(String(64), nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    expires_at = Column(DateTime(timezone=True))  # Nullable in DB script
    last_used = Column(DateTime(timezone=True))
    last_sequence = Column(BigInteger, default=0)

    is_active = Column(Boolean, default=True)


class AuditLog(db.Model):
    """Audit trail for security events"""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )

    event_type = Column(String(50), index=True, nullable=False)
    actor = Column(String(64))
    resource = Column(String(128))
    action = Column(String(50))

    details = Column(JSON, default={})
    ip_address = Column(String(45))


class IngestJob(db.Model):
    """Ingestion queue jobs (DB-backed)"""

    __tablename__ = "ingest_jobs"

    job_id = Column(String(64), primary_key=True)
    sensor_id = Column(String(64), nullable=False)
    batch_id = Column(String(64), nullable=True)
    received_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )

    status = Column(
        String(20), default="queued", index=True
    )  # queued, processing, done, failed
    payload = Column(JSON)

    attempts = Column(Integer, default=0)
    next_attempt_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    error_msg = Column(Text)

    __table_args__ = (
        Index("idx_jobs_status_next", "status", "next_attempt_at"),
        UniqueConstraint("sensor_id", "batch_id", name="uq_ingest_sensor_batch"),
    )
