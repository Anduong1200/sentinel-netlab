from datetime import UTC, datetime

from sqlalchemy.dialects.postgresql import JSONB

from .deps import config, db


class Telemetry(db.Model):
    __tablename__ = "telemetry"
    # Composite PK in DB (timescale), but here usually we don't need to model it strictly for inserts
    # We rely on auto-increment ID for basic fetching if needed.
    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    sensor_id = db.Column(db.String(64), index=True)
    batch_id = db.Column(db.String(64), index=True)
    timestamp = db.Column(db.DateTime(timezone=True), index=True)
    ingested_at = db.Column(db.DateTime(timezone=True), default=datetime.now(UTC))

    # Specific Columns
    bssid = db.Column(db.String(17), index=True)
    ssid = db.Column(db.String(32))
    channel = db.Column(db.Integer)
    rssi_dbm = db.Column(db.Integer)
    frequency_mhz = db.Column(db.Integer)
    security = db.Column(db.String(20))

    # JSON Data
    data = db.Column(JSONB if "postgresql" in config.database.url else db.JSON, name="raw_data")
    capabilities = db.Column(JSONB if "postgresql" in config.database.url else db.JSON, default={})


class IngestJob(db.Model):
    __tablename__ = "ingest_jobs"
    job_id = db.Column(db.String(64), primary_key=True) # batch_id
    sensor_id = db.Column(db.String(64), nullable=False)
    received_at = db.Column(db.DateTime(timezone=True), default=datetime.now(UTC))
    item_count = db.Column(db.Integer, default=0)

    status = db.Column(db.String(20), default="queued") # queued, processing, done, failed
    payload = db.Column(JSONB if "postgresql" in config.database.url else db.JSON)

    attempts = db.Column(db.Integer, default=0)
    next_attempt_at = db.Column(db.DateTime(timezone=True), default=datetime.now(UTC))
    error_msg = db.Column(db.Text)


class DBAlert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.String(32), primary_key=True)
    sensor_id = db.Column(db.String(64), index=True)
    alert_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    evidence = db.Column(JSONB if "postgresql" in config.database.url else db.JSON)


class Token(db.Model):
    __tablename__ = "api_tokens"
    token_id = db.Column(db.String(32), primary_key=True)
    token_hash = db.Column(db.String(64), index=True, unique=True, nullable=False)
    name = db.Column(db.String(100))
    role = db.Column(db.String(20), nullable=False)
    sensor_id = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_used = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_sequence = db.Column(db.BigInteger, default=0)
