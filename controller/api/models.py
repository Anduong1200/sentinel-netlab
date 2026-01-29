from datetime import datetime
from sqlalchemy.dialects.postgresql import JSONB
from .deps import db, config

class Telemetry(db.Model):
    __tablename__ = "telemetry"
    id = db.Column(db.Integer, primary_key=True)
    sensor_id = db.Column(db.String(64), index=True)
    batch_id = db.Column(db.String(64), index=True)
    ingested_at = db.Column(db.DateTime, default=datetime.utcnow)
    data = db.Column(JSONB if "postgresql" in config.database.url else db.JSON)


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
    __tablename__ = "tokens"
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
