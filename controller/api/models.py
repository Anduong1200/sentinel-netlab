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
