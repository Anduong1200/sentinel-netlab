from datetime import UTC, datetime

from sqlalchemy import JSON, Column, DateTime, Index, Integer, String

from controller.models import Base


class BaselineProfile(Base):
    """
    Statistical baseline for a specific network entity (Site + Network Key).
    Used to detect anomalies based on historical behavior.
    """

    __tablename__ = "baseline_profiles"

    # Composite PK might be complex, using ID for simplicity and unique constraint
    id = Column(
        String(64), primary_key=True
    )  # hash(site_id + network_key) ?? Or just UUID.
    # Let's use string composite key representation or just separate fields.
    # To avoid complex composite PKs in SQLAlchemy for now, let's use a synthetic ID or string ID.

    site_id = Column(String(64), nullable=False, index=True)
    network_key = Column(String(128), nullable=False, index=True)
    # network_key example: "network|OpenCafe" or "bssid|11:22:33..."

    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_updated = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    sample_count = Column(Integer, default=0)

    # Feature Stats (JSON)
    # {
    #   "channels": {"1": 50, "6": 10},
    #   "rssi": {"min": -80, "max": -50, "avg": -65, "sum": -6500, "count": 100},
    #   "security_modes": {"WPA2": 100},
    #   "vendors": {"Intel": 50, "Unknown": 50}
    # }
    features = Column(JSON, default={})

    __table_args__ = (
        Index("ix_baseline_site_network", "site_id", "network_key", unique=True),
    )
