
from datetime import UTC, datetime
from typing import Optional
from sqlalchemy.orm import Session
from controller.baseline.models import BaselineProfile
from controller.models import get_session

class BaselineStore:
    """
    Data Access Object for Baseline Profiles.
    """

    def __init__(self, session: Session = None):
        self.session = session or get_session()

    def get_profile(self, site_id: str, network_key: str) -> Optional[BaselineProfile]:
        """Fetch existing profile or None."""
        return self.session.query(BaselineProfile).filter_by(
            site_id=site_id, 
            network_key=network_key
        ).first()

    def get_or_create_profile(self, site_id: str, network_key: str) -> BaselineProfile:
        """Fetch or create a new profile."""
        profile = self.get_profile(site_id, network_key)
        if not profile:
            # Generate deterministic ID if needed, or rely on DB defaults
            # Here using simplistic string concat format for ID, or just UUID
            # Let's use site_id + network_key as ID implies 1:1
            import hashlib
            profile_id = hashlib.sha256(f"{site_id}:{network_key}".encode()).hexdigest()[:32]
            
            profile = BaselineProfile(
                id=profile_id,
                site_id=site_id,
                network_key=network_key,
                sample_count=0,
                features={
                    "channels": {},
                    "rssi": {"min": 999, "max": -999, "sum": 0, "count": 0},
                    "security_modes": {},
                    "vendors": {}
                }
            )
            self.session.add(profile)
            self.session.commit()
        return profile

    def update_profile(self, profile: BaselineProfile):
        """Commit changes to a profile."""
        profile.last_updated = datetime.now(UTC)
        self.session.add(profile)
        self.session.commit()
