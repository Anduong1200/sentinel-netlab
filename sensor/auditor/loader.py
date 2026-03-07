import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)


class ChecklistLoader:
    """Load and manage audit checklists"""

    def __init__(self, rules_dir: Path = None):
        if rules_dir is None:
            # Point to the original rules dir in sensor/rules
            rules_dir = Path(__file__).parent.parent / "rules"
        self.rules_dir = rules_dir

    def load_checklist(self, profile: str) -> list[dict]:
        """Load checklist for profile (home/sme)"""
        filename = f"audit-{profile}-checklist.json"
        filepath = self.rules_dir / filename

        if not filepath.exists():
            logger.warning(f"Checklist not found: {filepath}")
            return []

        with open(filepath, encoding="utf-8") as f:
            return json.load(f)

    def get_profiles(self) -> list[str]:
        """List available profiles"""
        profiles = []
        for f in self.rules_dir.glob("audit-*-checklist.json"):
            match = re.match(r"audit-(.+)-checklist\.json", f.name)
            if match:
                profiles.append(match.group(1))
        return profiles
