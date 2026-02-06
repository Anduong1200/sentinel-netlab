
from dataclasses import dataclass


@dataclass(frozen=True)
class ReasonCode:
    """
    Standardized reason for a detection finding.
    Used to explain 'Why' an alert was triggered.
    """
    code: str
    category: str
    message_template: str

    def format(self, **kwargs) -> str:
        """Format the message template with context variables."""
        try:
            return self.message_template.format(**kwargs)
        except KeyError:
            return self.message_template  # Fallback if args missing

class ReasonCategory:
    SIGNAL = "signal_anomaly"
    CONFIGURATION = "configuration_mismatch"
    BEHAVIOR = "behavioral_anomaly"
    THREAT = "known_threat"

class ReasonCodes:
    """Catalog of Standard Reason Codes"""

    # Evil Twin / Rogue AP
    SSID_SPOOFING = ReasonCode(
        code="SSID_SPOOFING",
        category=ReasonCategory.THREAT,
        message_template="SSID '{ssid}' matches authorized network but BSSID '{bssid}' is unknown."
    )

    SECURITY_DOWNGRADE = ReasonCode(
        code="SECURITY_DOWNGRADE",
        category=ReasonCategory.CONFIGURATION,
        message_template="Network '{ssid}' security downgraded to '{security}' (Expected: '{expected}')."
    )

    CHANNEL_MISMATCH = ReasonCode(
        code="CHANNEL_MISMATCH",
        category=ReasonCategory.SIGNAL,
        message_template="AP '{bssid}' operating on channel {channel} (Baseline: {baseline_channels})."
    )

    RSSI_ANOMALY = ReasonCode(
        code="RSSI_ANOMALY",
        category=ReasonCategory.SIGNAL,
        message_template="Signal strength {rssi}dBm deviates significantly from baseline ({expected_range})."
    )

    # Deauth / DoS
    DEAUTH_FLOOD = ReasonCode(
        code="DEAUTH_FLOOD",
        category=ReasonCategory.BEHAVIOR,
        message_template="Excessive deauthentication frames ({rate}/sec) targeting '{target}'."
    )

    # General
    UNKNOWN_DEVICE = ReasonCode(
        code="UNKNOWN_DEVICE",
        category=ReasonCategory.BEHAVIOR,
        message_template="New unclassified device '{mac}' with high activity."
    )
