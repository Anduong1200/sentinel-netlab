"""
Sentinel NetLab - Privacy Utilities
====================================
MAC address anonymization and data protection utilities.
Implements GDPR-friendly data handling patterns.
"""

import hashlib
import hmac
import re
import secrets

# Global salt (regenerate per deployment)
_PRIVACY_SALT: str | None = None


def get_privacy_salt() -> str:
    """Get or generate privacy salt for hashing"""
    global _PRIVACY_SALT
    if _PRIVACY_SALT is None:
        # In production, load from environment or secrets manager
        import os

        _PRIVACY_SALT = os.environ.get("PRIVACY_SALT", secrets.token_hex(16))
    return _PRIVACY_SALT


def set_privacy_salt(salt: str) -> None:
    """Set privacy salt (call once at startup)"""
    global _PRIVACY_SALT
    _PRIVACY_SALT = salt


# =============================================================================
# MAC ADDRESS HANDLING
# =============================================================================

MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def is_valid_mac(mac: str) -> bool:
    """Validate MAC address format"""
    return bool(MAC_PATTERN.match(mac))


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase with colons"""
    mac = mac.upper().replace("-", ":").replace(".", ":")
    # Handle Cisco format (1234.5678.9abc)
    if ":" not in mac and len(mac) == 12:
        mac = ":".join(mac[i : i + 2] for i in range(0, 12, 2))
    return mac


def hash_mac(mac: str, salt: str | None = None) -> str:
    """
    One-way hash MAC address for privacy.
    Uses SHA-256 with salt, returns 16-char hex string.

    Args:
        mac: MAC address (any format)
        salt: Optional salt (uses global if not provided)

    Returns:
        16-character hex hash (collision-resistant, irreversible)
    """
    if salt is None:
        salt = get_privacy_salt()

    normalized = normalize_mac(mac)
    return hashlib.sha256((salt + normalized).encode()).hexdigest()[:16]


def hash_mac_hmac(mac: str, key: bytes) -> str:
    """
    Hash MAC using HMAC-SHA256 (keyed hash).
    More secure for cross-system consistency.
    """
    normalized = normalize_mac(mac)
    return hmac.new(key, normalized.encode(), hashlib.sha256).hexdigest()[:16]


def anonymize_mac_oui(mac: str) -> str:
    """
    Anonymize MAC address while preserving OUI (vendor prefix).
    Replaces last 3 octets with XX.

    Example: "AA:BB:CC:11:22:33" → "AA:BB:CC:XX:XX:XX"
    """
    normalized = normalize_mac(mac)
    parts = normalized.split(":")
    if len(parts) == 6:
        return ":".join(parts[:3] + ["XX", "XX", "XX"])
    return mac


def anonymize_mac_full(mac: str) -> str:
    """
    Fully anonymize MAC address (hash entire address).
    Returns a pseudo-MAC that looks real but is hashed.

    Example: "AA:BB:CC:11:22:33" → "A1:B2:C3:D4:E5:F6"
    """
    hashed = hash_mac(mac)
    # Convert to MAC-like format
    return ":".join(hashed[i : i + 2].upper() for i in range(0, 12, 2))


def is_broadcast_mac(mac: str) -> bool:
    """Check if MAC is broadcast address"""
    return normalize_mac(mac) == "FF:FF:FF:FF:FF:FF"


def is_multicast_mac(mac: str) -> bool:
    """Check if MAC is multicast (LSB of first octet is 1)"""
    normalized = normalize_mac(mac)
    first_octet = int(normalized.split(":")[0], 16)
    return bool(first_octet & 0x01)


def is_locally_administered(mac: str) -> bool:
    """Check if MAC is locally administered (bit 1 of first octet)"""
    normalized = normalize_mac(mac)
    first_octet = int(normalized.split(":")[0], 16)
    return bool(first_octet & 0x02)


def get_oui(mac: str) -> str:
    """Extract OUI (first 3 octets) from MAC address"""
    normalized = normalize_mac(mac)
    return ":".join(normalized.split(":")[:3])


# =============================================================================
# SSID HANDLING
# =============================================================================


def anonymize_ssid(ssid: str, keep_length: bool = True) -> str:
    """
    Anonymize SSID while optionally preserving length info.

    Args:
        ssid: Original SSID
        keep_length: If True, returns same-length string of asterisks

    Returns:
        Anonymized SSID
    """
    if not ssid:
        return ""

    if keep_length:
        return "*" * len(ssid)
    else:
        return hash_mac(ssid)[:8] + "..."


def is_hidden_ssid(ssid: str | None) -> bool:
    """Check if SSID is hidden (null or empty)"""
    return ssid is None or ssid == "" or ssid == "\x00" * len(ssid)


# =============================================================================
# DATA RETENTION
# =============================================================================


class RetentionPolicy:
    """Data retention configuration"""

    def __init__(
        self,
        raw_frames_days: int = 7,
        normalized_days: int = 30,
        alerts_days: int = 90,
        anonymize_after_days: int = 1,
    ):
        self.raw_frames_days = raw_frames_days
        self.normalized_days = normalized_days
        self.alerts_days = alerts_days
        self.anonymize_after_days = anonymize_after_days

    @classmethod
    def gdpr_compliant(cls) -> "RetentionPolicy":
        """GDPR-compliant retention policy"""
        return cls(
            raw_frames_days=1,  # Minimal
            normalized_days=7,
            alerts_days=30,
            anonymize_after_days=0,  # Immediate anonymization
        )

    @classmethod
    def forensic_mode(cls) -> "RetentionPolicy":
        """Extended retention for incident investigation"""
        return cls(
            raw_frames_days=30,
            normalized_days=90,
            alerts_days=365,
            anonymize_after_days=7,
        )


# =============================================================================
# PRIVACY MODES
# =============================================================================


class PrivacyMode:
    """Privacy mode configuration for data handling"""

    NORMAL = "normal"  # Full data, for authorized testing
    ANONYMIZED = "anonymized"  # OUI preserved, rest hashed
    PRIVATE = "private"  # Fully hashed, no raw data
    FORENSIC = "forensic"  # Full data with extended retention

    @staticmethod
    def get_transformer(mode: str):
        """Get data transformer for privacy mode"""
        if mode == PrivacyMode.PRIVATE:
            return lambda mac: anonymize_mac_full(mac)
        elif mode == PrivacyMode.ANONYMIZED:
            return lambda mac: anonymize_mac_oui(mac)
        else:
            return lambda mac: mac  # No transformation
