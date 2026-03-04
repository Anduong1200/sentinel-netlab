"""
Sentinel NetLab - Privacy Utilities
====================================
MAC address anonymization and data protection utilities.
Implements GDPR-friendly data handling patterns.
"""

import hashlib
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


# =============================================================================
# MAC ADDRESS HANDLING
# =============================================================================

MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


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


def anonymize_mac_oui(mac: str) -> str:
    """
    Anonymize MAC address while preserving OUI (vendor prefix).
    Replaces last 3 octets with XX.

    Example: "AA:BB:CC:11:22:33" → "AA:BB:CC:XX:XX:XX"
    """
    normalized = normalize_mac(mac)
    parts = normalized.split(":")
    if len(parts) == 6:
        return ":".join(parts[:3] + ["00", "00", "00"])
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


def get_oui(mac: str) -> str:
    """Extract OUI (first 3 octets) from MAC address"""
    normalized = normalize_mac(mac)
    return ":".join(normalized.split(":")[:3])


def anonymize_mac(mac: str, mode: str = "full") -> str:
    """
    Anonymize MAC address based on GDPR privacy mode.

    Modes:
      - 'oui': Preserves vendor prefix, zeroes out device ID
      - 'full': Hashes the entire MAC address
    """
    if not mac:
        return mac

    if mode.lower() == "oui":
        return anonymize_mac_oui(mac)
    elif mode.lower() == "full":
        return anonymize_mac_full(mac)

    # Default fallback to full hash for safety
    return anonymize_mac_full(mac)


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
