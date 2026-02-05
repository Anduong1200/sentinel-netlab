
import hashlib
from common.detection.evidence import Finding

def generate_fingerprint(finding: Finding) -> str:
    """
    Generate a deterministic fingerprint for a Finding.
    Used to identify identical events for deduplication.
    
    Format: hash(detector_id + entity_key + primary_reason_code)
    """
    # Use the first reason code as the primary driver for "Why"
    reason_code = finding.reason_codes[0].code if finding.reason_codes else "UNKNOWN"
    
    # Construct raw string
    # e.g. "rogue_channel_dev|rogue|Net1|WPA2|AA:BB|CHANNEL_MISMATCH"
    raw = f"{finding.detector_id}|{finding.entity_key}|{reason_code}"
    
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
