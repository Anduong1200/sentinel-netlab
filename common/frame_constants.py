"""
Sentinel NetLab - 802.11 Frame Constants
=========================================
Standardized mapping of 802.11 frame types and subtypes.
Reference: IEEE 802.11-2020 standard
"""

# =============================================================================
# FRAME TYPE CODES (2 bits)
# =============================================================================
FRAME_TYPES = {
    0: "management",
    1: "control",
    2: "data",
    3: "extension",
}

# =============================================================================
# MANAGEMENT FRAME SUBTYPES (type=0)
# =============================================================================
MANAGEMENT_SUBTYPES = {
    0: "assoc_req",  # Association Request
    1: "assoc_resp",  # Association Response
    2: "reassoc_req",  # Reassociation Request
    3: "reassoc_resp",  # Reassociation Response
    4: "probe_req",  # Probe Request
    5: "probe_resp",  # Probe Response
    6: "timing_adv",  # Timing Advertisement
    7: "reserved",
    8: "beacon",  # Beacon
    9: "atim",  # Announcement Traffic Indication Map
    10: "disassoc",  # Disassociation
    11: "auth",  # Authentication
    12: "deauth",  # Deauthentication
    13: "action",  # Action
    14: "action_noack",  # Action No Ack
    15: "reserved",
}

# =============================================================================
# CONTROL FRAME SUBTYPES (type=1)
# =============================================================================
CONTROL_SUBTYPES = {
    0: "reserved",
    1: "reserved",
    2: "trigger",  # Trigger
    3: "tack",  # TACK
    4: "beamforming",  # Beamforming Report Poll
    5: "vht_ndp",  # VHT NDP Announcement
    6: "ctrl_ext",  # Control Frame Extension
    7: "ctrl_wrapper",  # Control Wrapper
    8: "block_ack_req",  # Block Ack Request
    9: "block_ack",  # Block Ack
    10: "ps_poll",  # PS-Poll
    11: "rts",  # Request To Send
    12: "cts",  # Clear To Send
    13: "ack",  # Acknowledgment
    14: "cf_end",  # CF-End
    15: "cf_end_ack",  # CF-End + CF-Ack
}

# =============================================================================
# DATA FRAME SUBTYPES (type=2)
# =============================================================================
DATA_SUBTYPES = {
    0: "data",  # Data
    1: "data_cf_ack",  # Data + CF-Ack
    2: "data_cf_poll",  # Data + CF-Poll
    3: "data_cf_ack_poll",  # Data + CF-Ack + CF-Poll
    4: "null",  # Null (no data)
    5: "cf_ack",  # CF-Ack (no data)
    6: "cf_poll",  # CF-Poll (no data)
    7: "cf_ack_poll",  # CF-Ack + CF-Poll (no data)
    8: "qos_data",  # QoS Data
    9: "qos_data_cf_ack",  # QoS Data + CF-Ack
    10: "qos_data_cf_poll",  # QoS Data + CF-Poll
    11: "qos_data_cf_ack_poll",  # QoS Data + CF-Ack + CF-Poll
    12: "qos_null",  # QoS Null (no data)
    13: "reserved",
    14: "qos_cf_poll",  # QoS CF-Poll (no data)
    15: "qos_cf_ack_poll",  # QoS CF-Ack + CF-Poll (no data)
}

# =============================================================================
# REASON CODES (for Deauth/Disassoc)
# =============================================================================
REASON_CODES = {
    0: "unspecified",
    1: "unspecified",
    2: "prev_auth_not_valid",
    3: "deauth_leaving",
    4: "disassoc_inactivity",
    5: "disassoc_ap_busy",
    6: "class2_frame_from_nonauth",
    7: "class3_frame_from_nonassoc",
    8: "disassoc_sta_leaving",
    9: "sta_req_assoc_not_auth",
    10: "disassoc_power_cap_bad",
    11: "disassoc_supp_chan_bad",
    12: "reserved",
    13: "invalid_ie",
    14: "mic_failure",
    15: "4way_handshake_timeout",
    16: "group_key_update_timeout",
    17: "ie_in_4way_differs",
    18: "group_cipher_not_valid",
    19: "pairwise_cipher_not_valid",
    20: "akmp_not_valid",
    21: "unsupported_rsn_ie_version",
    22: "invalid_rsn_ie_cap",
    23: "ieee_802_1x_auth_failed",
    24: "cipher_suite_rejected",
    # ... more codes exist
}

# =============================================================================
# SECURITY CAPABILITIES
# =============================================================================
CIPHER_SUITES = {
    0x00: "use_group",
    0x01: "wep40",
    0x02: "tkip",
    0x03: "reserved",
    0x04: "ccmp",  # AES-CCMP
    0x05: "wep104",
    0x06: "bip_cmac",  # BIP-CMAC-128
    0x08: "gcmp",  # GCMP-128
    0x09: "gcmp256",  # GCMP-256
    0x0A: "ccmp256",  # CCMP-256
}

AKM_SUITES = {
    0x01: "8021x",  # IEEE 802.1X/EAP
    0x02: "psk",  # Pre-Shared Key
    0x03: "ft_8021x",  # FT with 802.1X
    0x04: "ft_psk",  # FT with PSK
    0x05: "8021x_sha256",
    0x06: "psk_sha256",
    0x08: "sae",  # SAE (WPA3)
    0x09: "ft_sae",  # FT with SAE
    0x12: "owe",  # Opportunistic Wireless Encryption
}

# =============================================================================
# CHANNELS & FREQUENCIES
# =============================================================================

# 2.4 GHz channels (20 MHz)
CHANNELS_24GHZ = {
    1: 2412,
    2: 2417,
    3: 2422,
    4: 2427,
    5: 2432,
    6: 2437,
    7: 2442,
    8: 2447,
    9: 2452,
    10: 2457,
    11: 2462,
    12: 2467,
    13: 2472,
    14: 2484,  # Japan only
}

# 5 GHz UNII-1 channels
CHANNELS_5GHZ_UNII1 = {
    36: 5180,
    40: 5200,
    44: 5220,
    48: 5240,
}

# 5 GHz UNII-2A channels
CHANNELS_5GHZ_UNII2A = {
    52: 5260,
    56: 5280,
    60: 5300,
    64: 5320,
}

# 5 GHz UNII-2C channels
CHANNELS_5GHZ_UNII2C = {
    100: 5500,
    104: 5520,
    108: 5540,
    112: 5560,
    116: 5580,
    120: 5600,
    124: 5620,
    128: 5640,
    132: 5660,
    136: 5680,
    140: 5700,
    144: 5720,
}

# 5 GHz UNII-3 channels
CHANNELS_5GHZ_UNII3 = {
    149: 5745,
    153: 5765,
    157: 5785,
    161: 5805,
    165: 5825,
}

# All channels combined
ALL_CHANNELS = {
    **CHANNELS_24GHZ,
    **CHANNELS_5GHZ_UNII1,
    **CHANNELS_5GHZ_UNII2A,
    **CHANNELS_5GHZ_UNII2C,
    **CHANNELS_5GHZ_UNII3,
}


def channel_to_frequency(channel: int) -> int | None:
    """Convert channel number to frequency in MHz"""
    return ALL_CHANNELS.get(channel)


def frequency_to_channel(freq_mhz: int) -> int | None:
    """Convert frequency in MHz to channel number"""
    for ch, freq in ALL_CHANNELS.items():
        if freq == freq_mhz:
            return ch
    return None


def get_frame_type_name(type_code: int) -> str:
    """Get frame type name from code"""
    return FRAME_TYPES.get(type_code, "unknown")


def get_subtype_name(type_code: int, subtype_code: int) -> str:
    """Get frame subtype name from type and subtype codes"""
    if type_code == 0:
        return MANAGEMENT_SUBTYPES.get(subtype_code, "unknown")
    elif type_code == 1:
        return CONTROL_SUBTYPES.get(subtype_code, "unknown")
    elif type_code == 2:
        return DATA_SUBTYPES.get(subtype_code, "unknown")
    return "unknown"


def is_management_frame(type_code: int) -> bool:
    """Check if frame is management type"""
    return type_code == 0


def is_deauth_or_disassoc(type_code: int, subtype_code: int) -> bool:
    """Check if frame is deauthentication or disassociation"""
    return type_code == 0 and subtype_code in (10, 12)  # disassoc, deauth


def is_beacon_or_probe(type_code: int, subtype_code: int) -> bool:
    """Check if frame is beacon or probe response"""
    return type_code == 0 and subtype_code in (5, 8)  # probe_resp, beacon


def get_reason_description(reason_code: int) -> str:
    """Get human-readable reason code description"""
    return REASON_CODES.get(reason_code, f"unknown ({reason_code})")
