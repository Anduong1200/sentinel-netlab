"""
Sentinel NetLab - OUI Database
Centralized vendor lookup for MAC addresses.
"""

OUI_DATABASE = {
    "00:50:F2": "Microsoft",
    "00:0C:29": "VMware",
    "00:1A:2B": "Ayecom",
    "00:1B:21": "Intel",
    "00:1E:58": "D-Link",
    "00:1F:33": "Netgear",
    "00:21:5D": "Intel",
    "00:22:6B": "Cisco",
    "00:23:69": "Cisco",
    "00:24:D4": "FREEBOX",
    "00:25:9C": "Cisco",
    "00:26:5A": "D-Link",
    "00:E0:4C": "Realtek",
    "14:CF:E2": "Apple",
    "18:E8:29": "Apple",
    "1C:1B:0D": "Apple",
    "28:CF:E9": "Apple",
    "3C:15:C2": "Apple",
    "40:6C:8F": "Apple",
    "44:D8:84": "Apple",
    "48:45:20": "Intel",
    "5C:F9:38": "Apple",
    "60:03:08": "Apple",
    "64:A5:C3": "Apple",
    "68:A8:6D": "Apple",
    "70:73:CB": "Apple",
    "78:CA:39": "Apple",
    "7C:D1:C3": "Apple",
    "80:86:F2": "Intel",
    "84:38:35": "Apple",
    "88:E9:FE": "Apple",
    "8C:85:90": "Apple",
    "9C:04:EB": "Apple",
    "A4:5E:60": "Apple",
    "AC:22:0B": "ASUSTek",
    "AC:BC:32": "Apple",
    "B0:C0:90": "Chicony",
    "B8:27:EB": "Raspberry Pi",
    "BC:83:85": "Microsoft",
    "C8:6F:1D": "Apple",
    "D0:23:DB": "Apple",
    "DC:A9:04": "Apple",
    "E0:B9:A5": "Apple",
    "E4:C6:3D": "Apple",
    "F0:18:98": "Apple",
    "F4:5C:89": "Apple",
    "F8:1E:DF": "Apple",
    "FC:E9:98": "Apple",
}


def get_vendor(mac: str) -> str:
    """
    Look up vendor name from MAC address OUI.

    Args:
        mac: MAC address in format XX:XX:XX:XX:XX:XX

    Returns:
        Vendor name or "Unknown"
    """
    if not mac:
        return "Unknown"

    # Standardize separator
    mac = mac.upper().replace("-", ":").replace(".", ":")

    # Handle Cisco format XXXX.XXXX.XXXX -> XX:XX:XX...
    if ":" not in mac and len(mac) == 12:
        mac = ":".join(mac[i : i + 2] for i in range(0, 12, 2))

    try:
        oui = mac[:8]
        return OUI_DATABASE.get(oui, "Unknown")
    except IndexError:
        return "Unknown"
