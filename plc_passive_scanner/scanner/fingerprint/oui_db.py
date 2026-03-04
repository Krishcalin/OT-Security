"""
OUI (Organizationally Unique Identifier) Database for ICS/OT Vendors.

OUI is the first 3 octets (24 bits) of a MAC address, assigned by the IEEE
to identify the network interface manufacturer.

This database is focused on industrial automation vendors that manufacture
PLCs, RTUs, HMIs, and related OT equipment.

Format: "XX:XX:XX" (uppercase, colon-delimited) -> "Vendor Name"
"""

OUI_DATABASE: dict = {

    # ── Siemens ────────────────────────────────────────────────────────────
    "00:1B:1B": "Siemens AG",
    "00:E0:4F": "Siemens AG",
    "00:0E:8C": "Siemens AG",
    "00:1C:06": "Siemens AG",
    "28:63:36": "Siemens AG",
    "40:A8:F0": "Siemens AG",
    "54:A0:50": "Siemens AG",
    "58:FD:B1": "Siemens AG",
    "88:75:56": "Siemens AG",
    "98:6C:CC": "Siemens AG",
    "A0:47:D7": "Siemens AG",
    "AC:64:17": "Siemens AG",
    "B8:75:D4": "Siemens AG",
    "C0:A8:04": "Siemens AG",
    "D4:F5:27": "Siemens AG",
    "0C:D2:92": "Siemens AG",
    "3C:97:0E": "Siemens AG",
    "20:87:56": "Siemens AG",
    "E8:6D:52": "Siemens AG",
    "B4:A2:0E": "Siemens AG",

    # ── Rockwell Automation / Allen-Bradley ────────────────────────────────
    "00:00:BC": "Allen-Bradley (Rockwell)",
    "00:50:DA": "Allen-Bradley (Rockwell)",
    "00:0E:D7": "Rockwell Automation",
    "00:1D:9C": "Rockwell Automation",
    "00:1F:8D": "Rockwell Automation",
    "00:23:AE": "Rockwell Automation",
    "34:B1:2A": "Rockwell Automation",
    "4C:B1:99": "Rockwell Automation",
    "74:B5:7E": "Rockwell Automation",
    "78:AC:44": "Rockwell Automation",
    "A4:B8:05": "Rockwell Automation",
    "B0:26:28": "Rockwell Automation",
    "FC:73:E3": "Rockwell Automation",
    "00:60:9C": "Rockwell Automation",
    "88:A4:79": "Rockwell Automation",

    # ── Schneider Electric ─────────────────────────────────────────────────
    "00:01:29": "Schneider Electric",
    "00:0E:FC": "Schneider Electric",
    "00:80:F4": "Schneider Electric",
    "00:A0:2D": "Schneider Electric",
    "00:A0:CE": "Schneider Electric (Modicon)",
    "08:00:F4": "Schneider Electric",
    "20:18:CA": "Schneider Electric",
    "58:91:CF": "Schneider Electric",
    "78:9F:87": "Schneider Electric",
    "C4:ED:BA": "Schneider Electric",
    "D0:81:7A": "Schneider Electric",
    "F8:78:16": "Schneider Electric",
    "00:A0:9D": "Schneider Electric (Modicon M340)",

    # ── Mitsubishi Electric ────────────────────────────────────────────────
    "00:50:F9": "Mitsubishi Electric",
    "08:E8:4A": "Mitsubishi Electric",
    "70:4A:0E": "Mitsubishi Electric",
    "A4:BA:DB": "Mitsubishi Electric",
    "00:D0:8E": "Mitsubishi Electric",
    "14:2D:27": "Mitsubishi Electric",
    "B0:7D:64": "Mitsubishi Electric",
    "30:F3:35": "Mitsubishi Electric",

    # ── Omron ──────────────────────────────────────────────────────────────
    "00:00:57": "Omron Corporation",
    "00:02:1B": "Omron Corporation",
    "00:0A:79": "Omron Corporation",
    "00:20:0A": "Omron Corporation",
    "AC:E4:28": "Omron Corporation",
    "00:8C:2D": "Omron Corporation",
    "14:58:D0": "Omron Corporation",
    "84:EB:18": "Omron Corporation",

    # ── ABB ────────────────────────────────────────────────────────────────
    "00:04:15": "ABB Group",
    "00:1A:89": "ABB Group",
    "00:E0:7D": "ABB Group",
    "A4:AD:B8": "ABB Group",
    "B8:08:D7": "ABB Group",
    "18:F4:6A": "ABB Group",
    "50:02:ED": "ABB Group",
    "00:30:11": "ABB Group",

    # ── Honeywell ──────────────────────────────────────────────────────────
    "00:00:30": "Honeywell",
    "00:A0:65": "Honeywell",
    "00:23:64": "Honeywell",
    "60:1D:3D": "Honeywell",
    "40:84:93": "Honeywell",
    "94:F8:27": "Honeywell Process Solutions",

    # ── GE Automation (GE Vernova / GE Grid Solutions) ─────────────────────
    "00:01:3C": "GE Automation",
    "00:50:C2": "GE Automation",
    "00:14:7F": "GE Automation",
    "08:00:31": "GE Automation",
    "00:60:4F": "GE Intelligent Platforms",

    # ── Yokogawa Electric ──────────────────────────────────────────────────
    "00:02:A5": "Yokogawa Electric",
    "00:07:9E": "Yokogawa Electric",
    "00:09:93": "Yokogawa Electric",
    "B8:D7:AF": "Yokogawa Electric",

    # ── Emerson Electric (DeltaV, Fisher, Rosemount) ───────────────────────
    "00:01:3B": "Emerson Electric",
    "5C:26:0A": "Emerson Electric",
    "00:90:0B": "Emerson Electric",
    "00:D0:9E": "Emerson Network Power",

    # ── Phoenix Contact ────────────────────────────────────────────────────
    "00:A0:45": "Phoenix Contact",
    "44:C4:C6": "Phoenix Contact",
    "00:60:34": "Phoenix Contact",
    "A8:74:1D": "Phoenix Contact",
    "14:D4:AC": "Phoenix Contact",

    # ── WAGO ───────────────────────────────────────────────────────────────
    "00:30:DE": "WAGO Corporation",
    "00:10:8A": "WAGO Kontakttechnik",

    # ── Beckhoff Automation ────────────────────────────────────────────────
    "00:01:05": "Beckhoff Automation",
    "4C:05:DC": "Beckhoff Automation",

    # ── Moxa Technologies (common ICS comms hardware) ─────────────────────
    "00:90:E8": "Moxa Technologies",
    "44:39:C4": "Moxa Technologies",
    "00:00:03": "Moxa Technologies",

    # ── Hirschmann / Belden ────────────────────────────────────────────────
    "00:08:DC": "Hirschmann Automation (Belden)",
    "BC:F1:F2": "Hirschmann Automation (Belden)",
    "00:80:63": "Hirschmann Automation (Belden)",

    # ── Advantech ─────────────────────────────────────────────────────────
    "00:D0:C9": "Advantech Co.",
    "00:40:D0": "Advantech Co.",

    # ── SEL (Schweitzer Engineering Laboratories) ─────────────────────────
    "00:30:A7": "SEL (Schweitzer Engineering)",

    # ── Red Lion Controls ─────────────────────────────────────────────────
    "00:10:81": "Red Lion Controls",

    # ── Prosoft Technology ────────────────────────────────────────────────
    "00:0E:8F": "ProSoft Technology",

    # ── HMS Industrial Networks (Anybus) ──────────────────────────────────
    "00:30:11": "HMS Industrial Networks",
    "00:60:7E": "HMS Industrial Networks",

    # ── Turck ─────────────────────────────────────────────────────────────
    "00:07:86": "Turck",
    "04:8A:15": "Turck",

    # ── Pepperl+Fuchs ─────────────────────────────────────────────────────
    "00:30:70": "Pepperl+Fuchs",

    # ── Festo ─────────────────────────────────────────────────────────────
    "00:0E:F0": "Festo AG",

    # ── Danfoss ───────────────────────────────────────────────────────────
    "00:60:AA": "Danfoss A/S",

    # ── Pilz ──────────────────────────────────────────────────────────────
    "00:1C:44": "Pilz GmbH",

    # ── Keyence ───────────────────────────────────────────────────────────
    "00:08:AA": "Keyence Corporation",

    # ── Panasonic / SUNX ──────────────────────────────────────────────────
    "00:80:45": "Panasonic Electric Works",
    "00:50:B7": "Panasonic Electric Works",
}


def lookup_oui(mac: str):
    """
    Look up a vendor name by MAC address OUI.

    Args:
        mac: MAC address in any common format (colon, dash, or no separator).
             Case-insensitive.
    Returns:
        Vendor name string (str), or None if not found.
    """
    if not mac:
        return None

    # Normalise to "XX:XX:XX" uppercase, 3-octet prefix
    cleaned = mac.upper().replace("-", ":").replace(".", ":")
    parts = cleaned.split(":")
    if len(parts) < 3:
        # Try treating as raw hex string (e.g. "001B1B...")
        raw = cleaned.replace(":", "")
        if len(raw) >= 6:
            oui = f"{raw[0:2]}:{raw[2:4]}:{raw[4:6]}"
        else:
            return None
    else:
        oui = ":".join(parts[:3])

    return OUI_DATABASE.get(oui)
