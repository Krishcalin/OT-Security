"""
Unified OUI (Organizationally Unique Identifier) Database for OT Vendors.

Merged from PLC and RTU passive scanner OUI databases.  The OUI is the first
3 octets (24 bits) of a MAC address assigned by IEEE to the NIC manufacturer.

This database covers:
  - PLC manufacturers (Siemens, Rockwell, Schneider, ABB, Omron, Mitsubishi,
    Beckhoff, WAGO, Phoenix Contact)
  - Network infrastructure (Moxa, Hirschmann, Advantech, Belden)
  - RTU/IED vendors (SEL, GE Grid, Honeywell, Eaton, Noja, Landis+Gyr)
  - General OT (Red Lion, HMS/Anybus, Turck, Festo, Pepperl+Fuchs)

Format:
    "XX:XX:XX" -> {"vendor": str, "device_hint": Optional[str]}

    device_hint provides a higher-level classification when the OUI alone
    is enough to narrow the device family (e.g. "IED", "FRTU", "Gateway").
    It is None when the vendor makes broad product lines and the OUI is
    insufficient to distinguish.
"""
from typing import Dict, Optional


OUI_DATABASE: Dict[str, Dict] = {

    # ===================================================================
    # Siemens AG
    # PLCs: S7-300/400/1200/1500   RTUs: SICAM A8000, SICAM RTU
    # IEDs: SIPROTEC 4/5           Switches: RUGGEDCOM (see separate)
    # ===================================================================
    "00:1B:1B": {"vendor": "Siemens AG",               "device_hint": None},
    "00:E0:4F": {"vendor": "Siemens AG",               "device_hint": None},
    "00:0E:8C": {"vendor": "Siemens AG",               "device_hint": None},
    "00:1C:06": {"vendor": "Siemens AG",               "device_hint": None},
    "28:63:36": {"vendor": "Siemens AG",               "device_hint": None},
    "40:A8:F0": {"vendor": "Siemens AG",               "device_hint": None},
    "54:A0:50": {"vendor": "Siemens AG",               "device_hint": None},
    "58:FD:B1": {"vendor": "Siemens AG",               "device_hint": None},
    "88:75:56": {"vendor": "Siemens AG",               "device_hint": None},
    "98:6C:CC": {"vendor": "Siemens AG",               "device_hint": None},
    "A0:47:D7": {"vendor": "Siemens AG",               "device_hint": None},
    "AC:64:17": {"vendor": "Siemens AG",               "device_hint": None},
    "B8:75:D4": {"vendor": "Siemens AG",               "device_hint": None},
    "C0:A8:04": {"vendor": "Siemens AG",               "device_hint": None},
    "D4:F5:27": {"vendor": "Siemens AG",               "device_hint": None},
    "0C:D2:92": {"vendor": "Siemens AG",               "device_hint": None},
    "3C:97:0E": {"vendor": "Siemens AG",               "device_hint": None},
    "20:87:56": {"vendor": "Siemens AG",               "device_hint": None},
    "E8:6D:52": {"vendor": "Siemens AG",               "device_hint": None},
    "B4:A2:0E": {"vendor": "Siemens AG",               "device_hint": None},

    # ===================================================================
    # RuggedCom (Siemens subsidiary) -- substation-hardened switches
    # ===================================================================
    "00:A0:F8": {"vendor": "RuggedCom (Siemens)",      "device_hint": "Gateway"},
    "00:1D:49": {"vendor": "RuggedCom (Siemens)",      "device_hint": "Gateway"},

    # ===================================================================
    # Rockwell Automation / Allen-Bradley
    # PLCs: ControlLogix, CompactLogix, MicroLogix, PLC-5
    # ===================================================================
    "00:00:BC": {"vendor": "Allen-Bradley (Rockwell)",  "device_hint": None},
    "00:50:DA": {"vendor": "Allen-Bradley (Rockwell)",  "device_hint": None},
    "00:0E:D7": {"vendor": "Rockwell Automation",       "device_hint": None},
    "00:1D:9C": {"vendor": "Rockwell Automation",       "device_hint": None},
    "00:1F:8D": {"vendor": "Rockwell Automation",       "device_hint": None},
    "00:23:AE": {"vendor": "Rockwell Automation",       "device_hint": None},
    "34:B1:2A": {"vendor": "Rockwell Automation",       "device_hint": None},
    "4C:B1:99": {"vendor": "Rockwell Automation",       "device_hint": None},
    "74:B5:7E": {"vendor": "Rockwell Automation",       "device_hint": None},
    "78:AC:44": {"vendor": "Rockwell Automation",       "device_hint": None},
    "A4:B8:05": {"vendor": "Rockwell Automation",       "device_hint": None},
    "B0:26:28": {"vendor": "Rockwell Automation",       "device_hint": None},
    "FC:73:E3": {"vendor": "Rockwell Automation",       "device_hint": None},
    "00:60:9C": {"vendor": "Rockwell Automation",       "device_hint": None},
    "88:A4:79": {"vendor": "Rockwell Automation",       "device_hint": None},

    # ===================================================================
    # Schneider Electric
    # PLCs: Modicon M340/M580   RTUs: SCADAPack, Easergy T300
    # IEDs: MiCOM P series      Gateways: EcoStruxure
    # ===================================================================
    "00:01:29": {"vendor": "Schneider Electric",              "device_hint": None},
    "00:0E:FC": {"vendor": "Schneider Electric",              "device_hint": None},
    "00:80:F4": {"vendor": "Schneider Electric",              "device_hint": None},
    "00:A0:2D": {"vendor": "Schneider Electric",              "device_hint": None},
    "00:A0:CE": {"vendor": "Schneider Electric (Modicon)",    "device_hint": None},
    "08:00:F4": {"vendor": "Schneider Electric",              "device_hint": None},
    "20:18:CA": {"vendor": "Schneider Electric",              "device_hint": None},
    "58:91:CF": {"vendor": "Schneider Electric",              "device_hint": None},
    "78:9F:87": {"vendor": "Schneider Electric",              "device_hint": None},
    "C4:ED:BA": {"vendor": "Schneider Electric",              "device_hint": None},
    "D0:81:7A": {"vendor": "Schneider Electric",              "device_hint": None},
    "F8:78:16": {"vendor": "Schneider Electric",              "device_hint": None},
    "00:A0:9D": {"vendor": "Schneider Electric (Modicon M340)", "device_hint": None},

    # ===================================================================
    # Mitsubishi Electric
    # PLCs: MELSEC iQ-R, iQ-F, Q, FX series
    # ===================================================================
    "00:50:F9": {"vendor": "Mitsubishi Electric",      "device_hint": None},
    "08:E8:4A": {"vendor": "Mitsubishi Electric",      "device_hint": None},
    "70:4A:0E": {"vendor": "Mitsubishi Electric",      "device_hint": None},
    "A4:BA:DB": {"vendor": "Mitsubishi Electric",      "device_hint": None},
    "00:D0:8E": {"vendor": "Mitsubishi Electric",      "device_hint": None},
    "14:2D:27": {"vendor": "Mitsubishi Electric",      "device_hint": None},
    "B0:7D:64": {"vendor": "Mitsubishi Electric",      "device_hint": None},
    "30:F3:35": {"vendor": "Mitsubishi Electric",      "device_hint": None},

    # ===================================================================
    # Omron Corporation
    # PLCs: NJ/NX, CJ, CP, CS series
    # ===================================================================
    "00:00:57": {"vendor": "Omron Corporation",         "device_hint": None},
    "00:02:1B": {"vendor": "Omron Corporation",         "device_hint": None},
    "00:0A:79": {"vendor": "Omron Corporation",         "device_hint": None},
    "00:20:0A": {"vendor": "Omron Corporation",         "device_hint": None},
    "AC:E4:28": {"vendor": "Omron Corporation",         "device_hint": None},
    "00:8C:2D": {"vendor": "Omron Corporation",         "device_hint": None},
    "14:58:D0": {"vendor": "Omron Corporation",         "device_hint": None},
    "84:EB:18": {"vendor": "Omron Corporation",         "device_hint": None},

    # ===================================================================
    # ABB Group
    # PLCs: AC500   RTUs: RTU560, RTU560M, SRIO
    # IEDs: REF/REC/REL/RED/RET series   DCS: SPACOM, MicroSCADA
    # ===================================================================
    "00:04:15": {"vendor": "ABB Group",                 "device_hint": None},
    "00:1A:89": {"vendor": "ABB Group",                 "device_hint": None},
    "00:E0:7D": {"vendor": "ABB Group",                 "device_hint": None},
    "A4:AD:B8": {"vendor": "ABB Group",                 "device_hint": None},
    "B8:08:D7": {"vendor": "ABB Group",                 "device_hint": None},
    "18:F4:6A": {"vendor": "ABB Group",                 "device_hint": None},
    "50:02:ED": {"vendor": "ABB Group",                 "device_hint": None},
    "00:30:11": {"vendor": "ABB Group",                 "device_hint": None},
    "58:B6:23": {"vendor": "ABB Group",                 "device_hint": None},
    "00:A0:29": {"vendor": "ABB Group",                 "device_hint": None},
    "34:26:B9": {"vendor": "ABB Group",                 "device_hint": None},

    # ===================================================================
    # GE Grid Solutions / GE Automation / GE Intelligent Platforms
    # RTUs: D20MX, D400   IEDs: UR series, MultiLink EL, N60, T60, L90
    # PLCs: PACSystems RX3i
    # ===================================================================
    "00:01:3C": {"vendor": "GE Grid Solutions",         "device_hint": None},
    "00:50:C2": {"vendor": "GE Grid Solutions",         "device_hint": None},
    "00:14:7F": {"vendor": "GE Grid Solutions",         "device_hint": None},
    "08:00:31": {"vendor": "GE Automation",             "device_hint": None},
    "00:60:4F": {"vendor": "GE Intelligent Platforms",  "device_hint": None},
    "00:60:65": {"vendor": "GE Fanuc Automation",       "device_hint": None},
    "00:80:3D": {"vendor": "GE Grid Solutions",         "device_hint": None},
    "A4:34:D9": {"vendor": "GE Grid Solutions",         "device_hint": None},

    # ===================================================================
    # Honeywell
    # PLCs: C200/C300   RTUs: RTU2020, ControlEdge RTU   DCS: Experion PKS
    # ===================================================================
    "00:00:30": {"vendor": "Honeywell",                 "device_hint": None},
    "00:A0:65": {"vendor": "Honeywell",                 "device_hint": None},
    "00:23:64": {"vendor": "Honeywell",                 "device_hint": None},
    "60:1D:3D": {"vendor": "Honeywell",                 "device_hint": None},
    "40:84:93": {"vendor": "Honeywell",                 "device_hint": None},
    "94:F8:27": {"vendor": "Honeywell Process Solutions", "device_hint": None},

    # ===================================================================
    # Yokogawa Electric
    # PLCs: FA-M3   RTUs: StarDom   DCS: CENTUM VP
    # ===================================================================
    "00:02:A5": {"vendor": "Yokogawa Electric",         "device_hint": None},
    "00:07:9E": {"vendor": "Yokogawa Electric",         "device_hint": None},
    "00:09:93": {"vendor": "Yokogawa Electric",         "device_hint": None},
    "B8:D7:AF": {"vendor": "Yokogawa Electric",         "device_hint": None},

    # ===================================================================
    # Emerson Electric (DeltaV, Fisher, Rosemount, ROC, Bristol, ControlWave)
    # ===================================================================
    "00:01:3B": {"vendor": "Emerson Electric",          "device_hint": None},
    "5C:26:0A": {"vendor": "Emerson Electric",          "device_hint": None},
    "00:90:0B": {"vendor": "Emerson Electric",          "device_hint": None},
    "00:D0:9E": {"vendor": "Emerson Network Power",    "device_hint": None},
    "38:5B:44": {"vendor": "Emerson Electric",          "device_hint": None},

    # ===================================================================
    # SEL (Schweitzer Engineering Laboratories)
    # IEDs: SEL-421, SEL-651R, SEL-311C, SEL-3505, SEL-3530, SEL-3555
    # ===================================================================
    "00:30:A7": {"vendor": "SEL (Schweitzer Engineering Labs)", "device_hint": "IED"},

    # ===================================================================
    # Cooper Industries / Eaton -- recloser controllers, automated switching
    # ===================================================================
    "00:50:1D": {"vendor": "Cooper Industries (Eaton)", "device_hint": "FRTU"},
    "00:15:8B": {"vendor": "Eaton",                     "device_hint": "FRTU"},
    "48:0F:CF": {"vendor": "Eaton",                     "device_hint": "FRTU"},

    # ===================================================================
    # Noja Power -- OSM recloser, RC10/15 controllers
    # ===================================================================
    "00:23:17": {"vendor": "Noja Power",                "device_hint": "FRTU"},
    "DC:A9:04": {"vendor": "Noja Power",                "device_hint": "FRTU"},

    # ===================================================================
    # Landis+Gyr -- E350/E360 smart meters, FRTUs
    # ===================================================================
    "00:17:5F": {"vendor": "Landis+Gyr",                "device_hint": "FRTU"},
    "00:80:CE": {"vendor": "Landis+Gyr",                "device_hint": "FRTU"},
    "48:49:C7": {"vendor": "Landis+Gyr",                "device_hint": "FRTU"},
    "70:B3:D5": {"vendor": "Landis+Gyr",                "device_hint": "FRTU"},

    # ===================================================================
    # Itron -- OpenWay Riva, FRTUs, smart meters
    # ===================================================================
    "00:0A:3D": {"vendor": "Itron",                     "device_hint": "FRTU"},
    "00:12:A2": {"vendor": "Itron",                     "device_hint": "FRTU"},

    # ===================================================================
    # Alstom Grid (now GE Grid) -- MiCOM, P series IEDs
    # ===================================================================
    "00:0D:BC": {"vendor": "Alstom Grid",               "device_hint": "IED"},
    "00:30:05": {"vendor": "Alstom Grid",               "device_hint": "IED"},

    # ===================================================================
    # Sifang (SIFCO) -- Chinese RTU/IED vendor
    # ===================================================================
    "00:E0:E4": {"vendor": "Sifang (SIFCO)",            "device_hint": "RTU"},

    # ===================================================================
    # Phoenix Contact -- PLCnext, Inline I/O, managed switches
    # ===================================================================
    "00:A0:45": {"vendor": "Phoenix Contact",           "device_hint": None},
    "44:C4:C6": {"vendor": "Phoenix Contact",           "device_hint": None},
    "00:60:34": {"vendor": "Phoenix Contact",           "device_hint": None},
    "A8:74:1D": {"vendor": "Phoenix Contact",           "device_hint": None},
    "14:D4:AC": {"vendor": "Phoenix Contact",           "device_hint": None},

    # ===================================================================
    # WAGO Corporation -- 750 series controllers, PFC100/200
    # ===================================================================
    "00:30:DE": {"vendor": "WAGO Corporation",          "device_hint": None},
    "00:10:8A": {"vendor": "WAGO Kontakttechnik",       "device_hint": None},

    # ===================================================================
    # Beckhoff Automation -- TwinCAT-based PLCs and RTUs
    # ===================================================================
    "00:01:05": {"vendor": "Beckhoff Automation",       "device_hint": None},
    "4C:05:DC": {"vendor": "Beckhoff Automation",       "device_hint": None},

    # ===================================================================
    # Moxa Technologies -- industrial serial servers, managed switches
    # ===================================================================
    "00:90:E8": {"vendor": "Moxa Technologies",         "device_hint": "Gateway"},
    "44:39:C4": {"vendor": "Moxa Technologies",         "device_hint": "Gateway"},
    "00:00:03": {"vendor": "Moxa Technologies",         "device_hint": "Gateway"},

    # ===================================================================
    # Hirschmann / Belden -- substation-hardened managed switches
    # ===================================================================
    "00:08:DC": {"vendor": "Hirschmann Automation (Belden)", "device_hint": "Gateway"},
    "BC:F1:F2": {"vendor": "Hirschmann Automation (Belden)", "device_hint": "Gateway"},
    "00:80:63": {"vendor": "Hirschmann Automation (Belden)", "device_hint": "Gateway"},

    # ===================================================================
    # Advantech -- industrial computing, RTU platforms
    # ===================================================================
    "00:D0:C9": {"vendor": "Advantech Co.",              "device_hint": None},
    "00:40:D0": {"vendor": "Advantech Co.",              "device_hint": None},

    # ===================================================================
    # Red Lion Controls -- RTU/HMI for oil & gas, water/wastewater
    # ===================================================================
    "00:10:81": {"vendor": "Red Lion Controls",          "device_hint": None},

    # ===================================================================
    # ProSoft Technology -- protocol gateways for PLCs/RTUs
    # ===================================================================
    "00:0E:8F": {"vendor": "ProSoft Technology",         "device_hint": "Gateway"},

    # ===================================================================
    # HMS Industrial Networks (Anybus) -- protocol converters
    # ===================================================================
    "00:60:7E": {"vendor": "HMS Industrial Networks",    "device_hint": "Gateway"},

    # ===================================================================
    # Turck -- industrial I/O, RFID, fieldbus
    # ===================================================================
    "00:07:86": {"vendor": "Turck",                      "device_hint": None},
    "04:8A:15": {"vendor": "Turck",                      "device_hint": None},

    # ===================================================================
    # Pepperl+Fuchs -- sensors, intrinsic safety barriers
    # ===================================================================
    "00:30:70": {"vendor": "Pepperl+Fuchs",              "device_hint": None},

    # ===================================================================
    # Festo AG -- pneumatic / process automation
    # ===================================================================
    "00:0E:F0": {"vendor": "Festo AG",                   "device_hint": None},

    # ===================================================================
    # Danfoss A/S -- drives, valves, compressors
    # ===================================================================
    "00:60:AA": {"vendor": "Danfoss A/S",                "device_hint": None},

    # ===================================================================
    # Pilz GmbH -- safety PLCs, safety controllers
    # ===================================================================
    "00:1C:44": {"vendor": "Pilz GmbH",                  "device_hint": None},

    # ===================================================================
    # Keyence Corporation -- vision systems, laser sensors, PLCs
    # ===================================================================
    "00:08:AA": {"vendor": "Keyence Corporation",        "device_hint": None},

    # ===================================================================
    # Panasonic Electric Works / SUNX
    # ===================================================================
    "00:80:45": {"vendor": "Panasonic Electric Works",   "device_hint": None},
    "00:50:B7": {"vendor": "Panasonic Electric Works",   "device_hint": None},
}


def lookup_oui(mac: str) -> Optional[Dict]:
    """
    Look up vendor information by MAC address OUI prefix.

    Args:
        mac: MAC address in any common format (colon, dash, dot, or no
             separator).  Case-insensitive.

    Returns:
        Dict with ``{"vendor": str, "device_hint": Optional[str]}`` on
        match, or ``None`` if the OUI is not in the database.
    """
    if not mac:
        return None

    # Normalise to "XX:XX:XX" uppercase, 3-octet prefix
    cleaned = mac.upper().replace("-", ":").replace(".", ":")
    parts = cleaned.split(":")

    if len(parts) >= 3:
        oui = ":".join(parts[:3])
    else:
        # Try treating as raw hex string (e.g. "001B1B...")
        raw = cleaned.replace(":", "")
        if len(raw) < 6:
            return None
        oui = f"{raw[0:2]}:{raw[2:4]}:{raw[4:6]}"

    return OUI_DATABASE.get(oui)
