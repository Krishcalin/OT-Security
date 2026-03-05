"""
OUI Database for RTU / FRTU / IED Vendors.

Focused on field devices used in:
  Electric power transmission and distribution substations
  Oil & gas pipeline and wellhead control
  Water/wastewater SCADA
  Railway signalling and traction

Format: "XX:XX:XX" (uppercase colon-delimited) → "Vendor Name"
"""

OUI_DATABASE: dict = {

    # ── ABB ────────────────────────────────────────────────────────────────
    # RTU560, RTU560M, REF/REC/REL IED series, SRIO, SPACOM, MicroSCADA
    "00:04:15": "ABB Group",
    "00:1A:89": "ABB Group",
    "00:E0:7D": "ABB Group",
    "00:30:11": "ABB Group",
    "A4:AD:B8": "ABB Group",
    "B8:08:D7": "ABB Group",
    "18:F4:6A": "ABB Group",
    "50:02:ED": "ABB Group",
    "58:B6:23": "ABB Group",
    "00:A0:29": "ABB Group",
    "34:26:B9": "ABB Group",

    # ── GE Grid Solutions (Alstom, Multilin, GE Vernova) ──────────────────
    # D20MX, D400, UR series, MultiLink EL, N60, T60, L90
    "00:01:3C": "GE Grid Solutions",
    "00:60:4F": "GE Intelligent Platforms",
    "00:50:C2": "GE Grid Solutions",
    "00:14:7F": "GE Grid Solutions",
    "00:60:65": "GE Fanuc Automation",
    "00:80:3D": "GE Grid Solutions",
    "A4:34:D9": "GE Grid Solutions",

    # ── Siemens (SICAM RTU, SIPROTEC, RUGGEDCOM) ──────────────────────────
    # SICAM A8000, SICAM RTU, SIPROTEC 4/5, RUGGEDCOM RX1500
    "00:1B:1B": "Siemens AG",
    "00:E0:4F": "Siemens AG",
    "28:63:36": "Siemens AG",
    "00:1C:06": "Siemens AG",
    "88:75:56": "Siemens AG",
    "0C:D2:92": "Siemens AG",
    "AC:64:17": "Siemens AG",
    "54:A0:50": "Siemens AG",
    "B8:75:D4": "Siemens AG",
    "98:6C:CC": "Siemens AG",
    "40:A8:F0": "Siemens AG",
    "A0:47:D7": "Siemens AG",
    "3C:97:0E": "Siemens AG",
    "E8:6D:52": "Siemens AG",
    "00:0E:8C": "Siemens AG",

    # ── Schneider Electric (SCADAPack, EcoStruxure, MiCOM, Easergy) ───────
    # SCADAPack 300E/350/357/570, T200, Easergy T300, MiCOM P series
    "00:01:29": "Schneider Electric",
    "00:0E:FC": "Schneider Electric",
    "00:80:F4": "Schneider Electric",
    "00:A0:2D": "Schneider Electric",
    "00:A0:CE": "Schneider Electric",
    "08:00:F4": "Schneider Electric",
    "20:18:CA": "Schneider Electric",
    "58:91:CF": "Schneider Electric",
    "78:9F:87": "Schneider Electric",
    "C4:ED:BA": "Schneider Electric",
    "D0:81:7A": "Schneider Electric",
    "F8:78:16": "Schneider Electric",

    # ── SEL (Schweitzer Engineering Laboratories) ─────────────────────────
    # SEL-3505, SEL-3530, SEL-3555, SEL-651R, SEL-421, SEL-311C
    "00:30:A7": "SEL (Schweitzer Engineering Labs)",

    # ── Emerson (ROC, Bristol, ControlWave, DeltaV) ───────────────────────
    # ROC809, ROC800L, ControlWave Micro, Bristol 3330
    "00:01:3B": "Emerson Electric",
    "5C:26:0A": "Emerson Electric",
    "00:90:0B": "Emerson Electric",
    "00:D0:9E": "Emerson Electric",
    "38:5B:44": "Emerson Electric",

    # ── Honeywell (RTU2020, ControlEdge RTU, HC900) ───────────────────────
    "00:00:30": "Honeywell",
    "00:A0:65": "Honeywell",
    "00:23:64": "Honeywell",
    "60:1D:3D": "Honeywell",
    "40:84:93": "Honeywell",
    "94:F8:27": "Honeywell Process Solutions",

    # ── Cooper Industries / Eaton (Form6, Kyle, McGraw-Edison) ────────────
    # Recloser controllers, automated switching equipment
    "00:50:1D": "Cooper Industries (Eaton)",
    "00:15:8B": "Eaton",
    "48:0F:CF": "Eaton",

    # ── Noja Power (OSM recloser, RC10/15 controllers) ────────────────────
    "00:23:17": "Noja Power",
    "DC:A9:04": "Noja Power",

    # ── Landis+Gyr (E350, E360 smart meters / FRTUs) ──────────────────────
    "00:17:5F": "Landis+Gyr",
    "00:80:CE": "Landis+Gyr",
    "48:49:C7": "Landis+Gyr",
    "70:B3:D5": "Landis+Gyr",

    # ── Itron (OpenWay Riva, FRTUs, smart meters) ──────────────────────────
    "00:0A:3D": "Itron",
    "00:12:A2": "Itron",
    "00:17:5F": "Itron",

    # ── Yokogawa (StarDom RTU, FA-M3) ─────────────────────────────────────
    "00:02:A5": "Yokogawa Electric",
    "00:07:9E": "Yokogawa Electric",
    "00:09:93": "Yokogawa Electric",
    "B8:D7:AF": "Yokogawa Electric",

    # ── Alstom / GE Grid (MiCOM, P series IEDs) ──────────────────────────
    "00:0D:BC": "Alstom Grid",
    "00:30:05": "Alstom Grid",

    # ── SIFCO / Sifang (Chinese RTU/IED vendor) ───────────────────────────
    "00:E0:E4": "Sifang (SIFCO)",

    # ── Beckhoff (TwinCAT-based RTU/IED solutions) ────────────────────────
    "00:01:05": "Beckhoff Automation",
    "4C:05:DC": "Beckhoff Automation",

    # ── Moxa (Industrial networking, RTU comms equipment) ────────────────
    "00:90:E8": "Moxa Technologies",
    "44:39:C4": "Moxa Technologies",

    # ── Hirschmann / Belden (Substation-hardened switches) ────────────────
    "00:08:DC": "Hirschmann Automation (Belden)",
    "BC:F1:F2": "Hirschmann Automation (Belden)",
    "00:80:63": "Hirschmann Automation (Belden)",

    # ── Ruggedcom (Siemens) ────────────────────────────────────────────────
    "00:A0:F8": "RuggedCom (Siemens)",
    "00:1D:49": "RuggedCom (Siemens)",

    # ── Phoenix Contact ────────────────────────────────────────────────────
    "00:A0:45": "Phoenix Contact",
    "44:C4:C6": "Phoenix Contact",
    "00:60:34": "Phoenix Contact",

    # ── Red Lion Controls (RTU/HMI for oil & gas / water) ────────────────
    "00:10:81": "Red Lion Controls",

    # ── ProSoft Technology (protocol gateways for RTUs) ──────────────────
    "00:0E:8F": "ProSoft Technology",

    # ── Advantech (industrial computing / RTU platforms) ─────────────────
    "00:D0:C9": "Advantech Co.",
    "00:40:D0": "Advantech Co.",

    # ── Rockwell / Allen-Bradley (MicroLogix, some RTUs) ─────────────────
    "00:00:BC": "Allen-Bradley (Rockwell)",
    "00:0E:D7": "Rockwell Automation",
    "00:1D:9C": "Rockwell Automation",
    "34:B1:2A": "Rockwell Automation",
    "74:B5:7E": "Rockwell Automation",
    "FC:73:E3": "Rockwell Automation",
}


def lookup_oui(mac: str):
    """
    Return vendor name (str) or None given any MAC address format.
    Handles colon, dash, or no separator; case-insensitive.
    """
    if not mac:
        return None
    cleaned = mac.upper().replace("-", ":").replace(".", ":")
    parts   = cleaned.split(":")
    if len(parts) >= 3:
        oui = ":".join(parts[:3])
    else:
        raw = cleaned.replace(":", "")
        if len(raw) < 6:
            return None
        oui = f"{raw[0:2]}:{raw[2:4]}:{raw[4:6]}"
    return OUI_DATABASE.get(oui)
