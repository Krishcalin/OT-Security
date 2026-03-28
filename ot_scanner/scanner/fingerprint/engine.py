"""
Unified OT Vendor Fingerprinting Engine.

Merges PLC and RTU fingerprinting strategies into a single engine that
operates on the unified OTDevice model.

Evidence sources (priority order):
  1. Exclusive protocols  (S7comm -> Siemens, FINS -> Omron, MELSEC -> Mitsubishi,
                           SEL Fast Message -> SEL)
  2. CIP vendor ID mapping (from EtherNet/IP ListIdentity)
  3. Modbus MEI device identification strings
  4. DNP3 Group 0 device attribute strings
  5. IEC 61850 GOOSE gcbRef prefix (IED name encodes vendor)
  6. Vendor substring matching on protocol detail strings
  7. MAC OUI database lookup (lowest priority)

Each step enriches vendor, make, model, firmware, serial_number,
device_type, role, and vendor_confidence on the OTDevice in-place.
"""
from typing import Dict, Optional

from .oui_db import lookup_oui
from ..models import OTDevice


# ======================================================================
# 1. Protocols that unambiguously identify a single vendor
# ======================================================================

EXCLUSIVE_PROTOCOLS: Dict[str, Dict] = {
    # PLC-centric
    "S7comm":              {"vendor": "Siemens",              "make": "Siemens",              "device_type": "PLC",  "role": "plc"},
    "S7comm+":             {"vendor": "Siemens",              "make": "Siemens",              "device_type": "PLC",  "role": "plc"},
    "Omron FINS":          {"vendor": "Omron",                "make": "Omron",                "device_type": "PLC",  "role": "plc"},
    "MELSEC MC Protocol":  {"vendor": "Mitsubishi Electric",  "make": "Mitsubishi Electric",  "device_type": "PLC",  "role": "plc"},
    # RTU/IED-centric
    "SEL Fast Message":    {"vendor": "SEL",                  "make": "Schweitzer Engineering Labs", "device_type": "IED", "role": "ied"},
}


# ======================================================================
# 2. CIP Vendor ID -> vendor attribution  (from EtherNet/IP)
# ======================================================================

CIP_VENDOR_MAKE_MAP: Dict[str, Dict] = {
    "Rockwell Automation":            {"vendor": "Rockwell Automation",  "make": "Allen-Bradley"},
    "Allen-Bradley Company":          {"vendor": "Rockwell Automation",  "make": "Allen-Bradley"},
    "Allen-Bradley Company, LLC":     {"vendor": "Rockwell Automation",  "make": "Allen-Bradley"},
    "Omron":                          {"vendor": "Omron",                "make": "Omron"},
    "Omron Corporation":              {"vendor": "Omron",                "make": "Omron"},
    "Omron Americas":                 {"vendor": "Omron",                "make": "Omron"},
    "Omron Electronics LLC":          {"vendor": "Omron",                "make": "Omron"},
    "Schneider Electric":             {"vendor": "Schneider Electric",   "make": "Schneider Electric"},
    "Schneider Electric (Group)":     {"vendor": "Schneider Electric",   "make": "Schneider Electric"},
    "Schneider Electric (Modicon)":   {"vendor": "Schneider Electric",   "make": "Schneider Electric (Modicon)"},
    "Siemens Energy & Automation":    {"vendor": "Siemens",              "make": "Siemens"},
    "Siemens AG":                     {"vendor": "Siemens",              "make": "Siemens"},
    "Mitsubishi Electric":            {"vendor": "Mitsubishi Electric",  "make": "Mitsubishi Electric"},
    "Mitsubishi Electric Automation": {"vendor": "Mitsubishi Electric",  "make": "Mitsubishi Electric"},
    "ABB":                            {"vendor": "ABB",                  "make": "ABB"},
    "Honeywell International":        {"vendor": "Honeywell",            "make": "Honeywell"},
    "GE Automation & Controls":       {"vendor": "GE Automation",        "make": "GE Automation"},
    "Beckhoff Automation":            {"vendor": "Beckhoff",             "make": "Beckhoff"},
    "Phoenix Contact":                {"vendor": "Phoenix Contact",      "make": "Phoenix Contact"},
    "WAGO Corporation":               {"vendor": "WAGO",                 "make": "WAGO"},
    "Yokogawa Electric":              {"vendor": "Yokogawa",             "make": "Yokogawa"},
}


# ======================================================================
# 3. OUI vendor string -> make / device_type mapping
#    Used when OUI lookup returns a vendor string but we need to infer
#    device_type and a normalised make for the unified model.
# ======================================================================

OUI_MAKE_MAP: Dict[str, Dict] = {
    # RTU / IED / FRTU / Gateway families (from RTU scanner)
    "ABB Group":                        {"make": "ABB",                      "device_type": "RTU"},
    "GE Grid Solutions":                {"make": "GE Grid Solutions",        "device_type": "RTU"},
    "GE Intelligent Platforms":         {"make": "GE Grid Solutions",        "device_type": "RTU"},
    "GE Fanuc Automation":              {"make": "GE Automation",            "device_type": "RTU"},
    "GE Automation":                    {"make": "GE Automation",            "device_type": "PLC"},
    "Siemens AG":                       {"make": "Siemens",                  "device_type": None},
    "RuggedCom (Siemens)":              {"make": "Siemens / RuggedCom",      "device_type": "Gateway"},
    "Schneider Electric":               {"make": "Schneider Electric",       "device_type": None},
    "Schneider Electric (Modicon)":     {"make": "Schneider Electric (Modicon)", "device_type": None},
    "Schneider Electric (Modicon M340)": {"make": "Schneider Electric (Modicon)", "device_type": "PLC"},
    "SEL (Schweitzer Engineering Labs)": {"make": "SEL",                    "device_type": "IED"},
    "SEL (Schweitzer Engineering)":     {"make": "SEL",                      "device_type": "IED"},
    "Emerson Electric":                 {"make": "Emerson",                  "device_type": "RTU"},
    "Emerson Network Power":            {"make": "Emerson",                  "device_type": "RTU"},
    "Honeywell":                        {"make": "Honeywell",                "device_type": None},
    "Honeywell Process Solutions":      {"make": "Honeywell",                "device_type": None},
    "Cooper Industries (Eaton)":        {"make": "Eaton",                    "device_type": "FRTU"},
    "Eaton":                            {"make": "Eaton",                    "device_type": "FRTU"},
    "Noja Power":                       {"make": "Noja Power",               "device_type": "FRTU"},
    "Landis+Gyr":                       {"make": "Landis+Gyr",              "device_type": "FRTU"},
    "Itron":                            {"make": "Itron",                    "device_type": "FRTU"},
    "Yokogawa Electric":                {"make": "Yokogawa",                 "device_type": None},
    "Alstom Grid":                      {"make": "GE Grid (Alstom)",         "device_type": "IED"},
    "Sifang (SIFCO)":                   {"make": "Sifang",                   "device_type": "RTU"},
    "Rockwell Automation":              {"make": "Allen-Bradley",            "device_type": None},
    "Allen-Bradley (Rockwell)":         {"make": "Allen-Bradley",            "device_type": None},
    "Hirschmann Automation (Belden)":   {"make": "Hirschmann / Belden",      "device_type": "Gateway"},
    # PLC-centric families
    "Mitsubishi Electric":              {"make": "Mitsubishi Electric",       "device_type": "PLC"},
    "Omron Corporation":                {"make": "Omron",                    "device_type": "PLC"},
    "Beckhoff Automation":              {"make": "Beckhoff",                 "device_type": None},
    "Phoenix Contact":                  {"make": "Phoenix Contact",          "device_type": None},
    "WAGO Corporation":                 {"make": "WAGO",                     "device_type": None},
    "WAGO Kontakttechnik":              {"make": "WAGO",                     "device_type": None},
    "Moxa Technologies":                {"make": "Moxa",                     "device_type": "Gateway"},
    "Advantech Co.":                     {"make": "Advantech",                "device_type": None},
    "Red Lion Controls":                {"make": "Red Lion",                 "device_type": None},
    "ProSoft Technology":               {"make": "ProSoft",                  "device_type": "Gateway"},
    "HMS Industrial Networks":          {"make": "HMS / Anybus",             "device_type": "Gateway"},
    "Turck":                            {"make": "Turck",                    "device_type": None},
    "Pepperl+Fuchs":                    {"make": "Pepperl+Fuchs",            "device_type": None},
    "Festo AG":                         {"make": "Festo",                    "device_type": None},
    "Danfoss A/S":                      {"make": "Danfoss",                  "device_type": None},
    "Pilz GmbH":                        {"make": "Pilz",                     "device_type": None},
    "Keyence Corporation":              {"make": "Keyence",                  "device_type": None},
    "Panasonic Electric Works":         {"make": "Panasonic",                "device_type": None},
}


# ======================================================================
# 4. Vendor substrings found in DNP3 / Modbus vendor detail strings
# ======================================================================

VENDOR_SUBSTRINGS: Dict[str, Dict] = {
    "abb":          {"vendor": "ABB",                 "make": "ABB"},
    "ge ":          {"vendor": "GE Grid Solutions",   "make": "GE Grid Solutions"},
    "multilin":     {"vendor": "GE Grid Solutions",   "make": "GE Grid Solutions"},
    "schweitzer":   {"vendor": "SEL",                 "make": "SEL"},
    "sel-":         {"vendor": "SEL",                 "make": "SEL"},
    "siemens":      {"vendor": "Siemens",             "make": "Siemens"},
    "sicam":        {"vendor": "Siemens",             "make": "Siemens"},
    "schneider":    {"vendor": "Schneider Electric",  "make": "Schneider Electric"},
    "scadapack":    {"vendor": "Schneider Electric",  "make": "Schneider Electric"},
    "easergy":      {"vendor": "Schneider Electric",  "make": "Schneider Electric"},
    "emerson":      {"vendor": "Emerson",             "make": "Emerson"},
    "bristol":      {"vendor": "Emerson",             "make": "Emerson (Bristol)"},
    "controlwave":  {"vendor": "Emerson",             "make": "Emerson (ControlWave)"},
    "roc":          {"vendor": "Emerson",             "make": "Emerson (ROC)"},
    "honeywell":    {"vendor": "Honeywell",           "make": "Honeywell"},
    "noja":         {"vendor": "Noja Power",          "make": "Noja Power"},
    "landis":       {"vendor": "Landis+Gyr",          "make": "Landis+Gyr"},
    "yokogawa":     {"vendor": "Yokogawa",            "make": "Yokogawa"},
    "rockwell":     {"vendor": "Rockwell Automation", "make": "Allen-Bradley"},
    "allen-bradley": {"vendor": "Rockwell Automation", "make": "Allen-Bradley"},
    "omron":        {"vendor": "Omron",               "make": "Omron"},
    "mitsubishi":   {"vendor": "Mitsubishi Electric",  "make": "Mitsubishi Electric"},
    "beckhoff":     {"vendor": "Beckhoff",             "make": "Beckhoff"},
    "phoenix":      {"vendor": "Phoenix Contact",      "make": "Phoenix Contact"},
    "wago":         {"vendor": "WAGO",                 "make": "WAGO"},
}


# ======================================================================
# 5. GOOSE gcbRef prefix patterns  (IED name encodes vendor)
# ======================================================================

GOOSE_VENDOR_PREFIXES: Dict[str, str] = {
    # ABB feeder / bay / line / differential / transformer protection
    "REF":  "ABB",
    "REC":  "ABB",
    "REL":  "ABB",
    "RED":  "ABB",
    "RET":  "ABB",
    "RAR":  "ABB",
    # SEL IEDs
    "SEL":  "SEL",
    # GE Grid Solutions (MiCOM, Multilin relays)
    "P64":  "GE Grid Solutions",
    "P54":  "GE Grid Solutions",
    "T60":  "GE Grid Solutions",
    "L90":  "GE Grid Solutions",
    # Siemens SIPROTEC
    "7SL":  "Siemens",
    "7SD":  "Siemens",
    "7UT":  "Siemens",
    "7SA":  "Siemens",
    # Schneider Electric MiCOM Pro series
    "PRO":  "Schneider Electric",
    "P24":  "Schneider Electric",
    "P14":  "Schneider Electric",
}


# ======================================================================
# 6. Protocol -> default role mapping
# ======================================================================

PROTOCOL_ROLE_MAP: Dict[str, str] = {
    "S7comm":              "plc",
    "S7comm+":             "plc",
    "Modbus/TCP":          "plc",
    "EtherNet/IP":         "plc",
    "Omron FINS":          "plc",
    "MELSEC MC Protocol":  "plc",
    "DNP3":                "rtu",
    "IEC 60870-5-104":     "rtu",
    "SEL Fast Message":    "ied",
    "IEC 61850 GOOSE":     "ied",
    "IEC 61850 MMS":       "ied",
}


# ======================================================================
# Engine
# ======================================================================

class FingerprintEngine:
    """
    Applies vendor fingerprinting to an OTDevice, updating vendor, make,
    model, firmware, serial_number, device_type, role, and
    vendor_confidence based on available evidence.

    Call ``fingerprint(device)`` once after all protocol dissectors have
    populated the device.  The method modifies the device in-place.
    """

    # ---------------------------------------------------------------- public

    def fingerprint(self, device: OTDevice) -> None:
        """
        Run the full identification pipeline on *device* (mutates in-place).

        Priority order:
          1. Exclusive protocols
          2. CIP vendor ID
          3. Modbus MEI strings
          4. DNP3 device attributes
          5. GOOSE gcbRef IED inference
          6. Vendor substring matching
          7. OUI MAC lookup
        """
        identified = False

        # ------ 1. Exclusive-protocol identification (highest confidence) --
        for proto in device.protocols:
            if proto.protocol in EXCLUSIVE_PROTOCOLS:
                info = EXCLUSIVE_PROTOCOLS[proto.protocol]
                device.vendor            = info["vendor"]
                device.vendor_confidence = "high"
                device.make              = info["make"]
                self._set_classification(device, info)
                self._extract_model_from_proto(device, proto)
                identified = True
                break

        if not identified:
            # ------ 2. EtherNet/IP CIP vendor ID --------------------------
            for proto in device.protocols:
                if proto.protocol == "EtherNet/IP":
                    self._identify_from_cip(device, proto)
                    identified = device.vendor is not None
                    break

        if not identified:
            # ------ 3. Modbus MEI device identification strings -----------
            for proto in device.protocols:
                if proto.protocol == "Modbus/TCP":
                    self._identify_from_modbus(device, proto)
                    identified = device.vendor is not None
                    break

        if not identified:
            # ------ 4. DNP3 device attribute strings ----------------------
            for proto in device.protocols:
                if proto.protocol == "DNP3":
                    self._identify_from_dnp3(device, proto)
                    identified = device.vendor is not None
                    break

        # Even if already identified from exclusive/CIP, still enrich
        # model/firmware from Modbus/DNP3 if present.
        if identified:
            self._enrich_from_all_protocols(device)

        # ------ 5. GOOSE gcbRef prefix -> IED vendor ----------------------
        if not device.vendor and device.goose_ids:
            for gid in device.goose_ids:
                prefix = gid[:3].upper() if len(gid) >= 3 else ""
                vendor = GOOSE_VENDOR_PREFIXES.get(prefix)
                if vendor:
                    device.vendor            = vendor
                    device.vendor_confidence = "medium"
                    device.make              = vendor
                    device.device_type       = "IED" if device.device_type == "unknown" else device.device_type
                    device.role              = "ied" if device.role == "unknown" else device.role
                    break

        # ------ 6. Vendor substring matching on gathered strings ----------
        if not device.vendor:
            combined = self._gather_all_vendor_strings(device)
            if combined:
                hit = _match_vendor_substrings(combined)
                if hit:
                    device.vendor            = hit["vendor"]
                    device.vendor_confidence = "medium"
                    device.make              = device.make or hit.get("make")

        # ------ 7. OUI MAC-based fallback ---------------------------------
        if not device.vendor and device.mac:
            oui_result = lookup_oui(device.mac)
            if oui_result:
                oui_vendor = oui_result["vendor"]
                device.vendor            = oui_vendor
                device.vendor_confidence = "medium"
                mapping = OUI_MAKE_MAP.get(oui_vendor, {})
                device.make = device.make or mapping.get("make", oui_vendor)
                # Apply device_type from OUI hint
                hint_type = oui_result.get("device_hint") or mapping.get("device_type")
                if hint_type and device.device_type == "unknown":
                    device.device_type = hint_type
        elif device.mac and not device.make:
            # Vendor already set from protocol, but make may be missing
            oui_result = lookup_oui(device.mac)
            if oui_result:
                oui_vendor = oui_result["vendor"]
                mapping = OUI_MAKE_MAP.get(oui_vendor, {})
                device.make = device.make or mapping.get("make", oui_vendor)

        # ------ Infer role / device_type from protocols if still unknown ---
        self._infer_classification(device)

    # ---------------------------------------------------------------- CIP

    def _identify_from_cip(self, device: OTDevice, proto) -> None:
        """Identify vendor from EtherNet/IP CIP ListIdentity."""
        cip_vendor = proto.details.get("cip_vendor_name", "")
        mapping = CIP_VENDOR_MAKE_MAP.get(cip_vendor)
        if mapping:
            device.vendor            = mapping["vendor"]
            device.make              = mapping["make"]
            device.vendor_confidence = "high"
        elif cip_vendor:
            device.vendor            = cip_vendor
            device.vendor_confidence = "medium"

        # Enrich with CIP product info
        product_name = proto.details.get("cip_product_name")
        revision     = proto.details.get("cip_revision")
        serial       = proto.details.get("cip_serial")
        if product_name:
            device.model = device.model or product_name
        if revision:
            device.firmware = device.firmware or f"Rev {revision}"
        if serial:
            device.serial_number = device.serial_number or str(serial)

        # Default classification
        if device.role == "unknown":
            device.role = "plc"
        if device.device_type == "unknown":
            device.device_type = "PLC"

    # ---------------------------------------------------------------- Modbus

    def _identify_from_modbus(self, device: OTDevice, proto) -> None:
        """Identify vendor from Modbus MEI device identification strings."""
        d = proto.details
        inferred   = d.get("inferred_make")
        vendor_str = d.get("vendor_name")

        if vendor_str and not device.vendor:
            device.vendor            = vendor_str
            device.vendor_confidence = "high"
            # Try CIP map for normalised make
            cip_match = CIP_VENDOR_MAKE_MAP.get(vendor_str)
            if cip_match:
                device.make = cip_match["make"]
        elif inferred and not device.vendor:
            device.vendor            = inferred
            device.make              = inferred
            device.vendor_confidence = "medium"

        product = d.get("product_name") or d.get("product_code")
        firmware = d.get("firmware_version")
        model    = d.get("model_name")
        if product:
            device.model = device.model or product
        if model and not device.model:
            device.model = model
        if firmware:
            device.firmware = device.firmware or firmware

        if device.role == "unknown":
            device.role = "plc"

    # ---------------------------------------------------------------- DNP3

    def _identify_from_dnp3(self, device: OTDevice, proto) -> None:
        """Identify vendor from DNP3 Group 0 device attribute strings."""
        d = proto.details
        vendor_str  = d.get("vendor_name")
        product_str = d.get("product_model")
        firmware    = d.get("firmware_version")

        if vendor_str and not device.vendor:
            device.vendor            = vendor_str
            device.vendor_confidence = "high"

        if product_str:
            device.model = device.model or product_str
        if firmware:
            device.firmware = device.firmware or firmware

        # Extract DNP3 address
        if d.get("dnp3_src_address") is not None and device.dnp3_address is None:
            try:
                device.dnp3_address = int(d["dnp3_src_address"])
            except (TypeError, ValueError):
                pass

        if device.role == "unknown":
            device.role = "rtu"

    # ---------------------------------------------------------------- enrich

    def _enrich_from_all_protocols(self, device: OTDevice) -> None:
        """
        After primary identification, sweep remaining protocols for
        model/firmware/serial/address enrichment.
        """
        for proto in device.protocols:
            d = proto.details

            # Model / firmware from any protocol
            if not device.model:
                device.model = (
                    d.get("product_name") or d.get("product_model")
                    or d.get("model_name") or d.get("cip_product_name")
                    or d.get("cpu_family") or d.get("plc_model_raw")
                    or d.get("cpu_model") or d.get("cpu_name")
                )
            if not device.firmware:
                device.firmware = d.get("firmware_version") or d.get("cip_revision")
                if device.firmware and d.get("cip_revision") and not device.firmware.startswith("Rev"):
                    device.firmware = f"Rev {device.firmware}"
            if not device.serial_number:
                sn = d.get("serial_number") or d.get("cip_serial")
                if sn is not None:
                    device.serial_number = str(sn)

            # DNP3 address
            if d.get("dnp3_src_address") is not None and device.dnp3_address is None:
                try:
                    device.dnp3_address = int(d["dnp3_src_address"])
                except (TypeError, ValueError):
                    pass

            # IEC 104 common address
            if d.get("common_address") is not None and device.iec104_common_address is None:
                try:
                    device.iec104_common_address = int(d["common_address"])
                except (TypeError, ValueError):
                    pass

    # ---------------------------------------------------------------- model extraction

    def _extract_model_from_proto(self, device: OTDevice, proto) -> None:
        """
        Pull model/firmware/serial from S7comm, FINS, MELSEC, SEL, or
        generic protocol details.
        """
        d = proto.details

        # S7comm
        cpu_family = d.get("cpu_family")
        cpu_model  = d.get("cpu_model_hint") or d.get("cpu_name") or d.get("cpu_model")
        firmware   = d.get("firmware_version")
        serial     = d.get("serial_number")

        if cpu_family:
            device.model = device.model or cpu_family
        if cpu_model and not device.model:
            device.model = cpu_model.strip()
        if firmware:
            device.firmware = device.firmware or firmware
        if serial:
            device.serial_number = device.serial_number or serial

        # FINS
        fins_model = d.get("plc_model_raw")
        if fins_model and not device.model:
            device.model = fins_model

        # MELSEC
        melsec_model = d.get("cpu_model") or d.get("cpu_name")
        if melsec_model and not device.model:
            device.model = melsec_model

        # Generic fallbacks
        if not device.model:
            device.model = d.get("product_model") or d.get("product_name") or d.get("model_name")
        if not device.firmware:
            device.firmware = d.get("firmware_version")
        if not device.serial_number:
            sn = d.get("serial_number")
            if sn is not None:
                device.serial_number = str(sn)

    # ---------------------------------------------------------------- classification

    def _set_classification(self, device: OTDevice, info: Dict) -> None:
        """Apply device_type and role from an info dict if device is still unknown."""
        if device.device_type == "unknown" and info.get("device_type"):
            device.device_type = info["device_type"]
        if device.role == "unknown" and info.get("role"):
            device.role = info["role"]

    def _infer_classification(self, device: OTDevice) -> None:
        """
        Infer role and device_type from detected protocols and OUI hints
        when they have not been set by higher-priority evidence.
        """
        proto_names = {p.protocol for p in device.protocols}

        # Role from protocols
        if device.role == "unknown":
            for proto_name in proto_names:
                role = PROTOCOL_ROLE_MAP.get(proto_name)
                if role:
                    device.role = role
                    break

        # device_type from role
        if device.device_type == "unknown":
            role_to_type = {
                "plc": "PLC",
                "rtu": "RTU",
                "frtu": "FRTU",
                "ied": "IED",
                "relay": "Relay",
                "hmi": "HMI",
                "gateway": "Gateway",
                "engineering_station": "Engineering Workstation",
                "historian": "Historian",
                "master_station": "Master Station",
            }
            device.device_type = role_to_type.get(device.role, "unknown")

        # Refine: IEC 61850 GOOSE/MMS presence strongly suggests IED
        if device.device_type in ("unknown", "RTU", "PLC"):
            if "IEC 61850 GOOSE" in proto_names or "IEC 61850 MMS" in proto_names:
                device.device_type = "IED"
                device.role = "ied"

        # Refine: OUI device_hint can upgrade classification
        if device.device_type == "unknown" and device.mac:
            oui_result = lookup_oui(device.mac)
            if oui_result:
                hint = oui_result.get("device_hint")
                if hint:
                    device.device_type = hint

    # ---------------------------------------------------------------- string gathering

    def _gather_all_vendor_strings(self, device: OTDevice) -> str:
        """
        Collect all printable vendor-related strings from every protocol
        detection on the device and return them as a single lowercase string.
        """
        parts = []
        for proto in device.protocols:
            for key in ("vendor_name", "product_model", "inferred_make",
                        "vendor", "vendor_url", "product_name", "model_name",
                        "cip_vendor_name", "cpu_family", "cpu_name"):
                val = proto.details.get(key)
                if val and isinstance(val, str):
                    parts.append(val)
        return " ".join(parts).lower()


# ======================================================================
# Module-level helpers
# ======================================================================

def _match_vendor_substrings(text: str) -> Optional[Dict]:
    """Match a lowercase text against known vendor keyword substrings."""
    for keyword, info in VENDOR_SUBSTRINGS.items():
        if keyword in text:
            return info
    return None
