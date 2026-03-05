"""
RTU/FRTU Vendor Fingerprinting Engine.

Evidence sources (priority order):
  1. Protocol-exclusive identification  (SEL/FINS/MELSEC → vendor certain)
  2. DNP3 Group 0 device attribute strings
  3. Modbus MEI device identification strings
  4. IEC 61850 GOOSE gcbRef (contains IED name, infers vendor)
  5. IEC 61850 MMS logical node names
  6. MAC OUI database (fallback)
"""
from typing import Optional

from .oui_db import lookup_oui
from ..models import RTUDevice

# Protocols that unambiguously identify a single vendor
EXCLUSIVE_PROTOCOLS = {
    "SEL Fast Message":       {"vendor": "SEL",               "rtu_make": "Schweitzer Engineering Labs", "device_type": "IED"},
    "Omron FINS":             {"vendor": "Omron",             "rtu_make": "Omron",                       "device_type": "RTU"},
    "MELSEC MC Protocol":     {"vendor": "Mitsubishi Electric","rtu_make": "Mitsubishi Electric",         "device_type": "RTU"},
}

# OUI vendor → rtu_make mapping
OUI_MAKE_MAP = {
    "ABB Group":                    {"rtu_make": "ABB",                      "device_type": "RTU"},
    "GE Grid Solutions":            {"rtu_make": "GE Grid Solutions",        "device_type": "RTU"},
    "GE Intelligent Platforms":     {"rtu_make": "GE Grid Solutions",        "device_type": "RTU"},
    "Siemens AG":                   {"rtu_make": "Siemens",                  "device_type": "RTU"},
    "RuggedCom (Siemens)":          {"rtu_make": "Siemens / RuggedCom",      "device_type": "Gateway"},
    "Schneider Electric":           {"rtu_make": "Schneider Electric",       "device_type": "RTU"},
    "SEL (Schweitzer Engineering Labs)": {"rtu_make": "SEL",                 "device_type": "IED"},
    "Emerson Electric":             {"rtu_make": "Emerson",                  "device_type": "RTU"},
    "Honeywell":                    {"rtu_make": "Honeywell",                "device_type": "RTU"},
    "Honeywell Process Solutions":  {"rtu_make": "Honeywell",                "device_type": "RTU"},
    "Cooper Industries (Eaton)":    {"rtu_make": "Eaton",                    "device_type": "FRTU"},
    "Eaton":                        {"rtu_make": "Eaton",                    "device_type": "FRTU"},
    "Noja Power":                   {"rtu_make": "Noja Power",               "device_type": "FRTU"},
    "Landis+Gyr":                   {"rtu_make": "Landis+Gyr",               "device_type": "FRTU"},
    "Yokogawa Electric":            {"rtu_make": "Yokogawa",                 "device_type": "RTU"},
    "Alstom Grid":                  {"rtu_make": "GE Grid (Alstom)",         "device_type": "IED"},
    "Rockwell Automation":          {"rtu_make": "Rockwell Automation",      "device_type": "RTU"},
    "Allen-Bradley (Rockwell)":     {"rtu_make": "Rockwell Automation",      "device_type": "RTU"},
    "Hirschmann Automation (Belden)": {"rtu_make": "Hirschmann / Belden",   "device_type": "Gateway"},
}

# Substrings found in DNP3 / Modbus vendor strings
VENDOR_SUBSTRINGS = {
    "abb":          {"vendor": "ABB",                 "rtu_make": "ABB"},
    "ge ":          {"vendor": "GE Grid Solutions",   "rtu_make": "GE Grid Solutions"},
    "multilin":     {"vendor": "GE Grid Solutions",   "rtu_make": "GE Grid Solutions"},
    "schweitzer":   {"vendor": "SEL",                 "rtu_make": "SEL"},
    "sel-":         {"vendor": "SEL",                 "rtu_make": "SEL"},
    "siemens":      {"vendor": "Siemens",             "rtu_make": "Siemens"},
    "sicam":        {"vendor": "Siemens",             "rtu_make": "Siemens"},
    "schneider":    {"vendor": "Schneider Electric",  "rtu_make": "Schneider Electric"},
    "scadapack":    {"vendor": "Schneider Electric",  "rtu_make": "Schneider Electric"},
    "easergy":      {"vendor": "Schneider Electric",  "rtu_make": "Schneider Electric"},
    "emerson":      {"vendor": "Emerson",             "rtu_make": "Emerson"},
    "bristol":      {"vendor": "Emerson",             "rtu_make": "Emerson (Bristol)"},
    "controlwave":  {"vendor": "Emerson",             "rtu_make": "Emerson (ControlWave)"},
    "roc":          {"vendor": "Emerson",             "rtu_make": "Emerson (ROC)"},
    "honeywell":    {"vendor": "Honeywell",           "rtu_make": "Honeywell"},
    "noja":         {"vendor": "Noja Power",          "rtu_make": "Noja Power"},
    "landis":       {"vendor": "Landis+Gyr",          "rtu_make": "Landis+Gyr"},
    "yokogawa":     {"vendor": "Yokogawa",            "rtu_make": "Yokogawa"},
}

# GOOSE gcbRef prefix patterns (IED name encodes vendor in many cases)
GOOSE_VENDOR_PREFIXES = {
    "REF":  "ABB",   # REF615, REF630 — ABB feeder protection
    "REC":  "ABB",   # REC615 — bay controller
    "REL":  "ABB",   # REL670 — line protection
    "RED":  "ABB",   # RED670 — differential protection
    "RET":  "ABB",   # RET670 — transformer protection
    "RAR":  "ABB",   # Distance backup protection
    "SEL":  "SEL",   # SEL-xxx IEDs
    "P64":  "GE Grid Solutions",   # MiCOM P643
    "P54":  "GE Grid Solutions",   # MiCOM P543
    "T60":  "GE Grid Solutions",   # Transformer management relay
    "L90":  "GE Grid Solutions",   # Line differential relay
    "7SL":  "Siemens",             # SIPROTEC 7SL
    "7SD":  "Siemens",             # SIPROTEC 7SD
    "7UT":  "Siemens",             # SIPROTEC 7UT
    "7SA":  "Siemens",             # SIPROTEC 7SA
    "PRO":  "Schneider Electric",  # MiCOM Pro series
    "P24":  "Schneider Electric",  # MiCOM P243
    "P14":  "Schneider Electric",  # MiCOM P145
}


class FingerprintEngine:

    def lookup_oui(self, mac: str):
        return lookup_oui(mac)

    def fingerprint(self, device: RTUDevice) -> None:
        """
        Identify vendor / make / model / device_type for a device.
        Modifies device in-place.
        """
        # 1. Exclusive protocol (highest confidence)
        for proto in device.protocols:
            if proto.protocol in EXCLUSIVE_PROTOCOLS:
                info = EXCLUSIVE_PROTOCOLS[proto.protocol]
                device.vendor            = info["vendor"]
                device.vendor_confidence = "high"
                device.rtu_make          = info["rtu_make"]
                device.device_type       = device.device_type if device.device_type != "unknown" else info["device_type"]
                self._extract_from_proto(device, proto)
                return

        # 2. DNP3 / Modbus embedded strings
        for proto in device.protocols:
            strings = self._gather_vendor_strings(proto)
            if strings:
                hit = _match_vendor_strings(strings)
                if hit:
                    _apply(device, hit, confidence="high")
                    self._extract_from_proto(device, proto)

        # 3. IEC 61850 GOOSE gcbRef prefix
        if device.goose_ids:
            for gid in device.goose_ids:
                prefix = gid[:3].upper()
                vendor = GOOSE_VENDOR_PREFIXES.get(prefix)
                if vendor and not device.vendor:
                    device.vendor            = vendor
                    device.vendor_confidence = "medium"
                    device.rtu_make          = vendor
                    device.device_type       = "IED"
                    break

        # 4. OUI fallback
        if device.mac and not device.vendor:
            oui_vendor = lookup_oui(device.mac)
            if oui_vendor:
                device.vendor            = oui_vendor
                device.vendor_confidence = "medium"
                mapping = OUI_MAKE_MAP.get(oui_vendor, {})
                device.rtu_make   = device.rtu_make  or mapping.get("rtu_make")
                device.device_type = (device.device_type
                                      if device.device_type != "unknown"
                                      else mapping.get("device_type", "RTU"))

    # ── helpers ──────────────────────────────────────────────────────────

    def _gather_vendor_strings(self, proto) -> str:
        """Extract all printable strings from protocol details."""
        parts = []
        for key in ("vendor_name", "product_model", "inferred_make",
                    "vendor", "vendor_url", "product_name", "model_name"):
            val = proto.details.get(key)
            if val and isinstance(val, str):
                parts.append(val)
        return " ".join(parts).lower()

    def _extract_from_proto(self, device: RTUDevice, proto) -> None:
        """Pull model/firmware from protocol details."""
        d = proto.details
        device.rtu_model  = device.rtu_model  or d.get("product_model") or d.get("model_name") or d.get("cpu_model")
        device.firmware   = device.firmware   or d.get("firmware_version")
        device.serial_number = device.serial_number or d.get("serial_number")
        if d.get("dnp3_src_address") is not None and device.dnp3_address is None:
            try:
                device.dnp3_address = int(d["dnp3_src_address"])
            except (TypeError, ValueError):
                pass
        if d.get("common_address") is not None and device.iec104_common_address is None:
            try:
                device.iec104_common_address = int(d["common_address"])
            except (TypeError, ValueError):
                pass


def _match_vendor_strings(text: str) -> Optional[dict]:
    for keyword, info in VENDOR_SUBSTRINGS.items():
        if keyword in text:
            return info
    return None


def _apply(device: RTUDevice, info: dict, confidence: str) -> None:
    if not device.vendor:
        device.vendor            = info.get("vendor")
        device.vendor_confidence = confidence
    if not device.rtu_make:
        device.rtu_make = info.get("rtu_make")
