"""
Vendor Fingerprinting Engine.

Combines evidence from:
  1. MAC OUI database lookup
  2. Protocol-specific metadata (CIP vendor ID, MEI device strings, etc.)
  3. Port-based inference (S7comm is Siemens-exclusive)

Returns a unified vendor attribution with confidence level.
"""
from typing import Optional

from .oui_db import lookup_oui
from ..models import PLCDevice


# Protocols that unambiguously identify a single vendor
EXCLUSIVE_PROTOCOLS = {
    "S7comm":              {"vendor": "Siemens",             "plc_make": "Siemens",             "confidence": "high"},
    "S7comm+":             {"vendor": "Siemens",             "plc_make": "Siemens",             "confidence": "high"},
    "Omron FINS":          {"vendor": "Omron",               "plc_make": "Omron",               "confidence": "high"},
    "MELSEC MC Protocol":  {"vendor": "Mitsubishi Electric", "plc_make": "Mitsubishi Electric", "confidence": "high"},
}

# CIP Vendor IDs mapped to vendor attribution
CIP_VENDOR_MAKE_MAP = {
    "Rockwell Automation":          {"vendor": "Rockwell Automation", "plc_make": "Allen-Bradley"},
    "Allen-Bradley Company":        {"vendor": "Rockwell Automation", "plc_make": "Allen-Bradley"},
    "Allen-Bradley Company, LLC":   {"vendor": "Rockwell Automation", "plc_make": "Allen-Bradley"},
    "Omron":                        {"vendor": "Omron",               "plc_make": "Omron"},
    "Omron Corporation":            {"vendor": "Omron",               "plc_make": "Omron"},
    "Omron Americas":               {"vendor": "Omron",               "plc_make": "Omron"},
    "Omron Electronics LLC":        {"vendor": "Omron",               "plc_make": "Omron"},
    "Schneider Electric":           {"vendor": "Schneider Electric",  "plc_make": "Schneider Electric"},
    "Schneider Electric (Group)":   {"vendor": "Schneider Electric",  "plc_make": "Schneider Electric"},
    "Schneider Electric (Modicon)": {"vendor": "Schneider Electric",  "plc_make": "Schneider Electric (Modicon)"},
    "Siemens Energy & Automation":  {"vendor": "Siemens",             "plc_make": "Siemens"},
    "Siemens AG":                   {"vendor": "Siemens",             "plc_make": "Siemens"},
    "Mitsubishi Electric":          {"vendor": "Mitsubishi Electric", "plc_make": "Mitsubishi Electric"},
    "Mitsubishi Electric Automation": {"vendor": "Mitsubishi Electric", "plc_make": "Mitsubishi Electric"},
    "ABB":                          {"vendor": "ABB",                 "plc_make": "ABB"},
    "Honeywell International":      {"vendor": "Honeywell",           "plc_make": "Honeywell"},
    "GE Automation & Controls":     {"vendor": "GE Automation",       "plc_make": "GE Automation"},
    "Beckhoff Automation":          {"vendor": "Beckhoff",            "plc_make": "Beckhoff"},
    "Phoenix Contact":              {"vendor": "Phoenix Contact",     "plc_make": "Phoenix Contact"},
    "WAGO Corporation":             {"vendor": "WAGO",                "plc_make": "WAGO"},
    "Yokogawa Electric":            {"vendor": "Yokogawa",            "plc_make": "Yokogawa"},
}

# Role inference from protocol name
PROTOCOL_ROLE_MAP = {
    "S7comm":              "plc",
    "S7comm+":             "plc",
    "Modbus/TCP":          "plc",           # Could be HMI, but usually PLC
    "EtherNet/IP":         "plc",
    "Omron FINS":          "plc",
    "MELSEC MC Protocol":  "plc",
    "DNP3":                "plc",           # Could be RTU
    "IEC 60870-5-104":     "plc",           # Could be RTU
}


class FingerprintEngine:
    """
    Applies vendor fingerprinting to a PLCDevice, updating vendor/make/model
    and role fields based on available evidence.
    """

    def lookup_oui(self, mac: str) -> Optional[str]:
        """Return vendor name from OUI database, or None."""
        return lookup_oui(mac)

    def identify_from_protocols(self, device: PLCDevice) -> Optional[dict]:
        """
        Analyse protocol detections and return a fingerprint dict:
          { vendor, plc_make, plc_model, firmware, role, confidence }
        or None if no identification is possible.
        """
        result: dict = {}

        for proto in device.protocols:
            # --- Exclusive-protocol identification ---
            if proto.protocol in EXCLUSIVE_PROTOCOLS:
                exclusive = EXCLUSIVE_PROTOCOLS[proto.protocol]
                result.update(exclusive)
                role = PROTOCOL_ROLE_MAP.get(proto.protocol, "unknown")
                result.setdefault("role", role)

                # Extract model / firmware from protocol details
                self._extract_model_from_proto(result, proto)
                break    # exclusive identification is definitive

            # --- EtherNet/IP CIP vendor identification ---
            if proto.protocol == "EtherNet/IP":
                cip_vendor = proto.details.get("cip_vendor_name", "")
                mapping = CIP_VENDOR_MAKE_MAP.get(cip_vendor)
                if mapping:
                    result.update(mapping)
                    result["confidence"] = "high"
                else:
                    result["vendor"] = cip_vendor if cip_vendor else "Unknown"
                    result["confidence"] = "medium"

                # Enrich with CIP product info
                product_name = proto.details.get("cip_product_name")
                revision     = proto.details.get("cip_revision")
                serial       = proto.details.get("cip_serial")
                if product_name:
                    result["plc_model"]  = product_name
                if revision:
                    result["firmware"]   = f"Rev {revision}"
                if serial:
                    result["serial_number"] = serial
                result.setdefault("role", "plc")

            # --- Modbus MEI device identification strings ---
            if proto.protocol == "Modbus/TCP":
                inferred = proto.details.get("inferred_make")
                if inferred and "vendor" not in result:
                    result["vendor"]     = inferred
                    result["plc_make"]   = inferred
                    result["confidence"] = "medium"
                vendor_name  = proto.details.get("vendor_name")
                product_name = proto.details.get("product_name") or proto.details.get("product_code")
                firmware     = proto.details.get("firmware_version")
                model_name   = proto.details.get("model_name")
                if vendor_name and "vendor" not in result:
                    result["vendor"] = vendor_name
                    result["confidence"] = "high"
                if product_name:
                    result.setdefault("plc_model", product_name)
                if firmware:
                    result.setdefault("firmware", firmware)
                result.setdefault("role", "plc")

            # --- DNP3 device attribute strings ---
            if proto.protocol == "DNP3":
                vendor_name  = proto.details.get("vendor_name")
                product_name = proto.details.get("product_model")
                firmware     = proto.details.get("firmware_version")
                if vendor_name and "vendor" not in result:
                    result["vendor"]     = vendor_name
                    result["confidence"] = "high"
                if product_name:
                    result.setdefault("plc_model", product_name)
                if firmware:
                    result.setdefault("firmware", firmware)
                result.setdefault("role", "plc")

            # --- IEC 104 —  no vendor strings, but sets role ---
            if proto.protocol == "IEC 60870-5-104":
                result.setdefault("role", "plc")

        # --- OUI-based vendor enrichment (lower priority) ---
        if device.mac and "vendor" not in result:
            oui_vendor = lookup_oui(device.mac)
            if oui_vendor:
                result["vendor"]     = oui_vendor
                result["confidence"] = "medium"
                # Map OUI vendor to plc_make
                make = CIP_VENDOR_MAKE_MAP.get(oui_vendor, {}).get("plc_make", oui_vendor)
                result.setdefault("plc_make", make)

        return result if result else None

    # ------------------------------------------------------------------ helpers

    def _extract_model_from_proto(self, result: dict, proto) -> None:
        """Pull model/firmware from S7comm or FINS or MELSEC details."""
        d = proto.details

        # S7comm
        cpu_family = d.get("cpu_family")
        cpu_model  = d.get("cpu_model_hint") or d.get("cpu_name") or d.get("cpu_model")
        firmware   = d.get("firmware_version")
        serial     = d.get("serial_number")

        if cpu_family:
            result.setdefault("plc_model", cpu_family)
        if cpu_model and not result.get("plc_model"):
            result["plc_model"] = cpu_model.strip()
        if firmware:
            result.setdefault("firmware", firmware)
        if serial:
            result.setdefault("serial_number", serial)

        # FINS model
        fins_model = d.get("plc_model_raw")
        if fins_model and not result.get("plc_model"):
            result["plc_model"] = fins_model

        # MELSEC model
        melsec_model = d.get("cpu_model") or d.get("cpu_name")
        if melsec_model and not result.get("plc_model"):
            result["plc_model"] = melsec_model
