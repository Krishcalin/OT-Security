"""
Modbus/TCP Protocol Analyzer  (RFC 1006 / IEC 61158-5-15)
Port: TCP 502

Modbus is vendor-agnostic but heavily used by:
  Schneider Electric (Modicon M340/M580/Quantum/Premium)
  Rockwell Automation (MicroLogix via Modbus gateway)
  Siemens (via Modbus gateway)
  ABB, Honeywell, and many others

FC 43 / MEI (Read Device Identification) responses contain rich vendor data.
"""
import struct
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

MODBUS_PORT = 502

# Modbus function codes
FC_READ_COILS            = 0x01
FC_READ_DISCRETE_INPUTS  = 0x02
FC_READ_HOLD_REGS        = 0x03
FC_READ_INPUT_REGS       = 0x04
FC_WRITE_SINGLE_COIL     = 0x05
FC_WRITE_SINGLE_REG      = 0x06
FC_WRITE_MULTI_COILS     = 0x0F
FC_WRITE_MULTI_REGS      = 0x10
FC_MASK_WRITE_REG        = 0x16
FC_READ_WRITE_MULTI_REGS = 0x17
FC_MEI                   = 0x2B   # Read Device Identification (subtype 0x0E)
FC_ERROR_OFFSET          = 0x80   # Set on error response

MEI_SUBTYPE_DEVICE_ID = 0x0E

# MEI Device ID object codes
MEI_OBJECTS = {
    0x00: "vendor_name",
    0x01: "product_code",
    0x02: "firmware_version",
    0x03: "vendor_url",
    0x04: "product_name",
    0x05: "model_name",
    0x06: "application_name",
}

# Vendor-name strings -> known make
VENDOR_NAME_MAP = {
    "schneider": "Schneider Electric",
    "modicon":   "Schneider Electric",
    "rockwell":  "Rockwell Automation",
    "allen-bradley": "Rockwell Automation",
    "siemens":   "Siemens",
    "abb":       "ABB",
    "honeywell": "Honeywell",
    "ge":        "GE Automation",
    "omron":     "Omron",
    "mitsubishi": "Mitsubishi Electric",
    "yokogawa":  "Yokogawa",
    "advantech": "Advantech",
    "wago":      "WAGO",
    "beckhoff":  "Beckhoff",
    "phoenix":   "Phoenix Contact",
    "moxa":      "Moxa Technologies",
    "emerson":   "Emerson Electric",
}

ALL_FUNCTION_CODES = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x1A, 0x1B, 0x2B,
}


class ModbusAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport != MODBUS_PORT and dport != MODBUS_PORT:
            return False
        return len(payload) >= 8

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        parsed = self._parse_mbap(payload)
        if parsed is None:
            return None

        fc, unit_id, data = parsed
        # Device (server) is the one on port 502
        device_ip = dst_ip if dport == MODBUS_PORT else src_ip
        device_port = MODBUS_PORT
        is_response = (sport == MODBUS_PORT)

        details: dict = {
            "function_code": f"0x{fc:02X}",
            "function_name": _fc_name(fc),
            "unit_id": unit_id,
            "direction": "response" if is_response else "request",
        }

        confidence = "high"

        # Try to extract rich device information from MEI response
        if fc == FC_MEI and is_response and len(data) >= 3:
            mei_details = self._parse_mei_response(data)
            if mei_details:
                details.update(mei_details)
                confidence = "high"

        # Error response
        if fc & FC_ERROR_OFFSET:
            details["error_code"] = f"0x{data[0]:02X}" if data else "unknown"
            details["function_code"] = f"0x{(fc & 0x7F):02X} (error)"

        detection = self._make_detection(
            protocol="Modbus/TCP",
            port=device_port,
            confidence=confidence,
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_mbap(self, payload: bytes):
        """
        Parse Modbus Application Protocol header.
        Returns (function_code, unit_id, pdu_data) or None on failure.
        """
        if len(payload) < 8:
            return None
        try:
            transaction_id, protocol_id, length, unit_id = struct.unpack_from(">HHHB", payload, 0)
        except struct.error:
            return None

        if protocol_id != 0x0000:          # Must be 0 for Modbus
            return None
        if length < 2 or length > 260:      # Sane length bounds
            return None

        fc = payload[7]
        if fc not in ALL_FUNCTION_CODES and (fc & 0x7F) not in ALL_FUNCTION_CODES:
            return None

        data = payload[8:7 + length]        # PDU data after FC byte
        return fc, unit_id, data

    def _parse_mei_response(self, data: bytes) -> Optional[dict]:
        """
        Parse MEI Read Device Identification response (FC 43, sub 0x0E).
        data starts at the byte after the FC byte.
        """
        if len(data) < 5:
            return None
        mei_type = data[0]
        if mei_type != MEI_SUBTYPE_DEVICE_ID:
            return None

        # read_device_id_code = data[1]
        # conformity_level    = data[2]
        # more_follows        = data[3]
        # next_object_id      = data[4]
        num_objects = data[5] if len(data) > 5 else 0

        result = {}
        offset = 6
        for _ in range(num_objects):
            if offset + 2 > len(data):
                break
            obj_id  = data[offset]
            obj_len = data[offset + 1]
            offset += 2
            if offset + obj_len > len(data):
                break
            obj_val = data[offset: offset + obj_len].decode("latin-1", errors="replace").strip()
            offset += obj_len
            key = MEI_OBJECTS.get(obj_id, f"object_0x{obj_id:02X}")
            result[key] = obj_val

        if not result:
            return None

        # Try to infer vendor / make from the strings
        combined = " ".join(result.values()).lower()
        for keyword, make in VENDOR_NAME_MAP.items():
            if keyword in combined:
                result["inferred_make"] = make
                break

        return result


def _fc_name(fc: int) -> str:
    names = {
        0x01: "Read Coils",
        0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers",
        0x04: "Read Input Registers",
        0x05: "Write Single Coil",
        0x06: "Write Single Register",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
        0x11: "Report Server ID",
        0x16: "Mask Write Register",
        0x17: "Read/Write Multiple Registers",
        0x2B: "MEI / Read Device Identification",
    }
    bare = fc & 0x7F
    name = names.get(bare, f"FC 0x{bare:02X}")
    return f"{name} [ERROR]" if fc & 0x80 else name
