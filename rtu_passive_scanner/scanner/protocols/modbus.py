"""
Modbus/TCP Analyzer — Simplified for RTU context
Port: TCP 502

In RTU environments Modbus/TCP is often used as a legacy or gateway protocol.
Many RTUs expose Modbus as a secondary interface.  Full MEI parsing from the
PLC scanner is included; the RTU scanner uses it for vendor fingerprinting.
"""
import struct
from datetime import datetime
from typing import Dict, Optional

from .base import BaseProtocolAnalyzer, AnalysisResult

MODBUS_PORT = 502
FC_MEI      = 0x2B
MEI_SUBTYPE = 0x0E
FC_ERROR    = 0x80

ALL_FC = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x0F, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18, 0x2B,
}
FC_NAMES: Dict[int, str] = {
    0x01: "Read Coils",           0x02: "Read Discrete Inputs",
    0x03: "Read Holding Regs",    0x04: "Read Input Regs",
    0x05: "Write Single Coil",    0x06: "Write Single Reg",
    0x0F: "Write Multiple Coils", 0x10: "Write Multiple Regs",
    0x11: "Report Server ID",     0x2B: "MEI (Device Identification)",
}
MEI_OBJECTS: Dict[int, str] = {
    0x00: "vendor_name",    0x01: "product_code",
    0x02: "firmware_version", 0x03: "vendor_url",
    0x04: "product_name",   0x05: "model_name",
}
VENDOR_MAP: Dict[str, str] = {
    "schneider": "Schneider Electric", "modicon": "Schneider Electric",
    "abb": "ABB",                       "honeywell": "Honeywell",
    "ge": "GE Grid Solutions",          "emerson": "Emerson",
    "rockwell": "Rockwell Automation",  "siemens": "Siemens",
}


class ModbusAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport, dport, proto, payload):
        return (proto == "TCP" and
                (sport == MODBUS_PORT or dport == MODBUS_PORT) and
                len(payload) >= 8)

    def analyze(self, src_ip, dst_ip, sport, dport, proto, payload, timestamp):
        if len(payload) < 8:
            return None
        try:
            _, proto_id, length, unit_id = struct.unpack_from(">HHHB", payload, 0)
        except struct.error:
            return None
        if proto_id != 0 or length < 2 or length > 260:
            return None

        fc      = payload[7]
        bare_fc = fc & 0x7F
        if bare_fc not in ALL_FC:
            return None

        device_ip = dst_ip if dport == MODBUS_PORT else src_ip
        is_resp   = (sport == MODBUS_PORT)
        details: Dict = {
            "function_code": f"0x{bare_fc:02X}",
            "function_name": FC_NAMES.get(bare_fc, f"FC 0x{bare_fc:02X}"),
            "unit_id":       unit_id,
            "direction":     "response" if is_resp else "request",
        }
        if fc & FC_ERROR:
            details["error"] = True

        # MEI device identification
        if bare_fc == FC_MEI and is_resp and len(payload) >= 13:
            mei = self._parse_mei(payload[8:])
            if mei:
                details.update(mei)

        det = self._make_detection(
            protocol="Modbus/TCP",
            port=MODBUS_PORT,
            confidence="high",
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, det)]

    def _parse_mei(self, data: bytes) -> Optional[Dict]:
        if len(data) < 6 or data[0] != MEI_SUBTYPE:
            return None
        num_objects = data[5] if len(data) > 5 else 0
        result: Dict = {}
        offset = 6
        for _ in range(num_objects):
            if offset + 2 > len(data):
                break
            obj_id, obj_len = data[offset], data[offset+1]
            offset += 2
            if offset + obj_len > len(data):
                break
            val = data[offset:offset+obj_len].decode("latin-1", errors="replace").strip()
            offset += obj_len
            key = MEI_OBJECTS.get(obj_id, f"obj_0x{obj_id:02X}")
            result[key] = val
        if result:
            combined = " ".join(result.values()).lower()
            for kw, make in VENDOR_MAP.items():
                if kw in combined:
                    result["inferred_make"] = make
                    break
        return result or None
