"""
EtherNet/IP (EIP) + CIP (Common Industrial Protocol) Analyzer
Ports:  TCP 44818  (explicit messaging)
        UDP 2222   (implicit / I/O messaging)

EtherNet/IP is the primary protocol for:
  Rockwell Automation / Allen-Bradley  (ControlLogix, CompactLogix, MicroLogix ...)
  Omron                                 (NJ/NX Series)
  Schneider Electric                   (Modicon M340/M580 with EIP module)
  Siemens                               (SIMATIC ET 200)
  Many third-party devices supporting ODVA CIP

The ListIdentity command (0x0063) response is the gold mine --- it contains
vendor ID, device type, product code, revision, serial number, and product name.
"""
import struct
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

EIP_TCP_PORT = 44818
EIP_UDP_PORT = 2222

# Encapsulation command codes
CMD_LIST_SERVICES  = 0x0004
CMD_LIST_IDENTITY  = 0x0063
CMD_LIST_INTERFACES = 0x0064
CMD_REGISTER_SESSION = 0x0065
CMD_UNREGISTER_SESSION = 0x0066
CMD_SEND_RR_DATA   = 0x006F
CMD_SEND_UNIT_DATA = 0x0070

# CIP item type codes
ITEM_NULL          = 0x0000
ITEM_CONNECTED_ADR = 0x0001
ITEM_CONNECTED_DATA = 0x00B1
ITEM_UNCONNECTED   = 0x00B2
ITEM_LIST_IDENTITY = 0x000C
ITEM_LIST_SERVICES = 0x0100

# ODVA CIP Vendor IDs (partial --- covers the major OT vendors)
CIP_VENDORS: dict = {
    0x0001: "Rockwell Automation",
    0x0002: "Namco Controls Corp.",
    0x000B: "Eagle Signal Controls",
    0x000C: "Honeywell International",
    0x0012: "Allen-Bradley Company",
    0x0016: "GE Automation & Controls",
    0x001D: "Omron Americas",
    0x001E: "Omron Electronics LLC",
    0x0022: "Omron",
    0x0030: "Fanuc Robotics",
    0x0034: "Omron Corporation",
    0x004E: "Schneider Electric",
    0x0051: "Beckhoff Automation",
    0x0055: "Parker Hannifin",
    0x006B: "Siemens Energy & Automation",
    0x006E: "Schneider Electric (Group)",
    0x0079: "Mitsubishi Electric",
    0x0085: "Phoenix Contact",
    0x0095: "Pepperl+Fuchs",
    0x0096: "Balluff",
    0x00AE: "Emerson Network Power",
    0x00C7: "Mitsubishi Electric Automation",
    0x00EB: "WAGO Corporation",
    0x00F5: "Yokogawa Electric",
    0x0105: "ABB",
    0x0117: "Festo AG & Co.",
    0x012B: "Bosch Rexroth",
    0x014D: "Hirschmann Automation",
    0x015B: "Moxa Technologies",
    0x016C: "Turck",
}

# CIP Device Type codes
CIP_DEVICE_TYPES: dict = {
    0x00: "Generic Device",
    0x02: "AC Drive",
    0x04: "Position Controller",
    0x06: "Discrete I/O Device",
    0x07: "Limit Switch",
    0x09: "Motor Overload",
    0x0A: "Encoder",
    0x0C: "Analog I/O Device",
    0x10: "Programmable Logic Controller",
    0x12: "Soft Start",
    0x1D: "Communication Adapter",
    0x1E: "Bar Code Scanner",
    0x21: "Safety Discrete I/O Device",
    0x22: "Safety Drive",
    0x23: "Safety Encoder",
    0x25: "Safety Analog I/O Device",
    0x2C: "Managed Ethernet Switch",
}

# EIP Encapsulation header is always 24 bytes
EIP_HEADER_SIZE = 24


class EtherNetIPAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if sport in (EIP_TCP_PORT, EIP_UDP_PORT) or dport in (EIP_TCP_PORT, EIP_UDP_PORT):
            return len(payload) >= EIP_HEADER_SIZE
        return False

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        # Parse EIP encapsulation header
        hdr = self._parse_eip_header(payload)
        if hdr is None:
            return None

        command, length, session, status = hdr
        device_ip = dst_ip if dport in (EIP_TCP_PORT, EIP_UDP_PORT) else src_ip
        port_used = EIP_TCP_PORT

        details: dict = {
            "eip_command": f"0x{command:04X}",
            "eip_command_name": _cmd_name(command),
            "session_handle": f"0x{session:08X}" if session else None,
        }

        confidence = "high" if command in (CMD_LIST_IDENTITY, CMD_REGISTER_SESSION,
                                           CMD_SEND_RR_DATA, CMD_SEND_UNIT_DATA) else "medium"

        # ListIdentity response --- richest source of device info
        if command == CMD_LIST_IDENTITY and length > 0:
            body = payload[EIP_HEADER_SIZE:]
            identity = self._parse_list_identity(body)
            if identity:
                details.update(identity)
                confidence = "high"

        # RegisterSession --- confirms EIP endpoint
        elif command == CMD_REGISTER_SESSION:
            details["connection_type"] = "EIP session established"

        detection = self._make_detection(
            protocol="EtherNet/IP",
            port=port_used,
            confidence=confidence,
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_eip_header(self, payload: bytes):
        """Parse 24-byte EIP encapsulation header."""
        if len(payload) < EIP_HEADER_SIZE:
            return None
        try:
            command, length, session, status = struct.unpack_from("<HHII", payload, 0)
        except struct.error:
            return None

        # Basic sanity checks
        if command not in (CMD_LIST_SERVICES, CMD_LIST_IDENTITY, CMD_LIST_INTERFACES,
                           CMD_REGISTER_SESSION, CMD_UNREGISTER_SESSION,
                           CMD_SEND_RR_DATA, CMD_SEND_UNIT_DATA):
            return None
        if length > 65511:          # EIP max payload
            return None

        return command, length, session, status

    def _parse_list_identity(self, body: bytes) -> Optional[dict]:
        """
        Parse the body of a ListIdentity response.
        Returns dict with vendor, product name, revision, serial, etc.
        """
        if len(body) < 4:
            return None

        # Item count (2 bytes LE)
        item_count = struct.unpack_from("<H", body, 0)[0]
        if item_count == 0:
            return None

        offset = 2
        result = {}

        for _ in range(item_count):
            if offset + 4 > len(body):
                break
            item_type = struct.unpack_from("<H", body, offset)[0]
            item_len  = struct.unpack_from("<H", body, offset + 2)[0]
            offset += 4
            item_data  = body[offset: offset + item_len]
            offset    += item_len

            if item_type != ITEM_LIST_IDENTITY:
                continue

            # CIP Identity Item structure
            # [0:2]   Encap protocol version
            # [2:18]  Socket address (sin_family, sin_port, sin_addr, sin_zero)
            # [18:20] Vendor ID
            # [20:22] Device Type
            # [22:24] Product Code
            # [24:25] Major revision
            # [25:26] Minor revision
            # [26:28] Status
            # [28:32] Serial Number
            # [32]    Product Name length
            # [33:..] Product Name (ASCII)
            # last byte: State
            if len(item_data) < 33:
                continue

            vendor_id    = struct.unpack_from("<H", item_data, 18)[0]
            device_type  = struct.unpack_from("<H", item_data, 20)[0]
            product_code = struct.unpack_from("<H", item_data, 22)[0]
            rev_major    = item_data[24]
            rev_minor    = item_data[25]
            status       = struct.unpack_from("<H", item_data, 26)[0]
            serial_num   = struct.unpack_from("<I", item_data, 28)[0]
            name_len     = item_data[32]

            product_name = ""
            if 33 + name_len <= len(item_data):
                product_name = item_data[33: 33 + name_len].decode("latin-1",
                                                                     errors="replace").strip()

            vendor_name = CIP_VENDORS.get(vendor_id, f"VendorID 0x{vendor_id:04X}")
            device_type_name = CIP_DEVICE_TYPES.get(device_type,
                                                     f"Type 0x{device_type:04X}")

            result = {
                "cip_vendor_id":    f"0x{vendor_id:04X}",
                "cip_vendor_name":  vendor_name,
                "cip_device_type":  device_type_name,
                "cip_product_code": product_code,
                "cip_revision":     f"{rev_major}.{rev_minor:02d}",
                "cip_serial":       f"0x{serial_num:08X}",
                "cip_product_name": product_name,
                "cip_status":       f"0x{status:04X}",
            }
            break   # Only need first item

        return result if result else None


def _cmd_name(cmd: int) -> str:
    return {
        CMD_LIST_SERVICES:        "ListServices",
        CMD_LIST_IDENTITY:        "ListIdentity",
        CMD_LIST_INTERFACES:      "ListInterfaces",
        CMD_REGISTER_SESSION:     "RegisterSession",
        CMD_UNREGISTER_SESSION:   "UnRegisterSession",
        CMD_SEND_RR_DATA:         "SendRRData",
        CMD_SEND_UNIT_DATA:       "SendUnitData",
    }.get(cmd, f"0x{cmd:04X}")
