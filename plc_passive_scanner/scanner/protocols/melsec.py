"""
Mitsubishi MELSEC MC Protocol (3E / 4E Frame) Analyzer
Ports: TCP 5007 (default), TCP 5006, TCP 5008

Used exclusively by Mitsubishi Electric MELSEC PLCs:
  MELSEC Q Series (QnUDE, QnUDV)
  MELSEC iQ-R Series (RnCPU, RnENCPU)
  MELSEC iQ-F Series (FX5U, FX5UC, FX5UJ)
  MELSEC L Series (LCPU)
  MELSEC System Q (Q2MEM)

3E Frame structure:
  Sub header      : 2 bytes  — 0x50 0x00
  Serial number   : 2 bytes LE  — echoed in response
  Reserved        : 2 bytes  — 0x00 0x00
  Network No.     : 1 byte
  PC No.          : 1 byte   — 0xFF = own station
  I/O Request No. : 2 bytes LE  — 0x03FF = own station CPU
  Station No.     : 1 byte
  Request data len: 2 bytes LE
  CPU monitoring timer: 2 bytes LE
  Command         : 2 bytes LE
  Subcommand      : 2 bytes LE
  Data            : variable

4E Frame adds:
  Access route serial : 2 bytes (after sub header 0x54 0x00)
  Reserved (2 bytes)
  Then follows the same structure as 3E from Serial number onwards.
"""
import struct
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

MELSEC_PORTS = {5007, 5006, 5008}

# Sub-headers
SUBHDR_3E = b"\x50\x00"
SUBHDR_4E = b"\x54\x00"

# MELSEC MC Protocol commands (selection)
MELSEC_COMMANDS = {
    (0x0401, 0x0000): "Batch Read Bit",
    (0x0401, 0x0001): "Batch Read Bit (extended)",
    (0x0403, 0x0000): "Batch Read Word",
    (0x0403, 0x0001): "Batch Read Word (extended)",
    (0x1401, 0x0000): "Batch Write Bit",
    (0x1401, 0x0001): "Batch Write Bit (extended)",
    (0x1403, 0x0000): "Batch Write Word",
    (0x1403, 0x0001): "Batch Write Word (extended)",
    (0x0601, 0x0000): "Random Read Bit",
    (0x0603, 0x0000): "Random Read Word",
    (0x1601, 0x0000): "Random Write Bit",
    (0x1603, 0x0000): "Random Write Word",
    (0x0619, 0x0000): "Block Read Word",
    (0x1619, 0x0000): "Block Write Word",
    (0x0E91, 0x0000): "Self Test",
    (0x0619, 0x0001): "Remote Run",
    (0x0621, 0x0000): "Remote Stop",
    (0x0622, 0x0000): "Remote Pause",
    (0x0623, 0x0000): "Remote Latch Clear",
    (0x0625, 0x0000): "Remote Reset",
    (0x0631, 0x0000): "Read CPU Type Info",   # ← reveals CPU model
    (0x0634, 0x0000): "Read CPU Model",
}

# CPU type code to model mapping (common entries)
MELSEC_CPU_TYPES = {
    0x08: "Q02UCPU",
    0x09: "Q04UDCPU",
    0x0A: "Q06UDCPU",
    0x0B: "Q13UDCPU",
    0x0C: "Q26UDCPU",
    0x0E: "Q04UDVCPU",
    0x0F: "Q06UDVCPU",
    0x10: "Q13UDVCPU",
    0x11: "Q26UDVCPU",
    0x12: "Q50UDVCPU",
    0x13: "Q100UDVCPU",
    0x15: "R04CPU",
    0x16: "R08CPU",
    0x17: "R16CPU",
    0x18: "R32CPU",
    0x19: "R120CPU",
    0x1A: "R04ENCPU",
    0x1B: "R08ENCPU",
    0x1C: "R16ENCPU",
    0x1D: "R32ENCPU",
    0x1E: "R120ENCPU",
    0x20: "FX5U",
    0x21: "FX5UC",
    0x22: "FX5UJ",
}


class MELSECAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport not in MELSEC_PORTS and dport not in MELSEC_PORTS:
            return False
        if len(payload) < 9:
            return False
        return payload[:2] in (SUBHDR_3E, SUBHDR_4E)

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        # Determine frame type
        is_4e = payload[:2] == SUBHDR_4E
        frame_type = "4E" if is_4e else "3E"

        # Parse based on frame type
        parsed = self._parse_3e(payload) if not is_4e else self._parse_4e(payload)
        if parsed is None:
            return None

        network_no, pc_no, io_req, station, data_len, cmd, subcmd, body = parsed
        device_ip = dst_ip if dport in MELSEC_PORTS else src_ip
        port_used  = dport if dport in MELSEC_PORTS else sport

        cmd_name = MELSEC_COMMANDS.get((cmd, subcmd),
                                       f"CMD=0x{cmd:04X} SUB=0x{subcmd:04X}")
        details: dict = {
            "melsec_frame":   frame_type,
            "melsec_command": cmd_name,
            "network_no":     network_no,
            "station_no":     station,
            "vendor":         "Mitsubishi Electric",
        }

        # Read CPU Type Info response → extract model
        if cmd == 0x0631 and body:
            cpu_info = self._parse_cpu_type_response(body)
            if cpu_info:
                details.update(cpu_info)

        detection = self._make_detection(
            protocol="MELSEC MC Protocol",
            port=port_used,
            confidence="high",
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_3e(self, payload: bytes):
        """Parse 3E frame header. Returns parsed fields or None."""
        # sub(2) serial(2) reserved(2) network(1) pc(1) io_req(2) station(1) datalen(2) = 13 bytes
        if len(payload) < 15:
            return None
        serial     = struct.unpack_from("<H", payload, 2)[0]
        network_no = payload[6]
        pc_no      = payload[7]
        io_req     = struct.unpack_from("<H", payload, 8)[0]
        station    = payload[10]
        data_len   = struct.unpack_from("<H", payload, 11)[0]

        # Command + Subcommand are first 4 bytes of data section
        if len(payload) < 13 + 4:
            return None
        cmd    = struct.unpack_from("<H", payload, 15)[0]  # after timer(2)
        subcmd = struct.unpack_from("<H", payload, 17)[0]
        body   = payload[19:]

        # Basic sanity: data_len should match
        if data_len < 6 or data_len > 1024:
            return None

        return network_no, pc_no, io_req, station, data_len, cmd, subcmd, body

    def _parse_4e(self, payload: bytes):
        """Parse 4E frame (adds access route serial + reserved before 3E fields)."""
        # sub(2) acc_serial(2) reserved(2) + same as 3E from serial(2)
        if len(payload) < 19:
            return None
        # Access route serial at bytes 2-3, reserved at 4-5
        # Then same as 3E starting at byte 6
        rest = b"\x50\x00" + payload[6:]   # Fake 3E subheader to reuse parser
        return self._parse_3e(rest)

    def _parse_cpu_type_response(self, data: bytes) -> Optional[dict]:
        """
        Parse response to Read CPU Type Info (0x0631).
        data[0:2] = End code (0x0000 = success)
        data[2:18] = CPU name string (16 chars)
        data[18:20] = CPU type code
        """
        if len(data) < 4:
            return None
        end_code = struct.unpack_from("<H", data, 0)[0]
        if end_code != 0x0000:
            return {"melsec_end_code": f"0x{end_code:04X}"}

        result = {}
        if len(data) >= 18:
            cpu_name = data[2:18].decode("latin-1", errors="replace").strip("\x00").strip()
            if cpu_name:
                result["cpu_name"] = cpu_name

        if len(data) >= 20:
            cpu_type_code = struct.unpack_from("<H", data, 18)[0]
            model = MELSEC_CPU_TYPES.get(cpu_type_code)
            if model:
                result["cpu_model"] = model
            result["cpu_type_code"] = f"0x{cpu_type_code:04X}"

        return result if result else None
