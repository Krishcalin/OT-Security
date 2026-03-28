"""
Omron FINS (Factory Interface Network Service) Protocol Analyzer
Port: UDP 9600

FINS is Omron's proprietary network protocol used across all major Omron
PLC families: CJ1/CJ2, CS1, NJ, NX, CP, CVM1.

FINS Frame Structure (header = 10 bytes):
  ICF  : 1 byte  --- Information Control Field
         Bit 7: 0=command, 1=response
         Bit 6: 1 (always)
         Bit 0: Response required (0=yes, 1=no)
  RSV  : 1 byte  --- Reserved (always 0x00)
  GCT  : 1 byte  --- Gateway Count (max hops, usually 0x02)
  DNA  : 1 byte  --- Destination Network Address (0=local)
  DA1  : 1 byte  --- Destination Node Number
  DA2  : 1 byte  --- Destination Unit Address (0x00=CPU, 0xFE=broadcast)
  SNA  : 1 byte  --- Source Network Address
  SA1  : 1 byte  --- Source Node Number
  SA2  : 1 byte  --- Source Unit Address
  SID  : 1 byte  --- Service ID (transaction ID)
  MRC  : 1 byte  --- Main Request Code (only in command/response)
  SRC  : 1 byte  --- Sub Request Code

Common command codes:
  0x01 0x01 --- Memory Area Read
  0x04 0x01 --- Controller Data Read  <- exposes model name
  0x05 0x01 --- Controller Status Read
  0x06 0x03 --- Clock Read
  0x09 0x20 --- Program Area Read
"""
import struct
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

FINS_PORT = 9600

# FINS main request codes (MRC) and sub request codes (SRC)
FINS_COMMANDS = {
    (0x01, 0x01): "Memory Area Read",
    (0x01, 0x02): "Memory Area Write",
    (0x01, 0x04): "Memory Area Fill",
    (0x02, 0x01): "Parameter Area Read",
    (0x02, 0x02): "Parameter Area Write",
    (0x02, 0x03): "Parameter Area Fill",
    (0x03, 0x06): "Run",
    (0x03, 0x04): "Stop",
    (0x04, 0x01): "Controller Data Read",
    (0x04, 0x02): "Connection Data Read",
    (0x05, 0x01): "Controller Status Read",
    (0x05, 0x02): "Network Status Read",
    (0x06, 0x01): "Clock Read",
    (0x06, 0x02): "Clock Write",
    (0x09, 0x20): "Program Area Read",
    (0x21, 0x02): "Error Clear",
    (0x21, 0x03): "Error Log Read",
    (0x26, 0x01): "File Name Read",
}

# Known Omron CPU model prefixes
OMRON_CPU_MODELS = {
    "CJ1M": "CJ1M Series",
    "CJ1H": "CJ1H Series",
    "CJ2M": "CJ2M Series",
    "CJ2H": "CJ2H Series",
    "CS1H": "CS1H Series",
    "CS1G": "CS1G Series",
    "CP1L": "CP1L Series",
    "CP1H": "CP1H Series",
    "CP2E": "CP2E Series",
    "NX1P": "NX1P Series (Sysmac)",
    "NX102": "NX102 Series (Sysmac)",
    "NJ101": "NJ101 Series (Sysmac)",
    "NJ301": "NJ301 Series (Sysmac)",
    "NJ501": "NJ501 Series (Sysmac)",
}


class FINSAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "UDP":
            return False
        if sport != FINS_PORT and dport != FINS_PORT:
            return False
        return len(payload) >= 10

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        header = self._parse_fins_header(payload)
        if header is None:
            return None

        icf, gct, dna, da1, da2, sna, sa1, sa2, sid, mrc, src_code = header
        is_response = bool(icf & 0x40)

        # Device is on the FINS server port (9600)
        device_ip = dst_ip if dport == FINS_PORT else src_ip

        cmd_name = FINS_COMMANDS.get((mrc, src_code), f"MRC=0x{mrc:02X} SRC=0x{src_code:02X}")

        details: dict = {
            "fins_command": cmd_name,
            "direction": "response" if is_response else "request",
            "dest_node":    da1,
            "dest_unit":    f"0x{da2:02X}",
            "src_node":     sa1,
            "service_id":   sid,
            "vendor":       "Omron",
        }

        confidence = "high"

        # For Controller Data Read response (0x04, 0x01) --- parse device model
        if is_response and mrc == 0x04 and src_code == 0x01:
            model_info = self._parse_controller_data(payload[12:])
            if model_info:
                details.update(model_info)

        detection = self._make_detection(
            protocol="Omron FINS",
            port=FINS_PORT,
            confidence=confidence,
            timestamp=timestamp,
            transport="UDP",
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_fins_header(self, payload: bytes):
        """
        Parse 10-byte FINS header (+ 2 command bytes if present).
        Returns tuple or None.
        """
        if len(payload) < 12:
            return None

        icf = payload[0]
        rsv = payload[1]
        gct = payload[2]
        dna = payload[3]
        da1 = payload[4]
        da2 = payload[5]
        sna = payload[6]
        sa1 = payload[7]
        sa2 = payload[8]
        sid = payload[9]
        mrc = payload[10]
        src = payload[11]

        # Validate: RSV must be 0, ICF bit6 must be 1
        if rsv != 0x00:
            return None
        if not (icf & 0x40):
            return None
        if gct > 7:         # GCT > 7 is unrealistic
            return None

        return icf, gct, dna, da1, da2, sna, sa1, sa2, sid, mrc, src

    def _parse_controller_data(self, data: bytes) -> Optional[dict]:
        """
        Parse Controller Data Read (0x04/0x01) response body.
        Offset 0-1: end code (0x0000 = OK)
        Offset 2+: variable-length fields for controller model and version
        """
        if len(data) < 4:
            return None

        end_code = struct.unpack_from(">H", data, 0)[0]
        if end_code != 0x0000:
            return {"fins_end_code": f"0x{end_code:04X}"}

        result = {}
        # Attempt to read 20-byte model field at offset 2
        if len(data) >= 22:
            model_raw = data[2:22].decode("latin-1", errors="replace").strip("\x00").strip()
            if model_raw:
                result["plc_model_raw"] = model_raw
                for prefix, family in OMRON_CPU_MODELS.items():
                    if model_raw.startswith(prefix):
                        result["cpu_family"] = family
                        break

        # Version field (4 bytes after model)
        if len(data) >= 26:
            ver_raw = data[22:26].decode("latin-1", errors="replace").strip("\x00").strip()
            if ver_raw:
                result["firmware_version"] = ver_raw

        return result if result else None
