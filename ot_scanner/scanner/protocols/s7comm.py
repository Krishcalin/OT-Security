"""
Siemens S7comm / S7comm+ Protocol Analyzer
Port: TCP 102 (ISO-TSAP / COTP transport)

S7comm is exclusively Siemens.  It carries the S7 PDU over COTP (ISO 8073)
which runs over ISO-TSAP (RFC 1006) on TCP/102.

PDU type 7 (Userdata) carries SZL reads that expose CPU model and firmware.

S7comm+ (TLS, port 102) is used by S7-1200/1500 with newer firmware --- the
COTP/S7 header structure remains recognisable even when TLS is in use for
the payload, so we can still fingerprint the connection setup phase.
"""
import struct
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

S7_PORT = 102

# COTP PDU types
COTP_CR = 0xE0   # Connection Request
COTP_CC = 0xD0   # Connection Confirm
COTP_DT = 0xF0   # Data Transfer
COTP_DR = 0x80   # Disconnect Request

# S7 Protocol ID
S7_PROTO_ID = 0x32

# S7 ROSCTR (PDU types)
S7_JOB      = 0x01
S7_ACK      = 0x02
S7_ACK_DATA = 0x03
S7_USERDATA = 0x07

# Known SZL IDs (System Status List) used for device identification
SZL_CPU_ID   = 0x0011   # CPU identification (model, firmware, serial)
SZL_COMP_ID  = 0x001C   # Component identification
SZL_DIAG     = 0x0A91   # Diagnostic buffer

# CPU type strings -> model family
CPU_MODEL_HINTS = {
    "1200": "S7-1200",
    "1500": "S7-1500",
    "1516": "S7-1500",
    "1515": "S7-1500",
    "1513": "S7-1500",
    "1511": "S7-1500",
    "1214": "S7-1200",
    "1215": "S7-1200",
    "1217": "S7-1200",
    "315":  "S7-300",
    "317":  "S7-300",
    "319":  "S7-300",
    "300":  "S7-300",
    "400":  "S7-400",
    "412":  "S7-400",
    "414":  "S7-400",
    "416":  "S7-400",
    "WinAC": "WinAC RTX",
}


class S7CommAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport != S7_PORT and dport != S7_PORT:
            return False
        return len(payload) >= 4

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        device_ip = dst_ip if dport == S7_PORT else src_ip
        details = {}
        confidence = "medium"
        protocol_name = "S7comm"

        # ----- Try to parse COTP header -----
        cotp = self._parse_cotp(payload)
        if cotp is None:
            return None

        cotp_type, cotp_data = cotp
        details["cotp_pdu_type"] = f"0x{cotp_type:02X}"

        if cotp_type in (COTP_CR, COTP_CC):
            # Connection setup --- extract TSAP info (rack / slot)
            tsap_info = self._extract_tsap(payload)
            if tsap_info:
                details.update(tsap_info)
            confidence = "high"

        elif cotp_type == COTP_DT:
            # Data --- look for S7 PDU
            s7 = self._parse_s7_pdu(cotp_data)
            if s7 is None:
                return None
            confidence = "high"
            rosctr, s7_details = s7
            details.update(s7_details)

            # Check for S7+ / S7-1500 TLS indicator
            if b"\x72\x65\x6c\x65\x61\x73\x65" in cotp_data:   # "release"
                protocol_name = "S7comm+"
                details["tls_protected"] = True

        else:
            # Disconnect or unknown --- mild evidence
            confidence = "low"

        detection = self._make_detection(
            protocol=protocol_name,
            port=S7_PORT,
            confidence=confidence,
            timestamp=timestamp,
            vendor="Siemens",
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_cotp(self, payload: bytes):
        """
        Parse the RFC 1006 (ISO-TSAP) + COTP header.
        Returns (pdu_type, data_after_cotp_header) or None.
        """
        # RFC 1006 TPKT header: version(1) reserved(1) length(2)
        if len(payload) < 4:
            return None
        version = payload[0]
        if version != 0x03:        # TPKT version must be 3
            return None

        tpkt_len = struct.unpack_from(">H", payload, 2)[0]
        if tpkt_len < 7 or tpkt_len > len(payload):
            return None

        # COTP header starts at offset 4
        cotp_offset = 4
        cotp_len_indicator = payload[cotp_offset]       # bytes following (not incl. LI byte)
        if cotp_offset + 1 + cotp_len_indicator > len(payload):
            return None

        cotp_type = payload[cotp_offset + 1]
        cotp_end  = cotp_offset + 1 + cotp_len_indicator
        remainder = payload[cotp_end:]

        return cotp_type, remainder

    def _extract_tsap(self, payload: bytes) -> Optional[dict]:
        """
        Extract source/destination TSAP from COTP CR/CC.
        For S7-300/400 the destination TSAP encodes rack and slot.
        """
        details = {}
        # Scan for TSAP parameters in COTP variable part
        # Parameter code 0xC1 = src TSAP, 0xC2 = dst TSAP
        idx = 7
        while idx + 2 < len(payload):
            code   = payload[idx]
            length = payload[idx + 1]
            if idx + 2 + length > len(payload):
                break
            value = payload[idx + 2: idx + 2 + length]
            if code == 0xC1:
                details["src_tsap"] = value.hex()
            elif code == 0xC2 and len(value) >= 2:
                details["dst_tsap"] = value.hex()
                # High byte: type (01=PG, 02=OP, 03=Step7)
                # Low byte: (rack << 5) | slot
                rack = (value[1] >> 5) & 0x07
                slot = value[1] & 0x1F
                details["rack"] = rack
                details["slot"] = slot
                tsap_type_map = {0x01: "PG (Programming Device)",
                                 0x02: "OP (Operator Panel)",
                                 0x03: "Step 7 / TIA Portal"}
                details["connection_type"] = tsap_type_map.get(value[0], f"0x{value[0]:02X}")
            idx += 2 + length
        return details if details else None

    def _parse_s7_pdu(self, data: bytes):
        """
        Parse a Siemens S7 PDU.
        Returns (rosctr, details_dict) or None.
        """
        if len(data) < 10:
            return None
        if data[0] != S7_PROTO_ID:
            return None

        rosctr     = data[1]
        pdu_ref    = struct.unpack_from(">H", data, 4)[0]
        param_len  = struct.unpack_from(">H", data, 6)[0]
        data_len   = struct.unpack_from(">H", data, 8)[0]

        details = {
            "s7_rosctr": _rosctr_name(rosctr),
            "pdu_reference": pdu_ref,
        }

        if rosctr == S7_USERDATA and len(data) >= 17:
            ud_details = self._parse_s7_userdata(data, param_len, data_len)
            if ud_details:
                details.update(ud_details)

        elif rosctr == S7_ACK_DATA and len(data) >= 12:
            # Read SZL response --- contains CPU identification
            szl_details = self._parse_szl_ack(data, param_len, data_len)
            if szl_details:
                details.update(szl_details)

        return rosctr, details

    def _parse_s7_userdata(self, data: bytes, param_len: int, data_len: int) -> dict:
        """Parse S7 Userdata PDU (read SZL request/response)."""
        details = {}
        param_start = 10
        if param_start + param_len > len(data):
            return details

        params = data[param_start: param_start + param_len]
        # Userdata parameter block: header(4) + type/func(1) + seq_num(1) + ...
        if len(params) >= 8:
            func_group = (params[4] >> 4) & 0x0F   # High nibble
            func_code  = params[4] & 0x0F           # Low nibble
            # Group 4 = CPU functions, Func 1 = Read SZL
            if func_group == 4 and func_code == 1:
                details["s7_function"] = "Read SZL (System Status List)"
                # Extract SZL ID from the data section if present
                data_start = param_start + param_len
                if data_start + 6 < len(data):
                    szl_block = data[data_start:]
                    if len(szl_block) >= 6:
                        szl_id  = struct.unpack_from(">H", szl_block, 4)[0]
                        details["szl_id"] = f"0x{szl_id:04X}"
                        szl_name = {
                            0x0011: "CPU identification",
                            0x001C: "Component identification",
                            0x0A91: "Diagnostic buffer",
                            0x0131: "Communication capability",
                        }.get(szl_id, "Unknown")
                        details["szl_name"] = szl_name
        return details

    def _parse_szl_ack(self, data: bytes, param_len: int, data_len: int) -> dict:
        """Parse SZL response data from an S7 Ack-Data PDU."""
        details = {}
        param_start = 10
        if param_start + param_len > len(data):
            return details

        # Data block follows parameter block
        data_start = param_start + param_len

        # Ack-Data header: return_code(1) + transport_size(1) + data_length(2)
        # then SZL header: szl_id(2) + szl_index(2) + ...
        if data_start + 8 > len(data):
            return details

        return_code = data[data_start]
        if return_code != 0xFF:  # 0xFF = success
            return details

        szl_id = struct.unpack_from(">H", data, data_start + 4)[0]
        details["szl_id"] = f"0x{szl_id:04X}"

        payload = data[data_start + 8:]

        if szl_id == SZL_CPU_ID:
            self._parse_szl_0011(payload, details)
        elif szl_id == SZL_COMP_ID:
            self._parse_szl_001c(payload, details)
        else:
            self._parse_szl_fallback(payload, details)

        return details

    def _parse_szl_0011(self, payload: bytes, details: dict) -> None:
        """Parse SZL 0x0011 (Module Identification) records.

        Each record is typically 28 bytes:
          index(2) + order_number(20) + reserved(2) + firmware_version(4)
        """
        if len(payload) < 4:
            self._parse_szl_fallback(payload, details)
            return

        record_len = struct.unpack_from(">H", payload, 0)[0]
        record_count = struct.unpack_from(">H", payload, 2)[0]

        if record_len < 28 or record_count == 0:
            self._parse_szl_fallback(payload, details)
            return

        offset = 4
        for _ in range(record_count):
            if offset + record_len > len(payload):
                break
            rec = payload[offset:offset + record_len]
            idx = struct.unpack_from(">H", rec, 0)[0]
            order_number = rec[2:22].decode("latin-1", errors="replace") \
                .strip("\x00").strip()
            fw_bytes = rec[24:28]

            fw_str = None
            if len(fw_bytes) >= 3 and any(b != 0 for b in fw_bytes[:3]):
                fw_str = f"V{fw_bytes[0]}.{fw_bytes[1]}.{fw_bytes[2]}"

            if idx == 1:  # Index 1 = CPU module
                if order_number:
                    details["order_number"] = order_number
                    details["plc_vendor"] = "Siemens"
                    self._model_from_order_number(order_number, details)
                if fw_str:
                    details["firmware_version"] = fw_str
            elif idx == 7:  # Index 7 = serial number (some CPUs)
                serial = rec[2:22].decode("latin-1", errors="replace") \
                    .strip("\x00").strip()
                if serial and not serial.isspace():
                    details["serial_number"] = serial

            offset += record_len

    def _parse_szl_001c(self, payload: bytes, details: dict) -> None:
        """Parse SZL 0x001C (Component Identification) records.

        Provides a list of all modules in the rack — used for module inventory.
        """
        if len(payload) < 4:
            self._parse_szl_fallback(payload, details)
            return

        record_len = struct.unpack_from(">H", payload, 0)[0]
        record_count = struct.unpack_from(">H", payload, 2)[0]

        if record_len < 4 or record_count == 0:
            self._parse_szl_fallback(payload, details)
            return

        name_end = min(record_len, 26)  # name field up to 24 bytes
        modules = []
        offset = 4
        for _ in range(record_count):
            if offset + record_len > len(payload):
                break
            rec = payload[offset:offset + record_len]
            idx = struct.unpack_from(">H", rec, 0)[0]
            name = rec[2:name_end].decode("latin-1", errors="replace") \
                .strip("\x00").strip()

            if name:
                modules.append({
                    "slot": idx,
                    "name": name,
                    "type": "CPU" if idx == 1 else "Module",
                })
                if idx == 1:
                    details["cpu_info"] = name
                    details["plc_vendor"] = "Siemens"

            offset += record_len

        if modules:
            details["modules"] = modules

    def _parse_szl_fallback(self, payload: bytes, details: dict) -> None:
        """Fallback: scan for printable ASCII in unrecognised SZL payloads."""
        text_chunk = payload.decode("latin-1", errors="replace")
        for hint_key, model_family in CPU_MODEL_HINTS.items():
            if hint_key in text_chunk:
                details["cpu_family"] = model_family
                details["plc_vendor"] = "Siemens"
                idx = text_chunk.find(hint_key)
                start = max(0, idx - 4)
                raw_model = text_chunk[start:start + 32].strip()
                details["cpu_model_hint"] = raw_model
                break

    def _model_from_order_number(self, order_number: str, details: dict) -> None:
        """Infer CPU model family from a Siemens MLFB order number."""
        if not order_number:
            return
        for hint_key, model_family in CPU_MODEL_HINTS.items():
            if hint_key in order_number:
                details["cpu_family"] = model_family
                break


def _rosctr_name(rosctr: int) -> str:
    return {
        0x01: "Job",
        0x02: "Ack",
        0x03: "Ack-Data",
        0x07: "Userdata",
    }.get(rosctr, f"0x{rosctr:02X}")
