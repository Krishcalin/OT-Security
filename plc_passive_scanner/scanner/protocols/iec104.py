"""
IEC 60870-5-104 (IEC 104) Protocol Analyzer
Port: TCP 2404

IEC 104 is the network transport edition of IEC 60870-5-101, widely used
in power transmission and distribution for SCADA communications.

Common vendors: ABB, Siemens, Schneider Electric, Alstom (now GE Grid Solutions),
                Honeywell, SEL, Rockwell Automation (via gateways)

APDU (Application Protocol Data Unit):
  Start byte  : 0x68             (1 byte)
  APDU length : N                (1 byte — bytes following)
  Control field: 4 bytes — determines frame type:
    I-frame (Information):        bit 0 of byte 0 = 0
    S-frame (Supervisory):        bits 1-0 of byte 0 = 01
    U-frame (Unnumbered):         bits 1-0 of byte 0 = 11

U-frame function bits (byte 0):
  0x07 = STARTDT act   (master starts data transfer)
  0x0B = STARTDT con   (slave confirms)
  0x13 = STOPDT act
  0x23 = STOPDT con
  0x43 = TESTFR act    (heartbeat)
  0x83 = TESTFR con

I-frame ASDU (Application Service Data Unit):
  Type ID      : 1 byte
  VSQ          : 1 byte  (Variable Structure Qualifier)
  COT          : 2 bytes (Cause of Transmission)
  Common Addr  : 2 bytes (station address)
  IOA + data objects…

Key Type IDs:
  70  = M_EI_NA_1  — End of Initialization (device restart)
  100 = C_IC_NA_1  — General Interrogation command
  101 = C_CI_NA_1  — Counter Interrogation
"""
import struct
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

IEC104_PORT = 2404

IEC104_START_BYTE = 0x68

# U-frame types
U_FRAME_TYPES = {
    0x07: "STARTDT act",
    0x0B: "STARTDT con",
    0x13: "STOPDT act",
    0x23: "STOPDT con",
    0x43: "TESTFR act",
    0x83: "TESTFR con",
}

# ASDU Type IDs (selected)
ASDU_TYPES = {
    1:   "M_SP_NA_1 (Single Point Info)",
    3:   "M_DP_NA_1 (Double Point Info)",
    5:   "M_ST_NA_1 (Step Position)",
    7:   "M_BO_NA_1 (Bitstring 32-bit)",
    9:   "M_ME_NA_1 (Measured Value, Normalized)",
    11:  "M_ME_NB_1 (Measured Value, Scaled)",
    13:  "M_ME_NC_1 (Measured Value, Short Float)",
    15:  "M_IT_NA_1 (Integrated Totals)",
    30:  "M_SP_TB_1 (Single Point w/Time Tag)",
    31:  "M_DP_TB_1 (Double Point w/Time Tag)",
    36:  "M_ME_TF_1 (Meas. Value Short Float w/Time Tag)",
    45:  "C_SC_NA_1 (Single Command)",
    46:  "C_DC_NA_1 (Double Command)",
    48:  "C_SE_NA_1 (Set Point Command, Normalized)",
    50:  "C_SE_NC_1 (Set Point Command, Short Float)",
    70:  "M_EI_NA_1 (End of Initialization)",
    100: "C_IC_NA_1 (General Interrogation)",
    101: "C_CI_NA_1 (Counter Interrogation)",
    103: "C_CS_NA_1 (Clock Synchronization)",
    105: "C_RP_NA_1 (Reset Process)",
}

# Cause of Transmission codes (selection)
COT_NAMES = {
    1: "Periodic",
    2: "Background scan",
    3: "Spontaneous",
    4: "Initialized",
    5: "Request",
    6: "Activation",
    7: "Activation con",
    8: "Deactivation",
    9: "Deactivation con",
    10: "Activation term",
    11: "Return info rem",
    12: "Return info loc",
    13: "File transfer",
    20: "General interrogation",
    21: "Group 1 interrogation",
    44: "Unknown type ID",
    45: "Unknown COT",
    46: "Unknown common address",
    47: "Unknown IOA",
}


class IEC104Analyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport != IEC104_PORT and dport != IEC104_PORT:
            return False
        if len(payload) < 6:
            return False
        return payload[0] == IEC104_START_BYTE

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        apdu = self._parse_apdu(payload)
        if apdu is None:
            return None

        frame_type, ctrl_bytes, body = apdu
        device_ip = dst_ip if dport == IEC104_PORT else src_ip

        details: dict = {"iec104_frame_type": frame_type}
        confidence = "high"

        if frame_type == "U-frame":
            u_func = U_FRAME_TYPES.get(ctrl_bytes[0], f"0x{ctrl_bytes[0]:02X}")
            details["u_frame_function"] = u_func
            # STARTDT con means the RTU/PLC acknowledged start of data transfer
            if ctrl_bytes[0] == 0x0B:
                details["connection_status"] = "data transfer active"

        elif frame_type == "I-frame":
            # Parse send/receive sequence numbers
            send_seq = (ctrl_bytes[0] >> 1) | (ctrl_bytes[1] << 7)
            recv_seq = (ctrl_bytes[2] >> 1) | (ctrl_bytes[3] << 7)
            details["send_seq"] = send_seq
            details["recv_seq"] = recv_seq
            # Parse ASDU
            if body:
                asdu = self._parse_asdu(body)
                if asdu:
                    details.update(asdu)

        elif frame_type == "S-frame":
            recv_seq = (ctrl_bytes[2] >> 1) | (ctrl_bytes[3] << 7)
            details["recv_seq"] = recv_seq

        detection = self._make_detection(
            protocol="IEC 60870-5-104",
            port=IEC104_PORT,
            confidence=confidence,
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_apdu(self, payload: bytes):
        """
        Parse IEC 104 APDU header.
        Returns (frame_type_str, ctrl_bytes, body) or None.
        """
        # Allow multiple APDUs in one TCP segment — parse the first one
        offset = 0
        while offset < len(payload):
            if payload[offset] != IEC104_START_BYTE:
                offset += 1
                continue

            if offset + 6 > len(payload):
                break

            apdu_len = payload[offset + 1]
            if apdu_len < 4:
                break

            ctrl = payload[offset + 2: offset + 6]
            body = payload[offset + 6: offset + 2 + apdu_len]

            # Determine frame type
            c0 = ctrl[0]
            if c0 & 0x01 == 0:
                frame_type = "I-frame"
            elif c0 & 0x03 == 0x01:
                frame_type = "S-frame"
            elif c0 & 0x03 == 0x03:
                frame_type = "U-frame"
            else:
                break

            return frame_type, ctrl, body

        return None

    def _parse_asdu(self, data: bytes) -> Optional[dict]:
        """
        Parse ASDU (Application Service Data Unit).
        Returns dict with type id, cause of transmission, common address.
        """
        if len(data) < 6:
            return None

        type_id = data[0]
        vsq     = data[1]           # Variable Structure Qualifier
        cot     = struct.unpack_from("<H", data, 2)[0] & 0x3F   # Cause of Transmission (6 bits)
        ca      = struct.unpack_from("<H", data, 4)[0]           # Common Address (RTU address)

        result = {
            "asdu_type_id":   type_id,
            "asdu_type_name": ASDU_TYPES.get(type_id, f"Type {type_id}"),
            "cause_of_tx":    COT_NAMES.get(cot, f"COT {cot}"),
            "common_address": ca,
        }

        # Count of information objects
        sq    = bool(vsq & 0x80)
        count = vsq & 0x7F
        result["io_count"] = count

        # If End of Initialization, extract initialization cause
        if type_id == 70 and len(data) >= 10:
            coi = data[9] & 0x7F   # Cause of Initialization
            result["init_cause"] = {
                0: "Local power on",
                1: "Local manual reset",
                2: "Remote reset",
            }.get(coi, f"COI {coi}")

        return result
