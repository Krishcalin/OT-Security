"""
IEC 60870-5-104 Protocol Analyzer --- Enhanced with Session & Command Tracking
Port: TCP 2404  |  Standard: IEC 60870-5-104:2006 + Amendment 1:2016

RTU/FRTU relevance:
  IEC 104 is the TCP/IP transport edition of IEC 60870-5-101.
  Dominant in European power utilities and widely used in:
    Electric transmission / distribution substations (ABB, Siemens, Schneider)
    Oil & gas pipeline RTUs
    Water/wastewater control systems

This analyzer tracks per-session state to enable detection of:
  - Multiple master stations connected to the same RTU (rogue master risk)
  - Control commands (C_SC, C_DC, C_SE) --- switching / setpoint
  - Clock synchronisation commands (time injection risk)
  - No TLS wrapper (IEC 62351-3)

APDU Frame:
  0x68  Start byte
  N     APDU length
  [4-byte control field]
  [ASDU --- I-frames only]

Control Command Type IDs:
  45  C_SC_NA_1  Single Command (single-point switch)
  46  C_DC_NA_1  Double Command (double-point switch)
  47  C_RC_NA_1  Regulating-step Command
  48  C_SE_NA_1  Set-point Command, Normalised
  49  C_SE_NB_1  Set-point Command, Scaled
  50  C_SE_NC_1  Set-point Command, Short Float
  51  C_BO_NA_1  Bitstring Command
  58  C_SC_TA_1  Single Command with Time Tag
  59  C_DC_TA_1  Double Command with Time Tag
  100 C_IC_NA_1  General Interrogation
  103 C_CS_NA_1  Clock Synchronisation       <- time manipulation risk
"""
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import IEC104SessionState, ProtocolDetection

IEC104_PORT = 2404
START_BYTE  = 0x68

# ASDU Type IDs
ASDU_TYPES: Dict[int, str] = {
    1:   "M_SP_NA_1 (Single Point)",
    3:   "M_DP_NA_1 (Double Point)",
    5:   "M_ST_NA_1 (Step Position)",
    7:   "M_BO_NA_1 (Bitstring 32-bit)",
    9:   "M_ME_NA_1 (Meas. Normalised)",
    11:  "M_ME_NB_1 (Meas. Scaled)",
    13:  "M_ME_NC_1 (Meas. Short Float)",
    15:  "M_IT_NA_1 (Integrated Totals)",
    30:  "M_SP_TB_1 (Single Point+Time)",
    31:  "M_DP_TB_1 (Double Point+Time)",
    36:  "M_ME_TF_1 (Meas. Float+Time)",
    45:  "C_SC_NA_1 (Single Command)",
    46:  "C_DC_NA_1 (Double Command)",
    47:  "C_RC_NA_1 (Regulating Step)",
    48:  "C_SE_NA_1 (Set-point Norm.)",
    49:  "C_SE_NB_1 (Set-point Scaled)",
    50:  "C_SE_NC_1 (Set-point Float)",
    51:  "C_BO_NA_1 (Bitstring Cmd)",
    58:  "C_SC_TA_1 (Single Cmd+Time)",
    59:  "C_DC_TA_1 (Double Cmd+Time)",
    70:  "M_EI_NA_1 (End of Init.)",
    100: "C_IC_NA_1 (General Interrogation)",
    101: "C_CI_NA_1 (Counter Interrogation)",
    103: "C_CS_NA_1 (Clock Sync.)",
    105: "C_RP_NA_1 (Reset Process)",
    107: "C_TS_TA_1 (Test Cmd+Time)",
    110: "P_ME_NA_1 (Parameter Norm.)",
    112: "P_ME_NC_1 (Parameter Float)",
    120: "F_FR_NA_1 (File Ready)",
    121: "F_SR_NA_1 (Section Ready)",
    122: "F_SC_NA_1 (Call Directory)",
    123: "F_LS_NA_1 (Last Section)",
    124: "F_FA_NA_1 (ACK File)",
    125: "F_SG_NA_1 (Segment)",
    126: "F_DR_TA_1 (Directory)",
}

U_FRAMES: Dict[int, str] = {
    0x07: "STARTDT act",
    0x0B: "STARTDT con",
    0x13: "STOPDT act",
    0x23: "STOPDT con",
    0x43: "TESTFR act",
    0x83: "TESTFR con",
}

COT_NAMES: Dict[int, str] = {
    1: "Periodic", 2: "Background", 3: "Spontaneous", 4: "Initialized",
    5: "Request", 6: "Activation", 7: "Activation con", 8: "Deactivation",
    9: "Deactivation con", 10: "Activation term", 20: "General interrogation",
    44: "Unknown type", 45: "Unknown COT", 46: "Unknown common address",
}

# Control type IDs
CTRL_TYPE_IDS = {45, 46, 47, 48, 49, 50, 51, 58, 59}


class IEC104Analyzer(BaseProtocolAnalyzer):

    def __init__(self):
        # Key: (master_ip, rtu_ip) -> IEC104SessionState
        self._sessions: Dict[Tuple[str, str], IEC104SessionState] = {}

    def get_sessions(self) -> Dict:
        return self._sessions

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport != IEC104_PORT and dport != IEC104_PORT:
            return False
        return len(payload) >= 6 and payload[0] == START_BYTE

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        device_ip   = dst_ip if dport == IEC104_PORT else src_ip
        master_ip   = src_ip if dport == IEC104_PORT else dst_ip

        apdu = self._parse_apdu(payload)
        if apdu is None:
            return None

        frame_type, ctrl, body = apdu
        session_key = (master_ip, device_ip)
        if session_key not in self._sessions:
            self._sessions[session_key] = IEC104SessionState(
                master_ip=master_ip, rtu_ip=device_ip
            )
        sess = self._sessions[session_key]
        sess.packet_count += 1
        sess.last_seen = timestamp
        if not sess.first_seen:
            sess.first_seen = timestamp

        details: Dict = {"frame_type": frame_type}

        if frame_type == "U-frame":
            u_func = U_FRAMES.get(ctrl[0], f"0x{ctrl[0]:02X}")
            details["u_function"] = u_func
            if ctrl[0] == 0x07:
                sess.startdt_count += 1
            elif ctrl[0] in (0x13,):
                sess.stopdt_count += 1

        elif frame_type == "I-frame" and body:
            asdu_info = self._parse_asdu(body)
            if asdu_info:
                details.update(asdu_info)
                ca = asdu_info.get("common_address")
                if ca:
                    sess.common_address = ca
                self._record_command(sess, asdu_info, timestamp)

        detection = self._make_detection(
            protocol="IEC 60870-5-104",
            port=IEC104_PORT,
            confidence="high",
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, detection)]

    # -- session ---------------------------------------------------------------

    def _record_command(self, sess: IEC104SessionState,
                        asdu: Dict, ts: datetime) -> None:
        tid = asdu.get("type_id", 0)
        ev  = {**asdu, "ts": ts.isoformat()}
        if tid == 45:
            sess.single_commands.append(ev)
        elif tid == 46:
            sess.double_commands.append(ev)
        elif tid == 47:
            sess.regulating_step.append(ev)
        elif tid in (48, 49, 50):
            sess.setpoint_commands.append(ev)
        elif tid == 51:
            sess.bitstring_commands.append(ev)
        elif tid == 103:
            sess.clock_syncs += 1
        elif tid == 100:
            sess.general_interrogations += 1

    # -- parsers ---------------------------------------------------------------

    def _parse_apdu(self, payload: bytes):
        off = 0
        while off < len(payload):
            if payload[off] != START_BYTE:
                off += 1
                continue
            if off + 6 > len(payload):
                break
            apdu_len = payload[off + 1]
            if apdu_len < 4:
                break
            ctrl = payload[off + 2: off + 6]
            body = payload[off + 6: off + 2 + apdu_len]
            c0   = ctrl[0]
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

    def _parse_asdu(self, data: bytes) -> Optional[Dict]:
        if len(data) < 6:
            return None
        type_id = data[0]
        vsq     = data[1]
        cot     = struct.unpack_from("<H", data, 2)[0] & 0x3F
        ca      = struct.unpack_from("<H", data, 4)[0]
        count   = vsq & 0x7F
        return {
            "type_id":       type_id,
            "type_name":     ASDU_TYPES.get(type_id, f"Type {type_id}"),
            "cause_of_tx":   COT_NAMES.get(cot, f"COT {cot}"),
            "common_address": ca,
            "io_count":      count,
            "is_control":    type_id in CTRL_TYPE_IDS,
        }
