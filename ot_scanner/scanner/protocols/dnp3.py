"""
DNP3 Protocol Analyzer --- Enhanced with Secure Authentication Tracking
Port: TCP/UDP 20000  |  Standard: IEEE 1815-2012

RTU/FRTU relevance:
  DNP3 is the dominant RTU protocol in North American electric utilities,
  water/wastewater, and oil & gas.  It is used between:
    Master Station (SCADA/EMS/DMS) -> Outstation (RTU/FRTU/IED)

This analyzer tracks PER-SESSION state to detect:
  - Absence of DNP3 Secure Authentication (SAv5/SAv6) function codes
  - Control commands (Select, Operate, Direct Operate) without SA
  - Direct Operate bypassing the Select-Before-Operate (SBO) safety mechanism
  - Dangerous maintenance commands (Cold/Warm Restart, Stop/Start App)
  - File transfer function codes (potential firmware/config injection vector)
  - DNP3 over UDP (stateless, harder to secure)

Key Function Code Groups:
  0x03 (3)  : Select              --- SBO step 1
  0x04 (4)  : Operate             --- SBO step 2
  0x05 (5)  : Direct Operate      --- BYPASSES SBO <- security concern
  0x06 (6)  : Direct Operate No Ack
  0x0D (13) : Cold Restart        --- dangerous
  0x0E (14) : Warm Restart        --- dangerous
  0x12 (18) : Stop Application    --- dangerous
  0x19 (25) : Open File           --- file injection vector
  0x1E (30) : Abort File
  0x20 (32) : Authentication Challenge  --- SAv5 indicator
  0x21 (33) : Authentication Reply      --- SAv5 indicator
  0x83 (131): Auth Aggressive Mode Request --- SAv5 aggressive mode
"""
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import DNP3SessionState, ProtocolDetection

DNP3_PORT = 20000

# -- Function code catalogue ---------------------------------------------------
ALL_FC: Dict[int, str] = {
    0x00: "Confirm",
    0x01: "Read",
    0x02: "Write",
    0x03: "Select",
    0x04: "Operate",
    0x05: "Direct Operate",
    0x06: "Direct Operate No Ack",
    0x07: "Imm. Freeze",
    0x08: "Imm. Freeze No Ack",
    0x09: "Freeze-and-Clear",
    0x0A: "Freeze-and-Clear No Ack",
    0x0B: "Freeze with Time",
    0x0C: "Freeze with Time No Ack",
    0x0D: "Cold Restart",
    0x0E: "Warm Restart",
    0x0F: "Initialize Data",
    0x10: "Initialize Application",
    0x11: "Start Application",
    0x12: "Stop Application",
    0x13: "Save Configuration",
    0x14: "Enable Unsolicited",
    0x15: "Disable Unsolicited",
    0x16: "Assign Class",
    0x17: "Delay Measurement",
    0x18: "Record Current Time",
    0x19: "Open File",
    0x1A: "Close File",
    0x1B: "Delete File",
    0x1C: "Get File Info",
    0x1D: "Authenticate File",
    0x1E: "Abort File",
    0x1F: "Activate Configuration",
    0x20: "Authentication Challenge",     # SA function code
    0x21: "Authentication Reply",          # SA function code
    0x81: "Response",
    0x82: "Unsolicited Response",
    0x83: "Auth Aggressive Mode Request", # SA v5
    0x84: "Authentication Error",
}

# Control function codes
FC_CONTROL   = {0x03, 0x04, 0x05, 0x06}
FC_DANGEROUS = {0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13}
FC_FILE      = {0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
FC_SA        = {0x20, 0x21, 0x83, 0x84}

# Data Link control field bits
CTRL_DIR = 0x80   # 1 = master -> outstation
CTRL_PRM = 0x40
CTRL_FC  = 0x0F


class DNP3Analyzer(BaseProtocolAnalyzer):

    def __init__(self):
        # Key: (master_ip, outstation_ip) -> DNP3SessionState
        self._sessions: Dict[Tuple[str, str], DNP3SessionState] = {}

    def get_sessions(self) -> Dict:
        return self._sessions

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if sport != DNP3_PORT and dport != DNP3_PORT:
            return False
        if len(payload) < 10:
            return False
        return payload[0] == 0x05 and payload[1] == 0x64

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        frame = self._parse_dl_frame(payload)
        if frame is None:
            return None

        ctrl, dest_addr, src_addr, user_data = frame
        is_master = bool(ctrl & CTRL_DIR)

        # Identify master and outstation
        master_ip     = src_ip if is_master else dst_ip
        outstation_ip = dst_ip if is_master else src_ip
        session_key   = (master_ip, outstation_ip)

        if session_key not in self._sessions:
            self._sessions[session_key] = DNP3SessionState(
                master_ip=master_ip,
                outstation_ip=outstation_ip,
                outstation_addr=dest_addr if is_master else src_addr,
                master_addr=src_addr if is_master else dest_addr,
            )
        sess = self._sessions[session_key]
        sess.packet_count += 1
        sess.last_seen = timestamp
        if not sess.first_seen:
            sess.first_seen = timestamp
        if proto == "UDP":
            sess.over_udp = True

        # Parse application layer
        fc = None
        app_details: Dict = {}
        if user_data:
            al = self._parse_app_layer(user_data)
            if al:
                fc = al.get("fc")
                app_details = al
                self._update_session(sess, fc, app_details, timestamp)

        # Build ProtocolDetection
        device_ip = outstation_ip
        dl_fc = ctrl & CTRL_FC
        details: Dict = {
            "direction":    "master->outstation" if is_master else "outstation->master",
            "dest_addr":    dest_addr,
            "src_addr":     src_addr,
            "transport":    proto,
        }
        if fc is not None:
            details["app_fc"]   = f"0x{fc:02X}"
            details["app_fc_name"] = ALL_FC.get(fc, f"FC {fc}")
        details.update({k: v for k, v in app_details.items()
                        if k not in ("fc",) and v is not None})

        detection = self._make_detection(
            protocol="DNP3",
            port=DNP3_PORT,
            confidence="high",
            timestamp=timestamp,
            transport=proto,
            **details,
        )
        return [(device_ip, detection)]

    # -- session updater -------------------------------------------------------

    def _update_session(self, sess: DNP3SessionState, fc: Optional[int],
                        details: Dict, ts: datetime) -> None:
        if fc is None:
            return
        ev = {"fc": fc, "fc_name": ALL_FC.get(fc, "?"), "ts": ts.isoformat(),
              **{k: v for k, v in details.items() if k not in ("fc",)}}
        if fc == 0x03:
            sess.select_commands.append(ev)
        elif fc == 0x04:
            sess.operate_commands.append(ev)
        elif fc == 0x05:
            sess.direct_operate.append(ev)
        elif fc == 0x06:
            sess.direct_operate_noack.append(ev)
        elif fc == 0x0D:
            sess.cold_restarts += 1
        elif fc == 0x0E:
            sess.warm_restarts += 1
        elif fc == 0x12:
            sess.stop_app += 1
        elif fc == 0x11:
            sess.start_app += 1
        elif fc == 0x0F:
            sess.init_data += 1
        elif fc == 0x19:
            sess.file_opens.append(ev)
        elif fc == 0x1A:
            sess.file_closes += 1
        elif fc == 0x1B:
            sess.file_deletes += 1
        elif fc == 0x1E:
            sess.file_aborts += 1
        elif fc == 0x20:
            sess.auth_challenges += 1
        elif fc == 0x21:
            sess.auth_replies += 1
        elif fc == 0x83:
            sess.auth_aggressive += 1

    # -- frame parsers ---------------------------------------------------------

    def _parse_dl_frame(self, payload: bytes):
        if len(payload) < 10:
            return None
        if payload[0] != 0x05 or payload[1] != 0x64:
            return None
        length  = payload[2]
        control = payload[3]
        dest    = struct.unpack_from("<H", payload, 4)[0]
        src     = struct.unpack_from("<H", payload, 6)[0]
        if length < 5:
            return None
        return control, dest, src, payload[10:]

    def _parse_app_layer(self, data: bytes) -> Optional[Dict]:
        """Parse DNP3 Transport + Application layers."""
        if len(data) < 3:
            return None
        # Transport byte: bit7=FIN, bit6=FIR, bits0-5=seq
        ac  = data[1]   # Application Control: bit7=FIR, bit6=FIN, bits0-3=seq
        fc  = data[2]   # Function Code
        result: Dict = {"fc": fc}
        # Device Attribute objects (Group 0) --- firmware, model, vendor
        if fc in (0x01, 0x81) and len(data) > 3:
            attrs = self._scan_group0(data[3:])
            result.update(attrs)
        return result

    def _scan_group0(self, data: bytes) -> Dict:
        """Extract Group 0 device attributes."""
        result: Dict = {}
        i = 0
        while i + 3 <= len(data):
            group, variation, qualifier = data[i], data[i+1], data[i+2]
            i += 3
            if group == 0 and qualifier == 0x00 and i + 2 <= len(data):
                attr_type = data[i]; attr_len = data[i+1]; i += 2
                if i + attr_len <= len(data):
                    raw = data[i:i+attr_len]
                    i += attr_len
                    text = raw.decode("latin-1", errors="replace").strip()
                    if variation == 242:
                        result["product_model"]    = text
                    elif variation == 243:
                        result["firmware_version"] = text
                    elif variation == 245:
                        result["vendor_name"]      = text
                    continue
            break
        return result
