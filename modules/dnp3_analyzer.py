"""
DNP3 Security Analyzer
========================
Port: 20000 | Protocol: Distributed Network Protocol 3
Detects: Cold/warm restart, file transfer, control relay output,
         unsolicited responses, auth bypass, write operations
"""
import struct
from collections import defaultdict
from typing import List, Dict, Any
from modules.pcap_parser import BaseOTAuditor, Packet

DNP3_FC_CONFIRM = 0x00
DNP3_FC_READ = 0x01
DNP3_FC_WRITE = 0x02
DNP3_FC_SELECT = 0x03
DNP3_FC_OPERATE = 0x04
DNP3_FC_DIRECT_OP = 0x05
DNP3_FC_DIRECT_OP_NR = 0x06
DNP3_FC_FREEZE = 0x07
DNP3_FC_FREEZE_NR = 0x08
DNP3_FC_FREEZE_CLR = 0x09
DNP3_FC_FREEZE_CLR_NR = 0x0A
DNP3_FC_COLD_RESTART = 0x0D
DNP3_FC_WARM_RESTART = 0x0E
DNP3_FC_INIT_DATA = 0x0F
DNP3_FC_INIT_APP = 0x10
DNP3_FC_START_APP = 0x11
DNP3_FC_STOP_APP = 0x12
DNP3_FC_FILE_OPEN = 0x19
DNP3_FC_FILE_CLOSE = 0x1A
DNP3_FC_FILE_DELETE = 0x1B
DNP3_FC_FILE_INFO = 0x1C
DNP3_FC_FILE_AUTH = 0x1D
DNP3_FC_FILE_ABORT = 0x1E
DNP3_FC_ENABLE_UNSOLICITED = 0x14
DNP3_FC_DISABLE_UNSOLICITED = 0x15
DNP3_FC_ASSIGN_CLASS = 0x16
DNP3_FC_DELAY_MEASURE = 0x17
DNP3_FC_AUTH_REQ = 0x20
DNP3_FC_AUTH_RESP = 0x83

DANGEROUS_FCS = {
    DNP3_FC_WRITE: "Write — modify outstation data",
    DNP3_FC_SELECT: "Select — prepare control relay output",
    DNP3_FC_OPERATE: "Operate — execute control relay output",
    DNP3_FC_DIRECT_OP: "Direct Operate — immediate relay control",
    DNP3_FC_COLD_RESTART: "Cold Restart — full outstation reboot",
    DNP3_FC_WARM_RESTART: "Warm Restart — partial outstation restart",
    DNP3_FC_STOP_APP: "Stop Application — halt outstation program",
    DNP3_FC_FILE_DELETE: "Delete File — remove files from outstation",
}

class Dnp3Analyzer(BaseOTAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        dnp3_pkts = [p for p in self.packets if p.ot_protocol == "dnp3"]
        if not dnp3_pkts:
            return self.findings
        self.dnp3_pkts = dnp3_pkts
        self.check_control_operations()
        self.check_restart_commands()
        self.check_file_operations()
        self.check_unsolicited_config()
        self.check_no_secure_auth()
        self.check_unauthorized_sources()
        return self.findings

    def _get_dnp3_fc(self, payload: bytes) -> int:
        # DNP3/TCP: 2-byte start (0x0564), then length, control, dst, src, ...
        # Application layer FC is deeper; simplified heuristic
        if len(payload) < 12:
            return -1
        # Look for DNP3 start bytes
        start_idx = payload.find(b'\x05\x64')
        if start_idx < 0:
            return -1
        try:
            # Transport header at offset start_idx+8, then app control + FC
            app_offset = start_idx + 10
            if app_offset + 2 > len(payload):
                return -1
            fc = payload[app_offset + 1] & 0x7F  # Function code (mask DIR bit)
            return fc
        except (IndexError, struct.error):
            return -1

    def check_control_operations(self):
        controls = []
        for pkt in self.dnp3_pkts:
            if not pkt.payload:
                continue
            fc = self._get_dnp3_fc(pkt.payload)
            if fc in DANGEROUS_FCS:
                controls.append(f"{pkt.src_ip}→{pkt.dst_ip} FC={fc} ({DANGEROUS_FCS[fc]})")
        if controls:
            self.finding("DNP3-001", f"DNP3 control/write operations detected ({len(controls)})",
                self.SEVERITY_HIGH, "DNP3",
                f"{len(controls)} dangerous DNP3 function code(s) detected including write, "
                "select/operate, and direct operate commands.",
                controls[:20],
                "Enable DNP3 Secure Authentication (SA v5). Restrict control operations "
                "to authorized SCADA masters via firewall allowlists.",
                ["IEEE 1815-2012 (DNP3 SA)", "IEC 62351-5"],
                mitre_ics=["T0855 — Unauthorized Command Message",
                          "T0836 — Modify Parameter"])

    def check_restart_commands(self):
        restarts = []
        for pkt in self.dnp3_pkts:
            if not pkt.payload:
                continue
            fc = self._get_dnp3_fc(pkt.payload)
            if fc in (DNP3_FC_COLD_RESTART, DNP3_FC_WARM_RESTART):
                cmd = "Cold Restart" if fc == DNP3_FC_COLD_RESTART else "Warm Restart"
                restarts.append(f"{pkt.src_ip}→{pkt.dst_ip} — {cmd}")
        if restarts:
            self.finding("DNP3-002", f"DNP3 restart commands detected ({len(restarts)})",
                self.SEVERITY_CRITICAL, "DNP3",
                f"{len(restarts)} restart command(s) detected. Cold restart reboots the "
                "RTU/outstation, causing loss of real-time monitoring and control.",
                restarts,
                "Block restart function codes at OT firewall. Require Secure Auth for control.",
                ["IEEE 1815-2012"],
                mitre_ics=["T0816 — Device Restart/Shutdown"])

    def check_file_operations(self):
        file_ops = []
        file_fcs = {DNP3_FC_FILE_OPEN: "Open", DNP3_FC_FILE_CLOSE: "Close",
                   DNP3_FC_FILE_DELETE: "Delete", DNP3_FC_FILE_INFO: "Info"}
        for pkt in self.dnp3_pkts:
            if not pkt.payload:
                continue
            fc = self._get_dnp3_fc(pkt.payload)
            if fc in file_fcs:
                file_ops.append(f"{pkt.src_ip}→{pkt.dst_ip} — File {file_fcs[fc]}")
        if file_ops:
            self.finding("DNP3-003", f"DNP3 file transfer operations ({len(file_ops)})",
                self.SEVERITY_HIGH, "DNP3",
                f"{len(file_ops)} file operation(s) detected. File transfer can be used "
                "to modify outstation firmware or extract configuration.",
                file_ops[:15],
                "Restrict DNP3 file transfer FCs to maintenance windows only.",
                ["IEC 62443-3-3 SR 3.4"],
                mitre_ics=["T0857 — System Firmware",
                          "T0859 — Valid Accounts"])

    def check_unsolicited_config(self):
        unsolicited = []
        for pkt in self.dnp3_pkts:
            if not pkt.payload:
                continue
            fc = self._get_dnp3_fc(pkt.payload)
            if fc in (DNP3_FC_ENABLE_UNSOLICITED, DNP3_FC_DISABLE_UNSOLICITED):
                action = "Enable" if fc == DNP3_FC_ENABLE_UNSOLICITED else "Disable"
                unsolicited.append(f"{pkt.src_ip}→{pkt.dst_ip} — {action} Unsolicited Responses")
        if unsolicited:
            self.finding("DNP3-004", f"DNP3 unsolicited response configuration changes ({len(unsolicited)})",
                self.SEVERITY_MEDIUM, "DNP3",
                "Unsolicited response configuration is being modified. Disabling unsolicited "
                "responses prevents real-time event reporting from the outstation.",
                unsolicited[:10],
                "Monitor and restrict unsolicited configuration changes.",
                ["IEEE 1815-2012 — Unsolicited Responses"],
                mitre_ics=["T0836 — Modify Parameter"])

    def check_no_secure_auth(self):
        has_auth = False
        for pkt in self.dnp3_pkts:
            if not pkt.payload:
                continue
            fc = self._get_dnp3_fc(pkt.payload)
            if fc in (DNP3_FC_AUTH_REQ, 0x20, 0x83):
                has_auth = True
                break
            if b"\x78" in pkt.payload[10:20]:  # Auth object group 120
                has_auth = True
                break
        if not has_auth and self.dnp3_pkts:
            self.finding("DNP3-005", "DNP3 Secure Authentication not detected",
                self.SEVERITY_HIGH, "DNP3",
                f"{len(self.dnp3_pkts)} DNP3 packets without any Secure Authentication (SA) "
                "exchanges. Without SA, any device can send control commands to outstations.",
                [f"Total DNP3 packets: {len(self.dnp3_pkts)}"],
                "Enable DNP3 Secure Authentication v5 (IEEE 1815-2012). "
                "Requires firmware support on both master and outstation.",
                ["IEEE 1815-2012 — Secure Authentication", "IEC 62351-5"],
                mitre_ics=["T0830 — Man in the Middle"])

    def check_unauthorized_sources(self):
        src_to_outstation = defaultdict(set)
        for pkt in self.dnp3_pkts:
            if pkt.dst_port == 20000:
                src_to_outstation[pkt.dst_ip].add(pkt.src_ip)
        multi = [(o, s) for o, s in src_to_outstation.items() if len(s) > 2]
        if multi:
            items = [f"Outstation {o}: {len(s)} sources — {', '.join(list(s)[:4])}" for o, s in multi]
            self.finding("DNP3-006", f"DNP3 outstations accessed by multiple masters ({len(multi)})",
                self.SEVERITY_MEDIUM, "DNP3",
                "Multiple sources communicating with DNP3 outstations. In proper architecture, "
                "only the designated SCADA master should connect.",
                items,
                "Implement source IP allowlisting for DNP3 outstations.",
                ["IEC 62443-3-3 SR 5.1"],
                mitre_ics=["T0886 — Remote Services"])
