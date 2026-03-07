"""
Siemens S7comm Security Analyzer
===================================
Port: 102 (ISO-TSAP/COTP) | Protocol: S7 Communication
Detects: CPU stop/start, PLC program upload/download, password brute-force,
         firmware manipulation, unauthorized read/write, SZL enumeration
"""
import struct
from collections import defaultdict
from typing import List, Dict, Any
from modules.pcap_parser import BaseOTAuditor, Packet

# S7comm ROSCTR types
S7_JOB = 0x01
S7_ACK = 0x02
S7_ACK_DATA = 0x03
S7_USERDATA = 0x07

# S7 Function codes (in Job requests)
S7_FC_READ_VAR = 0x04
S7_FC_WRITE_VAR = 0x05
S7_FC_SETUP_COMM = 0xF0
S7_FC_CPU_SERVICES = 0x00  # Parameter-dependent

# S7 CPU control function group
S7_CPU_STOP = 0x29
S7_CPU_START = 0x28
S7_PROG_DOWNLOAD = 0x1A
S7_PROG_UPLOAD = 0x1D
S7_PLC_CTRL = 0x28


class S7commAnalyzer(BaseOTAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        s7_pkts = [p for p in self.packets if p.ot_protocol == "s7comm"]
        if not s7_pkts:
            return self.findings
        self.s7_pkts = s7_pkts
        self.check_cpu_stop_start()
        self.check_program_transfer()
        self.check_write_operations()
        self.check_password_auth()
        self.check_szl_enumeration()
        self.check_unauthorized_sources()
        self.check_no_auth()
        return self.findings

    def _is_s7_payload(self, payload: bytes) -> bool:
        # S7comm starts after COTP (at least 7 bytes TPKT + 3 COTP Data)
        if len(payload) < 17:
            return False
        # TPKT header: version=3, reserved=0
        if payload[0] == 0x03 and payload[1] == 0x00:
            return True
        return False

    def _get_s7_rosctr(self, payload: bytes) -> int:
        # TPKT(4) + COTP(variable, usually 3 for DT) + S7 header
        # S7 header starts at offset 7+ (after COTP)
        try:
            cotp_len = payload[4] + 1  # COTP length indicator + 1
            s7_offset = 4 + cotp_len
            if s7_offset + 2 > len(payload):
                return -1
            if payload[s7_offset] == 0x32:  # S7 protocol ID
                return payload[s7_offset + 1]  # ROSCTR
        except (IndexError, struct.error):
            pass
        return -1

    def check_cpu_stop_start(self):
        cpu_cmds = []
        for pkt in self.s7_pkts:
            if not pkt.payload or not self._is_s7_payload(pkt.payload):
                continue
            payload_hex = pkt.payload.hex().lower()
            # CPU STOP: parameter contains 29 00 00 00 00 00 09 50 5f 50 52 4f 47 52 41 4d
            if "29000000000009505f50524f4752414d" in payload_hex:
                cpu_cmds.append(f"{pkt.src_ip}→{pkt.dst_ip} — CPU STOP command")
            # CPU START
            if "28000000000009505f50524f4752414d" in payload_hex:
                cpu_cmds.append(f"{pkt.src_ip}→{pkt.dst_ip} — CPU START command")
            # Also check for PLCSTOP/PLCSTART strings
            if b"P_PROGRAM" in pkt.payload and (b"\x29" in pkt.payload[7:20] or b"\x28" in pkt.payload[7:20]):
                pass  # Already caught above
        if cpu_cmds:
            self.finding("S7-001", f"S7comm CPU STOP/START commands detected ({len(cpu_cmds)})",
                self.SEVERITY_CRITICAL, "Siemens S7comm",
                f"{len(cpu_cmds)} CPU control command(s) detected. CPU STOP halts the PLC "
                "program execution, directly impacting physical process control.",
                cpu_cmds,
                "Restrict CPU control to authorized engineering workstations only. "
                "Enable S7comm+ (TLS) on S7-1500 PLCs. Deploy access protection passwords.",
                ["IEC 62443-3-3 SR 3.5", "Siemens Security Advisory SSA-731239"],
                mitre_ics=["T0881 — Service Stop", "T0857 — System Firmware"])

    def check_program_transfer(self):
        transfers = []
        for pkt in self.s7_pkts:
            if not pkt.payload:
                continue
            ph = pkt.payload.hex().lower()
            # Download block (contains function code 0x1A in S7 userdata)
            if "1a" in ph[20:30] and len(pkt.payload) > 50:
                if b"_MODB" in pkt.payload or b"OB" in pkt.payload or b"FC" in pkt.payload:
                    transfers.append(f"{pkt.src_ip}→{pkt.dst_ip} — Program DOWNLOAD (block transfer)")
            # Upload (0x1D)
            if "1d" in ph[20:30] and len(pkt.payload) > 30:
                if b"_MODB" in pkt.payload or b"OB" in pkt.payload or b"DB" in pkt.payload:
                    transfers.append(f"{pkt.src_ip}→{pkt.dst_ip} — Program UPLOAD (block read)")
        if transfers:
            self.finding("S7-002", f"S7comm PLC program transfer detected ({len(transfers)})",
                self.SEVERITY_CRITICAL, "Siemens S7comm",
                f"{len(transfers)} program upload/download operation(s) detected. "
                "Unauthorized program changes can alter process logic (Stuxnet-style attack).",
                transfers[:15],
                "Enable PLC access protection (password). Monitor for unauthorized TIA Portal sessions. "
                "Use S7comm+ with TLS on S7-1500 series.",
                ["CVE-2019-13945", "Siemens CERT Advisory"],
                mitre_ics=["T0843 — Program Download",
                          "T0845 — Program Upload",
                          "T0873 — Project File Infection"])

    def check_write_operations(self):
        writes = []
        for pkt in self.s7_pkts:
            if not pkt.payload or not self._is_s7_payload(pkt.payload):
                continue
            rosctr = self._get_s7_rosctr(pkt.payload)
            if rosctr == S7_JOB:
                # Look for Write Var function (0x05)
                if b"\x05" in pkt.payload[10:15]:
                    writes.append(f"{pkt.src_ip}→{pkt.dst_ip} — S7 Write Variable")
        if writes:
            self.finding("S7-003", f"S7comm write variable operations ({len(writes)})",
                self.SEVERITY_HIGH, "Siemens S7comm",
                f"{len(writes)} S7 write operations detected. These modify PLC data blocks, "
                "flags, inputs/outputs, and timer/counter values.",
                writes[:20],
                "Restrict S7 write access to authorized engineering stations. "
                "Enable PLC access protection level 3 (read/write password).",
                ["IEC 62443-3-3 SR 3.5"],
                mitre_ics=["T0836 — Modify Parameter"])

    def check_password_auth(self):
        auth_attempts = []
        for pkt in self.s7_pkts:
            if not pkt.payload:
                continue
            if b"\x00\x01\x00\x01\x00\x00\x00\x00" in pkt.payload and len(pkt.payload) > 20:
                auth_attempts.append(f"{pkt.src_ip}→{pkt.dst_ip} — S7 authentication exchange")
        if len(auth_attempts) > 5:
            self.finding("S7-004", f"Multiple S7 authentication attempts ({len(auth_attempts)})",
                self.SEVERITY_HIGH, "Siemens S7comm",
                f"{len(auth_attempts)} authentication handshakes detected. Excessive auth "
                "attempts may indicate password brute-force attacks against the PLC.",
                auth_attempts[:10],
                "Implement account lockout on PLC. Monitor for authentication failures. "
                "Use strong PLC passwords (not default 'SIEMENS' or empty).",
                ["Siemens Industrial Security Guide"],
                mitre_ics=["T0812 — Default Credentials",
                          "T0859 — Valid Accounts"])

    def check_szl_enumeration(self):
        szl_reads = []
        for pkt in self.s7_pkts:
            if not pkt.payload:
                continue
            if b"\x44\x01" in pkt.payload or b"\x00\x1c" in pkt.payload[15:25]:
                szl_reads.append(f"{pkt.src_ip}→{pkt.dst_ip} — SZL read (system info)")
        if szl_reads:
            self.finding("S7-005", f"S7comm SZL system info enumeration ({len(szl_reads)})",
                self.SEVERITY_MEDIUM, "Siemens S7comm",
                f"{len(szl_reads)} SZL (System Status List) read requests detected. "
                "SZL provides detailed PLC info: model, firmware, serial, module list.",
                szl_reads[:10],
                "Restrict SZL read access. Block from non-engineering networks.",
                ["IEC 62443-3-3 SR 7.6"],
                mitre_ics=["T0846 — Remote System Discovery"])

    def check_unauthorized_sources(self):
        src_to_plc = defaultdict(set)
        for pkt in self.s7_pkts:
            if pkt.dst_port == 102:
                src_to_plc[pkt.dst_ip].add(pkt.src_ip)
        multi = [(plc, srcs) for plc, srcs in src_to_plc.items() if len(srcs) > 2]
        if multi:
            items = [f"PLC {plc}: accessed by {len(srcs)} sources — {', '.join(list(srcs)[:4])}"
                    for plc, srcs in multi]
            self.finding("S7-006", f"PLCs accessed by multiple sources ({len(multi)})",
                self.SEVERITY_MEDIUM, "Siemens S7comm",
                "Multiple unique IPs communicating with PLCs. Only authorized SCADA/HMI "
                "and engineering workstations should connect.",
                items,
                "Implement firewall allowlists per PLC. Use PLC access protection.",
                ["IEC 62443-3-3 SR 5.1"],
                mitre_ics=["T0886 — Remote Services"])

    def check_no_auth(self):
        if self.s7_pkts:
            self.finding("S7-007", "S7comm (classic) traffic has no authentication/encryption",
                self.SEVERITY_HIGH, "Siemens S7comm",
                f"{len(self.s7_pkts)} S7comm packets detected. Classic S7comm (port 102) has "
                "no built-in authentication or encryption. Any device on the network can "
                "read/write PLC data and control the CPU.",
                [f"Total S7 packets: {len(self.s7_pkts)}"],
                "Upgrade to S7-1500 with S7comm+ (TLS). For S7-300/400, deploy network "
                "segmentation and OT-aware firewalls.",
                ["Siemens Security Guide — S7comm+", "IEC 62443-3-3 SR 4.1"],
                mitre_ics=["T0830 — Man in the Middle"])
