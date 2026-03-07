"""
Modbus/TCP Security Analyzer
===============================
Port: 502 | Protocol: Modbus Application Protocol (MBAP)
Detects: Write abuse, diagnostic commands, unauthorized function codes,
         reconnaissance, broadcast storms, register manipulation
"""
import struct
from collections import defaultdict
from typing import List, Dict, Any
from modules.pcap_parser import BaseOTAuditor, Packet

# Modbus function codes
FC_READ_COILS = 1
FC_READ_DISCRETE = 2
FC_READ_HOLDING = 3
FC_READ_INPUT = 4
FC_WRITE_SINGLE_COIL = 5
FC_WRITE_SINGLE_REG = 6
FC_DIAGNOSTICS = 8
FC_WRITE_MULTI_COILS = 15
FC_WRITE_MULTI_REGS = 16
FC_FILE_RECORD_READ = 20
FC_FILE_RECORD_WRITE = 21
FC_MASK_WRITE = 22
FC_READ_DEVICE_ID = 43
FC_ENCAP_TRANSPORT = 43

DANGEROUS_FCS = {
    FC_WRITE_SINGLE_COIL: "Write Single Coil — can toggle outputs",
    FC_WRITE_SINGLE_REG: "Write Single Register — can change setpoints",
    FC_WRITE_MULTI_COILS: "Write Multiple Coils — bulk output control",
    FC_WRITE_MULTI_REGS: "Write Multiple Registers — bulk setpoint change",
    FC_DIAGNOSTICS: "Diagnostics — can force listen-only mode (DoS)",
    FC_FILE_RECORD_WRITE: "Write File Record — firmware/config modification",
    FC_MASK_WRITE: "Mask Write Register — bitwise register manipulation",
}

RECON_FCS = {
    FC_READ_DEVICE_ID: "Read Device Identification — fingerprinting",
    FC_ENCAP_TRANSPORT: "Encapsulated Interface Transport — device enumeration",
}


class ModbusAnalyzer(BaseOTAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        modbus_pkts = [p for p in self.packets if p.ot_protocol == "modbus"]
        if not modbus_pkts:
            return self.findings
        self.modbus_pkts = modbus_pkts
        self.check_write_operations()
        self.check_diagnostic_abuse()
        self.check_broadcast_commands()
        self.check_unauthorized_sources()
        self.check_exception_responses()
        self.check_reconnaissance()
        self.check_force_listen_only()
        self.check_no_encryption()
        return self.findings

    def _parse_mbap(self, payload: bytes):
        if len(payload) < 8:
            return None
        tid = struct.unpack_from(">H", payload, 0)[0]
        proto = struct.unpack_from(">H", payload, 2)[0]
        length = struct.unpack_from(">H", payload, 4)[0]
        uid = payload[6]
        fc = payload[7]
        return {"tid": tid, "proto": proto, "length": length, "uid": uid, "fc": fc,
                "data": payload[8:]}

    def check_write_operations(self):
        writes = []
        for pkt in self.modbus_pkts:
            if not pkt.payload or len(pkt.payload) < 8:
                continue
            mbap = self._parse_mbap(pkt.payload)
            if mbap and mbap["fc"] in DANGEROUS_FCS:
                writes.append(
                    f"{pkt.src_ip}→{pkt.dst_ip}:{pkt.dst_port} FC={mbap['fc']} "
                    f"({DANGEROUS_FCS[mbap['fc']]}), UID={mbap['uid']}")
        if writes:
            self.finding("MODBUS-001", f"Modbus write/control operations detected ({len(writes)})",
                self.SEVERITY_HIGH, "Modbus/TCP",
                f"{len(writes)} Modbus write/control commands detected. These can modify "
                "PLC outputs, setpoints, and coil states — potentially causing physical harm.",
                writes[:30],
                "Implement Modbus deep packet inspection (DPI) firewall rules to restrict "
                "write function codes to authorized engineering workstations only. "
                "Deploy read-only Modbus access for monitoring systems.",
                ["IEC 62443-3-3 SR 3.5", "NIST SP 800-82 Rev 3"],
                mitre_ics=["T0855 — Unauthorized Command Message",
                          "T0836 — Modify Parameter"],
                details={"total": len(writes)})

    def check_diagnostic_abuse(self):
        diag = []
        for pkt in self.modbus_pkts:
            if not pkt.payload or len(pkt.payload) < 8:
                continue
            mbap = self._parse_mbap(pkt.payload)
            if mbap and mbap["fc"] == FC_DIAGNOSTICS:
                sub_fc = struct.unpack_from(">H", mbap["data"], 0)[0] if len(mbap["data"]) >= 2 else 0
                diag.append(f"{pkt.src_ip}→{pkt.dst_ip} FC=8 SubFC={sub_fc}")
        if diag:
            self.finding("MODBUS-002", f"Modbus diagnostic commands detected ({len(diag)})",
                self.SEVERITY_CRITICAL, "Modbus/TCP",
                f"{len(diag)} diagnostic commands detected. Sub-function 4 (Force Listen Only) "
                "causes a Modbus slave to stop responding — a known DoS attack vector.",
                diag[:20],
                "Block Modbus FC=8 (Diagnostics) at the OT firewall. "
                "Only allow from authorized engineering stations during maintenance.",
                ["NIST SP 800-82 — Modbus Security"],
                mitre_ics=["T0814 — Denial of Service"])

    def check_broadcast_commands(self):
        broadcasts = [p for p in self.modbus_pkts
                     if p.dst_ip.endswith(".255") or p.dst_ip == "255.255.255.255"]
        if broadcasts:
            items = [f"{p.src_ip}→{p.dst_ip} (broadcast)" for p in broadcasts[:10]]
            self.finding("MODBUS-003", f"Modbus broadcast packets detected ({len(broadcasts)})",
                self.SEVERITY_MEDIUM, "Modbus/TCP",
                f"{len(broadcasts)} Modbus packets sent to broadcast addresses. "
                "Broadcast Modbus commands affect all slaves simultaneously.",
                items,
                "Restrict Modbus to unicast communications. Block broadcast on OT VLANs.",
                ["IEC 62443-3-3 SR 5.2"],
                mitre_ics=["T0855 — Unauthorized Command Message"])

    def check_unauthorized_sources(self):
        src_dst = defaultdict(set)
        for pkt in self.modbus_pkts:
            if pkt.dst_port == 502:
                src_dst[pkt.dst_ip].add(pkt.src_ip)
        many_sources = [(dst, srcs) for dst, srcs in src_dst.items() if len(srcs) > 3]
        if many_sources:
            items = [f"Slave {dst}: accessed by {len(srcs)} unique sources — {', '.join(list(srcs)[:5])}"
                    for dst, srcs in many_sources]
            self.finding("MODBUS-004", f"Modbus slaves accessed by multiple sources ({len(many_sources)})",
                self.SEVERITY_MEDIUM, "Modbus/TCP",
                "Modbus slaves are accessed by many unique IP addresses. "
                "In a properly segmented OT network, only designated HMI/SCADA systems "
                "should communicate with PLCs.",
                items,
                "Implement allowlisting — restrict Modbus client IPs per slave device.",
                ["IEC 62443-3-3 SR 5.1"],
                mitre_ics=["T0846 — Remote System Discovery"])

    def check_exception_responses(self):
        exceptions = []
        for pkt in self.modbus_pkts:
            if not pkt.payload or len(pkt.payload) < 9:
                continue
            mbap = self._parse_mbap(pkt.payload)
            if mbap and mbap["fc"] > 0x80:
                exc_code = mbap["data"][0] if mbap["data"] else 0
                exceptions.append(
                    f"{pkt.src_ip}→{pkt.dst_ip} FC=0x{mbap['fc']:02x} ExceptionCode={exc_code}")
        if exceptions and len(exceptions) > 10:
            self.finding("MODBUS-005", f"Excessive Modbus exception responses ({len(exceptions)})",
                self.SEVERITY_MEDIUM, "Modbus/TCP",
                f"{len(exceptions)} Modbus exception responses detected. High exception rates "
                "may indicate scanning, fuzzing, or unauthorized access attempts.",
                exceptions[:15],
                "Investigate source IPs generating exceptions. Deploy IDS with Modbus signatures.",
                ["NIST SP 800-82 — ICS Monitoring"],
                mitre_ics=["T0846 — Remote System Discovery"])

    def check_reconnaissance(self):
        recon = []
        for pkt in self.modbus_pkts:
            if not pkt.payload or len(pkt.payload) < 8:
                continue
            mbap = self._parse_mbap(pkt.payload)
            if mbap and mbap["fc"] in RECON_FCS:
                recon.append(f"{pkt.src_ip}→{pkt.dst_ip} FC={mbap['fc']} ({RECON_FCS[mbap['fc']]})")
        if recon:
            self.finding("MODBUS-006", f"Modbus device reconnaissance detected ({len(recon)})",
                self.SEVERITY_HIGH, "Modbus/TCP",
                f"{len(recon)} device identification/enumeration commands detected. "
                "Attackers use these to fingerprint PLC models and firmware versions.",
                recon[:15],
                "Block FC 43 (MEI) from non-engineering stations.",
                ["IEC 62443-3-3 SR 7.6"],
                mitre_ics=["T0846 — Remote System Discovery"])

    def check_force_listen_only(self):
        for pkt in self.modbus_pkts:
            if not pkt.payload or len(pkt.payload) < 12:
                continue
            mbap = self._parse_mbap(pkt.payload)
            if mbap and mbap["fc"] == FC_DIAGNOSTICS and len(mbap["data"]) >= 2:
                sub_fc = struct.unpack_from(">H", mbap["data"], 0)[0]
                if sub_fc == 4:
                    self.finding("MODBUS-007", "Modbus Force Listen Only Mode attack detected",
                        self.SEVERITY_CRITICAL, "Modbus/TCP",
                        f"Force Listen Only Mode (FC=8, SubFC=4) sent from {pkt.src_ip} "
                        f"to {pkt.dst_ip}. This disables the slave from responding — "
                        "a known ICS DoS attack used in real-world incidents.",
                        [f"{pkt.src_ip}→{pkt.dst_ip}"],
                        "Immediately block FC=8/SubFC=4 at the OT firewall. "
                        "Investigate the source IP.",
                        ["CVE-2017-6034", "NIST SP 800-82"],
                        mitre_ics=["T0814 — Denial of Service",
                                  "T0881 — Service Stop"])
                    return

    def check_no_encryption(self):
        if self.modbus_pkts:
            self.finding("MODBUS-008", "Modbus/TCP traffic is unencrypted (by design)",
                self.SEVERITY_HIGH, "Modbus/TCP",
                f"{len(self.modbus_pkts)} Modbus/TCP packets detected. Modbus has no built-in "
                "authentication or encryption — all commands, responses, and register values "
                "are transmitted in plaintext.",
                [f"Total Modbus packets: {len(self.modbus_pkts)}"],
                "Deploy a Modbus-aware DPI firewall (e.g., Tofino, Bayshore) between zones. "
                "Consider Modbus/TCP Security (TLS wrapper) where supported. "
                "Implement network segmentation per IEC 62443 zones/conduits.",
                ["IEC 62443-3-3 SR 4.1", "NIST SP 800-82 Rev 3"],
                mitre_ics=["T0830 — Man in the Middle"])
