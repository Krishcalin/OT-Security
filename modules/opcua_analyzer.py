"""
OPC UA Security Analyzer
===========================
Port: 4840/4843 | Protocol: OPC Unified Architecture
"""
from collections import defaultdict
from typing import List, Dict, Any
from modules.pcap_parser import BaseOTAuditor, Packet

class OpcuaAnalyzer(BaseOTAuditor):
    def run_all_checks(self) -> List[Dict[str, Any]]:
        opcua = [p for p in self.packets if p.ot_protocol in ("opcua", "opcua_tls")]
        if not opcua: return self.findings
        self.opcua_pkts = opcua
        self.check_security_mode()
        self.check_anonymous_access()
        self.check_write_operations()
        self.check_unencrypted_sessions()
        self.check_excessive_browse()
        return self.findings

    def check_security_mode(self):
        none_mode = []
        for pkt in self.opcua_pkts:
            if not pkt.payload: continue
            if b"None" in pkt.payload and b"SecurityMode" in pkt.payload:
                none_mode.append(f"{pkt.src_ip}→{pkt.dst_ip}")
            if b"\x01\x00\x00\x00" in pkt.payload[:20] and pkt.dst_port == 4840:
                if b"\x00\x00\x00\x01" in pkt.payload[40:60]:
                    none_mode.append(f"{pkt.src_ip}→{pkt.dst_ip} — SecurityMode=None")
        if none_mode:
            self.finding("OPCUA-001", f"OPC UA sessions with SecurityMode=None ({len(set(none_mode))})",
                self.SEVERITY_CRITICAL, "OPC UA",
                "OPC UA sessions detected with SecurityMode set to None. "
                "No signing or encryption — all data including credentials transmitted in clear.",
                list(set(none_mode))[:10],
                "Set SecurityMode to SignAndEncrypt on all OPC UA endpoints. "
                "Disable None mode in server configuration.",
                ["OPC 10000-4 — Security Model", "IEC 62443-3-3 SR 4.1"],
                mitre_ics=["T0830 — Man in the Middle"])

    def check_anonymous_access(self):
        anon = []
        for pkt in self.opcua_pkts:
            if not pkt.payload: continue
            if b"Anonymous" in pkt.payload or b"\x00\x00\x00\x00" in pkt.payload[60:70]:
                if b"ActivateSession" in pkt.payload or b"\x01\x00\xd3\x01" in pkt.payload[:20]:
                    anon.append(f"{pkt.src_ip}→{pkt.dst_ip} — Anonymous session")
        if anon:
            self.finding("OPCUA-002", f"OPC UA anonymous access detected ({len(set(anon))})",
                self.SEVERITY_HIGH, "OPC UA",
                "Anonymous OPC UA sessions detected. Any client can connect without credentials.",
                list(set(anon))[:10],
                "Disable anonymous access. Require username/password or X.509 certificate auth.",
                ["OPC 10000-4 — User Authentication", "IEC 62443-3-3 SR 1.1"],
                mitre_ics=["T0812 — Default Credentials"])

    def check_write_operations(self):
        writes = []
        for pkt in self.opcua_pkts:
            if not pkt.payload: continue
            if b"WriteRequest" in pkt.payload or b"\x01\x00\xa1\x02" in pkt.payload[:8]:
                writes.append(f"{pkt.src_ip}→{pkt.dst_ip} — Write operation")
        if writes:
            self.finding("OPCUA-003", f"OPC UA write operations ({len(writes)})",
                self.SEVERITY_HIGH, "OPC UA",
                f"{len(writes)} OPC UA Write requests detected.",
                writes[:15],
                "Restrict write access via OPC UA role-based access control.",
                ["IEC 62443-3-3 SR 3.5"],
                mitre_ics=["T0836 — Modify Parameter"])

    def check_unencrypted_sessions(self):
        plain = [p for p in self.opcua_pkts if p.ot_protocol == "opcua" and p.dst_port == 4840]
        tls = [p for p in self.opcua_pkts if p.ot_protocol == "opcua_tls" or p.dst_port == 4843]
        if plain and not tls:
            self.finding("OPCUA-004", "OPC UA sessions on unencrypted port 4840 only",
                self.SEVERITY_HIGH, "OPC UA",
                f"{len(plain)} OPC UA packets on port 4840 (unencrypted). No TLS sessions detected.",
                [f"Unencrypted: {len(plain)} packets, TLS: {len(tls)} packets"],
                "Enable OPC UA Secure Channel with SignAndEncrypt security policy.",
                ["OPC 10000-6 — Secure Channel", "IEC 62443-3-3 SR 4.1"],
                mitre_ics=["T0830 — Man in the Middle"])

    def check_excessive_browse(self):
        browse_srcs = defaultdict(int)
        for pkt in self.opcua_pkts:
            if not pkt.payload: continue
            if b"BrowseRequest" in pkt.payload or b"\x01\x00\x0f\x02" in pkt.payload[:8]:
                browse_srcs[pkt.src_ip] += 1
        scanners = [(ip, c) for ip, c in browse_srcs.items() if c > 50]
        if scanners:
            items = [f"{ip}: {c} Browse requests" for ip, c in scanners]
            self.finding("OPCUA-005", f"Excessive OPC UA Browse requests ({len(scanners)} sources)",
                self.SEVERITY_MEDIUM, "OPC UA",
                "Excessive Browse requests indicate OPC UA namespace enumeration.",
                items,
                "Rate-limit Browse operations. Restrict to authorized clients.",
                ["IEC 62443-3-3 SR 7.6"],
                mitre_ics=["T0846 — Remote System Discovery"])
