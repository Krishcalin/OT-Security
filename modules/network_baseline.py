"""
PROFINET Security Analyzer
Port: 34962-34964 | Protocol: PROFINET IO/CBA/DCP
"""
from collections import defaultdict
from typing import List, Dict, Any
from modules.pcap_parser import BaseOTAuditor, Packet

class ProfinetAnalyzer(BaseOTAuditor):
    def run_all_checks(self) -> List[Dict[str, Any]]:
        pn = [p for p in self.packets if p.ot_protocol == "profinet"]
        if not pn: return self.findings
        self.pn_pkts = pn
        self.check_dcp_identify()
        self.check_config_changes()
        self.check_no_encryption()
        return self.findings

    def check_dcp_identify(self):
        dcp = []
        for pkt in self.pn_pkts:
            if not pkt.payload: continue
            if b"\xfe\xfe" in pkt.payload[:4] or pkt.dst_port == 34964:
                dcp.append(f"{pkt.src_ip}→{pkt.dst_ip} — PROFINET DCP")
        if dcp and len(dcp) > 10:
            self.finding("PN-001", f"PROFINET DCP device identification ({len(dcp)})",
                self.SEVERITY_MEDIUM, "PROFINET",
                f"{len(dcp)} PROFINET DCP requests — device enumeration detected.",
                dcp[:10],
                "Restrict DCP to authorized engineering stations. Monitor for scanning.",
                ["IEC 62443-3-3 SR 7.6"],
                mitre_ics=["T0846 — Remote System Discovery"])

    def check_config_changes(self):
        configs = []
        for pkt in self.pn_pkts:
            if not pkt.payload: continue
            if b"Set" in pkt.payload and (b"NameOfStation" in pkt.payload or b"IPAddress" in pkt.payload):
                configs.append(f"{pkt.src_ip}→{pkt.dst_ip} — DCP Set (config change)")
        if configs:
            self.finding("PN-002", f"PROFINET configuration changes ({len(configs)})",
                self.SEVERITY_HIGH, "PROFINET",
                "PROFINET DCP Set commands can change device names and IP addresses.",
                configs[:10],
                "Protect PROFINET devices against unauthorized DCP Set commands.",
                ["IEC 62443-3-3 SR 3.5"],
                mitre_ics=["T0836 — Modify Parameter"])

    def check_no_encryption(self):
        if self.pn_pkts:
            self.finding("PN-003", "PROFINET traffic is unencrypted",
                self.SEVERITY_HIGH, "PROFINET",
                f"{len(self.pn_pkts)} unencrypted PROFINET packets detected.",
                [f"Total: {len(self.pn_pkts)}"],
                "Implement PROFINET Security Classes (Class 2/3 for encryption). "
                "Deploy network segmentation.",
                ["IEC 62443-3-3 SR 4.1", "PROFINET Security Guideline"],
                mitre_ics=["T0830 — Man in the Middle"])


"""
Network Baseline & Asset Discovery Analyzer
Analyzes all traffic to build asset inventory, communication matrix, and Purdue level mapping
"""

class NetworkBaselineAnalyzer(BaseOTAuditor):

    PURDUE_PORT_MAP = {
        502: 1, 102: 1, 44818: 1, 2404: 1, 34962: 0, 34964: 0, 20000: 1,
        47808: 1, 4840: 2, 1883: 2, 80: 3, 443: 3, 8080: 3,
        3389: 3, 5900: 3, 22: 3, 23: 3, 21: 3,
        1433: 3, 3306: 3, 5432: 3,  # Database ports — historian level
        25: 4, 53: 4, 389: 4, 636: 4,  # Email, DNS, LDAP — enterprise
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.all_packets:
            return self.findings
        self.check_asset_inventory()
        self.check_it_ot_crossover()
        self.check_insecure_protocols()
        self.check_communication_anomalies()
        self.check_multicast_broadcast()
        return self.findings

    def check_asset_inventory(self):
        assets = defaultdict(lambda: {"ports": set(), "protocols": set(),
                                       "peers": set(), "packet_count": 0})
        for pkt in self.all_packets:
            for ip in (pkt.src_ip, pkt.dst_ip):
                if ip and not ip.startswith("0.") and ip != "255.255.255.255":
                    assets[ip]["packet_count"] += 1
                    if pkt.ot_protocol:
                        assets[ip]["protocols"].add(pkt.ot_protocol)
                    assets[ip]["ports"].add(pkt.dst_port)
            if pkt.src_ip and pkt.dst_ip:
                assets[pkt.src_ip]["peers"].add(pkt.dst_ip)
                assets[pkt.dst_ip]["peers"].add(pkt.src_ip)
        ot_assets = {ip: a for ip, a in assets.items()
                    if a["protocols"] & {"modbus","s7comm","dnp3","bacnet","opcua","enip","iec104","profinet","mqtt"}}
        items = [f"{ip}: protocols={','.join(a['protocols'])}, peers={len(a['peers'])}, "
                f"packets={a['packet_count']}" for ip, a in sorted(ot_assets.items())]
        if items:
            self.finding("NET-001", f"OT asset inventory — {len(ot_assets)} devices discovered",
                self.SEVERITY_LOW, "Network Baseline",
                f"{len(ot_assets)} OT devices identified using industrial protocols.",
                items[:40],
                "Maintain an authoritative OT asset inventory. Compare against baseline.",
                ["IEC 62443-2-1 SR 4.2", "NIST SP 800-82 Rev 3"],
                details={"total_assets": len(assets), "ot_assets": len(ot_assets)})

    def check_it_ot_crossover(self):
        it_protocols = {"http", "https", "ssh", "telnet", "ftp", "rdp", "vnc", "snmp"}
        ot_protocols = {"modbus", "s7comm", "dnp3", "bacnet", "opcua", "enip", "iec104", "profinet"}
        ip_protocols = defaultdict(set)
        for pkt in self.all_packets:
            if pkt.ot_protocol:
                ip_protocols[pkt.src_ip].add(pkt.ot_protocol)
                ip_protocols[pkt.dst_ip].add(pkt.ot_protocol)
        crossover = []
        for ip, protos in ip_protocols.items():
            has_it = protos & it_protocols
            has_ot = protos & ot_protocols
            if has_it and has_ot:
                crossover.append(f"{ip}: IT={','.join(has_it)} + OT={','.join(has_ot)}")
        if crossover:
            self.finding("NET-002", f"IT/OT protocol crossover detected ({len(crossover)} hosts)",
                self.SEVERITY_HIGH, "Network Baseline",
                f"{len(crossover)} host(s) use both IT and OT protocols. This indicates "
                "potential flat network without IT/OT segmentation (Purdue model violation).",
                crossover[:20],
                "Implement Purdue model zones: separate IT (L4-5) from OT (L0-2) with DMZ (L3.5). "
                "No direct IT-to-OT communication.",
                ["IEC 62443-3-3 SR 5.1", "Purdue Model — Zone Segmentation"],
                mitre_ics=["T0886 — Remote Services"])

    def check_insecure_protocols(self):
        insecure = {"telnet": [], "ftp": [], "http": [], "snmp": [], "vnc": [], "rdp": []}
        for pkt in self.all_packets:
            if pkt.ot_protocol in insecure:
                insecure[pkt.ot_protocol].append(f"{pkt.src_ip}→{pkt.dst_ip}:{pkt.dst_port}")
        findings = []
        for proto, pkts in insecure.items():
            if pkts:
                unique = list(set(pkts))
                findings.append(f"{proto.upper()}: {len(unique)} unique flows")
        if findings:
            self.finding("NET-003", f"Insecure IT protocols on OT network ({len(findings)} types)",
                self.SEVERITY_HIGH, "Network Baseline",
                "Insecure plaintext protocols detected on the OT network.",
                findings,
                "Replace Telnet→SSH, FTP→SFTP, HTTP→HTTPS. Disable VNC/RDP "
                "or tunnel through encrypted VPN.",
                ["IEC 62443-3-3 SR 4.1", "NIST SP 800-82 Rev 3"],
                mitre_ics=["T0886 — Remote Services", "T0830 — Man in the Middle"])

    def check_communication_anomalies(self):
        pair_count = defaultdict(int)
        for pkt in self.all_packets:
            if pkt.src_ip and pkt.dst_ip:
                pair = tuple(sorted([pkt.src_ip, pkt.dst_ip]))
                pair_count[pair] += 1
        top_talkers = sorted(pair_count.items(), key=lambda x: -x[1])[:10]
        if top_talkers:
            items = [f"{a}↔{b}: {c} packets" for (a, b), c in top_talkers]
            self.finding("NET-004", "Top communication pairs (baseline reference)",
                self.SEVERITY_LOW, "Network Baseline",
                "Top 10 communication pairs by packet count for baseline establishment.",
                items,
                "Document as baseline. Alert on new communication pairs not in baseline.",
                ["IEC 62443-3-3 SR 6.1"],
                details={"pairs": len(pair_count)})

    def check_multicast_broadcast(self):
        broadcasts = [p for p in self.all_packets
                     if p.dst_ip and (p.dst_ip.endswith(".255") or
                        p.dst_ip.startswith("224.") or p.dst_ip == "255.255.255.255")]
        if broadcasts and len(broadcasts) > 100:
            self.finding("NET-005", f"Excessive broadcast/multicast traffic ({len(broadcasts)} packets)",
                self.SEVERITY_MEDIUM, "Network Baseline",
                "High volume of broadcast/multicast traffic on the OT network. "
                "Excessive broadcasts can impact real-time control systems.",
                [f"Broadcast/multicast packets: {len(broadcasts)}"],
                "Implement storm control. Segment VLANs to contain broadcast domains.",
                ["IEC 62443-3-3 SR 5.2"])
