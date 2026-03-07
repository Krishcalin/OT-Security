"""
IEC 62443 Compliance Analyzer
================================
Maps PCAP findings to IEC 62443-3-3 System Requirements (SR)
"""
from collections import defaultdict
from typing import List, Dict, Any
from modules.pcap_parser import BaseOTAuditor, Packet

class Iec62443Analyzer(BaseOTAuditor):
    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.all_packets: return self.findings
        self.check_zone_segmentation()
        self.check_encrypted_conduits()
        self.check_authentication_coverage()
        self.check_audit_trail()
        return self.findings

    def check_zone_segmentation(self):
        ot_ports = {502, 102, 20000, 47808, 4840, 44818, 2404, 34962, 34964}
        it_ports = {80, 443, 22, 23, 21, 3389, 5900, 25, 53, 389, 445, 135, 139}
        subnets = defaultdict(lambda: {"ot": set(), "it": set()})
        for pkt in self.all_packets:
            subnet = ".".join(pkt.src_ip.split(".")[:3]) if pkt.src_ip else ""
            if not subnet: continue
            if pkt.dst_port in ot_ports or pkt.src_port in ot_ports:
                subnets[subnet]["ot"].add(pkt.dst_port if pkt.dst_port in ot_ports else pkt.src_port)
            if pkt.dst_port in it_ports or pkt.src_port in it_ports:
                subnets[subnet]["it"].add(pkt.dst_port if pkt.dst_port in it_ports else pkt.src_port)
        mixed = []
        for subnet, protos in subnets.items():
            if protos["ot"] and protos["it"]:
                mixed.append(f"Subnet {subnet}.0/24: OT ports={protos['ot']}, IT ports={protos['it']}")
        if mixed:
            self.finding("IEC-001", f"IEC 62443 SR 5.1: IT/OT on same subnet ({len(mixed)})",
                self.SEVERITY_CRITICAL, "IEC 62443 Compliance",
                f"{len(mixed)} subnet(s) carry both IT and OT traffic — violating zone segmentation.",
                mixed[:15],
                "Segment IT and OT into separate zones per IEC 62443-3-2. "
                "Deploy conduit firewalls with DPI between zones.",
                ["IEC 62443-3-3 SR 5.1 — Network Segmentation"],
                mitre_ics=["T0886 — Remote Services"])

    def check_encrypted_conduits(self):
        ot_protocols = {"modbus", "s7comm", "dnp3", "bacnet", "enip", "iec104", "profinet"}
        unencrypted = defaultdict(int)
        for pkt in self.all_packets:
            if pkt.ot_protocol in ot_protocols:
                unencrypted[pkt.ot_protocol] += 1
        if unencrypted:
            items = [f"{proto}: {cnt} unencrypted packets" for proto, cnt in unencrypted.items()]
            self.finding("IEC-002", f"IEC 62443 SR 4.1: Unencrypted OT conduits ({len(unencrypted)} protocols)",
                self.SEVERITY_HIGH, "IEC 62443 Compliance",
                "Multiple OT protocols running without encryption.",
                items,
                "Implement TLS wrappers, VPN tunnels, or protocol-native security "
                "(DNP3-SA, OPC UA SecureChannel, BACnet/SC, CIP Security).",
                ["IEC 62443-3-3 SR 4.1 — Confidentiality of Information in Transit"])

    def check_authentication_coverage(self):
        no_auth = {"modbus": "No built-in auth", "s7comm": "No auth (classic S7)",
                  "bacnet": "No auth (classic BACnet/IP)", "enip": "No auth (classic CIP)"}
        present = set()
        for pkt in self.all_packets:
            if pkt.ot_protocol in no_auth:
                present.add(pkt.ot_protocol)
        if present:
            items = [f"{p}: {no_auth[p]}" for p in present]
            self.finding("IEC-003", f"IEC 62443 SR 1.1: OT protocols without authentication ({len(present)})",
                self.SEVERITY_HIGH, "IEC 62443 Compliance",
                "OT protocols detected that have no built-in authentication mechanism.",
                items,
                "Deploy compensating controls: OT-aware firewalls with DPI, "
                "source IP allowlists, and network segmentation.",
                ["IEC 62443-3-3 SR 1.1 — Human User Identification & Authentication"])

    def check_audit_trail(self):
        has_syslog = any(p.dst_port == 514 or p.src_port == 514 for p in self.all_packets)
        has_snmp_trap = any(p.dst_port == 162 or p.src_port == 162 for p in self.all_packets)
        if not has_syslog and not has_snmp_trap:
            self.finding("IEC-004", "IEC 62443 SR 6.1: No syslog/SNMP trap traffic detected",
                self.SEVERITY_MEDIUM, "IEC 62443 Compliance",
                "No syslog (514) or SNMP trap (162) traffic detected. OT device events "
                "may not be forwarded to a central monitoring system.",
                ["No syslog traffic detected", "No SNMP trap traffic detected"],
                "Configure syslog forwarding to a centralized SIEM/log collector. "
                "Deploy OT-aware monitoring (e.g., Dragos, Claroty, Nozomi).",
                ["IEC 62443-3-3 SR 6.1 — Audit Log Accessibility"])


"""
MITRE ATT&CK for ICS Mapper
Maps detected activities to MITRE ATT&CK for ICS techniques
"""
class MitreIcsMapper(BaseOTAuditor):

    TECHNIQUE_PATTERNS = {
        "T0846": {"name": "Remote System Discovery", "ports": {502, 102, 44818, 47808, 20000, 4840},
                  "desc": "OT device enumeration via protocol-specific scanning"},
        "T0886": {"name": "Remote Services", "ports": {22, 23, 3389, 5900, 21},
                  "desc": "Remote access to OT systems via IT management protocols"},
        "T0830": {"name": "Man in the Middle", "ports": {502, 102, 20000, 47808, 44818, 1883},
                  "desc": "Unencrypted OT protocols vulnerable to interception"},
        "T0855": {"name": "Unauthorized Command Message", "ports": {502, 102, 20000, 2404, 44818},
                  "desc": "Control commands sent to PLCs/RTUs"},
        "T0814": {"name": "Denial of Service", "ports": {502, 47808},
                  "desc": "DoS attacks against OT devices"},
        "T0812": {"name": "Default Credentials", "ports": {80, 443, 22, 23, 102},
                  "desc": "Access attempts using default/no credentials"},
        "T0836": {"name": "Modify Parameter", "ports": {502, 102, 44818, 2404, 4840},
                  "desc": "Process parameter modification via write commands"},
        "T0843": {"name": "Program Download", "ports": {102, 44818},
                  "desc": "PLC program transfer/modification"},
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        if not self.all_packets: return self.findings
        self.check_technique_coverage()
        self.check_initial_access()
        self.check_lateral_movement()
        return self.findings

    def check_technique_coverage(self):
        detected = defaultdict(int)
        for pkt in self.all_packets:
            for tid, info in self.TECHNIQUE_PATTERNS.items():
                if pkt.dst_port in info["ports"] or pkt.src_port in info["ports"]:
                    detected[tid] += 1
        if detected:
            items = [f"{tid} — {self.TECHNIQUE_PATTERNS[tid]['name']}: "
                    f"{cnt} related packets ({self.TECHNIQUE_PATTERNS[tid]['desc']})"
                    for tid, cnt in sorted(detected.items(), key=lambda x: -x[1])]
            self.finding("MITRE-001", f"MITRE ATT&CK for ICS technique coverage ({len(detected)} techniques)",
                self.SEVERITY_LOW, "MITRE ATT&CK ICS",
                "Traffic patterns map to these MITRE ATT&CK for ICS techniques.",
                items,
                "Use MITRE ATT&CK for ICS to prioritize detection rules and incident response playbooks.",
                ["MITRE ATT&CK for ICS — https://attack.mitre.org/techniques/ics/"],
                mitre_ics=list(detected.keys()))

    def check_initial_access(self):
        remote_access = []
        for pkt in self.all_packets:
            if pkt.ot_protocol in ("telnet", "rdp", "vnc", "ssh", "http"):
                ot_dst = any(p.dst_ip == pkt.dst_ip and p.ot_protocol in
                           ("modbus","s7comm","dnp3","bacnet","enip","iec104")
                           for p in self.all_packets[:5000])
                if ot_dst:
                    remote_access.append(
                        f"{pkt.src_ip}→{pkt.dst_ip}:{pkt.dst_port} ({pkt.ot_protocol}) to OT device")
        if remote_access:
            unique = list(set(remote_access))
            self.finding("MITRE-002", f"T0886 Remote Services to OT devices ({len(unique)} flows)",
                self.SEVERITY_HIGH, "MITRE ATT&CK ICS",
                "IT remote access protocols targeting OT devices. This is a primary "
                "initial access vector in ICS attacks.",
                unique[:15],
                "Disable direct remote access to OT devices. Use jump servers in DMZ.",
                ["MITRE ATT&CK T0886", "IEC 62443-3-3 SR 1.13"],
                mitre_ics=["T0886 — Remote Services", "T0822 — External Remote Services"])

    def check_lateral_movement(self):
        ip_to_ot_protos = defaultdict(set)
        for pkt in self.all_packets:
            if pkt.ot_protocol in ("modbus","s7comm","dnp3","bacnet","enip","iec104","opcua"):
                if pkt.dst_port in (502,102,20000,47808,44818,2404,4840):
                    ip_to_ot_protos[pkt.src_ip].add(pkt.ot_protocol)
        multi_proto = [(ip, protos) for ip, protos in ip_to_ot_protos.items() if len(protos) >= 2]
        if multi_proto:
            items = [f"{ip}: accesses {','.join(protos)}" for ip, protos in multi_proto]
            self.finding("MITRE-003", f"Multi-protocol OT access from single hosts ({len(multi_proto)})",
                self.SEVERITY_HIGH, "MITRE ATT&CK ICS",
                f"{len(multi_proto)} host(s) communicate using multiple OT protocols. "
                "This may indicate lateral movement or a compromised engineering workstation.",
                items[:15],
                "Investigate these hosts. Engineering workstations should be monitored. "
                "Implement network segmentation per protocol zone.",
                ["MITRE ATT&CK T0867 — Lateral Tool Transfer"],
                mitre_ics=["T0867 — Lateral Tool Transfer"])
