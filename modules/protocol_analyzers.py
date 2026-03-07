"""
EtherNet/IP (CIP) Security Analyzer
Port: 44818 | Protocol: Common Industrial Protocol over EtherNet/IP
"""
from collections import defaultdict
from typing import List, Dict, Any
from modules.pcap_parser import BaseOTAuditor, Packet

class EthernetIpAnalyzer(BaseOTAuditor):
    def run_all_checks(self) -> List[Dict[str, Any]]:
        enip = [p for p in self.packets if p.ot_protocol == "enip"]
        if not enip: return self.findings
        self.enip_pkts = enip
        self.check_program_operations()
        self.check_config_changes()
        self.check_unauth_access()
        self.check_no_encryption()
        return self.findings

    def check_program_operations(self):
        prog_ops = []
        for pkt in self.enip_pkts:
            if not pkt.payload: continue
            if b"\x4b" in pkt.payload[24:30] or b"\x4c" in pkt.payload[24:30]:
                prog_ops.append(f"{pkt.src_ip}→{pkt.dst_ip} — CIP program upload/download")
            if b"\x52" in pkt.payload[20:30]:
                prog_ops.append(f"{pkt.src_ip}→{pkt.dst_ip} — CIP Unconnected Send (execute)")
        if prog_ops:
            self.finding("ENIP-001", f"EtherNet/IP program operations ({len(prog_ops)})",
                self.SEVERITY_CRITICAL, "EtherNet/IP",
                "CIP program upload/download or execution commands detected.",
                prog_ops[:15],
                "Restrict CIP write access. Enable CIP Security (EtherNet/IP Confidentiality).",
                ["ODVA CIP Security", "IEC 62443-3-3 SR 3.5"],
                mitre_ics=["T0843 — Program Download"])

    def check_config_changes(self):
        config_writes = []
        for pkt in self.enip_pkts:
            if not pkt.payload: continue
            if b"\x10" in pkt.payload[24:28] or b"\x0e" in pkt.payload[24:28]:
                config_writes.append(f"{pkt.src_ip}→{pkt.dst_ip} — CIP Set_Attribute/Write")
        if config_writes:
            self.finding("ENIP-002", f"EtherNet/IP configuration changes ({len(config_writes)})",
                self.SEVERITY_HIGH, "EtherNet/IP",
                "CIP Set_Attribute/configuration write commands detected.",
                config_writes[:15],
                "Restrict CIP configuration access to authorized engineering stations.",
                ["ODVA CIP Security Specification"],
                mitre_ics=["T0836 — Modify Parameter"])

    def check_unauth_access(self):
        src_to_ctrl = defaultdict(set)
        for pkt in self.enip_pkts:
            if pkt.dst_port == 44818:
                src_to_ctrl[pkt.dst_ip].add(pkt.src_ip)
        multi = [(c, s) for c, s in src_to_ctrl.items() if len(s) > 3]
        if multi:
            items = [f"Controller {c}: {len(s)} sources" for c, s in multi]
            self.finding("ENIP-003", f"Controllers accessed by multiple sources ({len(multi)})",
                self.SEVERITY_MEDIUM, "EtherNet/IP",
                "Multiple IPs accessing EtherNet/IP controllers.", items,
                "Implement allowlists per controller.",
                ["IEC 62443-3-3 SR 5.1"],
                mitre_ics=["T0886 — Remote Services"])

    def check_no_encryption(self):
        if self.enip_pkts:
            self.finding("ENIP-004", "EtherNet/IP traffic is unencrypted",
                self.SEVERITY_HIGH, "EtherNet/IP",
                f"{len(self.enip_pkts)} unencrypted EtherNet/IP packets. "
                "Classic EtherNet/IP has no built-in security.",
                [f"Total packets: {len(self.enip_pkts)}"],
                "Enable CIP Security (ODVA EtherNet/IP Confidentiality Profile). "
                "Segment with OT-aware firewalls.",
                ["ODVA CIP Security", "IEC 62443-3-3 SR 4.1"],
                mitre_ics=["T0830 — Man in the Middle"])


"""
IEC 60870-5-104 Security Analyzer
Port: 2404 | Protocol: IEC 104 (Telecontrol)
"""
class Iec104Analyzer(BaseOTAuditor):
    def run_all_checks(self) -> List[Dict[str, Any]]:
        iec104 = [p for p in self.packets if p.ot_protocol == "iec104"]
        if not iec104: return self.findings
        self.iec104_pkts = iec104
        self.check_control_commands()
        self.check_interrogation()
        self.check_setpoint_changes()
        self.check_no_security()
        return self.findings

    def check_control_commands(self):
        controls = []
        for pkt in self.iec104_pkts:
            if not pkt.payload or len(pkt.payload) < 6: continue
            if pkt.payload[0] == 0x68:
                apdu_len = pkt.payload[1]
                if apdu_len > 4 and len(pkt.payload) > 6:
                    type_id = pkt.payload[6] if len(pkt.payload) > 6 else 0
                    if type_id in (45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64):
                        controls.append(f"{pkt.src_ip}→{pkt.dst_ip} — TypeID={type_id} (control command)")
        if controls:
            self.finding("IEC104-001", f"IEC 104 control commands detected ({len(controls)})",
                self.SEVERITY_HIGH, "IEC 60870-5-104",
                f"{len(controls)} IEC 104 control/setpoint commands detected.",
                controls[:15],
                "Implement IEC 62351 for authentication. Restrict control to authorized masters.",
                ["IEC 62351-5", "IEC 62443-3-3 SR 3.5"],
                mitre_ics=["T0855 — Unauthorized Command Message"])

    def check_interrogation(self):
        interrog = []
        for pkt in self.iec104_pkts:
            if not pkt.payload or len(pkt.payload) < 7: continue
            if pkt.payload[0] == 0x68 and len(pkt.payload) > 6:
                type_id = pkt.payload[6] if len(pkt.payload) > 6 else 0
                if type_id == 100:
                    interrog.append(f"{pkt.src_ip}→{pkt.dst_ip} — General Interrogation")
        if interrog and len(interrog) > 5:
            self.finding("IEC104-002", f"Excessive IEC 104 interrogation commands ({len(interrog)})",
                self.SEVERITY_MEDIUM, "IEC 60870-5-104",
                "Many general interrogation commands may indicate scanning.",
                interrog[:10],
                "Monitor interrogation frequency. Rate-limit per source.",
                ["IEC 62443-3-3 SR 7.6"],
                mitre_ics=["T0846 — Remote System Discovery"])

    def check_setpoint_changes(self):
        setpoints = []
        for pkt in self.iec104_pkts:
            if not pkt.payload or len(pkt.payload) < 7: continue
            if pkt.payload[0] == 0x68 and len(pkt.payload) > 6:
                type_id = pkt.payload[6] if len(pkt.payload) > 6 else 0
                if type_id in (48, 49, 50, 61, 62, 63):
                    setpoints.append(f"{pkt.src_ip}→{pkt.dst_ip} — Setpoint command TypeID={type_id}")
        if setpoints:
            self.finding("IEC104-003", f"IEC 104 setpoint commands ({len(setpoints)})",
                self.SEVERITY_HIGH, "IEC 60870-5-104",
                "Setpoint commands can modify analog values in RTUs/controllers.",
                setpoints[:15],
                "Restrict setpoint commands to authorized SCADA masters.",
                ["IEC 62351-5"],
                mitre_ics=["T0836 — Modify Parameter"])

    def check_no_security(self):
        if self.iec104_pkts:
            self.finding("IEC104-004", "IEC 104 traffic without IEC 62351 security",
                self.SEVERITY_HIGH, "IEC 60870-5-104",
                f"{len(self.iec104_pkts)} IEC 104 packets without encryption/authentication.",
                [f"Total: {len(self.iec104_pkts)}"],
                "Implement IEC 62351 (TLS for SCADA). Deploy bump-in-the-wire encryptors.",
                ["IEC 62351-3/5", "IEC 62443-3-3 SR 4.1"],
                mitre_ics=["T0830 — Man in the Middle"])


"""
MQTT Security Analyzer
Port: 1883/8883 | Protocol: Message Queuing Telemetry Transport
"""
class MqttAnalyzer(BaseOTAuditor):
    def run_all_checks(self) -> List[Dict[str, Any]]:
        mqtt = [p for p in self.packets if p.ot_protocol in ("mqtt", "mqtt_tls")]
        if not mqtt: return self.findings
        self.mqtt_pkts = mqtt
        self.check_unencrypted()
        self.check_anonymous_connect()
        self.check_wildcard_subscribe()
        self.check_sensitive_topics()
        return self.findings

    def check_unencrypted(self):
        plain = [p for p in self.mqtt_pkts if p.dst_port == 1883 or p.src_port == 1883]
        if plain:
            self.finding("MQTT-001", f"Unencrypted MQTT traffic ({len(plain)} packets)",
                self.SEVERITY_HIGH, "MQTT",
                "MQTT running on port 1883 (unencrypted). Credentials, telemetry data, "
                "and control commands are transmitted in plaintext.",
                [f"Unencrypted MQTT: {len(plain)} packets"],
                "Migrate to MQTT over TLS (port 8883). Enable client certificate auth.",
                ["IEC 62443-3-3 SR 4.1", "OWASP IoT — Insecure Communication"],
                mitre_ics=["T0830 — Man in the Middle"])

    def check_anonymous_connect(self):
        anon = []
        for pkt in self.mqtt_pkts:
            if not pkt.payload or len(pkt.payload) < 4: continue
            pkt_type = (pkt.payload[0] >> 4) & 0x0F
            if pkt_type == 1:  # CONNECT
                if len(pkt.payload) > 12:
                    flags = pkt.payload[9] if len(pkt.payload) > 9 else 0
                    has_username = (flags >> 7) & 1
                    has_password = (flags >> 6) & 1
                    if not has_username and not has_password:
                        anon.append(f"{pkt.src_ip}→{pkt.dst_ip} — Anonymous CONNECT")
        if anon:
            self.finding("MQTT-002", f"MQTT anonymous connections ({len(anon)})",
                self.SEVERITY_HIGH, "MQTT",
                "MQTT CONNECT packets without username/password authentication.",
                anon[:10],
                "Require authentication on all MQTT connections. Use client certificates.",
                ["IEC 62443-3-3 SR 1.1"],
                mitre_ics=["T0812 — Default Credentials"])

    def check_wildcard_subscribe(self):
        wildcard = []
        for pkt in self.mqtt_pkts:
            if not pkt.payload or len(pkt.payload) < 4: continue
            pkt_type = (pkt.payload[0] >> 4) & 0x0F
            if pkt_type == 8:  # SUBSCRIBE
                if b"#" in pkt.payload or b"+" in pkt.payload:
                    wildcard.append(f"{pkt.src_ip} — Wildcard subscribe (#/+)")
        if wildcard:
            self.finding("MQTT-003", f"MQTT wildcard subscriptions ({len(wildcard)})",
                self.SEVERITY_MEDIUM, "MQTT",
                "Wildcard MQTT subscriptions (# or +) capture all messages on the broker.",
                wildcard[:10],
                "Implement topic-level ACLs. Restrict wildcard subscriptions.",
                ["MQTT Security Best Practices"],
                mitre_ics=["T0830 — Man in the Middle"])

    def check_sensitive_topics(self):
        topics = []
        sensitive = [b"plc", b"scada", b"control", b"setpoint", b"actuator",
                    b"valve", b"pump", b"relay", b"command", b"firmware"]
        for pkt in self.mqtt_pkts:
            if not pkt.payload: continue
            for s in sensitive:
                if s in pkt.payload.lower():
                    topics.append(f"{pkt.src_ip} — topic contains '{s.decode()}'")
                    break
        if topics:
            self.finding("MQTT-004", f"MQTT traffic with sensitive OT topics ({len(topics)})",
                self.SEVERITY_MEDIUM, "MQTT",
                "MQTT messages reference sensitive OT topics (PLC, SCADA, control, setpoint).",
                topics[:15],
                "Encrypt MQTT (TLS). Implement topic-level authorization.",
                ["IEC 62443-3-3 SR 4.1"])
