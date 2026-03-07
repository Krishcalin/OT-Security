"""
BACnet/IP Security Analyzer
==============================
Port: 47808 (UDP) | Protocol: Building Automation and Control Networks
Detects: WriteProperty abuse, DeviceCommunicationControl, ReinitializeDevice,
         Who-Is scanning, unauthorized BACnet routing, unencrypted traffic
"""
from collections import defaultdict
from typing import List, Dict, Any
from modules.pcap_parser import BaseOTAuditor, Packet

BACNET_WHOIS = 0x08
BACNET_IAM = 0x00
BACNET_WRITE_PROP = 0x0F
BACNET_WRITE_PROP_MULTI = 0x10
BACNET_REINIT_DEVICE = 0x14
BACNET_DEV_COMM_CTRL = 0x11
BACNET_CONFIRMED_COV = 0x01
BACNET_READ_PROP = 0x0C
BACNET_SUBSCRIBE_COV = 0x05
BACNET_CREATE_OBJECT = 0x0A
BACNET_DELETE_OBJECT = 0x0B

DANGEROUS_SERVICES = {
    BACNET_WRITE_PROP: "WriteProperty — modify BAS setpoints/schedules",
    BACNET_WRITE_PROP_MULTI: "WritePropertyMultiple — bulk property modification",
    BACNET_REINIT_DEVICE: "ReinitializeDevice — reboot BACnet controller",
    BACNET_DEV_COMM_CTRL: "DeviceCommunicationControl — disable device communication (DoS)",
    BACNET_CREATE_OBJECT: "CreateObject — add objects to controllers",
    BACNET_DELETE_OBJECT: "DeleteObject — remove objects from controllers",
}

class BacnetAnalyzer(BaseOTAuditor):

    def run_all_checks(self) -> List[Dict[str, Any]]:
        bacnet_pkts = [p for p in self.packets if p.ot_protocol == "bacnet"]
        if not bacnet_pkts:
            return self.findings
        self.bacnet_pkts = bacnet_pkts
        self.check_write_operations()
        self.check_device_reinitialize()
        self.check_comm_control()
        self.check_whois_scanning()
        self.check_unauthorized_sources()
        self.check_no_security()
        return self.findings

    def _get_service_choice(self, payload: bytes) -> int:
        if len(payload) < 6:
            return -1
        # BACnet/IP: BVLC header (4 bytes) + NPDU + APDU
        bvlc_type = payload[0]
        bvlc_func = payload[1]
        bvlc_len = (payload[2] << 8) | payload[3]
        # NPDU starts at offset 4
        npdu_offset = 4
        if npdu_offset >= len(payload):
            return -1
        npdu_ver = payload[npdu_offset]
        npdu_ctrl = payload[npdu_offset + 1] if npdu_offset + 1 < len(payload) else 0
        # Calculate APDU offset (skip NPDU variable fields)
        apdu_offset = npdu_offset + 2
        if npdu_ctrl & 0x08:  # DNET present
            apdu_offset += 4  # Simplified
        if npdu_ctrl & 0x04:  # SNET present
            apdu_offset += 4
        if apdu_offset >= len(payload):
            return -1
        apdu_type = (payload[apdu_offset] >> 4) & 0x0F
        if apdu_type in (0, 1):  # Confirmed/Unconfirmed request
            if apdu_type == 0 and apdu_offset + 3 < len(payload):
                return payload[apdu_offset + 3]  # Service choice
            if apdu_type == 1 and apdu_offset + 1 < len(payload):
                return payload[apdu_offset + 1]  # Service choice
        return -1

    def check_write_operations(self):
        writes = []
        for pkt in self.bacnet_pkts:
            if not pkt.payload:
                continue
            sc = self._get_service_choice(pkt.payload)
            if sc in (BACNET_WRITE_PROP, BACNET_WRITE_PROP_MULTI):
                writes.append(f"{pkt.src_ip}→{pkt.dst_ip} — {DANGEROUS_SERVICES.get(sc, f'SC={sc}')}")
        if writes:
            self.finding("BACNET-001", f"BACnet write operations detected ({len(writes)})",
                self.SEVERITY_HIGH, "BACnet/IP",
                f"{len(writes)} BACnet WriteProperty/WritePropertyMultiple commands detected. "
                "These can modify HVAC setpoints, lighting schedules, and access control.",
                writes[:20],
                "Segment BACnet networks from IT. Restrict write access to authorized BMS workstations.",
                ["ASHRAE 135 — BACnet Security", "IEC 62443-3-3 SR 3.5"],
                mitre_ics=["T0836 — Modify Parameter"])

    def check_device_reinitialize(self):
        reinit = []
        for pkt in self.bacnet_pkts:
            if not pkt.payload:
                continue
            sc = self._get_service_choice(pkt.payload)
            if sc == BACNET_REINIT_DEVICE:
                reinit.append(f"{pkt.src_ip}→{pkt.dst_ip} — ReinitializeDevice")
        if reinit:
            self.finding("BACNET-002", f"BACnet ReinitializeDevice commands ({len(reinit)})",
                self.SEVERITY_CRITICAL, "BACnet/IP",
                f"{len(reinit)} ReinitializeDevice command(s) detected. This reboots "
                "building controllers, disrupting HVAC, fire, and access systems.",
                reinit,
                "Block ReinitializeDevice at network level. Require BACnet/SC (Secure Connect).",
                ["ASHRAE 135 Addendum — BACnet/SC"],
                mitre_ics=["T0816 — Device Restart/Shutdown"])

    def check_comm_control(self):
        comm_ctrl = []
        for pkt in self.bacnet_pkts:
            if not pkt.payload:
                continue
            sc = self._get_service_choice(pkt.payload)
            if sc == BACNET_DEV_COMM_CTRL:
                comm_ctrl.append(f"{pkt.src_ip}→{pkt.dst_ip} — DeviceCommunicationControl")
        if comm_ctrl:
            self.finding("BACNET-003", f"BACnet DeviceCommunicationControl detected ({len(comm_ctrl)})",
                self.SEVERITY_CRITICAL, "BACnet/IP",
                f"{len(comm_ctrl)} DeviceCommunicationControl command(s). This can disable "
                "a controller's network communication — a BACnet-specific DoS attack.",
                comm_ctrl,
                "Block DeviceCommunicationControl service at the firewall.",
                ["ASHRAE — BACnet Security Considerations"],
                mitre_ics=["T0814 — Denial of Service"])

    def check_whois_scanning(self):
        whois_srcs = defaultdict(int)
        for pkt in self.bacnet_pkts:
            if not pkt.payload:
                continue
            sc = self._get_service_choice(pkt.payload)
            if sc == BACNET_WHOIS:
                whois_srcs[pkt.src_ip] += 1
        scanners = [(ip, cnt) for ip, cnt in whois_srcs.items() if cnt > 10]
        if scanners:
            items = [f"{ip}: {cnt} Who-Is requests" for ip, cnt in scanners]
            self.finding("BACNET-004", f"BACnet Who-Is scanning detected ({len(scanners)} sources)",
                self.SEVERITY_MEDIUM, "BACnet/IP",
                "Excessive Who-Is requests indicate BACnet device enumeration/scanning.",
                items,
                "Restrict Who-Is to authorized BMS management stations.",
                ["IEC 62443-3-3 SR 7.6"],
                mitre_ics=["T0846 — Remote System Discovery"])

    def check_unauthorized_sources(self):
        src_to_controller = defaultdict(set)
        for pkt in self.bacnet_pkts:
            if pkt.dst_port == 47808:
                src_to_controller[pkt.dst_ip].add(pkt.src_ip)
        multi = [(c, s) for c, s in src_to_controller.items() if len(s) > 3]
        if multi:
            items = [f"Controller {c}: {len(s)} sources" for c, s in multi]
            self.finding("BACNET-005", f"BACnet controllers accessed by many sources ({len(multi)})",
                self.SEVERITY_MEDIUM, "BACnet/IP",
                "Multiple IPs communicating with BACnet controllers.",
                items,
                "Restrict BACnet access to authorized BMS workstations.",
                ["IEC 62443-3-3 SR 5.1"])

    def check_no_security(self):
        if self.bacnet_pkts:
            has_sc = any(b"BACnet/SC" in p.payload or b"\x0b\xac" in p.payload[:4]
                        for p in self.bacnet_pkts if p.payload)
            if not has_sc:
                self.finding("BACNET-006", "BACnet/IP traffic without BACnet/SC (Secure Connect)",
                    self.SEVERITY_HIGH, "BACnet/IP",
                    f"{len(self.bacnet_pkts)} BACnet packets without BACnet Secure Connect (TLS). "
                    "Classic BACnet/IP has no authentication or encryption.",
                    [f"Total BACnet packets: {len(self.bacnet_pkts)}"],
                    "Upgrade to BACnet/SC (ASHRAE 135 Addendum BJ) for TLS-based security. "
                    "For legacy devices, implement network-level segmentation.",
                    ["ASHRAE 135 — BACnet/SC", "IEC 62443-3-3 SR 4.1"],
                    mitre_ics=["T0830 — Man in the Middle"])
