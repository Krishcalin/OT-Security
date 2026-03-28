"""Tests for SecureAccessEngine — CIP-005 compliance and jump server detection."""

from datetime import datetime
from scanner.models import OTDevice, ITProtocolHit, RemoteAccessSession, NetworkZone, CommFlow
from scanner.access.engine import SecureAccessEngine


class TestComplianceClassification:
    def test_rdp_to_safety_is_non_compliant(self):
        dev = OTDevice(ip="10.1.0.10")
        dev.device_criticality = "safety_system"
        dev.it_protocols = [ITProtocolHit(
            protocol="RDP", port=3389, transport="TCP",
            src_ip="10.1.2.30", dst_ip="10.1.0.10",
            details={"category": "remote_access", "risk": "high"},
        )]
        dev.protocol_stats = []; dev.remote_access_sessions = []
        zone = NetworkZone(zone_id="z0", subnet="10.1.0.0/24", purdue_level=0,
                           purdue_label="Process", device_ips={"10.1.0.10"}, device_count=1)

        engine = SecureAccessEngine([dev], [], [zone], [])
        sessions = engine.audit()
        assert "10.1.0.10" in sessions
        s = sessions["10.1.0.10"][0]
        assert s.compliance_status == "non_compliant"
        assert any("safety" in issue.lower() for issue in s.compliance_issues)

    def test_ssh_to_l2_is_compliant(self):
        dev = OTDevice(ip="10.1.2.20")
        dev.device_criticality = "monitoring"
        dev.it_protocols = [ITProtocolHit(
            protocol="SSH", port=22, transport="TCP",
            src_ip="10.1.3.50", dst_ip="10.1.2.20",
            details={"category": "remote_access", "risk": "medium"},
        )]
        dev.protocol_stats = []; dev.remote_access_sessions = []
        zone = NetworkZone(zone_id="z2", subnet="10.1.2.0/24", purdue_level=2,
                           purdue_label="Supervisory", device_ips={"10.1.2.20"}, device_count=1)

        engine = SecureAccessEngine([dev], [], [zone], [])
        sessions = engine.audit()
        assert "10.1.2.20" in sessions
        s = sessions["10.1.2.20"][0]
        assert s.is_encrypted is True
        assert s.compliance_status == "compliant"

    def test_vpn_to_l1_is_non_compliant(self):
        dev = OTDevice(ip="10.1.1.30")
        dev.device_criticality = "process_control"
        dev.it_protocols = [ITProtocolHit(
            protocol="IKE/IPsec", port=500, transport="UDP",
            src_ip="192.168.1.200", dst_ip="10.1.1.30",
            details={"category": "vpn", "risk": "medium"},
        )]
        dev.protocol_stats = []; dev.remote_access_sessions = []
        zone = NetworkZone(zone_id="z1", subnet="10.1.1.0/24", purdue_level=1,
                           purdue_label="Control", device_ips={"10.1.1.30"}, device_count=1)

        engine = SecureAccessEngine([dev], [], [zone], [])
        sessions = engine.audit()
        assert "10.1.1.30" in sessions
        s = sessions["10.1.1.30"][0]
        assert s.is_vpn is True
        assert s.compliance_status == "non_compliant"


class TestJumpServerDetection:
    def test_identifies_jump_server(self):
        js = OTDevice(ip="10.1.3.50")
        js.role = "unknown"; js.communicating_with = {"10.1.2.20"}
        js.open_ports = {22}
        js.it_protocols = [ITProtocolHit(
            protocol="SSH", port=22, transport="TCP",
            src_ip="192.168.1.100", dst_ip="10.1.3.50",
            details={"category": "remote_access", "risk": "medium"},
        )]
        js.protocol_stats = []; js.remote_access_sessions = []

        peer = OTDevice(ip="10.1.2.20")
        peer.open_ports = {102}; peer.it_protocols = []
        peer.protocol_stats = []; peer.remote_access_sessions = []

        zone3 = NetworkZone(zone_id="z3", subnet="10.1.3.0/24", purdue_level=3,
                            purdue_label="Operations", device_ips={"10.1.3.50"}, device_count=1)

        flows = [CommFlow(src_ip="10.1.3.50", dst_ip="10.1.2.20",
                          protocol="S7comm", port=102, transport="TCP",
                          packet_count=100, byte_count=9000)]

        engine = SecureAccessEngine([js, peer], flows, [zone3], [])
        engine.audit()
        assert js.role == "jump_server"
