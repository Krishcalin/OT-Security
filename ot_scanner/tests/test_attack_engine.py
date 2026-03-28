"""Tests for AttackPathEngine — pathfinding, scoring, kill chain."""

from scanner.models import OTDevice, ProtocolDetection, ProtocolStats, NetworkZone, TopologyEdge, CVEMatch, RemoteAccessSession, ITProtocolHit
from scanner.attack.engine import AttackPathEngine


class TestCrownJewelIdentification:
    def test_safety_system_is_crown_jewel(self, safety_device, sample_zones, sample_edges):
        engine = AttackPathEngine([safety_device], [], sample_zones, sample_edges)
        jewels = engine._identify_crown_jewels()
        assert safety_device.ip in jewels

    def test_high_risk_device_is_crown_jewel(self, sample_device, sample_zones, sample_edges):
        sample_device.composite_risk_score = 75.0
        engine = AttackPathEngine([sample_device], [], sample_zones, sample_edges)
        jewels = engine._identify_crown_jewels()
        assert sample_device.ip in jewels


class TestEntryPointIdentification:
    def test_remote_access_is_entry(self, sample_zones, sample_edges):
        dev = OTDevice(ip="10.1.3.50")
        dev.remote_access_sessions = [RemoteAccessSession(session_type="ssh")]
        dev.it_protocols = []; dev.protocol_stats = []
        engine = AttackPathEngine([dev], [], sample_zones, sample_edges)
        entries = engine._identify_entry_points()
        assert dev.ip in entries

    def test_jump_server_is_entry(self, sample_zones, sample_edges):
        dev = OTDevice(ip="10.1.3.50")
        dev.role = "jump_server"
        dev.it_protocols = []; dev.remote_access_sessions = []; dev.protocol_stats = []
        engine = AttackPathEngine([dev], [], sample_zones, sample_edges)
        entries = engine._identify_entry_points()
        assert dev.ip in entries


class TestPathfinding:
    def test_finds_path_to_crown_jewel(self):
        entry = OTDevice(ip="10.1.3.50")
        entry.role = "jump_server"
        entry.communicating_with = {"10.1.2.20"}
        entry.it_protocols = []; entry.remote_access_sessions = []; entry.protocol_stats = []

        mid = OTDevice(ip="10.1.2.20")
        mid.role = "hmi"; mid.communicating_with = {"10.1.3.50", "10.1.1.10"}
        mid.it_protocols = []; mid.remote_access_sessions = []; mid.protocol_stats = []

        target = OTDevice(ip="10.1.1.10")
        target.role = "plc"; target.device_criticality = "process_control"
        target.communicating_with = {"10.1.2.20"}; target.composite_risk_score = 0
        target.it_protocols = []; target.remote_access_sessions = []; target.protocol_stats = []
        target.cve_matches = []; target.vulnerabilities = []

        zones = [
            NetworkZone(zone_id="z1", subnet="10.1.1.0/24", purdue_level=1,
                        purdue_label="Control", device_ips={"10.1.1.10"}, device_count=1),
            NetworkZone(zone_id="z2", subnet="10.1.2.0/24", purdue_level=2,
                        purdue_label="Supervisory", device_ips={"10.1.2.20"}, device_count=1),
            NetworkZone(zone_id="z3", subnet="10.1.3.0/24", purdue_level=3,
                        purdue_label="Operations", device_ips={"10.1.3.50"}, device_count=1),
        ]

        edges = [
            TopologyEdge(src_ip="10.1.3.50", dst_ip="10.1.2.20",
                         protocols={"S7comm"}, is_control=True, is_cross_zone=True, purdue_span=1),
            TopologyEdge(src_ip="10.1.2.20", dst_ip="10.1.1.10",
                         protocols={"Modbus/TCP"}, is_control=True, is_cross_zone=True, purdue_span=1),
        ]

        engine = AttackPathEngine([entry, mid, target], [], zones, edges)
        paths = engine.analyze()
        assert len(paths) >= 1
        target_paths = [p for p in paths if p.target_ip == "10.1.1.10"]
        assert target_paths
        assert target_paths[0].hop_count >= 2
        assert target_paths[0].mitre_kill_chain  # kill chain populated


class TestPathScoring:
    def test_auth_gaps_increase_score(self):
        entry = OTDevice(ip="10.1.3.50")
        entry.role = "jump_server"; entry.communicating_with = {"10.1.1.10"}
        entry.it_protocols = []; entry.remote_access_sessions = []; entry.protocol_stats = []

        target = OTDevice(ip="10.1.1.10")
        target.role = "plc"; target.device_criticality = "process_control"
        target.communicating_with = {"10.1.3.50"}; target.composite_risk_score = 50.0
        target.it_protocols = []; target.remote_access_sessions = []; target.protocol_stats = []
        target.cve_matches = []; target.vulnerabilities = []

        zones = [
            NetworkZone(zone_id="z1", subnet="10.1.1.0/24", purdue_level=1,
                        purdue_label="Control", device_ips={"10.1.1.10"}, device_count=1),
            NetworkZone(zone_id="z3", subnet="10.1.3.0/24", purdue_level=3,
                        purdue_label="Operations", device_ips={"10.1.3.50"}, device_count=1),
        ]
        # Modbus is unauthenticated + unencrypted
        edges = [TopologyEdge(src_ip="10.1.3.50", dst_ip="10.1.1.10",
                              protocols={"Modbus/TCP"}, is_control=True,
                              is_cross_zone=True, purdue_span=2)]

        engine = AttackPathEngine([entry, target], [], zones, edges)
        paths = engine.analyze()
        assert paths
        assert paths[0].auth_gaps >= 1
        assert paths[0].encryption_gaps >= 1
