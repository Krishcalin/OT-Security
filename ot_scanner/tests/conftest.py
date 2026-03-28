"""Shared pytest fixtures for OT Scanner tests."""

import pytest
from datetime import datetime

from scanner.models import (
    OTDevice, CommFlow, NetworkZone, ZoneViolation, TopologyEdge,
    ProtocolDetection, ProtocolStats, VulnerabilityFinding, CVEMatch,
    ITProtocolHit, ThreatAlert, RemoteAccessSession, PolicyRule,
    PolicyRuleSet, DeviceConfig, ConfigDriftAlert, AttackPath,
    DNP3SessionState, IEC104SessionState, GOOSEPublisherState,
)


@pytest.fixture
def sample_device():
    """A Siemens S7-1500 PLC at Purdue Level 1."""
    dev = OTDevice(ip="10.1.1.10")
    dev.vendor = "Siemens"
    dev.make = "Siemens"
    dev.model = "S7-1500"
    dev.firmware = "V4.5"
    dev.role = "plc"
    dev.device_type = "PLC"
    dev.device_criticality = "process_control"
    dev.risk_level = "high"
    dev.composite_risk_score = 55.0
    dev.mac = "aa:bb:cc:dd:ee:ff"
    dev.communicating_with = {"10.1.2.20"}
    dev.master_stations = {"10.1.2.20"}
    dev.open_ports = {102}
    dev.protocols = [
        ProtocolDetection(protocol="S7comm", port=102, confidence="high"),
    ]
    dev.protocol_stats = [ProtocolStats(
        protocol="S7comm", total_packets=1000,
        function_codes={"0x04 Read Var": 800, "0x05 Write Var": 200},
        read_count=800, write_count=200, control_count=50, diagnostic_count=0,
        has_program_upload=False, has_program_download=False,
        has_firmware_update=False, has_config_change=False,
        unique_addresses=set(), unique_data_points=30,
    )]
    dev.it_protocols = []
    return dev


@pytest.fixture
def sample_hmi():
    """An HMI device at Purdue Level 2."""
    dev = OTDevice(ip="10.1.2.20")
    dev.vendor = "Rockwell"
    dev.model = "PanelView"
    dev.role = "hmi"
    dev.device_criticality = "monitoring"
    dev.risk_level = "low"
    dev.composite_risk_score = 5.0
    dev.communicating_with = {"10.1.1.10"}
    dev.open_ports = {44818}
    dev.protocols = [
        ProtocolDetection(protocol="EtherNet/IP", port=44818, confidence="high"),
    ]
    dev.protocol_stats = []
    dev.it_protocols = []
    return dev


@pytest.fixture
def safety_device():
    """A safety instrumented system at Purdue Level 0."""
    dev = OTDevice(ip="10.1.0.5")
    dev.role = "plc"
    dev.device_criticality = "safety_system"
    dev.risk_level = "critical"
    dev.composite_risk_score = 80.0
    dev.communicating_with = {"10.1.1.10"}
    dev.master_stations = {"10.1.1.10"}
    dev.open_ports = {502}
    dev.protocols = [
        ProtocolDetection(protocol="Modbus/TCP", port=502, confidence="high"),
    ]
    dev.protocol_stats = [ProtocolStats(
        protocol="Modbus/TCP", total_packets=200,
        function_codes={"0x03 Read": 200},
        read_count=200, write_count=0, control_count=0, diagnostic_count=0,
        has_program_upload=False, has_program_download=False,
        has_firmware_update=False, has_config_change=False,
        unique_addresses=set(), unique_data_points=10,
    )]
    dev.it_protocols = []
    return dev


@pytest.fixture
def sample_zones():
    """Purdue zones L0 through L3."""
    return [
        NetworkZone(zone_id="z0", subnet="10.1.0.0/24", purdue_level=0,
                    purdue_label="Process", device_ips={"10.1.0.5"}, device_count=1),
        NetworkZone(zone_id="z1", subnet="10.1.1.0/24", purdue_level=1,
                    purdue_label="Control", device_ips={"10.1.1.10"}, device_count=1),
        NetworkZone(zone_id="z2", subnet="10.1.2.0/24", purdue_level=2,
                    purdue_label="Supervisory", device_ips={"10.1.2.20"}, device_count=1),
        NetworkZone(zone_id="z3", subnet="10.1.3.0/24", purdue_level=3,
                    purdue_label="Operations", device_ips={"10.1.3.50"}, device_count=1),
    ]


@pytest.fixture
def sample_flows():
    """Communication flows between PLC and HMI."""
    return [
        CommFlow(src_ip="10.1.2.20", dst_ip="10.1.1.10", protocol="S7comm",
                 port=102, transport="TCP", packet_count=500, byte_count=45000,
                 first_seen=datetime(2024, 1, 1), last_seen=datetime(2024, 1, 2)),
    ]


@pytest.fixture
def sample_edges():
    """Topology edges with control + cross-zone annotations."""
    return [
        TopologyEdge(src_ip="10.1.2.20", dst_ip="10.1.1.10",
                     protocols={"S7comm"}, packet_count=500, byte_count=45000,
                     is_control=True, is_cross_zone=True, purdue_span=1),
        TopologyEdge(src_ip="10.1.1.10", dst_ip="10.1.0.5",
                     protocols={"Modbus/TCP"}, packet_count=200, byte_count=18000,
                     is_control=True, is_cross_zone=True, purdue_span=1),
    ]


@pytest.fixture
def sample_cve_match():
    """A NOW-priority CISA KEV CVE match."""
    return CVEMatch(
        cve_id="CVE-2019-13945", device_ip="10.1.1.10", priority="now",
        severity="critical", cvss_score=9.8, title="S7 Replay Attack",
        has_public_exploit=True, epss_score=0.91, is_cisa_kev=True,
        exploit_maturity="functional",
    )
