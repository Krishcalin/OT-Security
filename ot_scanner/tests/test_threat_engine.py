"""Tests for ThreatDetectionEngine — all 9 malware signatures."""

from datetime import datetime
from scanner.models import (
    OTDevice, ProtocolDetection, ProtocolStats, ITProtocolHit,
    IEC104SessionState,
)
from scanner.threat.engine import ThreatDetectionEngine
from scanner.threat.signatures import ICS_MALWARE_SIGNATURES


class TestSignatureCount:
    def test_ten_signatures_loaded(self):
        assert len(ICS_MALWARE_SIGNATURES) == 10

    def test_all_match_functions_exist(self):
        for sig in ICS_MALWARE_SIGNATURES:
            fn_name = f"_{sig['match_fn']}"
            assert hasattr(ThreatDetectionEngine, fn_name), f"Missing: {fn_name}"


class TestTritonSignature:
    def test_triton_on_sis_with_program_download_and_firmware(self):
        dev = OTDevice(ip="10.1.0.10")
        dev.device_criticality = "safety_system"
        dev.protocol_stats = [ProtocolStats(
            protocol="S7comm", total_packets=100, function_codes={},
            read_count=10, write_count=5, control_count=0, diagnostic_count=0,
            has_program_upload=False, has_program_download=True,
            has_firmware_update=True, has_config_change=False,
            unique_addresses=set(), unique_data_points=0,
        )]
        dev.it_protocols = []; dev.vulnerabilities = []; dev.cve_matches = []; dev.threat_alerts = []
        engine = ThreatDetectionEngine([dev], [], [], [], {}, {}, {})
        alerts = engine.analyze()
        malware = [a for al in alerts.values() for a in al if "TRITON" in a.title]
        assert malware, "TRITON should be detected on SIS with program_download + firmware_update"


class TestIndustroyerSignature:
    def test_industroyer_iec104_pattern(self):
        dev = OTDevice(ip="10.1.1.20")
        dev.role = "rtu"; dev.protocol_stats = []; dev.it_protocols = []
        dev.vulnerabilities = []; dev.cve_matches = []; dev.threat_alerts = []
        session = IEC104SessionState(
            master_ip="10.1.2.30", rtu_ip="10.1.1.20",
            single_commands=[{"type": 45}], general_interrogations=2,
            clock_syncs=3, packet_count=200,
            first_seen=datetime(2024, 1, 1), last_seen=datetime(2024, 1, 2),
        )
        engine = ThreatDetectionEngine([dev], [], [], [], {},
                                       {("10.1.2.30", "10.1.1.20"): session}, {})
        alerts = engine.analyze()
        malware = [a for al in alerts.values() for a in al if "Industroyer" in a.title]
        assert malware, "Industroyer should be detected with control + GI + clock sync"


class TestCosmicEnergySignature:
    def test_cosmicenergy_iec104_control_with_mssql_master(self):
        rtu = OTDevice(ip="10.1.1.20")
        rtu.role = "rtu"; rtu.protocol_stats = []; rtu.it_protocols = []
        rtu.vulnerabilities = []; rtu.cve_matches = []; rtu.threat_alerts = []
        master = OTDevice(ip="10.1.2.30")
        master.protocol_stats = []; master.vulnerabilities = []
        master.cve_matches = []; master.threat_alerts = []
        master.it_protocols = [ITProtocolHit(protocol="MSSQL", port=1433,
                                             details={"category": "database"})]
        # control commands but NO general interrogation / clock sync -> not Industroyer
        session = IEC104SessionState(
            master_ip="10.1.2.30", rtu_ip="10.1.1.20",
            single_commands=[{"type": 45}], general_interrogations=0,
            clock_syncs=0, packet_count=120,
            first_seen=datetime(2024, 1, 1), last_seen=datetime(2024, 1, 2),
        )
        engine = ThreatDetectionEngine([rtu, master], [], [], [], {},
                                       {("10.1.2.30", "10.1.1.20"): session}, {})
        alerts = engine.analyze()
        titles = [a.title for al in alerts.values() for a in al]
        assert any("CosmicEnergy" in t for t in titles), \
            "CosmicEnergy should fire on IEC-104 control from an MSSQL-running master"
        assert not any("Industroyer" in t for t in titles), \
            "Industroyer must NOT fire without GI + clock sync (distinguishes the two)"


class TestFuxnetSignature:
    def test_fuxnet_modbus_flood(self):
        dev = OTDevice(ip="10.1.0.50")
        dev.protocol_stats = [ProtocolStats(
            protocol="Modbus/TCP", total_packets=2000, function_codes={},
            read_count=100, write_count=800, control_count=0, diagnostic_count=20,
            has_program_upload=False, has_program_download=False,
            has_firmware_update=False, has_config_change=False,
            unique_addresses=set(), unique_data_points=25,
        )]
        dev.it_protocols = []; dev.vulnerabilities = []; dev.cve_matches = []; dev.threat_alerts = []
        engine = ThreatDetectionEngine([dev], [], [], [], {}, {}, {})
        alerts = engine.analyze()
        malware = [a for al in alerts.values() for a in al if "Fuxnet" in a.title]
        assert malware, "Fuxnet should be detected with heavy writes + diagnostics"


class TestIOControlSignature:
    def test_iocontrol_mqtt_c2(self):
        dev = OTDevice(ip="10.1.1.80")
        dev.protocols = [ProtocolDetection(protocol="MQTT", port=1883, confidence="high")]
        dev.protocol_stats = [ProtocolStats(
            protocol="MQTT", total_packets=500, function_codes={},
            read_count=100, write_count=200, control_count=0, diagnostic_count=0,
            has_program_upload=False, has_program_download=False,
            has_firmware_update=False, has_config_change=True,
            unique_addresses=set(), unique_data_points=5,
        )]
        dev.it_protocols = [ITProtocolHit(protocol="HTTP", port=80,
                                          details={"category": "web", "risk": "medium"})]
        dev.communicating_with = {f"10.1.{i}.{j}" for i in range(6) for j in range(1, 2)}
        dev.vulnerabilities = []; dev.cve_matches = []; dev.threat_alerts = []
        engine = ThreatDetectionEngine([dev], [], [], [], {}, {}, {})
        alerts = engine.analyze()
        malware = [a for al in alerts.values() for a in al if "IOControl" in a.title]
        assert malware, "IOControl should be detected with MQTT + IT + config change"


class TestUnauthorizedCommands:
    def test_firmware_update_alert(self):
        dev = OTDevice(ip="10.1.1.10")
        dev.protocol_stats = [ProtocolStats(
            protocol="S7comm", total_packets=100, function_codes={},
            read_count=50, write_count=10, control_count=0, diagnostic_count=0,
            has_program_upload=False, has_program_download=False,
            has_firmware_update=True, has_config_change=False,
            unique_addresses=set(), unique_data_points=0,
        )]
        dev.it_protocols = []; dev.vulnerabilities = []; dev.cve_matches = []; dev.threat_alerts = []
        engine = ThreatDetectionEngine([dev], [], [], [], {}, {}, {})
        alerts = engine.analyze()
        fw_alerts = [a for al in alerts.values() for a in al if "Firmware" in a.title]
        assert fw_alerts, "Firmware update should trigger alert"
        assert fw_alerts[0].severity == "critical"
