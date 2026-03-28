"""Tests for scanner data models — verify to_dict() and field defaults."""

from scanner.models import (
    OTDevice, CommFlow, NetworkZone, ZoneViolation, TopologyEdge,
    ProtocolDetection, ProtocolStats, VulnerabilityFinding, CVEMatch,
    ITProtocolHit, ThreatAlert, RemoteAccessSession, PolicyRule,
    PolicyRuleSet, DeviceConfig, ConfigDriftAlert, AttackPath,
)


class TestOTDevice:
    def test_defaults(self):
        dev = OTDevice(ip="10.0.0.1")
        assert dev.ip == "10.0.0.1"
        assert dev.risk_level == "unknown"
        assert dev.composite_risk_score == 0.0
        assert dev.threat_alerts == []
        assert dev.remote_access_sessions == []
        assert dev.config_drift_alerts == []
        assert dev.attack_paths == []

    def test_to_dict_keys(self, sample_device):
        d = sample_device.to_dict()
        assert d["ip"] == "10.1.1.10"
        assert d["vendor"] == "Siemens"
        assert "composite_risk_score" in d
        assert "threat_alerts" in d
        assert "remote_access_sessions" in d
        assert "config_drift_alerts" in d
        assert "attack_paths" in d
        assert "compensating_controls" in d


class TestCVEMatch:
    def test_epss_kev_fields(self, sample_cve_match):
        d = sample_cve_match.to_dict()
        assert d["epss_score"] == 0.91
        assert d["is_cisa_kev"] is True
        assert d["exploit_maturity"] == "functional"

    def test_defaults(self):
        m = CVEMatch(cve_id="CVE-2024-0001", device_ip="10.0.0.1",
                     priority="next", severity="high")
        assert m.epss_score == 0.0
        assert m.is_cisa_kev is False
        assert m.exploit_maturity == "unknown"


class TestPolicyRule:
    def test_to_dict(self):
        r = PolicyRule(rule_id="PR-001", action="allow", src_ip="10.0.0.1",
                       dst_ip="10.0.0.2", port=502, protocol="Modbus/TCP")
        d = r.to_dict()
        assert d["rule_id"] == "PR-001"
        assert d["action"] == "allow"
        assert d["port"] == 502


class TestThreatAlert:
    def test_to_dict(self):
        a = ThreatAlert(alert_id="TA-001", alert_type="malware_signature",
                        severity="critical", title="Test", device_ip="10.0.0.1",
                        mitre_technique="T0855")
        d = a.to_dict()
        assert d["alert_type"] == "malware_signature"
        assert d["mitre_technique"] == "T0855"


class TestRemoteAccessSession:
    def test_compliance_fields(self):
        s = RemoteAccessSession(session_type="rdp", protocol="RDP",
                                compliance_status="non_compliant",
                                compliance_issues=["Unencrypted"])
        d = s.to_dict()
        assert d["compliance_status"] == "non_compliant"
        assert len(d["compliance_issues"]) == 1


class TestDeviceConfig:
    def test_to_dict(self):
        c = DeviceConfig(device_ip="10.0.0.1", firmware="V4.5",
                         protocol_list=["S7comm", "Modbus/TCP"])
        d = c.to_dict()
        assert d["firmware"] == "V4.5"
        assert len(d["protocol_list"]) == 2


class TestAttackPath:
    def test_to_dict(self):
        p = AttackPath(path_id="AP-001", severity="critical",
                       entry_ip="10.1.4.100", target_ip="10.1.0.5",
                       hop_count=3, path_score=85.0)
        d = p.to_dict()
        assert d["path_score"] == 85.0
        assert d["hop_count"] == 3
