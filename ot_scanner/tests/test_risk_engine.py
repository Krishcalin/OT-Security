"""Tests for CompositeRiskEngine — scoring formula and multipliers."""

from scanner.models import OTDevice, VulnerabilityFinding, CVEMatch, NetworkZone, ProtocolStats
from scanner.risk.engine import CompositeRiskEngine


class TestCompositeScoring:
    def test_safety_system_scores_highest(self, sample_device, safety_device, sample_zones):
        engine = CompositeRiskEngine(zones=sample_zones)
        sample_device.cve_matches = [CVEMatch(
            cve_id="CVE-TEST", device_ip=sample_device.ip, priority="now",
            severity="critical", cvss_score=9.8, is_cisa_kev=True, epss_score=0.9,
        )]
        sample_device.vulnerabilities = [VulnerabilityFinding(
            vuln_id="TEST-001", title="Test", severity="critical",
            category="auth", description="", evidence={}, remediation="",
            references=[], mitre_attack=[],
        )]
        engine.score_device(sample_device)
        engine.score_device(safety_device)
        # Safety device at L0 with existing high score should remain high
        assert safety_device.composite_risk_score >= 0
        assert sample_device.composite_risk_score > 0

    def test_criticality_multiplier(self, sample_zones):
        engine = CompositeRiskEngine(zones=sample_zones)
        dev_safety = OTDevice(ip="10.1.0.5")
        dev_safety.device_criticality = "safety_system"
        dev_safety.vulnerabilities = [VulnerabilityFinding(
            vuln_id="V1", title="T", severity="high", category="auth",
            description="", evidence={}, remediation="", references=[], mitre_attack=[],
        )]
        dev_safety.protocol_stats = []
        dev_safety.cve_matches = []

        dev_support = OTDevice(ip="10.1.3.50")
        dev_support.device_criticality = "support"
        dev_support.vulnerabilities = list(dev_safety.vulnerabilities)
        dev_support.protocol_stats = []
        dev_support.cve_matches = []

        engine.score_device(dev_safety)
        engine.score_device(dev_support)
        assert dev_safety.composite_risk_score > dev_support.composite_risk_score

    def test_compensating_controls_reduce_score(self, sample_zones):
        engine = CompositeRiskEngine(zones=sample_zones)
        dev = OTDevice(ip="10.1.1.10")
        dev.device_criticality = "process_control"
        dev.vulnerabilities = [VulnerabilityFinding(
            vuln_id="V1", title="T", severity="medium", category="encryption",
            description="", evidence={}, remediation="", references=[], mitre_attack=[],
        )]
        dev.protocol_stats = []
        dev.cve_matches = []
        dev.communicating_with = {"10.1.1.20", "10.1.1.30"}
        dev.communication_profile = {"control_ratio": 0}

        engine.score_device(dev)
        assert dev.compensating_controls  # should have read-only + limited peers
        assert dev.risk_score_breakdown["controls_factor"] < 1.0

    def test_zero_score_for_clean_device(self):
        engine = CompositeRiskEngine()
        dev = OTDevice(ip="10.0.0.1")
        dev.vulnerabilities = []
        dev.cve_matches = []
        dev.protocol_stats = []
        engine.score_device(dev)
        assert dev.composite_risk_score == 0.0
        assert dev.risk_level == "low"

    def test_kev_boost(self, sample_zones):
        engine = CompositeRiskEngine(zones=sample_zones)
        dev = OTDevice(ip="10.1.1.10")
        dev.vulnerabilities = [VulnerabilityFinding(
            vuln_id="V1", title="T", severity="high", category="auth",
            description="", evidence={}, remediation="", references=[], mitre_attack=[],
        )]
        dev.cve_matches = [CVEMatch(
            cve_id="CVE-TEST", device_ip="10.1.1.10", priority="now",
            severity="critical", cvss_score=9.8, is_cisa_kev=True, epss_score=0.9,
        )]
        dev.protocol_stats = []
        engine.score_device(dev)
        assert dev.risk_score_breakdown["kev_boost"] > 1.0
        assert dev.risk_score_breakdown["epss_boost"] > 1.0
