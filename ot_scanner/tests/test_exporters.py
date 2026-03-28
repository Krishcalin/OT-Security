"""Tests for integration exporters — ServiceNow, Splunk, Elastic, Webhook."""

import json
import tempfile
import os
from scanner.models import OTDevice, VulnerabilityFinding, CVEMatch, ThreatAlert, NetworkZone, ZoneViolation
from scanner.export.servicenow import ServiceNowExporter
from scanner.export.splunk import SplunkHECExporter
from scanner.export.elastic import ElasticECSExporter
from scanner.export.webhook import WebhookExporter


def _make_device():
    dev = OTDevice(ip="10.1.1.10")
    dev.vendor = "Siemens"; dev.model = "S7-1500"; dev.role = "plc"
    dev.risk_level = "high"; dev.composite_risk_score = 55.0
    dev.vulnerabilities = [VulnerabilityFinding(
        vuln_id="RTU-DNP3-001", title="No DNP3 SA", severity="high",
        category="authentication", description="", evidence={},
        remediation="", references=[], mitre_attack=["T0855"],
    )]
    dev.cve_matches = [CVEMatch(
        cve_id="CVE-2019-13945", device_ip="10.1.1.10", priority="now",
        severity="critical", cvss_score=9.8, is_cisa_kev=True, epss_score=0.91,
    )]
    dev.threat_alerts = [ThreatAlert(
        alert_id="TA-001", alert_type="malware_signature", severity="critical",
        title="TRITON", device_ip="10.1.1.10", mitre_technique="T0839",
    )]
    dev.protocol_stats = []; dev.it_protocols = []
    return dev


class TestServiceNowExporter:
    def test_produces_valid_json(self):
        dev = _make_device()
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "sn.json")
        ServiceNowExporter([dev]).to_cmdb_json(path)
        with open(path) as f:
            data = json.load(f)
        assert data["total_configuration_items"] == 1
        ci = data["configuration_items"][0]
        assert ci["manufacturer"] == "Siemens"
        assert ci["u_risk_level"] == "high"


class TestSplunkHECExporter:
    def test_produces_valid_ndjson(self):
        dev = _make_device()
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "splunk.ndjson")
        SplunkHECExporter([dev]).to_hec_json(path)
        with open(path) as f:
            lines = f.readlines()
        assert len(lines) >= 4  # inventory + vuln + cve + threat
        for line in lines:
            event = json.loads(line)
            assert "source" in event
            assert "sourcetype" in event


class TestElasticECSExporter:
    def test_produces_ecs_compliant_ndjson(self):
        dev = _make_device()
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "elastic.ndjson")
        ElasticECSExporter([dev]).to_ecs_ndjson(path)
        with open(path) as f:
            lines = f.readlines()
        assert len(lines) >= 4
        for line in lines:
            event = json.loads(line)
            assert "@timestamp" in event
            assert "event" in event


class TestWebhookExporter:
    def test_produces_summary_payload(self):
        dev = _make_device()
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "webhook.json")
        WebhookExporter([dev], pcap_file="test.pcap").to_payload_json(path)
        with open(path) as f:
            data = json.load(f)
        assert data["summary"]["devices_discovered"] == 1
        assert data["summary"]["now_priority_cves"] == 1
        assert data["summary"]["malware_signature_matches"] == 1
        assert len(data["critical_findings"]) >= 1
