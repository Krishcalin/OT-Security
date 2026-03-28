"""
Webhook Notification Payload Export for the OT Passive Scanner.

Generates a JSON payload suitable for POSTing to any webhook endpoint
(Slack, Microsoft Teams, PagerDuty, generic HTTP, SOAR platforms).

The file-based approach keeps zero external dependencies — the payload
can be POSTed with curl, PowerShell, or any HTTP client.

Usage:
    exporter = WebhookExporter(devices, violations=violations, pcap_file="capture.pcap")
    exporter.to_payload_json("webhook_payload.json")

    # Then POST with: curl -X POST -H "Content-Type: application/json" -d @webhook_payload.json <URL>

Zero external dependencies — uses only Python stdlib.
"""

import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from ..models import OTDevice, CommFlow, NetworkZone, ZoneViolation

VERSION = "2.0.0"

# Maximum entries in critical_findings list
_MAX_CRITICAL = 20
# Maximum entries in top_risk_devices list
_MAX_TOP_DEVICES = 10


class WebhookExporter:
    """Export scan summary as a webhook-ready JSON payload."""

    def __init__(
        self,
        devices: List[OTDevice],
        flows: Optional[List[CommFlow]] = None,
        zones: Optional[List[NetworkZone]] = None,
        violations: Optional[List[ZoneViolation]] = None,
        pcap_file: str = "",
    ) -> None:
        self.devices = devices
        self.flows = flows or []
        self.zones = zones or []
        self.violations = violations or []
        self.pcap_file = pcap_file

    def to_payload_json(self, path: str) -> None:
        """Write webhook notification payload JSON."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        payload = {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "scanner": f"OT Passive Scanner v{VERSION}",
            "pcap_file": os.path.basename(self.pcap_file),
            "summary": self._build_summary(),
            "critical_findings": self._build_critical_findings(),
            "top_risk_devices": self._build_top_devices(),
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

    def _build_summary(self) -> Dict:
        """Aggregate scan statistics."""
        all_vulns = [v for d in self.devices for v in d.vulnerabilities]
        all_cves = [c for d in self.devices for c in d.cve_matches]
        all_alerts = [a for d in self.devices for a in d.threat_alerts]

        return {
            "devices_discovered": len(self.devices),
            "critical_risk_devices": sum(
                1 for d in self.devices if d.risk_level == "critical"
            ),
            "high_risk_devices": sum(
                1 for d in self.devices if d.risk_level == "high"
            ),
            "total_vulnerabilities": len(all_vulns),
            "critical_vulnerabilities": sum(
                1 for v in all_vulns if v.severity == "critical"
            ),
            "total_cve_matches": len(all_cves),
            "now_priority_cves": sum(
                1 for c in all_cves if c.priority == "now"
            ),
            "cisa_kev_cves": sum(
                1 for c in all_cves if c.is_cisa_kev
            ),
            "zone_violations": len(self.violations),
            "threat_alerts": len(all_alerts),
            "malware_signature_matches": sum(
                1 for a in all_alerts if a.alert_type == "malware_signature"
            ),
            "zones_identified": len(self.zones),
            "communication_flows": len(self.flows),
        }

    def _build_critical_findings(self) -> List[Dict]:
        """Collect critical findings across all categories, limited to top N."""
        findings: List[Dict] = []

        # Critical vulnerabilities
        for dev in self.devices:
            for v in dev.vulnerabilities:
                if v.severity == "critical":
                    findings.append({
                        "type": "vulnerability",
                        "device_ip": dev.ip,
                        "title": v.title,
                        "severity": v.severity,
                        "finding_id": v.vuln_id,
                        "category": v.category,
                    })

        # NOW-priority CVEs (especially CISA KEV)
        for dev in self.devices:
            for c in dev.cve_matches:
                if c.priority == "now":
                    findings.append({
                        "type": "cve_match",
                        "device_ip": dev.ip,
                        "title": f"{c.cve_id}: {c.title}",
                        "severity": c.severity,
                        "cvss_score": c.cvss_score,
                        "is_cisa_kev": c.is_cisa_kev,
                        "epss_score": c.epss_score,
                    })

        # Critical threat alerts
        for dev in self.devices:
            for a in dev.threat_alerts:
                if a.severity == "critical":
                    findings.append({
                        "type": a.alert_type,
                        "device_ip": dev.ip,
                        "title": a.title,
                        "severity": a.severity,
                        "mitre_technique": a.mitre_technique,
                    })

        # Critical zone violations
        for v in self.violations:
            if v.severity == "critical":
                findings.append({
                    "type": "zone_violation",
                    "device_ip": v.src_ip,
                    "title": v.title,
                    "severity": v.severity,
                    "dst_ip": v.dst_ip,
                })

        return findings[:_MAX_CRITICAL]

    def _build_top_devices(self) -> List[Dict]:
        """Top N devices by composite risk score."""
        sorted_devs = sorted(
            self.devices,
            key=lambda d: -d.composite_risk_score,
        )

        top: List[Dict] = []
        for dev in sorted_devs[:_MAX_TOP_DEVICES]:
            if dev.composite_risk_score <= 0:
                break
            top.append({
                "ip": dev.ip,
                "vendor": dev.vendor or "Unknown",
                "model": dev.model or "Unknown",
                "role": dev.role,
                "risk_level": dev.risk_level,
                "composite_risk_score": dev.composite_risk_score,
                "vuln_count": len(dev.vulnerabilities),
                "cve_now_count": sum(
                    1 for c in dev.cve_matches if c.priority == "now"
                ),
                "threat_alert_count": len(dev.threat_alerts),
            })

        return top
