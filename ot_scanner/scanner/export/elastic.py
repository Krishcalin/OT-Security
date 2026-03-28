"""
Elastic Common Schema (ECS) Export for the OT Passive Scanner.

Generates NDJSON conforming to ECS 8.x for direct Elasticsearch bulk
ingest or Filebeat pickup. Events are structured for Kibana dashboards
and Elastic Security detection rules.

Event datasets:
  ot_scanner.vulnerability  — Vulnerability findings
  ot_scanner.cve            — CVE matches
  ot_scanner.threat_alert   — Threat detection alerts
  ot_scanner.zone_violation — Network segmentation violations
  ot_scanner.device         — Device inventory

Usage:
    exporter = ElasticECSExporter(devices, zones=zones, violations=violations)
    exporter.to_ecs_ndjson("elastic_events.ndjson")

Zero external dependencies — uses only Python stdlib.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from ..models import OTDevice, CommFlow, NetworkZone, ZoneViolation

VERSION = "2.0.0"

# ECS severity mapping (1-10 scale)
_ECS_SEVERITY = {
    "critical": 9,
    "high": 7,
    "medium": 5,
    "low": 3,
    "info": 1,
}


class ElasticECSExporter:
    """Export scan results as Elastic Common Schema NDJSON events."""

    def __init__(
        self,
        devices: List[OTDevice],
        flows: Optional[List[CommFlow]] = None,
        zones: Optional[List[NetworkZone]] = None,
        violations: Optional[List[ZoneViolation]] = None,
    ) -> None:
        self.devices = devices
        self.flows = flows or []
        self.zones = zones or []
        self.violations = violations or []

    def to_ecs_ndjson(self, path: str) -> None:
        """Write ECS-compliant NDJSON events."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        now = datetime.now().isoformat() + "Z"

        with open(path, "w", encoding="utf-8") as fh:
            # Device inventory
            for dev in self.devices:
                fh.write(json.dumps(self._device_event(dev, now), default=str))
                fh.write("\n")

            # Vulnerability events
            for dev in self.devices:
                for vuln in dev.vulnerabilities:
                    fh.write(json.dumps(self._vuln_event(dev, vuln, now), default=str))
                    fh.write("\n")

            # CVE events
            for dev in self.devices:
                for cve in dev.cve_matches:
                    if cve.priority in ("now", "next"):
                        fh.write(json.dumps(self._cve_event(dev, cve, now), default=str))
                        fh.write("\n")

            # Threat alerts
            for dev in self.devices:
                for alert in dev.threat_alerts:
                    fh.write(json.dumps(self._threat_event(dev, alert, now), default=str))
                    fh.write("\n")

            # Zone violations
            for viol in self.violations:
                fh.write(json.dumps(self._violation_event(viol, now), default=str))
                fh.write("\n")

    def _base_event(self, dev: OTDevice) -> Dict:
        """Common ECS fields for device-centric events."""
        return {
            "host": {
                "ip": [dev.ip],
                "mac": [dev.mac] if dev.mac else [],
                "name": f"{dev.vendor or ''} {dev.model or ''}".strip() or dev.ip,
                "type": dev.role,
            },
            "observer": {
                "name": "OT Passive Scanner",
                "type": "passive",
                "vendor": "OT Scanner",
                "version": VERSION,
            },
        }

    def _device_event(self, dev: OTDevice, ts: str) -> Dict:
        event = self._base_event(dev)
        event.update({
            "@timestamp": ts,
            "message": (
                f"OT device discovered: {dev.ip} "
                f"({dev.vendor or 'Unknown'} {dev.model or 'Unknown'})"
            ),
            "event": {
                "kind": "asset",
                "category": ["host"],
                "type": ["info"],
                "action": "device_discovered",
                "module": "ot-scanner",
                "dataset": "ot_scanner.device",
            },
            "ot": {
                "device_role": dev.role,
                "device_type": dev.device_type,
                "device_criticality": dev.device_criticality,
                "protocols": dev.get_protocol_names(),
                "risk_level": dev.risk_level,
                "composite_risk_score": dev.composite_risk_score,
                "firmware": dev.firmware or "",
                "vendor_confidence": dev.vendor_confidence,
            },
        })
        return event

    def _vuln_event(self, dev: OTDevice, vuln, ts: str) -> Dict:
        event = self._base_event(dev)
        event.update({
            "@timestamp": ts,
            "message": (
                f"Vulnerability {vuln.vuln_id} on {dev.ip}: {vuln.title}"
            ),
            "event": {
                "kind": "alert",
                "category": ["network"],
                "type": ["info"],
                "action": "vulnerability_detected",
                "severity": _ECS_SEVERITY.get(vuln.severity, 1),
                "module": "ot-scanner",
                "dataset": "ot_scanner.vulnerability",
            },
            "vulnerability": {
                "id": vuln.vuln_id,
                "severity": vuln.severity,
                "category": [vuln.category],
                "description": vuln.description[:1024],
            },
            "rule": {
                "name": vuln.title,
                "description": vuln.remediation[:512] if vuln.remediation else "",
                "reference": ", ".join(vuln.references[:3]),
            },
        })
        if vuln.mitre_attack:
            event["threat"] = {
                "technique": {
                    "id": vuln.mitre_attack,
                },
                "framework": "MITRE ATT&CK for ICS",
            }
        return event

    def _cve_event(self, dev: OTDevice, cve, ts: str) -> Dict:
        event = self._base_event(dev)
        event.update({
            "@timestamp": ts,
            "message": (
                f"CVE {cve.cve_id} matched on {dev.ip}: {cve.title} "
                f"(CVSS {cve.cvss_score}, priority: {cve.priority})"
            ),
            "event": {
                "kind": "alert",
                "category": ["vulnerability"],
                "type": ["indicator"],
                "action": "cve_matched",
                "severity": _ECS_SEVERITY.get(cve.severity, 1),
                "module": "ot-scanner",
                "dataset": "ot_scanner.cve",
            },
            "vulnerability": {
                "id": cve.cve_id,
                "severity": cve.severity,
                "description": cve.description[:1024],
                "score": {
                    "base": cve.cvss_score,
                    "version": "3.1",
                },
                "classification": "CVSS",
                "reference": (
                    f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"
                ),
                "scanner": {
                    "vendor": "OT Scanner",
                },
            },
            "ot": {
                "cve_priority": cve.priority,
                "epss_score": cve.epss_score,
                "is_cisa_kev": cve.is_cisa_kev,
                "exploit_maturity": cve.exploit_maturity,
                "has_public_exploit": cve.has_public_exploit,
                "match_confidence": cve.match_confidence,
                "ics_cert_advisory": cve.ics_cert_advisory,
            },
        })
        return event

    def _threat_event(self, dev: OTDevice, alert, ts: str) -> Dict:
        event = self._base_event(dev)
        event.update({
            "@timestamp": ts,
            "message": f"Threat alert on {dev.ip}: {alert.title}",
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["indicator"],
                "action": alert.alert_type,
                "severity": _ECS_SEVERITY.get(alert.severity, 1),
                "module": "ot-scanner",
                "dataset": "ot_scanner.threat_alert",
            },
            "rule": {
                "name": alert.title,
                "description": alert.description[:512],
            },
        })
        if alert.mitre_technique:
            event["threat"] = {
                "technique": {
                    "id": [alert.mitre_technique],
                    "name": [alert.mitre_tactic],
                },
                "framework": "MITRE ATT&CK for ICS",
            }
        if alert.peer_ip:
            event["destination"] = {"ip": alert.peer_ip}
        return event

    def _violation_event(self, viol, ts: str) -> Dict:
        return {
            "@timestamp": ts,
            "message": (
                f"Zone violation {viol.violation_id}: {viol.title}"
            ),
            "event": {
                "kind": "alert",
                "category": ["network"],
                "type": ["denied"],
                "action": "zone_violation",
                "severity": _ECS_SEVERITY.get(viol.severity, 1),
                "module": "ot-scanner",
                "dataset": "ot_scanner.zone_violation",
            },
            "source": {
                "ip": viol.src_ip,
            },
            "destination": {
                "ip": viol.dst_ip,
            },
            "network": {
                "protocol": viol.protocol,
            },
            "observer": {
                "name": "OT Passive Scanner",
                "type": "passive",
                "version": VERSION,
            },
            "ot": {
                "src_zone": viol.src_zone,
                "src_purdue": viol.src_purdue,
                "dst_zone": viol.dst_zone,
                "dst_purdue": viol.dst_purdue,
                "packet_count": viol.packet_count,
            },
        }
