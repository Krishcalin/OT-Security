"""
Splunk HTTP Event Collector (HEC) Export for the OT Passive Scanner.

Generates NDJSON (one JSON object per line) compatible with Splunk's
HTTP Event Collector for direct SIEM ingestion.

Event sourcetypes:
  ot:device:inventory  — One per discovered device (asset context)
  ot:device:vuln       — One per vulnerability finding
  ot:device:cve        — One per CVE match (now/next priority only)
  ot:device:threat     — One per threat alert
  ot:network:violation  — One per zone violation

Usage:
    exporter = SplunkHECExporter(devices, zones=zones, violations=violations)
    exporter.to_hec_json("splunk_events.ndjson")

Zero external dependencies — uses only Python stdlib.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from ..models import OTDevice, CommFlow, NetworkZone, ZoneViolation

VERSION = "2.0.0"

# Severity → Splunk severity integer (1=info, 10=critical)
_SEVERITY_INT = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}


class SplunkHECExporter:
    """Export scan results as Splunk HEC-compatible NDJSON events."""

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

    def to_hec_json(self, path: str) -> None:
        """Write Splunk HEC NDJSON events (one JSON per line)."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        now_ts = int(datetime.now().timestamp())

        with open(path, "w", encoding="utf-8") as fh:
            # Device inventory events
            for dev in self.devices:
                fh.write(json.dumps(self._inventory_event(dev, now_ts), default=str))
                fh.write("\n")

            # Vulnerability events
            for dev in self.devices:
                for vuln in dev.vulnerabilities:
                    fh.write(json.dumps(self._vuln_event(dev, vuln, now_ts), default=str))
                    fh.write("\n")

            # CVE match events (now/next only)
            for dev in self.devices:
                for cve in dev.cve_matches:
                    if cve.priority in ("now", "next"):
                        fh.write(json.dumps(self._cve_event(dev, cve, now_ts), default=str))
                        fh.write("\n")

            # Threat alert events
            for dev in self.devices:
                for alert in dev.threat_alerts:
                    fh.write(json.dumps(self._threat_event(dev, alert, now_ts), default=str))
                    fh.write("\n")

            # Zone violation events
            for viol in self.violations:
                fh.write(json.dumps(self._violation_event(viol, now_ts), default=str))
                fh.write("\n")

    def _inventory_event(self, dev: OTDevice, ts: int) -> Dict:
        return {
            "time": ts,
            "source": "ot-scanner",
            "sourcetype": "ot:device:inventory",
            "host": dev.ip,
            "event": {
                "device_ip": dev.ip,
                "mac": dev.mac or "",
                "vendor": dev.vendor or "",
                "model": dev.model or "",
                "firmware": dev.firmware or "",
                "role": dev.role,
                "device_type": dev.device_type,
                "device_criticality": dev.device_criticality,
                "risk_level": dev.risk_level,
                "composite_risk_score": dev.composite_risk_score,
                "protocols": dev.get_protocol_names(),
                "peer_count": len(dev.communicating_with),
                "vuln_count": len(dev.vulnerabilities),
                "cve_count": len(dev.cve_matches),
                "threat_alert_count": len(dev.threat_alerts),
                "packet_count": dev.packet_count,
            },
        }

    def _vuln_event(self, dev: OTDevice, vuln, ts: int) -> Dict:
        return {
            "time": ts,
            "source": "ot-scanner",
            "sourcetype": "ot:device:vuln",
            "host": dev.ip,
            "event": {
                "device_ip": dev.ip,
                "vendor": dev.vendor or "",
                "model": dev.model or "",
                "risk_level": dev.risk_level,
                "finding_type": "vulnerability",
                "finding_id": vuln.vuln_id,
                "severity": vuln.severity,
                "severity_int": _SEVERITY_INT.get(vuln.severity, 1),
                "title": vuln.title,
                "description": vuln.description,
                "category": vuln.category,
                "mitre_attack": vuln.mitre_attack,
                "remediation": vuln.remediation,
            },
        }

    def _cve_event(self, dev: OTDevice, cve, ts: int) -> Dict:
        return {
            "time": ts,
            "source": "ot-scanner",
            "sourcetype": "ot:device:cve",
            "host": dev.ip,
            "event": {
                "device_ip": dev.ip,
                "vendor": dev.vendor or "",
                "model": dev.model or "",
                "finding_type": "cve_match",
                "cve_id": cve.cve_id,
                "priority": cve.priority,
                "severity": cve.severity,
                "severity_int": _SEVERITY_INT.get(cve.severity, 1),
                "cvss_score": cve.cvss_score,
                "epss_score": cve.epss_score,
                "is_cisa_kev": cve.is_cisa_kev,
                "exploit_maturity": cve.exploit_maturity,
                "has_public_exploit": cve.has_public_exploit,
                "title": cve.title,
                "match_confidence": cve.match_confidence,
                "ics_cert_advisory": cve.ics_cert_advisory,
                "remediation": cve.remediation,
            },
        }

    def _threat_event(self, dev: OTDevice, alert, ts: int) -> Dict:
        return {
            "time": ts,
            "source": "ot-scanner",
            "sourcetype": "ot:device:threat",
            "host": dev.ip,
            "event": {
                "device_ip": dev.ip,
                "vendor": dev.vendor or "",
                "model": dev.model or "",
                "finding_type": "threat_alert",
                "alert_id": alert.alert_id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "severity_int": _SEVERITY_INT.get(alert.severity, 1),
                "title": alert.title,
                "description": alert.description,
                "peer_ip": alert.peer_ip,
                "protocol": alert.protocol,
                "mitre_technique": alert.mitre_technique,
                "mitre_tactic": alert.mitre_tactic,
                "confidence": alert.confidence,
            },
        }

    def _violation_event(self, viol, ts: int) -> Dict:
        return {
            "time": ts,
            "source": "ot-scanner",
            "sourcetype": "ot:network:violation",
            "host": viol.src_ip,
            "event": {
                "finding_type": "zone_violation",
                "violation_id": viol.violation_id,
                "severity": viol.severity,
                "severity_int": _SEVERITY_INT.get(viol.severity, 1),
                "title": viol.title,
                "src_ip": viol.src_ip,
                "src_zone": viol.src_zone,
                "src_purdue": viol.src_purdue,
                "dst_ip": viol.dst_ip,
                "dst_zone": viol.dst_zone,
                "dst_purdue": viol.dst_purdue,
                "protocol": viol.protocol,
                "packet_count": viol.packet_count,
                "remediation": viol.remediation,
            },
        }
