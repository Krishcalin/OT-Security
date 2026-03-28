"""
ServiceNow CMDB Export for the OT Passive Scanner.

Generates a JSON file compatible with ServiceNow's CMDB Import Set API.
Each discovered OT device becomes a Configuration Item (CI) with
relationships to master stations and peer devices.

Usage:
    exporter = ServiceNowExporter(devices, zones=zones)
    exporter.to_cmdb_json("servicenow_cmdb.json")

Zero external dependencies — uses only Python stdlib.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from ..models import OTDevice, CommFlow, NetworkZone, ZoneViolation

VERSION = "2.0.0"

# OT device role → ServiceNow CMDB CI class
_ROLE_TO_CLASS = {
    "plc":                 "cmdb_ci_ip_switch",
    "rtu":                 "cmdb_ci_ip_switch",
    "frtu":                "cmdb_ci_ip_switch",
    "ied":                 "cmdb_ci_ip_switch",
    "relay":               "cmdb_ci_ip_switch",
    "hmi":                 "cmdb_ci_computer",
    "engineering_station": "cmdb_ci_computer",
    "master_station":      "cmdb_ci_computer",
    "historian":           "cmdb_ci_server",
    "gateway":             "cmdb_ci_ip_router",
    "building_controller": "cmdb_ci_ip_switch",
    "iot_device":          "cmdb_ci_ip_switch",
    "unknown":             "cmdb_ci_hardware",
}


class ServiceNowExporter:
    """Export OT device inventory as ServiceNow CMDB Import Set JSON."""

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

        self._ip_to_zone: Dict[str, NetworkZone] = {}
        for z in self.zones:
            for ip in z.device_ips:
                self._ip_to_zone[ip] = z

    def to_cmdb_json(self, path: str) -> None:
        """Write ServiceNow CMDB Import Set JSON."""
        cis: List[Dict] = []
        relationships: List[Dict] = []

        for dev in self.devices:
            cis.append(self._device_to_ci(dev))

            # Relationships: master → device (Controls)
            for master_ip in dev.master_stations:
                relationships.append({
                    "parent": master_ip,
                    "child": dev.ip,
                    "type": "Controls::Controlled by",
                })

            # Relationships: device → peers (Communicates with)
            for peer_ip in dev.communicating_with:
                if peer_ip not in dev.master_stations:
                    relationships.append({
                        "parent": dev.ip,
                        "child": peer_ip,
                        "type": "Communicates with::Communicates with",
                    })

        report = {
            "source": f"OT Passive Scanner v{VERSION}",
            "generated": datetime.now().isoformat(),
            "total_configuration_items": len(cis),
            "total_relationships": len(relationships),
            "configuration_items": cis,
            "relationships": relationships,
        }

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)

    def _device_to_ci(self, dev: OTDevice) -> Dict:
        """Convert OTDevice to ServiceNow CI record."""
        zone = self._ip_to_zone.get(dev.ip)
        purdue = zone.purdue_level if zone else -1
        vendor = dev.vendor or dev.make or "Unknown"
        model = dev.model or "Unknown"
        name = f"{vendor} {model} ({dev.ip})"

        return {
            # Standard ServiceNow CMDB fields
            "name": name,
            "sys_class_name": _ROLE_TO_CLASS.get(dev.role, "cmdb_ci_hardware"),
            "ip_address": dev.ip,
            "mac_address": dev.mac or "",
            "manufacturer": vendor,
            "model_id": model,
            "firmware_version": dev.firmware or "",
            "serial_number": dev.serial_number or "",
            "asset_tag": dev.asset_tag or "",
            "assigned_to": dev.asset_owner or "",
            "location": dev.location or "",
            "operational_status": "operational",
            "discovery_source": "OT Passive Scanner",
            # Custom OT fields (u_ prefix for ServiceNow custom fields)
            "u_device_role": dev.role,
            "u_device_type": dev.device_type,
            "u_device_criticality": dev.device_criticality,
            "u_purdue_level": purdue,
            "u_purdue_label": zone.purdue_label if zone else "Unknown",
            "u_risk_level": dev.risk_level,
            "u_composite_risk_score": dev.composite_risk_score,
            "u_protocols": " | ".join(dev.get_protocol_names()),
            "u_open_ports": ", ".join(str(p) for p in sorted(dev.open_ports)),
            "u_vuln_count": len(dev.vulnerabilities),
            "u_cve_count": len(dev.cve_matches),
            "u_cve_now_count": sum(
                1 for c in dev.cve_matches if c.priority == "now"
            ),
            "u_threat_alert_count": len(dev.threat_alerts),
            "u_peer_count": len(dev.communicating_with),
            "u_master_stations": ", ".join(sorted(dev.master_stations)),
            "u_vendor_confidence": dev.vendor_confidence,
            "u_hardware_version": dev.hardware_version or "",
            "u_product_code": dev.product_code or "",
            "u_first_seen": dev.first_seen.isoformat() if dev.first_seen else "",
            "u_last_seen": dev.last_seen.isoformat() if dev.last_seen else "",
            "u_packet_count": dev.packet_count,
        }
