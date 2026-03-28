"""
Firewall policy exporters for multiple vendor formats.

Supported export formats:
  - Palo Alto PAN-OS XML      (importable via Panorama / PAN-OS API)
  - Fortinet FortiGate CLI    (paste into FortiGate console or upload)
  - Cisco IOS Extended ACL     (one ACL per zone)
  - Generic JSON               (machine-readable for custom integrations)

Zero external dependencies -- uses only Python stdlib.
"""

import json
import os
import re
from datetime import datetime
from typing import Dict, List
from xml.etree.ElementTree import Element, SubElement, tostring

from ..models import PolicyRule, PolicyRuleSet


# ── Base exporter ────────────────────────────────────────────────────────

class BasePolicyExporter:
    """Abstract base for policy format exporters."""

    def __init__(self, ruleset: PolicyRuleSet) -> None:
        self.ruleset = ruleset

    def export(self, output_dir: str) -> List[str]:
        """Export rules and return list of written file paths."""
        raise NotImplementedError


# ── Palo Alto PAN-OS XML ─────────────────────────────────────────────────

class PaloAltoExporter(BasePolicyExporter):
    """Export rules as PAN-OS XML importable via Panorama or CLI."""

    def export(self, output_dir: str) -> List[str]:
        pa_dir = os.path.join(output_dir, "paloalto")
        os.makedirs(pa_dir, exist_ok=True)
        out_path = os.path.join(pa_dir, "ot_policy.xml")

        config = Element("config")
        devices = SubElement(config, "devices")
        entry_dev = SubElement(devices, "entry", name="localhost.localdomain")
        vsys = SubElement(entry_dev, "vsys")
        entry_vsys = SubElement(vsys, "entry", name="vsys1")

        # Address objects
        addr_grp = SubElement(entry_vsys, "address")
        addr_seen = set()
        for rule in self.ruleset.rules:
            for ip, subnet, tag in [
                (rule.src_ip, rule.src_subnet, "src"),
                (rule.dst_ip, rule.dst_subnet, "dst"),
            ]:
                addr_name = self._address_name(ip, subnet)
                if addr_name and addr_name not in addr_seen:
                    addr_seen.add(addr_name)
                    addr_entry = SubElement(addr_grp, "entry", name=addr_name)
                    if ip:
                        SubElement(addr_entry, "ip-netmask").text = f"{ip}/32"
                    elif subnet and subnet != "0.0.0.0/0":
                        SubElement(addr_entry, "ip-netmask").text = subnet

        # Service objects
        svc_grp = SubElement(entry_vsys, "service")
        svc_seen = set()
        for rule in self.ruleset.rules:
            if rule.port > 0:
                svc_name = self._service_name(rule)
                if svc_name not in svc_seen:
                    svc_seen.add(svc_name)
                    svc_entry = SubElement(svc_grp, "entry", name=svc_name)
                    proto_el = SubElement(svc_entry, "protocol")
                    transport_el = SubElement(
                        proto_el,
                        rule.transport.lower() if rule.transport in ("TCP", "UDP") else "tcp",
                    )
                    SubElement(transport_el, "port").text = str(rule.port)

        # Security rules
        rulebase = SubElement(entry_vsys, "rulebase")
        security = SubElement(rulebase, "security")
        rules_el = SubElement(security, "rules")

        for rule in self.ruleset.rules:
            entry = SubElement(rules_el, "entry", name=rule.rule_id)

            # From / To zones
            from_el = SubElement(entry, "from")
            SubElement(from_el, "member").text = rule.src_zone or "any"

            to_el = SubElement(entry, "to")
            SubElement(to_el, "member").text = rule.dst_zone or "any"

            # Source
            source_el = SubElement(entry, "source")
            src_name = self._address_name(rule.src_ip, rule.src_subnet) or "any"
            SubElement(source_el, "member").text = src_name

            # Destination
            dest_el = SubElement(entry, "destination")
            dst_name = self._address_name(rule.dst_ip, rule.dst_subnet) or "any"
            SubElement(dest_el, "member").text = dst_name

            # Service
            service_el = SubElement(entry, "service")
            if rule.port > 0:
                SubElement(service_el, "member").text = self._service_name(rule)
            else:
                SubElement(service_el, "member").text = "any"

            # Application
            app_el = SubElement(entry, "application")
            SubElement(app_el, "member").text = "any"

            # Action
            SubElement(entry, "action").text = (
                "allow" if rule.action == "allow" else "deny"
            )

            # Logging
            if rule.logging:
                SubElement(entry, "log-start").text = "yes"
                SubElement(entry, "log-end").text = "yes"

            # Description
            if rule.description:
                desc_text = rule.description[:1023]
                SubElement(entry, "description").text = desc_text

        # Write XML with declaration
        xml_bytes = tostring(config, encoding="unicode")
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            fh.write(f"<!-- OT Policy generated {datetime.now().isoformat()} -->\n")
            fh.write(xml_bytes)
            fh.write("\n")

        return [out_path]

    @staticmethod
    def _address_name(ip: str, subnet: str) -> str:
        """Create a PAN-OS address object name."""
        if ip:
            return f"H_{ip.replace('.', '_')}"
        if subnet and subnet != "0.0.0.0/0":
            return f"N_{subnet.replace('.', '_').replace('/', '_')}"
        return ""

    @staticmethod
    def _service_name(rule: PolicyRule) -> str:
        """Create a PAN-OS service object name."""
        transport = rule.transport.lower() if rule.transport in ("TCP", "UDP") else "tcp"
        if rule.ics_protocol:
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", rule.ics_protocol)
            return f"svc_{safe}_{transport}_{rule.port}"
        return f"svc_{transport}_{rule.port}"


# ── Fortinet FortiGate CLI ───────────────────────────────────────────────

class FortinetExporter(BasePolicyExporter):
    """Export rules as FortiGate CLI configuration commands."""

    def export(self, output_dir: str) -> List[str]:
        fg_dir = os.path.join(output_dir, "fortinet")
        os.makedirs(fg_dir, exist_ok=True)
        out_path = os.path.join(fg_dir, "ot_policy.conf")

        lines: List[str] = [
            f"# OT Network Policy - FortiGate Configuration",
            f"# Generated: {datetime.now().isoformat()}",
            f"# Total rules: {self.ruleset.total_rules}",
            f"# Source: {self.ruleset.pcap_file}",
            "",
        ]

        # Address objects
        lines.append("# --- Address Objects ---")
        lines.append("config firewall address")
        addr_seen: set = set()
        for rule in self.ruleset.rules:
            for ip, subnet in [(rule.src_ip, rule.src_subnet),
                                (rule.dst_ip, rule.dst_subnet)]:
                name = self._address_name(ip, subnet)
                if name and name not in addr_seen:
                    addr_seen.add(name)
                    lines.append(f'  edit "{name}"')
                    if ip:
                        lines.append(f"    set subnet {ip}/32")
                    elif subnet and subnet != "0.0.0.0/0":
                        lines.append(f"    set subnet {subnet}")
                    lines.append("  next")
        lines.append("end")
        lines.append("")

        # Service objects
        lines.append("# --- Service Objects ---")
        lines.append("config firewall service custom")
        svc_seen: set = set()
        for rule in self.ruleset.rules:
            if rule.port > 0:
                svc_name = self._service_name(rule)
                if svc_name not in svc_seen:
                    svc_seen.add(svc_name)
                    transport = rule.transport.upper()
                    lines.append(f'  edit "{svc_name}"')
                    if transport in ("TCP", "UDP"):
                        lines.append(f"    set protocol TCP/UDP/SCTP")
                        port_field = "tcp-portrange" if transport == "TCP" else "udp-portrange"
                        lines.append(f"    set {port_field} {rule.port}")
                    lines.append("  next")
        lines.append("end")
        lines.append("")

        # Firewall policies
        lines.append("# --- Firewall Policies ---")
        lines.append("config firewall policy")
        for idx, rule in enumerate(self.ruleset.rules, 1):
            lines.append(f"  edit {idx}")
            lines.append(f'    set name "{rule.rule_id}"')
            lines.append(f'    set srcintf "{rule.src_zone or "any"}"')
            lines.append(f'    set dstintf "{rule.dst_zone or "any"}"')

            src_addr = self._address_name(rule.src_ip, rule.src_subnet) or "all"
            dst_addr = self._address_name(rule.dst_ip, rule.dst_subnet) or "all"
            lines.append(f'    set srcaddr "{src_addr}"')
            lines.append(f'    set dstaddr "{dst_addr}"')

            if rule.port > 0:
                lines.append(f'    set service "{self._service_name(rule)}"')
            else:
                lines.append('    set service "ALL"')

            action = "accept" if rule.action == "allow" else "deny"
            lines.append(f"    set action {action}")
            lines.append(f"    set logtraffic all")

            if rule.description:
                safe_desc = rule.description.replace('"', "'")[:255]
                lines.append(f'    set comments "{safe_desc}"')

            lines.append("  next")
        lines.append("end")
        lines.append("")

        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        return [out_path]

    @staticmethod
    def _address_name(ip: str, subnet: str) -> str:
        if ip:
            return f"H_{ip.replace('.', '_')}"
        if subnet and subnet != "0.0.0.0/0":
            return f"N_{subnet.replace('.', '_').replace('/', '_')}"
        return ""

    @staticmethod
    def _service_name(rule: PolicyRule) -> str:
        transport = rule.transport.upper() if rule.transport in ("TCP", "UDP") else "TCP"
        if rule.ics_protocol:
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", rule.ics_protocol)
            return f"{safe}_{transport}_{rule.port}"
        return f"svc_{transport}_{rule.port}"


# ── Cisco IOS Extended ACL ───────────────────────────────────────────────

class CiscoACLExporter(BasePolicyExporter):
    """Export rules as Cisco IOS extended ACLs, one per zone."""

    def export(self, output_dir: str) -> List[str]:
        cisco_dir = os.path.join(output_dir, "cisco")
        os.makedirs(cisco_dir, exist_ok=True)
        written: List[str] = []

        for zone_id, zone_rules in sorted(self.ruleset.rules_by_zone.items()):
            acl_name = self._sanitize_acl_name(zone_id)
            out_path = os.path.join(cisco_dir, f"OT_ZONE_{acl_name}.acl")

            lines: List[str] = [
                f"! OT Network Policy - Zone: {zone_id}",
                f"! Generated: {datetime.now().isoformat()}",
                f"! Rules: {len(zone_rules)}",
                f"! Source: {self.ruleset.pcap_file}",
                "!",
            ]

            if len(zone_rules) > 1000:
                lines.append(
                    "! WARNING: Rule count exceeds 1000 -- "
                    "consider consolidating for IOS performance"
                )
                lines.append("!")

            lines.append(f"ip access-list extended OT_ZONE_{acl_name}")

            for rule in zone_rules:
                action = "permit" if rule.action == "allow" else "deny"
                proto_kw = self._protocol_keyword(rule.transport)

                # Source
                if rule.src_ip:
                    src = f"host {rule.src_ip}"
                elif rule.src_subnet and rule.src_subnet != "0.0.0.0/0":
                    src = self._subnet_to_wildcard(rule.src_subnet)
                else:
                    src = "any"

                # Destination
                if rule.dst_ip:
                    dst = f"host {rule.dst_ip}"
                elif rule.dst_subnet and rule.dst_subnet != "0.0.0.0/0":
                    dst = self._subnet_to_wildcard(rule.dst_subnet)
                else:
                    dst = "any"

                # Port
                port_str = ""
                if rule.port > 0 and proto_kw in ("tcp", "udp"):
                    port_str = f" eq {rule.port}"

                # Remark
                if rule.description:
                    safe_desc = rule.description[:100]
                    lines.append(f"  remark {rule.rule_id}: {safe_desc}")

                # ACE
                log_str = " log" if rule.logging and rule.action == "deny" else ""
                lines.append(
                    f"  {action} {proto_kw} {src} {dst}{port_str}{log_str}"
                )

            lines.append("!")
            lines.append("")

            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            written.append(out_path)

        return written

    @staticmethod
    def _sanitize_acl_name(zone_id: str) -> str:
        """Convert zone_id to valid Cisco ACL name."""
        return re.sub(r"[^a-zA-Z0-9_]", "_", zone_id)

    @staticmethod
    def _protocol_keyword(transport: str) -> str:
        """Map transport to Cisco ACL keyword."""
        mapping = {"TCP": "tcp", "UDP": "udp", "IP": "ip"}
        return mapping.get(transport.upper(), "ip")

    @staticmethod
    def _subnet_to_wildcard(subnet: str) -> str:
        """Convert CIDR notation to Cisco wildcard mask format."""
        if "/" not in subnet:
            return subnet

        parts = subnet.split("/")
        ip = parts[0]
        try:
            prefix = int(parts[1])
        except (ValueError, IndexError):
            return ip

        # Calculate wildcard mask
        mask_int = (0xFFFFFFFF >> prefix) & 0xFFFFFFFF
        wildcard = ".".join(str((mask_int >> (8 * i)) & 0xFF) for i in range(3, -1, -1))
        return f"{ip} {wildcard}"


# ── Generic JSON ─────────────────────────────────────────────────────────

class JSONPolicyExporter(BasePolicyExporter):
    """Export rules as machine-readable JSON."""

    def export(self, output_dir: str) -> List[str]:
        json_dir = os.path.join(output_dir, "json")
        os.makedirs(json_dir, exist_ok=True)
        written: List[str] = []

        # Full ruleset
        full_path = os.path.join(json_dir, "ot_policy.json")
        with open(full_path, "w", encoding="utf-8") as fh:
            json.dump(self.ruleset.to_dict(), fh, indent=2, default=str)
        written.append(full_path)

        # Per-zone files
        for zone_id, zone_rules in sorted(self.ruleset.rules_by_zone.items()):
            safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", zone_id)
            zone_path = os.path.join(json_dir, f"zone_{safe_id}.json")
            zone_data = {
                "zone_id": zone_id,
                "rule_count": len(zone_rules),
                "rules": [r.to_dict() for r in zone_rules],
            }
            with open(zone_path, "w", encoding="utf-8") as fh:
                json.dump(zone_data, fh, indent=2, default=str)
            written.append(zone_path)

        return written


# ── Convenience function ─────────────────────────────────────────────────

def export_all_formats(ruleset: PolicyRuleSet, output_dir: str) -> List[str]:
    """Run all four exporters and return combined list of written file paths."""
    os.makedirs(output_dir, exist_ok=True)
    written: List[str] = []
    for exporter_cls in (
        PaloAltoExporter,
        FortinetExporter,
        CiscoACLExporter,
        JSONPolicyExporter,
    ):
        exporter = exporter_cls(ruleset)
        written.extend(exporter.export(output_dir))
    return written
