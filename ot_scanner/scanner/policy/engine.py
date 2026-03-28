"""
Network Policy Recommendation Engine for the OT Passive Scanner.

Analyses observed communication flows, device roles, Purdue model zones,
and topology edges to auto-generate firewall / network segmentation rules.

Rule priority scheme (lower = higher priority):
    10-49    Safety system isolation
    50-99    Control traffic rules
   100-499   Flow-based allow rules
   500-599   DMZ enforcement
   600-799   Zone segmentation (inter-zone deny-with-exceptions)
   9999      Implicit deny all (always last per zone)

Zero external dependencies -- uses only Python stdlib.
"""

import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from ..models import (
    CommFlow,
    NetworkZone,
    OTDevice,
    PolicyRule,
    PolicyRuleSet,
    TopologyEdge,
    ZoneViolation,
)

logger = logging.getLogger(__name__)


# ── ICS protocol -> (default_port, transport) ───────────────────────────
ICS_PROTOCOL_PORTS: Dict[str, Tuple[int, str]] = {
    "Modbus/TCP":           (502, "TCP"),
    "Modbus":               (502, "TCP"),
    "S7comm":               (102, "TCP"),
    "S7comm+":              (102, "TCP"),
    "EtherNet/IP":          (44818, "TCP"),
    "EtherNet/IP CIP":      (44818, "TCP"),
    "DNP3":                 (20000, "TCP"),
    "Omron FINS":           (9600, "UDP"),
    "MELSEC MC Protocol":   (5006, "TCP"),
    "MELSEC":               (5006, "TCP"),
    "IEC 60870-5-104":      (2404, "TCP"),
    "IEC-104":              (2404, "TCP"),
    "IEC 61850 MMS":        (102, "TCP"),
    "MMS":                  (102, "TCP"),
    "SEL Fast Message":     (702, "TCP"),
    "OPC-UA":               (4840, "TCP"),
    "BACnet/IP":            (47808, "UDP"),
    "BACnet":               (47808, "UDP"),
    "MQTT":                 (1883, "TCP"),
    "PROFINET RT":          (34962, "UDP"),
    "PROFINET":             (34962, "UDP"),
}

# ── Compliance framework references by rule category ────────────────────
COMPLIANCE_MAP: Dict[str, List[str]] = {
    "zone_segmentation": [
        "IEC 62443-3-3 SR 5.1",
        "NERC CIP-005-6 R1",
        "NIST 800-82 \u00a75.1",
    ],
    "zone_boundary": [
        "IEC 62443-3-3 SR 5.2",
        "NERC CIP-005-6 R1.5",
    ],
    "control_traffic": [
        "IEC 62443-3-3 SR 3.1",
        "NERC CIP-007-6 R5",
    ],
    "safety_isolation": [
        "IEC 62443-3-3 SR 5.1",
        "IEC 62443-3-3 SR 1.1",
        "NIST 800-82 \u00a76.2.5",
    ],
    "dmz_enforcement": [
        "IEC 62443-3-3 SR 5.2",
        "NERC CIP-005-6 R1",
        "NIST 800-82 \u00a75.2",
    ],
    "default_deny": [
        "IEC 62443-3-3 SR 5.1",
        "NERC CIP-005-6 R2.4",
        "NIST 800-82 \u00a75.1",
    ],
}

# Protocols that are connectionless and should get bidirectional rules
_UDP_PROTOCOLS: Set[str] = {
    "Omron FINS", "BACnet/IP", "BACnet", "PROFINET RT", "PROFINET",
}


class PolicyEngine:
    """
    Generates firewall / network segmentation rule recommendations
    from observed OT/ICS communication patterns.

    Usage::

        engine = PolicyEngine(devices, flows, zones, violations, edges)
        ruleset = engine.generate()
    """

    def __init__(
        self,
        devices: List[OTDevice],
        flows: List[CommFlow],
        zones: List[NetworkZone],
        violations: List[ZoneViolation],
        edges: List[TopologyEdge],
        pcap_file: str = "",
    ) -> None:
        self._devices = devices
        self._flows = flows
        self._zones = zones
        self._violations = violations
        self._edges = edges
        self._pcap_file = pcap_file

        # Build lookup tables
        self._device_map: Dict[str, OTDevice] = {d.ip: d for d in devices}
        self._ip_to_zone: Dict[str, NetworkZone] = {}
        self._zone_map: Dict[str, NetworkZone] = {}
        for z in zones:
            self._zone_map[z.zone_id] = z
            for ip in z.device_ips:
                self._ip_to_zone[ip] = z

    # ── public API ───────────────────────────────────────────────────

    def generate(self) -> PolicyRuleSet:
        """Generate the complete recommended policy rule set."""
        all_rules: List[PolicyRule] = []

        # Stage 1-6: generate rules by category
        all_rules.extend(self._generate_safety_system_rules())
        all_rules.extend(self._generate_control_traffic_rules())
        all_rules.extend(self._generate_flow_allow_rules())
        all_rules.extend(self._generate_dmz_enforcement_rules())
        all_rules.extend(self._generate_zone_segmentation_rules())
        all_rules.extend(self._generate_implicit_deny_rules())

        # Deduplicate and sort by priority
        all_rules = self._deduplicate_rules(all_rules)
        all_rules.sort(key=lambda r: (r.priority, r.rule_id))

        # Assign sequential rule IDs
        for idx, rule in enumerate(all_rules, 1):
            rule.rule_id = f"PR-{idx:03d}"

        # Organize by zone
        rules_by_zone: Dict[str, List[PolicyRule]] = defaultdict(list)
        for rule in all_rules:
            zone_key = rule.src_zone or rule.dst_zone or "global"
            rules_by_zone[zone_key].append(rule)

        # Build summary
        allow_count = sum(1 for r in all_rules if r.action == "allow")
        deny_count = sum(1 for r in all_rules if r.action == "deny")
        control_count = sum(1 for r in all_rules if r.is_control_traffic)
        safety_count = sum(
            1 for r in all_rules
            if "safety" in r.rationale.lower()
            or "safety" in r.description.lower()
        )

        ruleset = PolicyRuleSet(
            generated_at=datetime.now().isoformat(),
            pcap_file=self._pcap_file,
            total_rules=len(all_rules),
            zone_count=len(rules_by_zone),
            rules=all_rules,
            rules_by_zone=dict(rules_by_zone),
            summary={
                "allow_rules": allow_count,
                "deny_rules": deny_count,
                "control_traffic_rules": control_count,
                "safety_isolation_rules": safety_count,
                "zones_covered": len(rules_by_zone),
                "ics_protocols_observed": sorted({
                    r.ics_protocol for r in all_rules if r.ics_protocol
                }),
            },
        )

        logger.info(
            "Generated %d policy rules across %d zones",
            ruleset.total_rules, ruleset.zone_count,
        )
        return ruleset

    # ── Stage 1: Safety system isolation (priority 10-49) ────────────

    def _generate_safety_system_rules(self) -> List[PolicyRule]:
        """Strict isolation for safety-critical devices."""
        rules: List[PolicyRule] = []
        priority = 10

        for dev in self._devices:
            if dev.device_criticality != "safety_system":
                continue

            src_zone, src_subnet, src_purdue = self._resolve_zone(dev.ip)

            # Allow rules: only known master stations on observed protocols
            allowed_ports: Set[int] = set()
            for master_ip in dev.master_stations:
                m_zone, m_subnet, m_purdue = self._resolve_zone(master_ip)
                # Determine protocols between master and this device
                proto_ports = self._get_observed_ports(master_ip, dev.ip)
                for proto, port, transport in proto_ports:
                    allowed_ports.add(port)
                    rules.append(PolicyRule(
                        action="allow",
                        src_ip=master_ip,
                        dst_ip=dev.ip,
                        protocol=proto,
                        port=port,
                        transport=transport,
                        src_zone=m_zone,
                        dst_zone=src_zone,
                        src_purdue=m_purdue,
                        dst_purdue=src_purdue,
                        direction="inbound",
                        priority=priority,
                        description=(
                            f"Allow {proto} from master {master_ip} to "
                            f"safety system {dev.ip}"
                        ),
                        rationale=(
                            "Safety-critical device must only accept control "
                            "from known, authorized master stations"
                        ),
                        ics_protocol=self._get_ics_protocol_name(proto),
                        is_control_traffic=True,
                        compliance_refs=self._get_compliance_refs("safety_isolation"),
                    ))
                    priority = min(priority + 1, 49)

            # Deny all other inbound to safety device
            rules.append(PolicyRule(
                action="deny",
                dst_ip=dev.ip,
                dst_subnet=src_subnet,
                src_zone="any",
                dst_zone=src_zone,
                dst_purdue=src_purdue,
                direction="inbound",
                priority=45,
                logging=True,
                description=f"Deny all unauthorized traffic to safety system {dev.ip}",
                rationale=(
                    "Safety instrumented systems require strict network isolation; "
                    "only pre-authorized master stations are permitted"
                ),
                compliance_refs=self._get_compliance_refs("safety_isolation"),
            ))

            # Deny all outbound from safety device except to known peers
            known_peers = dev.communicating_with | dev.master_stations
            if known_peers:
                rules.append(PolicyRule(
                    action="deny",
                    src_ip=dev.ip,
                    src_zone=src_zone,
                    dst_zone="any",
                    src_purdue=src_purdue,
                    direction="outbound",
                    priority=48,
                    logging=True,
                    description=(
                        f"Deny unauthorized outbound from safety system {dev.ip} "
                        f"(known peers: {len(known_peers)})"
                    ),
                    rationale=(
                        "Safety systems should not initiate connections to "
                        "unknown destinations"
                    ),
                    compliance_refs=self._get_compliance_refs("safety_isolation"),
                ))

        return rules

    # ── Stage 2: Control traffic rules (priority 50-99) ──────────────

    def _generate_control_traffic_rules(self) -> List[PolicyRule]:
        """Higher-priority rules for control-bearing communication edges."""
        rules: List[PolicyRule] = []
        priority = 50

        for edge in self._edges:
            if not edge.is_control:
                continue

            src_zone, src_subnet, src_purdue = self._resolve_zone(edge.src_ip)
            dst_zone, dst_subnet, dst_purdue = self._resolve_zone(edge.dst_ip)

            for proto in sorted(edge.protocols):
                ics_name = self._get_ics_protocol_name(proto)
                port_info = ICS_PROTOCOL_PORTS.get(proto) or ICS_PROTOCOL_PORTS.get(ics_name)
                port = port_info[0] if port_info else 0
                transport = port_info[1] if port_info else "TCP"

                rules.append(PolicyRule(
                    action="allow",
                    src_ip=edge.src_ip,
                    dst_ip=edge.dst_ip,
                    protocol=proto,
                    port=port,
                    transport=transport,
                    src_zone=src_zone,
                    dst_zone=dst_zone,
                    src_purdue=src_purdue,
                    dst_purdue=dst_purdue,
                    direction="inbound",
                    priority=priority,
                    description=(
                        f"Allow control traffic: {proto} from {edge.src_ip} "
                        f"to {edge.dst_ip} ({edge.packet_count} packets observed)"
                    ),
                    rationale=(
                        f"Control-bearing communication observed between "
                        f"Purdue L{src_purdue} and L{dst_purdue}"
                    ),
                    ics_protocol=ics_name,
                    is_control_traffic=True,
                    compliance_refs=self._get_compliance_refs("control_traffic"),
                ))
                priority = min(priority + 1, 99)

        return rules

    # ── Stage 3: Flow-based allow rules (priority 100-499) ───────────

    def _generate_flow_allow_rules(self) -> List[PolicyRule]:
        """One allow rule per observed communication flow."""
        rules: List[PolicyRule] = []
        priority = 100

        # Track already-covered (src, dst, port) from control rules
        covered: Set[Tuple[str, str, int]] = set()
        for edge in self._edges:
            if edge.is_control:
                for proto in edge.protocols:
                    port_info = ICS_PROTOCOL_PORTS.get(proto)
                    if port_info:
                        covered.add((edge.src_ip, edge.dst_ip, port_info[0]))

        for flow in self._flows:
            # Skip flows already covered by control traffic rules
            if (flow.src_ip, flow.dst_ip, flow.port) in covered:
                continue

            src_zone, src_subnet, src_purdue = self._resolve_zone(flow.src_ip)
            dst_zone, dst_subnet, dst_purdue = self._resolve_zone(flow.dst_ip)

            ics_name = self._get_ics_protocol_name(flow.protocol)
            is_udp_proto = flow.protocol in _UDP_PROTOCOLS or flow.transport == "UDP"

            first = flow.first_seen.isoformat() if flow.first_seen else "unknown"
            last = flow.last_seen.isoformat() if flow.last_seen else "unknown"

            rules.append(PolicyRule(
                action="allow",
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                protocol=flow.protocol,
                port=flow.port,
                transport=flow.transport,
                src_zone=src_zone,
                dst_zone=dst_zone,
                src_purdue=src_purdue,
                dst_purdue=dst_purdue,
                direction="bidirectional" if is_udp_proto else "inbound",
                priority=priority,
                description=(
                    f"Allow {flow.protocol} from {flow.src_ip} to "
                    f"{flow.dst_ip}:{flow.port}/{flow.transport}"
                ),
                rationale=(
                    f"Observed {flow.packet_count} packets "
                    f"({flow.byte_count} bytes) between {first} and {last}"
                ),
                ics_protocol=ics_name,
                compliance_refs=self._get_compliance_refs("zone_segmentation"),
            ))
            priority = min(priority + 1, 499)

        return rules

    # ── Stage 4: DMZ enforcement (priority 500-599) ──────────────────

    def _generate_dmz_enforcement_rules(self) -> List[PolicyRule]:
        """Rules enforcing DMZ boundary between OT (L0-2) and IT (L4+)."""
        rules: List[PolicyRule] = []
        priority = 500

        # Find DMZ zones (L3 or L3.5)
        dmz_zones = [
            z for z in self._zones
            if z.purdue_level == 3 or z.purdue_level == 4
        ]
        ot_zones = [z for z in self._zones if 0 <= z.purdue_level <= 2]
        it_zones = [z for z in self._zones if z.purdue_level >= 4]

        if not dmz_zones:
            return rules

        # For cross-zone edges that span OT<->IT, check if they transit DMZ
        for edge in self._edges:
            if not edge.is_cross_zone:
                continue

            src_zone = self._ip_to_zone.get(edge.src_ip)
            dst_zone = self._ip_to_zone.get(edge.dst_ip)
            if not src_zone or not dst_zone:
                continue

            src_lv = src_zone.purdue_level
            dst_lv = dst_zone.purdue_level

            # Direct L0-2 <-> L4+ bypass (skipping DMZ)
            if (src_lv <= 2 and dst_lv >= 4) or (src_lv >= 4 and dst_lv <= 2):
                for proto in sorted(edge.protocols):
                    rules.append(PolicyRule(
                        action="deny",
                        src_ip=edge.src_ip,
                        dst_ip=edge.dst_ip,
                        protocol=proto,
                        src_zone=src_zone.zone_id,
                        dst_zone=dst_zone.zone_id,
                        src_purdue=src_lv,
                        dst_purdue=dst_lv,
                        direction="bidirectional",
                        priority=priority,
                        logging=True,
                        description=(
                            f"Block direct OT/IT bypass: {proto} from "
                            f"L{src_lv} ({edge.src_ip}) to L{dst_lv} ({edge.dst_ip})"
                        ),
                        rationale=(
                            "Direct communication between OT control zones (L0-2) "
                            "and IT enterprise (L4+) must transit through a DMZ"
                        ),
                        ics_protocol=self._get_ics_protocol_name(proto),
                        compliance_refs=self._get_compliance_refs("dmz_enforcement"),
                    ))
                    priority = min(priority + 1, 599)

        return rules

    # ── Stage 5: Zone segmentation (priority 600-799) ────────────────

    def _generate_zone_segmentation_rules(self) -> List[PolicyRule]:
        """Inter-zone deny-by-default with specific allows for observed traffic."""
        rules: List[PolicyRule] = []
        priority = 600

        # Build cross-zone allow set from edges
        cross_zone_allows: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        for edge in self._edges:
            if not edge.is_cross_zone:
                continue
            src_z = self._ip_to_zone.get(edge.src_ip)
            dst_z = self._ip_to_zone.get(edge.dst_ip)
            if src_z and dst_z:
                pair = (src_z.zone_id, dst_z.zone_id)
                cross_zone_allows[pair].update(edge.protocols)

        # For each zone pair with observed traffic, generate allow + deny
        for (src_zid, dst_zid), protocols in sorted(cross_zone_allows.items()):
            src_z = self._zone_map.get(src_zid)
            dst_z = self._zone_map.get(dst_zid)
            if not src_z or not dst_z:
                continue

            # Allow rules for observed protocols
            for proto in sorted(protocols):
                ics_name = self._get_ics_protocol_name(proto)
                port_info = ICS_PROTOCOL_PORTS.get(proto) or ICS_PROTOCOL_PORTS.get(ics_name)
                port = port_info[0] if port_info else 0
                transport = port_info[1] if port_info else "TCP"

                rules.append(PolicyRule(
                    action="allow",
                    src_subnet=src_z.subnet,
                    dst_subnet=dst_z.subnet,
                    protocol=proto,
                    port=port,
                    transport=transport,
                    src_zone=src_zid,
                    dst_zone=dst_zid,
                    src_purdue=src_z.purdue_level,
                    dst_purdue=dst_z.purdue_level,
                    direction="inbound",
                    priority=priority,
                    description=(
                        f"Allow {proto} between zone {src_z.subnet} "
                        f"(L{src_z.purdue_level}) and {dst_z.subnet} "
                        f"(L{dst_z.purdue_level})"
                    ),
                    rationale=(
                        f"Cross-zone {proto} traffic observed between "
                        f"{src_z.purdue_label} and {dst_z.purdue_label}"
                    ),
                    ics_protocol=ics_name,
                    compliance_refs=self._get_compliance_refs("zone_boundary"),
                ))
                priority = min(priority + 1, 799)

            # Deny all other traffic between this zone pair
            rules.append(PolicyRule(
                action="deny",
                src_subnet=src_z.subnet,
                dst_subnet=dst_z.subnet,
                src_zone=src_zid,
                dst_zone=dst_zid,
                src_purdue=src_z.purdue_level,
                dst_purdue=dst_z.purdue_level,
                direction="bidirectional",
                priority=min(priority, 799),
                logging=True,
                description=(
                    f"Deny unobserved traffic between {src_z.subnet} "
                    f"(L{src_z.purdue_level}) and {dst_z.subnet} "
                    f"(L{dst_z.purdue_level})"
                ),
                rationale=(
                    "Only protocols observed in the PCAP baseline are permitted "
                    "across zone boundaries; all other inter-zone traffic is denied"
                ),
                compliance_refs=self._get_compliance_refs("zone_segmentation"),
            ))

        return rules

    # ── Stage 6: Implicit deny all (priority 9999) ───────────────────

    def _generate_implicit_deny_rules(self) -> List[PolicyRule]:
        """One deny-all rule per zone as the final catch-all."""
        rules: List[PolicyRule] = []

        for zone in self._zones:
            rules.append(PolicyRule(
                action="deny",
                src_subnet=zone.subnet,
                dst_subnet="0.0.0.0/0",
                transport="IP",
                src_zone=zone.zone_id,
                dst_zone="any",
                src_purdue=zone.purdue_level,
                direction="outbound",
                priority=9999,
                logging=True,
                description=(
                    f"Default deny all from zone {zone.subnet} "
                    f"(L{zone.purdue_level} {zone.purdue_label})"
                ),
                rationale=(
                    "Implicit deny-all ensures only explicitly permitted "
                    "traffic is allowed from this zone"
                ),
                compliance_refs=self._get_compliance_refs("default_deny"),
            ))

            rules.append(PolicyRule(
                action="deny",
                src_subnet="0.0.0.0/0",
                dst_subnet=zone.subnet,
                transport="IP",
                src_zone="any",
                dst_zone=zone.zone_id,
                dst_purdue=zone.purdue_level,
                direction="inbound",
                priority=9999,
                logging=True,
                description=(
                    f"Default deny all to zone {zone.subnet} "
                    f"(L{zone.purdue_level} {zone.purdue_label})"
                ),
                rationale=(
                    "Implicit deny-all ensures only explicitly permitted "
                    "traffic is allowed into this zone"
                ),
                compliance_refs=self._get_compliance_refs("default_deny"),
            ))

        return rules

    # ── helpers ───────────────────────────────────────────────────────

    def _resolve_zone(self, ip: str) -> Tuple[str, str, int]:
        """Return (zone_id, subnet, purdue_level) for an IP."""
        zone = self._ip_to_zone.get(ip)
        if zone:
            return zone.zone_id, zone.subnet, zone.purdue_level
        return "external", "0.0.0.0/0", -1

    def _get_observed_ports(
        self, src_ip: str, dst_ip: str,
    ) -> List[Tuple[str, int, str]]:
        """Return list of (protocol, port, transport) observed between two IPs."""
        results: List[Tuple[str, int, str]] = []
        for flow in self._flows:
            if flow.src_ip == src_ip and flow.dst_ip == dst_ip:
                results.append((flow.protocol, flow.port, flow.transport))
            elif flow.src_ip == dst_ip and flow.dst_ip == src_ip:
                results.append((flow.protocol, flow.port, flow.transport))
        return results

    def _get_ics_protocol_name(self, protocol: str) -> str:
        """Normalize protocol string to canonical ICS name."""
        if protocol in ICS_PROTOCOL_PORTS:
            return protocol
        # Try substring matching
        proto_lower = protocol.lower()
        for name in ICS_PROTOCOL_PORTS:
            if name.lower() in proto_lower or proto_lower in name.lower():
                return name
        return protocol

    def _get_compliance_refs(self, rule_type: str) -> List[str]:
        """Return compliance references for a given rule category."""
        return list(COMPLIANCE_MAP.get(rule_type, []))

    def _deduplicate_rules(self, rules: List[PolicyRule]) -> List[PolicyRule]:
        """
        Remove duplicate rules by (src, dst, port, transport, action) key.
        Keeps the rule with the lowest (highest-priority) priority value.
        """
        seen: Dict[tuple, PolicyRule] = {}
        for rule in rules:
            key = (
                rule.src_ip or rule.src_subnet,
                rule.dst_ip or rule.dst_subnet,
                rule.port,
                rule.transport,
                rule.action,
            )
            existing = seen.get(key)
            if existing is None or rule.priority < existing.priority:
                seen[key] = rule

        return list(seen.values())
