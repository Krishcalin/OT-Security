"""
Topology analysis engine for OT passive scanner.

Performs:
  1. Subnet inference from observed device IPs
  2. Purdue model level assignment based on device roles and protocols
  3. Topology edge aggregation from communication flows
  4. Zone violation detection (IEC 62443 / NERC CIP segmentation rules)
  5. GraphML export for visualization

References:
  - IEC 62443-3-3  Zone and conduit requirements
  - NERC CIP-005   Electronic Security Perimeter(s)
  - Purdue Enterprise Reference Architecture (ISA-95 / ISA-99)
"""

from typing import Dict, List, Set, Tuple
from collections import Counter
from xml.sax.saxutils import escape as xml_escape

from ..models import OTDevice, CommFlow, NetworkZone, ZoneViolation, TopologyEdge


# ───────────────────────────────── Constants ──────────────────────────────────

PURDUE_LABELS: Dict[int, str] = {
    0:  "Level 0 — Process",
    1:  "Level 1 — Basic Control",
    2:  "Level 2 — Area Supervisory",
    3:  "Level 3 — Site Operations",
    -1: "Unknown",
}

# Protocols strongly associated with Purdue Level 1 (field bus / direct control)
LEVEL1_PROTOCOLS: Set[str] = {
    "Modbus/TCP", "S7comm", "S7comm+", "DNP3", "IEC 60870-5-104",
    "Omron FINS", "MELSEC MC Protocol", "IEC 61850 GOOSE", "IEC 61850 MMS",
    "SEL Fast Message", "PROFINET RT", "PROFINET DCP", "EtherNet/IP",
}

# Protocols that indicate supervisory / aggregation layer when combined with L1
LEVEL2_PROTOCOLS: Set[str] = {"OPC-UA"}

# Protocols associated with site operations / IoT when standing alone
LEVEL3_PROTOCOLS: Set[str] = {"MQTT", "BACnet/IP"}

# Control protocols that should not traverse more than one Purdue boundary
CONTROL_PROTOCOLS: Set[str] = {
    "DNP3", "IEC 60870-5-104", "S7comm", "S7comm+",
    "MELSEC MC Protocol", "Omron FINS", "SEL Fast Message",
    "Modbus/TCP", "EtherNet/IP", "IEC 61850 GOOSE", "IEC 61850 MMS",
    "PROFINET RT",
}

# IT protocols that should NOT appear inside Level 0-1 OT zones
IT_PROTOCOLS_IN_OT: Dict[str, Set[int]] = {
    "HTTP":  {80, 443, 8080, 8443},
    "HTTPS": {443, 8443},
    "SSH":   {22},
    "RDP":   {3389},
    "SMB":   {445, 139},
    "DNS":   {53},
}

# Roles that map directly to a Purdue level (strongest signal)
ROLE_TO_PURDUE: Dict[str, int] = {
    "plc":                 1,
    "rtu":                 1,
    "frtu":                1,
    "ied":                 1,
    "relay":               1,
    "hmi":                 2,
    "engineering_station": 2,
    "master_station":      2,
    "historian":           3,
    "gateway":             2,   # default; may be reclassified as DMZ (3.5)
}

# GraphML node fill colour by Purdue level (Catppuccin Mocha palette)
PURDUE_COLORS: Dict[int, str] = {
    0:  "#89b4fa",   # blue  — Process
    1:  "#a6e3a1",   # green — Basic Control
    2:  "#f9e2af",   # yellow — Area Supervisory
    3:  "#fab387",   # peach — Site Operations
    -1: "#cdd6f4",   # text  — Unknown / Enterprise
}


# ────────────────────────────── TopologyEngine ────────────────────────────────

class TopologyEngine:
    """
    Analyses OT device inventory and communication flows to produce:
      - NetworkZone objects (subnet inference + Purdue level)
      - ZoneViolation objects (segmentation rule breaches)
      - TopologyEdge objects (aggregated directed graph edges)
      - GraphML XML string for external visualization tools
    """

    # ── public API ────────────────────────────────────────────────────────

    def analyze(
        self,
        devices: List[OTDevice],
        flows: List[CommFlow],
    ) -> Tuple[List[NetworkZone], List[ZoneViolation], List[TopologyEdge]]:
        """
        Main entry point — run all topology analysis stages.

        Args:
            devices: Discovered OT devices with protocol and role data.
            flows:   Observed directional communication flows.

        Returns:
            Tuple of (zones, violations, edges).
        """
        if not devices:
            return [], [], []

        # Build lookup: ip -> OTDevice
        device_map: Dict[str, OTDevice] = {d.ip: d for d in devices}

        # Step 1: group devices into /24 subnets
        zones = self._infer_subnets(devices)

        # Step 2: assign Purdue levels using role + protocol heuristics
        self._assign_purdue_levels(zones, device_map, flows)

        # Build quick lookups used by later stages
        ip_to_zone: Dict[str, NetworkZone] = {}
        for z in zones:
            for ip in z.device_ips:
                ip_to_zone[ip] = z

        # Step 3: aggregate flows into topology edges
        edges = self._build_edges(flows, ip_to_zone)

        # Step 4: detect zone segmentation violations
        violations = self._detect_violations(edges, ip_to_zone, device_map, flows)

        return zones, violations, edges

    def to_graphml(
        self,
        devices: List[OTDevice],
        zones: List[NetworkZone],
        edges: List[TopologyEdge],
        violations: List[ZoneViolation],
    ) -> str:
        """
        Export the topology as a GraphML XML string.

        Nodes represent individual device IPs; edges represent aggregated
        communication flows.  Node colour is mapped to the device's Purdue
        level; edge colour encodes cross-zone severity.
        """
        device_map: Dict[str, OTDevice] = {d.ip: d for d in devices}
        ip_to_zone: Dict[str, NetworkZone] = {}
        for z in zones:
            for ip in z.device_ips:
                ip_to_zone[ip] = z

        # Collect all unique IPs that appear in edges (covers devices + peers)
        all_ips: Set[str] = set()
        for d in devices:
            all_ips.add(d.ip)
        for e in edges:
            all_ips.add(e.src_ip)
            all_ips.add(e.dst_ip)

        lines: List[str] = []
        lines.append('<?xml version="1.0" encoding="UTF-8"?>')
        lines.append(
            '<graphml xmlns="http://graphml.graphsheets.org/xmlns"'
            ' xmlns:y="http://www.yworks.com/xml/graphml">'
        )

        # Key declarations for node/edge attributes
        lines.append('  <key id="d_label" for="node" attr.name="label" attr.type="string"/>')
        lines.append('  <key id="d_vendor" for="node" attr.name="vendor" attr.type="string"/>')
        lines.append('  <key id="d_role" for="node" attr.name="role" attr.type="string"/>')
        lines.append('  <key id="d_purdue" for="node" attr.name="purdue_level" attr.type="int"/>')
        lines.append('  <key id="d_risk" for="node" attr.name="risk_level" attr.type="string"/>')
        lines.append('  <key id="d_zone" for="node" attr.name="zone_id" attr.type="string"/>')
        lines.append('  <key id="d_fill" for="node" attr.name="fill" attr.type="string"/>')
        lines.append('  <key id="e_proto" for="edge" attr.name="protocols" attr.type="string"/>')
        lines.append('  <key id="e_pkts" for="edge" attr.name="packet_count" attr.type="int"/>')
        lines.append('  <key id="e_ctrl" for="edge" attr.name="is_control" attr.type="boolean"/>')
        lines.append('  <key id="e_xzone" for="edge" attr.name="is_cross_zone" attr.type="boolean"/>')
        lines.append('  <key id="e_span" for="edge" attr.name="purdue_span" attr.type="int"/>')
        lines.append('  <key id="e_color" for="edge" attr.name="color" attr.type="string"/>')

        lines.append('  <graph id="ot_topology" edgedefault="directed">')

        # ── Nodes ──
        for ip in sorted(all_ips):
            dev = device_map.get(ip)
            zone = ip_to_zone.get(ip)
            vendor = xml_escape(dev.vendor or "unknown") if dev else "unknown"
            role = dev.role if dev else "unknown"
            risk = dev.risk_level if dev else "unknown"
            purdue = zone.purdue_level if zone else -1
            zone_id = xml_escape(zone.zone_id) if zone else "unknown"
            fill = PURDUE_COLORS.get(purdue, PURDUE_COLORS[-1])

            lines.append(f'    <node id="{xml_escape(ip)}">')
            lines.append(f'      <data key="d_label">{xml_escape(ip)}</data>')
            lines.append(f'      <data key="d_vendor">{vendor}</data>')
            lines.append(f'      <data key="d_role">{xml_escape(role)}</data>')
            lines.append(f'      <data key="d_purdue">{purdue}</data>')
            lines.append(f'      <data key="d_risk">{xml_escape(risk)}</data>')
            lines.append(f'      <data key="d_zone">{zone_id}</data>')
            lines.append(f'      <data key="d_fill">{fill}</data>')
            lines.append('    </node>')

        # ── Edges ──
        for idx, edge in enumerate(edges):
            color = self._edge_color(edge)
            proto_str = xml_escape(", ".join(sorted(edge.protocols)))
            eid = f"e{idx}"
            lines.append(
                f'    <edge id="{eid}" source="{xml_escape(edge.src_ip)}"'
                f' target="{xml_escape(edge.dst_ip)}">'
            )
            lines.append(f'      <data key="e_proto">{proto_str}</data>')
            lines.append(f'      <data key="e_pkts">{edge.packet_count}</data>')
            lines.append(f'      <data key="e_ctrl">{str(edge.is_control).lower()}</data>')
            lines.append(f'      <data key="e_xzone">{str(edge.is_cross_zone).lower()}</data>')
            lines.append(f'      <data key="e_span">{edge.purdue_span}</data>')
            lines.append(f'      <data key="e_color">{color}</data>')
            lines.append('    </edge>')

        lines.append('  </graph>')
        lines.append('</graphml>')
        return "\n".join(lines)

    # ── private: Step 1 — subnet inference ────────────────────────────────

    def _infer_subnets(self, devices: List[OTDevice]) -> List[NetworkZone]:
        """
        Group devices by /24 subnet and create a NetworkZone for each.

        Each zone records the IPs, observed protocols, and the most common
        device role (dominant_role) within that subnet.
        """
        subnet_groups: Dict[str, List[OTDevice]] = {}
        for dev in devices:
            prefix = self._ip_prefix(dev.ip)
            if prefix is None:
                continue
            subnet_groups.setdefault(prefix, []).append(dev)

        zones: List[NetworkZone] = []
        for prefix, devs in sorted(subnet_groups.items()):
            ips: Set[str] = {d.ip for d in devs}
            protocols: Set[str] = set()
            roles: List[str] = []
            for d in devs:
                protocols.update(d.get_protocol_names())
                roles.append(d.role)

            role_counter = Counter(roles)
            dominant = role_counter.most_common(1)[0][0] if role_counter else "unknown"

            zone = NetworkZone(
                zone_id=f"zone_{prefix}",
                subnet=f"{prefix}.0/24",
                subnet_mask=24,
                device_ips=ips,
                device_count=len(ips),
                protocols_seen=protocols,
                dominant_role=dominant,
            )
            zones.append(zone)

        return zones

    # ── private: Step 2 — Purdue level assignment ─────────────────────────

    def _assign_purdue_levels(
        self,
        zones: List[NetworkZone],
        device_map: Dict[str, OTDevice],
        flows: List[CommFlow],
    ) -> None:
        """
        Assign a Purdue model level to each zone based on heuristics.

        Priority order:
          1. Dominant role (strongest signal — direct mapping)
          2. Protocol mix (L1 vs L2 vs L3 indicators)
          3. Master-station / client analysis for L1 vs L2 disambiguation
          4. Default to Level 1 for any zone with OT protocols
        """
        # Pre-compute which zone pairs communicate (for DMZ detection later)
        zone_id_for_ip: Dict[str, str] = {}
        for z in zones:
            for ip in z.device_ips:
                zone_id_for_ip[ip] = z.zone_id

        zone_peers: Dict[str, Set[str]] = {}  # zone_id -> set of peer zone_ids
        for f in flows:
            src_z = zone_id_for_ip.get(f.src_ip)
            dst_z = zone_id_for_ip.get(f.dst_ip)
            if src_z and dst_z and src_z != dst_z:
                zone_peers.setdefault(src_z, set()).add(dst_z)
                zone_peers.setdefault(dst_z, set()).add(src_z)

        # First pass: assign levels based on role + protocol heuristics
        for zone in zones:
            level = self._purdue_from_role(zone.dominant_role)

            if level is not None:
                zone.purdue_level = level
            else:
                # Fall back to protocol analysis
                level = self._purdue_from_protocols(zone, device_map)
                zone.purdue_level = level

            zone.purdue_label = PURDUE_LABELS.get(zone.purdue_level, "Unknown")

        # Criticality-based override (safety_system → L0, process_control → L1)
        for zone in zones:
            crit_level = self._criticality_purdue_override(zone, device_map)
            if crit_level is not None:
                zone.purdue_level = crit_level
                zone.purdue_label = PURDUE_LABELS.get(crit_level, "Unknown")

        # Second pass: detect DMZ zones (zones bridging low and high levels)
        zone_by_id: Dict[str, NetworkZone] = {z.zone_id: z for z in zones}
        for zone in zones:
            peers = zone_peers.get(zone.zone_id, set())
            if len(peers) < 2:
                continue

            peer_levels: Set[int] = set()
            for pid in peers:
                pz = zone_by_id.get(pid)
                if pz and pz.purdue_level >= 0:
                    peer_levels.add(pz.purdue_level)

            has_low = any(lv <= 2 for lv in peer_levels)
            has_high = any(lv >= 3 for lv in peer_levels)

            if has_low and has_high:
                # This zone bridges control (L0-2) and operations (L3+)
                zone.purdue_level = 3  # Treat as DMZ / L3.5 boundary
                zone.purdue_label = "Level 3.5 — DMZ"
                zone.notes.append(
                    "Zone reclassified as DMZ: communicates with both "
                    "control-level and operations-level zones."
                )

    def _purdue_from_role(self, role: str) -> "int | None":
        """Return a Purdue level if the role maps directly, else None."""
        if role in ROLE_TO_PURDUE:
            return ROLE_TO_PURDUE[role]
        return None

    def _criticality_purdue_override(
        self,
        zone: NetworkZone,
        device_map: Dict[str, OTDevice],
    ) -> "int | None":
        """Override Purdue level if device_criticality gives a strong signal.

        Returns a level (int) if the majority of devices in the zone share
        a safety_system or process_control criticality, else None.
        """
        criticalities = []
        for ip in zone.device_ips:
            dev = device_map.get(ip)
            if dev and dev.device_criticality != "unknown":
                criticalities.append(dev.device_criticality)

        if not criticalities:
            return None

        # Safety-system majority → Level 0
        safety_count = criticalities.count("safety_system")
        if safety_count > 0 and safety_count >= len(criticalities) / 2:
            zone.notes.append(
                f"Purdue level forced to 0: {safety_count}/{len(criticalities)} "
                f"devices classified as safety_system."
            )
            return 0

        # Process-control majority → reinforce Level 1
        pc_count = criticalities.count("process_control")
        if pc_count > 0 and pc_count >= len(criticalities) / 2:
            return 1

        return None

    def _purdue_from_protocols(
        self,
        zone: NetworkZone,
        device_map: Dict[str, OTDevice],
    ) -> int:
        """
        Determine Purdue level from the zone's protocol mix and device
        master-station relationships.
        """
        protos = zone.protocols_seen
        has_l1 = bool(protos & LEVEL1_PROTOCOLS)
        has_l2 = bool(protos & LEVEL2_PROTOCOLS)
        has_l3 = bool(protos & LEVEL3_PROTOCOLS)
        has_any_ot = has_l1 or has_l2 or has_l3

        if not has_any_ot:
            # No OT protocols — likely IT / Enterprise (Level 4+) or unknown
            if protos:
                return -1  # has traffic but no OT protocols
            return -1      # no protocols at all

        # L1 + L2 ambiguity: check if devices are servers (L1) or clients (L2)
        if has_l1 and has_l2:
            master_count = 0
            total = 0
            for ip in zone.device_ips:
                dev = device_map.get(ip)
                if dev:
                    total += 1
                    if dev.master_stations:
                        master_count += 1
            # Devices WITH master_stations are outstations (L1);
            # devices WITHOUT master_stations that use OPC-UA are supervisory (L2)
            if total > 0 and master_count < total / 2:
                return 2
            return 1

        if has_l2 and not has_l1:
            return 2

        if has_l3 and not has_l1:
            return 3

        # Pure GOOSE-only zone with all unknowns -> Level 0 (process bus)
        if protos == {"IEC 61850 GOOSE"} and zone.dominant_role == "unknown":
            return 0

        # Default: any remaining OT protocol presence -> Level 1
        if has_l1:
            return 1

        return -1

    # ── private: Step 3 — build edges ─────────────────────────────────────

    def _build_edges(
        self,
        flows: List[CommFlow],
        ip_to_zone: Dict[str, NetworkZone],
    ) -> List[TopologyEdge]:
        """
        Aggregate individual CommFlow records into TopologyEdge objects
        keyed by (src_ip, dst_ip).  Annotate each edge with control flag,
        cross-zone flag, and Purdue span.
        """
        edge_map: Dict[Tuple[str, str], TopologyEdge] = {}

        for f in flows:
            key = (f.src_ip, f.dst_ip)
            if key not in edge_map:
                edge_map[key] = TopologyEdge(src_ip=f.src_ip, dst_ip=f.dst_ip)
            edge = edge_map[key]
            edge.protocols.add(f.protocol)
            edge.packet_count += f.packet_count
            edge.byte_count += f.byte_count

        # Annotate edges
        for edge in edge_map.values():
            # Control flag
            edge.is_control = bool(edge.protocols & CONTROL_PROTOCOLS)

            # Cross-zone and Purdue span
            src_zone = ip_to_zone.get(edge.src_ip)
            dst_zone = ip_to_zone.get(edge.dst_ip)
            if src_zone and dst_zone and src_zone.zone_id != dst_zone.zone_id:
                edge.is_cross_zone = True
                src_lv = src_zone.purdue_level if src_zone.purdue_level >= 0 else 0
                dst_lv = dst_zone.purdue_level if dst_zone.purdue_level >= 0 else 0
                edge.purdue_span = abs(src_lv - dst_lv)
            else:
                edge.is_cross_zone = False
                edge.purdue_span = 0

        return sorted(
            edge_map.values(),
            key=lambda e: (e.src_ip, e.dst_ip),
        )

    # ── private: Step 4 — detect zone violations ─────────────────────────

    def _detect_violations(
        self,
        edges: List[TopologyEdge],
        ip_to_zone: Dict[str, NetworkZone],
        device_map: Dict[str, OTDevice],
        flows: List[CommFlow],
    ) -> List[ZoneViolation]:
        """
        Scan edges and flows for zone segmentation violations.

        Rules:
          ZV-001  Direct L1 -> L3+ communication (bypassing supervisory)
          ZV-002  Control protocol crossing 2+ Purdue levels
          ZV-003  IT protocol in OT zone (L0-1)
          ZV-004  Outbound OT protocol from control zone toward L3+
          ZV-005  Excessive cross-zone peers for L0-1 device
        """
        violations: List[ZoneViolation] = []
        seen: Set[str] = set()  # dedup key

        for edge in edges:
            src_zone = ip_to_zone.get(edge.src_ip)
            dst_zone = ip_to_zone.get(edge.dst_ip)
            if not src_zone or not dst_zone:
                continue

            src_lv = src_zone.purdue_level
            dst_lv = dst_zone.purdue_level

            # Skip edges where we cannot determine levels
            if src_lv < 0 and dst_lv < 0:
                continue

            # Treat unknown (-1) conservatively: skip violation checks
            # unless at least one side is known.
            eff_src = src_lv if src_lv >= 0 else 0
            eff_dst = dst_lv if dst_lv >= 0 else 0
            span = abs(eff_src - eff_dst)

            # ── ZV-001: Direct L1 -> L3+ ──
            if src_lv == 1 and dst_lv >= 3:
                dedup = f"ZV-001:{edge.src_ip}:{edge.dst_ip}"
                if dedup not in seen:
                    seen.add(dedup)
                    violations.append(ZoneViolation(
                        violation_id="ZV-001",
                        severity="high",
                        title="Direct Level 1 to Level 3+ Communication",
                        description=(
                            f"Field device {edge.src_ip} (Level 1, zone {src_zone.zone_id}) "
                            f"communicates directly with {edge.dst_ip} (Level {dst_lv}, "
                            f"zone {dst_zone.zone_id}), bypassing the Area Supervisory layer "
                            f"(Level 2). Protocols: {', '.join(sorted(edge.protocols))}."
                        ),
                        src_ip=edge.src_ip,
                        src_zone=src_zone.zone_id,
                        src_purdue=src_lv,
                        dst_ip=edge.dst_ip,
                        dst_zone=dst_zone.zone_id,
                        dst_purdue=dst_lv,
                        protocol=", ".join(sorted(edge.protocols)),
                        packet_count=edge.packet_count,
                        remediation=(
                            "Route traffic through a Level 2 supervisory system or a "
                            "properly segmented DMZ (Level 3.5). Deploy firewall rules "
                            "enforcing adjacent-layer-only communication per IEC 62443-3-3 "
                            "SR 5.1 and NERC CIP-005-7 R1."
                        ),
                    ))

            # ── ZV-002: Control protocol crossing 2+ levels ──
            if edge.is_control and span >= 2:
                control_protos = edge.protocols & CONTROL_PROTOCOLS
                if control_protos:
                    dedup = f"ZV-002:{edge.src_ip}:{edge.dst_ip}"
                    if dedup not in seen:
                        seen.add(dedup)
                        violations.append(ZoneViolation(
                            violation_id="ZV-002",
                            severity="critical",
                            title="Control Protocol Crossing 2+ Purdue Levels",
                            description=(
                                f"Control protocol(s) {', '.join(sorted(control_protos))} "
                                f"observed between {edge.src_ip} (Level {eff_src}, "
                                f"zone {src_zone.zone_id}) and {edge.dst_ip} "
                                f"(Level {eff_dst}, zone {dst_zone.zone_id}), spanning "
                                f"{span} Purdue levels. Control traffic should only "
                                f"traverse adjacent levels through segmented firewalls."
                            ),
                            src_ip=edge.src_ip,
                            src_zone=src_zone.zone_id,
                            src_purdue=eff_src,
                            dst_ip=edge.dst_ip,
                            dst_zone=dst_zone.zone_id,
                            dst_purdue=eff_dst,
                            protocol=", ".join(sorted(control_protos)),
                            packet_count=edge.packet_count,
                            remediation=(
                                "Introduce an application-layer firewall or data diode at "
                                "each Purdue level boundary. Control protocols must not "
                                "bypass intermediate zones. Ref: IEC 62443-3-3 SR 5.1 / "
                                "SR 5.2, NERC CIP-005-7 R1.2."
                            ),
                        ))

            # ── ZV-003: IT protocol in OT zone (L0-1) ──
            if dst_lv in (0, 1):
                it_protos_found: List[str] = []
                for proto_name, ports in IT_PROTOCOLS_IN_OT.items():
                    for fl in flows:
                        if fl.dst_ip == edge.dst_ip and fl.src_ip == edge.src_ip:
                            if fl.port in ports or fl.protocol in (proto_name,):
                                it_protos_found.append(f"{proto_name}/{fl.port}")
                if it_protos_found:
                    dedup = f"ZV-003:{edge.src_ip}:{edge.dst_ip}"
                    if dedup not in seen:
                        seen.add(dedup)
                        violations.append(ZoneViolation(
                            violation_id="ZV-003",
                            severity="medium",
                            title="IT Protocol in OT Zone",
                            description=(
                                f"IT protocol traffic ({', '.join(sorted(set(it_protos_found)))}) "
                                f"detected flowing from {edge.src_ip} into Level {dst_lv} "
                                f"zone {dst_zone.zone_id} (device {edge.dst_ip}). IT protocols "
                                f"in deep OT zones indicate insufficient network segmentation."
                            ),
                            src_ip=edge.src_ip,
                            src_zone=src_zone.zone_id,
                            src_purdue=eff_src,
                            dst_ip=edge.dst_ip,
                            dst_zone=dst_zone.zone_id,
                            dst_purdue=dst_lv,
                            protocol=", ".join(sorted(set(it_protos_found))),
                            packet_count=edge.packet_count,
                            remediation=(
                                "Block IT protocols (HTTP, SSH, RDP, SMB, DNS) at the OT "
                                "zone firewall. Use OT-specific remote access solutions with "
                                "jump servers in the DMZ. Ref: IEC 62443-3-3 SR 7.1, "
                                "NERC CIP-005-7 R2."
                            ),
                        ))

            # ── ZV-004: Outbound OT protocol from control zone toward L3+ ──
            if src_lv in (0, 1) and dst_lv >= 3 and edge.is_control:
                control_protos = edge.protocols & CONTROL_PROTOCOLS
                if control_protos:
                    dedup = f"ZV-004:{edge.src_ip}:{edge.dst_ip}"
                    if dedup not in seen:
                        seen.add(dedup)
                        violations.append(ZoneViolation(
                            violation_id="ZV-004",
                            severity="high",
                            title="Outbound OT Protocol from Control Zone",
                            description=(
                                f"OT control protocol(s) {', '.join(sorted(control_protos))} "
                                f"observed leaving the control zone from {edge.src_ip} "
                                f"(Level {src_lv}, zone {src_zone.zone_id}) toward "
                                f"{edge.dst_ip} (Level {dst_lv}, zone {dst_zone.zone_id}). "
                                f"This may indicate data exfiltration or a misconfigured "
                                f"gateway."
                            ),
                            src_ip=edge.src_ip,
                            src_zone=src_zone.zone_id,
                            src_purdue=src_lv,
                            dst_ip=edge.dst_ip,
                            dst_zone=dst_zone.zone_id,
                            dst_purdue=dst_lv,
                            protocol=", ".join(sorted(control_protos)),
                            packet_count=edge.packet_count,
                            remediation=(
                                "OT control protocols should never egress the control zone "
                                "toward enterprise or operations networks. Deploy a data "
                                "diode or unidirectional security gateway at the zone "
                                "boundary. Ref: IEC 62443-3-3 SR 5.2, NERC CIP-005-7 R1."
                            ),
                        ))

        # ── ZV-005: Excessive cross-zone peers for L0-1 device ──
        violations.extend(self._check_excessive_peers(edges, ip_to_zone, seen))

        return violations

    def _check_excessive_peers(
        self,
        edges: List[TopologyEdge],
        ip_to_zone: Dict[str, NetworkZone],
        seen: Set[str],
    ) -> List[ZoneViolation]:
        """
        ZV-005: Flag devices in Level 0-1 zones that communicate with
        devices across 3 or more distinct zones.
        """
        results: List[ZoneViolation] = []

        # Map each IP to the set of peer zone_ids it talks to
        ip_peer_zones: Dict[str, Set[str]] = {}
        ip_peer_protos: Dict[str, Set[str]] = {}

        for edge in edges:
            if not edge.is_cross_zone:
                continue
            dst_zone = ip_to_zone.get(edge.dst_ip)
            if dst_zone:
                ip_peer_zones.setdefault(edge.src_ip, set()).add(dst_zone.zone_id)
                ip_peer_protos.setdefault(edge.src_ip, set()).update(edge.protocols)

            src_zone = ip_to_zone.get(edge.src_ip)
            if src_zone:
                ip_peer_zones.setdefault(edge.dst_ip, set()).add(src_zone.zone_id)
                ip_peer_protos.setdefault(edge.dst_ip, set()).update(edge.protocols)

        for ip, peer_zones in ip_peer_zones.items():
            if len(peer_zones) < 3:
                continue
            zone = ip_to_zone.get(ip)
            if not zone or zone.purdue_level not in (0, 1):
                continue

            dedup = f"ZV-005:{ip}"
            if dedup in seen:
                continue
            seen.add(dedup)

            protos = ip_peer_protos.get(ip, set())
            results.append(ZoneViolation(
                violation_id="ZV-005",
                severity="medium",
                title="Excessive Cross-Zone Peers",
                description=(
                    f"Device {ip} in Level {zone.purdue_level} zone "
                    f"{zone.zone_id} communicates with devices across "
                    f"{len(peer_zones)} different zones "
                    f"({', '.join(sorted(peer_zones))}). Field devices should "
                    f"have minimal, well-defined communication partners."
                ),
                src_ip=ip,
                src_zone=zone.zone_id,
                src_purdue=zone.purdue_level,
                dst_ip="(multiple)",
                dst_zone=", ".join(sorted(peer_zones)),
                dst_purdue=-1,
                protocol=", ".join(sorted(protos)),
                packet_count=0,
                remediation=(
                    "Review and restrict the allowed communication partners for "
                    "this field device using host-based firewall rules or switch "
                    "ACLs. Each Level 0-1 device should only communicate with its "
                    "designated controller/supervisor. Ref: IEC 62443-3-3 SR 5.1, "
                    "NERC CIP-005-7 R1."
                ),
            ))

        return results

    # ── private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _ip_prefix(ip: str) -> "str | None":
        """
        Extract the /24 prefix (first 3 octets) from an IPv4 address.

        Returns None if the address is not a valid IPv4 string.
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return None
        if all(0 <= o <= 255 for o in octets):
            return f"{octets[0]}.{octets[1]}.{octets[2]}"
        return None

    @staticmethod
    def _edge_color(edge: TopologyEdge) -> str:
        """Pick an edge colour based on cross-zone severity."""
        if edge.is_cross_zone and edge.purdue_span >= 2:
            return "#f38ba8"   # red — severe cross-zone
        if edge.is_cross_zone:
            return "#fab387"   # orange — cross-zone
        return "#6c7086"       # gray — normal intra-zone
