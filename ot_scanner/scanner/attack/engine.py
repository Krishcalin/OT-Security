"""
Attack Path Analysis Engine for the OT Passive Scanner.

Builds a directed graph from observed network topology, identifies crown
jewel OT devices (safety systems, critical PLCs) and IT entry points,
discovers multi-hop attack paths via BFS, scores each path by
exploitability, and maps hops to the MITRE ATT&CK for ICS kill chain.

Scoring formula:
  PATH_SCORE = min(100,
    hop_count × 5
    + auth_gaps × 15
    + encryption_gaps × 10
    + purdue_levels_crossed × 8
    + target_value_bonus
    + target_composite_risk × 0.3
    + target_now_cves × 5
  )

Zero external dependencies — uses only Python stdlib.
"""

import logging
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

from ..models import (
    AttackPath,
    CommFlow,
    NetworkZone,
    OTDevice,
    TopologyEdge,
    ZoneViolation,
)

logger = logging.getLogger(__name__)

# Protocols considered unauthenticated by default
_UNAUTH_PROTOCOLS = {
    "Modbus/TCP", "S7comm", "BACnet/IP", "PROFINET RT", "Omron FINS",
    "MELSEC MC Protocol", "EtherNet/IP",
}

# Protocols considered unencrypted
_UNENCRYPTED_PROTOCOLS = {
    "Modbus/TCP", "S7comm", "DNP3", "IEC 60870-5-104", "BACnet/IP",
    "Omron FINS", "MELSEC MC Protocol", "EtherNet/IP", "PROFINET RT",
    "SEL Fast Message", "MQTT",
}

# Target criticality bonus for path scoring
_TARGET_VALUE = {
    "safety_system": 20,
    "process_control": 15,
    "monitoring": 5,
    "support": 2,
    "unknown": 3,
}

# Roles that qualify as crown jewels
_CROWN_JEWEL_ROLES = {"plc", "rtu", "frtu", "ied", "relay", "historian"}

# Max hops to search
_MAX_HOPS = 6


class AttackPathEngine:
    """
    Multi-hop attack path discovery and scoring for OT networks.

    Usage::

        engine = AttackPathEngine(devices, flows, zones, edges, violations)
        paths = engine.analyze()
    """

    def __init__(
        self,
        devices: List[OTDevice],
        flows: List[CommFlow],
        zones: List[NetworkZone],
        edges: List[TopologyEdge],
        violations: Optional[List[ZoneViolation]] = None,
    ) -> None:
        self._devices = devices
        self._flows = flows
        self._zones = zones
        self._edges = edges
        self._violations = violations or []

        self._device_map: Dict[str, OTDevice] = {d.ip: d for d in devices}
        self._ip_to_zone: Dict[str, NetworkZone] = {}
        for z in zones:
            for ip in z.device_ips:
                self._ip_to_zone[ip] = z

        # Edge annotations: (src, dst) -> {protocols, is_control, auth_gap, enc_gap}
        self._edge_info: Dict[Tuple[str, str], Dict] = {}
        for e in edges:
            auth_gap = bool(e.protocols & _UNAUTH_PROTOCOLS)
            enc_gap = bool(e.protocols & _UNENCRYPTED_PROTOCOLS)
            self._edge_info[(e.src_ip, e.dst_ip)] = {
                "protocols": e.protocols,
                "is_control": e.is_control,
                "auth_gap": auth_gap,
                "encryption_gap": enc_gap,
                "purdue_span": e.purdue_span,
            }

        # Build adjacency graph
        self._adj: Dict[str, Set[str]] = defaultdict(set)
        self._build_adjacency_graph()

    # ── public API ───────────────────────────────────────────────────

    def analyze(self) -> List[AttackPath]:
        """Discover and score all attack paths from entry points to crown jewels."""
        crown_jewels = self._identify_crown_jewels()
        entry_points = self._identify_entry_points()

        if not crown_jewels or not entry_points:
            logger.info("Attack paths: %d entry points, %d crown jewels — %s",
                        len(entry_points), len(crown_jewels),
                        "no paths possible" if not crown_jewels or not entry_points else "")
            return []

        all_paths: List[AttackPath] = []

        for entry_ip in entry_points:
            for target_ip in crown_jewels:
                if entry_ip == target_ip:
                    continue
                raw_paths = self._find_paths(entry_ip, target_ip)
                for hop_ips in raw_paths:
                    path = self._build_attack_path(hop_ips)
                    if path:
                        all_paths.append(path)

        # Deduplicate by (entry, target, hop_count)
        seen: Set[Tuple[str, str, int]] = set()
        deduped: List[AttackPath] = []
        for p in all_paths:
            key = (p.entry_ip, p.target_ip, p.hop_count)
            if key not in seen:
                seen.add(key)
                deduped.append(p)

        # Sort by score descending, assign IDs
        deduped.sort(key=lambda p: -p.path_score)
        for idx, path in enumerate(deduped, 1):
            path.path_id = f"AP-{idx:03d}"

        logger.info("Attack paths: %d path(s) from %d entry point(s) to %d crown jewel(s)",
                     len(deduped), len(entry_points), len(crown_jewels))
        return deduped

    # ── Step 1: Build adjacency graph ────────────────────────────────

    def _build_adjacency_graph(self) -> None:
        """Build directed adjacency from topology edges + communicating_with."""
        for e in self._edges:
            self._adj[e.src_ip].add(e.dst_ip)
            self._adj[e.dst_ip].add(e.src_ip)  # bidirectional reachability

        for dev in self._devices:
            for peer in dev.communicating_with:
                self._adj[dev.ip].add(peer)
                self._adj[peer].add(dev.ip)

    # ── Step 2: Identify crown jewels ────────────────────────────────

    def _identify_crown_jewels(self) -> Set[str]:
        """Find high-value target devices."""
        jewels: Set[str] = set()
        for dev in self._devices:
            if dev.device_criticality == "safety_system":
                jewels.add(dev.ip)
            elif (dev.device_criticality == "process_control"
                  and dev.role in _CROWN_JEWEL_ROLES):
                jewels.add(dev.ip)
            elif dev.role == "historian":
                jewels.add(dev.ip)
            elif dev.composite_risk_score >= 70:
                jewels.add(dev.ip)
            elif any(c.is_cisa_kev and c.priority == "now" for c in dev.cve_matches):
                jewels.add(dev.ip)
        return jewels

    # ── Step 3: Identify entry points ────────────────────────────────

    def _identify_entry_points(self) -> Set[str]:
        """Find IT-accessible devices that could be initial compromise points."""
        entries: Set[str] = set()
        for dev in self._devices:
            # Has remote access sessions
            if dev.remote_access_sessions:
                entries.add(dev.ip)
                continue

            # Has IT protocols (remote_access or vpn category)
            for hit in dev.it_protocols:
                cat = hit.details.get("category", "")
                if cat in ("remote_access", "vpn"):
                    entries.add(dev.ip)
                    break

            # Jump server, gateway, or engineering station
            if dev.role in ("jump_server", "gateway", "engineering_station"):
                entries.add(dev.ip)
                continue

            # High Purdue device with OT connections
            zone = self._ip_to_zone.get(dev.ip)
            if zone and zone.purdue_level >= 3:
                has_ot_peer = any(
                    self._ip_to_zone.get(p, NetworkZone(zone_id="")).purdue_level <= 2
                    for p in dev.communicating_with
                    if p in self._ip_to_zone
                )
                if has_ot_peer:
                    entries.add(dev.ip)

        return entries

    # ── Step 4: BFS pathfinding ──────────────────────────────────────

    def _find_paths(
        self, entry_ip: str, target_ip: str,
    ) -> List[List[str]]:
        """
        BFS to find shortest paths from entry to target (up to MAX_HOPS).
        Returns list of paths, each a list of IP addresses.
        """
        if entry_ip not in self._adj or target_ip not in self._adj:
            return []

        # BFS with path tracking
        queue: deque = deque([(entry_ip, [entry_ip])])
        visited: Set[str] = {entry_ip}
        found_paths: List[List[str]] = []

        while queue:
            current, path = queue.popleft()

            if len(path) > _MAX_HOPS + 1:
                continue

            if current == target_ip:
                found_paths.append(path)
                continue  # Don't explore further from target

            for neighbor in self._adj.get(current, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return found_paths

    # ── Step 5: Build and score attack path ──────────────────────────

    def _build_attack_path(self, hop_ips: List[str]) -> Optional[AttackPath]:
        """Convert a list of IPs into a scored AttackPath with kill chain."""
        if len(hop_ips) < 2:
            return None

        entry_ip = hop_ips[0]
        target_ip = hop_ips[-1]
        target_dev = self._device_map.get(target_ip)
        if not target_dev:
            return None

        # Build hop details
        hops: List[Dict] = []
        total_auth_gaps = 0
        total_enc_gaps = 0
        total_purdue_span = 0

        for i, ip in enumerate(hop_ips):
            dev = self._device_map.get(ip)
            zone = self._ip_to_zone.get(ip)

            hop_info: Dict = {
                "ip": ip,
                "role": dev.role if dev else "unknown",
                "purdue_level": zone.purdue_level if zone else -1,
                "protocols_to_next": [],
                "auth_gap": False,
                "encryption_gap": False,
            }

            # Edge to next hop
            if i < len(hop_ips) - 1:
                next_ip = hop_ips[i + 1]
                edge = self._edge_info.get((ip, next_ip)) or self._edge_info.get((next_ip, ip))
                if edge:
                    hop_info["protocols_to_next"] = sorted(edge["protocols"])
                    hop_info["auth_gap"] = edge["auth_gap"]
                    hop_info["encryption_gap"] = edge["encryption_gap"]
                    if edge["auth_gap"]:
                        total_auth_gaps += 1
                    if edge["encryption_gap"]:
                        total_enc_gaps += 1
                    total_purdue_span += edge["purdue_span"]

            hops.append(hop_info)

        # Score
        hop_count = len(hop_ips) - 1
        target_value = _TARGET_VALUE.get(target_dev.device_criticality, 3)
        target_risk = target_dev.composite_risk_score
        now_cves = sum(1 for c in target_dev.cve_matches if c.priority == "now")

        raw_score = (
            hop_count * 5
            + total_auth_gaps * 15
            + total_enc_gaps * 10
            + total_purdue_span * 8
            + target_value
            + target_risk * 0.3
            + now_cves * 5
        )
        path_score = min(100.0, round(raw_score, 1))

        # Severity
        if path_score >= 70:
            severity = "critical"
        elif path_score >= 45:
            severity = "high"
        elif path_score >= 20:
            severity = "medium"
        else:
            severity = "low"

        # Kill chain
        kill_chain = self._map_kill_chain(hops, target_dev)

        # Remediation
        remediation = self._generate_remediation(
            hops, total_auth_gaps, total_enc_gaps, target_dev,
        )

        return AttackPath(
            severity=severity,
            entry_ip=entry_ip,
            target_ip=target_ip,
            target_role=target_dev.role,
            target_criticality=target_dev.device_criticality,
            hops=hops,
            hop_count=hop_count,
            purdue_levels_crossed=total_purdue_span,
            auth_gaps=total_auth_gaps,
            encryption_gaps=total_enc_gaps,
            path_score=path_score,
            mitre_kill_chain=kill_chain,
            remediation=remediation,
        )

    # ── Kill chain mapping ───────────────────────────────────────────

    def _map_kill_chain(
        self, hops: List[Dict], target_dev: OTDevice,
    ) -> List[Dict]:
        """Map each hop to a MITRE ATT&CK for ICS technique."""
        chain: List[Dict] = []

        for i, hop in enumerate(hops):
            dev = self._device_map.get(hop["ip"])
            if not dev:
                continue

            if i == 0:
                # Entry point
                has_remote = bool(dev.remote_access_sessions) or any(
                    h.details.get("category") in ("remote_access", "vpn")
                    for h in dev.it_protocols
                )
                if has_remote:
                    chain.append({
                        "technique": "T0886",
                        "tactic": "Initial Access",
                        "description": f"Remote access entry via {dev.ip} ({dev.role})",
                        "hop_ip": dev.ip,
                    })
                else:
                    chain.append({
                        "technique": "T0859",
                        "tactic": "Initial Access",
                        "description": f"Compromised credentials on {dev.ip}",
                        "hop_ip": dev.ip,
                    })

            elif i < len(hops) - 1:
                # Intermediate hop — lateral movement
                if hop.get("auth_gap"):
                    chain.append({
                        "technique": "T0855",
                        "tactic": "Lateral Movement",
                        "description": (
                            f"Unauthenticated protocol traversal via {dev.ip} "
                            f"({', '.join(hop.get('protocols_to_next', []))})"
                        ),
                        "hop_ip": dev.ip,
                    })
                else:
                    chain.append({
                        "technique": "T0859",
                        "tactic": "Lateral Movement",
                        "description": f"Lateral movement through {dev.ip} ({dev.role})",
                        "hop_ip": dev.ip,
                    })

            else:
                # Target — execution / impact
                has_prog = any(
                    ps.has_program_download or ps.has_program_upload
                    for ps in dev.protocol_stats
                )
                has_fw = any(ps.has_firmware_update for ps in dev.protocol_stats)

                if dev.device_criticality == "safety_system":
                    chain.append({
                        "technique": "T0836",
                        "tactic": "Inhibit Response Function",
                        "description": f"Compromise safety system {dev.ip} ({dev.model or dev.role})",
                        "hop_ip": dev.ip,
                    })
                elif has_fw:
                    chain.append({
                        "technique": "T0839",
                        "tactic": "Inhibit Response Function",
                        "description": f"Firmware modification on {dev.ip}",
                        "hop_ip": dev.ip,
                    })
                elif has_prog:
                    chain.append({
                        "technique": "T0843",
                        "tactic": "Execution",
                        "description": f"Program modification on {dev.ip}",
                        "hop_ip": dev.ip,
                    })
                else:
                    chain.append({
                        "technique": "T0855",
                        "tactic": "Execution",
                        "description": f"Unauthorized commands to {dev.ip} ({dev.role})",
                        "hop_ip": dev.ip,
                    })

        return chain

    # ── Remediation generation ───────────────────────────────────────

    @staticmethod
    def _generate_remediation(
        hops: List[Dict],
        auth_gaps: int,
        enc_gaps: int,
        target_dev: OTDevice,
    ) -> List[str]:
        """Generate ordered mitigation steps for the attack path."""
        steps: List[str] = []

        # 1. Segmentation
        purdue_levels = [h.get("purdue_level", -1) for h in hops if h.get("purdue_level", -1) >= 0]
        if len(set(purdue_levels)) > 2:
            steps.append(
                "Deploy firewall rules between Purdue zones to restrict "
                "lateral movement across the attack path"
            )

        # 2. Authentication
        if auth_gaps > 0:
            steps.append(
                f"Enable protocol authentication on {auth_gaps} unauthenticated "
                f"hop(s) — deploy DNP3 Secure Auth, S7comm+, or protocol-specific auth"
            )

        # 3. Encryption
        if enc_gaps > 0:
            steps.append(
                f"Enable encryption on {enc_gaps} cleartext hop(s) — "
                f"deploy TLS for IEC-104, IEC 62351 for GOOSE/MMS, VPN for legacy"
            )

        # 4. Patch CVEs
        now_cves = [c for c in target_dev.cve_matches if c.priority == "now"]
        if now_cves:
            cve_list = ", ".join(c.cve_id for c in now_cves[:3])
            steps.append(
                f"Patch {len(now_cves)} NOW-priority CVE(s) on target device: {cve_list}"
            )

        # 5. Access control
        steps.append(
            "Restrict remote access to jump servers only — "
            "enforce NERC CIP-005-6 R2 interactive remote access controls"
        )

        return steps
