"""
Secure Access Audit Engine for the OT Passive Scanner.

Detects remote access sessions in PCAP traffic, identifies jump servers /
bastion hosts, and evaluates each session against NERC CIP-005-6 R2
(Interactive Remote Access) compliance requirements.

Detections:
  - Remote desktop sessions (RDP, VNC, TeamViewer, AnyDesk, X11)
  - Secure shell sessions (SSH)
  - VPN tunnels (IPsec/IKE, OpenVPN, PPTP)
  - Unencrypted remote access (Telnet)
  - Jump server / bastion host patterns
  - Compliance classification per session

Zero external dependencies — uses only Python stdlib.
"""

import logging
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from ..models import (
    CommFlow,
    NetworkZone,
    OTDevice,
    RemoteAccessSession,
    TopologyEdge,
)

logger = logging.getLogger(__name__)


# ── Protocol classification ──────────────────────────────────────────────

# Protocol name → session_type mapping
_PROTO_TO_SESSION_TYPE = {
    "RDP":          "rdp",
    "SSH":          "ssh",
    "VNC":          "vnc",
    "VNC-1":        "vnc",
    "Telnet":       "telnet",
    "TeamViewer":   "teamviewer",
    "AnyDesk":      "anydesk",
    "Radmin":       "radmin",
    "X11":          "x11",
    "IKE/IPsec":    "vpn",
    "OpenVPN":      "vpn",
    "PPTP":         "vpn",
}

# Categories that indicate remote access
_REMOTE_CATEGORIES = {"remote_access", "vpn"}

# Encrypted protocols
_ENCRYPTED_PROTOCOLS = {"SSH", "IKE/IPsec", "OpenVPN", "HTTPS", "HTTPS-Alt"}

# VPN protocols
_VPN_PROTOCOLS = {"IKE/IPsec", "OpenVPN", "PPTP"}

# Industrial port set for jump server detection
_INDUSTRIAL_PORTS = {
    102, 502, 702, 1883, 2404, 4840, 4843, 5006, 5007, 5008,
    8883, 9600, 20000, 34962, 34963, 34964, 44818, 47808,
}


class SecureAccessEngine:
    """
    Audits remote access patterns in OT networks for compliance.

    Usage::

        engine = SecureAccessEngine(devices, flows, zones, edges)
        sessions_by_ip = engine.audit()
    """

    def __init__(
        self,
        devices: List[OTDevice],
        flows: List[CommFlow],
        zones: List[NetworkZone],
        edges: List[TopologyEdge],
    ) -> None:
        self._devices = devices
        self._flows = flows
        self._zones = zones
        self._edges = edges

        # Lookups
        self._device_map: Dict[str, OTDevice] = {d.ip: d for d in devices}
        self._ip_to_zone: Dict[str, NetworkZone] = {}
        for z in zones:
            for ip in z.device_ips:
                self._ip_to_zone[ip] = z

        # Flow lookup for byte/packet enrichment
        self._flow_key: Dict[Tuple[str, str, int], CommFlow] = {}
        for f in flows:
            self._flow_key[(f.src_ip, f.dst_ip, f.port)] = f

        # Track identified jump servers
        self._jump_servers: Set[str] = set()

    # ── public API ───────────────────────────────────────────────────

    def audit(self) -> Dict[str, List[RemoteAccessSession]]:
        """
        Run the full secure access audit and return sessions by device IP.
        """
        # 1. Extract raw remote sessions from IT protocol hits
        all_sessions = self._extract_remote_sessions()

        # 2. Identify jump servers
        self._identify_jump_servers()

        # 3. Assess compliance for each session
        self._assess_compliance(all_sessions)

        # 4. Assign sequential IDs
        for idx, session in enumerate(all_sessions, 1):
            session.session_id = f"RA-{idx:03d}"

        # 5. Group by device IP (dst_ip = OT device being accessed)
        by_ip: Dict[str, List[RemoteAccessSession]] = defaultdict(list)
        for s in all_sessions:
            by_ip[s.dst_ip].append(s)

        logger.info(
            "Secure access audit: %d session(s) across %d device(s), "
            "%d jump server(s) identified",
            len(all_sessions), len(by_ip), len(self._jump_servers),
        )
        return dict(by_ip)

    # ── Step 1: Extract remote sessions ──────────────────────────────

    def _extract_remote_sessions(self) -> List[RemoteAccessSession]:
        """Build RemoteAccessSession from IT protocol hits on each device."""
        sessions: List[RemoteAccessSession] = []

        for dev in self._devices:
            for hit in dev.it_protocols:
                cat = hit.details.get("category", "")
                if cat not in _REMOTE_CATEGORIES:
                    continue

                proto = hit.protocol
                session_type = _PROTO_TO_SESSION_TYPE.get(proto, "unknown")
                is_encrypted = proto in _ENCRYPTED_PROTOCOLS
                is_vpn = proto in _VPN_PROTOCOLS

                # Determine direction: if hit.dst_ip == dev.ip → inbound
                if hit.dst_ip == dev.ip:
                    direction = "inbound"
                    src_ip = hit.src_ip
                    dst_ip = dev.ip
                else:
                    direction = "outbound"
                    src_ip = dev.ip
                    dst_ip = hit.dst_ip or hit.src_ip

                # Compute duration
                duration = 0.0
                if hit.first_seen and hit.last_seen:
                    duration = (hit.last_seen - hit.first_seen).total_seconds()

                # Enrich with flow byte/packet data
                flow = self._flow_key.get((src_ip, dst_ip, hit.port))
                byte_count = flow.byte_count if flow else 0
                packet_count = hit.packet_count or (flow.packet_count if flow else 0)

                # Zone enrichment
                src_zone, src_purdue = self._resolve_zone(src_ip)
                dst_zone, dst_purdue = self._resolve_zone(dst_ip)

                sessions.append(RemoteAccessSession(
                    session_type=session_type,
                    protocol=proto,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    port=hit.port,
                    transport=hit.transport,
                    direction=direction,
                    duration_seconds=duration,
                    byte_count=byte_count,
                    packet_count=packet_count,
                    first_seen=hit.first_seen,
                    last_seen=hit.last_seen,
                    is_encrypted=is_encrypted,
                    is_vpn=is_vpn,
                    src_zone=src_zone,
                    dst_zone=dst_zone,
                    src_purdue=src_purdue,
                    dst_purdue=dst_purdue,
                ))

        return sessions

    # ── Step 2: Identify jump servers ────────────────────────────────

    def _identify_jump_servers(self) -> None:
        """
        Flag devices with inbound remote access AND outbound OT connections
        as jump servers / bastion hosts.
        """
        for dev in self._devices:
            # Check for inbound remote access
            has_inbound_remote = any(
                hit.details.get("category") in _REMOTE_CATEGORIES
                and (hit.dst_ip == dev.ip)
                for hit in dev.it_protocols
            )
            if not has_inbound_remote:
                continue

            # Check for outbound connections to industrial ports
            has_outbound_ot = any(
                p in _INDUSTRIAL_PORTS
                for peer_ip in dev.communicating_with
                for p in self._device_map.get(peer_ip, OTDevice(ip="")).open_ports
                if peer_ip != dev.ip
            )
            # Also check if this device connects to OT devices via flows
            if not has_outbound_ot:
                for f in self._flows:
                    if f.src_ip == dev.ip and f.port in _INDUSTRIAL_PORTS:
                        has_outbound_ot = True
                        break

            if has_outbound_ot:
                zone = self._ip_to_zone.get(dev.ip)
                purdue = zone.purdue_level if zone else -1
                # Jump servers are typically in L2+ (DMZ or supervisory)
                if purdue >= 2 or purdue == -1:
                    self._jump_servers.add(dev.ip)
                    if dev.role in ("unknown", ""):
                        dev.role = "jump_server"
                    dev.notes.append(
                        "Identified as jump server / bastion host "
                        "(inbound remote access + outbound OT connections)"
                    )

    # ── Step 3: Assess compliance ────────────────────────────────────

    def _assess_compliance(self, sessions: List[RemoteAccessSession]) -> None:
        """
        Evaluate each session against NERC CIP-005-6 R2 requirements.
        Sets compliance_status and compliance_issues on each session.
        """
        for s in sessions:
            issues: List[str] = []

            # Rule 1: Encrypted transport required
            if not s.is_encrypted:
                issues.append(
                    "Unencrypted remote access — requires encryption "
                    "(NERC CIP-005-6 R2.1)"
                )

            # Rule 2: VPN should terminate in DMZ (L3+), not OT zone (L0-2)
            if s.is_vpn and 0 <= s.dst_purdue <= 2:
                issues.append(
                    f"VPN terminates in OT zone (Purdue L{s.dst_purdue}), "
                    "should terminate in DMZ (NERC CIP-005-6 R2.2)"
                )

            # Rule 3: No direct remote access to L0-1 control zone
            if 0 <= s.dst_purdue <= 1:
                issues.append(
                    f"Direct remote access to control zone "
                    f"(Purdue L{s.dst_purdue}) — must route through "
                    "jump server (NERC CIP-005-6 R2.3)"
                )

            # Rule 4: No remote access to safety systems
            dst_dev = self._device_map.get(s.dst_ip)
            if dst_dev and dst_dev.device_criticality == "safety_system":
                issues.append(
                    "Remote access to safety instrumented system — "
                    "prohibited (IEC 62443-3-3 SR 1.13)"
                )

            # Rule 5: Cross-zone access should use jump server
            if (s.src_purdue >= 3 and s.dst_purdue <= 2
                    and s.src_ip not in self._jump_servers
                    and s.dst_ip not in self._jump_servers):
                issues.append(
                    "Cross-zone remote access without bastion/jump server "
                    "in path (NERC CIP-005-6 R2.4)"
                )

            # Classify
            if not issues:
                s.compliance_status = "compliant"
            elif any("prohibited" in i or "control zone" in i for i in issues):
                s.compliance_status = "non_compliant"
            else:
                s.compliance_status = "non_compliant" if len(issues) >= 2 else "review_required"

            s.compliance_issues = issues

    # ── helpers ───────────────────────────────────────────────────────

    def _resolve_zone(self, ip: str) -> Tuple[str, int]:
        """Return (zone_id, purdue_level) for an IP."""
        zone = self._ip_to_zone.get(ip)
        if zone:
            return zone.zone_id, zone.purdue_level
        return "external", -1
