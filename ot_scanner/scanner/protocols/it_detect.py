"""
IT/Enterprise Protocol Detector for OT Network Captures
Ports:  See IT_PORTS map below

Detects common IT/enterprise protocols on OT network segments by port number
and basic header validation.  This is NOT a full IT protocol parser --- it
simply identifies the *presence* of IT protocols to flag IT/OT convergence
risks and Purdue model violations.

The detector does NOT create ProtocolDetection objects (these are reserved for
industrial protocols).  Instead it accumulates ITProtocolHit records that are
later attached to OTDevice.it_protocols.

Why this matters:
  - IT protocols on OT segments indicate poor segmentation (IEC 62443 zone model)
  - Remote-access protocols (RDP, VNC, TeamViewer) on OT are high-risk vectors
  - Database traffic in the control zone may signal improper historian placement
  - File-sharing protocols (SMB, FTP) are common lateral-movement channels
"""
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ITProtocolHit

# ──────────────────────────────────────────── Industrial ports to exclude ──
# Ports already handled by dedicated OT protocol analyzers.
# The IT detector MUST NOT flag these as IT traffic.
INDUSTRIAL_PORTS = frozenset({
    102,     # S7comm / IEC 61850 MMS (ISO-TSAP)
    502,     # Modbus/TCP
    702,     # SEL Fast Message
    1883,    # MQTT (plaintext)
    2222,    # EtherNet/IP implicit (UDP)
    2404,    # IEC 60870-5-104
    4840,    # OPC-UA Binary
    4843,    # OPC-UA TLS
    5006,    # MELSEC MC Protocol
    5007,    # MELSEC MC Protocol
    5008,    # MELSEC MC Protocol
    8883,    # MQTT over TLS
    9600,    # Omron FINS
    20000,   # DNP3
    34962,   # PROFINET RT Class 1 (UDP)
    34963,   # PROFINET RT Class 2 (UDP)
    34964,   # PROFINET RT Class 3 / CBA (TCP)
    44818,   # EtherNet/IP explicit (TCP)
    47808,   # BACnet/IP
})

# ──────────────────────────────────────────── IT Protocol Port Map ──

IT_PORTS: Dict[int, Dict] = {
    # Web
    80:    {"protocol": "HTTP",           "risk": "medium", "category": "web"},
    443:   {"protocol": "HTTPS",          "risk": "low",    "category": "web"},
    8080:  {"protocol": "HTTP-Alt",       "risk": "medium", "category": "web"},
    8443:  {"protocol": "HTTPS-Alt",      "risk": "low",    "category": "web"},
    # Remote access
    22:    {"protocol": "SSH",            "risk": "medium", "category": "remote_access"},
    23:    {"protocol": "Telnet",         "risk": "high",   "category": "remote_access"},
    3389:  {"protocol": "RDP",            "risk": "high",   "category": "remote_access"},
    5900:  {"protocol": "VNC",            "risk": "high",   "category": "remote_access"},
    5901:  {"protocol": "VNC-1",          "risk": "high",   "category": "remote_access"},
    5938:  {"protocol": "TeamViewer",     "risk": "high",   "category": "remote_access"},
    7070:  {"protocol": "AnyDesk",        "risk": "high",   "category": "remote_access"},
    4899:  {"protocol": "Radmin",         "risk": "high",   "category": "remote_access"},
    6000:  {"protocol": "X11",            "risk": "high",   "category": "remote_access"},
    # VPN / Encrypted tunnels
    500:   {"protocol": "IKE/IPsec",      "risk": "medium", "category": "vpn"},
    1194:  {"protocol": "OpenVPN",        "risk": "medium", "category": "vpn"},
    1723:  {"protocol": "PPTP",           "risk": "high",   "category": "vpn"},
    # File sharing
    445:   {"protocol": "SMB",            "risk": "high",   "category": "file_sharing"},
    139:   {"protocol": "NetBIOS-SSN",    "risk": "high",   "category": "file_sharing"},
    21:    {"protocol": "FTP",            "risk": "high",   "category": "file_sharing"},
    69:    {"protocol": "TFTP",           "risk": "high",   "category": "file_sharing"},
    # Network services
    53:    {"protocol": "DNS",            "risk": "low",    "category": "network_service"},
    67:    {"protocol": "DHCP-Server",    "risk": "low",    "category": "network_service"},
    68:    {"protocol": "DHCP-Client",    "risk": "low",    "category": "network_service"},
    123:   {"protocol": "NTP",            "risk": "low",    "category": "network_service"},
    161:   {"protocol": "SNMP",           "risk": "medium", "category": "network_service"},
    162:   {"protocol": "SNMP-Trap",      "risk": "medium", "category": "network_service"},
    514:   {"protocol": "Syslog",         "risk": "low",    "category": "network_service"},
    # Database
    1433:  {"protocol": "MSSQL",          "risk": "high",   "category": "database"},
    3306:  {"protocol": "MySQL",          "risk": "high",   "category": "database"},
    5432:  {"protocol": "PostgreSQL",     "risk": "high",   "category": "database"},
    1521:  {"protocol": "Oracle",         "risk": "high",   "category": "database"},
    6379:  {"protocol": "Redis",          "risk": "high",   "category": "database"},
    # Email
    25:    {"protocol": "SMTP",           "risk": "medium", "category": "email"},
    110:   {"protocol": "POP3",           "risk": "medium", "category": "email"},
    143:   {"protocol": "IMAP",           "risk": "medium", "category": "email"},
    # Messaging
    5672:  {"protocol": "AMQP",           "risk": "low",    "category": "messaging"},
}

# Precompute the set of known IT port numbers for fast lookup
_IT_PORT_SET = frozenset(IT_PORTS.keys())

# HTTP method prefixes for header validation
_HTTP_PREFIXES = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HTTP/", b"HEAD ",
                  b"PATCH ", b"OPTIONS ")

# SMB magic bytes
_SMB1_MAGIC = b"\xFF\x53\x4D\x42"   # \xFFSMB
_SMB2_MAGIC = b"\xFE\x53\x4D\x42"   # \xFESMB

# SSH banner prefix
_SSH_PREFIX = b"SSH-"

# Minimum DNS header size (ID + flags + 4x 16-bit counts = 12 bytes)
_DNS_MIN_SIZE = 12


class ITProtocolDetector(BaseProtocolAnalyzer):
    """
    Lightweight detector for IT/enterprise protocols on OT network segments.

    Does NOT produce ProtocolDetection objects --- instead it accumulates
    ITProtocolHit records keyed by (src_ip, dst_ip, protocol_name, port).
    Retrieve the results via get_it_hits() after packet processing.
    """

    def __init__(self):
        # Key: (src_ip, dst_ip, protocol_name, port) -> ITProtocolHit
        self._hits: Dict[Tuple[str, str, str, int], ITProtocolHit] = {}

    # ── BaseProtocolAnalyzer interface ────────────────────────────────────

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        """Return True if src or dst port is a known IT port."""
        # Exclude ports that are handled by dedicated OT analyzers
        if sport in INDUSTRIAL_PORTS or dport in INDUSTRIAL_PORTS:
            return False
        return sport in _IT_PORT_SET or dport in _IT_PORT_SET

    def analyze(
        self,
        src_ip: str, dst_ip: str,
        sport: int, dport: int,
        proto: str, payload: bytes,
        timestamp: datetime,
    ) -> Optional[AnalysisResult]:
        """
        Record the IT protocol hit.  Returns None because IT protocols are
        NOT modelled as ProtocolDetection (those are reserved for OT).
        """
        # Determine which port matched
        matched_port, info, direction = self._match_port(
            sport, dport, src_ip, dst_ip, payload,
        )
        if matched_port is None or info is None:
            return None

        protocol_name = info["protocol"]
        # Validate header when possible --- reduces false positives
        if not self._validate_header(matched_port, protocol_name, payload):
            return None

        key = (src_ip, dst_ip, protocol_name, matched_port)

        if key in self._hits:
            hit = self._hits[key]
            hit.packet_count += 1
            if hit.last_seen is None or timestamp > hit.last_seen:
                hit.last_seen = timestamp
            if hit.first_seen is None or timestamp < hit.first_seen:
                hit.first_seen = timestamp
        else:
            self._hits[key] = ITProtocolHit(
                protocol=protocol_name,
                port=matched_port,
                transport=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                packet_count=1,
                first_seen=timestamp,
                last_seen=timestamp,
                details={
                    "category":  info["category"],
                    "risk":      info["risk"],
                    "direction": direction,
                },
            )

        # Intentionally return None --- no ProtocolDetection for IT traffic
        return None

    # ── Public query methods ─────────────────────────────────────────────

    def get_it_hits(self) -> List[ITProtocolHit]:
        """Return all accumulated IT protocol hits."""
        return list(self._hits.values())

    def get_device_hits(self, ip: str) -> List[ITProtocolHit]:
        """Return IT hits involving a specific IP (as src or dst)."""
        return [
            hit for hit in self._hits.values()
            if hit.src_ip == ip or hit.dst_ip == ip
        ]

    # ── Internal helpers ─────────────────────────────────────────────────

    def _match_port(
        self,
        sport: int, dport: int,
        src_ip: str, dst_ip: str,
        payload: bytes,
    ) -> Tuple[Optional[int], Optional[Dict], str]:
        """
        Determine which port matched the IT protocol map and infer direction.

        Returns (matched_port, info_dict, direction_str) or (None, None, "").
        Direction semantics:
          "inbound"  — traffic is heading TO the OT device (dport matched)
          "outbound" — traffic is coming FROM the OT device (sport matched)
          "both"     — both ports are known IT ports (pick the lower-numbered / server)
        """
        sport_match = IT_PORTS.get(sport)
        dport_match = IT_PORTS.get(dport)

        if dport_match and sport_match:
            # Both ports are known --- prefer the server (destination) port
            return dport, dport_match, "inbound"
        if dport_match:
            return dport, dport_match, "inbound"
        if sport_match:
            return sport, sport_match, "outbound"
        return None, None, ""

    def _validate_header(self, port: int, protocol: str, payload: bytes) -> bool:
        """
        Optional header validation for select protocols to reduce false positives.
        Returns True if the payload passes (or if no validation is defined).
        """
        if not payload:
            # Port-only match is acceptable when there is no payload (e.g. SYN)
            return True

        if protocol in ("HTTP", "HTTP-Alt"):
            return self._check_http(payload)
        if protocol == "SSH":
            return self._check_ssh(payload)
        if protocol == "SMB":
            return self._check_smb(payload)
        if protocol == "DNS":
            return self._check_dns(payload)

        # All other protocols: accept on port match alone
        return True

    @staticmethod
    def _check_http(payload: bytes) -> bool:
        """Check for HTTP request/response prefix."""
        for prefix in _HTTP_PREFIXES:
            if payload[:len(prefix)] == prefix:
                return True
        # Allow port-only if payload is too short to tell
        return len(payload) < 4

    @staticmethod
    def _check_ssh(payload: bytes) -> bool:
        """Check for SSH version banner."""
        if payload[:len(_SSH_PREFIX)] == _SSH_PREFIX:
            return True
        # Allow port-only if payload is too short
        return len(payload) < 4

    @staticmethod
    def _check_smb(payload: bytes) -> bool:
        """Check for SMB/SMB2 magic bytes (may be preceded by 4-byte NetBIOS header)."""
        # Direct match
        if len(payload) >= 4:
            if payload[:4] == _SMB1_MAGIC or payload[:4] == _SMB2_MAGIC:
                return True
        # After NetBIOS Session Service header (4 bytes)
        if len(payload) >= 8:
            if payload[4:8] == _SMB1_MAGIC or payload[4:8] == _SMB2_MAGIC:
                return True
        # Allow port-only if payload is too short
        return len(payload) < 4

    @staticmethod
    def _check_dns(payload: bytes) -> bool:
        """Check minimum DNS header size."""
        return len(payload) >= _DNS_MIN_SIZE or len(payload) < 4
