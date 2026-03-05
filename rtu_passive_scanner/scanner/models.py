"""
Data models for the RTU / FRTU Passive Scanner.

Key additions vs. PLC scanner:
  - VulnerabilityFinding  : a specific security issue detected from PCAP evidence
  - DNP3SessionState      : per-session state for SA / command tracking
  - IEC104SessionState    : per-session state for IEC-104 master tracking
  - GOOSEPublisherState   : per-publisher state for IEC 61850 GOOSE
  - RTUDevice             : enriched device model with vuln/role fields
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from datetime import datetime


# ─────────────────────────────────────────────────────────────── Protocol ────

@dataclass
class ProtocolDetection:
    """A detected industrial protocol on a device."""
    protocol: str
    port: int
    confidence: str = "medium"          # "high" | "medium" | "low"
    transport: str = "TCP"              # "TCP" | "UDP" | "Ethernet"
    details: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    packet_count: int = 0

    def merge(self, other: "ProtocolDetection") -> None:
        self.packet_count += other.packet_count
        if other.last_seen and (not self.last_seen or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen
        if other.first_seen and (not self.first_seen or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        for k, v in other.details.items():
            if v is not None:
                self.details[k] = v
        _ord = {"low": 0, "medium": 1, "high": 2}
        if _ord.get(other.confidence, 0) > _ord.get(self.confidence, 0):
            self.confidence = other.confidence

    def to_dict(self) -> Dict:
        return {
            "protocol":     self.protocol,
            "port":         self.port,
            "confidence":   self.confidence,
            "transport":    self.transport,
            "details":      self.details,
            "first_seen":   self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":    self.last_seen.isoformat()  if self.last_seen  else None,
            "packet_count": self.packet_count,
        }


# ──────────────────────────────────────────────────────────── Vulnerability ──

@dataclass
class VulnerabilityFinding:
    """
    A specific security vulnerability or misconfiguration detected from PCAP traffic.

    Severity levels follow ICS-CERT / CVSS guidance:
      critical  – direct path to physical consequence (tripping a breaker, etc.)
      high      – enables significant access or control
      medium    – weakens defence-in-depth
      low       – informational concern
      info      – neutral observation
    """
    vuln_id: str                        # "RTU-DNP3-001"
    title: str                          # Short descriptive title
    severity: str                       # critical | high | medium | low | info
    category: str                       # authentication | encryption | command-security
                                        #   | misconfiguration | protocol | availability
    description: str                    # What was observed
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""              # How to fix
    references: List[str] = field(default_factory=list)   # IEC 62351, NERC CIP, etc.
    first_seen: Optional[datetime] = None
    packet_count: int = 0

    def to_dict(self) -> Dict:
        return {
            "vuln_id":      self.vuln_id,
            "title":        self.title,
            "severity":     self.severity,
            "category":     self.category,
            "description":  self.description,
            "evidence":     self.evidence,
            "remediation":  self.remediation,
            "references":   self.references,
            "first_seen":   self.first_seen.isoformat() if self.first_seen else None,
            "packet_count": self.packet_count,
        }


# ─────────────────────────────────────────────────────── Session State Types ──

@dataclass
class DNP3SessionState:
    """Tracks per-session DNP3 behaviour for vulnerability analysis."""
    master_ip: str
    outstation_ip: str
    outstation_addr: int = 0
    master_addr: int = 0

    # Secure Authentication tracking
    auth_challenges: int = 0           # FC 32 / 0x20 observed
    auth_replies: int = 0              # FC 33 / 0x21 observed
    auth_aggressive: int = 0           # FC 131 / 0x83 (SAv5 aggressive mode)

    # Control command tracking
    select_commands: List[Dict] = field(default_factory=list)       # FC 3
    operate_commands: List[Dict] = field(default_factory=list)      # FC 4
    direct_operate: List[Dict] = field(default_factory=list)        # FC 5 (no SBO!)
    direct_operate_noack: List[Dict] = field(default_factory=list)  # FC 6

    # Maintenance / dangerous commands
    cold_restarts: int = 0             # FC 13
    warm_restarts: int = 0             # FC 14
    init_data: int = 0                 # FC 15
    start_app: int = 0                 # FC 17
    stop_app: int = 0                  # FC 18

    # File transfer (potential config/firmware injection)
    file_opens: List[Dict] = field(default_factory=list)    # FC 25
    file_closes: int = 0               # FC 26
    file_deletes: int = 0              # FC 27
    file_aborts: int = 0               # FC 30

    # Transport
    over_udp: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    packet_count: int = 0


@dataclass
class IEC104SessionState:
    """Tracks per-session IEC 60870-5-104 behaviour."""
    master_ip: str
    rtu_ip: str
    common_address: Optional[int] = None

    # Connection events
    startdt_count: int = 0             # STARTDT act — data transfer started
    stopdt_count: int = 0

    # Control commands (type IDs)
    single_commands: List[Dict] = field(default_factory=list)      # type 45
    double_commands: List[Dict] = field(default_factory=list)      # type 46
    regulating_step: List[Dict] = field(default_factory=list)      # type 47
    setpoint_commands: List[Dict] = field(default_factory=list)    # types 48–50
    bitstring_commands: List[Dict] = field(default_factory=list)   # type 51
    clock_syncs: int = 0               # type 103
    general_interrogations: int = 0    # type 100

    # Timestamps
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    packet_count: int = 0


@dataclass
class GOOSEPublisherState:
    """Tracks per-publisher IEC 61850 GOOSE state."""
    src_mac: str
    app_id: int
    goose_id: str = ""
    gcb_ref: str = ""               # GOOSE Control Block Reference → identifies IED
    dat_set: str = ""               # Dataset name → identifies logical nodes

    # Security indicators
    simulation_seen: bool = False   # simulation bit = TRUE → test mode in live traffic
    min_ttl_ms: int = 999999        # Very low TTL → replay window vulnerability
    conf_rev_changes: int = 0       # Config revision changes → configuration drift
    last_conf_rev: Optional[int] = None

    # State tracking
    last_st_num: int = 0            # State change number
    total_packets: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


# ──────────────────────────────────────────────────────────────── RTUDevice ──

@dataclass
class RTUDevice:
    """
    A discovered RTU, FRTU, IED, or related OT field device.
    """
    ip: str

    # L2
    mac: Optional[str] = None
    hostname: Optional[str] = None

    # Vendor identification
    vendor: Optional[str] = None
    vendor_confidence: str = "unknown"
    rtu_make: Optional[str] = None      # e.g., "ABB", "GE Grid Solutions"
    rtu_model: Optional[str] = None     # e.g., "RTU560", "D20MX"
    firmware: Optional[str] = None
    hardware_version: Optional[str] = None
    serial_number: Optional[str] = None

    # Protocol-level addressing
    dnp3_address: Optional[int] = None          # DNP3 outstation address
    iec104_common_address: Optional[int] = None  # IEC-104 ASDU common address
    goose_ids: Set[str] = field(default_factory=set)  # GOOSE IDs published
    logical_nodes: Set[str] = field(default_factory=set)  # IEC 61850 LN names
    master_stations: Set[str] = field(default_factory=set)  # SCADA master IPs

    # Protocol detections
    protocols: List[ProtocolDetection] = field(default_factory=list)
    open_ports: Set[int] = field(default_factory=set)
    communicating_with: Set[str] = field(default_factory=set)

    # Temporal
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    packet_count: int = 0

    # Classification
    role: str = "unknown"       # "rtu" | "frtu" | "ied" | "master_station"
                                # | "gateway" | "engineering_station" | "unknown"
    device_type: str = "unknown"  # "RTU" | "FRTU" | "IED" | "Relay" | "Gateway"

    # Vulnerability findings
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    risk_level: str = "unknown"   # "critical" | "high" | "medium" | "low" | "unknown"
    risk_score: int = 0
    notes: List[str] = field(default_factory=list)

    # ── convenience methods ──

    def add_protocol(self, det: ProtocolDetection) -> None:
        for existing in self.protocols:
            if existing.protocol == det.protocol:
                existing.merge(det)
                return
        self.protocols.append(det)

    def update_time(self, ts: datetime) -> None:
        if not self.first_seen or ts < self.first_seen:
            self.first_seen = ts
        if not self.last_seen or ts > self.last_seen:
            self.last_seen = ts

    def get_protocol_names(self) -> List[str]:
        return [p.protocol for p in self.protocols]

    def get_vuln_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for v in self.vulnerabilities:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict:
        return {
            "ip":                   self.ip,
            "mac":                  self.mac,
            "hostname":             self.hostname,
            "vendor":               self.vendor,
            "vendor_confidence":    self.vendor_confidence,
            "rtu_make":             self.rtu_make,
            "rtu_model":            self.rtu_model,
            "firmware":             self.firmware,
            "hardware_version":     self.hardware_version,
            "serial_number":        self.serial_number,
            "dnp3_address":         self.dnp3_address,
            "iec104_common_address": self.iec104_common_address,
            "goose_ids":            sorted(self.goose_ids),
            "logical_nodes":        sorted(self.logical_nodes),
            "master_stations":      sorted(self.master_stations),
            "protocols":            [p.to_dict() for p in self.protocols],
            "open_ports":           sorted(self.open_ports),
            "communicating_with":   sorted(self.communicating_with),
            "first_seen":           self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":            self.last_seen.isoformat()  if self.last_seen  else None,
            "packet_count":         self.packet_count,
            "role":                 self.role,
            "device_type":          self.device_type,
            "vulnerabilities":      [v.to_dict() for v in self.vulnerabilities],
            "risk_level":           self.risk_level,
            "risk_score":           self.risk_score,
            "notes":                self.notes,
        }
