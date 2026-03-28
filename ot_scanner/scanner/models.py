"""
Unified data models for the OT Passive Scanner v2.0.

Merges PLCDevice + RTUDevice into a single OTDevice model that supports:
  - PLC identification (vendor, model, firmware, serial)
  - RTU/FRTU/IED classification and vulnerability findings
  - Protocol-level addressing (DNP3, IEC-104, GOOSE, etc.)
  - Stateful session tracking for vulnerability detection
  - Communication flow tracking for topology mapping
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from datetime import datetime


# ──────────────────────────────────────────────────── Protocol Detection ──

@dataclass
class ProtocolDetection:
    """A detected industrial protocol on a device."""
    protocol: str                       # e.g. "Modbus/TCP", "S7comm", "OPC-UA"
    port: int                           # Transport port (0 for L2 protocols)
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


# ──────────────────────────────────────────────────── Vulnerability ──

@dataclass
class VulnerabilityFinding:
    """A security vulnerability or misconfiguration detected from PCAP evidence."""
    vuln_id: str                        # "RTU-DNP3-001", "OT-GEN-001"
    title: str
    severity: str                       # critical | high | medium | low | info
    category: str                       # authentication | encryption | command-security
                                        # | misconfiguration | protocol | availability
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
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


# ──────────────────────────────────────────────── Communication Flow ──

@dataclass
class CommFlow:
    """A directional communication flow between two devices."""
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
    transport: str = "TCP"
    packet_count: int = 0
    byte_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            "src_ip":       self.src_ip,
            "dst_ip":       self.dst_ip,
            "protocol":     self.protocol,
            "port":         self.port,
            "transport":    self.transport,
            "packet_count": self.packet_count,
            "byte_count":   self.byte_count,
            "first_seen":   self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":    self.last_seen.isoformat()  if self.last_seen  else None,
        }


# ────────────────────────────────────────────── Network Topology ──

@dataclass
class NetworkZone:
    """
    A network zone inferred from observed IP subnets and device roles.
    Maps to the Purdue / IEC 62443 reference architecture.

    Purdue Levels:
      0 — Process: sensors, actuators, safety systems (field I/O)
      1 — Basic Control: PLCs, RTUs, DCS controllers
      2 — Area Supervisory: HMI, SCADA servers, engineering workstations
      3 — Site Operations: historians, OPC-UA aggregation, MES
      3.5 — DMZ: data diodes, jump servers, patch management
      4 — Enterprise IT: ERP, email, business apps
      5 — Internet / Cloud: remote access, cloud SCADA
    """
    zone_id: str                            # "zone_10.1.1.0/24"
    subnet: str                             # "10.1.1.0/24"
    subnet_mask: int = 24                   # CIDR prefix length
    purdue_level: int = -1                  # 0-5, -1 = unknown
    purdue_label: str = "Unknown"           # "Basic Control", "Area Supervisory", etc.
    device_ips: Set[str] = field(default_factory=set)
    device_count: int = 0
    dominant_role: str = "unknown"          # most common role in this zone
    protocols_seen: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "zone_id":        self.zone_id,
            "subnet":         self.subnet,
            "subnet_mask":    self.subnet_mask,
            "purdue_level":   self.purdue_level,
            "purdue_label":   self.purdue_label,
            "device_ips":     sorted(self.device_ips),
            "device_count":   self.device_count,
            "dominant_role":  self.dominant_role,
            "protocols_seen": sorted(self.protocols_seen),
            "notes":          self.notes,
        }


@dataclass
class ZoneViolation:
    """
    A detected cross-zone communication that violates Purdue model segmentation.
    E.g., a Level 0 field device talking directly to a Level 3 historian.
    """
    violation_id: str                       # "ZV-001"
    severity: str                           # critical | high | medium | low
    title: str
    description: str
    src_ip: str
    src_zone: str                           # zone_id
    src_purdue: int
    dst_ip: str
    dst_zone: str
    dst_purdue: int
    protocol: str
    packet_count: int = 0
    remediation: str = ""

    def to_dict(self) -> Dict:
        return {
            "violation_id":  self.violation_id,
            "severity":      self.severity,
            "title":         self.title,
            "description":   self.description,
            "src_ip":        self.src_ip,
            "src_zone":      self.src_zone,
            "src_purdue":    self.src_purdue,
            "dst_ip":        self.dst_ip,
            "dst_zone":      self.dst_zone,
            "dst_purdue":    self.dst_purdue,
            "protocol":      self.protocol,
            "packet_count":  self.packet_count,
            "remediation":   self.remediation,
        }


@dataclass
class CVEEntry:
    """
    A known ICS/SCADA CVE from the local vulnerability database.
    Mapped to vendor + product + firmware version range.
    """
    cve_id: str                             # "CVE-2019-13945"
    vendor: str                             # "Siemens"
    product_pattern: str                    # regex or substring matching model
    affected_versions: str                  # version range: "<4.5", ">=2.0,<3.1"
    severity: str                           # critical | high | medium | low
    cvss_score: float = 0.0                 # CVSS v3 base score
    title: str = ""
    description: str = ""
    has_public_exploit: bool = False         # known exploit in the wild
    ics_cert_advisory: str = ""             # "ICSA-19-344-02"
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "cve_id":              self.cve_id,
            "vendor":              self.vendor,
            "product_pattern":     self.product_pattern,
            "affected_versions":   self.affected_versions,
            "severity":            self.severity,
            "cvss_score":          self.cvss_score,
            "title":               self.title,
            "description":         self.description,
            "has_public_exploit":  self.has_public_exploit,
            "ics_cert_advisory":   self.ics_cert_advisory,
            "remediation":         self.remediation,
            "references":          self.references,
        }


@dataclass
class CVEMatch:
    """
    A CVE matched to a discovered device based on vendor + model + firmware.

    Priority classification (Dragos-inspired):
      now   — CVE with known public exploit AND device is network-reachable
      next  — CVE confirmed but no public exploit, or mitigated by network position
      never — Theoretical, not applicable to observed firmware, or false positive
    """
    cve_id: str
    device_ip: str
    priority: str                           # "now" | "next" | "never"
    severity: str                           # from CVE entry
    cvss_score: float = 0.0
    title: str = ""
    description: str = ""
    match_confidence: str = "medium"        # "high" | "medium" | "low"
    match_reason: str = ""                  # why this CVE matched
    has_public_exploit: bool = False
    ics_cert_advisory: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "cve_id":              self.cve_id,
            "device_ip":           self.device_ip,
            "priority":            self.priority,
            "severity":            self.severity,
            "cvss_score":          self.cvss_score,
            "title":               self.title,
            "description":         self.description,
            "match_confidence":    self.match_confidence,
            "match_reason":        self.match_reason,
            "has_public_exploit":  self.has_public_exploit,
            "ics_cert_advisory":   self.ics_cert_advisory,
            "remediation":         self.remediation,
            "references":          self.references,
        }


@dataclass
class ProtocolStats:
    """
    Deep packet inspection statistics for a device's protocol usage.
    Tracks function code distributions, command patterns, and behavior metrics.
    """
    protocol: str                           # "Modbus/TCP", "S7comm", etc.
    total_packets: int = 0
    # Function code / command distribution
    function_codes: Dict[str, int] = field(default_factory=dict)  # "0x03 Read Holding Regs": 142
    # Read vs Write ratio
    read_count: int = 0
    write_count: int = 0
    control_count: int = 0                  # commands that actuate (write coils, operate, etc.)
    diagnostic_count: int = 0               # maintenance / diagnostic commands
    # Behavioral flags
    has_program_upload: bool = False         # PLC program read/download detected
    has_program_download: bool = False       # PLC program write/upload detected
    has_firmware_update: bool = False        # firmware transfer detected
    has_config_change: bool = False          # configuration modification detected
    # Unique addresses / data points
    unique_addresses: Set[str] = field(default_factory=set)  # coil/register/IOA addresses
    unique_data_points: int = 0

    def to_dict(self) -> Dict:
        return {
            "protocol":             self.protocol,
            "total_packets":        self.total_packets,
            "function_codes":       self.function_codes,
            "read_count":           self.read_count,
            "write_count":          self.write_count,
            "control_count":        self.control_count,
            "diagnostic_count":     self.diagnostic_count,
            "has_program_upload":   self.has_program_upload,
            "has_program_download": self.has_program_download,
            "has_firmware_update":  self.has_firmware_update,
            "has_config_change":    self.has_config_change,
            "unique_data_points":   len(self.unique_addresses),
        }


@dataclass
class ITProtocolHit:
    """An IT/enterprise protocol detected on an OT network segment."""
    protocol: str                           # "HTTP", "SSH", "RDP", "SMB", etc.
    port: int
    transport: str = "TCP"
    src_ip: str = ""
    dst_ip: str = ""
    packet_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "protocol":     self.protocol,
            "port":         self.port,
            "transport":    self.transport,
            "src_ip":       self.src_ip,
            "dst_ip":       self.dst_ip,
            "packet_count": self.packet_count,
            "first_seen":   self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":    self.last_seen.isoformat()  if self.last_seen  else None,
            "details":      self.details,
        }


@dataclass
class TopologyEdge:
    """A directed edge in the network topology graph."""
    src_ip: str
    dst_ip: str
    protocols: Set[str] = field(default_factory=set)
    packet_count: int = 0
    byte_count: int = 0
    is_control: bool = False                # carries control commands (SCADA → RTU)
    is_cross_zone: bool = False             # crosses Purdue level boundary
    purdue_span: int = 0                    # abs(src_purdue - dst_purdue)

    def to_dict(self) -> Dict:
        return {
            "src_ip":        self.src_ip,
            "dst_ip":        self.dst_ip,
            "protocols":     sorted(self.protocols),
            "packet_count":  self.packet_count,
            "byte_count":    self.byte_count,
            "is_control":    self.is_control,
            "is_cross_zone": self.is_cross_zone,
            "purdue_span":   self.purdue_span,
        }


# ──────────────────────────────────────────── Session State Types ──

@dataclass
class DNP3SessionState:
    """Tracks per-session DNP3 behaviour for vulnerability analysis."""
    master_ip: str
    outstation_ip: str
    outstation_addr: int = 0
    master_addr: int = 0
    # Secure Authentication tracking
    auth_challenges: int = 0
    auth_replies: int = 0
    auth_aggressive: int = 0
    # Control command tracking
    select_commands: List[Dict] = field(default_factory=list)
    operate_commands: List[Dict] = field(default_factory=list)
    direct_operate: List[Dict] = field(default_factory=list)
    direct_operate_noack: List[Dict] = field(default_factory=list)
    # Maintenance / dangerous commands
    cold_restarts: int = 0
    warm_restarts: int = 0
    init_data: int = 0
    start_app: int = 0
    stop_app: int = 0
    # File transfer
    file_opens: List[Dict] = field(default_factory=list)
    file_closes: int = 0
    file_deletes: int = 0
    file_aborts: int = 0
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
    startdt_count: int = 0
    stopdt_count: int = 0
    single_commands: List[Dict] = field(default_factory=list)
    double_commands: List[Dict] = field(default_factory=list)
    regulating_step: List[Dict] = field(default_factory=list)
    setpoint_commands: List[Dict] = field(default_factory=list)
    bitstring_commands: List[Dict] = field(default_factory=list)
    clock_syncs: int = 0
    general_interrogations: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    packet_count: int = 0


@dataclass
class GOOSEPublisherState:
    """Tracks per-publisher IEC 61850 GOOSE state."""
    src_mac: str
    app_id: int
    goose_id: str = ""
    gcb_ref: str = ""
    dat_set: str = ""
    simulation_seen: bool = False
    min_ttl_ms: int = 999999
    conf_rev_changes: int = 0
    last_conf_rev: Optional[int] = None
    last_st_num: int = 0
    total_packets: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


# ──────────────────────────────────────────────────── OTDevice ──

@dataclass
class OTDevice:
    """
    A discovered OT device — PLCs, RTUs, FRTUs, IEDs, HMIs, gateways, etc.
    Unified model combining PLC and RTU scanner capabilities.
    """
    ip: str

    # L2 identity
    mac: Optional[str] = None
    hostname: Optional[str] = None

    # Vendor / product identification
    vendor: Optional[str] = None
    vendor_confidence: str = "unknown"      # "high" | "medium" | "low" | "unknown"
    make: Optional[str] = None              # e.g. "Siemens", "ABB"
    model: Optional[str] = None             # e.g. "S7-1500 CPU 1516-3 PN/DP"
    firmware: Optional[str] = None
    hardware_version: Optional[str] = None
    serial_number: Optional[str] = None
    product_code: Optional[str] = None

    # Protocol-level addressing
    dnp3_address: Optional[int] = None
    iec104_common_address: Optional[int] = None
    goose_ids: Set[str] = field(default_factory=set)
    logical_nodes: Set[str] = field(default_factory=set)
    master_stations: Set[str] = field(default_factory=set)

    # Protocol detections
    protocols: List[ProtocolDetection] = field(default_factory=list)
    open_ports: Set[int] = field(default_factory=set)
    communicating_with: Set[str] = field(default_factory=set)

    # Temporal
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    packet_count: int = 0

    # Classification
    role: str = "unknown"               # plc | rtu | frtu | ied | relay | hmi
                                        # | engineering_station | historian
                                        # | gateway | master_station | unknown
    device_type: str = "unknown"        # PLC | RTU | FRTU | IED | Relay | Gateway
                                        # | HMI | Engineering Workstation | Unknown

    # Deep packet inspection stats
    protocol_stats: List["ProtocolStats"] = field(default_factory=list)
    it_protocols: List["ITProtocolHit"] = field(default_factory=list)

    # Vulnerability findings
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    cve_matches: List["CVEMatch"] = field(default_factory=list)  # matched CVEs
    risk_level: str = "unknown"         # critical | high | medium | low | unknown
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
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
            "ip":                    self.ip,
            "mac":                   self.mac,
            "hostname":              self.hostname,
            "vendor":                self.vendor,
            "vendor_confidence":     self.vendor_confidence,
            "make":                  self.make,
            "model":                 self.model,
            "firmware":              self.firmware,
            "hardware_version":      self.hardware_version,
            "serial_number":         self.serial_number,
            "product_code":          self.product_code,
            "dnp3_address":          self.dnp3_address,
            "iec104_common_address": self.iec104_common_address,
            "goose_ids":             sorted(self.goose_ids),
            "logical_nodes":         sorted(self.logical_nodes),
            "master_stations":       sorted(self.master_stations),
            "protocols":             [p.to_dict() for p in self.protocols],
            "open_ports":            sorted(self.open_ports),
            "communicating_with":    sorted(self.communicating_with),
            "first_seen":            self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":             self.last_seen.isoformat()  if self.last_seen  else None,
            "packet_count":          self.packet_count,
            "role":                  self.role,
            "device_type":           self.device_type,
            "protocol_stats":        [s.to_dict() for s in self.protocol_stats],
            "it_protocols":          [p.to_dict() for p in self.it_protocols],
            "vulnerabilities":       [v.to_dict() for v in self.vulnerabilities],
            "cve_matches":           [c.to_dict() for c in self.cve_matches],
            "risk_level":            self.risk_level,
            "risk_score":            self.risk_score,
            "risk_factors":          self.risk_factors,
            "notes":                 self.notes,
        }
