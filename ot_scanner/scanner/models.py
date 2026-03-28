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
    mitre_attack: List[str] = field(default_factory=list)  # MITRE ATT&CK for ICS technique IDs
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
            "mitre_attack": self.mitre_attack,
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
    epss_score: float = 0.0                 # EPSS exploitation probability (0-1)
    is_cisa_kev: bool = False               # CISA Known Exploited Vulnerability
    exploit_maturity: str = "unknown"       # "poc" | "functional" | "high" | "unknown"
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
            "epss_score":          self.epss_score,
            "is_cisa_kev":         self.is_cisa_kev,
            "exploit_maturity":    self.exploit_maturity,
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
    epss_score: float = 0.0                 # EPSS exploitation probability (0-1)
    is_cisa_kev: bool = False               # CISA Known Exploited Vulnerability
    exploit_maturity: str = "unknown"       # "poc" | "functional" | "high" | "unknown"

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
            "epss_score":          self.epss_score,
            "is_cisa_kev":         self.is_cisa_kev,
            "exploit_maturity":    self.exploit_maturity,
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

    # Deep asset profiling (S7comm SZL, CIP, etc.)
    rack: Optional[int] = None                          # PLC rack number (S7comm TSAP)
    slot: Optional[int] = None                          # PLC slot number (S7comm TSAP)
    cpu_info: Optional[str] = None                      # CPU identification string (SZL)
    modules: List[Dict] = field(default_factory=list)   # I/O module inventory
    last_program_event: Optional[str] = None            # "upload" or "download"
    communication_profile: Dict = field(default_factory=dict)  # auto-computed comm summary

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

    # Business context (populated via --enrich or inferred)
    device_criticality: str = "unknown"     # safety_system | process_control
                                            # | monitoring | support | unknown
    asset_owner: Optional[str] = None
    location: Optional[str] = None
    asset_tag: Optional[str] = None

    # Vulnerability findings
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    cve_matches: List["CVEMatch"] = field(default_factory=list)  # matched CVEs
    risk_level: str = "unknown"         # critical | high | medium | low | unknown
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    composite_risk_score: float = 0.0       # Phase 4 weighted composite (0-100)
    risk_score_breakdown: Dict = field(default_factory=dict)  # component scores
    compensating_controls: List[str] = field(default_factory=list)
    threat_alerts: List["ThreatAlert"] = field(default_factory=list)
    remote_access_sessions: List["RemoteAccessSession"] = field(default_factory=list)
    config_drift_alerts: List["ConfigDriftAlert"] = field(default_factory=list)
    attack_paths: List["AttackPath"] = field(default_factory=list)
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
            "rack":                  self.rack,
            "slot":                  self.slot,
            "cpu_info":              self.cpu_info,
            "modules":               self.modules,
            "last_program_event":    self.last_program_event,
            "communication_profile": self.communication_profile,
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
            "device_criticality":    self.device_criticality,
            "asset_owner":           self.asset_owner,
            "location":              self.location,
            "asset_tag":             self.asset_tag,
            "protocol_stats":        [s.to_dict() for s in self.protocol_stats],
            "it_protocols":          [p.to_dict() for p in self.it_protocols],
            "vulnerabilities":       [v.to_dict() for v in self.vulnerabilities],
            "cve_matches":           [c.to_dict() for c in self.cve_matches],
            "risk_level":            self.risk_level,
            "risk_score":            self.risk_score,
            "risk_factors":          self.risk_factors,
            "composite_risk_score":  self.composite_risk_score,
            "risk_score_breakdown":  self.risk_score_breakdown,
            "compensating_controls": self.compensating_controls,
            "threat_alerts":         [a.to_dict() for a in self.threat_alerts],
            "remote_access_sessions": [s.to_dict() for s in self.remote_access_sessions],
            "config_drift_alerts":   [a.to_dict() for a in self.config_drift_alerts],
            "attack_paths":          [p.to_dict() for p in self.attack_paths],
            "notes":                 self.notes,
        }


# ──────────────────────────────────────── Network Policy Rules ──

@dataclass
class PolicyRule:
    """A recommended firewall / network segmentation rule."""
    rule_id: str = ""                       # "PR-001"
    action: str = "allow"                   # "allow" | "deny"
    src_ip: str = ""
    src_subnet: str = ""                    # "10.1.1.0/24"
    dst_ip: str = ""
    dst_subnet: str = ""
    protocol: str = ""                      # "Modbus/TCP", "S7comm", etc.
    port: int = 0
    transport: str = "TCP"                  # "TCP" | "UDP" | "IP"
    src_zone: str = ""
    dst_zone: str = ""
    src_purdue: int = -1
    dst_purdue: int = -1
    direction: str = "inbound"             # "inbound" | "outbound" | "bidirectional"
    priority: int = 1000                    # lower = higher priority
    logging: bool = True
    description: str = ""
    rationale: str = ""
    ics_protocol: str = ""                  # normalized ICS protocol name
    is_control_traffic: bool = False
    compliance_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "rule_id":            self.rule_id,
            "action":             self.action,
            "src_ip":             self.src_ip,
            "src_subnet":         self.src_subnet,
            "dst_ip":             self.dst_ip,
            "dst_subnet":         self.dst_subnet,
            "protocol":           self.protocol,
            "port":               self.port,
            "transport":          self.transport,
            "src_zone":           self.src_zone,
            "dst_zone":           self.dst_zone,
            "src_purdue":         self.src_purdue,
            "dst_purdue":         self.dst_purdue,
            "direction":          self.direction,
            "priority":           self.priority,
            "logging":            self.logging,
            "description":        self.description,
            "rationale":          self.rationale,
            "ics_protocol":       self.ics_protocol,
            "is_control_traffic": self.is_control_traffic,
            "compliance_refs":    self.compliance_refs,
        }


@dataclass
class PolicyRuleSet:
    """A complete set of recommended firewall rules organized by zone."""
    generated_at: str = ""
    pcap_file: str = ""
    total_rules: int = 0
    zone_count: int = 0
    rules: List[PolicyRule] = field(default_factory=list)
    rules_by_zone: Dict[str, List[PolicyRule]] = field(default_factory=dict)
    summary: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "generated_at":  self.generated_at,
            "pcap_file":     self.pcap_file,
            "total_rules":   self.total_rules,
            "zone_count":    self.zone_count,
            "rules":         [r.to_dict() for r in self.rules],
            "rules_by_zone": {
                z: [r.to_dict() for r in rs]
                for z, rs in self.rules_by_zone.items()
            },
            "summary":       self.summary,
        }


# ──────────────────────────────────────────── Threat Alerts ──

@dataclass
class ThreatAlert:
    """A threat detection alert from behavioral analysis or malware signature matching."""
    alert_id: str = ""                          # "TA-001"
    alert_type: str = "anomaly"                 # anomaly | malware_signature | policy_violation | reconnaissance
    severity: str = "medium"                    # critical | high | medium | low | info
    title: str = ""
    description: str = ""
    device_ip: str = ""
    peer_ip: str = ""                           # related peer (if applicable)
    protocol: str = ""
    mitre_technique: str = ""                   # "T0855"
    mitre_tactic: str = ""                      # "Execution", "Lateral Movement", etc.
    evidence: Dict = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    confidence: str = "medium"                  # "high" | "medium" | "low"

    def to_dict(self) -> Dict:
        return {
            "alert_id":         self.alert_id,
            "alert_type":       self.alert_type,
            "severity":         self.severity,
            "title":            self.title,
            "description":      self.description,
            "device_ip":        self.device_ip,
            "peer_ip":          self.peer_ip,
            "protocol":         self.protocol,
            "mitre_technique":  self.mitre_technique,
            "mitre_tactic":     self.mitre_tactic,
            "evidence":         self.evidence,
            "first_seen":       self.first_seen.isoformat() if self.first_seen else None,
            "confidence":       self.confidence,
        }


# ────────────────────────────────────── Remote Access Sessions ──

@dataclass
class RemoteAccessSession:
    """A detected remote access session from the Secure Access Audit."""
    session_id: str = ""                        # "RA-001"
    session_type: str = "unknown"               # rdp | ssh | vnc | vpn | teamviewer | anydesk | telnet | web_remote
    protocol: str = ""                          # "RDP", "SSH", "IKE/IPsec", etc.
    src_ip: str = ""                            # remote/external side
    dst_ip: str = ""                            # OT device side
    port: int = 0
    transport: str = "TCP"
    direction: str = "inbound"                  # inbound | outbound
    duration_seconds: float = 0.0               # last_seen - first_seen
    byte_count: int = 0
    packet_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_encrypted: bool = False                  # SSH, VPN, HTTPS
    is_vpn: bool = False                        # IKE, OpenVPN, PPTP
    compliance_status: str = "review_required"  # compliant | non_compliant | review_required
    compliance_issues: List[str] = field(default_factory=list)
    src_zone: str = ""
    dst_zone: str = ""
    src_purdue: int = -1
    dst_purdue: int = -1

    def to_dict(self) -> Dict:
        return {
            "session_id":        self.session_id,
            "session_type":      self.session_type,
            "protocol":          self.protocol,
            "src_ip":            self.src_ip,
            "dst_ip":            self.dst_ip,
            "port":              self.port,
            "transport":         self.transport,
            "direction":         self.direction,
            "duration_seconds":  self.duration_seconds,
            "byte_count":        self.byte_count,
            "packet_count":      self.packet_count,
            "first_seen":        self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":         self.last_seen.isoformat() if self.last_seen else None,
            "is_encrypted":      self.is_encrypted,
            "is_vpn":            self.is_vpn,
            "compliance_status": self.compliance_status,
            "compliance_issues": self.compliance_issues,
            "src_zone":          self.src_zone,
            "dst_zone":          self.dst_zone,
            "src_purdue":        self.src_purdue,
            "dst_purdue":        self.dst_purdue,
        }


# ──────────────────────────────────── Configuration Snapshots ──

@dataclass
class DeviceConfig:
    """A point-in-time configuration snapshot of an OT device."""
    device_ip: str = ""
    snapshot_id: str = ""                       # "SNAP-20240101T080000-10.1.1.10"
    timestamp: str = ""                         # ISO-8601
    firmware: str = ""
    hardware_version: str = ""
    product_code: str = ""
    serial_number: str = ""
    modules: List[Dict] = field(default_factory=list)
    function_code_profile: Dict[str, Dict[str, int]] = field(default_factory=dict)
    program_state: Dict = field(default_factory=dict)
    protocol_list: List[str] = field(default_factory=list)
    data_point_counts: Dict[str, int] = field(default_factory=dict)
    communication_peers: List[str] = field(default_factory=list)
    master_stations: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    risk_level: str = "unknown"
    composite_risk_score: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "device_ip":              self.device_ip,
            "snapshot_id":            self.snapshot_id,
            "timestamp":              self.timestamp,
            "firmware":               self.firmware,
            "hardware_version":       self.hardware_version,
            "product_code":           self.product_code,
            "serial_number":          self.serial_number,
            "modules":                self.modules,
            "function_code_profile":  self.function_code_profile,
            "program_state":          self.program_state,
            "protocol_list":          self.protocol_list,
            "data_point_counts":      self.data_point_counts,
            "communication_peers":    self.communication_peers,
            "master_stations":        self.master_stations,
            "open_ports":             self.open_ports,
            "risk_level":             self.risk_level,
            "composite_risk_score":   self.composite_risk_score,
        }


@dataclass
class ConfigDriftAlert:
    """An alert generated when device configuration changes between snapshots."""
    alert_id: str = ""                          # "CD-001"
    device_ip: str = ""
    drift_type: str = ""                        # firmware_change | module_change | program_event | function_code_shift | new_protocol | peer_change | risk_escalation
    severity: str = "medium"
    title: str = ""
    description: str = ""
    old_value: str = ""
    new_value: str = ""
    mitre_technique: str = ""
    mitre_tactic: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict:
        return {
            "alert_id":         self.alert_id,
            "device_ip":        self.device_ip,
            "drift_type":       self.drift_type,
            "severity":         self.severity,
            "title":            self.title,
            "description":      self.description,
            "old_value":        self.old_value,
            "new_value":        self.new_value,
            "mitre_technique":  self.mitre_technique,
            "mitre_tactic":     self.mitre_tactic,
            "timestamp":        self.timestamp,
        }


# ──────────────────────────────────────────── Attack Paths ──

@dataclass
class AttackPath:
    """A multi-hop attack path from an IT entry point to a crown jewel OT device."""
    path_id: str = ""                           # "AP-001"
    severity: str = "medium"
    entry_ip: str = ""                          # IT entry point
    target_ip: str = ""                         # crown jewel target
    target_role: str = ""
    target_criticality: str = ""
    hops: List[Dict] = field(default_factory=list)  # [{ip, role, purdue_level, ...}]
    hop_count: int = 0
    purdue_levels_crossed: int = 0
    auth_gaps: int = 0
    encryption_gaps: int = 0
    path_score: float = 0.0                     # 0-100 exploitability
    mitre_kill_chain: List[Dict] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "path_id":               self.path_id,
            "severity":              self.severity,
            "entry_ip":              self.entry_ip,
            "target_ip":             self.target_ip,
            "target_role":           self.target_role,
            "target_criticality":    self.target_criticality,
            "hops":                  self.hops,
            "hop_count":             self.hop_count,
            "purdue_levels_crossed": self.purdue_levels_crossed,
            "auth_gaps":             self.auth_gaps,
            "encryption_gaps":       self.encryption_gaps,
            "path_score":            self.path_score,
            "mitre_kill_chain":      self.mitre_kill_chain,
            "remediation":           self.remediation,
        }
