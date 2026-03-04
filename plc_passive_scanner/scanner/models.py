"""
Data models for the PLC Passive Scanner.
Represents discovered industrial devices and their detected protocols.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from datetime import datetime


@dataclass
class ProtocolDetection:
    """A single industrial protocol detected on a device."""
    protocol: str               # e.g., "Modbus/TCP", "S7comm", "EtherNet/IP"
    port: int                   # Transport port where detected
    confidence: str = "medium"  # "high" | "medium" | "low"
    details: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    packet_count: int = 0

    def merge(self, other: "ProtocolDetection") -> None:
        """Merge another detection into this one (update counts and details)."""
        self.packet_count += other.packet_count
        if other.last_seen and (not self.last_seen or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen
        if other.first_seen and (not self.first_seen or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        # Merge details, non-None values from other take precedence
        for k, v in other.details.items():
            if v is not None:
                self.details[k] = v
        # Upgrade confidence if possible
        _order = {"low": 0, "medium": 1, "high": 2}
        if _order.get(other.confidence, 0) > _order.get(self.confidence, 0):
            self.confidence = other.confidence

    def to_dict(self) -> Dict:
        return {
            "protocol": self.protocol,
            "port": self.port,
            "confidence": self.confidence,
            "details": self.details,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "packet_count": self.packet_count,
        }


@dataclass
class PLCDevice:
    """A discovered industrial PLC or related OT device."""
    ip: str

    # L2 identity
    mac: Optional[str] = None
    hostname: Optional[str] = None

    # Vendor / product identification
    vendor: Optional[str] = None
    vendor_confidence: str = "unknown"  # "high" | "medium" | "low" | "unknown"
    plc_make: Optional[str] = None      # e.g., "Siemens"
    plc_model: Optional[str] = None     # e.g., "S7-1500 CPU 1516-3 PN/DP"
    firmware: Optional[str] = None
    hardware_version: Optional[str] = None
    serial_number: Optional[str] = None
    product_code: Optional[str] = None

    # Protocol detections
    protocols: List[ProtocolDetection] = field(default_factory=list)
    open_ports: Set[int] = field(default_factory=set)
    communicating_with: Set[str] = field(default_factory=set)

    # Temporal metadata
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    packet_count: int = 0

    # Classification
    role: str = "unknown"           # "plc" | "hmi" | "engineering_station" | "historian" | "gateway" | "unknown"
    risk_level: str = "unknown"     # "critical" | "high" | "medium" | "low" | "unknown"
    risk_factors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def add_protocol(self, detection: ProtocolDetection) -> None:
        """Add or merge a protocol detection."""
        for existing in self.protocols:
            if existing.protocol == detection.protocol:
                existing.merge(detection)
                return
        self.protocols.append(detection)

    def update_time(self, ts: datetime) -> None:
        """Update first/last seen timestamps."""
        if not self.first_seen or ts < self.first_seen:
            self.first_seen = ts
        if not self.last_seen or ts > self.last_seen:
            self.last_seen = ts

    def get_protocol_names(self) -> List[str]:
        return [p.protocol for p in self.protocols]

    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "vendor_confidence": self.vendor_confidence,
            "plc_make": self.plc_make,
            "plc_model": self.plc_model,
            "firmware": self.firmware,
            "hardware_version": self.hardware_version,
            "serial_number": self.serial_number,
            "product_code": self.product_code,
            "protocols": [p.to_dict() for p in self.protocols],
            "open_ports": sorted(self.open_ports),
            "communicating_with": sorted(self.communicating_with),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "packet_count": self.packet_count,
            "role": self.role,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
            "notes": self.notes,
        }
