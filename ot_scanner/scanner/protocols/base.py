"""
Base classes for all industrial protocol analyzers.

Two base types:
  BaseProtocolAnalyzer — IP-layer (TCP/UDP) analyzers
  BaseL2Analyzer       — Ethernet-layer (GOOSE, SV, PROFINET) analyzers

Both support stateful session tracking via get_sessions().
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ..models import ProtocolDetection

# (device_ip, ProtocolDetection)
AnalysisResult = List[Tuple[str, ProtocolDetection]]


class BaseProtocolAnalyzer(ABC):
    """Abstract base for IP-transport protocol analyzers."""

    @abstractmethod
    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        """Return True if this analyzer should attempt to parse the packet."""
        ...

    @abstractmethod
    def analyze(
        self,
        src_ip: str, dst_ip: str,
        sport: int, dport: int,
        proto: str, payload: bytes,
        timestamp: datetime,
    ) -> Optional[AnalysisResult]:
        """
        Parse payload and return a list of (ip, ProtocolDetection) pairs.
        Return None or [] if the packet does not match.
        """
        ...

    def get_sessions(self) -> Dict:
        """Return session state dict (override in stateful analyzers)."""
        return {}

    @staticmethod
    def _make_detection(
        protocol: str, port: int, confidence: str,
        timestamp: datetime, transport: str = "TCP", **details,
    ) -> ProtocolDetection:
        return ProtocolDetection(
            protocol=protocol,
            port=port,
            confidence=confidence,
            transport=transport,
            details={k: v for k, v in details.items() if v is not None},
            first_seen=timestamp,
            last_seen=timestamp,
            packet_count=1,
        )


class BaseL2Analyzer(ABC):
    """Base for Layer-2 analyzers (GOOSE, Sampled Values, PROFINET)."""

    @abstractmethod
    def can_analyze_frame(self, eth_type: int, payload: bytes) -> bool:
        ...

    @abstractmethod
    def analyze_frame(
        self,
        src_mac: str, dst_mac: str,
        eth_type: int, payload: bytes,
        timestamp: datetime,
    ) -> Optional[dict]:
        """Return enriched state dict or None."""
        ...

    def get_sessions(self) -> Dict:
        return {}
