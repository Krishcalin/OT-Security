"""
Base class for RTU/FRTU protocol analyzers.

Key difference vs. PLC scanner base: analyzers here are *stateful* —
they accumulate session state across multiple packets so that the
vulnerability engine can detect multi-packet patterns (e.g. a control
command that lacks a preceding authentication challenge).
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ..models import ProtocolDetection

# (device_ip, ProtocolDetection)
AnalysisResult = List[Tuple[str, ProtocolDetection]]


class BaseProtocolAnalyzer(ABC):

    @abstractmethod
    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        ...

    @abstractmethod
    def analyze(
        self,
        src_ip: str, dst_ip: str,
        sport: int, dport: int,
        proto: str, payload: bytes,
        timestamp: datetime,
    ) -> Optional[AnalysisResult]:
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
    """
    Base for Layer-2 analyzers (GOOSE, Sampled Values) that work on
    raw Ethernet frames rather than TCP/UDP payloads.
    """

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
