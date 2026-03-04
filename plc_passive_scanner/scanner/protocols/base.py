"""
Base class for all industrial protocol analyzers.
Each analyzer inspects raw TCP/UDP payloads and emits ProtocolDetection results.
"""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Tuple

from ..models import ProtocolDetection

# Type alias: list of (device_ip, ProtocolDetection) tuples
AnalysisResult = List[Tuple[str, ProtocolDetection]]


class BaseProtocolAnalyzer(ABC):
    """
    Abstract base for protocol analyzers.

    Subclasses implement:
      can_analyze()  – quick pre-filter (port/magic-byte check)
      analyze()      – full parse, returns AnalysisResult
    """

    @abstractmethod
    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        """Return True if this analyzer should attempt to parse the packet."""
        ...

    @abstractmethod
    def analyze(
        self,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        proto: str,
        payload: bytes,
        timestamp: datetime,
    ) -> Optional[AnalysisResult]:
        """
        Parse payload and return a list of (ip, ProtocolDetection) pairs.
        Return None or [] if the packet does not match.
        The IP in each tuple is the *device* (usually the server/controller).
        """
        ...

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _make_detection(
        protocol: str,
        port: int,
        confidence: str,
        timestamp: datetime,
        **details,
    ) -> ProtocolDetection:
        return ProtocolDetection(
            protocol=protocol,
            port=port,
            confidence=confidence,
            details={k: v for k, v in details.items() if v is not None},
            first_seen=timestamp,
            last_seen=timestamp,
            packet_count=1,
        )
