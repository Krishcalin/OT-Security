"""
GE-SRTP Protocol Analyzer  (GE Service Request Transport Protocol)
Ports: TCP 18245 (default), 18246

SRTP is GE Intelligent Platforms' proprietary protocol for reading/writing PLC
memory on GE Series 90-30/90-70, VersaMax, RX3i and PACSystems controllers. It is
GE-specific, so detecting it is a strong vendor signal (feeds the fingerprint and
CVE-matching engines). The wire format is a fixed ~56-byte message header; we
validate structurally and attribute the device to GE rather than deep-parsing the
mailbox (undocumented offsets are not invented).
"""
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult

GE_SRTP_PORTS = (18245, 18246)

# First-byte message-type hints seen in SRTP captures (best-effort labels only).
_MTYPE = {0x02: "request/text-buffer", 0x03: "response"}


class GESRTPAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport not in GE_SRTP_PORTS and dport not in GE_SRTP_PORTS:
            return False
        return len(payload) >= 4

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        device_ip = dst_ip if dport in GE_SRTP_PORTS else src_ip
        mtype = payload[0]
        # The port is GE-specific; a full 56-byte header raises confidence.
        confidence = "high" if len(payload) >= 56 else "medium"

        details = {
            "message_type": _MTYPE.get(mtype, f"0x{mtype:02X}"),
            "length": len(payload),
            "inferred_make": "GE Automation",
            "device_class": "GE Series 90 / PACSystems PLC",
        }
        detection = self._make_detection(
            protocol="GE-SRTP", port=18245, confidence=confidence,
            timestamp=timestamp, transport="TCP", **details,
        )
        return [(device_ip, detection)]
