"""
HART-IP Protocol Analyzer  (FieldComm Group HART-IP)
Ports: UDP/TCP 5094

HART-IP carries HART field-instrument communication over Ethernet — used by
process-industry transmitters, gateways, and multiplexers (Emerson, Endress+Hauser,
Yokogawa, Honeywell, ...). Detecting it surfaces field instrumentation / I/O
gateways that pure PLC-protocol scanning misses.

Message header (8 bytes, big-endian):
  version(1)=1 | msg_type(1) | msg_id(1) | status(1) | seq_number(2) | byte_count(2)
"""
import struct
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult

HARTIP_PORT = 5094

_MSG_TYPE = {0: "request", 1: "response", 2: "publish", 3: "nak"}
_MSG_ID = {
    0: "session-initiate", 1: "session-close", 2: "keep-alive",
    3: "token-passing-pdu", 4: "direct-pdu", 5: "read-audit-log",
}


class HartIPAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto not in ("TCP", "UDP"):
            return False
        if HARTIP_PORT not in (sport, dport):
            return False
        return len(payload) >= 8

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        version, msg_type, msg_id, status = payload[0], payload[1], payload[2], payload[3]
        seq, byte_count = struct.unpack_from(">HH", payload, 4)

        # Validate the header so we don't false-positive on port reuse.
        if version != 1 or msg_type not in _MSG_TYPE or msg_id not in _MSG_ID:
            return None

        device_ip = dst_ip if dport == HARTIP_PORT else src_ip
        # byte_count may or may not include the 8-byte header, depending on stack.
        confidence = "high" if byte_count in (len(payload), len(payload) - 8) else "medium"

        details = {
            "version": version,
            "message_type": _MSG_TYPE.get(msg_type, str(msg_type)),
            "message_id": _MSG_ID.get(msg_id, str(msg_id)),
            "status": f"0x{status:02X}",
            "sequence_number": seq,
            "byte_count": byte_count,
            "direction": "response" if msg_type == 1 else "request",
            "device_class": "field instrument / HART gateway",
        }
        detection = self._make_detection(
            protocol="HART-IP", port=HARTIP_PORT, confidence=confidence,
            timestamp=timestamp, transport=proto, **details,
        )
        return [(device_ip, detection)]
