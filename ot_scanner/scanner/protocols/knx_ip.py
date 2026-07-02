"""
KNXnet/IP Protocol Analyzer  (KNX Association ISO/IEC 14543-3)
Ports: UDP/TCP 3671 (routing multicast 224.0.23.12)

KNXnet/IP tunnels the KNX building-automation bus over IP — lighting, HVAC,
access control, blinds. Widely deployed and frequently internet-exposed with weak
or no authentication.

Frame header (6 bytes, big-endian):
  header_length(1)=0x06 | protocol_version(1)=0x10 | service_type(2) | total_length(2)
"""
import struct
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult

KNX_PORT = 3671

_KNX_SERVICES = {
    0x0201: "SEARCH_REQUEST", 0x0202: "SEARCH_RESPONSE",
    0x0203: "DESCRIPTION_REQUEST", 0x0204: "DESCRIPTION_RESPONSE",
    0x0205: "CONNECT_REQUEST", 0x0206: "CONNECT_RESPONSE",
    0x0207: "CONNECTIONSTATE_REQUEST", 0x0208: "CONNECTIONSTATE_RESPONSE",
    0x0209: "DISCONNECT_REQUEST", 0x020A: "DISCONNECT_RESPONSE",
    0x0310: "DEVICE_CONFIGURATION_REQUEST", 0x0311: "DEVICE_CONFIGURATION_ACK",
    0x0420: "TUNNELLING_REQUEST", 0x0421: "TUNNELLING_ACK",
    0x0530: "ROUTING_INDICATION", 0x0531: "ROUTING_LOST_MESSAGE",
    0x0532: "ROUTING_BUSY",
}


class KNXnetIPAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto not in ("UDP", "TCP") or len(payload) < 6:
            return False
        if KNX_PORT in (sport, dport):
            return True
        return payload[0] == 0x06 and payload[1] == 0x10

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        if payload[0] != 0x06 or payload[1] != 0x10:      # header length + KNXnet/IP v1.0
            return None
        service, total_len = struct.unpack_from(">HH", payload, 2)
        if service not in _KNX_SERVICES:
            return None

        # The device is the endpoint on the KNX port (router / gateway).
        device_ip = src_ip if sport == KNX_PORT else dst_ip
        confidence = "high" if total_len == len(payload) else "medium"

        details = {
            "service_type": f"0x{service:04X}",
            "service_name": _KNX_SERVICES[service],
            "total_length": total_len,
            "domain": "building automation (KNX)",
        }
        detection = self._make_detection(
            protocol="KNXnet/IP", port=KNX_PORT, confidence=confidence,
            timestamp=timestamp, transport=proto, **details,
        )
        return [(device_ip, detection)]
