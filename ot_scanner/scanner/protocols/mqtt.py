"""
MQTT Protocol Analyzer  (OASIS Standard / ISO 20922)
Ports:  TCP 1883  (plaintext MQTT)
        TCP 8883  (MQTT over TLS)

MQTT (Message Queuing Telemetry Transport) is a lightweight publish/subscribe
messaging protocol widely adopted in IIoT and OT environments:
  HiveMQ             (Enterprise MQTT broker)
  Eclipse Mosquitto   (Open-source broker)
  EMQX               (Scalable MQTT platform)
  AWS IoT Core       (MQTT endpoint)
  Azure IoT Hub      (MQTT endpoint)
  Google Cloud IoT   (MQTT bridge)
  Sparkplug B        (MQTT for OT — Ignition, Inductive Automation)
  Unified Namespace  (UNS architecture — MQTT as OT data backbone)

MQTT is increasingly used as the backbone for Unified Namespace (UNS)
architectures in manufacturing, connecting PLCs, SCADA, MES, and ERP
systems via hierarchical topic structures like:
  enterprise/site/area/line/cell/device/telemetry

MQTT Fixed Header (all packet types):
  Byte 0:
    [7:4]  Packet Type  (1=CONNECT, 2=CONNACK, 3=PUBLISH, ...)
    [3:0]  Flags        (type-specific; for PUBLISH: DUP, QoS, RETAIN)
  Bytes 1..4:
    Remaining Length    (variable-length encoding, 1-4 bytes)

CONNECT packet (type 1):
  Variable Header:
    Protocol Name     — UTF-8 prefixed: "MQTT" (v3.1.1/5.0) or "MQIsdp" (v3.1)
    Protocol Level    — 4 (v3.1.1), 5 (v5.0), 3 (v3.1)
    Connect Flags     — username, password, will, clean session
    Keep Alive        — uint16 BE seconds
  Payload:
    Client Identifier — UTF-8 prefixed string (may contain device IDs)
    [Will Topic]      — if will flag set
    [Will Message]    — if will flag set
    [Username]        — if username flag set
    [Password]        — if password flag set

Security concerns:
  - Port 1883 = unencrypted (no TLS) — credentials and data in cleartext
  - CONNECT without username flag = no authentication
  - CONNECT without password flag = username-only auth (weak)
  - Anonymous access to OT topics = critical vulnerability
"""
import struct
from datetime import datetime
from typing import Dict, Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

MQTT_PORT     = 1883
MQTT_TLS_PORT = 8883

# MQTT Packet Types (top 4 bits of byte 0)
PKT_CONNECT     = 1
PKT_CONNACK     = 2
PKT_PUBLISH     = 3
PKT_PUBACK      = 4
PKT_PUBREC      = 5
PKT_PUBREL      = 6
PKT_PUBCOMP     = 7
PKT_SUBSCRIBE   = 8
PKT_SUBACK      = 9
PKT_UNSUBSCRIBE = 10
PKT_UNSUBACK    = 11
PKT_PINGREQ     = 12
PKT_PINGRESP    = 13
PKT_DISCONNECT  = 14
PKT_AUTH        = 15   # MQTT 5.0 only

PACKET_TYPE_NAMES: Dict[int, str] = {
    1:  "CONNECT",
    2:  "CONNACK",
    3:  "PUBLISH",
    4:  "PUBACK",
    5:  "PUBREC",
    6:  "PUBREL",
    7:  "PUBCOMP",
    8:  "SUBSCRIBE",
    9:  "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}

# MQTT Protocol Level values
MQTT_V31   = 3    # "MQIsdp"
MQTT_V311  = 4    # "MQTT" v3.1.1
MQTT_V50   = 5    # "MQTT" v5.0

PROTOCOL_VERSION_NAMES: Dict[int, str] = {
    3: "MQTT 3.1",
    4: "MQTT 3.1.1",
    5: "MQTT 5.0",
}

# CONNECT flags bitmask
FLAG_USERNAME     = 0x80
FLAG_PASSWORD     = 0x40
FLAG_WILL_RETAIN  = 0x20
FLAG_WILL_QOS     = 0x18   # 2 bits
FLAG_WILL_FLAG    = 0x04
FLAG_CLEAN_SESSION = 0x02  # Clean Session (v3.1.1) / Clean Start (v5.0)

# CONNACK return codes (v3.1.1)
CONNACK_CODES_V311: Dict[int, str] = {
    0: "Connection Accepted",
    1: "Unacceptable Protocol Version",
    2: "Identifier Rejected",
    3: "Server Unavailable",
    4: "Bad Username or Password",
    5: "Not Authorized",
}

# CONNACK reason codes (v5.0, partial)
CONNACK_CODES_V50: Dict[int, str] = {
    0x00: "Success",
    0x80: "Unspecified Error",
    0x81: "Malformed Packet",
    0x82: "Protocol Error",
    0x83: "Implementation Specific Error",
    0x84: "Unsupported Protocol Version",
    0x85: "Client Identifier Not Valid",
    0x86: "Bad User Name or Password",
    0x87: "Not Authorized",
    0x88: "Server Unavailable",
    0x89: "Server Busy",
    0x8A: "Banned",
    0x8C: "Bad Authentication Method",
    0x90: "Topic Name Invalid",
    0x95: "Packet Too Large",
    0x97: "Quota Exceeded",
    0x99: "Payload Format Invalid",
    0x9A: "Retain Not Supported",
    0x9B: "QoS Not Supported",
    0x9C: "Use Another Server",
    0x9D: "Server Moved",
    0x9F: "Connection Rate Exceeded",
}

# Minimum fixed header is 2 bytes (type+flags + at least 1 byte remaining length)
MQTT_MIN_SIZE = 2


class MQTTAnalyzer(BaseProtocolAnalyzer):
    """
    Passive analyzer for MQTT protocol traffic.

    Detects MQTT brokers and clients by parsing CONNECT, CONNACK, PUBLISH,
    SUBSCRIBE, and control packets. Extracts protocol version, client IDs,
    authentication flags, topic names, and flags unencrypted or
    unauthenticated connections as potential vulnerabilities.
    """

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport not in (MQTT_PORT, MQTT_TLS_PORT) and \
           dport not in (MQTT_PORT, MQTT_TLS_PORT):
            return False
        return len(payload) >= MQTT_MIN_SIZE

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        hdr = self._parse_fixed_header(payload)
        if hdr is None:
            return None

        pkt_type, flags, remaining_len, var_start = hdr

        # Broker (server) is the one listening on the MQTT port
        is_broker_src = sport in (MQTT_PORT, MQTT_TLS_PORT)
        device_ip = dst_ip if dport in (MQTT_PORT, MQTT_TLS_PORT) else src_ip
        port_used = sport if is_broker_src else dport

        details: dict = {
            "packet_type":  PACKET_TYPE_NAMES.get(pkt_type, f"Type {pkt_type}"),
        }

        confidence = "low"

        # ── CONNECT (client -> broker) ──
        if pkt_type == PKT_CONNECT:
            connect_info = self._parse_connect(payload, var_start, remaining_len)
            if connect_info:
                details.update(connect_info)
                confidence = "high"

                # Flag authentication concerns
                if not connect_info.get("has_username"):
                    details["no_authentication"] = True
                elif not connect_info.get("has_password"):
                    details["username_only_auth"] = True

        # ── CONNACK (broker -> client) ──
        elif pkt_type == PKT_CONNACK:
            connack_info = self._parse_connack(payload, var_start)
            if connack_info:
                details.update(connack_info)
                confidence = "high"

        # ── PUBLISH ──
        elif pkt_type == PKT_PUBLISH:
            pub_info = self._parse_publish(payload, var_start, flags)
            if pub_info:
                details.update(pub_info)
                confidence = "medium"

        # ── SUBSCRIBE / UNSUBSCRIBE ──
        elif pkt_type in (PKT_SUBSCRIBE, PKT_UNSUBSCRIBE):
            sub_info = self._parse_subscribe(payload, var_start)
            if sub_info:
                details.update(sub_info)
                confidence = "medium"

        # ── PINGREQ / PINGRESP — confirms active connection ──
        elif pkt_type in (PKT_PINGREQ, PKT_PINGRESP):
            confidence = "medium"

        # ── DISCONNECT ──
        elif pkt_type == PKT_DISCONNECT:
            confidence = "medium"

        # Flag TLS status
        if port_used == MQTT_TLS_PORT:
            details["tls_protected"] = True
        elif port_used == MQTT_PORT:
            details["unencrypted"] = True

        detection = self._make_detection(
            protocol="MQTT",
            port=port_used,
            confidence=confidence,
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_fixed_header(self, payload: bytes):
        """
        Parse MQTT fixed header.
        Returns (packet_type, flags, remaining_length, var_header_offset) or None.
        """
        if len(payload) < MQTT_MIN_SIZE:
            return None

        byte0 = payload[0]
        pkt_type = (byte0 >> 4) & 0x0F
        flags    = byte0 & 0x0F

        # Validate packet type range
        if pkt_type < 1 or pkt_type > 15:
            return None

        # Decode variable-length Remaining Length field (1-4 bytes)
        multiplier = 1
        remaining_len = 0
        offset = 1
        for _ in range(4):
            if offset >= len(payload):
                return None
            encoded_byte = payload[offset]
            remaining_len += (encoded_byte & 0x7F) * multiplier
            offset += 1
            if not (encoded_byte & 0x80):
                break
            multiplier *= 128
        else:
            # More than 4 continuation bytes — malformed
            return None

        # Sanity check: remaining length should not be absurdly large
        if remaining_len > 0x10000000:   # 256 MB
            return None

        return pkt_type, flags, remaining_len, offset

    def _parse_connect(self, payload: bytes, offset: int, remaining_len: int) -> Optional[dict]:
        """
        Parse MQTT CONNECT packet variable header and payload.

        Variable Header:
          Protocol Name (UTF-8 prefixed) + Protocol Level (1 byte) +
          Connect Flags (1 byte) + Keep Alive (2 bytes BE)
        Payload:
          Client ID (UTF-8 prefixed) + [Will Topic] + [Will Message] +
          [Username] + [Password]
        """
        result: dict = {}
        end = offset + remaining_len
        if end > len(payload):
            end = len(payload)

        # Protocol Name (length-prefixed UTF-8 string)
        proto_name, offset = self._read_utf8_string(payload, offset, end)
        if proto_name is None:
            return None

        result["protocol_name"] = proto_name
        if proto_name not in ("MQTT", "MQIsdp"):
            return None   # Not a valid MQTT CONNECT

        # Protocol Level
        if offset >= end:
            return result
        proto_level = payload[offset]
        offset += 1
        result["protocol_version"] = PROTOCOL_VERSION_NAMES.get(
            proto_level, f"Level {proto_level}"
        )

        # Connect Flags
        if offset >= end:
            return result
        connect_flags = payload[offset]
        offset += 1

        has_username = bool(connect_flags & FLAG_USERNAME)
        has_password = bool(connect_flags & FLAG_PASSWORD)
        has_will     = bool(connect_flags & FLAG_WILL_FLAG)
        will_qos     = (connect_flags & FLAG_WILL_QOS) >> 3
        will_retain  = bool(connect_flags & FLAG_WILL_RETAIN)
        clean_session = bool(connect_flags & FLAG_CLEAN_SESSION)

        result["has_username"]   = has_username
        result["has_password"]   = has_password
        result["has_will"]       = has_will
        result["clean_session"]  = clean_session
        if has_will:
            result["will_qos"]    = will_qos
            result["will_retain"] = will_retain

        # Keep Alive
        if offset + 2 > end:
            return result
        try:
            keep_alive = struct.unpack_from(">H", payload, offset)[0]
        except struct.error:
            return result
        offset += 2
        result["keep_alive_seconds"] = keep_alive

        # MQTT 5.0 Properties (skip for now — variable length)
        if proto_level == MQTT_V50:
            prop_len, offset = self._decode_variable_int(payload, offset, end)
            if prop_len is not None:
                offset += prop_len   # skip properties block

        # ── Payload ──

        # Client ID
        client_id, offset = self._read_utf8_string(payload, offset, end)
        if client_id is not None:
            result["client_id"] = client_id

        # Will Topic + Will Message (skip)
        if has_will:
            _, offset = self._read_utf8_string(payload, offset, end)   # will topic
            # Will payload (binary, length-prefixed)
            if offset + 2 <= end:
                try:
                    will_msg_len = struct.unpack_from(">H", payload, offset)[0]
                except struct.error:
                    return result
                offset += 2 + will_msg_len

        # Username
        if has_username:
            username, offset = self._read_utf8_string(payload, offset, end)
            if username is not None:
                # Do not store the actual username — just note presence
                result["username_present"] = True

        # Password — just note presence (do not log)
        if has_password:
            result["password_present"] = True

        return result

    def _parse_connack(self, payload: bytes, offset: int) -> Optional[dict]:
        """
        Parse MQTT CONNACK packet.

        v3.1.1: Session Present (1 byte) + Return Code (1 byte)
        v5.0:   Session Present (1 byte) + Reason Code (1 byte) + Properties
        """
        if offset + 2 > len(payload):
            return None

        session_present = payload[offset] & 0x01
        return_code     = payload[offset + 1]

        result: dict = {
            "session_present": bool(session_present),
        }

        # Try v3.1.1 codes first (0-5), then v5.0 range
        if return_code <= 5:
            result["return_code"] = return_code
            result["return_code_name"] = CONNACK_CODES_V311.get(
                return_code, f"Code {return_code}"
            )
        else:
            result["reason_code"] = f"0x{return_code:02X}"
            result["reason_code_name"] = CONNACK_CODES_V50.get(
                return_code, f"Code 0x{return_code:02X}"
            )

        return result

    def _parse_publish(self, payload: bytes, offset: int, flags: int) -> Optional[dict]:
        """
        Parse MQTT PUBLISH packet to extract topic name.

        Flags: DUP(bit3) QoS(bit2-1) RETAIN(bit0)
        Variable Header: Topic Name (UTF-8) + [Packet ID if QoS>0]
        """
        end = len(payload)
        result: dict = {}

        dup    = bool(flags & 0x08)
        qos    = (flags >> 1) & 0x03
        retain = bool(flags & 0x01)

        result["qos"]    = qos
        result["retain"] = retain
        if dup:
            result["dup"] = True

        # Topic Name (UTF-8 prefixed)
        topic, offset = self._read_utf8_string(payload, offset, end)
        if topic is not None:
            result["topic"] = topic

        return result if result else None

    def _parse_subscribe(self, payload: bytes, offset: int) -> Optional[dict]:
        """
        Parse MQTT SUBSCRIBE packet to extract topic filters.

        Variable Header: Packet ID (2 bytes)
        Payload: list of (Topic Filter + QoS byte)
        """
        end = len(payload)
        if offset + 2 > end:
            return None

        # Packet ID
        offset += 2

        topics = []
        while offset < end and len(topics) < 10:   # cap at 10 for safety
            topic, offset = self._read_utf8_string(payload, offset, end)
            if topic is None:
                break
            topics.append(topic)
            # QoS byte follows each topic filter
            if offset < end:
                offset += 1

        if not topics:
            return None

        return {"subscribed_topics": topics}

    # ── utility methods ──

    def _read_utf8_string(self, payload: bytes, offset: int, end: int):
        """
        Read an MQTT UTF-8 prefixed string.
        Returns (string, new_offset) or (None, offset) on failure.
        """
        if offset + 2 > end:
            return None, offset

        try:
            str_len = struct.unpack_from(">H", payload, offset)[0]
        except struct.error:
            return None, offset
        offset += 2

        if str_len == 0:
            return "", offset

        if offset + str_len > end:
            return None, offset

        try:
            value = payload[offset: offset + str_len].decode("utf-8", errors="replace")
        except Exception:
            return None, offset

        return value, offset + str_len

    def _decode_variable_int(self, payload: bytes, offset: int, end: int):
        """
        Decode MQTT variable-length integer (used in v5.0 properties).
        Returns (value, new_offset) or (None, offset) on failure.
        """
        multiplier = 1
        value = 0
        for _ in range(4):
            if offset >= end:
                return None, offset
            encoded_byte = payload[offset]
            value += (encoded_byte & 0x7F) * multiplier
            offset += 1
            if not (encoded_byte & 0x80):
                return value, offset
            multiplier *= 128
        return None, offset
