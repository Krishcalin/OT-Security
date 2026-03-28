"""
OPC-UA Binary Protocol Analyzer  (IEC 62541 / OPC Foundation)
Ports:  TCP 4840  (default OPC-UA Binary)
        TCP 4843  (OPC-UA over TLS)

OPC Unified Architecture is the cross-platform successor to OPC Classic (COM/DCOM).
It is vendor-agnostic and used by virtually every modern OT vendor:
  Siemens            (SIMATIC S7-1500, WinCC OA, TIA Portal)
  Rockwell Automation (FactoryTalk Linx Gateway)
  Beckhoff           (TwinCAT 3 OPC-UA Server)
  B&R Automation     (Automation Studio)
  Unified Automation (SDK & demo servers)
  Schneider Electric (EcoStruxure)
  ABB, Honeywell, Yokogawa, WAGO, Phoenix Contact, ...

OPC-UA uses a binary protocol with three transport layers:
  1. UA TCP (uacp://) — raw binary on TCP
  2. HTTPS — binary over HTTPS
  3. WebSocket — binary over WebSocket

All messages share a common header:
  [0:3]  MessageType  — 3-byte ASCII: HEL, ACK, OPN, CLO, MSG, ERR
  [3]    ChunkType    — 'C' (intermediate), 'F' (final), 'A' (abort)
  [4:8]  MessageSize  — uint32 LE (total message length)

HEL (Hello) contains the EndpointUrl that identifies the server.
OPN (OpenSecureChannel) contains the SecurityPolicyUri — if set to
"http://opcfoundation.org/UA/SecurityPolicy#None" the channel is unencrypted
and unauthenticated, a critical vulnerability in OT environments.
"""
import struct
from datetime import datetime
from typing import Dict, Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

OPCUA_PORT     = 4840
OPCUA_TLS_PORT = 4843

# Valid OPC-UA message type prefixes (3-byte ASCII)
MSG_HELLO              = b"HEL"
MSG_ACKNOWLEDGE        = b"ACK"
MSG_OPEN_CHANNEL       = b"OPN"
MSG_CLOSE_CHANNEL      = b"CLO"
MSG_MESSAGE            = b"MSG"
MSG_ERROR              = b"ERR"

VALID_MSG_TYPES = {MSG_HELLO, MSG_ACKNOWLEDGE, MSG_OPEN_CHANNEL,
                   MSG_CLOSE_CHANNEL, MSG_MESSAGE, MSG_ERROR}

# Chunk type codes (single ASCII byte after message type)
CHUNK_INTERMEDIATE = ord("C")
CHUNK_FINAL        = ord("F")
CHUNK_ABORT        = ord("A")

VALID_CHUNK_TYPES = {CHUNK_INTERMEDIATE, CHUNK_FINAL, CHUNK_ABORT}

# Human-readable message type names
MSG_TYPE_NAMES: Dict[bytes, str] = {
    MSG_HELLO:         "Hello",
    MSG_ACKNOWLEDGE:   "Acknowledge",
    MSG_OPEN_CHANNEL:  "OpenSecureChannel",
    MSG_CLOSE_CHANNEL: "CloseSecureChannel",
    MSG_MESSAGE:       "SecureMessage",
    MSG_ERROR:         "Error",
}

# Human-readable chunk type names
CHUNK_TYPE_NAMES: Dict[int, str] = {
    CHUNK_INTERMEDIATE: "Intermediate",
    CHUNK_FINAL:        "Final",
    CHUNK_ABORT:        "Abort",
}

# OPC-UA Security Policies — the URI string embedded in OPN messages
SECURITY_POLICIES: Dict[str, str] = {
    "http://opcfoundation.org/UA/SecurityPolicy#None":
        "None (no encryption, no signing)",
    "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15":
        "Basic128Rsa15 (deprecated, weak)",
    "http://opcfoundation.org/UA/SecurityPolicy#Basic256":
        "Basic256 (deprecated, weak)",
    "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256":
        "Basic256Sha256 (recommended)",
    "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep":
        "Aes128-Sha256-RsaOaep (strong)",
    "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss":
        "Aes256-Sha256-RsaPss (strong)",
}

# Insecure policies that should be flagged
INSECURE_POLICIES = {
    "http://opcfoundation.org/UA/SecurityPolicy#None",
    "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
    "http://opcfoundation.org/UA/SecurityPolicy#Basic256",
}

# OPC-UA minimum header size: 3 (type) + 1 (chunk) + 4 (size) = 8 bytes
OPCUA_HEADER_SIZE = 8


class OPCUAAnalyzer(BaseProtocolAnalyzer):
    """
    Passive analyzer for OPC-UA Binary Protocol traffic.

    Detects OPC-UA endpoints by parsing message headers, extracts
    EndpointUrl from HEL messages, and identifies the security policy
    from OPN messages to flag unencrypted channels.
    """

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport not in (OPCUA_PORT, OPCUA_TLS_PORT) and \
           dport not in (OPCUA_PORT, OPCUA_TLS_PORT):
            return False
        return len(payload) >= OPCUA_HEADER_SIZE

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        hdr = self._parse_header(payload)
        if hdr is None:
            return None

        msg_type, chunk_type, msg_size = hdr
        # Device (server) is the one listening on the OPC-UA port
        is_server_src = sport in (OPCUA_PORT, OPCUA_TLS_PORT)
        device_ip = src_ip if is_server_src else dst_ip
        port_used = sport if is_server_src else dport

        details: dict = {
            "message_type":      MSG_TYPE_NAMES.get(msg_type, msg_type.decode("ascii", errors="replace")),
            "chunk_type":        CHUNK_TYPE_NAMES.get(chunk_type, f"0x{chunk_type:02X}"),
            "message_size":      msg_size,
        }

        confidence = "medium"

        # ── HEL (Hello) — extract EndpointUrl ──
        if msg_type == MSG_HELLO:
            endpoint_url = self._parse_hello(payload)
            if endpoint_url:
                details["endpoint_url"] = endpoint_url
                confidence = "high"

        # ── ACK (Acknowledge) — confirms OPC-UA endpoint ──
        elif msg_type == MSG_ACKNOWLEDGE:
            ack_info = self._parse_acknowledge(payload)
            if ack_info:
                details.update(ack_info)
            confidence = "high"

        # ── OPN (OpenSecureChannel) — extract security policy ──
        elif msg_type == MSG_OPEN_CHANNEL:
            policy_info = self._parse_open_channel(payload)
            if policy_info:
                details.update(policy_info)
                confidence = "high"

        # ── MSG (SecureMessage) — high confidence ──
        elif msg_type == MSG_MESSAGE:
            confidence = "high"

        # ── ERR (Error) ──
        elif msg_type == MSG_ERROR:
            err_info = self._parse_error(payload)
            if err_info:
                details.update(err_info)
            confidence = "high"

        # Note TLS-protected connections
        if port_used == OPCUA_TLS_PORT:
            details["tls_protected"] = True

        detection = self._make_detection(
            protocol="OPC-UA",
            port=port_used,
            confidence=confidence,
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_header(self, payload: bytes):
        """
        Parse the 8-byte OPC-UA message header.
        Returns (msg_type, chunk_type, msg_size) or None on failure.
        """
        if len(payload) < OPCUA_HEADER_SIZE:
            return None

        msg_type = payload[0:3]
        if msg_type not in VALID_MSG_TYPES:
            return None

        chunk_type = payload[3]
        # HEL, ACK, ERR use 'F' as chunk type; OPN, CLO, MSG use C/F/A
        if msg_type in (MSG_HELLO, MSG_ACKNOWLEDGE, MSG_ERROR):
            if chunk_type != CHUNK_FINAL:
                return None
        else:
            if chunk_type not in VALID_CHUNK_TYPES:
                return None

        try:
            msg_size = struct.unpack_from("<I", payload, 4)[0]
        except struct.error:
            return None

        # Sanity: size must be at least 8 and not exceed reasonable bound
        if msg_size < OPCUA_HEADER_SIZE or msg_size > 0x01000000:  # 16 MB max
            return None

        return msg_type, chunk_type, msg_size

    def _parse_hello(self, payload: bytes) -> Optional[str]:
        """
        Parse OPC-UA Hello message to extract EndpointUrl.

        HEL layout after 8-byte header:
          [8:12]   ProtocolVersion    (uint32 LE)
          [12:16]  ReceiveBufferSize  (uint32 LE)
          [16:20]  SendBufferSize     (uint32 LE)
          [20:24]  MaxMessageSize     (uint32 LE)
          [24:28]  MaxChunkCount      (uint32 LE)
          [28:32]  EndpointUrl length (int32 LE, -1 = null)
          [32:..+len] EndpointUrl     (UTF-8)
        """
        if len(payload) < 32:
            return None
        try:
            url_len = struct.unpack_from("<i", payload, 28)[0]
        except struct.error:
            return None

        if url_len <= 0 or url_len > 4096:
            return None
        if 32 + url_len > len(payload):
            return None

        try:
            return payload[32:32 + url_len].decode("utf-8", errors="replace").strip()
        except Exception:
            return None

    def _parse_acknowledge(self, payload: bytes) -> Optional[dict]:
        """
        Parse OPC-UA Acknowledge message.

        ACK layout after 8-byte header:
          [8:12]   ProtocolVersion    (uint32 LE)
          [12:16]  ReceiveBufferSize  (uint32 LE)
          [16:20]  SendBufferSize     (uint32 LE)
          [20:24]  MaxMessageSize     (uint32 LE)
          [24:28]  MaxChunkCount      (uint32 LE)
        """
        if len(payload) < 28:
            return None
        try:
            proto_ver    = struct.unpack_from("<I", payload, 8)[0]
            recv_buf     = struct.unpack_from("<I", payload, 12)[0]
            send_buf     = struct.unpack_from("<I", payload, 16)[0]
            max_msg_size = struct.unpack_from("<I", payload, 20)[0]
            max_chunks   = struct.unpack_from("<I", payload, 24)[0]
        except struct.error:
            return None

        return {
            "protocol_version":   proto_ver,
            "receive_buffer":     recv_buf,
            "send_buffer":        send_buf,
            "max_message_size":   max_msg_size,
            "max_chunk_count":    max_chunks,
        }

    def _parse_open_channel(self, payload: bytes) -> Optional[dict]:
        """
        Parse OPC-UA OpenSecureChannel request/response to extract
        the SecurityPolicyUri.

        OPN layout after 8-byte header:
          [8:12]   SecureChannelId  (uint32 LE)
          [12:..] SecurityPolicyUri (UA String: int32 LE length + UTF-8)
        """
        if len(payload) < 16:
            return None
        try:
            secure_channel_id = struct.unpack_from("<I", payload, 8)[0]
            policy_len = struct.unpack_from("<i", payload, 12)[0]
        except struct.error:
            return None

        result: dict = {
            "secure_channel_id": f"0x{secure_channel_id:08X}",
        }

        if policy_len <= 0 or policy_len > 4096:
            return result
        if 16 + policy_len > len(payload):
            return result

        try:
            policy_uri = payload[16:16 + policy_len].decode("utf-8", errors="replace").strip()
        except Exception:
            return result

        result["security_policy_uri"] = policy_uri
        result["security_policy_name"] = SECURITY_POLICIES.get(policy_uri, "Unknown")
        result["security_none"] = policy_uri in INSECURE_POLICIES

        return result

    def _parse_error(self, payload: bytes) -> Optional[dict]:
        """
        Parse OPC-UA Error message.

        ERR layout after 8-byte header:
          [8:12]   Error code    (uint32 LE)
          [12:16]  Reason length (int32 LE)
          [16:..]  Reason string (UTF-8)
        """
        if len(payload) < 12:
            return None
        try:
            error_code = struct.unpack_from("<I", payload, 8)[0]
        except struct.error:
            return None

        result: dict = {"error_code": f"0x{error_code:08X}"}

        if len(payload) >= 16:
            try:
                reason_len = struct.unpack_from("<i", payload, 12)[0]
                if 0 < reason_len <= 4096 and 16 + reason_len <= len(payload):
                    result["error_reason"] = payload[16:16 + reason_len].decode(
                        "utf-8", errors="replace"
                    ).strip()
            except (struct.error, Exception):
                pass

        return result
