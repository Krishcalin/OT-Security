"""
BACnet/IP Protocol Analyzer  (ASHRAE Standard 135 / ISO 16484-5)
Port: UDP 47808 (0xBAC0)

BACnet (Building Automation and Control Networks) is the dominant protocol
for building management systems (BMS), HVAC, fire/life safety, lighting,
and access control.  BACnet/IP wraps BACnet frames in UDP datagrams.

Used by virtually every BAS vendor:
  Johnson Controls / Metasys      (Vendor ID 5)
  Siemens Building Technologies   (Vendor ID 7)
  Schneider Electric / TAC         (Vendor ID 10)
  Honeywell Building Solutions     (Vendor ID 20)
  Tridium / Niagara               (Vendor ID 21)
  Automated Logic / Carrier       (Vendor ID 24)
  Delta Controls                   (Vendor ID 30)
  ABB                              (Vendor ID 216)
  Distech Controls                 (Vendor ID 180)
  Reliable Controls                (Vendor ID 218)
  Carel                            (Vendor ID 323)
  KMC Controls                     (Vendor ID 69)

Protocol stack (BACnet/IP):
  UDP/IP  ->  BVLC  ->  NPDU  ->  APDU

BVLC (BACnet Virtual Link Control):
  [0]    Type        — 0x81 = BACnet/IP
  [1]    Function    — BVLC function code
  [2:4]  Length      — total BVLC packet length (BE uint16)

NPDU (Network Protocol Data Unit):
  [0]    Version     — 0x01 for BACnet
  [1]    Control     — bit 7: network layer msg; bit 5: has DNET; bit 3: has SNET; bit 2: expecting reply

APDU (Application Protocol Data Unit):
  Byte 0 top nibble = PDU type:
    0 = BACnet-Confirmed-Request
    1 = BACnet-Unconfirmed-Request
    2 = SimpleACK
    3 = ComplexACK
    4 = SegmentACK
    5 = Error
    6 = Reject
    7 = Abort
"""
import struct
from datetime import datetime
from typing import Dict, Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

BACNET_PORT = 47808   # 0xBAC0

# BVLC Type
BVLC_TYPE_BACNET_IP = 0x81

# BVLC Function codes
BVLC_RESULT                    = 0x00
BVLC_WRITE_BDT                 = 0x01
BVLC_READ_BDT                  = 0x02
BVLC_READ_BDT_ACK              = 0x03
BVLC_FORWARDED_NPDU            = 0x04
BVLC_REGISTER_FD               = 0x05
BVLC_READ_FD_TABLE             = 0x06
BVLC_READ_FD_TABLE_ACK         = 0x07
BVLC_DELETE_FD_ENTRY           = 0x08
BVLC_DISTRIBUTE_BROADCAST      = 0x09
BVLC_ORIGINAL_UNICAST          = 0x0A
BVLC_ORIGINAL_BROADCAST        = 0x0B

BVLC_FUNCTION_NAMES: Dict[int, str] = {
    0x00: "BVLC-Result",
    0x01: "Write-Broadcast-Distribution-Table",
    0x02: "Read-Broadcast-Distribution-Table",
    0x03: "Read-Broadcast-Distribution-Table-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-Foreign-Device-Table",
    0x07: "Read-Foreign-Device-Table-Ack",
    0x08: "Delete-Foreign-Device-Table-Entry",
    0x09: "Distribute-Broadcast-To-Network",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
}

# NPDU version
BACNET_NPDU_VERSION = 0x01

# APDU PDU types (top 4 bits of first APDU byte)
APDU_CONFIRMED_REQUEST   = 0
APDU_UNCONFIRMED_REQUEST = 1
APDU_SIMPLE_ACK          = 2
APDU_COMPLEX_ACK         = 3
APDU_SEGMENT_ACK         = 4
APDU_ERROR               = 5
APDU_REJECT              = 6
APDU_ABORT               = 7

APDU_TYPE_NAMES: Dict[int, str] = {
    0: "Confirmed-Request",
    1: "Unconfirmed-Request",
    2: "SimpleACK",
    3: "ComplexACK",
    4: "SegmentACK",
    5: "Error",
    6: "Reject",
    7: "Abort",
}

# BACnet confirmed service choices
SVC_ACKNOWLEDGE_ALARM        = 0
SVC_CONFIRMED_COV_NOTIF      = 1
SVC_CONFIRMED_EVENT_NOTIF    = 2
SVC_GET_ALARM_SUMMARY        = 3
SVC_GET_ENROLLMENT_SUMMARY   = 4
SVC_SUBSCRIBE_COV            = 5
SVC_ATOMIC_READ_FILE         = 6
SVC_ATOMIC_WRITE_FILE        = 7
SVC_ADD_LIST_ELEMENT         = 8
SVC_REMOVE_LIST_ELEMENT      = 9
SVC_CREATE_OBJECT            = 10
SVC_DELETE_OBJECT            = 11
SVC_READ_PROPERTY            = 12
SVC_READ_PROPERTY_MULTIPLE   = 14
SVC_WRITE_PROPERTY           = 15
SVC_WRITE_PROPERTY_MULTIPLE  = 16
SVC_DEVICE_COMM_CONTROL      = 17
SVC_CONFIRMED_PRIVATE_XFER   = 18
SVC_CONFIRMED_TEXT_MSG        = 19
SVC_REINITIALIZE_DEVICE      = 20
SVC_READ_RANGE               = 26

CONFIRMED_SERVICE_NAMES: Dict[int, str] = {
    0:  "AcknowledgeAlarm",
    1:  "ConfirmedCOVNotification",
    2:  "ConfirmedEventNotification",
    3:  "GetAlarmSummary",
    4:  "GetEnrollmentSummary",
    5:  "SubscribeCOV",
    6:  "AtomicReadFile",
    7:  "AtomicWriteFile",
    8:  "AddListElement",
    9:  "RemoveListElement",
    10: "CreateObject",
    11: "DeleteObject",
    12: "ReadProperty",
    14: "ReadPropertyMultiple",
    15: "WriteProperty",
    16: "WritePropertyMultiple",
    17: "DeviceCommunicationControl",
    18: "ConfirmedPrivateTransfer",
    19: "ConfirmedTextMessage",
    20: "ReinitializeDevice",
    26: "ReadRange",
}

# BACnet unconfirmed service choices
SVC_I_AM         = 0
SVC_I_HAVE       = 1
SVC_UNCONFIRMED_COV_NOTIF = 2
SVC_UNCONFIRMED_EVENT_NOTIF = 3
SVC_UNCONFIRMED_PRIVATE_XFER = 4
SVC_UNCONFIRMED_TEXT_MSG = 5
SVC_TIME_SYNC    = 6
SVC_WHO_HAS      = 7
SVC_WHO_IS       = 8
SVC_UTC_TIME_SYNC = 9

UNCONFIRMED_SERVICE_NAMES: Dict[int, str] = {
    0: "I-Am",
    1: "I-Have",
    2: "UnconfirmedCOVNotification",
    3: "UnconfirmedEventNotification",
    4: "UnconfirmedPrivateTransfer",
    5: "UnconfirmedTextMessage",
    6: "TimeSynchronization",
    7: "Who-Has",
    8: "Who-Is",
    9: "UTCTimeSynchronization",
}

# BACnet Object Types (used in I-Am object identifier)
BACNET_OBJECT_TYPES: Dict[int, str] = {
    0:  "analog-input",
    1:  "analog-output",
    2:  "analog-value",
    3:  "binary-input",
    4:  "binary-output",
    5:  "binary-value",
    8:  "device",
    10: "file",
    13: "multi-state-input",
    14: "multi-state-output",
    17: "schedule",
    19: "multi-state-value",
    20: "notification-class",
    23: "accumulator",
    28: "trend-log-multiple",
    30: "access-point",
    56: "network-port",
}

# BACnet Vendor IDs (partial — major BAS vendors)
BACNET_VENDORS: Dict[int, str] = {
    0:   "ASHRAE",
    2:   "The Trane Company",
    4:   "Carrier / United Technologies",
    5:   "Johnson Controls",
    7:   "Siemens Building Technologies",
    8:   "Lithonia Lighting",
    10:  "Schneider Electric / TAC",
    15:  "York / Johnson Controls",
    20:  "Honeywell Building Solutions",
    21:  "Tridium / Niagara",
    24:  "Automated Logic / Carrier",
    25:  "Control4",
    30:  "Delta Controls",
    36:  "Alerton / Honeywell",
    47:  "Lennox International",
    69:  "KMC Controls",
    86:  "Contemporary Controls",
    95:  "Cimetrics",
    113: "Reliable Controls Corporation",
    149: "Daikin Industries",
    171: "Loytec Electronics",
    180: "Distech Controls / Acuity",
    216: "ABB",
    218: "Reliable Controls",
    260: "Carel",
    323: "Carel Industries",
    343: "Belimo",
    414: "EasyIO",
}

# Segmentation support codes (from I-Am)
SEGMENTATION_NAMES: Dict[int, str] = {
    0: "segmented-both",
    1: "segmented-transmit",
    2: "segmented-receive",
    3: "no-segmentation",
}

# Minimum BVLC header size: Type(1) + Function(1) + Length(2) = 4 bytes
BVLC_HEADER_SIZE = 4


class BACnetAnalyzer(BaseProtocolAnalyzer):
    """
    Passive analyzer for BACnet/IP traffic on UDP 47808 (0xBAC0).

    Parses BVLC, NPDU, and APDU layers to identify BACnet devices.
    Extracts rich device identity from I-Am responses (device instance,
    vendor ID, max APDU length, segmentation support) and classifies
    service types for Who-Is discovery, Read/WriteProperty, and
    device control commands.
    """

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "UDP":
            return False
        if sport != BACNET_PORT and dport != BACNET_PORT:
            return False
        return len(payload) >= BVLC_HEADER_SIZE

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        bvlc = self._parse_bvlc(payload)
        if bvlc is None:
            return None

        bvlc_func, bvlc_len, npdu_offset = bvlc
        device_ip = src_ip if sport == BACNET_PORT else dst_ip

        details: dict = {
            "bvlc_function":      BVLC_FUNCTION_NAMES.get(bvlc_func, f"0x{bvlc_func:02X}"),
            "bvlc_length":        bvlc_len,
        }

        confidence = "medium"

        # For Forwarded-NPDU, skip the 6-byte original-source-address
        if bvlc_func == BVLC_FORWARDED_NPDU:
            npdu_offset += 6   # 4 bytes IP + 2 bytes port

        # Parse NPDU
        npdu_data = payload[npdu_offset:]
        npdu = self._parse_npdu(npdu_data)
        if npdu is not None:
            npdu_ctrl, apdu_offset = npdu
            confidence = "high"
            details["npdu_version"] = 1

            # Check if this is a network-layer message (no APDU)
            if npdu_ctrl & 0x80:
                details["network_layer_message"] = True
            else:
                # Parse APDU
                apdu_data = npdu_data[apdu_offset:]
                apdu_info = self._parse_apdu(apdu_data)
                if apdu_info:
                    details.update(apdu_info)

        detection = self._make_detection(
            protocol="BACnet/IP",
            port=BACNET_PORT,
            confidence=confidence,
            timestamp=timestamp,
            transport="UDP",
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_bvlc(self, payload: bytes):
        """
        Parse BVLC header.
        Returns (function_code, length, npdu_offset) or None.
        """
        if len(payload) < BVLC_HEADER_SIZE:
            return None

        bvlc_type = payload[0]
        if bvlc_type != BVLC_TYPE_BACNET_IP:
            return None

        bvlc_func = payload[1]
        try:
            bvlc_len = struct.unpack_from(">H", payload, 2)[0]
        except struct.error:
            return None

        # Sanity: length should cover at least the header and not exceed packet
        if bvlc_len < BVLC_HEADER_SIZE:
            return None

        # NPDU starts right after the 4-byte BVLC header
        return bvlc_func, bvlc_len, BVLC_HEADER_SIZE

    def _parse_npdu(self, data: bytes):
        """
        Parse BACnet NPDU header.
        Returns (control_byte, apdu_start_offset) or None.
        """
        if len(data) < 2:
            return None

        version = data[0]
        if version != BACNET_NPDU_VERSION:
            return None

        control = data[1]
        offset = 2

        # If DNET is present (bit 5), skip DNET(2) + DLEN(1) + DADR(DLEN) + HopCount(1)
        if control & 0x20:
            if offset + 3 > len(data):
                return None
            dlen = data[offset + 2]
            offset += 3 + dlen
            # Hop count follows DADR
            if offset >= len(data):
                return None
            offset += 1   # skip hop count

        # If SNET is present (bit 3), skip SNET(2) + SLEN(1) + SADR(SLEN)
        if control & 0x08:
            if offset + 3 > len(data):
                return None
            slen = data[offset + 2]
            offset += 3 + slen

        return control, offset

    def _parse_apdu(self, data: bytes) -> Optional[dict]:
        """
        Parse BACnet APDU header and extract PDU type, service choice,
        and for I-Am responses: device instance, vendor ID, etc.
        """
        if not data:
            return None

        pdu_type = (data[0] >> 4) & 0x0F
        result: dict = {
            "apdu_type": APDU_TYPE_NAMES.get(pdu_type, f"0x{pdu_type:X}"),
        }

        if pdu_type == APDU_CONFIRMED_REQUEST:
            # Confirmed Request: PDU-type(4bits)+flags(4bits) + MaxSegs/MaxResp(1) +
            #   InvokeID(1) + [Sequence(1) + Window(1)] + ServiceChoice(1)
            segmented = data[0] & 0x08
            offset = 1
            if offset >= len(data):
                return result
            offset += 1   # MaxSegs/MaxResp
            if offset >= len(data):
                return result
            result["invoke_id"] = data[offset]
            offset += 1

            if segmented:
                offset += 2   # sequence number + proposed window size

            if offset < len(data):
                svc = data[offset]
                result["service_choice"] = svc
                result["service_name"] = CONFIRMED_SERVICE_NAMES.get(svc, f"Service {svc}")

        elif pdu_type == APDU_UNCONFIRMED_REQUEST:
            # Unconfirmed Request: PDU-type(4bits)+0(4bits) + ServiceChoice(1) + ...
            if len(data) < 2:
                return result
            svc = data[1]
            result["service_choice"] = svc
            result["service_name"] = UNCONFIRMED_SERVICE_NAMES.get(svc, f"Service {svc}")

            # Parse I-Am payload
            if svc == SVC_I_AM:
                iam = self._parse_iam(data[2:])
                if iam:
                    result.update(iam)

            # Who-Is
            elif svc == SVC_WHO_IS:
                result["discovery"] = True

        elif pdu_type == APDU_SIMPLE_ACK:
            if len(data) >= 3:
                result["invoke_id"]    = data[1]
                result["service_name"] = CONFIRMED_SERVICE_NAMES.get(data[2], f"Service {data[2]}")

        elif pdu_type == APDU_COMPLEX_ACK:
            segmented = data[0] & 0x08
            offset = 1
            if offset < len(data):
                result["invoke_id"] = data[offset]
                offset += 1
            if segmented:
                offset += 2
            if offset < len(data):
                svc = data[offset]
                result["service_name"] = CONFIRMED_SERVICE_NAMES.get(svc, f"Service {svc}")

        elif pdu_type == APDU_ERROR:
            if len(data) >= 3:
                result["invoke_id"]    = data[1]
                result["service_name"] = CONFIRMED_SERVICE_NAMES.get(data[2], f"Service {data[2]}")

        return result

    def _parse_iam(self, data: bytes) -> Optional[dict]:
        """
        Parse the I-Am service payload.

        I-Am contains (all ASN.1/BER encoded):
          - BACnetObjectIdentifier (device instance)  — context tag [0] or app tag 0xC4
          - Unsigned (max APDU length)                 — app tag 0x21/0x22/0x23/0x24
          - BACnetSegmentation                         — app tag 0x91
          - Unsigned (vendor ID)                       — app tag 0x21/0x22
        """
        if len(data) < 7:
            return None

        result: dict = {}
        offset = 0

        # 1. Object Identifier (Application tag 12 = 0xC4, 4 bytes)
        if offset < len(data) and data[offset] == 0xC4:
            offset += 1
            if offset + 4 <= len(data):
                oid = struct.unpack_from(">I", data, offset)[0]
                obj_type = (oid >> 22) & 0x3FF
                instance = oid & 0x3FFFFF
                result["object_type"] = BACNET_OBJECT_TYPES.get(obj_type, f"type-{obj_type}")
                result["device_instance"] = instance
                offset += 4

        # 2. Max APDU Length Accepted (Application tag 2 = unsigned)
        if offset < len(data):
            tag = data[offset]
            tag_num = (tag >> 4) & 0x0F
            tag_len = tag & 0x07
            if tag_num == 2 and tag_len > 0 and tag_len <= 4:
                offset += 1
                if offset + tag_len <= len(data):
                    val = int.from_bytes(data[offset:offset + tag_len], "big")
                    result["max_apdu_length"] = val
                    offset += tag_len

        # 3. Segmentation Supported (Application tag 9 = enumerated, 1 byte)
        if offset < len(data) and (data[offset] & 0xF0) == 0x90:
            tag_len = data[offset] & 0x07
            offset += 1
            if tag_len > 0 and offset + tag_len <= len(data):
                seg_val = data[offset]
                result["segmentation"] = SEGMENTATION_NAMES.get(seg_val, f"0x{seg_val:02X}")
                offset += tag_len

        # 4. Vendor ID (Application tag 2 = unsigned)
        if offset < len(data):
            tag = data[offset]
            tag_num = (tag >> 4) & 0x0F
            tag_len = tag & 0x07
            if tag_num == 2 and tag_len > 0 and tag_len <= 4:
                offset += 1
                if offset + tag_len <= len(data):
                    vendor_id = int.from_bytes(data[offset:offset + tag_len], "big")
                    result["vendor_id"] = vendor_id
                    result["vendor_name"] = BACNET_VENDORS.get(
                        vendor_id, f"VendorID {vendor_id}"
                    )

        return result if result else None
