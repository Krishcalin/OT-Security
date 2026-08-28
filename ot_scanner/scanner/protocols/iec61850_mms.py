"""
IEC 61850 MMS (Manufacturing Message Specification) Analyzer
Port: TCP 102  |  Standards: ISO 9506, IEC 61850-8-1

MMS runs over the full ISO/OSI application stack:
  TCP -> RFC1006/TPKT -> COTP (ISO 8073) -> ISO Session -> ISO Presentation
  -> ACSE (ISO 8649/8650) -> MMS (ISO 9506)

Detection heuristic: port 102 traffic that does NOT carry a Siemens S7 PDU
(i.e., no 0x32 byte at the expected position) is assumed to be MMS.
The analyzer looks for ASN.1/BER patterns in COTP DT data payloads:
  0x61 = Application [1] Constructed -> MMS Initiate-Request
  0xA8 = Context [8] Constructed     -> MMS Confirmed-Request
  0xA9 = Context [9] Constructed     -> MMS Confirmed-Response

Vendors running IEC 61850 MMS:
  ABB (REC/REF/REL IEDs, RTU560), Siemens (SIPROTEC), GE Grid Solutions
  (UR series, D20MX), Schneider (MiCOM, Easergy), SEL, Alstom/GE

Logical Node name prefixes (IEC 61850-7-4) --- identified from MMS strings:
  XCBR -> Circuit Breaker
  XSWI -> Disconnector / Switch
  CSWI -> Circuit Switch Controller
  RREC -> Auto Recloser              <- FRTU key node
  RFLO -> Fault Locator
  PTOC -> Overcurrent Protection
  PDIF -> Differential Protection
  PHAR -> Harmonic Restraint
  MMXU -> Measurements Unit
  MSQI -> Sequence & Imbalance
"""
import struct
from datetime import datetime
from typing import Dict, List, Optional, Set

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection
from .ber import CONTEXT_0, CONTEXT_1, CONTEXT_2, elements, read_string

MMS_PORT    = 102
S7_PROTO_ID = 0x32

# ASN.1/BER tags indicating MMS PDUs
MMS_INITIATE_TAG    = 0x61   # Application [1] Constructed
# ISO 9506-2, MMSpdu ::= CHOICE. confirmed-RequestPDU is [0] and
# confirmed-ResponsePDU is [1]; this file previously had them as [8] and [9],
# which are cancel-RequestPDU and initiate-ResponsePDU. The consequence was not
# a crash: a real confirmed response (0xA1) was not recognised as an MMS PDU at
# all, and every Initiate response was reported as "Confirmed-Response".
MMS_CONFIRMED_REQ   = 0xA0   # Context [0]  Constructed
MMS_CONFIRMED_RESP  = 0xA1   # Context [1]  Constructed
MMS_UNCONFIRMED     = 0xA3   # Context [3]  Constructed
MMS_REJECT          = 0xA4   # Context [4]  Constructed
# Kept recognised because they were shipped as the confirmed tags and a capture
# replayed against an older build should not silently change meaning.
MMS_CANCEL_REQ      = 0xA8   # Context [8]
MMS_INITIATE_RESP   = 0xA9   # Context [9]

MMS_PDU_TAGS = {MMS_INITIATE_TAG, MMS_CONFIRMED_REQ, MMS_CONFIRMED_RESP,
                MMS_UNCONFIRMED, MMS_REJECT, MMS_CANCEL_REQ,
                MMS_INITIATE_RESP}

# MMS service tags
MMS_SERVICES: Dict[int, str] = {
    0:  "status",
    1:  "getNameList",
    2:  "identify",
    4:  "read",
    5:  "write",
    6:  "getVariableAccessAttributes",
    7:  "defineNamedVariable",
    9:  "deleteNamedVariable",
    10: "getNamedVariableListAttributes",
    11: "defineNamedVariableList",
    12: "deleteNamedVariableList",
    72: "fileOpen",
    73: "fileRead",
    74: "fileClose",
    75: "fileRename",
    76: "fileDelete",
    77: "fileDirectory",
    201: "informationReport",
}

# IEC 61850 Logical Node prefixes and their meaning
IEC61850_LN_PREFIXES: Dict[str, str] = {
    "XCBR": "Circuit Breaker",
    "XSWI": "Disconnector/Switch",
    "CSWI": "Circuit Switch Controller",
    "RREC": "Automatic Recloser",
    "RFLO": "Fault Locator",
    "PTOC": "Overcurrent Protection",
    "PDIF": "Differential Protection",
    "PHAR": "Harmonic Restraint",
    "MMXU": "Measurement Unit",
    "MSQI": "Sequence/Imbalance Measurement",
    "TCTR": "Current Transformer",
    "TVTR": "Voltage Transformer",
    "ARCO": "Reactive Power Compensation",
    "ATCC": "Automatic Tap-Changer Controller",
    "AVCO": "Voltage Control",
    "CALH": "Alarm Handling",
    "CCGR": "Cooling Group Control",
    "CPOW": "Power Factor Control",
    "CRLC": "Line Control",
    "DTMS": "Transformer Monitoring Supervision",
    "RBRF": "Breaker Failure",
    "RDRE": "Disturbance Recorder",
    "RDRS": "Disturbance Record Supervisor",
}


class IEC61850MmsAnalyzer(BaseProtocolAnalyzer):

    def __init__(self):
        self._detected_lds: Dict[str, Set[str]] = {}   # ip -> Logical Device names
        self._detected_lns: Dict[str, Set[str]] = {}   # ip -> Logical Node names

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport != MMS_PORT and dport != MMS_PORT:
            return False
        return len(payload) >= 7

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        # Quick rejection: if S7 protocol byte is at expected position, this is S7
        cotp = self._parse_cotp(payload)
        if cotp is None:
            return None
        cotp_type, remainder = cotp

        # Reject S7comm PDUs
        if remainder and len(remainder) > 0 and remainder[0] == S7_PROTO_ID:
            return None

        # We need COTP Data Transfer with non-S7 content
        if cotp_type != 0xF0:   # DT Data
            if cotp_type in (0xE0, 0xD0):    # CR / CC --- mild detection
                device_ip = dst_ip if dport == MMS_PORT else src_ip
                det = self._make_detection(
                    protocol="IEC 61850 MMS",
                    port=MMS_PORT,
                    confidence="low",
                    timestamp=timestamp,
                    connection_phase="COTP handshake",
                )
                return [(device_ip, det)]
            return None

        device_ip = dst_ip if dport == MMS_PORT else src_ip
        details: Dict = {"mms_port": MMS_PORT}

        # Try to identify MMS PDU
        mms_info = self._parse_mms_pdu(remainder)
        if mms_info:
            details.update(mms_info)
        else:
            # Could still be MMS --- the ISO presentation header is long
            # Accept as low-confidence detection
            details["parse_note"] = "MMS PDU structure present (deep parse skipped)"

        # Extract Logical Device / Node names from string data
        raw_text = remainder.decode("latin-1", errors="replace")
        lns, lds = self._extract_ln_names(raw_text)
        if lns:
            details["logical_nodes"] = list(lns)
            self._detected_lns.setdefault(device_ip, set()).update(lns)
        if lds:
            details["logical_devices"] = list(lds)
            self._detected_lds.setdefault(device_ip, set()).update(lds)

        det = self._make_detection(
            protocol="IEC 61850 MMS",
            port=MMS_PORT,
            confidence="high" if mms_info else "medium",
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, det)]

    def get_logical_nodes(self, ip: str) -> Set[str]:
        return self._detected_lns.get(ip, set())

    def get_logical_devices(self, ip: str) -> Set[str]:
        return self._detected_lds.get(ip, set())

    # -- parsers ---------------------------------------------------------------

    def _parse_cotp(self, payload: bytes):
        """Parse RFC 1006 TPKT + COTP header. Returns (pdu_type, remainder)."""
        if len(payload) < 7:
            return None
        if payload[0] != 0x03:     # TPKT version
            return None
        tpkt_len = struct.unpack_from(">H", payload, 2)[0]
        if tpkt_len < 7 or tpkt_len > len(payload):
            return None
        cotp_li   = payload[4]     # length indicator
        cotp_type = payload[5]     # PDU type
        cotp_end  = 4 + 1 + cotp_li
        return cotp_type, payload[cotp_end:]

    def _parse_mms_pdu(self, data: bytes) -> Optional[Dict]:
        """
        Try to identify MMS PDU type from ASN.1/BER tag.
        Returns minimal info dict or None.
        """
        if not data:
            return None
        # Skip possible ISO Presentation / Session wrapper bytes
        for i in range(min(len(data), 32)):
            tag = data[i]
            if tag in MMS_PDU_TAGS:
                svc = _get_mms_service(data, i)
                pdu_type = {
                    MMS_INITIATE_TAG:   "Initiate",
                    MMS_CONFIRMED_REQ:  "Confirmed-Request",
                    MMS_CONFIRMED_RESP: "Confirmed-Response",
                    MMS_UNCONFIRMED:    "Unconfirmed",
                    MMS_CANCEL_REQ:     "Cancel-Request",
                    MMS_INITIATE_RESP:  "Initiate-Response",
                    MMS_REJECT:         "Reject",
                }.get(tag, f"tag 0x{tag:02X}")
                result = {"mms_pdu_type": pdu_type}
                if svc:
                    result["mms_service"] = svc
                return result
        return None

    def _extract_ln_names(self, text: str):
        """
        Scan for IEC 61850 Logical Node / Logical Device name patterns in
        raw string data. Returns (ln_set, ld_set).
        """
        lns: Set[str] = set()
        lds: Set[str] = set()
        words = text.replace("/", " ").replace(".", " ").split()
        for word in words:
            if len(word) < 3:
                continue
            prefix = word[:4].upper()
            if prefix in IEC61850_LN_PREFIXES:
                lns.add(word[:max(6, len(word))][:16])  # keep reasonable length
            # Logical Device names often end in "LD" or contain known patterns
            if word.endswith("LD") and len(word) >= 4:
                lds.add(word[:16])
        return lns, lds


#: confirmed-ResponsePDU [1] and the identify service [2] inside it.
MMS_IDENTIFY_SERVICE = 0xA2


def parse_identify_response(data: bytes) -> Dict[str, str]:
    """vendorName, modelName and revision out of an MMS IdentifyResponse.

    This is the richest identification an IEC 61850 IED will ever hand a
    passive listener. The service was already RECOGNISED here (id 2 in
    MMS_SERVICES) and the response thrown away — so an estate full of 61850
    relays reported a vendor guessed from an OUI and no model at all.

    ISO 9506-2:

        confirmed-ResponsePDU [1] IMPLICIT SEQUENCE {
            invokeID  Unsigned32,
            service   ConfirmedServiceResponse }

        ConfirmedServiceResponse ::= CHOICE { … identify [2] IMPLICIT … }

        IdentifyResponse ::= SEQUENCE {
            vendorName [0] IMPLICIT VisibleString,
            modelName  [1] IMPLICIT VisibleString,
            revision   [2] IMPLICIT VisibleString,
            listOfAbstractSyntaxes [3] OPTIONAL }

    The identify body is located by walking, not by a fixed offset: what sits
    in front of the MMS PDU depends on how many OSI presentation and session
    layers the IED wrapped it in, and that varies by vendor.
    """
    body = _find_identify_body(data)
    if body is None:
        return {}
    fields = {}
    for tag, value in elements(body):
        if tag == CONTEXT_0:
            fields["vendor"] = read_string(value)
        elif tag == CONTEXT_1:
            fields["model"] = read_string(value)
        elif tag == CONTEXT_2:
            fields["firmware"] = read_string(value)
    if not fields.get("vendor") and not fields.get("model"):
        # A response carrying neither is not identification. Returning the
        # empty revision alone would put a bare version on a device whose make
        # is unknown, and that version is matched against the CVE corpus.
        return {}
    out = {k: v for k, v in fields.items() if v}
    if out.get("vendor"):
        out["make"] = out["vendor"]
    if out.get("firmware"):
        out["os_version"] = out["firmware"]
    out["identified_by"] = "mms-identify"
    return out


def _find_identify_body(data: bytes) -> Optional[bytes]:
    """The IdentifyResponse SEQUENCE, wherever the wrappers left it.

    Located by its SHAPE, not by the enclosing PDU tag. Two things vary in
    front of it and neither is worth trusting: how many OSI presentation and
    session layers the IED wrapped the PDU in, which differs by vendor, and
    which tag this file believes means "confirmed response" — a question this
    module got wrong for its whole life until now.

    An identify body is a [2] constructed element whose immediate children are
    context [0], [1] and [2] primitives. That pattern is specific enough to
    find on its own and does not care what is in front of it.
    """
    for start in range(len(data)):
        if data[start] != MMS_IDENTIFY_SERVICE:
            continue
        try:
            _tag, body, _ = _read_one(data, start)
        except ValueError:
            continue
        tags = [tag for tag, _value in elements(body)]
        if tags and tags[0] == CONTEXT_0 and set(tags) <= {
                CONTEXT_0, CONTEXT_1, CONTEXT_2, 0xA3}:
            return body
    return None


def _read_one(data: bytes, index: int):
    from .ber import read_tlv
    return read_tlv(data, index)


def _get_mms_service(data: bytes, pdu_start: int) -> Optional[str]:
    """
    Attempt to extract MMS confirmed-request service tag from the PDU.
    In MMS Confirmed-Request/Response, service type is a context tag inside.
    """
    if pdu_start + 4 >= len(data):
        return None
    # The service tag is typically the first inner tag of the Confirmed-Request
    # It's a context-specific primitive or constructed tag 0x80-0xBF
    inner_offset = pdu_start + 2    # skip outer tag + length
    if inner_offset >= len(data):
        return None
    # skip invoke ID (usually 0x02 0x01 xx)
    pos = inner_offset
    while pos < min(pdu_start + 20, len(data) - 1):
        tag = data[pos]
        # Service tag is context-specific [0]..[77]
        if 0x80 <= tag <= 0xBF:
            svc_num = tag & 0x1F
            if svc_num in MMS_SERVICES:
                return MMS_SERVICES[svc_num]
        pos += 1
    return None
