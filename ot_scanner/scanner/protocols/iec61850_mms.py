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

MMS_PORT    = 102
S7_PROTO_ID = 0x32

# ASN.1/BER tags indicating MMS PDUs
MMS_INITIATE_TAG    = 0x61   # Application [1] Constructed
MMS_CONFIRMED_REQ   = 0xA8   # Context [8]  Constructed
MMS_CONFIRMED_RESP  = 0xA9   # Context [9]  Constructed
MMS_UNCONFIRMED     = 0xAA   # Context [10] Constructed
MMS_REJECT          = 0xAC   # Context [12] Constructed

MMS_PDU_TAGS = {MMS_INITIATE_TAG, MMS_CONFIRMED_REQ,
                MMS_CONFIRMED_RESP, MMS_UNCONFIRMED, MMS_REJECT}

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
