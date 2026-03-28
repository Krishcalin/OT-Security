"""
IEC 61850 GOOSE (Generic Object Oriented Substation Event) Analyzer
EtherType: 0x88B8  |  Standard: IEC 61850-8-1

GOOSE is a Layer-2 multicast protocol used for fast protection signalling
between IEDs in substations (trip signals, breaker status, etc.).

It does NOT traverse IP routers, so detection requires Ethernet frame access.

Destination MAC convention (IEEE 802.3):
  01:0C:CD:01:XX:XX -> IEC 61850 GOOSE
  01:0C:CD:02:XX:XX -> GSSE (obsolete)
  01:0C:CD:04:XX:XX -> SV (Sampled Values)

GOOSE Frame:
  AppID   : 2 bytes BE  (identifies control block)
  Length  : 2 bytes BE  (total length incl header)
  Reserved1: 2 bytes    (0x0000 normal, or security tag indicator)
  Reserved2: 2 bytes    (0x0000)
  PDU     : ASN.1/BER GOOSE PDU (Application tag 0x61)

GOOSE PDU key fields (ASN.1 context tags 0x80-0x8A, 0xAB):
  0x80 gocbRef         --- identifies source IED and control block
  0x81 timeAllowedToLive --- TTL in milliseconds
  0x82 datSet          --- dataset name
  0x83 goID            --- GOOSE identifier
  0x84 t               --- UTC timestamp (8 bytes)
  0x85 stNum           --- state number (increments on state change -> trip)
  0x86 sqNum           --- sequence number (increments every message)
  0x87 simulation      --- boolean (TRUE = test mode in live traffic = VULN)
  0x88 confRev         --- configuration revision
  0x89 ndsCom          --- needs commissioning (TRUE = unconfigured device)
  0x8A numDatSetEntries
  0xAB allData         --- the actual data values

Security vulnerabilities detected:
  1. simulation=TRUE in live traffic  (IEC 62351-6 violation)
  2. Low timeAllowedToLive (<= 1000ms) -> short replay window but also
     means the receiver stops within 1s if messages stop --- DoS risk
  3. confRev changes -> configuration modified without coordinated change
  4. No TLS / VLAN tags (baseline --- all GOOSE on port 0 VLAN = unprotected)
  5. ndsCom=TRUE -> device needs commissioning (misconfiguration)
"""
import struct
from datetime import datetime
from typing import Dict, Optional

from .base import BaseL2Analyzer
from ..models import GOOSEPublisherState

GOOSE_ETHERTYPE = 0x88B8
SV_ETHERTYPE    = 0x88BA

# Minimum TTL threshold --- below this is flagged as replay-attack risk
LOW_TTL_THRESHOLD_MS = 2000   # 2 seconds

# GOOSE ASN.1 context tags
TAG_GCB_REF     = 0x80
TAG_TTL         = 0x81
TAG_DAT_SET     = 0x82
TAG_GOOSE_ID    = 0x83
TAG_TIMESTAMP   = 0x84
TAG_ST_NUM      = 0x85
TAG_SQ_NUM      = 0x86
TAG_SIMULATION  = 0x87
TAG_CONF_REV    = 0x88
TAG_NDS_COM     = 0x89
TAG_NUM_ENTRIES = 0x8A
TAG_ALL_DATA    = 0xAB


class GOOSEAnalyzer(BaseL2Analyzer):

    def __init__(self):
        # Key: (src_mac, app_id) -> GOOSEPublisherState
        self._publishers: Dict[tuple, GOOSEPublisherState] = {}

    def get_sessions(self) -> Dict:
        return self._publishers

    def can_analyze_frame(self, eth_type: int, payload: bytes) -> bool:
        return eth_type == GOOSE_ETHERTYPE and len(payload) >= 8

    def analyze_frame(
        self,
        src_mac: str, dst_mac: str,
        eth_type: int, payload: bytes,
        timestamp: datetime,
    ) -> Optional[dict]:
        if not self.can_analyze_frame(eth_type, payload):
            return None

        # Parse GOOSE Ethernet header
        app_id   = struct.unpack_from(">H", payload, 0)[0]
        length   = struct.unpack_from(">H", payload, 2)[0]
        reserved1 = struct.unpack_from(">H", payload, 4)[0]
        reserved2 = struct.unpack_from(">H", payload, 6)[0]

        key = (src_mac, app_id)
        if key not in self._publishers:
            self._publishers[key] = GOOSEPublisherState(
                src_mac=src_mac,
                app_id=app_id,
                first_seen=timestamp,
            )
        pub = self._publishers[key]
        pub.total_packets += 1
        pub.last_seen = timestamp

        # Check security tags in Reserved fields
        has_security_tag = reserved1 != 0 or reserved2 != 0

        # Parse GOOSE PDU (ASN.1 BER)
        pdu_data = payload[8: length] if length <= len(payload) else payload[8:]
        pdu_info = self._parse_goose_pdu(pdu_data)

        if pdu_info:
            gcb_ref    = pdu_info.get("gcb_ref", "")
            dat_set    = pdu_info.get("dat_set", "")
            goose_id   = pdu_info.get("goose_id", "")
            ttl        = pdu_info.get("ttl_ms", 0)
            st_num     = pdu_info.get("st_num", 0)
            sq_num     = pdu_info.get("sq_num", 0)
            simulation = pdu_info.get("simulation", False)
            conf_rev   = pdu_info.get("conf_rev", 0)
            nds_com    = pdu_info.get("nds_com", False)

            pub.gcb_ref  = gcb_ref  or pub.gcb_ref
            pub.dat_set  = dat_set  or pub.dat_set
            pub.goose_id = goose_id or pub.goose_id
            pub.last_st_num = st_num

            if simulation:
                pub.simulation_seen = True
            if ttl and ttl < pub.min_ttl_ms:
                pub.min_ttl_ms = ttl
            if conf_rev:
                if pub.last_conf_rev is not None and conf_rev != pub.last_conf_rev:
                    pub.conf_rev_changes += 1
                pub.last_conf_rev = conf_rev

            return {
                "src_mac":       src_mac,
                "dst_mac":       dst_mac,
                "app_id":        f"0x{app_id:04X}",
                "gcb_ref":       gcb_ref,
                "dat_set":       dat_set,
                "goose_id":      goose_id,
                "ttl_ms":        ttl,
                "st_num":        st_num,
                "sq_num":        sq_num,
                "simulation":    simulation,
                "conf_rev":      conf_rev,
                "nds_com":       nds_com,
                "security_tag":  has_security_tag,
            }

        return {
            "src_mac": src_mac,
            "app_id":  f"0x{app_id:04X}",
            "parse_note": "GOOSE frame (PDU parse failed)",
        }

    # -- PDU parser ------------------------------------------------------------

    def _parse_goose_pdu(self, data: bytes) -> Optional[Dict]:
        """
        Parse GOOSE PDU from ASN.1 BER bytes.
        The outer wrapper is Application [1] (tag 0x61).
        """
        if not data or data[0] != 0x61:
            # Try searching for the tag within first 16 bytes (VLAN tags, etc.)
            found = False
            for i in range(min(len(data), 16)):
                if data[i] == 0x61:
                    data = data[i:]
                    found = True
                    break
            if not found:
                return None

        # Skip outer tag + length
        offset = 1
        if offset >= len(data):
            return None
        outer_len_byte = data[offset]
        offset += 1
        if outer_len_byte & 0x80:   # Long-form length
            num_bytes = outer_len_byte & 0x7F
            offset += num_bytes

        result: Dict = {}
        while offset + 2 <= len(data):
            tag = data[offset]; offset += 1
            # Read length
            l_byte = data[offset]; offset += 1
            if l_byte & 0x80:
                n = l_byte & 0x7F
                if offset + n > len(data):
                    break
                val_len = int.from_bytes(data[offset:offset+n], "big")
                offset += n
            else:
                val_len = l_byte

            if offset + val_len > len(data):
                break
            val_bytes = data[offset:offset + val_len]
            offset += val_len

            if tag == TAG_GCB_REF:
                result["gcb_ref"]  = val_bytes.decode("latin-1", errors="replace").strip()
            elif tag == TAG_TTL:
                result["ttl_ms"]   = int.from_bytes(val_bytes, "big")
            elif tag == TAG_DAT_SET:
                result["dat_set"]  = val_bytes.decode("latin-1", errors="replace").strip()
            elif tag == TAG_GOOSE_ID:
                result["goose_id"] = val_bytes.decode("latin-1", errors="replace").strip()
            elif tag == TAG_ST_NUM:
                result["st_num"]   = int.from_bytes(val_bytes, "big")
            elif tag == TAG_SQ_NUM:
                result["sq_num"]   = int.from_bytes(val_bytes, "big")
            elif tag == TAG_SIMULATION:
                result["simulation"] = bool(val_bytes[0]) if val_bytes else False
            elif tag == TAG_CONF_REV:
                result["conf_rev"] = int.from_bytes(val_bytes, "big")
            elif tag == TAG_NDS_COM:
                result["nds_com"]  = bool(val_bytes[0]) if val_bytes else False
            elif tag == TAG_NUM_ENTRIES:
                result["num_entries"] = int.from_bytes(val_bytes, "big")
            elif tag == TAG_ALL_DATA:
                break   # don't need to parse individual data values

        return result if result else None


class SVAnalyzer(BaseL2Analyzer):
    """
    IEC 61850 Sampled Values (SV) Analyzer --- EtherType 0x88BA.
    SV carries high-frequency digitized current/voltage samples from
    instrument transformers.  Detection confirms IEC 61850 deployment.
    """

    def __init__(self):
        self._publishers: Dict[tuple, dict] = {}

    def get_sessions(self) -> Dict:
        return self._publishers

    def can_analyze_frame(self, eth_type: int, payload: bytes) -> bool:
        return eth_type == SV_ETHERTYPE and len(payload) >= 8

    def analyze_frame(
        self, src_mac, dst_mac, eth_type, payload, timestamp
    ) -> Optional[dict]:
        if not self.can_analyze_frame(eth_type, payload):
            return None
        app_id = struct.unpack_from(">H", payload, 0)[0]
        key    = (src_mac, app_id)
        if key not in self._publishers:
            self._publishers[key] = {
                "src_mac":     src_mac,
                "app_id":      f"0x{app_id:04X}",
                "first_seen":  timestamp,
                "packets":     0,
            }
        self._publishers[key]["packets"]  += 1
        self._publishers[key]["last_seen"] = timestamp
        return self._publishers[key]
