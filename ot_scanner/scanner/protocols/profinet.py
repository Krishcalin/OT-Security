"""
PROFINET Protocol Analyzer — DCP (Layer-2) + RT (IP-layer)

PROFINET is the industrial Ethernet standard of PROFIBUS International (PI)
and is used exclusively by Siemens and PI-certified devices:
  Siemens        (SIMATIC S7-1200/1500, ET 200SP/AL/MP, SCALANCE switches)
  Phoenix Contact (IL, AXL F series)
  Beckhoff       (EK9300 PROFINET coupler)
  Weidmuller     (u-remote)
  Festo          (CPX-AP series)
  Murrelektronik (Cube67, MVK Metal)
  WAGO           (750-375 PROFINET coupler)
  Turck          (TBEN modules)

Two sub-protocols are analyzed here:

1. PROFINET DCP (Discovery and Configuration Protocol)
   - EtherType: 0x8892 (Layer-2, no IP)
   - Used for device discovery, name assignment, and IP configuration
   - Frame ID 0xFEFD = Identify Multicast (request)
   - Frame ID 0xFEFE = Identify Response (contains Name of Station, vendor)
   - Frame ID 0xFEFF = Hello (device announcement)
   - Service IDs: 0x03=Get, 0x04=Set, 0x05=Identify

2. PROFINET RT (Real-Time)
   - Ports: TCP/UDP 34962 (RT_CLASS_1), 34963 (RT_CLASS_2), 34964 (RT_CLASS_3)
   - Used for cyclic I/O data exchange
   - Also EtherType 0x8892 with Frame IDs 0x0100-0x7FFF (cyclic) and
     0xC000-0xFBFF (acyclic RT)

DCP Block Types (Type.Subtype):
  0x0101  IP / MAC Address
  0x0102  IP / IP Parameter (IP, subnet, gateway)
  0x0201  Device / Name of Station
  0x0202  Device / Vendor (alias name or device vendor info)
  0x0203  Device / Device ID (VendorID + DeviceID)
  0x0204  Device / Device Role
  0x0205  Device / Device Options
  0x0206  Device / Alias Name
"""
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .base import BaseL2Analyzer, BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

# ── Layer-2 constants ──────────────────────────────────────────────────
PROFINET_ETHERTYPE = 0x8892

# DCP Frame IDs
FRAME_ID_IDENTIFY_REQ  = 0xFEFD   # Identify Multicast
FRAME_ID_IDENTIFY_RESP = 0xFEFE   # Identify Response
FRAME_ID_HELLO         = 0xFEFF   # Hello
FRAME_ID_GET_SET_BASE  = 0xFEFC   # Get/Set

DCP_FRAME_IDS = {FRAME_ID_IDENTIFY_REQ, FRAME_ID_IDENTIFY_RESP,
                 FRAME_ID_HELLO, FRAME_ID_GET_SET_BASE}

# DCP Service IDs
DCP_SVC_GET      = 0x03
DCP_SVC_SET      = 0x04
DCP_SVC_IDENTIFY = 0x05

DCP_SERVICE_NAMES: Dict[int, str] = {
    0x03: "Get",
    0x04: "Set",
    0x05: "Identify",
    0x06: "Hello",
}

# DCP Service Types
DCP_SVCTYPE_REQUEST  = 0x00
DCP_SVCTYPE_RESPONSE = 0x01

# DCP Block Type / Subtype combos (big-endian 2 bytes)
BLOCK_IP_MAC        = (0x01, 0x01)
BLOCK_IP_PARAM      = (0x01, 0x02)
BLOCK_DEV_NAME      = (0x02, 0x01)
BLOCK_DEV_VENDOR    = (0x02, 0x02)
BLOCK_DEV_DEVID     = (0x02, 0x03)
BLOCK_DEV_ROLE      = (0x02, 0x04)
BLOCK_DEV_OPTIONS   = (0x02, 0x05)
BLOCK_DEV_ALIAS     = (0x02, 0x06)

# Name of Station keywords -> vendor inference
DCP_VENDOR_HINTS: Dict[str, str] = {
    "siemens":       "Siemens",
    "simatic":       "Siemens",
    "scalance":      "Siemens",
    "et200":         "Siemens",
    "s7-":           "Siemens",
    "phoenix":       "Phoenix Contact",
    "fl-switch":     "Phoenix Contact",
    "axioline":      "Phoenix Contact",
    "beckhoff":      "Beckhoff",
    "ek9":           "Beckhoff",
    "weidmuller":    "Weidmuller",
    "u-remote":      "Weidmuller",
    "festo":         "Festo",
    "cpx-ap":        "Festo",
    "murr":          "Murrelektronik",
    "cube67":        "Murrelektronik",
    "wago":          "WAGO",
    "turck":         "Turck",
    "tben":          "Turck",
    "pilz":          "Pilz",
    "sick":          "SICK",
    "pepperl":       "Pepperl+Fuchs",
    "balluff":       "Balluff",
    "ifm":           "ifm electronic",
    "hirschmann":    "Hirschmann / Belden",
    "moxa":          "Moxa Technologies",
}

# PROFINET Device Role codes (from block 0x0204)
DEVICE_ROLES: Dict[int, str] = {
    0x01: "IO Device",
    0x02: "IO Controller",
    0x04: "IO Multidevice",
    0x08: "IO Supervisor",
}

# ── IP-layer constants (PROFINET RT on UDP/TCP) ───────────────────────
PROFINET_RT_PORT1 = 34962   # RT_CLASS_1 (UDP)
PROFINET_RT_PORT2 = 34963   # RT_CLASS_2 (UDP)
PROFINET_RT_PORT3 = 34964   # RT_CLASS_3 / CBA (TCP)

PROFINET_RT_PORTS = {PROFINET_RT_PORT1, PROFINET_RT_PORT2, PROFINET_RT_PORT3}

# Minimum DCP frame: FrameID(2) + ServiceID(1) + ServiceType(1) +
#                     Xid(4) + ResponseDelay(2) + DataLength(2) = 12 bytes
DCP_MIN_SIZE = 12


class ProfinetDCPAnalyzer(BaseL2Analyzer):
    """
    Passive analyzer for PROFINET DCP (Discovery and Configuration Protocol).

    Operates at Layer-2 (EtherType 0x8892) and extracts device identity
    from Identify Response frames: Name of Station, Vendor ID, Device ID,
    IP parameters, device role, and alias names.
    """

    def __init__(self):
        # Key: src_mac -> accumulated device info
        self._devices: Dict[str, dict] = {}

    def get_sessions(self) -> Dict:
        return self._devices

    def can_analyze_frame(self, eth_type: int, payload: bytes) -> bool:
        if eth_type != PROFINET_ETHERTYPE:
            return False
        if len(payload) < DCP_MIN_SIZE:
            return False
        # Check Frame ID is in DCP range (0xFEFC-0xFEFF)
        frame_id = struct.unpack_from(">H", payload, 0)[0]
        return frame_id in DCP_FRAME_IDS

    def analyze_frame(
        self,
        src_mac: str, dst_mac: str,
        eth_type: int, payload: bytes,
        timestamp: datetime,
    ) -> Optional[dict]:
        if not self.can_analyze_frame(eth_type, payload):
            return None

        frame_id = struct.unpack_from(">H", payload, 0)[0]
        service_id   = payload[2]
        service_type = payload[3]

        result: dict = {
            "src_mac":      src_mac,
            "dst_mac":      dst_mac,
            "frame_id":     f"0x{frame_id:04X}",
            "service_id":   DCP_SERVICE_NAMES.get(service_id, f"0x{service_id:02X}"),
            "service_type": "Response" if service_type == DCP_SVCTYPE_RESPONSE else "Request",
        }

        # Parse DCP data blocks (available in Identify Response and Hello)
        if frame_id in (FRAME_ID_IDENTIFY_RESP, FRAME_ID_HELLO):
            # Xid (4 bytes) + ResponseDelay (2 bytes) + DataLength (2 bytes)
            if len(payload) < DCP_MIN_SIZE:
                return result

            try:
                data_length = struct.unpack_from(">H", payload, 10)[0]
            except struct.error:
                return result

            block_data = payload[12: 12 + data_length]
            blocks = self._parse_dcp_blocks(block_data)
            if blocks:
                result.update(blocks)

                # Infer vendor from Name of Station
                name = blocks.get("name_of_station", "").lower()
                for hint, vendor in DCP_VENDOR_HINTS.items():
                    if hint in name:
                        result["inferred_vendor"] = vendor
                        break

        # Update session state
        if src_mac not in self._devices:
            self._devices[src_mac] = {
                "src_mac":    src_mac,
                "first_seen": timestamp,
                "packets":    0,
            }
        dev = self._devices[src_mac]
        dev["packets"]  += 1
        dev["last_seen"] = timestamp
        for key in ("name_of_station", "alias_name", "vendor_id", "device_id",
                     "device_role", "ip_address", "subnet_mask", "gateway",
                     "inferred_vendor"):
            if key in result:
                dev[key] = result[key]

        return result

    # ------------------------------------------------------------------ helpers

    def _parse_dcp_blocks(self, data: bytes) -> dict:
        """
        Parse DCP data blocks from an Identify Response or Hello frame.
        Each block: Option(1) + Suboption(1) + BlockLength(2) + BlockInfo(2) + value.
        Blocks are padded to even length.
        """
        result: dict = {}
        offset = 0

        while offset + 4 <= len(data):
            option    = data[offset]
            suboption = data[offset + 1]
            try:
                block_len = struct.unpack_from(">H", data, offset + 2)[0]
            except struct.error:
                break
            offset += 4

            if offset + block_len > len(data):
                break

            block_value = data[offset: offset + block_len]

            # Parse known block types
            if (option, suboption) == BLOCK_DEV_NAME and block_len >= 2:
                # BlockInfo (2 bytes) + Name of Station (ASCII)
                result["name_of_station"] = block_value[2:].decode(
                    "ascii", errors="replace"
                ).strip().rstrip("\x00")

            elif (option, suboption) == BLOCK_DEV_VENDOR and block_len >= 2:
                result["device_vendor_info"] = block_value[2:].decode(
                    "ascii", errors="replace"
                ).strip().rstrip("\x00")

            elif (option, suboption) == BLOCK_DEV_DEVID and block_len >= 6:
                # BlockInfo (2 bytes) + VendorID (2 bytes BE) + DeviceID (2 bytes BE)
                vendor_id = struct.unpack_from(">H", block_value, 2)[0]
                device_id = struct.unpack_from(">H", block_value, 4)[0]
                result["vendor_id"] = f"0x{vendor_id:04X}"
                result["device_id"] = f"0x{device_id:04X}"

            elif (option, suboption) == BLOCK_DEV_ROLE and block_len >= 4:
                # BlockInfo (2 bytes) + RoleDetails (1 byte) + reserved (1 byte)
                role_byte = block_value[2]
                roles: List[str] = []
                for bit, name in DEVICE_ROLES.items():
                    if role_byte & bit:
                        roles.append(name)
                result["device_role"] = ", ".join(roles) if roles else f"0x{role_byte:02X}"

            elif (option, suboption) == BLOCK_DEV_ALIAS and block_len >= 2:
                result["alias_name"] = block_value[2:].decode(
                    "ascii", errors="replace"
                ).strip().rstrip("\x00")

            elif (option, suboption) == BLOCK_IP_PARAM and block_len >= 14:
                # BlockInfo (2 bytes) + IP (4) + Subnet (4) + Gateway (4)
                ip_bytes = block_value[2:6]
                sn_bytes = block_value[6:10]
                gw_bytes = block_value[10:14]
                result["ip_address"]  = ".".join(str(b) for b in ip_bytes)
                result["subnet_mask"] = ".".join(str(b) for b in sn_bytes)
                result["gateway"]     = ".".join(str(b) for b in gw_bytes)

            elif (option, suboption) == BLOCK_IP_MAC and block_len >= 8:
                # BlockInfo (2 bytes) + MAC (6 bytes)
                mac_bytes = block_value[2:8]
                result["device_mac"] = ":".join(f"{b:02X}" for b in mac_bytes)

            # Advance offset — blocks are padded to even length
            padded_len = block_len + (block_len % 2)
            offset += padded_len

        return result


class ProfinetRTAnalyzer(BaseProtocolAnalyzer):
    """
    Passive analyzer for PROFINET RT (Real-Time) over UDP/TCP.

    Detects cyclic and acyclic PROFINET RT communication on ports
    34962 (RT_CLASS_1), 34963 (RT_CLASS_2), and 34964 (RT_CLASS_3/CBA).
    """

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        return sport in PROFINET_RT_PORTS or dport in PROFINET_RT_PORTS

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        is_server_src = sport in PROFINET_RT_PORTS
        device_ip = src_ip if is_server_src else dst_ip
        port_used = sport if is_server_src else dport

        # Determine RT class from port
        rt_class = {
            PROFINET_RT_PORT1: "RT_CLASS_1",
            PROFINET_RT_PORT2: "RT_CLASS_2",
            PROFINET_RT_PORT3: "RT_CLASS_3 / CBA",
        }.get(port_used, "Unknown")

        transport = "TCP" if port_used == PROFINET_RT_PORT3 else "UDP"

        details: dict = {
            "rt_class":  rt_class,
            "direction": "response" if is_server_src else "request",
        }

        # If payload starts with a valid PROFINET frame ID we can raise confidence
        confidence = "medium"
        if len(payload) >= 2:
            frame_id = struct.unpack_from(">H", payload, 0)[0]
            if 0x0100 <= frame_id <= 0x7FFF:
                details["frame_id"] = f"0x{frame_id:04X}"
                details["frame_type"] = "Cyclic RT"
                confidence = "high"
            elif 0xC000 <= frame_id <= 0xFBFF:
                details["frame_id"] = f"0x{frame_id:04X}"
                details["frame_type"] = "Acyclic RT"
                confidence = "high"

        detection = self._make_detection(
            protocol="PROFINET RT",
            port=port_used,
            confidence=confidence,
            timestamp=timestamp,
            transport=transport,
            vendor="Siemens / PI",
            **details,
        )
        return [(device_ip, detection)]
