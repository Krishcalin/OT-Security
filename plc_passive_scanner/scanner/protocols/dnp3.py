"""
DNP3 (Distributed Network Protocol 3) Analyzer
Ports: TCP 20000, UDP 20000

DNP3 is widely used in electric utilities, oil & gas, and water/wastewater.
Common vendors: ABB, Honeywell, Schneider Electric (Easergy / SCADAPack),
                GE Power Management, SEL (Schweitzer Engineering Labs)

Frame structure:
  Start bytes : 0x0564         (2 bytes — sync word)
  Length      : 1 byte         (number of bytes from Control to end of frame, incl CRC)
  Control     : 1 byte
  Destination : 2 bytes LE
  Source      : 2 bytes LE
  CRC         : 2 bytes        (covers bytes 2-9)
  Data blocks : up to 16 bytes + 2 CRC each

Application layer (after Transport Function byte):
  AC (Application Control) : 1 byte
  FC (Function Code)        : 1 byte
  Objects…
"""
import struct
from datetime import datetime
from typing import Optional

from .base import BaseProtocolAnalyzer, AnalysisResult
from ..models import ProtocolDetection

DNP3_PORT  = 20000
DNP3_SYNC  = 0x6405   # 0x0564 stored little-endian as 16-bit int → bytes 05 64

# DNP3 Application Layer Function Codes
DNP3_FC = {
    0x00: "Confirm",
    0x01: "Read",
    0x02: "Write",
    0x03: "Select",
    0x04: "Operate",
    0x05: "Direct Operate",
    0x06: "Direct Operate – No Ack",
    0x07: "Imm. Freeze",
    0x08: "Imm. Freeze – No Ack",
    0x0D: "Cold Restart",
    0x0E: "Warm Restart",
    0x0F: "Initialize Data",
    0x10: "Initialize Application",
    0x11: "Start Application",
    0x12: "Stop Application",
    0x13: "Save Configuration",
    0x14: "Enable Unsolicited",
    0x15: "Disable Unsolicited",
    0x16: "Assign Class",
    0x17: "Delay Measurement",
    0x81: "Response",
    0x82: "Unsolicited Response",
    0x83: "Authentication Challenge",
    0x84: "Authentication Reply",
}

# DNP3 Control field bits
CTRL_DIR = 0x80   # Direction (1=master->outstation)
CTRL_PRM = 0x40   # Primary message
CTRL_FCB = 0x20   # Frame Count Bit
CTRL_FCV = 0x10   # Frame Count Valid
CTRL_FC  = 0x0F   # Function Code mask

# Data Link FC codes
DL_FC = {
    0x00: "RESET_LINK",
    0x01: "RESET_PROCESS",
    0x02: "TEST_LINK",
    0x03: "USER_DATA_CONFIRM",
    0x04: "USER_DATA_NOCONFIRM",
    0x09: "REQUEST_STATUS",
    0x0B: "LINK_STATUS",
    0x0D: "NOT_SUPPORTED",
    0x0E: "ACK",
    0x0F: "NAK",
}


class DNP3Analyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if sport != DNP3_PORT and dport != DNP3_PORT:
            return False
        if len(payload) < 10:
            return False
        # Quick sync-word check (bytes 0-1 == 0x05 0x64)
        return payload[0] == 0x05 and payload[1] == 0x64

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        frame = self._parse_dl_frame(payload)
        if frame is None:
            return None

        device_ip = dst_ip if dport == DNP3_PORT else src_ip
        ctrl, dest_addr, src_addr, data_bytes = frame

        is_master  = bool(ctrl & CTRL_DIR)
        dl_fc_code = ctrl & CTRL_FC
        dl_fc_name = DL_FC.get(dl_fc_code, f"0x{dl_fc_code:02X}")

        details: dict = {
            "dl_function": dl_fc_name,
            "dnp3_src_address":  src_addr,
            "dnp3_dest_address": dest_addr,
            "role": "Master" if is_master else "Outstation",
        }

        confidence = "high"

        # Try to parse application layer
        if data_bytes:
            al = self._parse_app_layer(data_bytes)
            if al:
                details.update(al)

        # If this is an outstation (the PLC/RTU side), adjust device IP
        if is_master:
            device_ip = dst_ip   # Master sends TO the outstation
        else:
            device_ip = src_ip   # Outstation is the sender

        detection = self._make_detection(
            protocol="DNP3",
            port=DNP3_PORT,
            confidence=confidence,
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, detection)]

    # ------------------------------------------------------------------ helpers

    def _parse_dl_frame(self, payload: bytes):
        """
        Parse DNP3 Data Link Layer frame.
        Returns (control_byte, dest_addr, src_addr, user_data) or None.
        """
        if len(payload) < 10:
            return None
        if payload[0] != 0x05 or payload[1] != 0x64:
            return None

        length  = payload[2]           # Number of bytes from Control field to end
        control = payload[3]
        dest    = struct.unpack_from("<H", payload, 4)[0]
        src     = struct.unpack_from("<H", payload, 6)[0]
        # bytes 8-9 = CRC of header

        # User data starts at byte 10
        user_data = payload[10:]

        # Basic sanity: length byte should be >= 5 (Control + Dest + Src + CRC = 5)
        if length < 5:
            return None

        return control, dest, src, user_data

    def _parse_app_layer(self, data: bytes) -> Optional[dict]:
        """
        Parse DNP3 Application Layer.
        data[0] = Transport Function byte (FIR/FIN flags + seq)
        data[1] = Application Control byte
        data[2] = Function Code
        """
        if len(data) < 3:
            return None

        # Transport Function: bit7=FIN, bit6=FIR, bits0-5=sequence
        transport = data[0]
        fin = bool(transport & 0x80)
        fir = bool(transport & 0x40)
        seq = transport & 0x3F

        ac   = data[1]    # Application Control
        fc   = data[2]    # Function Code
        fc_name = DNP3_FC.get(fc, f"0x{fc:02X}")

        result = {
            "app_function_code": f"0x{fc:02X}",
            "app_function_name": fc_name,
        }

        # Check for device attributes (Group 0) in READ request/response
        # which may contain device name, firmware, etc.
        if fc in (0x01, 0x81) and len(data) > 3:
            objects = self._scan_for_device_attrs(data[3:])
            if objects:
                result.update(objects)

        return result

    def _scan_for_device_attrs(self, data: bytes) -> dict:
        """
        Scan for Group 0 (Device Attributes) objects in the data.
        Group 0 Variation 242 = Product Name & Model
        Group 0 Variation 243 = Firmware Version
        Group 0 Variation 245 = Vendor Name
        """
        result = {}
        i = 0
        while i + 3 <= len(data):
            group     = data[i]
            variation = data[i + 1]
            qualifier = data[i + 2]
            i += 3

            if group == 0:      # Device Attributes
                # The qualifier code tells us how to read the object
                if qualifier == 0x00 and i + 2 <= len(data):
                    attr_type = data[i]
                    attr_len  = data[i + 1] if i + 1 < len(data) else 0
                    i += 2
                    if i + attr_len <= len(data):
                        raw = data[i: i + attr_len]
                        try:
                            text = raw.decode("latin-1", errors="replace").strip()
                        except Exception:
                            text = raw.hex()
                        i += attr_len

                        if variation == 242:
                            result["product_model"] = text
                        elif variation == 243:
                            result["firmware_version"] = text
                        elif variation == 245:
                            result["vendor_name"] = text
                        continue
            # Unknown object — stop parsing cleanly
            break

        return result
