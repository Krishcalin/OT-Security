"""
SEL (Schweitzer Engineering Laboratories) Protocol Analyzer
Port: TCP 702 (SEL MIRRORED BITS / Fast Meter / Fast Operate)

SEL RTUs and protective relays (SEL-3505, SEL-3530, SEL-651R, SEL-421,
SEL-311C, etc.) communicate using Schweitzer's proprietary binary protocols:

  Fast Meter    --- high-speed metering data (analog measurements, status bits)
  Fast Operate  --- control commands (open/close breaker, assert bits)
  Fast SER      --- Sequential Events Recorder data
  Mirrored Bits --- peer-to-peer status mirroring (often over fiber/serial)

TCP port 702 is the standard SEL Fast Message port.
Some variants use ports 23 (telnet), 2404 (may coexist with IEC-104), or others.

Binary Frame:
  SOH (0x01) : 1 byte  --- start of header
  Dev ID     : 2 bytes --- SEL device address
  Status     : 2 bytes
  CMD        : 1 byte  --- command byte
  LEN        : 1 byte  --- message length
  Data       : variable
  CRC        : 2 bytes

SEL Fast Meter Command Codes:
  0xA5 --- Fast Meter Configuration (identify meter channels)
  0xA6 --- Fast Meter Data
  0xAE --- Fast Operate Status
  0xB0 --- Fast Operate Command    <- control command
  0xC0 --- Fast SER Request
  0xC4 --- Fast SER Data

Because SEL devices are always SEL-brand, detection of this protocol
provides high-confidence vendor identification.
"""
import struct
from datetime import datetime
from typing import Dict, Optional

from .base import BaseProtocolAnalyzer, AnalysisResult

SEL_PORT = 702

SEL_SOH = 0x01

SEL_COMMANDS: Dict[int, str] = {
    0xA5: "Fast Meter Configuration",
    0xA6: "Fast Meter Data",
    0xAB: "Fast Meter (2nd msg)",
    0xAE: "Fast Operate Status",
    0xB0: "Fast Operate Command",
    0xB5: "Fast Operate (2nd)",
    0xC0: "Fast SER Request",
    0xC4: "Fast SER Data",
    0xD0: "Fast Operate (unsol.)",
    0x40: "DNA/Relay Word Request",
}

# SEL device model hints from Device ID ranges
SEL_DEVICE_HINTS = {
    (300, 399):  "SEL-3xx Series Relay",
    (400, 499):  "SEL-4xx Series Relay",
    (651, 651):  "SEL-651R (Feeder Protection Relay)",
    (700, 799):  "SEL-7xx Series",
    (311, 311):  "SEL-311C (Line Current Differential)",
    (421, 421):  "SEL-421 (Line Protection)",
    (487, 487):  "SEL-487B (Bus Protection)",
    (3505, 3505): "SEL-3505 RTU",
    (3530, 3530): "SEL-3530 RTU",
}


class SELProtocolAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport: int, dport: int, proto: str, payload: bytes) -> bool:
        if proto != "TCP":
            return False
        if sport != SEL_PORT and dport != SEL_PORT:
            return False
        if len(payload) < 6:
            return False
        return payload[0] == SEL_SOH

    def analyze(
        self, src_ip, dst_ip, sport, dport, proto, payload, timestamp
    ) -> Optional[AnalysisResult]:
        frame = self._parse_frame(payload)
        if frame is None:
            return None

        device_id, cmd, data = frame
        device_ip = dst_ip if dport == SEL_PORT else src_ip

        cmd_name = SEL_COMMANDS.get(cmd, f"0x{cmd:02X}")
        model    = self._guess_model(device_id)

        details: Dict = {
            "sel_device_id": device_id,
            "sel_command":   cmd_name,
            "vendor":        "Schweitzer Engineering Laboratories (SEL)",
        }
        if model:
            details["device_model_hint"] = model

        # Fast Operate Command is a control action --- noteworthy
        if cmd == 0xB0:
            details["is_control_command"] = True

        det = self._make_detection(
            protocol="SEL Fast Message",
            port=SEL_PORT,
            confidence="high",
            timestamp=timestamp,
            **details,
        )
        return [(device_ip, det)]

    def _parse_frame(self, payload: bytes):
        """Parse SEL Fast Message binary frame."""
        if payload[0] != SEL_SOH:
            return None
        if len(payload) < 6:
            return None
        try:
            dev_id = struct.unpack_from(">H", payload, 1)[0]
            # status (2 bytes), cmd (1 byte), length (1 byte)
            cmd    = payload[5]
        except (struct.error, IndexError):
            return None
        data = payload[6:]
        return dev_id, cmd, data

    def _guess_model(self, device_id: int) -> Optional[str]:
        for (lo, hi), model in SEL_DEVICE_HINTS.items():
            if lo <= device_id <= hi:
                return model
        return None
