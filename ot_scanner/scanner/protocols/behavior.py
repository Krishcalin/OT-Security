"""
Protocol Behavior Tracker  (post-processing step)

Analyses accumulated ProtocolDetection data on each OTDevice and computes
ProtocolStats --- read/write ratios, function code distributions, and
behavioural flags (program upload/download, firmware update, config change).

This module is called AFTER packet processing is complete.  It works with
the merged ProtocolDetection objects attached to each device, extracting
whatever detail keys the individual protocol analyzers populated.

Supported protocol-specific analysis:
  Modbus/TCP        — function code classification (read/write/control/diag)
  S7comm            — ROSCTR types, SZL reads, program transfer detection
  DNP3              — application FC groups (read/write/control/file/SA)
  IEC 60870-5-104   — ASDU type ID groups (monitoring/control/system)
  EtherNet/IP       — EIP command tracking, session analysis
  OPC-UA            — message type tracking, security policy detection
  Omron FINS        — command classification
  MELSEC MC         — command classification
  SEL Fast Message  — control command detection
  BACnet/IP         — APDU type and service tracking
  MQTT              — packet type tracking, auth status
"""
from typing import Dict, List, Optional

from ..models import OTDevice, ProtocolStats, ProtocolDetection


class BehaviorAnalyzer:
    """
    Post-processing analyzer that builds ProtocolStats for every protocol
    detected on an OTDevice.

    Usage:
        analyzer = BehaviorAnalyzer()
        for device in discovered_devices:
            stats = analyzer.analyze_device(device)
            device.protocol_stats = stats
    """

    # ── Modbus function code classification ──────────────────────────────
    _MODBUS_READ_FCS    = {0x01, 0x02, 0x03, 0x04}
    _MODBUS_WRITE_FCS   = {0x05, 0x06, 0x0F, 0x10, 0x16, 0x17}
    _MODBUS_CONTROL_FCS = {0x05, 0x0F}       # Coil writes = actuation
    _MODBUS_DIAG_FCS    = {0x08, 0x11}       # Diagnostics, Report Server ID
    _MODBUS_FILE_READ   = 0x14               # Read File Record
    _MODBUS_FILE_WRITE  = 0x15               # Write File Record

    # ── DNP3 function code groups ────────────────────────────────────────
    _DNP3_READ_FCS     = {0x01}              # Read
    _DNP3_WRITE_FCS    = {0x02}              # Write
    _DNP3_CONTROL_FCS  = {0x03, 0x04, 0x05, 0x06}  # Select, Operate, Direct Op
    _DNP3_DIAG_FCS     = {0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13}
    _DNP3_FILE_FCS     = {0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}

    # ── IEC 104 type ID groups ───────────────────────────────────────────
    _IEC104_MONITORING_RANGE = range(1, 41)       # Type 1-40: monitoring
    _IEC104_CONTROL_IDS      = {45, 46, 47, 48, 49, 50, 51, 58, 59}
    _IEC104_SYSTEM_IDS       = {70, 100, 101, 103, 105, 107}
    _IEC104_CLOCK_SYNC       = 103

    # ── Public API ───────────────────────────────────────────────────────

    def analyze_device(self, device: OTDevice) -> List[ProtocolStats]:
        """Compute behaviour stats for all protocols on a device."""
        stats: List[ProtocolStats] = []

        for proto_det in device.protocols:
            proto_name = proto_det.protocol
            handler = self._get_handler(proto_name)
            if handler is not None:
                ps = handler(proto_det)
            else:
                ps = self._generic_stats(proto_det)
            stats.append(ps)

        return stats

    # ── Handler dispatch ─────────────────────────────────────────────────

    def _get_handler(self, proto_name: str):
        """Return a protocol-specific handler or None for generic."""
        _map = {
            "Modbus/TCP":         self._modbus_stats,
            "S7comm":             self._s7comm_stats,
            "S7comm+":            self._s7comm_stats,
            "DNP3":               self._dnp3_stats,
            "IEC 60870-5-104":    self._iec104_stats,
            "EtherNet/IP":        self._enip_stats,
            "OPC-UA":             self._opcua_stats,
            "Omron FINS":         self._fins_stats,
            "MELSEC MC Protocol": self._melsec_stats,
            "SEL Fast Message":   self._sel_stats,
            "BACnet/IP":          self._bacnet_stats,
            "MQTT":               self._mqtt_stats,
        }
        return _map.get(proto_name)

    # ── Protocol-specific analyzers ──────────────────────────────────────

    def _modbus_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        Modbus/TCP behaviour analysis.

        Detail keys used:
          function_code  — "0x03", "0x10", etc.
          function_name  — human-readable name
        """
        ps = self._base_stats(det)
        fc_val = self._parse_fc_hex(det.details.get("function_code"))
        fc_name = det.details.get("function_name", "")

        if fc_val is not None:
            label = f"0x{fc_val:02X} {fc_name}".strip()
            ps.function_codes[label] = ps.function_codes.get(label, 0) + det.packet_count

            if fc_val in self._MODBUS_READ_FCS:
                ps.read_count += det.packet_count
            if fc_val in self._MODBUS_WRITE_FCS:
                ps.write_count += det.packet_count
            if fc_val in self._MODBUS_CONTROL_FCS:
                ps.control_count += det.packet_count
            if fc_val in self._MODBUS_DIAG_FCS:
                ps.diagnostic_count += det.packet_count
            if fc_val == self._MODBUS_FILE_READ:
                ps.has_program_upload = True
            if fc_val == self._MODBUS_FILE_WRITE:
                ps.has_program_download = True

        # Track unit_id as an address
        unit_id = det.details.get("unit_id")
        if unit_id is not None:
            ps.unique_addresses.add(f"unit:{unit_id}")

        return ps

    def _s7comm_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        S7comm / S7comm+ behaviour analysis.

        Detail keys used:
          s7_rosctr      — "Job", "Ack-Data", "Userdata", etc.
          s7_function    — "Read SZL (System Status List)", etc.
          szl_id         — "0x0011", etc.
          szl_name       — human-readable SZL name
        """
        ps = self._base_stats(det)
        rosctr = det.details.get("s7_rosctr", "")
        s7_func = det.details.get("s7_function", "")
        szl_id = det.details.get("szl_id", "")

        if rosctr:
            ps.function_codes[rosctr] = ps.function_codes.get(rosctr, 0) + det.packet_count

        # Job with SZL reads -> read operations
        if rosctr == "Job" and "Read SZL" in s7_func:
            ps.read_count += det.packet_count
        elif rosctr == "Job":
            # Generic Job --- could be read or write; count conservatively
            ps.read_count += det.packet_count
        elif rosctr == "Ack-Data":
            ps.read_count += det.packet_count

        # Program upload/download detection via SZL component identification
        if szl_id == "0x001C":
            # Component identification SZL --- reading is fingerprinting,
            # writing would be a config change
            ps.has_config_change = True

        # Userdata with high PDU references may indicate program transfer
        if rosctr == "Userdata":
            ps.diagnostic_count += det.packet_count

        # Track SZL IDs as addressed data points
        if szl_id:
            ps.unique_addresses.add(f"szl:{szl_id}")

        # Track rack/slot
        rack = det.details.get("rack")
        slot = det.details.get("slot")
        if rack is not None and slot is not None:
            ps.unique_addresses.add(f"rack:{rack}/slot:{slot}")

        return ps

    def _dnp3_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        DNP3 behaviour analysis.

        Detail keys used:
          app_fc       — "0x01", "0x05", etc.
          app_fc_name  — "Read", "Direct Operate", etc.
          dest_addr    — DNP3 destination address (int)
          src_addr     — DNP3 source address (int)
        """
        ps = self._base_stats(det)
        fc_val = self._parse_fc_hex(det.details.get("app_fc"))
        fc_name = det.details.get("app_fc_name", "")

        if fc_val is not None:
            label = f"0x{fc_val:02X} {fc_name}".strip()
            ps.function_codes[label] = ps.function_codes.get(label, 0) + det.packet_count

            if fc_val in self._DNP3_READ_FCS:
                ps.read_count += det.packet_count
            if fc_val in self._DNP3_WRITE_FCS:
                ps.write_count += det.packet_count
            if fc_val in self._DNP3_CONTROL_FCS:
                ps.control_count += det.packet_count
            if fc_val in self._DNP3_DIAG_FCS:
                ps.diagnostic_count += det.packet_count
            if fc_val in self._DNP3_FILE_FCS:
                ps.has_firmware_update = True
                # Read File Record -> upload; Write File Record -> download
                if fc_val in (0x19, 0x1A, 0x1C, 0x1D):
                    ps.has_program_upload = True
                if fc_val in (0x1B, 0x1F):
                    ps.has_program_download = True

        # Track unique DNP3 address pairs
        dest_addr = det.details.get("dest_addr")
        src_addr = det.details.get("src_addr")
        if dest_addr is not None:
            ps.unique_addresses.add(f"dnp3_dst:{dest_addr}")
        if src_addr is not None:
            ps.unique_addresses.add(f"dnp3_src:{src_addr}")

        return ps

    def _iec104_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        IEC 60870-5-104 behaviour analysis.

        Detail keys used:
          type_id          — ASDU type ID (int)
          type_name        — human-readable type name
          common_address   — common address of ASDU (int)
          is_control       — bool flag for control type IDs
          frame_type       — "I-frame", "S-frame", "U-frame"
        """
        ps = self._base_stats(det)
        type_id = det.details.get("type_id")
        type_name = det.details.get("type_name", "")
        frame_type = det.details.get("frame_type", "")

        if frame_type:
            ps.function_codes[frame_type] = (
                ps.function_codes.get(frame_type, 0) + det.packet_count
            )

        if type_id is not None:
            try:
                tid = int(type_id)
            except (TypeError, ValueError):
                tid = None

            if tid is not None:
                label = f"TypeID {tid} {type_name}".strip()
                ps.function_codes[label] = ps.function_codes.get(label, 0) + det.packet_count

                # Monitoring types (1-40)
                if tid in self._IEC104_MONITORING_RANGE:
                    ps.read_count += det.packet_count
                # Control types (45-51, 58-59)
                if tid in self._IEC104_CONTROL_IDS:
                    ps.control_count += det.packet_count
                    ps.write_count += det.packet_count
                # System types (70, 100-107)
                if tid in self._IEC104_SYSTEM_IDS:
                    ps.diagnostic_count += det.packet_count
                # Clock sync -> config change
                if tid == self._IEC104_CLOCK_SYNC:
                    ps.has_config_change = True

        # Track unique common addresses
        ca = det.details.get("common_address")
        if ca is not None:
            ps.unique_addresses.add(f"ca:{ca}")

        return ps

    def _enip_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        EtherNet/IP behaviour analysis.

        Detail keys used:
          eip_command       — "0x0063", etc.
          eip_command_name  — "ListIdentity", "SendRRData", etc.
          session_handle    — EIP session handle (hex string)
        """
        ps = self._base_stats(det)
        cmd_name = det.details.get("eip_command_name", "")
        cmd_hex = det.details.get("eip_command", "")

        if cmd_name:
            ps.function_codes[cmd_name] = (
                ps.function_codes.get(cmd_name, 0) + det.packet_count
            )

        # Classify commands
        if cmd_name in ("ListIdentity", "ListServices", "ListInterfaces",
                        "RegisterSession", "UnRegisterSession"):
            ps.diagnostic_count += det.packet_count
        elif cmd_name == "SendRRData":
            # Explicit messaging --- typically reads (could be writes)
            ps.read_count += det.packet_count
        elif cmd_name == "SendUnitData":
            # Implicit / connected messaging --- typically I/O (mixed read/write)
            ps.read_count += det.packet_count

        # Track unique session handles
        session_handle = det.details.get("session_handle")
        if session_handle and session_handle != "0x00000000":
            ps.unique_addresses.add(f"session:{session_handle}")

        return ps

    def _opcua_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        OPC-UA behaviour analysis.

        Detail keys used:
          message_type        — "Hello", "SecureMessage", "OpenSecureChannel", etc.
          security_policy_uri — the policy URI string
          security_none       — True if insecure policy
        """
        ps = self._base_stats(det)
        msg_type = det.details.get("message_type", "")

        if msg_type:
            ps.function_codes[msg_type] = (
                ps.function_codes.get(msg_type, 0) + det.packet_count
            )

        # Classify by message type
        if msg_type == "SecureMessage":
            # Could be reads or writes --- count as reads conservatively
            ps.read_count += det.packet_count
        elif msg_type in ("Hello", "Acknowledge", "OpenSecureChannel",
                          "CloseSecureChannel", "Error"):
            ps.diagnostic_count += det.packet_count

        # Flag insecure security policy
        if det.details.get("security_none"):
            ps.has_config_change = True  # security misconfiguration worth noting

        # Track endpoint URLs
        endpoint = det.details.get("endpoint_url")
        if endpoint:
            ps.unique_addresses.add(f"endpoint:{endpoint}")

        return ps

    def _fins_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        Omron FINS behaviour analysis.

        Detail keys used:
          fins_command  — human-readable command name
          direction     — "request" / "response"
          dest_node     — FINS destination node (int)
        """
        ps = self._base_stats(det)
        cmd = det.details.get("fins_command", "")

        if cmd:
            ps.function_codes[cmd] = ps.function_codes.get(cmd, 0) + det.packet_count

        # Classify based on common FINS command names
        cmd_lower = cmd.lower()
        if "read" in cmd_lower or "memory area read" in cmd_lower:
            ps.read_count += det.packet_count
        elif "write" in cmd_lower or "memory area write" in cmd_lower:
            ps.write_count += det.packet_count
        elif "controller data read" in cmd_lower:
            ps.read_count += det.packet_count
            ps.diagnostic_count += det.packet_count

        # Track dest nodes
        dest_node = det.details.get("dest_node")
        if dest_node is not None:
            ps.unique_addresses.add(f"fins_node:{dest_node}")

        return ps

    def _melsec_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        Mitsubishi MELSEC MC Protocol behaviour analysis.

        Detail keys used:
          melsec_command  — human-readable command name
          station_no      — station number (int)
        """
        ps = self._base_stats(det)
        cmd = det.details.get("melsec_command", "")

        if cmd:
            ps.function_codes[cmd] = ps.function_codes.get(cmd, 0) + det.packet_count

        cmd_lower = cmd.lower()
        if "read" in cmd_lower or "batch read" in cmd_lower:
            ps.read_count += det.packet_count
        elif "write" in cmd_lower or "batch write" in cmd_lower:
            ps.write_count += det.packet_count
        elif "cpu type" in cmd_lower:
            ps.diagnostic_count += det.packet_count

        # Track stations
        station = det.details.get("station_no")
        if station is not None:
            ps.unique_addresses.add(f"melsec_station:{station}")

        return ps

    def _sel_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        SEL Fast Message behaviour analysis.

        Detail keys used:
          sel_command        — human-readable command name
          sel_device_id      — device ID (int)
          is_control_command — True for Fast Operate commands
        """
        ps = self._base_stats(det)
        cmd = det.details.get("sel_command", "")

        if cmd:
            ps.function_codes[cmd] = ps.function_codes.get(cmd, 0) + det.packet_count

        if det.details.get("is_control_command"):
            ps.control_count += det.packet_count
            ps.write_count += det.packet_count
        else:
            ps.read_count += det.packet_count

        # Track device IDs
        dev_id = det.details.get("sel_device_id")
        if dev_id is not None:
            ps.unique_addresses.add(f"sel_dev:{dev_id}")

        return ps

    def _bacnet_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        BACnet/IP behaviour analysis.

        Detail keys used:
          bvlc_function     — BVLC function name
          apdu_type         — "Confirmed-Request", "Unconfirmed-Request", etc.
          service_choice    — BACnet service name
        """
        ps = self._base_stats(det)
        apdu_type = det.details.get("apdu_type", "")
        bvlc_func = det.details.get("bvlc_function", "")
        service = det.details.get("service_choice", "")

        if apdu_type:
            ps.function_codes[apdu_type] = (
                ps.function_codes.get(apdu_type, 0) + det.packet_count
            )

        if service:
            ps.function_codes[service] = (
                ps.function_codes.get(service, 0) + det.packet_count
            )

        # Classify by service name
        svc_lower = service.lower()
        if "read" in svc_lower or "i-am" in apdu_type.lower():
            ps.read_count += det.packet_count
        elif "write" in svc_lower:
            ps.write_count += det.packet_count
        elif "who-is" in svc_lower or "i-am" in svc_lower:
            ps.diagnostic_count += det.packet_count

        return ps

    def _mqtt_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """
        MQTT behaviour analysis.

        Detail keys used:
          packet_type       — "CONNECT", "PUBLISH", "SUBSCRIBE", etc.
          no_authentication — True if no auth
          topic             — MQTT topic string
        """
        ps = self._base_stats(det)
        pkt_type = det.details.get("packet_type", "")

        if pkt_type:
            ps.function_codes[pkt_type] = (
                ps.function_codes.get(pkt_type, 0) + det.packet_count
            )

        pkt_lower = pkt_type.lower()
        if "publish" in pkt_lower:
            ps.write_count += det.packet_count
        elif "subscribe" in pkt_lower:
            ps.read_count += det.packet_count
        elif pkt_lower in ("connect", "connack", "pingreq", "pingresp", "disconnect"):
            ps.diagnostic_count += det.packet_count

        # Flag unauthenticated connections
        if det.details.get("no_authentication"):
            ps.has_config_change = True  # security concern

        # Track topics
        topic = det.details.get("topic")
        if topic:
            ps.unique_addresses.add(f"topic:{topic}")

        return ps

    # ── Generic / shared helpers ─────────────────────────────────────────

    def _generic_stats(self, det: ProtocolDetection) -> ProtocolStats:
        """Fallback stats for protocols without a dedicated handler."""
        ps = self._base_stats(det)
        # Record whatever function-like detail keys exist
        for key in ("function_code", "command", "packet_type", "message_type"):
            val = det.details.get(key)
            if val:
                ps.function_codes[str(val)] = (
                    ps.function_codes.get(str(val), 0) + det.packet_count
                )
        return ps

    @staticmethod
    def _base_stats(det: ProtocolDetection) -> ProtocolStats:
        """Create a ProtocolStats object with common fields populated."""
        return ProtocolStats(
            protocol=det.protocol,
            total_packets=det.packet_count,
        )

    @staticmethod
    def _parse_fc_hex(fc_str: Optional[str]) -> Optional[int]:
        """
        Parse a function code hex string like "0x03" or "0x10 (error)" to int.
        Returns None if parsing fails.
        """
        if not fc_str:
            return None
        try:
            # Strip trailing annotation like " (error)"
            clean = fc_str.split()[0] if " " in fc_str else fc_str
            return int(clean, 16)
        except (ValueError, TypeError):
            return None
