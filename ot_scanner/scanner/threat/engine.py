"""
Threat Detection Engine for the OT Passive Scanner.

Generates behavioral baselines from observed traffic, detects anomalies,
matches ICS malware signatures, and maps all detections to MITRE ATT&CK
for ICS techniques.

Detection modules:
  1. Baseline anomaly detection  — statistical outliers in traffic patterns
  2. ICS malware signatures      — known attack tool behavior matching
  3. Reconnaissance detection    — scanning and enumeration patterns
  4. Unauthorized command detection — dangerous commands from unexpected sources

Zero external dependencies — uses only Python stdlib.
"""

import logging
from collections import defaultdict
from statistics import median
from typing import Dict, List, Optional, Set, Tuple

from ..models import (
    CommFlow,
    NetworkZone,
    OTDevice,
    ThreatAlert,
    TopologyEdge,
)
from .signatures import ICS_MALWARE_SIGNATURES

logger = logging.getLogger(__name__)


class ThreatDetectionEngine:
    """
    Behavioral analysis and threat detection for OT/ICS networks.

    Usage::

        engine = ThreatDetectionEngine(devices, flows, zones, edges,
                                       dnp3_sessions, iec104_sessions,
                                       goose_publishers)
        alerts_by_ip = engine.analyze()
    """

    def __init__(
        self,
        devices: List[OTDevice],
        flows: List[CommFlow],
        zones: List[NetworkZone],
        edges: List[TopologyEdge],
        dnp3_sessions: Optional[Dict] = None,
        iec104_sessions: Optional[Dict] = None,
        goose_publishers: Optional[Dict] = None,
    ) -> None:
        self._devices = devices
        self._flows = flows
        self._zones = zones
        self._edges = edges
        self._dnp3_sessions = dnp3_sessions or {}
        self._iec104_sessions = iec104_sessions or {}
        self._goose_publishers = goose_publishers or {}

        # Lookups
        self._device_map: Dict[str, OTDevice] = {d.ip: d for d in devices}
        self._ip_to_zone: Dict[str, NetworkZone] = {}
        self._zone_map: Dict[str, NetworkZone] = {}
        for z in zones:
            self._zone_map[z.zone_id] = z
            for ip in z.device_ips:
                self._ip_to_zone[ip] = z

        # Flow index: dst_ip -> list of flows
        self._flows_to: Dict[str, List[CommFlow]] = defaultdict(list)
        self._flows_from: Dict[str, List[CommFlow]] = defaultdict(list)
        for f in flows:
            self._flows_to[f.dst_ip].append(f)
            self._flows_from[f.src_ip].append(f)

    # ── public API ───────────────────────────────────────────────────

    def analyze(self) -> Dict[str, List[ThreatAlert]]:
        """
        Run all detection modules and return alerts grouped by device IP.
        """
        all_alerts: List[ThreatAlert] = []

        all_alerts.extend(self._detect_unauthorized_commands())
        all_alerts.extend(self._detect_malware_signatures())
        all_alerts.extend(self._detect_reconnaissance())
        all_alerts.extend(self._detect_baseline_anomalies())

        # Deduplicate by (device_ip, title)
        seen: Set[Tuple[str, str]] = set()
        deduped: List[ThreatAlert] = []
        for a in all_alerts:
            key = (a.device_ip, a.title)
            if key not in seen:
                seen.add(key)
                deduped.append(a)

        # Assign sequential IDs and sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        deduped.sort(key=lambda a: (sev_order.get(a.severity, 5), a.device_ip))
        for idx, alert in enumerate(deduped, 1):
            alert.alert_id = f"TA-{idx:03d}"

        # Group by device IP
        by_ip: Dict[str, List[ThreatAlert]] = defaultdict(list)
        for alert in deduped:
            by_ip[alert.device_ip].append(alert)

        logger.info("Threat detection: %d alert(s) across %d device(s)",
                     len(deduped), len(by_ip))
        return dict(by_ip)

    # ── Module 1: Unauthorized command detection ─────────────────────

    def _detect_unauthorized_commands(self) -> List[ThreatAlert]:
        """Flag dangerous commands from unexpected sources."""
        alerts: List[ThreatAlert] = []

        for dev in self._devices:
            # Program transfer detection
            for ps in dev.protocol_stats:
                if ps.has_program_download:
                    alerts.append(ThreatAlert(
                        alert_type="policy_violation",
                        severity="high",
                        title=f"Program download detected on {dev.ip}",
                        description=(
                            f"PLC/RTU program write/download activity detected on "
                            f"{ps.protocol}. This could indicate legitimate maintenance "
                            f"or an attacker modifying control logic."
                        ),
                        device_ip=dev.ip,
                        protocol=ps.protocol,
                        mitre_technique="T0843",
                        mitre_tactic="Execution",
                        evidence={"protocol": ps.protocol, "role": dev.role},
                        confidence="high",
                    ))

                if ps.has_program_upload:
                    alerts.append(ThreatAlert(
                        alert_type="policy_violation",
                        severity="high",
                        title=f"Program upload detected on {dev.ip}",
                        description=(
                            f"PLC/RTU program read/upload activity detected on "
                            f"{ps.protocol}. An attacker may be exfiltrating "
                            f"control logic for reverse engineering."
                        ),
                        device_ip=dev.ip,
                        protocol=ps.protocol,
                        mitre_technique="T0845",
                        mitre_tactic="Collection",
                        evidence={"protocol": ps.protocol},
                        confidence="high",
                    ))

                if ps.has_firmware_update:
                    alerts.append(ThreatAlert(
                        alert_type="policy_violation",
                        severity="critical",
                        title=f"Firmware update detected on {dev.ip}",
                        description=(
                            f"Firmware modification activity detected on {ps.protocol}. "
                            f"Unauthorized firmware updates can permanently compromise "
                            f"device integrity."
                        ),
                        device_ip=dev.ip,
                        protocol=ps.protocol,
                        mitre_technique="T0839",
                        mitre_tactic="Inhibit Response Function",
                        evidence={"protocol": ps.protocol},
                        confidence="high",
                    ))

                if ps.has_config_change:
                    alerts.append(ThreatAlert(
                        alert_type="policy_violation",
                        severity="high",
                        title=f"Configuration change on {dev.ip}",
                        description=(
                            f"Device configuration modification detected on "
                            f"{ps.protocol}. This may alter operating parameters."
                        ),
                        device_ip=dev.ip,
                        protocol=ps.protocol,
                        mitre_technique="T0858",
                        mitre_tactic="Execution",
                        evidence={"protocol": ps.protocol},
                        confidence="medium",
                    ))

            # DNP3 restart commands
            for key, session in self._dnp3_sessions.items():
                if session.outstation_ip != dev.ip:
                    continue
                if session.cold_restarts > 0 or session.warm_restarts > 0:
                    alerts.append(ThreatAlert(
                        alert_type="policy_violation",
                        severity="high",
                        title=f"DNP3 restart command to {dev.ip}",
                        description=(
                            f"DNP3 cold restart ({session.cold_restarts}) and/or "
                            f"warm restart ({session.warm_restarts}) commands sent "
                            f"from master {session.master_ip}."
                        ),
                        device_ip=dev.ip,
                        peer_ip=session.master_ip,
                        protocol="DNP3",
                        mitre_technique="T0816",
                        mitre_tactic="Inhibit Response Function",
                        evidence={
                            "cold_restarts": session.cold_restarts,
                            "warm_restarts": session.warm_restarts,
                            "master_ip": session.master_ip,
                        },
                        confidence="high",
                    ))

                # File operations
                if session.file_opens or session.file_deletes > 0:
                    alerts.append(ThreatAlert(
                        alert_type="policy_violation",
                        severity="medium",
                        title=f"DNP3 file operations on {dev.ip}",
                        description=(
                            f"DNP3 file transfer activity detected: "
                            f"{len(session.file_opens)} opens, "
                            f"{session.file_deletes} deletes from "
                            f"master {session.master_ip}."
                        ),
                        device_ip=dev.ip,
                        peer_ip=session.master_ip,
                        protocol="DNP3",
                        mitre_technique="T0882",
                        mitre_tactic="Collection",
                        evidence={
                            "file_opens": len(session.file_opens),
                            "file_deletes": session.file_deletes,
                        },
                        confidence="medium",
                    ))

            # Cross-zone control traffic
            for edge in self._edges:
                if edge.dst_ip != dev.ip or not edge.is_control:
                    continue
                src_z = self._ip_to_zone.get(edge.src_ip)
                dst_z = self._ip_to_zone.get(edge.dst_ip)
                if src_z and dst_z and edge.purdue_span > 1:
                    alerts.append(ThreatAlert(
                        alert_type="policy_violation",
                        severity="high",
                        title=f"Cross-zone control to {dev.ip} (span {edge.purdue_span})",
                        description=(
                            f"Control commands from {edge.src_ip} "
                            f"(Purdue L{src_z.purdue_level}) to {dev.ip} "
                            f"(Purdue L{dst_z.purdue_level}) spanning "
                            f"{edge.purdue_span} levels."
                        ),
                        device_ip=dev.ip,
                        peer_ip=edge.src_ip,
                        protocol=", ".join(sorted(edge.protocols)),
                        mitre_technique="T0855",
                        mitre_tactic="Execution",
                        evidence={
                            "src_purdue": src_z.purdue_level,
                            "dst_purdue": dst_z.purdue_level,
                            "purdue_span": edge.purdue_span,
                            "packet_count": edge.packet_count,
                        },
                        confidence="high",
                    ))

        return alerts

    # ── Module 2: ICS malware signature matching ─────────────────────

    def _detect_malware_signatures(self) -> List[ThreatAlert]:
        """Match device behavior against known ICS malware patterns."""
        alerts: List[ThreatAlert] = []

        for sig in ICS_MALWARE_SIGNATURES:
            fn_name = sig.get("match_fn", "")
            match_fn = getattr(self, f"_{fn_name}", None)
            if match_fn is None:
                continue
            try:
                sig_alerts = match_fn(sig)
                alerts.extend(sig_alerts)
            except Exception as exc:
                logger.warning("Malware signature %s error: %s", sig["name"], exc)

        return alerts

    def _match_industroyer(self, sig: Dict) -> List[ThreatAlert]:
        """Industroyer: IEC-104 control + GI + clock sync from same master."""
        alerts: List[ThreatAlert] = []
        for key, session in self._iec104_sessions.items():
            has_control = bool(
                session.single_commands or session.double_commands
                or session.regulating_step or session.setpoint_commands
            )
            has_gi = session.general_interrogations > 0
            has_clock = session.clock_syncs > 0

            if has_control and has_gi and has_clock:
                alerts.append(ThreatAlert(
                    alert_type="malware_signature",
                    severity=sig["severity"],
                    title=f"Industroyer/CrashOverride pattern: {session.rtu_ip}",
                    description=sig["description"],
                    device_ip=session.rtu_ip,
                    peer_ip=session.master_ip,
                    protocol="IEC 60870-5-104",
                    mitre_technique=sig["mitre_technique"],
                    mitre_tactic=sig["mitre_tactic"],
                    evidence={
                        "master_ip": session.master_ip,
                        "control_commands": True,
                        "general_interrogations": session.general_interrogations,
                        "clock_syncs": session.clock_syncs,
                        "packet_count": session.packet_count,
                    },
                    first_seen=session.first_seen,
                    confidence="medium",
                ))
        return alerts

    def _match_triton(self, sig: Dict) -> List[ThreatAlert]:
        """TRITON: SIS device with program download + firmware update."""
        alerts: List[ThreatAlert] = []
        for dev in self._devices:
            if dev.device_criticality != "safety_system":
                continue
            for ps in dev.protocol_stats:
                if ps.has_program_download and ps.has_firmware_update:
                    alerts.append(ThreatAlert(
                        alert_type="malware_signature",
                        severity=sig["severity"],
                        title=f"TRITON/TRISIS pattern: {dev.ip}",
                        description=sig["description"],
                        device_ip=dev.ip,
                        protocol=ps.protocol,
                        mitre_technique=sig["mitre_technique"],
                        mitre_tactic=sig["mitre_tactic"],
                        evidence={
                            "device_criticality": dev.device_criticality,
                            "protocol": ps.protocol,
                            "program_download": True,
                            "firmware_update": True,
                        },
                        confidence="high",
                    ))
        return alerts

    def _match_havex(self, sig: Dict) -> List[ThreatAlert]:
        """Havex: OPC-UA device with high peer count + diagnostics."""
        alerts: List[ThreatAlert] = []
        for dev in self._devices:
            proto_names = set(dev.get_protocol_names())
            if "OPC-UA" not in proto_names:
                continue
            peer_count = len(dev.communicating_with)
            has_diag = any(ps.diagnostic_count > 0 for ps in dev.protocol_stats)
            if peer_count > 10 and has_diag:
                alerts.append(ThreatAlert(
                    alert_type="malware_signature",
                    severity=sig["severity"],
                    title=f"Havex OPC scanner pattern: {dev.ip}",
                    description=sig["description"],
                    device_ip=dev.ip,
                    protocol="OPC-UA",
                    mitre_technique=sig["mitre_technique"],
                    mitre_tactic=sig["mitre_tactic"],
                    evidence={
                        "peer_count": peer_count,
                        "diagnostic_commands": True,
                    },
                    confidence="low",
                ))
        return alerts

    def _match_blackenergy(self, sig: Dict) -> List[ThreatAlert]:
        """BlackEnergy: Multiple protocols + IT protocols + program upload."""
        alerts: List[ThreatAlert] = []
        for dev in self._devices:
            multi_proto = len(dev.protocols) >= 3
            has_it = bool(dev.it_protocols)
            has_upload = any(ps.has_program_upload for ps in dev.protocol_stats)
            if multi_proto and has_it and has_upload:
                alerts.append(ThreatAlert(
                    alert_type="malware_signature",
                    severity=sig["severity"],
                    title=f"BlackEnergy pattern: {dev.ip}",
                    description=sig["description"],
                    device_ip=dev.ip,
                    mitre_technique=sig["mitre_technique"],
                    mitre_tactic=sig["mitre_tactic"],
                    evidence={
                        "protocol_count": len(dev.protocols),
                        "it_protocols": [p.protocol for p in dev.it_protocols],
                        "program_upload": True,
                    },
                    confidence="medium",
                ))
        return alerts

    def _match_pipedream(self, sig: Dict) -> List[ThreatAlert]:
        """Pipedream: S7comm program download + Modbus writes from same source."""
        alerts: List[ThreatAlert] = []
        for dev in self._devices:
            proto_names = set(dev.get_protocol_names())
            has_s7 = "S7comm" in proto_names or "S7comm+" in proto_names
            has_modbus = "Modbus/TCP" in proto_names
            if not (has_s7 and has_modbus):
                continue
            has_download = any(
                ps.has_program_download
                for ps in dev.protocol_stats
                if "S7" in ps.protocol.upper()
            )
            has_writes = any(
                ps.write_count > 0
                for ps in dev.protocol_stats
                if "MODBUS" in ps.protocol.upper()
            )
            if has_download and has_writes:
                alerts.append(ThreatAlert(
                    alert_type="malware_signature",
                    severity=sig["severity"],
                    title=f"Pipedream/Incontroller pattern: {dev.ip}",
                    description=sig["description"],
                    device_ip=dev.ip,
                    protocol="S7comm + Modbus/TCP",
                    mitre_technique=sig["mitre_technique"],
                    mitre_tactic=sig["mitre_tactic"],
                    evidence={
                        "s7_program_download": True,
                        "modbus_writes": True,
                    },
                    confidence="medium",
                ))
        return alerts

    def _match_stuxnet(self, sig: Dict) -> List[ThreatAlert]:
        """Stuxnet: S7comm program upload AND download (possibly different sources)."""
        alerts: List[ThreatAlert] = []
        for dev in self._devices:
            has_upload = any(
                ps.has_program_upload for ps in dev.protocol_stats
                if "S7" in ps.protocol.upper()
            )
            has_download = any(
                ps.has_program_download for ps in dev.protocol_stats
                if "S7" in ps.protocol.upper()
            )
            if has_upload and has_download:
                alerts.append(ThreatAlert(
                    alert_type="malware_signature",
                    severity=sig["severity"],
                    title=f"Stuxnet pattern: {dev.ip}",
                    description=sig["description"],
                    device_ip=dev.ip,
                    protocol="S7comm",
                    mitre_technique=sig["mitre_technique"],
                    mitre_tactic=sig["mitre_tactic"],
                    evidence={
                        "program_upload": True,
                        "program_download": True,
                        "masters": sorted(dev.master_stations),
                    },
                    confidence="medium",
                ))
        return alerts

    def _match_frostygoop(self, sig: Dict) -> List[ThreatAlert]:
        """FrostyGoop: Modbus writes to many addresses from higher Purdue zone."""
        alerts: List[ThreatAlert] = []
        for dev in self._devices:
            dev_zone = self._ip_to_zone.get(dev.ip)
            for ps in dev.protocol_stats:
                if "MODBUS" not in ps.protocol.upper():
                    continue
                if ps.write_count <= 0 or ps.unique_data_points < 5:
                    continue
                # Check if writes come from a higher Purdue level
                for master_ip in dev.master_stations:
                    m_zone = self._ip_to_zone.get(master_ip)
                    if m_zone and dev_zone and m_zone.purdue_level > dev_zone.purdue_level:
                        alerts.append(ThreatAlert(
                            alert_type="malware_signature",
                            severity=sig["severity"],
                            title=f"FrostyGoop pattern: {dev.ip}",
                            description=sig["description"],
                            device_ip=dev.ip,
                            peer_ip=master_ip,
                            protocol="Modbus/TCP",
                            mitre_technique=sig["mitre_technique"],
                            mitre_tactic=sig["mitre_tactic"],
                            evidence={
                                "write_count": ps.write_count,
                                "unique_addresses": ps.unique_data_points,
                                "master_ip": master_ip,
                                "master_purdue": m_zone.purdue_level,
                                "device_purdue": dev_zone.purdue_level,
                            },
                            confidence="medium",
                        ))
                        break  # one alert per device
        return alerts

    def _match_fuxnet(self, sig: Dict) -> List[ThreatAlert]:
        """Fuxnet: Modbus rapid writes + diagnostic/restart commands (PLC bricking)."""
        alerts: List[ThreatAlert] = []
        for dev in self._devices:
            for ps in dev.protocol_stats:
                if "MODBUS" not in ps.protocol.upper():
                    continue
                # High write volume + diagnostic commands = bricking pattern
                has_heavy_writes = ps.write_count > 50
                has_diag = ps.diagnostic_count > 0
                has_many_addrs = ps.unique_data_points >= 10
                if has_heavy_writes and (has_diag or has_many_addrs):
                    alerts.append(ThreatAlert(
                        alert_type="malware_signature",
                        severity=sig["severity"],
                        title=f"Fuxnet pattern: {dev.ip}",
                        description=sig["description"],
                        device_ip=dev.ip,
                        protocol="Modbus/TCP",
                        mitre_technique=sig["mitre_technique"],
                        mitre_tactic=sig["mitre_tactic"],
                        evidence={
                            "write_count": ps.write_count,
                            "diagnostic_count": ps.diagnostic_count,
                            "unique_addresses": ps.unique_data_points,
                        },
                        confidence="medium",
                    ))
                    break
        return alerts

    def _match_iocontrol(self, sig: Dict) -> List[ThreatAlert]:
        """IOControl: MQTT device with IT protocols + config changes (C2 via MQTT)."""
        alerts: List[ThreatAlert] = []
        for dev in self._devices:
            proto_names = set(dev.get_protocol_names())
            if "MQTT" not in proto_names:
                continue
            has_it = bool(dev.it_protocols)
            has_config = any(ps.has_config_change for ps in dev.protocol_stats)
            has_many_peers = len(dev.communicating_with) > 5
            # MQTT + IT protocols + (config change or high peer count) = C2 pattern
            if has_it and (has_config or has_many_peers):
                alerts.append(ThreatAlert(
                    alert_type="malware_signature",
                    severity=sig["severity"],
                    title=f"IOControl pattern: {dev.ip}",
                    description=sig["description"],
                    device_ip=dev.ip,
                    protocol="MQTT",
                    mitre_technique=sig["mitre_technique"],
                    mitre_tactic=sig["mitre_tactic"],
                    evidence={
                        "mqtt_detected": True,
                        "it_protocols": [p.protocol for p in dev.it_protocols],
                        "config_change": has_config,
                        "peer_count": len(dev.communicating_with),
                    },
                    confidence="medium",
                ))
        return alerts

    # ── Module 3: Reconnaissance detection ───────────────────────────

    def _detect_reconnaissance(self) -> List[ThreatAlert]:
        """Identify scanning and enumeration behavior."""
        alerts: List[ThreatAlert] = []

        # Build per-IP outbound peer counts
        ip_peer_count: Dict[str, int] = {}
        for dev in self._devices:
            ip_peer_count[dev.ip] = len(dev.communicating_with)

        # Network mapping: non-master/historian talking to >15 peers
        for dev in self._devices:
            if dev.role in ("historian", "master_station", "gateway"):
                continue
            if ip_peer_count.get(dev.ip, 0) > 15:
                alerts.append(ThreatAlert(
                    alert_type="reconnaissance",
                    severity="high",
                    title=f"Network mapping activity from {dev.ip}",
                    description=(
                        f"Device {dev.ip} (role: {dev.role}) communicates with "
                        f"{ip_peer_count[dev.ip]} peers, far exceeding normal "
                        f"for its role. May indicate network scanning."
                    ),
                    device_ip=dev.ip,
                    mitre_technique="T0842",
                    mitre_tactic="Discovery",
                    evidence={
                        "peer_count": ip_peer_count[dev.ip],
                        "role": dev.role,
                    },
                    confidence="medium",
                ))

        # Port scan: device with >20 open ports
        for dev in self._devices:
            if len(dev.open_ports) > 20:
                alerts.append(ThreatAlert(
                    alert_type="reconnaissance",
                    severity="medium",
                    title=f"Excessive open ports on {dev.ip}",
                    description=(
                        f"Device {dev.ip} has {len(dev.open_ports)} open ports, "
                        f"suggesting it has been port-scanned or runs many services."
                    ),
                    device_ip=dev.ip,
                    mitre_technique="T0846",
                    mitre_tactic="Discovery",
                    evidence={"open_port_count": len(dev.open_ports)},
                    confidence="medium",
                ))

        # Protocol enumeration: single source using >5 protocols across devices
        src_protos: Dict[str, Set[str]] = defaultdict(set)
        for f in self._flows:
            src_protos[f.src_ip].add(f.protocol)
        for ip, protos in src_protos.items():
            if len(protos) > 5:
                dev = self._device_map.get(ip)
                role = dev.role if dev else "unknown"
                if role not in ("historian", "master_station", "gateway"):
                    alerts.append(ThreatAlert(
                        alert_type="reconnaissance",
                        severity="medium",
                        title=f"Protocol enumeration from {ip}",
                        description=(
                            f"Source {ip} uses {len(protos)} distinct protocols: "
                            f"{', '.join(sorted(protos))}. May indicate "
                            f"multi-protocol scanning/enumeration."
                        ),
                        device_ip=ip,
                        mitre_technique="T0846",
                        mitre_tactic="Discovery",
                        evidence={
                            "protocol_count": len(protos),
                            "protocols": sorted(protos),
                        },
                        confidence="low",
                    ))

        # Modbus device scan: traffic to >10 unit IDs from single source
        for dev in self._devices:
            for ps in dev.protocol_stats:
                if "MODBUS" in ps.protocol.upper() and len(ps.unique_addresses) > 10:
                    alerts.append(ThreatAlert(
                        alert_type="reconnaissance",
                        severity="medium",
                        title=f"Modbus address scan on {dev.ip}",
                        description=(
                            f"Modbus traffic targeting {len(ps.unique_addresses)} "
                            f"unique register/coil addresses on {dev.ip}."
                        ),
                        device_ip=dev.ip,
                        protocol="Modbus/TCP",
                        mitre_technique="T0846",
                        mitre_tactic="Discovery",
                        evidence={
                            "unique_addresses": len(ps.unique_addresses),
                        },
                        confidence="low",
                    ))

        return alerts

    # ── Module 4: Baseline anomaly detection ─────────────────────────

    def _detect_baseline_anomalies(self) -> List[ThreatAlert]:
        """Compare device behavior against zone-level baselines."""
        alerts: List[ThreatAlert] = []

        # Compute zone-level baselines
        zone_byte_counts: Dict[str, List[int]] = defaultdict(list)
        zone_protocols: Dict[str, Set[str]] = defaultdict(set)
        role_function_codes: Dict[str, Set[str]] = defaultdict(set)

        for dev in self._devices:
            zone = self._ip_to_zone.get(dev.ip)
            zone_id = zone.zone_id if zone else "unknown"

            # Byte counts per zone
            total_bytes = sum(
                f.byte_count for f in self._flows
                if f.src_ip == dev.ip or f.dst_ip == dev.ip
            )
            zone_byte_counts[zone_id].append(total_bytes)

            # Protocols per zone
            for p in dev.get_protocol_names():
                zone_protocols[zone_id].add(p)

            # Function codes per role
            for ps in dev.protocol_stats:
                for fc_name in ps.function_codes:
                    role_function_codes[dev.role].add(fc_name)

        # Volume spike: device bytes > 3× zone median
        for dev in self._devices:
            zone = self._ip_to_zone.get(dev.ip)
            zone_id = zone.zone_id if zone else "unknown"
            dev_bytes = sum(
                f.byte_count for f in self._flows
                if f.src_ip == dev.ip or f.dst_ip == dev.ip
            )
            zone_bytes = zone_byte_counts.get(zone_id, [])
            if zone_bytes and len(zone_bytes) >= 3:
                zone_med = median(zone_bytes)
                if zone_med > 0 and dev_bytes > 3 * zone_med:
                    alerts.append(ThreatAlert(
                        alert_type="anomaly",
                        severity="medium",
                        title=f"Traffic volume spike: {dev.ip}",
                        description=(
                            f"Device {dev.ip} transferred {dev_bytes:,} bytes, "
                            f"exceeding 3x the zone median ({zone_med:,.0f} bytes)."
                        ),
                        device_ip=dev.ip,
                        mitre_technique="T0882",
                        mitre_tactic="Collection",
                        evidence={
                            "device_bytes": dev_bytes,
                            "zone_median": zone_med,
                            "ratio": round(dev_bytes / zone_med, 1),
                        },
                        confidence="low",
                    ))

        # Protocol deviation: device uses protocol unseen in its zone
        for dev in self._devices:
            zone = self._ip_to_zone.get(dev.ip)
            zone_id = zone.zone_id if zone else "unknown"
            z_protos = zone_protocols.get(zone_id, set())
            dev_protos = set(dev.get_protocol_names())
            unique_protos = dev_protos - z_protos
            # This triggers only if zone has >1 device (otherwise all protos are "normal")
            zone_devs = len(zone.device_ips) if zone else 0
            if unique_protos and zone_devs > 1:
                for proto in unique_protos:
                    alerts.append(ThreatAlert(
                        alert_type="anomaly",
                        severity="high",
                        title=f"Unusual protocol on {dev.ip}: {proto}",
                        description=(
                            f"Device {dev.ip} uses {proto} which is not seen "
                            f"on any other device in zone {zone_id}."
                        ),
                        device_ip=dev.ip,
                        protocol=proto,
                        mitre_technique="T0869",
                        mitre_tactic="Execution",
                        evidence={
                            "protocol": proto,
                            "zone_id": zone_id,
                            "zone_protocols": sorted(z_protos),
                        },
                        confidence="low",
                    ))

        # Function code anomaly: device uses FCs not seen by same-role peers
        for dev in self._devices:
            if dev.role == "unknown":
                continue
            role_fcs = role_function_codes.get(dev.role, set())
            for ps in dev.protocol_stats:
                dev_fcs = set(ps.function_codes.keys())
                unusual_fcs = dev_fcs - role_fcs
                if unusual_fcs and len(role_fcs) > 3:
                    alerts.append(ThreatAlert(
                        alert_type="anomaly",
                        severity="high",
                        title=f"Unusual function codes on {dev.ip}",
                        description=(
                            f"Device {dev.ip} (role: {dev.role}) uses function codes "
                            f"not seen on other {dev.role} devices: "
                            f"{', '.join(sorted(unusual_fcs)[:5])}"
                        ),
                        device_ip=dev.ip,
                        protocol=ps.protocol,
                        mitre_technique="T0855",
                        mitre_tactic="Execution",
                        evidence={
                            "unusual_fcs": sorted(unusual_fcs)[:10],
                            "device_role": dev.role,
                        },
                        confidence="low",
                    ))

        return alerts
