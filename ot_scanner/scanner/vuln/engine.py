"""
Vulnerability Engine -- Orchestrates all check modules and assigns risk scores.

After all packets are processed by the core analyzer, this engine is called
once per device with the accumulated session state, then:
  1. Runs each check module (DNP3, IEC-104, IEC 61850, general + OPC-UA + MQTT)
  2. De-duplicates findings
  3. Calculates an aggregate risk score and risk level
  4. Attaches findings to the OTDevice
  5. Populates risk_factors list
"""
from typing import Dict, List, Optional, Set

from ..models import OTDevice, VulnerabilityFinding
from .dnp3_checks     import run_dnp3_checks
from .iec104_checks   import run_iec104_checks
from .iec61850_checks import run_iec61850_checks
from .general_checks  import run_general_checks

# Severity -> numeric weight for risk score calculation
SEVERITY_WEIGHT = {
    "critical": 10,
    "high":      6,
    "medium":    3,
    "low":       1,
    "info":      0,
}

# Score -> risk level band
def _score_to_level(score: int) -> str:
    if score >= 20:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 1:
        return "low"
    return "low"


class VulnerabilityEngine:
    """
    Orchestrates all vulnerability check modules.

    Usage:
        engine = VulnerabilityEngine()
        engine.assess(device, dnp3_sessions, iec104_sessions,
                      goose_publishers, mms_device_ips)
        # device.vulnerabilities and device.risk_level are now populated
    """

    def assess(
        self,
        device: OTDevice,
        dnp3_sessions: Dict,        # (master, outstation) -> DNP3SessionState
        iec104_sessions: Dict,      # (master, rtu)       -> IEC104SessionState
        goose_publishers: Dict,     # (mac, app_id)       -> GOOSEPublisherState
        mms_device_ips: Set[str],   # IPs seen running MMS
    ) -> None:
        """
        Run all checks, populate device.vulnerabilities and risk fields.
        Modifies device in-place.
        """
        findings: List[VulnerabilityFinding] = []

        # Protocol-specific checks (only if the device actually runs the protocol)
        proto_names = device.get_protocol_names()

        if "DNP3" in proto_names:
            findings += run_dnp3_checks(device, dnp3_sessions)

        if "IEC 60870-5-104" in proto_names:
            findings += run_iec104_checks(device, iec104_sessions)

        if "IEC 61850 GOOSE" in proto_names or "IEC 61850 MMS" in proto_names:
            findings += run_iec61850_checks(device, goose_publishers, mms_device_ips)

        # General checks -- always run (includes OPC-UA and MQTT checks)
        findings += run_general_checks(device)

        # De-duplicate by vuln_id (keep the one with highest packet_count)
        findings = _dedup(findings)

        # Sort: critical first, then high, medium, low, info
        findings.sort(key=lambda f: -SEVERITY_WEIGHT.get(f.severity, 0))

        # Score
        total_score = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)

        device.vulnerabilities = findings
        device.risk_score      = total_score
        device.risk_level      = _score_to_level(total_score)

        # Populate risk factors
        device.risk_factors = _build_risk_factors(device, findings)

        # Infer role from protocols
        if device.role == "unknown":
            device.role = _infer_role(device)


def _dedup(findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
    """Keep the highest-count finding per vuln_id."""
    seen: Dict[str, VulnerabilityFinding] = {}
    for f in findings:
        if f.vuln_id not in seen or f.packet_count > seen[f.vuln_id].packet_count:
            seen[f.vuln_id] = f
    return list(seen.values())


def _infer_role(device: OTDevice) -> str:
    """
    Infer the device role from its detected protocols.

    Protocol -> role mapping:
      - S7comm / FINS / MELSEC MC / EtherNet/IP CIP -> plc
      - DNP3 / IEC-104 / SEL Fast Message           -> rtu or ied
      - IEC 61850 GOOSE / MMS                       -> ied
      - OPC-UA                                       -> (don't override -- could be any)
      - BACnet/IP                                    -> building_controller
      - MQTT                                         -> iot_device
      - Modbus/TCP                                   -> rtu (default field device)
    """
    proto_names = set(device.get_protocol_names())

    # PLC protocols (highest confidence -- override others)
    plc_protocols = {"S7comm", "S7comm Plus", "Omron FINS", "MELSEC MC Protocol",
                     "EtherNet/IP CIP"}
    if proto_names & plc_protocols:
        return "plc"

    # IEC 61850 IED
    goose_proto = "IEC 61850 GOOSE"
    mms_proto   = "IEC 61850 MMS"
    if goose_proto in proto_names or mms_proto in proto_names:
        if device.goose_ids:
            return "ied"
        return "ied"

    # RTU / IED protocols
    if "DNP3" in proto_names or "IEC 60870-5-104" in proto_names:
        if device.master_stations:
            return "rtu"
        return "rtu"

    if "SEL Fast Message" in proto_names:
        return "ied"

    # BACnet -> building automation controller
    if "BACnet/IP" in proto_names:
        return "building_controller"

    # MQTT -> IoT device (sensor / gateway)
    if "MQTT" in proto_names:
        return "iot_device"

    # Modbus field device
    if "Modbus/TCP" in proto_names:
        return "rtu"

    # OPC-UA can be anything -- don't override
    if "OPC-UA" in proto_names:
        return "unknown"

    # PROFINET
    if "PROFINET RT" in proto_names or "PROFINET IO" in proto_names:
        return "plc"

    return "unknown"


def _build_risk_factors(
    device: OTDevice,
    findings: List[VulnerabilityFinding],
) -> List[str]:
    """
    Build a human-readable list of risk factors for the device.
    Combines vulnerability-derived factors with device characteristics.
    """
    factors: List[str] = []

    # Severity-based factors
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    if sev_counts.get("critical", 0) > 0:
        factors.append(
            f"{sev_counts['critical']} critical vulnerability(ies) detected"
        )
    if sev_counts.get("high", 0) > 0:
        factors.append(
            f"{sev_counts['high']} high-severity vulnerability(ies) detected"
        )

    # Category-based factors
    categories = {f.category for f in findings}
    if "authentication" in categories:
        factors.append("Missing or weak authentication on one or more protocols")
    if "encryption" in categories:
        factors.append("Cleartext protocol communications (no encryption)")
    if "command-security" in categories:
        factors.append("Control commands transmitted without integrity protection")

    # Protocol exposure
    proto_names = device.get_protocol_names()
    if len(proto_names) >= 3:
        factors.append(
            f"Excessive protocol exposure ({len(proto_names)} protocols)"
        )

    # Peer count
    peer_count = len(device.communicating_with)
    if peer_count > 10:
        factors.append(
            f"Communicating with {peer_count} peers (expected <= 5)"
        )

    # Role-based risk
    if device.role in ("plc", "rtu", "ied", "relay"):
        factors.append(
            f"Device role '{device.role}' -- direct process control capability"
        )

    return factors
