"""
Vulnerability Engine — Orchestrates all check modules and assigns risk scores.

After all packets are processed by the core analyzer, this engine is called
once per device with the accumulated session state, then:
  1. Runs each check module
  2. De-duplicates findings
  3. Calculates an aggregate risk score and risk level
  4. Attaches findings to the RTUDevice
"""
from typing import Dict, List, Optional, Set

from ..models import RTUDevice, VulnerabilityFinding
from .dnp3_checks    import run_dnp3_checks
from .iec104_checks  import run_iec104_checks
from .iec61850_checks import run_iec61850_checks
from .general_checks import run_general_checks

# Severity → numeric weight for risk score calculation
SEVERITY_WEIGHT = {
    "critical": 10,
    "high":      6,
    "medium":    3,
    "low":       1,
    "info":      0,
}

# Score → risk level band
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
        device: RTUDevice,
        dnp3_sessions: Dict,        # (master, outstation) → DNP3SessionState
        iec104_sessions: Dict,      # (master, rtu)       → IEC104SessionState
        goose_publishers: Dict,     # (mac, app_id)       → GOOSEPublisherState
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

        # General checks — always run
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


def _infer_role(device: RTUDevice) -> str:
    proto_names = set(device.get_protocol_names())
    goose_proto = "IEC 61850 GOOSE"
    mms_proto   = "IEC 61850 MMS"

    if goose_proto in proto_names or mms_proto in proto_names:
        # IEDs / FRTU in IEC 61850 substations
        if device.goose_ids:
            return "ied"
        return "ied"
    if "DNP3" in proto_names or "IEC 60870-5-104" in proto_names:
        if device.master_stations:
            return "rtu"
        return "rtu"
    if "Modbus/TCP" in proto_names:
        return "rtu"
    if "SEL Fast Message" in proto_names:
        return "ied"
    return "unknown"
