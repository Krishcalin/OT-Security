"""
Composite Risk Scoring Engine for the OT Passive Scanner.

Produces a context-weighted risk score (0-100) for each device by combining:
  - Vulnerability finding severity weights
  - CVE CVSS base scores + EPSS exploitation probability
  - CISA KEV (Known Exploited Vulnerabilities) boost
  - Device criticality multiplier (safety_system > process_control > ...)
  - Network exposure multiplier (Purdue level — L0 highest risk)
  - Protocol-specific risk penalties (unauthenticated, unencrypted, etc.)
  - Compensating controls discount (authenticated sessions, encryption, etc.)

Formula:
  COMPOSITE = min(100, (BASE + protocol_penalties) × Π(multipliers) × controls_factor)

Zero external dependencies — uses only Python stdlib.
"""

import logging
from typing import Dict, List, Optional, Tuple

from ..models import NetworkZone, OTDevice

logger = logging.getLogger(__name__)


# ── Severity weights (same as vuln engine for base calculation) ──────────
SEVERITY_WEIGHT = {
    "critical": 10,
    "high":      6,
    "medium":    3,
    "low":       1,
    "info":      0,
}

# ── Criticality multipliers ─────────────────────────────────────────────
CRITICALITY_MULT = {
    "safety_system":    1.5,
    "process_control":  1.3,
    "monitoring":       1.0,
    "support":          0.8,
    "unknown":          1.0,
}

# ── Purdue level exposure multipliers ───────────────────────────────────
EXPOSURE_MULT = {
    0:  1.5,    # Level 0 — Process (highest risk)
    1:  1.3,    # Level 1 — Basic Control
    2:  1.1,    # Level 2 — Area Supervisory
    3:  0.9,    # Level 3 — Site Operations
    4:  0.7,    # Level 4 — Enterprise IT
    5:  0.6,    # Level 5 — Internet / Cloud
    -1: 1.0,    # Unknown
}

# ── Composite score → risk level ────────────────────────────────────────
def _composite_to_level(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    if score >= 1:
        return "low"
    return "low"


class CompositeRiskEngine:
    """
    Multi-factor weighted risk scoring for OT/ICS devices.

    Usage::

        engine = CompositeRiskEngine(zones)
        for device in devices:
            engine.score_device(device)
    """

    def __init__(self, zones: Optional[List[NetworkZone]] = None) -> None:
        self._ip_to_zone: Dict[str, NetworkZone] = {}
        if zones:
            for z in zones:
                for ip in z.device_ips:
                    self._ip_to_zone[ip] = z

    # ── public API ───────────────────────────────────────────────────

    def score_device(self, device: OTDevice) -> None:
        """
        Compute composite risk score and update device in-place.

        Sets: composite_risk_score, risk_score_breakdown,
              risk_level (overwritten), compensating_controls.
        """
        # 1. Base score from vulns + CVEs
        base = self._calculate_base_score(device)

        # 2. Protocol-specific penalties
        penalties = self._calculate_protocol_penalties(device)

        # 3. Multipliers
        crit_mult = self._get_criticality_multiplier(device)
        exp_mult = self._get_exposure_multiplier(device)
        kev_boost = self._calculate_kev_boost(device)
        epss_boost = self._calculate_epss_boost(device)

        # 4. Compensating controls
        controls, controls_factor = self._detect_compensating_controls(device)

        # 5. Composite calculation
        raw = (base + penalties) * crit_mult * exp_mult * kev_boost * epss_boost * controls_factor
        composite = min(100.0, max(0.0, round(raw, 1)))

        # 6. Update device
        device.composite_risk_score = composite
        device.risk_level = _composite_to_level(composite)
        device.compensating_controls = controls
        device.risk_score_breakdown = self._build_breakdown(
            base=base,
            protocol_penalties=penalties,
            criticality_multiplier=crit_mult,
            exposure_multiplier=exp_mult,
            kev_boost=kev_boost,
            epss_boost=epss_boost,
            controls_factor=controls_factor,
            controls_list=controls,
            composite=composite,
        )

    # ── private: component calculations ──────────────────────────────

    def _calculate_base_score(self, device: OTDevice) -> float:
        """
        Base score = sum(vuln severity weights) + sum(cvss/10 * 5 per CVE).
        """
        vuln_score = sum(
            SEVERITY_WEIGHT.get(v.severity, 0)
            for v in device.vulnerabilities
        )

        cve_score = sum(
            (c.cvss_score / 10.0) * 5.0
            for c in device.cve_matches
            if c.priority != "never"
        )

        return vuln_score + cve_score

    def _get_criticality_multiplier(self, device: OTDevice) -> float:
        """Map device_criticality to weight."""
        return CRITICALITY_MULT.get(device.device_criticality, 1.0)

    def _get_exposure_multiplier(self, device: OTDevice) -> float:
        """Map Purdue level to weight."""
        zone = self._ip_to_zone.get(device.ip)
        if zone:
            return EXPOSURE_MULT.get(zone.purdue_level, 1.0)
        return 1.0

    def _calculate_kev_boost(self, device: OTDevice) -> float:
        """Boost from CISA KEV CVEs: 1.0 + 0.3 per KEV match."""
        kev_count = sum(1 for c in device.cve_matches if c.is_cisa_kev)
        return 1.0 + (0.3 * kev_count)

    def _calculate_epss_boost(self, device: OTDevice) -> float:
        """Boost from highest EPSS score: 1.0 + max_epss * 0.4."""
        if not device.cve_matches:
            return 1.0
        max_epss = max(
            (c.epss_score for c in device.cve_matches if c.priority != "never"),
            default=0.0,
        )
        return 1.0 + (max_epss * 0.4)

    def _calculate_protocol_penalties(self, device: OTDevice) -> float:
        """Sum protocol-specific risk additions from vulnerability evidence."""
        penalty = 0.0
        vuln_ids = {v.vuln_id.upper() for v in device.vulnerabilities}
        vuln_cats = {
            (v.vuln_id.upper(), v.category)
            for v in device.vulnerabilities
        }

        # Check vulnerability findings for protocol-specific risks
        for vid, cat in vuln_cats:
            # Unauthenticated DNP3 with control commands
            if "DNP3" in vid and cat in ("authentication", "command-security"):
                penalty += 5.0
            # Unauthenticated IEC-104 with control commands
            elif "IEC104" in vid and cat == "command-security":
                penalty += 4.0
            # GOOSE without authentication
            elif "GOOSE" in vid and cat == "authentication":
                penalty += 5.0
            # Direct operate without select-before-operate
            elif "DIRECT" in vid and "OPERATE" in vid:
                penalty += 2.0
            # DNP3 over UDP
            elif "DNP3" in vid and "UDP" in vid:
                penalty += 2.0

        # Check protocol stats for Modbus write operations
        for ps in device.protocol_stats:
            proto = ps.protocol.upper()
            if "MODBUS" in proto and ps.write_count > 0:
                penalty += 3.0
                break

        # Check for program upload/download
        for ps in device.protocol_stats:
            if ps.has_program_upload or ps.has_program_download:
                penalty += 3.0
                break

        return penalty

    def _detect_compensating_controls(
        self, device: OTDevice,
    ) -> Tuple[List[str], float]:
        """
        Identify mitigating factors. Returns (controls_list, factor).
        Factor = max(0.5, 1.0 - sum_of_discounts).
        """
        controls: List[str] = []
        discount = 0.0

        # Check for authenticated DNP3 sessions (via vulnerability absence)
        # If device runs DNP3 but has NO authentication vulnerability → authenticated
        proto_names = set(device.get_protocol_names())
        dnp3_auth_vuln = any(
            "DNP3" in v.vuln_id.upper() and v.category == "authentication"
            for v in device.vulnerabilities
        )
        if "DNP3" in proto_names and not dnp3_auth_vuln:
            controls.append("DNP3 Secure Authentication enabled")
            discount += 0.10

        # Check for encrypted transport
        has_tls = any(p == 8883 for p in device.open_ports)  # MQTT over TLS
        opcua_secure = any(
            "OPC-UA" in p.protocol and p.details.get("security_policy")
            for p in device.protocols
            if hasattr(p, "details") and isinstance(getattr(p, "details", None), dict)
        )
        iec104_tls_vuln = any(
            "IEC104" in v.vuln_id.upper() and v.category == "encryption"
            for v in device.vulnerabilities
        )
        if "IEC 60870-5-104" in proto_names and not iec104_tls_vuln:
            controls.append("IEC 60870-5-104 TLS encryption detected")
            discount += 0.10

        if has_tls:
            controls.append("MQTT TLS encryption (port 8883)")
            discount += 0.10

        if opcua_secure:
            controls.append("OPC-UA security policy enabled")
            discount += 0.10

        # Limited peer count for L0-1 devices
        zone = self._ip_to_zone.get(device.ip)
        purdue = zone.purdue_level if zone else -1
        peer_count = len(device.communicating_with)
        if purdue <= 1 and purdue >= 0 and peer_count <= 3:
            controls.append(
                f"Limited network exposure ({peer_count} peers at Purdue L{purdue})"
            )
            discount += 0.05

        # Read-only communication profile
        cp = device.communication_profile
        if cp and cp.get("control_ratio", 1) == 0:
            controls.append("Read-only communication profile (no control commands)")
            discount += 0.05

        # Floor at 0.5 — never reduce risk by more than half
        factor = max(0.5, 1.0 - discount)
        return controls, factor

    @staticmethod
    def _build_breakdown(
        base: float,
        protocol_penalties: float,
        criticality_multiplier: float,
        exposure_multiplier: float,
        kev_boost: float,
        epss_boost: float,
        controls_factor: float,
        controls_list: List[str],
        composite: float,
    ) -> Dict:
        """Assemble the risk_score_breakdown dict for transparency."""
        return {
            "base_score": round(base, 1),
            "protocol_penalties": round(protocol_penalties, 1),
            "criticality_multiplier": criticality_multiplier,
            "exposure_multiplier": exposure_multiplier,
            "kev_boost": round(kev_boost, 2),
            "epss_boost": round(epss_boost, 2),
            "controls_factor": round(controls_factor, 2),
            "compensating_controls": controls_list,
            "composite_score": composite,
            "formula": (
                "min(100, (base + penalties) × criticality × exposure "
                "× kev_boost × epss_boost × controls_factor)"
            ),
        }
