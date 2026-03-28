"""
Compliance framework mapper for OT Passive Scanner findings.

Maps scan results (vulnerabilities, CVE matches, zone violations) to
three ICS/OT compliance frameworks and generates a posture assessment:

  - NERC CIP   (v5-7) -- North American bulk electric system
  - IEC 62443-3-3     -- Industrial network and system security
  - NIST SP 800-82 Rev 3 -- Guide to OT Security

Each framework is evaluated as a list of ComplianceCheck objects whose
status is derived from the presence (or absence) of specific vuln IDs
and zone violations in the scan data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..models import OTDevice, NetworkZone, ZoneViolation


# ────────────────────────────────────────────────── Data Model ──

@dataclass
class ComplianceCheck:
    """A single compliance control evaluation result."""
    framework: str          # "NERC CIP", "IEC 62443", "NIST 800-82"
    control_id: str         # "CIP-005-6 R2", "SR 4.3", "6.2.5"
    title: str              # human-readable control name
    status: str             # "pass" | "fail" | "warning" | "not_assessed"
    severity: str           # critical | high | medium | low
    finding: str            # what was observed
    recommendation: str     # what to do
    related_vulns: List[str] = field(default_factory=list)


# ────────────────────────────────────────────────── Framework Definitions ──

# Each entry: (control_id, title, severity, related_vuln_ids, recommendation)
# related_vuln_ids may include special prefixes:
#   "CVE:now"  -- any CVE match with priority=now
#   "ZV-*"     -- any zone violation
#   "DEVICE_ID" -- requires devices to be identified (vendor/model)
#   "PASSIVE"  -- cannot be assessed from passive PCAP

_NERC_CIP_CONTROLS: List[Dict[str, Any]] = [
    {
        "id": "CIP-002-5.1 R1",
        "title": "BES Cyber Asset Identification",
        "severity": "high",
        "vulns": ["DEVICE_ID"],
        "rec": "Maintain a complete inventory of BES Cyber Assets with vendor, model, and firmware.",
    },
    {
        "id": "CIP-005-6 R1",
        "title": "Electronic Security Perimeter",
        "severity": "critical",
        "vulns": ["ZV-001", "ZV-002", "ZV-003", "ZV-004", "ZV-005"],
        "rec": "Enforce network segmentation with firewalls/data diodes at zone boundaries.",
    },
    {
        "id": "CIP-005-6 R2",
        "title": "Interactive Remote Access",
        "severity": "critical",
        "vulns": ["OT-ITOT-001"],
        "rec": "Remove direct RDP/VNC access to OT zones; use jump servers with MFA.",
    },
    {
        "id": "CIP-007-6 R1",
        "title": "Ports and Services",
        "severity": "high",
        "vulns": ["OT-GEN-002", "OT-ITOT-005"],
        "rec": "Disable unnecessary services and close unused ports on OT devices.",
    },
    {
        "id": "CIP-007-6 R2",
        "title": "Security Patch Management",
        "severity": "critical",
        "vulns": ["CVE:now"],
        "rec": "Apply vendor patches for all NOW-priority CVEs or implement compensating controls.",
    },
    {
        "id": "CIP-007-6 R5",
        "title": "System Access Controls",
        "severity": "critical",
        "vulns": ["RTU-DNP3-001", "RTU-DNP3-002", "RTU-104-003"],
        "rec": "Enable authentication on all SCADA control protocols (DNP3 SA, IEC 62351).",
    },
    {
        "id": "CIP-010-3 R1",
        "title": "Configuration Change Management",
        "severity": "high",
        "vulns": ["RTU-61850-004"],
        "rec": "Monitor and baseline GOOSE confRev values; alert on unexpected changes.",
    },
    {
        "id": "CIP-010-3 R2",
        "title": "Configuration Monitoring",
        "severity": "medium",
        "vulns": ["DEVICE_ID"],
        "rec": "Establish device baselines via passive fingerprinting and monitor for drift.",
    },
    {
        "id": "CIP-011-2 R1",
        "title": "Information Protection",
        "severity": "high",
        "vulns": ["OT-GEN-001"],
        "rec": "Replace cleartext protocols with encrypted alternatives (TLS, IPsec, MACsec).",
    },
    {
        "id": "CIP-013-1 R1",
        "title": "Supply Chain Risk Management",
        "severity": "high",
        "vulns": ["CVE:any"],
        "rec": "Track known CVEs for all deployed ICS products and maintain a software BOM.",
    },
    {
        "id": "CIP-005-6 R1.5",
        "title": "Inbound/Outbound Access Permissions",
        "severity": "high",
        "vulns": ["ZV-004"],
        "rec": "Restrict OT protocol traffic to designated control zones; block outbound leaks.",
    },
    {
        "id": "CIP-007-6 R3",
        "title": "Malicious Code Prevention",
        "severity": "high",
        "vulns": ["OT-ITOT-004"],
        "rec": "Block SMB/file sharing in OT zones; deploy application whitelisting.",
    },
    {
        "id": "CIP-007-6 R4",
        "title": "Security Event Monitoring",
        "severity": "medium",
        "vulns": ["PASSIVE"],
        "rec": "Deploy centralized log collection and SIEM monitoring for OT networks.",
    },
    {
        "id": "CIP-005-6 R2.4",
        "title": "Default Deny and Multi-Master Restriction",
        "severity": "medium",
        "vulns": ["RTU-DNP3-006", "RTU-104-002"],
        "rec": "Restrict multiple masters per outstation; enforce default-deny on perimeter.",
    },
    {
        "id": "CIP-003-8 R4",
        "title": "Physical Security of BES Cyber Systems",
        "severity": "high",
        "vulns": ["OT-ITOT-003"],
        "rec": "Eliminate Telnet cleartext access; use SSH with certificate authentication.",
    },
]

_IEC_62443_CONTROLS: List[Dict[str, Any]] = [
    {
        "id": "SR 1.1",
        "title": "Human User Identification and Authentication",
        "severity": "high",
        "vulns": ["RTU-DNP3-001", "OT-MQTT-002"],
        "rec": "Require authentication for all human users accessing control systems.",
    },
    {
        "id": "SR 1.13",
        "title": "Remote Access Control",
        "severity": "critical",
        "vulns": ["OT-ITOT-001"],
        "rec": "Use encrypted, MFA-protected remote access through monitored jump servers.",
    },
    {
        "id": "SR 3.1",
        "title": "Communication Integrity",
        "severity": "high",
        "vulns": ["RTU-DNP3-002", "RTU-104-003"],
        "rec": "Enable message authentication to ensure integrity of control commands.",
    },
    {
        "id": "SR 4.1",
        "title": "Information Confidentiality",
        "severity": "high",
        "vulns": ["OT-GEN-001", "RTU-104-001"],
        "rec": "Encrypt sensitive OT communications to prevent eavesdropping.",
    },
    {
        "id": "SR 4.3",
        "title": "Use of Cryptography",
        "severity": "high",
        "vulns": ["OT-GEN-001", "OT-OPCUA-001"],
        "rec": "Deploy TLS/DTLS or application-layer encryption for all control traffic.",
    },
    {
        "id": "SR 5.1",
        "title": "Network Segmentation",
        "severity": "critical",
        "vulns": ["ZV-001", "ZV-002", "ZV-003", "ZV-004", "ZV-005"],
        "rec": "Implement zone-based segmentation per IEC 62443 / Purdue reference model.",
    },
    {
        "id": "SR 5.2",
        "title": "Zone Boundary Protection",
        "severity": "high",
        "vulns": ["ZV-002", "ZV-003"],
        "rec": "Deploy conduit-level inspection at zone boundaries (firewalls, data diodes).",
    },
    {
        "id": "SR 7.1",
        "title": "Denial of Service Protection",
        "severity": "medium",
        "vulns": ["RTU-104-005"],
        "rec": "Rate-limit connections and commands; deploy ICS-aware intrusion prevention.",
    },
    {
        "id": "SR 7.6",
        "title": "Network and Security Configuration Settings",
        "severity": "medium",
        "vulns": ["OT-GEN-002", "OT-GEN-004"],
        "rec": "Harden device configurations; disable unused services and protocols.",
    },
    {
        "id": "SR 7.7",
        "title": "Least Functionality",
        "severity": "medium",
        "vulns": ["OT-GEN-002", "OT-ITOT-005"],
        "rec": "Restrict devices to only the protocols and services required for operation.",
    },
    {
        "id": "SR 3.5",
        "title": "Input Validation",
        "severity": "medium",
        "vulns": ["RTU-DNP3-003"],
        "rec": "Validate control commands before execution; enforce Select-Before-Operate.",
    },
    {
        "id": "SR 2.8",
        "title": "Auditable Events",
        "severity": "medium",
        "vulns": ["RTU-61850-004"],
        "rec": "Log configuration changes, control commands, and authentication events.",
    },
]

_NIST_800_82_CONTROLS: List[Dict[str, Any]] = [
    {
        "id": "5.1",
        "title": "ICS Network Architecture",
        "severity": "critical",
        "vulns": ["ZV-001", "ZV-002", "ZV-003", "ZV-004", "ZV-005"],
        "rec": "Implement defence-in-depth network architecture with Purdue model segmentation.",
    },
    {
        "id": "6.2.1",
        "title": "Restrict Logical Access to ICS Networks",
        "severity": "high",
        "vulns": ["RTU-DNP3-001", "RTU-DNP3-002", "RTU-104-001"],
        "rec": "Enforce authentication and access control on all ICS network interfaces.",
    },
    {
        "id": "6.2.5",
        "title": "Restrict ICS Logical Access -- Least Functionality",
        "severity": "medium",
        "vulns": ["OT-GEN-002", "OT-ITOT-005"],
        "rec": "Disable unneeded ports, protocols, and services on ICS components.",
    },
    {
        "id": "6.2.7",
        "title": "Encrypt ICS Communications Where Feasible",
        "severity": "high",
        "vulns": ["OT-GEN-001", "OT-OPCUA-001"],
        "rec": "Encrypt communications using TLS, IPsec, or protocol-specific security layers.",
    },
    {
        "id": "6.2.8",
        "title": "Remote Access to ICS",
        "severity": "critical",
        "vulns": ["OT-ITOT-001"],
        "rec": "Restrict remote access via jump servers, VPNs with MFA, and session recording.",
    },
    {
        "id": "6.2.9",
        "title": "Audit and Accountability",
        "severity": "medium",
        "vulns": ["RTU-61850-004"],
        "rec": "Implement centralised logging of OT events, control commands, and changes.",
    },
    {
        "id": "6.3.3",
        "title": "Patch Management",
        "severity": "critical",
        "vulns": ["CVE:now"],
        "rec": "Prioritise patching of NOW-priority CVEs; test patches in staging first.",
    },
    {
        "id": "6.3.4",
        "title": "Malware Detection and Prevention",
        "severity": "high",
        "vulns": ["OT-ITOT-004"],
        "rec": "Deploy application whitelisting and block file-sharing protocols in OT zones.",
    },
]


# ────────────────────────────────────────────────── Compliance Mapper ──

class ComplianceMapper:
    """
    Map OT scan findings to NERC CIP, IEC 62443, and NIST 800-82 controls.

    Evaluates each control's pass/fail status based on the presence of
    related vulnerability IDs, CVE matches, and zone violations in the
    scan results.

    Parameters
    ----------
    devices : list[OTDevice]
        Discovered devices with their vulnerability findings and CVE matches.
    zones : list[NetworkZone], optional
        Detected network zones (used for segmentation checks).
    violations : list[ZoneViolation], optional
        Detected Purdue model zone violations.
    """

    def __init__(
        self,
        devices: List[OTDevice],
        zones: Optional[List[NetworkZone]] = None,
        violations: Optional[List[ZoneViolation]] = None,
    ) -> None:
        self.devices = devices
        self.zones = zones or []
        self.violations = violations or []

        # Pre-index scan data for fast lookups
        self._vuln_ids: Set[str] = set()
        self._vuln_by_id: Dict[str, List[Dict[str, str]]] = {}
        self._cve_now: Set[str] = set()
        self._cve_any: Set[str] = set()
        self._violation_ids: Set[str] = set()
        self._devices_identified: int = 0
        self._total_devices: int = len(devices)

        self._index_data()

    # ── public API ───────────────────────────────────────────────────

    def assess(self) -> Dict[str, List[ComplianceCheck]]:
        """Run compliance assessment against all three frameworks.

        Returns
        -------
        dict
            ``{framework_name: [ComplianceCheck, ...]}`` for each framework.
        """
        return {
            "NERC CIP":   self._assess_framework("NERC CIP", _NERC_CIP_CONTROLS),
            "IEC 62443":  self._assess_framework("IEC 62443", _IEC_62443_CONTROLS),
            "NIST 800-82": self._assess_framework("NIST 800-82", _NIST_800_82_CONTROLS),
        }

    def to_text(self) -> str:
        """Generate a formatted text compliance report.

        Returns
        -------
        str
            Multi-line compliance report suitable for console or file output.
        """
        results = self.assess()
        sections: List[str] = []

        for framework, checks in results.items():
            header = f"{framework} COMPLIANCE ASSESSMENT"
            sections.append(header)
            sections.append("=" * len(header))

            pass_count = sum(1 for c in checks if c.status == "pass")
            fail_count = sum(1 for c in checks if c.status == "fail")
            warn_count = sum(1 for c in checks if c.status == "warning")
            na_count = sum(1 for c in checks if c.status == "not_assessed")

            sections.append(
                f"  Pass: {pass_count}  |  Fail: {fail_count}  "
                f"|  Warning: {warn_count}  |  N/A: {na_count}"
            )
            sections.append("")

            for check in checks:
                status_tag = {
                    "pass": "[PASS] ",
                    "fail": "[FAIL] ",
                    "warning": "[WARN] ",
                    "not_assessed": "[N/A]  ",
                }.get(check.status, "[????] ")

                sections.append(
                    f"{status_tag} {check.control_id} -- {check.title}"
                )
                sections.append(f"        Finding: {check.finding}")
                sections.append(f"        Action:  {check.recommendation}")
                if check.related_vulns:
                    sections.append(
                        f"        Vulns:   {', '.join(check.related_vulns)}"
                    )
                sections.append("")

            sections.append("")

        return "\n".join(sections)

    def to_dict(self) -> Dict[str, Any]:
        """Generate compliance data suitable for JSON serialisation.

        Returns
        -------
        dict
            Structured compliance data including summary statistics and
            per-control details for each framework.
        """
        results = self.assess()
        output: Dict[str, Any] = {
            "summary": {},
            "frameworks": {},
        }

        total_pass = 0
        total_fail = 0
        total_warn = 0
        total_na = 0

        for framework, checks in results.items():
            fw_pass = sum(1 for c in checks if c.status == "pass")
            fw_fail = sum(1 for c in checks if c.status == "fail")
            fw_warn = sum(1 for c in checks if c.status == "warning")
            fw_na = sum(1 for c in checks if c.status == "not_assessed")

            total_pass += fw_pass
            total_fail += fw_fail
            total_warn += fw_warn
            total_na += fw_na

            assessed = fw_pass + fw_fail + fw_warn
            score = round((fw_pass / assessed * 100) if assessed > 0 else 0, 1)

            output["frameworks"][framework] = {
                "summary": {
                    "total_controls": len(checks),
                    "pass": fw_pass,
                    "fail": fw_fail,
                    "warning": fw_warn,
                    "not_assessed": fw_na,
                    "compliance_score_pct": score,
                },
                "controls": [
                    {
                        "control_id": c.control_id,
                        "title": c.title,
                        "status": c.status,
                        "severity": c.severity,
                        "finding": c.finding,
                        "recommendation": c.recommendation,
                        "related_vulns": c.related_vulns,
                    }
                    for c in checks
                ],
            }

        total_assessed = total_pass + total_fail + total_warn
        output["summary"] = {
            "total_controls": total_pass + total_fail + total_warn + total_na,
            "pass": total_pass,
            "fail": total_fail,
            "warning": total_warn,
            "not_assessed": total_na,
            "overall_compliance_pct": round(
                (total_pass / total_assessed * 100) if total_assessed > 0 else 0, 1
            ),
            "devices_scanned": self._total_devices,
            "devices_identified": self._devices_identified,
            "zone_violations": len(self.violations),
            "unique_vulns": len(self._vuln_ids),
            "cve_now_count": len(self._cve_now),
        }

        return output

    # ── internal ─────────────────────────────────────────────────────

    def _index_data(self) -> None:
        """Pre-index scan data for efficient control evaluation."""
        for dev in self.devices:
            # Track device identification
            if dev.vendor or dev.model:
                self._devices_identified += 1

            # Index vulnerability IDs
            for vuln in dev.vulnerabilities:
                self._vuln_ids.add(vuln.vuln_id)
                if vuln.vuln_id not in self._vuln_by_id:
                    self._vuln_by_id[vuln.vuln_id] = []
                self._vuln_by_id[vuln.vuln_id].append({
                    "device_ip": dev.ip,
                    "title": vuln.title,
                    "severity": vuln.severity,
                })

            # Index CVE matches
            for cve in dev.cve_matches:
                self._cve_any.add(cve.cve_id)
                if cve.priority == "now":
                    self._cve_now.add(cve.cve_id)

        # Index zone violations
        for zv in self.violations:
            self._violation_ids.add(zv.violation_id)

    def _assess_framework(
        self,
        framework_name: str,
        controls: List[Dict[str, Any]],
    ) -> List[ComplianceCheck]:
        """Evaluate all controls for a single compliance framework.

        Parameters
        ----------
        framework_name : str
            Display name of the framework.
        controls : list[dict]
            Control definitions from the framework constant.

        Returns
        -------
        list[ComplianceCheck]
            Evaluated controls sorted by status (fail first, then warn,
            pass, not_assessed).
        """
        checks: List[ComplianceCheck] = []

        for ctrl in controls:
            check = self._evaluate_control(framework_name, ctrl)
            checks.append(check)

        # Sort: fail -> warning -> pass -> not_assessed
        status_order = {"fail": 0, "warning": 1, "pass": 2, "not_assessed": 3}
        checks.sort(key=lambda c: status_order.get(c.status, 4))
        return checks

    def _evaluate_control(
        self,
        framework: str,
        ctrl: Dict[str, Any],
    ) -> ComplianceCheck:
        """Evaluate a single control against indexed scan data.

        Special vuln ID prefixes handled:
          - ``DEVICE_ID``  -- passes if devices were identified
          - ``PASSIVE``    -- always not_assessed (requires active scan)
          - ``CVE:now``    -- fails if any NOW-priority CVEs exist
          - ``CVE:any``    -- fails if any CVEs matched at all
          - ``ZV-*``       -- checks zone violation IDs
          - All others     -- checked against vulnerability finding IDs
        """
        control_id: str = ctrl["id"]
        title: str = ctrl["title"]
        severity: str = ctrl["severity"]
        related_vuln_patterns: List[str] = ctrl["vulns"]
        recommendation: str = ctrl["rec"]

        # Check for PASSIVE controls first
        if "PASSIVE" in related_vuln_patterns:
            return ComplianceCheck(
                framework=framework,
                control_id=control_id,
                title=title,
                status="not_assessed",
                severity=severity,
                finding="Cannot be assessed from passive PCAP analysis alone.",
                recommendation=recommendation,
                related_vulns=[],
            )

        # Check for DEVICE_ID controls
        if "DEVICE_ID" in related_vuln_patterns:
            if self._devices_identified >= self._total_devices and self._total_devices > 0:
                return ComplianceCheck(
                    framework=framework,
                    control_id=control_id,
                    title=title,
                    status="pass",
                    severity=severity,
                    finding=(
                        f"{self._devices_identified} of {self._total_devices} "
                        f"devices identified with vendor/model information."
                    ),
                    recommendation=recommendation,
                    related_vulns=[],
                )
            elif self._devices_identified > 0:
                return ComplianceCheck(
                    framework=framework,
                    control_id=control_id,
                    title=title,
                    status="warning",
                    severity=severity,
                    finding=(
                        f"Only {self._devices_identified} of {self._total_devices} "
                        f"devices have vendor/model identification."
                    ),
                    recommendation=recommendation,
                    related_vulns=[],
                )
            else:
                return ComplianceCheck(
                    framework=framework,
                    control_id=control_id,
                    title=title,
                    status="fail",
                    severity=severity,
                    finding="No devices identified with vendor/model information.",
                    recommendation=recommendation,
                    related_vulns=[],
                )

        # Collect matched vuln IDs for this control
        matched_vulns: List[str] = []
        matched_details: List[str] = []

        for pattern in related_vuln_patterns:
            if pattern == "CVE:now":
                if self._cve_now:
                    for cve_id in sorted(self._cve_now):
                        matched_vulns.append(cve_id)
                    matched_details.append(
                        f"{len(self._cve_now)} NOW-priority CVE(s) unpatched: "
                        f"{', '.join(sorted(self._cve_now)[:5])}"
                    )
            elif pattern == "CVE:any":
                if self._cve_any:
                    for cve_id in sorted(self._cve_any):
                        matched_vulns.append(cve_id)
                    matched_details.append(
                        f"{len(self._cve_any)} known CVE(s) matched to deployed devices."
                    )
            elif pattern.startswith("ZV-"):
                if pattern in self._violation_ids:
                    matched_vulns.append(pattern)
                    # Find details from violations list
                    for zv in self.violations:
                        if zv.violation_id == pattern:
                            matched_details.append(
                                f"{zv.violation_id}: {zv.title} "
                                f"({zv.src_ip} -> {zv.dst_ip})"
                            )
                            break
            else:
                # Standard vulnerability ID
                if pattern in self._vuln_ids:
                    matched_vulns.append(pattern)
                    hits = self._vuln_by_id.get(pattern, [])
                    for hit in hits[:3]:  # limit detail lines
                        matched_details.append(
                            f"{pattern} on {hit['device_ip']}: {hit['title']}"
                        )

        # Determine status
        if matched_vulns:
            finding = "; ".join(matched_details) if matched_details else (
                f"Findings detected: {', '.join(matched_vulns)}"
            )
            return ComplianceCheck(
                framework=framework,
                control_id=control_id,
                title=title,
                status="fail",
                severity=severity,
                finding=finding,
                recommendation=recommendation,
                related_vulns=matched_vulns,
            )
        else:
            # No matching vulns found -- control passes
            return ComplianceCheck(
                framework=framework,
                control_id=control_id,
                title=title,
                status="pass",
                severity=severity,
                finding="No related findings detected in scan results.",
                recommendation=recommendation,
                related_vulns=[],
            )
