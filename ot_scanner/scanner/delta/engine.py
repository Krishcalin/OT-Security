"""
Delta / Diff Engine for OT Scan Results.

Compares two JSON scan results (baseline vs current) to identify changes
in the OT environment — new devices, resolved vulnerabilities, risk
escalations, protocol changes, firmware updates, and more.

Usage:
    from scanner.delta.engine import DeltaEngine

    engine = DeltaEngine()
    report = engine.compare("baseline.json", "current.json")
    print(report.to_text())
"""
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


# ── Severity ordering ──────────────────────────────────────────────────────

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "unknown": -1,
}

# IT protocols classified as high-risk in an OT environment
HIGH_RISK_IT_PROTOCOLS = {
    "RDP", "SMB", "Telnet", "FTP", "TFTP", "VNC",
    "SNMP-v1", "SNMP-v2c", "HTTP",
}


# ── Data classes ───────────────────────────────────────────────────────────

@dataclass
class DeltaChange:
    """A single detected change between baseline and current scan."""
    change_type: str        # "new_device" | "removed_device" | "new_vuln" | "resolved_vuln"
                            # | "new_cve" | "new_protocol" | "removed_protocol"
                            # | "risk_change" | "firmware_change" | "new_it_protocol"
                            # | "new_zone_violation"
    severity: str           # critical | high | medium | low | info
    device_ip: str
    title: str
    description: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "change_type":  self.change_type,
            "severity":     self.severity,
            "device_ip":    self.device_ip,
            "title":        self.title,
            "description":  self.description,
            "old_value":    self.old_value,
            "new_value":    self.new_value,
        }


@dataclass
class DeltaReport:
    """Full diff report comparing baseline and current scan results."""
    baseline_file: str
    current_file: str
    baseline_timestamp: str
    current_timestamp: str
    changes: List[DeltaChange] = field(default_factory=list)
    # Summary counts
    new_devices: int = 0
    removed_devices: int = 0
    new_vulns: int = 0
    resolved_vulns: int = 0
    new_cves: int = 0
    risk_changes: int = 0
    baseline_device_count: int = 0
    current_device_count: int = 0

    def to_dict(self) -> dict:
        return {
            "baseline_file":        self.baseline_file,
            "current_file":         self.current_file,
            "baseline_timestamp":   self.baseline_timestamp,
            "current_timestamp":    self.current_timestamp,
            "baseline_device_count": self.baseline_device_count,
            "current_device_count": self.current_device_count,
            "summary": {
                "new_devices":      self.new_devices,
                "removed_devices":  self.removed_devices,
                "new_vulns":        self.new_vulns,
                "resolved_vulns":   self.resolved_vulns,
                "new_cves":         self.new_cves,
                "risk_changes":     self.risk_changes,
                "total_changes":    len(self.changes),
            },
            "changes": [c.to_dict() for c in self.changes],
        }

    def to_text(self) -> str:
        """Generate a human-readable text report of the delta analysis."""
        lines: List[str] = []

        # Header
        lines.append(f"DELTA ANALYSIS: {self.baseline_file} -> {self.current_file}")
        lines.append("=" * 72)
        lines.append(f"Baseline: {self.baseline_timestamp} ({self.baseline_device_count} devices)")
        lines.append(f"Current:  {self.current_timestamp} ({self.current_device_count} devices)")
        lines.append("")

        # Summary
        lines.append("SUMMARY")
        lines.append(f"  New devices:          {self.new_devices}")
        lines.append(f"  Removed devices:      {self.removed_devices}")
        lines.append(f"  New vulnerabilities:  {self.new_vulns}")
        lines.append(f"  Resolved vulns:       {self.resolved_vulns}")
        lines.append(f"  New CVE matches:      {self.new_cves}")
        lines.append(f"  Risk escalations:     {self.risk_changes}")
        lines.append(f"  Total changes:        {len(self.changes)}")
        lines.append("")

        if not self.changes:
            lines.append("No changes detected between baseline and current scan.")
            return "\n".join(lines)

        # Changes sorted by severity (highest first)
        sorted_changes = sorted(
            self.changes,
            key=lambda c: -SEVERITY_ORDER.get(c.severity, -1),
        )

        lines.append("CHANGES (sorted by severity)")
        for ch in sorted_changes:
            sev_tag = f"[{ch.severity.upper():<8}]"
            lines.append(f"  {sev_tag} {ch.device_ip:<16} {ch.title}")
            if ch.description:
                lines.append(f"{'':>30} {ch.description}")

        lines.append("")
        lines.append(f"--- End of delta report ({len(self.changes)} change(s)) ---")
        return "\n".join(lines)


# ── Delta Engine ───────────────────────────────────────────────────────────

class DeltaEngine:
    """
    Compare two OT scan JSON files and produce a delta report.

    Detects:
      - New / removed devices
      - New / resolved vulnerabilities
      - New CVE matches
      - New / removed OT protocols
      - Risk level changes (escalation or improvement)
      - Firmware changes
      - New IT protocols in OT zone
      - New zone violations
    """

    def compare(self, baseline_path: str, current_path: str) -> DeltaReport:
        """
        Compare two OT scan JSON files and return a DeltaReport.

        Args:
            baseline_path: Path to the baseline (older) scan JSON file.
            current_path:  Path to the current (newer) scan JSON file.

        Returns:
            DeltaReport with all detected changes.
        """
        with open(baseline_path, "r", encoding="utf-8") as fh:
            baseline_data = json.load(fh)

        with open(current_path, "r", encoding="utf-8") as fh:
            current_data = json.load(fh)

        # Extract device lists
        baseline_devices = baseline_data.get("devices", [])
        current_devices = current_data.get("devices", [])

        # Extract timestamps
        baseline_ts = baseline_data.get("scan_metadata", {}).get("generated", "unknown")
        current_ts = current_data.get("scan_metadata", {}).get("generated", "unknown")

        report = self.compare_devices(baseline_devices, current_devices)
        report.baseline_file = baseline_path
        report.current_file = current_path
        report.baseline_timestamp = baseline_ts
        report.current_timestamp = current_ts

        # Zone violation changes
        baseline_violations = baseline_data.get("zone_violations", [])
        current_violations = current_data.get("zone_violations", [])
        self._compare_zone_violations(baseline_violations, current_violations, report)

        return report

    def compare_devices(
        self,
        baseline: List[dict],
        current: List[dict],
    ) -> DeltaReport:
        """
        Compare two device lists (already parsed from JSON) and return a DeltaReport.

        Args:
            baseline: List of device dicts from the baseline scan.
            current:  List of device dicts from the current scan.

        Returns:
            DeltaReport with all detected changes.
        """
        report = DeltaReport(
            baseline_file="",
            current_file="",
            baseline_timestamp="",
            current_timestamp="",
            baseline_device_count=len(baseline),
            current_device_count=len(current),
        )

        # Build IP -> device lookup
        baseline_map: Dict[str, dict] = {d["ip"]: d for d in baseline if "ip" in d}
        current_map: Dict[str, dict] = {d["ip"]: d for d in current if "ip" in d}

        baseline_ips: Set[str] = set(baseline_map.keys())
        current_ips: Set[str] = set(current_map.keys())

        # ── New devices ────────────────────────────────────────────────────
        new_ips = current_ips - baseline_ips
        for ip in sorted(new_ips):
            dev = current_map[ip]
            risk = dev.get("risk_level", "unknown")
            severity = self._risk_to_severity(risk)
            vendor = dev.get("make") or dev.get("vendor") or "Unknown"
            model = dev.get("model") or ""
            device_label = f"{vendor} {model}".strip()
            report.changes.append(DeltaChange(
                change_type="new_device",
                severity=severity,
                device_ip=ip,
                title=f"New device -- {device_label} (risk: {risk})",
                description=f"Device type: {dev.get('device_type', 'unknown')}, "
                            f"role: {dev.get('role', 'unknown')}",
                new_value=device_label,
            ))
        report.new_devices = len(new_ips)

        # ── Removed devices ────────────────────────────────────────────────
        removed_ips = baseline_ips - current_ips
        for ip in sorted(removed_ips):
            dev = baseline_map[ip]
            vendor = dev.get("make") or dev.get("vendor") or "Unknown"
            model = dev.get("model") or ""
            device_label = f"{vendor} {model}".strip()
            report.changes.append(DeltaChange(
                change_type="removed_device",
                severity="info",
                device_ip=ip,
                title=f"Device removed -- {device_label}",
                description="Device no longer observed in current scan",
                old_value=device_label,
            ))
        report.removed_devices = len(removed_ips)

        # ── Compare devices present in both scans ──────────────────────────
        common_ips = baseline_ips & current_ips
        for ip in sorted(common_ips):
            b_dev = baseline_map[ip]
            c_dev = current_map[ip]
            self._compare_single_device(b_dev, c_dev, report)

        return report

    # ── Private comparison helpers ─────────────────────────────────────────

    def _compare_single_device(
        self,
        b_dev: dict,
        c_dev: dict,
        report: DeltaReport,
    ) -> None:
        """Compare a single device across baseline and current."""
        ip = c_dev["ip"]

        # Vulnerabilities
        self._compare_vulns(ip, b_dev, c_dev, report)

        # CVE matches
        self._compare_cves(ip, b_dev, c_dev, report)

        # OT Protocols
        self._compare_protocols(ip, b_dev, c_dev, report)

        # Risk level
        self._compare_risk(ip, b_dev, c_dev, report)

        # Firmware
        self._compare_firmware(ip, b_dev, c_dev, report)

        # IT protocols
        self._compare_it_protocols(ip, b_dev, c_dev, report)

    def _compare_vulns(
        self,
        ip: str,
        b_dev: dict,
        c_dev: dict,
        report: DeltaReport,
    ) -> None:
        """Detect new and resolved vulnerabilities."""
        b_vulns = {v.get("vuln_id", ""): v for v in b_dev.get("vulnerabilities", [])}
        c_vulns = {v.get("vuln_id", ""): v for v in c_dev.get("vulnerabilities", [])}

        b_ids: Set[str] = set(b_vulns.keys()) - {""}
        c_ids: Set[str] = set(c_vulns.keys()) - {""}

        # New vulnerabilities
        for vid in sorted(c_ids - b_ids):
            vuln = c_vulns[vid]
            sev = vuln.get("severity", "medium")
            report.changes.append(DeltaChange(
                change_type="new_vuln",
                severity=sev,
                device_ip=ip,
                title=f"New vulnerability -- {vid} {vuln.get('title', '')}",
                description=vuln.get("description", ""),
                new_value=vid,
            ))
            report.new_vulns += 1

        # Resolved vulnerabilities
        for vid in sorted(b_ids - c_ids):
            vuln = b_vulns[vid]
            report.changes.append(DeltaChange(
                change_type="resolved_vuln",
                severity="info",
                device_ip=ip,
                title=f"Vulnerability resolved -- {vid}",
                description=f"Previously: {vuln.get('title', '')}",
                old_value=vid,
            ))
            report.resolved_vulns += 1

    def _compare_cves(
        self,
        ip: str,
        b_dev: dict,
        c_dev: dict,
        report: DeltaReport,
    ) -> None:
        """Detect new CVE matches."""
        b_cves: Set[str] = {
            c.get("cve_id", "") for c in b_dev.get("cve_matches", [])
        } - {""}
        c_cves_list = c_dev.get("cve_matches", [])
        c_cves_map = {c.get("cve_id", ""): c for c in c_cves_list}
        c_cve_ids: Set[str] = set(c_cves_map.keys()) - {""}

        for cve_id in sorted(c_cve_ids - b_cves):
            cve = c_cves_map[cve_id]
            sev = cve.get("severity", "high")
            cvss = cve.get("cvss_score", 0.0)
            priority = cve.get("priority", "next")
            report.changes.append(DeltaChange(
                change_type="new_cve",
                severity=sev,
                device_ip=ip,
                title=f"New CVE match -- {cve_id} (CVSS {cvss:.1f}, priority: {priority})",
                description=cve.get("title", ""),
                new_value=cve_id,
            ))
            report.new_cves += 1

    def _compare_protocols(
        self,
        ip: str,
        b_dev: dict,
        c_dev: dict,
        report: DeltaReport,
    ) -> None:
        """Detect new and removed OT protocols."""
        b_protos: Set[str] = {
            p.get("protocol", "") for p in b_dev.get("protocols", [])
        } - {""}
        c_protos: Set[str] = {
            p.get("protocol", "") for p in c_dev.get("protocols", [])
        } - {""}

        for proto in sorted(c_protos - b_protos):
            report.changes.append(DeltaChange(
                change_type="new_protocol",
                severity="medium",
                device_ip=ip,
                title=f"New protocol -- {proto} detected",
                description=f"Protocol {proto} was not seen on this device in the baseline scan",
                new_value=proto,
            ))

        for proto in sorted(b_protos - c_protos):
            report.changes.append(DeltaChange(
                change_type="removed_protocol",
                severity="low",
                device_ip=ip,
                title=f"Protocol removed -- {proto} no longer seen",
                description=f"Protocol {proto} was present in baseline but not in current scan",
                old_value=proto,
            ))

    def _compare_risk(
        self,
        ip: str,
        b_dev: dict,
        c_dev: dict,
        report: DeltaReport,
    ) -> None:
        """Detect risk level changes."""
        b_risk = b_dev.get("risk_level", "unknown")
        c_risk = c_dev.get("risk_level", "unknown")

        if b_risk == c_risk:
            return

        b_order = SEVERITY_ORDER.get(b_risk, -1)
        c_order = SEVERITY_ORDER.get(c_risk, -1)

        if c_order > b_order:
            # Risk escalated
            severity = "high" if c_order >= 3 else "medium"
            report.changes.append(DeltaChange(
                change_type="risk_change",
                severity=severity,
                device_ip=ip,
                title=f"Risk escalated: {b_risk} -> {c_risk}",
                description="Device risk level increased since baseline scan",
                old_value=b_risk,
                new_value=c_risk,
            ))
            report.risk_changes += 1
        else:
            # Risk improved
            report.changes.append(DeltaChange(
                change_type="risk_change",
                severity="info",
                device_ip=ip,
                title=f"Risk improved: {b_risk} -> {c_risk}",
                description="Device risk level decreased since baseline scan",
                old_value=b_risk,
                new_value=c_risk,
            ))

    def _compare_firmware(
        self,
        ip: str,
        b_dev: dict,
        c_dev: dict,
        report: DeltaReport,
    ) -> None:
        """Detect firmware changes."""
        b_fw = b_dev.get("firmware") or ""
        c_fw = c_dev.get("firmware") or ""

        if b_fw == c_fw:
            return
        if not b_fw and not c_fw:
            return

        report.changes.append(DeltaChange(
            change_type="firmware_change",
            severity="medium",
            device_ip=ip,
            title=f"Firmware changed: {b_fw or '(unknown)'} -> {c_fw or '(unknown)'}",
            description="Device firmware version changed between scans",
            old_value=b_fw or None,
            new_value=c_fw or None,
        ))

    def _compare_it_protocols(
        self,
        ip: str,
        b_dev: dict,
        c_dev: dict,
        report: DeltaReport,
    ) -> None:
        """Detect new IT protocols appearing on OT devices."""
        b_it: Set[str] = {
            h.get("protocol", "") for h in b_dev.get("it_protocols", [])
        } - {""}
        c_it: Set[str] = {
            h.get("protocol", "") for h in c_dev.get("it_protocols", [])
        } - {""}

        for proto in sorted(c_it - b_it):
            is_high_risk = proto in HIGH_RISK_IT_PROTOCOLS
            report.changes.append(DeltaChange(
                change_type="new_it_protocol",
                severity="high" if is_high_risk else "medium",
                device_ip=ip,
                title=f"New IT protocol -- {proto}"
                      + (" (HIGH RISK)" if is_high_risk else ""),
                description=f"IT protocol {proto} detected on OT device for the first time",
                new_value=proto,
            ))

    def _compare_zone_violations(
        self,
        baseline_violations: List[dict],
        current_violations: List[dict],
        report: DeltaReport,
    ) -> None:
        """Detect new zone segmentation violations."""
        def _viol_key(v: dict) -> str:
            return f"{v.get('src_ip', '')}->{v.get('dst_ip', '')}:{v.get('protocol', '')}"

        b_keys = {_viol_key(v) for v in baseline_violations}

        for v in current_violations:
            key = _viol_key(v)
            if key not in b_keys:
                sev = v.get("severity", "high")
                report.changes.append(DeltaChange(
                    change_type="new_zone_violation",
                    severity=sev,
                    device_ip=v.get("src_ip", "unknown"),
                    title=f"New zone violation -- {v.get('title', key)}",
                    description=(
                        f"{v.get('src_ip', '?')} (L{v.get('src_purdue', '?')}) -> "
                        f"{v.get('dst_ip', '?')} (L{v.get('dst_purdue', '?')}) "
                        f"via {v.get('protocol', '?')}"
                    ),
                ))

    @staticmethod
    def _risk_to_severity(risk_level: str) -> str:
        """Map a device risk_level to a change severity for new device alerts."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "unknown": "info",
        }
        return mapping.get(risk_level, "info")
