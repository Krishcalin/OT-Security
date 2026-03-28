"""
CEF and LEEF syslog exporter for OT Passive Scanner findings.

Generates syslog-formatted events from scan findings for ingestion into
enterprise SIEMs:
  - CEF (Common Event Format)  -- ArcSight, Splunk, Elastic
  - LEEF (Log Event Extended Format) -- IBM QRadar

Each vulnerability finding, CVE match, and zone violation on every scanned
device is emitted as a single log line with structured key-value metadata.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List

from ..models import OTDevice, ZoneViolation


# ────────────────────────────────────────────────── Severity Mapping ──

_CEF_SEVERITY = {
    "critical": 10,
    "high":     8,
    "medium":   5,
    "low":      3,
    "info":     1,
}


# ────────────────────────────────────────────────── Helpers ──

def _escape_cef_header(value: str) -> str:
    """Escape pipes and backslashes in CEF header fields."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_cef_value(value: str) -> str:
    """Escape backslashes, equals signs, and newlines in CEF extension values."""
    return (
        value
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", " ")
        .replace("\r", "")
    )


def _escape_leef_value(value: str) -> str:
    """Escape pipes, backslashes, equals, and tabs in LEEF key-value pairs."""
    return (
        value
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\t", " ")
        .replace("\n", " ")
        .replace("\r", "")
    )


def _truncate(text: str, maxlen: int) -> str:
    """Truncate a string to *maxlen* characters, appending '...' if trimmed."""
    if len(text) <= maxlen:
        return text
    return text[: maxlen - 3] + "..."


def _timestamp_rfc3339() -> str:
    """Return current UTC timestamp in RFC-3339 / syslog-compatible format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ────────────────────────────────────────────────── SIEMExporter ──

class SIEMExporter:
    """
    Export OT scan findings as CEF or LEEF syslog lines.

    Parameters
    ----------
    devices : list[OTDevice]
        Discovered devices with their vulnerability findings and CVE matches.
    zone_violations : list[ZoneViolation], optional
        Purdue-model zone violations to include in the export.
    scanner_name : str
        Product name embedded in each log line header.
    scanner_version : str
        Product version embedded in each log line header.
    """

    def __init__(
        self,
        devices: List[OTDevice],
        zone_violations: List[ZoneViolation] | None = None,
        scanner_name: str = "OT-Scanner",
        scanner_version: str = "2.0.0",
    ) -> None:
        self.devices = devices
        self.zone_violations = zone_violations or []
        self.scanner_name = scanner_name
        self.scanner_version = scanner_version

    # ── public API ───────────────────────────────────────────────────

    def to_cef(self, path: str) -> None:
        """Export findings as CEF (Common Event Format) syslog lines.

        One line per vulnerability finding, CVE match (priority now/next),
        and zone violation.
        """
        lines = self._build_cef_lines()
        self._write(path, lines)

    def to_leef(self, path: str) -> None:
        """Export findings as LEEF 2.0 (Log Event Extended Format) syslog lines.

        One line per vulnerability finding, CVE match (priority now/next),
        and zone violation.
        """
        lines = self._build_leef_lines()
        self._write(path, lines)

    def to_syslog(self, path: str, fmt: str = "cef") -> None:
        """Convenience method -- writes CEF or LEEF based on *fmt*.

        Parameters
        ----------
        path : str
            Destination file path.
        fmt : str
            ``"cef"`` (default) or ``"leef"``.
        """
        if fmt.lower() == "leef":
            self.to_leef(path)
        else:
            self.to_cef(path)

    # ── CEF builder ──────────────────────────────────────────────────

    def _build_cef_lines(self) -> List[str]:
        """Build all CEF syslog lines from devices, CVEs, and zone violations."""
        lines: List[str] = []
        ts = _timestamp_rfc3339()
        vendor = _escape_cef_header(self.scanner_name)
        product = _escape_cef_header("OT Passive Scanner")
        version = _escape_cef_header(self.scanner_version)

        for dev in self.devices:
            ip = dev.ip
            dev_vendor = dev.vendor or "Unknown"
            dev_model = dev.model or "Unknown"

            # Vulnerability findings
            for vuln in dev.vulnerabilities:
                sev_int = _CEF_SEVERITY.get(vuln.severity, 1)
                sig_id = _escape_cef_header(vuln.vuln_id)
                name = _escape_cef_header(vuln.title)

                ext = self._cef_vuln_extension(
                    ip, dev_vendor, dev_model, vuln.severity,
                    vuln.category, vuln.vuln_id, vuln.description,
                    vuln.remediation,
                )
                lines.append(
                    f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{sev_int}|{ext}"
                )

            # CVE matches (now and next priority)
            for cve in dev.cve_matches:
                if cve.priority not in ("now", "next"):
                    continue
                sev_int = _CEF_SEVERITY.get(cve.severity, 1)
                sig_id = _escape_cef_header(cve.cve_id)
                name = _escape_cef_header(cve.title or cve.cve_id)

                ext = self._cef_cve_extension(
                    ip, dev_vendor, dev_model, cve,
                )
                lines.append(
                    f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{sev_int}|{ext}"
                )

        # Zone violations
        for zv in self.zone_violations:
            sev_int = _CEF_SEVERITY.get(zv.severity, 1)
            sig_id = _escape_cef_header(zv.violation_id)
            name = _escape_cef_header(zv.title)

            ext = self._cef_zone_extension(zv)
            lines.append(
                f"CEF:0|{vendor}|{product}|{version}|{sig_id}|{name}|{sev_int}|{ext}"
            )

        return lines

    def _cef_vuln_extension(
        self,
        ip: str,
        dev_vendor: str,
        dev_model: str,
        severity: str,
        category: str,
        vuln_id: str,
        description: str,
        remediation: str,
    ) -> str:
        """Build CEF extension key=value string for a vulnerability finding."""
        parts = [
            f"src={ip}",
            f"dst={ip}",
            f"dvc={ip}",
            f"dvcVendor={_escape_cef_value(dev_vendor)}",
            f"dvcModel={_escape_cef_value(dev_model)}",
            f"cs1={_escape_cef_value(severity)}",
            "cs1Label=severity",
            f"cs2={_escape_cef_value(category)}",
            "cs2Label=category",
            f"cs3={_escape_cef_value(vuln_id)}",
            "cs3Label=vuln_id",
            f"msg={_escape_cef_value(_truncate(description, 1023))}",
            f"act={_escape_cef_value(_truncate(remediation, 512))}",
        ]
        return " ".join(parts)

    def _cef_cve_extension(
        self,
        ip: str,
        dev_vendor: str,
        dev_model: str,
        cve: object,
    ) -> str:
        """Build CEF extension key=value string for a CVE match."""
        parts = [
            f"src={ip}",
            f"dst={ip}",
            f"dvc={ip}",
            f"dvcVendor={_escape_cef_value(dev_vendor)}",
            f"dvcModel={_escape_cef_value(dev_model)}",
            f"cs1={_escape_cef_value(cve.severity)}",
            "cs1Label=severity",
            f"cs2={_escape_cef_value(cve.priority)}",
            "cs2Label=priority",
            f"cs3={_escape_cef_value(cve.cve_id)}",
            "cs3Label=vuln_id",
            f"msg={_escape_cef_value(_truncate(cve.description, 1023))}",
            f"act={_escape_cef_value(_truncate(cve.remediation, 512))}",
            f"cn1={cve.cvss_score}",
            "cn1Label=cvss_score",
            f"externalId={_escape_cef_value(cve.cve_id)}",
        ]
        return " ".join(parts)

    def _cef_zone_extension(self, zv: ZoneViolation) -> str:
        """Build CEF extension key=value string for a zone violation."""
        parts = [
            f"src={zv.src_ip}",
            f"dst={zv.dst_ip}",
            f"dvc={zv.src_ip}",
            f"cs1={_escape_cef_value(zv.severity)}",
            "cs1Label=severity",
            f"cs2=zone_violation",
            "cs2Label=category",
            f"cs3={_escape_cef_value(zv.violation_id)}",
            "cs3Label=vuln_id",
            f"msg={_escape_cef_value(_truncate(zv.description, 1023))}",
            f"act={_escape_cef_value(_truncate(zv.remediation, 512))}",
            f"cn1={zv.src_purdue}",
            "cn1Label=src_purdue_level",
            f"cn2={zv.dst_purdue}",
            "cn2Label=dst_purdue_level",
        ]
        return " ".join(parts)

    # ── LEEF builder ─────────────────────────────────────────────────

    def _build_leef_lines(self) -> List[str]:
        """Build all LEEF 2.0 syslog lines from devices, CVEs, and zone violations."""
        lines: List[str] = []
        vendor = _escape_leef_value(self.scanner_name)
        product = _escape_leef_value("OT Passive Scanner")
        version = _escape_leef_value(self.scanner_version)

        for dev in self.devices:
            ip = dev.ip
            dev_vendor = dev.vendor or "Unknown"
            dev_model = dev.model or "Unknown"

            # Vulnerability findings
            for vuln in dev.vulnerabilities:
                sev_int = _CEF_SEVERITY.get(vuln.severity, 1)
                event_id = _escape_leef_value(vuln.vuln_id)

                kv = self._leef_vuln_kv(
                    ip, dev_vendor, dev_model, sev_int,
                    vuln.category, vuln.description, vuln.remediation,
                )
                lines.append(
                    f"LEEF:2.0|{vendor}|{product}|{version}|{event_id}|{kv}"
                )

            # CVE matches (now and next)
            for cve in dev.cve_matches:
                if cve.priority not in ("now", "next"):
                    continue
                sev_int = _CEF_SEVERITY.get(cve.severity, 1)
                event_id = _escape_leef_value(cve.cve_id)

                kv = self._leef_cve_kv(ip, dev_vendor, dev_model, sev_int, cve)
                lines.append(
                    f"LEEF:2.0|{vendor}|{product}|{version}|{event_id}|{kv}"
                )

        # Zone violations
        for zv in self.zone_violations:
            sev_int = _CEF_SEVERITY.get(zv.severity, 1)
            event_id = _escape_leef_value(zv.violation_id)

            kv = self._leef_zone_kv(zv, sev_int)
            lines.append(
                f"LEEF:2.0|{vendor}|{product}|{version}|{event_id}|{kv}"
            )

        return lines

    def _leef_vuln_kv(
        self,
        ip: str,
        dev_vendor: str,
        dev_model: str,
        sev: int,
        category: str,
        description: str,
        remediation: str,
    ) -> str:
        """Build LEEF tab-separated key=value string for a vulnerability."""
        parts = [
            f"src={ip}",
            f"dst={ip}",
            f"devName={_escape_leef_value(ip)}",
            f"sev={sev}",
            f"cat={_escape_leef_value(category)}",
            f"msg={_escape_leef_value(_truncate(description, 1023))}",
            f"policy={_escape_leef_value(_truncate(remediation, 512))}",
            f"dvcVendor={_escape_leef_value(dev_vendor)}",
            f"dvcModel={_escape_leef_value(dev_model)}",
        ]
        return "\t".join(parts)

    def _leef_cve_kv(
        self,
        ip: str,
        dev_vendor: str,
        dev_model: str,
        sev: int,
        cve: object,
    ) -> str:
        """Build LEEF tab-separated key=value string for a CVE match."""
        parts = [
            f"src={ip}",
            f"dst={ip}",
            f"devName={_escape_leef_value(ip)}",
            f"sev={sev}",
            f"cat={_escape_leef_value(cve.priority)}",
            f"msg={_escape_leef_value(_truncate(cve.description, 1023))}",
            f"policy={_escape_leef_value(_truncate(cve.remediation, 512))}",
            f"dvcVendor={_escape_leef_value(dev_vendor)}",
            f"dvcModel={_escape_leef_value(dev_model)}",
            f"cvss={cve.cvss_score}",
            f"externalId={_escape_leef_value(cve.cve_id)}",
        ]
        return "\t".join(parts)

    def _leef_zone_kv(self, zv: ZoneViolation, sev: int) -> str:
        """Build LEEF tab-separated key=value string for a zone violation."""
        parts = [
            f"src={zv.src_ip}",
            f"dst={zv.dst_ip}",
            f"devName={_escape_leef_value(zv.src_ip)}",
            f"sev={sev}",
            f"cat=zone_violation",
            f"msg={_escape_leef_value(_truncate(zv.description, 1023))}",
            f"policy={_escape_leef_value(_truncate(zv.remediation, 512))}",
            f"srcPurdue={zv.src_purdue}",
            f"dstPurdue={zv.dst_purdue}",
            f"protocol={_escape_leef_value(zv.protocol)}",
        ]
        return "\t".join(parts)

    # ── I/O ──────────────────────────────────────────────────────────

    @staticmethod
    def _write(path: str, lines: List[str]) -> None:
        """Write log lines to a file, creating parent directories if needed."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
