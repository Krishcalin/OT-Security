"""
Report Generator -- JSON, CSV, and standalone HTML reports for unified OT scan results.

Merges PLC scanner (device identification / risk factors) and RTU scanner
(vulnerability cards / evidence / remediation) report styles into a single
generator that handles OTDevice + CommFlow objects.

HTML report:
  - Catppuccin Mocha dark theme (#1e1e2e bg, #cdd6f4 text)
  - Summary cards, protocol breakdown, top flows, device detail cards
  - Expandable vulnerability cards with severity badges and evidence
  - Responsive CSS, no external dependencies
"""
import csv
import json
import os
from collections import Counter
from datetime import datetime
from typing import List, Optional

from ..models import OTDevice, CommFlow, VulnerabilityFinding, NetworkZone, ZoneViolation, TopologyEdge

# ── Catppuccin Mocha severity colours ────────────────────────────────────────
SEVERITY_COLOR = {
    "critical": "#f38ba8",   # red
    "high":     "#fab387",   # peach
    "medium":   "#89b4fa",   # blue
    "low":      "#a6e3a1",   # green
    "info":     "#cdd6f4",   # text
    "unknown":  "#6c7086",   # overlay0
}

SEVERITY_BG = {
    "critical": "#f38ba820",
    "high":     "#fab38720",
    "medium":   "#89b4fa20",
    "low":      "#a6e3a120",
    "info":     "#cdd6f420",
    "unknown":  "#6c708620",
}

VERSION = "2.0.0"


class ReportGenerator:
    """
    Generate scanner reports in multiple formats.

    Args:
        devices:   List of discovered OTDevice objects.
        flows:     List of CommFlow objects (communication topology).
        pcap_file: Path to the PCAP file that was scanned (for metadata).
        version:   Scanner version string.
    """

    def __init__(
        self,
        devices: List[OTDevice],
        flows: Optional[List[CommFlow]] = None,
        zones: Optional[List[NetworkZone]] = None,
        violations: Optional[List[ZoneViolation]] = None,
        edges: Optional[List[TopologyEdge]] = None,
        pcap_file: str = "",
        version: str = VERSION,
    ):
        self.devices    = devices
        self.flows      = flows or []
        self.zones      = zones or []
        self.violations = violations or []
        self.edges      = edges or []
        self.pcap_file  = pcap_file
        self.version    = version
        self.generated  = datetime.now()

    # ──────────────────────────────────────────────────── console ────────

    def print_summary(self) -> None:
        """Print a formatted summary table to stdout."""
        try:
            from colorama import Fore, Style, init
            init(autoreset=True)
            has_color = True
        except ImportError:
            has_color = False

        def _color(text: str, risk: str) -> str:
            if not has_color:
                return text
            c = {
                "critical": Fore.RED + Style.BRIGHT,
                "high":     Fore.YELLOW + Style.BRIGHT,
                "medium":   Fore.YELLOW,
                "low":      Fore.GREEN,
                "unknown":  Fore.WHITE,
            }.get(risk, "")
            return f"{c}{text}{Style.RESET_ALL}" if c else text

        width = 140
        print("=" * width)
        print(f"{'IP':<18} {'MAC':<20} {'Make / Vendor':<24} {'Model':<20} "
              f"{'Protocols':<30} {'Vulns':>6} {'Risk':<10} {'Pkts':>8}")
        print("-" * width)

        for dev in self.devices:
            protos  = ", ".join(dev.get_protocol_names()) or "-"
            make    = dev.make or dev.vendor or "Unknown"
            model   = (dev.model or "")[:18]
            mac     = dev.mac or "-"
            v_count = len(dev.vulnerabilities)
            risk    = dev.risk_level.upper()
            row = (f"{dev.ip:<18} {mac:<20} {make:<24} {model:<20} "
                   f"{protos[:29]:<30} {v_count:>6} {risk:<10} {dev.packet_count:>8,}")
            print(_color(row, dev.risk_level))

        print("=" * width)
        print()

        # Risk summary
        risk_c = Counter(d.risk_level for d in self.devices)
        print("Risk Summary:")
        for lvl in ("critical", "high", "medium", "low", "unknown"):
            n = risk_c.get(lvl, 0)
            if n:
                bar = "#" * n
                print(f"  {lvl.upper():<12} {bar} ({n})")

        # Vulnerability summary
        all_vulns = [v for d in self.devices for v in d.vulnerabilities]
        sev_c = Counter(v.severity for v in all_vulns)
        print(f"\nVulnerabilities Found: {len(all_vulns)}")
        for lvl in ("critical", "high", "medium", "low", "info"):
            n = sev_c.get(lvl, 0)
            if n:
                print(f"  {lvl.upper():<12} {n}")

        # Protocol summary
        proto_c: Counter = Counter()
        for dev in self.devices:
            for p in dev.get_protocol_names():
                proto_c[p] += 1
        print("\nProtocol Breakdown:")
        for p, n in proto_c.most_common():
            print(f"  {p:<34} {n} device(s)")

        # Top flows
        if self.flows:
            print(f"\nTop Communication Flows ({min(10, len(self.flows))} of {len(self.flows)}):")
            for f in self.flows[:10]:
                print(f"  {f.src_ip:<18} -> {f.dst_ip:<18} "
                      f"{f.protocol:<26} {f.packet_count:>8,} pkts  "
                      f"{f.byte_count:>12,} bytes")

        # CVE match summary (Now / Next / Never)
        all_cves = [c for d in self.devices for c in d.cve_matches]
        if all_cves:
            now_count  = sum(1 for c in all_cves if c.priority == "now")
            next_count = sum(1 for c in all_cves if c.priority == "next")
            never_count = sum(1 for c in all_cves if c.priority == "never")
            print(f"\nCVE Matches (Now/Next/Never): {len(all_cves)} total")
            print(f"  NOW  (patch immediately)   : {now_count}")
            print(f"  NEXT (plan remediation)    : {next_count}")
            print(f"  NEVER (monitor/accept)     : {never_count}")
            now_cves = [c for c in all_cves if c.priority == "now"]
            if now_cves:
                print(f"\n  Top NOW CVEs (act immediately):")
                for c in sorted(now_cves, key=lambda x: -x.cvss_score)[:10]:
                    print(f"    {c.cve_id:<20} CVSS {c.cvss_score:<5.1f} {c.device_ip:<16} {c.title[:50]}")

        # IT/OT Convergence summary
        all_it = [h for d in self.devices for h in d.it_protocols]
        if all_it:
            it_protos = sorted(set(h.protocol for h in all_it))
            high_risk = [h for h in all_it if h.details.get("risk") == "high"]
            print(f"\nIT/OT Convergence: {len(all_it)} IT protocol hit(s) across {len(it_protos)} protocol(s)")
            if high_risk:
                hr_protos = sorted(set(h.protocol for h in high_risk))
                print(f"  HIGH RISK: {', '.join(hr_protos)}")
            for p in it_protos[:8]:
                cnt = sum(1 for h in all_it if h.protocol == p)
                print(f"  {p:<20} {cnt} hit(s)")

        # Zone / Purdue Model summary
        if self.zones:
            print(f"\nNetwork Zones (Purdue Model) — {len(self.zones)} zone(s):")
            for z in sorted(self.zones, key=lambda z: z.purdue_level):
                print(f"  {z.purdue_label:<34} {z.subnet:<18} "
                      f"{z.device_count} device(s)  "
                      f"protocols: {', '.join(sorted(z.protocols_seen)[:4])}")

        if self.violations:
            print(f"\nZone Violations: {len(self.violations)}")
            for v in self.violations:
                sev_str = v.severity.upper()
                print(f"  [{sev_str:<8}] {v.title}")
                print(f"           {v.src_ip} (L{v.src_purdue}) -> "
                      f"{v.dst_ip} (L{v.dst_purdue}) via {v.protocol}")

        # Compliance summary
        try:
            from ..compliance.engine import ComplianceMapper
            mapper = ComplianceMapper(self.devices, zones=self.zones, violations=self.violations)
            results = mapper.assess()
            print(f"\nCompliance Assessment:")
            for framework, checks in results.items():
                fails = sum(1 for c in checks if c.status == "fail")
                passes = sum(1 for c in checks if c.status == "pass")
                total = len(checks)
                print(f"  {framework:<24} {passes}/{total} PASS, {fails} FAIL")
        except ImportError:
            pass

        print()

    # ──────────────────────────────────────────────────────── JSON ────────

    def to_json(self, path: str) -> None:
        all_vulns = [v for d in self.devices for v in d.vulnerabilities]
        report = {
            "scan_metadata": {
                "pcap_file":        os.path.basename(self.pcap_file),
                "generated":        self.generated.isoformat(),
                "tool":             f"OT Passive Scanner v{self.version}",
                "total_devices":    len(self.devices),
                "total_vulns":      len(all_vulns),
                "total_flows":      len(self.flows),
            },
            "risk_summary":      _risk_summary(self.devices),
            "vuln_summary":      _vuln_summary(self.devices),
            "protocol_summary":  _proto_summary(self.devices),
            "devices":           [d.to_dict() for d in self.devices],
            "flows":             [f.to_dict() for f in self.flows],
            "zones":             [z.to_dict() for z in self.zones],
            "zone_violations":   [v.to_dict() for v in self.violations],
            "topology_edges":    [e.to_dict() for e in self.edges],
            "cve_summary":       _cve_summary(self.devices),
            "compliance":        self._compliance_data(),
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)

    def _compliance_data(self) -> dict:
        """Generate compliance summary for JSON export."""
        try:
            from ..compliance.engine import ComplianceMapper
            mapper = ComplianceMapper(self.devices, zones=self.zones, violations=self.violations)
            results = mapper.assess()
            summary = {}
            for framework, checks in results.items():
                summary[framework] = {
                    "total": len(checks),
                    "pass": sum(1 for c in checks if c.status == "pass"),
                    "fail": sum(1 for c in checks if c.status == "fail"),
                    "warning": sum(1 for c in checks if c.status == "warning"),
                    "not_assessed": sum(1 for c in checks if c.status == "not_assessed"),
                    "checks": [{"control_id": c.control_id, "title": c.title, "status": c.status,
                                "severity": c.severity, "finding": c.finding} for c in checks],
                }
            return summary
        except ImportError:
            return {}

    # ──────────────────────────────────────────────────────── CSV ─────────

    def to_csv(self, path: str) -> None:
        fields = [
            "ip", "mac", "vendor", "make", "model", "firmware",
            "serial_number", "hardware_version", "product_code",
            "rack", "slot", "cpu_info", "modules_count",
            "device_type", "role", "device_criticality",
            "dnp3_address", "iec104_common_address",
            "protocols", "open_ports", "goose_ids",
            "communicating_with_count", "master_stations",
            "comm_peer_count", "comm_role",
            "first_seen", "last_seen", "packet_count",
            "risk_level", "risk_score", "composite_risk_score",
            "compensating_controls_count", "cve_kev_count",
            "vuln_count", "critical_vulns", "high_vulns",
            "vuln_ids",
            "threat_alert_count", "critical_threat_alerts",
            "remote_access_sessions", "ra_compliant", "ra_non_compliant",
            "config_drift_alerts", "config_drift_critical",
            "attack_paths_targeting", "critical_attack_paths",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for d in self.devices:
                sev = Counter(v.severity for v in d.vulnerabilities)
                cp = d.communication_profile
                comm_role = ("master" if cp.get("is_master")
                             else "slave" if cp.get("is_slave")
                             else "peer") if cp else ""
                w.writerow({
                    "ip":                      d.ip,
                    "mac":                     d.mac or "",
                    "vendor":                  d.vendor or "",
                    "make":                    d.make or "",
                    "model":                   d.model or "",
                    "firmware":                d.firmware or "",
                    "serial_number":           d.serial_number or "",
                    "hardware_version":        d.hardware_version or "",
                    "product_code":            d.product_code or "",
                    "rack":                    d.rack if d.rack is not None else "",
                    "slot":                    d.slot if d.slot is not None else "",
                    "cpu_info":                d.cpu_info or "",
                    "modules_count":           len(d.modules),
                    "device_type":             d.device_type,
                    "role":                    d.role,
                    "device_criticality":      d.device_criticality,
                    "dnp3_address":            d.dnp3_address or "",
                    "iec104_common_address":   d.iec104_common_address or "",
                    "protocols":               " | ".join(d.get_protocol_names()),
                    "open_ports":              " | ".join(str(p) for p in sorted(d.open_ports)),
                    "goose_ids":               " | ".join(sorted(d.goose_ids)),
                    "communicating_with_count": len(d.communicating_with),
                    "master_stations":         " | ".join(sorted(d.master_stations)),
                    "comm_peer_count":         cp.get("peer_count", "") if cp else "",
                    "comm_role":               comm_role,
                    "first_seen":              d.first_seen.isoformat() if d.first_seen else "",
                    "last_seen":               d.last_seen.isoformat()  if d.last_seen  else "",
                    "packet_count":            d.packet_count,
                    "risk_level":              d.risk_level,
                    "risk_score":              d.risk_score,
                    "composite_risk_score":    d.composite_risk_score,
                    "compensating_controls_count": len(d.compensating_controls),
                    "cve_kev_count":           sum(1 for c in d.cve_matches if c.is_cisa_kev),
                    "vuln_count":              len(d.vulnerabilities),
                    "critical_vulns":          sev.get("critical", 0),
                    "high_vulns":              sev.get("high", 0),
                    "vuln_ids":                " | ".join(v.vuln_id for v in d.vulnerabilities),
                    "threat_alert_count":       len(d.threat_alerts),
                    "critical_threat_alerts":   sum(1 for a in d.threat_alerts if a.severity == "critical"),
                    "remote_access_sessions":  len(d.remote_access_sessions),
                    "ra_compliant":            sum(1 for s in d.remote_access_sessions if s.compliance_status == "compliant"),
                    "ra_non_compliant":        sum(1 for s in d.remote_access_sessions if s.compliance_status == "non_compliant"),
                    "config_drift_alerts":     len(d.config_drift_alerts),
                    "config_drift_critical":   sum(1 for a in d.config_drift_alerts if a.severity == "critical"),
                    "attack_paths_targeting":  len(d.attack_paths),
                    "critical_attack_paths":   sum(1 for p in d.attack_paths if p.severity == "critical"),
                })

    # ──────────────────────────────────────────────────────── GraphML ──

    def to_graphml(self, path: str) -> None:
        """Export topology as GraphML file (for Gephi / yEd / Cytoscape)."""
        try:
            from ..topology.engine import TopologyEngine
            engine = TopologyEngine()
            xml = engine.to_graphml(self.devices, self.zones, self.edges, self.violations)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(xml)
        except ImportError:
            # Topology module not available — write a basic GraphML
            self._basic_graphml(path)

    def _basic_graphml(self, path: str) -> None:
        """Fallback basic GraphML when topology engine is not available."""
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<graphml xmlns="http://graphml.graphsheets.org/xmlns">',
                 '<graph id="OT" edgedefault="directed">']
        for d in self.devices:
            lines.append(f'  <node id="{d.ip}"/>')
        seen = set()
        for f in self.flows:
            eid = f"{f.src_ip}-{f.dst_ip}"
            if eid not in seen:
                lines.append(f'  <edge source="{f.src_ip}" target="{f.dst_ip}"/>')
                seen.add(eid)
        lines.append('</graph></graphml>')
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    # ──────────────────────────────────────────────────────── HTML ────────

    def to_html(self, path: str) -> None:
        all_vulns    = [v for d in self.devices for v in d.vulnerabilities]
        risk_counts  = _risk_summary(self.devices)
        proto_counts = _proto_summary(self.devices)
        vuln_counts  = _vuln_summary(self.devices)

        risk_badges = " ".join(
            f'<span class="badge" style="background:{SEVERITY_COLOR[r]}">'
            f'{r.upper()}: {risk_counts.get(r, 0)}</span>'
            for r in ("critical", "high", "medium", "low")
            if risk_counts.get(r, 0)
        )
        vuln_badges = " ".join(
            f'<span class="badge" style="background:{SEVERITY_COLOR[s]}">'
            f'{s.upper()}: {vuln_counts.get(s, 0)}</span>'
            for s in ("critical", "high", "medium", "low")
            if vuln_counts.get(s, 0)
        )
        proto_rows = "".join(
            f"<tr><td>{p}</td><td>{c}</td></tr>"
            for p, c in proto_counts.items()
        )
        devices_html = "\n".join(self._device_row(d) for d in self.devices)

        # Top 50 flows
        flow_rows = ""
        for f in self.flows[:50]:
            flow_rows += (
                f"<tr>"
                f"<td>{f.src_ip}</td>"
                f"<td>{f.dst_ip}</td>"
                f"<td>{_h(f.protocol)}</td>"
                f"<td>{f.port}</td>"
                f"<td>{f.transport}</td>"
                f"<td style='text-align:right'>{f.packet_count:,}</td>"
                f"<td style='text-align:right'>{f.byte_count:,}</td>"
                f"<td style='font-size:.72rem'>"
                f"{f.first_seen.strftime('%H:%M:%S') if f.first_seen else '-'} / "
                f"{f.last_seen.strftime('%H:%M:%S') if f.last_seen else '-'}</td>"
                f"</tr>"
            )

        # ── Topology HTML data ────────────────────────────────────────
        PURDUE_COLORS = {
            0: "#89b4fa",   # blue — process
            1: "#a6e3a1",   # green — basic control
            2: "#f9e2af",   # yellow — supervisory
            3: "#fab387",   # peach — operations
            -1: "#6c7086",  # gray — unknown
        }

        # Zone summary rows
        zone_rows_html = ""
        for z in sorted(self.zones, key=lambda z: z.purdue_level):
            plvl = z.purdue_level
            pcolor = PURDUE_COLORS.get(plvl, PURDUE_COLORS[-1])
            protos = ", ".join(sorted(z.protocols_seen)[:5]) or "-"
            zone_rows_html += (
                f"<tr>"
                f"<td><span class='risk-pill' style='background:{pcolor}'>"
                f"L{plvl}</span></td>"
                f"<td>{_h(z.purdue_label)}</td>"
                f"<td style='font-family:monospace'>{_h(z.subnet)}</td>"
                f"<td style='text-align:center'>{z.device_count}</td>"
                f"<td>{_h(z.dominant_role)}</td>"
                f"<td style='font-size:.78rem'>{_h(protos)}</td>"
                f"</tr>"
            )

        # Zone violation rows
        violation_rows_html = ""
        for v in self.violations:
            vc = SEVERITY_COLOR.get(v.severity, SEVERITY_COLOR["unknown"])
            violation_rows_html += (
                f"<tr>"
                f"<td><span class='risk-pill' style='background:{vc}'>"
                f"{v.severity.upper()}</span></td>"
                f"<td>{_h(v.title)}</td>"
                f"<td>{v.src_ip} (L{v.src_purdue})</td>"
                f"<td>{v.dst_ip} (L{v.dst_purdue})</td>"
                f"<td>{_h(v.protocol)}</td>"
                f"<td style='text-align:right'>{v.packet_count:,}</td>"
                f"</tr>"
            )

        # Build D3 topology data (JSON for inline script)
        ip_purdue = {}
        for z in self.zones:
            for dip in z.device_ips:
                ip_purdue[dip] = z.purdue_level

        # Violation edge set for colouring
        violation_pairs = set()
        for v in self.violations:
            violation_pairs.add((v.src_ip, v.dst_ip))
            violation_pairs.add((v.dst_ip, v.src_ip))

        import math as _math
        topo_nodes_json = json.dumps([
            {
                "id": d.ip,
                "label": d.ip,
                "vendor": d.vendor or d.make or "Unknown",
                "role": d.role,
                "purdue": ip_purdue.get(d.ip, -1),
                "risk": d.risk_level,
                "packets": d.packet_count,
                "radius": max(5, min(25, int(5 + _math.log(max(d.packet_count, 1)) * 2))),
            }
            for d in self.devices
        ])
        topo_links_json = json.dumps([
            {
                "source": e.src_ip,
                "target": e.dst_ip,
                "protocols": ", ".join(sorted(e.protocols)),
                "packets": e.packet_count,
                "crossZone": e.is_cross_zone,
                "purdueSpan": e.purdue_span,
                "isViolation": (e.src_ip, e.dst_ip) in violation_pairs,
            }
            for e in self.edges
        ])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>OT Passive Scan Report</title>
<style>
* {{ box-sizing:border-box; margin:0; padding:0 }}
body {{ font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
       background:#1e1e2e; color:#cdd6f4 }}
header {{ background:linear-gradient(135deg,#181825 0%,#1e1e2e 100%);
          padding:2rem; border-bottom:2px solid #313244 }}
header h1 {{ font-size:1.7rem; color:#cba6f7 }}
header .sub {{ color:#a6adc8; font-size:.85rem; margin-top:.4rem }}
.container {{ max-width:1500px; margin:0 auto; padding:1.5rem }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
         gap:1rem; margin:1.5rem 0 }}
.card {{ background:#181825; border:1px solid #313244; border-radius:8px; padding:1.2rem }}
.card h3 {{ color:#a6adc8; font-size:.72rem; text-transform:uppercase;
            letter-spacing:.1em; margin-bottom:.5rem }}
.card .val {{ font-size:1.9rem; font-weight:700; color:#cdd6f4 }}
.card .sub {{ font-size:.78rem; color:#6c7086; margin-top:.2rem }}
.badge {{ display:inline-block; padding:.2rem .65rem; border-radius:999px;
          color:#1e1e2e; font-size:.72rem; font-weight:700; margin:.12rem }}
.sec {{ color:#cba6f7; font-size:1.05rem; font-weight:600;
        margin:2rem 0 .8rem; border-bottom:1px solid #313244; padding-bottom:.3rem }}
table {{ width:100%; border-collapse:collapse }}
th {{ background:#181825; color:#a6adc8; text-align:left; padding:.55rem .8rem;
      font-size:.72rem; text-transform:uppercase; letter-spacing:.05em;
      border-bottom:2px solid #313244; white-space:nowrap }}
td {{ padding:.5rem .8rem; border-bottom:1px solid #181825; font-size:.82rem; vertical-align:top }}
tr:nth-child(even) td {{ background:#11111b }}
tr:hover td {{ background:#1e1e2e; outline:1px solid #313244 }}
.risk-pill {{ display:inline-block; padding:.18rem .5rem; border-radius:4px;
              font-size:.7rem; font-weight:700; color:#1e1e2e }}
.proto-tag {{ display:inline-block; background:#313244; color:#89dceb;
              border-radius:4px; padding:.08rem .4rem; font-size:.7rem; margin:.08rem }}
.expand-btn {{ background:#313244; border:none; color:#cba6f7; cursor:pointer;
               padding:.22rem .55rem; border-radius:4px; font-size:.75rem }}
.expand-btn:hover {{ background:#45475a }}
.detail-tr {{ display:none }}
.detail-td {{ background:#11111b !important; padding:1rem 1.2rem }}
.detail-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:.5rem 2rem }}
.dl {{ color:#6c7086; font-size:.7rem; text-transform:uppercase; margin-bottom:.1rem }}
.dv {{ color:#cdd6f4; font-size:.8rem; word-break:break-all; margin-bottom:.5rem }}
/* Vulnerability cards */
.vuln-card {{ border-left:3px solid; border-radius:0 6px 6px 0;
              padding:.6rem .8rem; margin:.35rem 0; font-size:.8rem }}
.vuln-title {{ font-weight:600; margin-bottom:.2rem }}
.vuln-desc {{ color:#a6adc8; font-size:.75rem; margin-bottom:.3rem }}
.vuln-rem {{ color:#89dceb; font-size:.73rem }}
.vuln-ref {{ color:#6c7086; font-size:.7rem; margin-top:.2rem }}
.vuln-id {{ font-family:monospace; font-size:.68rem; color:#6c7086 }}
/* Risk factor cards */
.risk-factor {{ background:#45475a20; border-left:3px solid #f38ba8;
                padding:.3rem .6rem; margin:.2rem 0; border-radius:0 4px 4px 0;
                font-size:.8rem; color:#f38ba8 }}
footer {{ text-align:center; color:#313244; font-size:.75rem;
          padding:2rem; border-top:1px solid #181825; margin-top:3rem }}
@media (max-width:900px) {{
  .detail-grid {{ grid-template-columns:1fr }}
  .grid {{ grid-template-columns:1fr 1fr }}
}}
</style>
</head>
<body>
<header>
  <h1>OT / ICS Passive Network Scan Report</h1>
  <div class="sub">
    <strong>PCAP:</strong> {_h(os.path.basename(self.pcap_file))} &nbsp;|&nbsp;
    <strong>Generated:</strong> {self.generated.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
    <strong>Tool:</strong> OT Passive Scanner v{self.version} &nbsp;|&nbsp;
    <strong>Mode:</strong> Offline / Passive -- no packets sent
  </div>
</header>

<div class="container">

  <!-- Summary Cards -->
  <div class="grid">
    <div class="card">
      <h3>Devices Found</h3>
      <div class="val">{len(self.devices)}</div>
      <div class="sub">Industrial OT devices</div>
    </div>
    <div class="card">
      <h3>Protocols Detected</h3>
      <div class="val">{len(proto_counts)}</div>
      <div class="sub">{_h(', '.join(list(proto_counts.keys())[:4]))}</div>
    </div>
    <div class="card">
      <h3>Vulnerabilities</h3>
      <div class="val" style="font-size:1.5rem">{len(all_vulns)}</div>
      <div style="margin-top:.3rem">{vuln_badges}</div>
    </div>
    <div class="card">
      <h3>Risk Distribution</h3>
      <div style="margin-top:.4rem">{risk_badges}</div>
    </div>
    <div class="card">
      <h3>Critical + High Risk</h3>
      <div class="val" style="color:{SEVERITY_COLOR['critical']}">
        {risk_counts.get('critical', 0) + risk_counts.get('high', 0)}
      </div>
      <div class="sub">Require immediate attention</div>
    </div>
    <div class="card">
      <h3>Communication Flows</h3>
      <div class="val">{len(self.flows):,}</div>
      <div class="sub">Unique src/dst/proto tuples</div>
    </div>
  </div>

  <!-- Protocol Breakdown -->
  <div class="sec">Protocol Breakdown</div>
  <div style="overflow:auto;margin-bottom:1.5rem">
  <table style="width:auto;min-width:420px">
    <thead><tr><th>Protocol</th><th>Devices</th></tr></thead>
    <tbody>{proto_rows}</tbody>
  </table>
  </div>

  <!-- Communication Flows -->
  <div class="sec">Communication Flows (Top {min(50, len(self.flows))})</div>
  <div style="overflow:auto;margin-bottom:1.5rem">
  <table>
    <thead>
      <tr>
        <th>Source IP</th><th>Destination IP</th><th>Protocol</th>
        <th>Port</th><th>Transport</th><th>Packets</th><th>Bytes</th>
        <th>First / Last</th>
      </tr>
    </thead>
    <tbody>{flow_rows or '<tr><td colspan="8" style="color:#6c7086">No flows recorded</td></tr>'}</tbody>
  </table>
  </div>

  <!-- Network Zones (Purdue Model) -->
  {"" if not self.zones else '''
  <div class="sec">Network Zones (Purdue Model)</div>
  <div style="overflow:auto;margin-bottom:1.5rem">
  <table style="width:auto;min-width:600px">
    <thead>
      <tr>
        <th>Level</th><th>Zone Name</th><th>Subnet</th>
        <th>Devices</th><th>Dominant Role</th><th>Protocols</th>
      </tr>
    </thead>
    <tbody>''' + zone_rows_html + '''</tbody>
  </table>
  </div>
  '''}

  <!-- Zone Violations -->
  {"" if not self.violations else '''
  <div class="sec">Zone Segmentation Violations</div>
  <div style="overflow:auto;margin-bottom:1.5rem">
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Title</th><th>Source (Level)</th>
        <th>Destination (Level)</th><th>Protocol</th><th>Packets</th>
      </tr>
    </thead>
    <tbody>''' + violation_rows_html + '''</tbody>
  </table>
  </div>
  '''}

  <!-- Network Topology (D3.js) -->
  {"" if not self.edges else '''
  <div class="sec">Network Topology</div>
  <div style="background:#11111b;border:1px solid #313244;border-radius:8px;padding:.5rem;margin-bottom:1.5rem">
    <svg id="topo-svg" width="100%%" height="500" style="display:block"></svg>
  </div>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <script>
  (function(){{
    const PURDUE_CLR = {{0:"#89b4fa",1:"#a6e3a1",2:"#f9e2af",3:"#fab387","-1":"#6c7086"}};
    const nodes = ''' + topo_nodes_json + ''';
    const links = ''' + topo_links_json + ''';
    const svg = d3.select("#topo-svg");
    const width = svg.node().getBoundingClientRect().width;
    const height = 500;
    svg.attr("viewBox", [0, 0, width, height]);

    const g = svg.append("g");

    // Zoom
    svg.call(d3.zoom().scaleExtent([0.3, 5]).on("zoom", (e) => g.attr("transform", e.transform)));

    const sim = d3.forceSimulation(nodes)
      .force("link",   d3.forceLink(links).id(d => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-250))
      .force("center", d3.forceCenter(width / 2, height / 2));

    // Links
    const link = g.append("g")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", d => d.isViolation ? "#f38ba8" : d.crossZone ? "#fab387" : "#45475a")
      .attr("stroke-width", d => Math.max(1, Math.min(4, Math.log(d.packets + 1))))
      .attr("stroke-opacity", 0.7);

    // Nodes
    const node = g.append("g")
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", d => d.radius)
      .attr("fill", d => PURDUE_CLR[d.purdue] || PURDUE_CLR["-1"])
      .attr("stroke", "#cdd6f4")
      .attr("stroke-width", 1)
      .call(d3.drag()
        .on("start", (e, d) => {{ if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
        .on("drag",  (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
        .on("end",   (e, d) => {{ if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }}));

    // Labels
    const label = g.append("g")
      .selectAll("text")
      .data(nodes)
      .join("text")
      .text(d => d.id)
      .attr("fill", "#cdd6f4")
      .attr("font-size", "9px")
      .attr("dx", d => d.radius + 3)
      .attr("dy", 3);

    // Tooltip
    const tip = d3.select("body").append("div")
      .style("position", "absolute").style("padding", ".5rem .7rem")
      .style("background", "#181825").style("border", "1px solid #313244")
      .style("border-radius", "6px").style("color", "#cdd6f4")
      .style("font-size", ".78rem").style("pointer-events", "none")
      .style("opacity", 0);

    node.on("mouseover", (e, d) => {{
      tip.transition().duration(150).style("opacity", 1);
      tip.html("<strong>" + d.id + "</strong><br>Vendor: " + d.vendor
        + "<br>Role: " + d.role + "<br>Purdue Level: " + d.purdue
        + "<br>Risk: " + d.risk + "<br>Packets: " + d.packets.toLocaleString());
    }}).on("mousemove", (e) => {{
      tip.style("left", (e.pageX + 14) + "px").style("top", (e.pageY - 10) + "px");
    }}).on("mouseout", () => {{
      tip.transition().duration(200).style("opacity", 0);
    }});

    sim.on("tick", () => {{
      link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
          .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
      node.attr("cx", d => d.x).attr("cy", d => d.y);
      label.attr("x", d => d.x).attr("y", d => d.y);
    }});
  }})();
  </script>
  '''}

  <!-- CVE Vulnerability Intelligence -->
  {self._cve_section_html()}

  <!-- IT/OT Convergence -->
  {self._itot_section_html()}

  <!-- Protocol Behavior Analytics -->
  {self._behavior_section_html()}

  <!-- Devices -->
  <div class="sec">Discovered Devices &amp; Vulnerability Findings</div>
  <div style="overflow:auto">
  <table>
    <thead>
      <tr>
        <th>IP Address</th><th>MAC</th><th>Make / Vendor</th>
        <th>Model</th><th>Type</th><th>Protocols</th>
        <th>Vulns</th><th>Risk</th><th>Pkts</th><th>Details</th>
      </tr>
    </thead>
    <tbody>
{devices_html}
    </tbody>
  </table>
  </div>

</div>

<footer>
  OT / ICS Passive Scanner v{self.version} -- Defensive OT Security Tool &nbsp;|&nbsp;
  {self.generated.strftime('%Y-%m-%d')}
</footer>

<script>
function toggle(id){{
  var r = document.getElementById('dr_'+id);
  if(r) r.style.display = r.style.display === 'none' ? 'table-row' : 'none';
}}
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)

    # ──────────────────────────────────────── CVE intelligence section ──

    def _cve_section_html(self) -> str:
        """Build the CVE Vulnerability Intelligence HTML section."""
        all_cves = [c for d in self.devices for c in d.cve_matches]
        if not all_cves:
            return ""

        now_cves = [c for c in all_cves if c.priority == "now"]
        next_cves = [c for c in all_cves if c.priority == "next"]
        never_cves = [c for c in all_cves if c.priority == "never"]

        # Summary cards
        html = """
  <div class="sec">CVE Vulnerability Intelligence</div>
  <div class="grid" style="grid-template-columns:repeat(4,1fr)">
    <div class="card">
      <h3>Total CVE Matches</h3>
      <div class="val">%d</div>
      <div class="sub">Across %d device(s)</div>
    </div>
    <div class="card" style="border-left:3px solid #f38ba8">
      <h3>NOW (Patch Immediately)</h3>
      <div class="val" style="color:#f38ba8">%d</div>
      <div class="sub">Known exploit, device reachable</div>
    </div>
    <div class="card" style="border-left:3px solid #fab387">
      <h3>NEXT (Plan Remediation)</h3>
      <div class="val" style="color:#fab387">%d</div>
      <div class="sub">Confirmed, no public exploit</div>
    </div>
    <div class="card" style="border-left:3px solid #a6e3a1">
      <h3>NEVER (Monitor/Accept)</h3>
      <div class="val" style="color:#a6e3a1">%d</div>
      <div class="sub">Theoretical or mitigated</div>
    </div>
  </div>
""" % (
            len(all_cves),
            sum(1 for d in self.devices if d.cve_matches),
            len(now_cves),
            len(next_cves),
            len(never_cves),
        )

        # NOW CVEs table
        if now_cves:
            now_rows = ""
            for c in sorted(now_cves, key=lambda x: -x.cvss_score):
                now_rows += (
                    "<tr>"
                    f"<td style='font-family:monospace;font-weight:700;color:#f38ba8'>"
                    f"{_h(c.cve_id)}</td>"
                    f"<td style='text-align:center;font-weight:700'>{c.cvss_score:.1f}</td>"
                    f"<td>{c.device_ip}</td>"
                    f"<td>{_h(c.title[:60])}</td>"
                    f"<td style='font-size:.72rem'>{_h(c.ics_cert_advisory or '-')}</td>"
                    f"<td style='text-align:center'>{_h(c.match_confidence)}</td>"
                    "</tr>"
                )
            html += """
  <div style="margin-bottom:1.5rem">
  <div style="color:#f38ba8;font-weight:700;font-size:.85rem;margin-bottom:.5rem">
    NOW Priority CVEs &mdash; Act Immediately</div>
  <div style="overflow:auto">
  <table>
    <thead>
      <tr><th>CVE ID</th><th>CVSS</th><th>Device IP</th>
          <th>Title</th><th>ICS-CERT Advisory</th><th>Confidence</th></tr>
    </thead>
    <tbody>%s</tbody>
  </table>
  </div>
  </div>
""" % now_rows

        # NEXT CVEs collapsible
        if next_cves:
            next_rows = ""
            for c in sorted(next_cves, key=lambda x: -x.cvss_score):
                next_rows += (
                    "<tr>"
                    f"<td style='font-family:monospace;color:#fab387'>"
                    f"{_h(c.cve_id)}</td>"
                    f"<td style='text-align:center'>{c.cvss_score:.1f}</td>"
                    f"<td>{c.device_ip}</td>"
                    f"<td>{_h(c.title[:60])}</td>"
                    f"<td style='font-size:.72rem'>{_h(c.ics_cert_advisory or '-')}</td>"
                    f"<td style='text-align:center'>{_h(c.match_confidence)}</td>"
                    "</tr>"
                )
            html += """
  <details style="margin-bottom:1.5rem">
    <summary style="cursor:pointer;color:#fab387;font-weight:700;font-size:.85rem">
      NEXT Priority CVEs (%d) &mdash; Plan Remediation</summary>
    <div style="overflow:auto;margin-top:.5rem">
    <table>
      <thead>
        <tr><th>CVE ID</th><th>CVSS</th><th>Device IP</th>
            <th>Title</th><th>ICS-CERT Advisory</th><th>Confidence</th></tr>
      </thead>
      <tbody>%s</tbody>
    </table>
    </div>
  </details>
""" % (len(next_cves), next_rows)

        return html

    def _itot_section_html(self) -> str:
        """Build the IT/OT Convergence HTML section."""
        all_it = [h for d in self.devices for h in d.it_protocols]
        if not all_it:
            return ""

        it_protos = sorted(set(h.protocol for h in all_it))
        high_risk = [h for h in all_it if h.details.get("risk") == "high"]
        hr_protos = sorted(set(h.protocol for h in high_risk))
        devices_with_it = sum(1 for d in self.devices if d.it_protocols)

        # Summary cards
        html = f"""
  <div class="sec">IT/OT Convergence Analysis</div>
  <div class="grid" style="grid-template-columns:repeat(4,1fr)">
    <div class="card">
      <h3>IT Protocol Hits</h3>
      <div class="val">{len(all_it)}</div>
      <div class="sub">Across {devices_with_it} device(s)</div>
    </div>
    <div class="card" style="border-left:3px solid #f38ba8">
      <h3>High Risk Hits</h3>
      <div class="val" style="color:#f38ba8">{len(high_risk)}</div>
      <div class="sub">{', '.join(hr_protos[:4]) or 'None'}</div>
    </div>
    <div class="card">
      <h3>IT Protocols</h3>
      <div class="val">{len(it_protos)}</div>
      <div class="sub">{', '.join(it_protos[:4])}</div>
    </div>
    <div class="card">
      <h3>Total IT Packets</h3>
      <div class="val">{sum(h.packet_count for h in all_it):,}</div>
      <div class="sub">IT traffic in OT zone</div>
    </div>
  </div>
"""

        # High-risk alert box
        if hr_protos:
            html += (
                '<div style="background:#f38ba815;border:1px solid #f38ba8;border-radius:8px;'
                'padding:.8rem 1rem;margin-bottom:1rem;font-size:.82rem">'
                '<span style="color:#f38ba8;font-weight:700">HIGH RISK IT PROTOCOLS IN OT ZONE:</span> '
                f'{_h(", ".join(hr_protos))}. '
                'These protocols provide direct attack paths into the OT network and must be '
                'removed or tightly controlled via jump servers and firewall rules.'
                '</div>'
            )

        # Protocol summary table grouped by protocol
        proto_summary: dict = {}
        for h in all_it:
            key = h.protocol
            if key not in proto_summary:
                proto_summary[key] = {
                    "category": h.details.get("category", ""),
                    "risk": h.details.get("risk", "low"),
                    "hits": 0,
                    "devices": set(),
                }
            proto_summary[key]["hits"] += 1
            # Determine which device this hit belongs to
            for d in self.devices:
                if h in d.it_protocols:
                    proto_summary[key]["devices"].add(d.ip)
                    break

        proto_rows = ""
        for pname in sorted(proto_summary.keys()):
            ps = proto_summary[pname]
            risk = ps["risk"]
            risk_c = {"high": "#f38ba8", "medium": "#fab387", "low": "#a6e3a1"}.get(risk, "#6c7086")
            proto_rows += (
                f"<tr>"
                f"<td><strong>{_h(pname)}</strong></td>"
                f"<td>{_h(ps['category'])}</td>"
                f"<td><span class='risk-pill' style='background:{risk_c}'>{risk.upper()}</span></td>"
                f"<td style='text-align:center'>{ps['hits']}</td>"
                f"<td style='text-align:center'>{len(ps['devices'])}</td>"
                f"</tr>"
            )

        html += f"""
  <div style="overflow:auto;margin-bottom:1.5rem">
  <table style="width:auto;min-width:500px">
    <thead>
      <tr><th>Protocol</th><th>Category</th><th>Risk</th><th>Hits</th><th>Devices</th></tr>
    </thead>
    <tbody>{proto_rows}</tbody>
  </table>
  </div>
"""
        return html

    def _behavior_section_html(self) -> str:
        """Build the Protocol Behavior Analytics HTML section."""
        devices_with_stats = [d for d in self.devices if d.protocol_stats]
        if not devices_with_stats:
            return ""

        html = """
  <div class="sec">Protocol Behavior Analytics</div>
"""
        for dev in devices_with_stats:
            stats_rows = ""
            warnings = []
            for ps in dev.protocol_stats:
                # Flag dangerous behaviors
                badges = ""
                if ps.has_program_upload:
                    badges += ('<span class="badge" style="background:#f38ba8">'
                               'PROGRAM UPLOAD</span> ')
                    warnings.append(f"{dev.ip}: {ps.protocol} program upload detected")
                if ps.has_program_download:
                    badges += ('<span class="badge" style="background:#f38ba8">'
                               'PROGRAM DOWNLOAD</span> ')
                    warnings.append(f"{dev.ip}: {ps.protocol} program download detected")
                if ps.has_firmware_update:
                    badges += ('<span class="badge" style="background:#fab387">'
                               'FIRMWARE UPDATE</span> ')
                    warnings.append(f"{dev.ip}: {ps.protocol} firmware update detected")
                if ps.has_config_change:
                    badges += ('<span class="badge" style="background:#fab387">'
                               'CONFIG CHANGE</span> ')

                stats_rows += (
                    f"<tr>"
                    f"<td>{_h(ps.protocol)}</td>"
                    f"<td style='text-align:right'>{ps.total_packets:,}</td>"
                    f"<td style='text-align:right'>{ps.read_count:,}</td>"
                    f"<td style='text-align:right'>{ps.write_count:,}</td>"
                    f"<td style='text-align:right'>{ps.control_count:,}</td>"
                    f"<td style='text-align:right'>{ps.diagnostic_count:,}</td>"
                    f"<td>{badges or '-'}</td>"
                    f"</tr>"
                )

            html += f"""
  <details style="margin-bottom:.8rem">
    <summary style="cursor:pointer;color:#89dceb;font-size:.82rem;font-weight:600">
      {dev.ip} — {len(dev.protocol_stats)} protocol(s) analysed</summary>
    <div style="overflow:auto;margin-top:.4rem">
    <table style="width:auto;min-width:600px">
      <thead>
        <tr><th>Protocol</th><th>Packets</th><th>Reads</th><th>Writes</th>
            <th>Controls</th><th>Diagnostics</th><th>Flags</th></tr>
      </thead>
      <tbody>{stats_rows}</tbody>
    </table>
    </div>
  </details>
"""
        return html

    def _cve_matches_html(self, dev: OTDevice) -> str:
        """Build CVE match cards for a single device's detail panel."""
        if not dev.cve_matches:
            return ""
        parts = []
        for cm in sorted(
            dev.cve_matches,
            key=lambda x: ({"now": 0, "next": 1, "never": 2}.get(x.priority, 3), -x.cvss_score),
        ):
            pri_color = {"now": "#f38ba8", "next": "#fab387", "never": "#a6e3a1"}.get(
                cm.priority, "#6c7086"
            )
            parts.append(
                f'<div style="border-left:3px solid {pri_color};padding:.3rem .6rem;margin:.2rem 0;'
                f'background:{pri_color}15;border-radius:0 4px 4px 0;font-size:.78rem">'
                f'<span style="color:{pri_color};font-weight:700">[{cm.priority.upper()}]</span> '
                f'<span style="font-family:monospace">{_h(cm.cve_id)}</span> '
                f'CVSS {cm.cvss_score:.1f} — {_h(cm.title)}'
                f'<div style="color:#a6adc8;font-size:.72rem;margin-top:.1rem">'
                f'{_h(cm.match_reason)} (confidence: {cm.match_confidence})</div>'
                f'</div>'
            )
        return "\n".join(parts)

    # ──────────────────────────────── IT protocol detail for device card ──

    def _it_protocols_detail(self, dev: OTDevice) -> str:
        """Build IT protocol hit cards for a single device's detail panel."""
        if not dev.it_protocols:
            return ""
        parts = []
        for hit in dev.it_protocols:
            risk_c = {"high": "#f38ba8", "medium": "#fab387", "low": "#a6e3a1"}.get(
                hit.details.get("risk", ""), "#6c7086")
            parts.append(
                f'<div style="border-left:3px solid {risk_c};padding:.2rem .5rem;margin:.15rem 0;'
                f'font-size:.75rem;background:{risk_c}10;border-radius:0 3px 3px 0">'
                f'<span style="color:{risk_c};font-weight:600">{_h(hit.protocol)}</span> '
                f'port {hit.port} — {hit.packet_count} pkts '
                f'({hit.details.get("category","")}, {hit.details.get("direction","")})'
                f'</div>'
            )
        return "\n".join(parts)

    @staticmethod
    def _comm_summary(dev: OTDevice) -> str:
        """One-line communication profile summary for HTML."""
        cp = dev.communication_profile
        if not cp:
            return "-"
        role = ("master" if cp.get("is_master")
                else "slave" if cp.get("is_slave") else "peer")
        peers = cp.get("peer_count", 0)
        cr = cp.get("control_ratio", 0)
        return f"{role} | {peers} peers | control_ratio={cr}"

    @staticmethod
    def _risk_breakdown_html(dev: OTDevice) -> str:
        """Risk score breakdown table + compensating controls for HTML card."""
        bd = dev.risk_score_breakdown
        if not bd:
            return ""

        # Score bar color
        score = dev.composite_risk_score
        if score >= 70:
            bar_color = SEVERITY_COLOR["critical"]
        elif score >= 40:
            bar_color = SEVERITY_COLOR["high"]
        elif score >= 15:
            bar_color = SEVERITY_COLOR["medium"]
        else:
            bar_color = SEVERITY_COLOR["low"]

        rows = f"""
    <div style="margin-top:.5rem">
      <div style="background:#313244;border-radius:4px;height:8px;margin-bottom:.4rem">
        <div style="background:{bar_color};height:100%;width:{min(score, 100)}%;border-radius:4px"></div>
      </div>
      <table style="font-size:.72rem;width:100%;border-collapse:collapse">
        <tr><td style="color:#9399b2">Base score</td><td style="text-align:right">{bd.get('base_score', 0)}</td></tr>
        <tr><td style="color:#9399b2">Protocol penalties</td><td style="text-align:right">+{bd.get('protocol_penalties', 0)}</td></tr>
        <tr><td style="color:#9399b2">Criticality mult</td><td style="text-align:right">&times;{bd.get('criticality_multiplier', 1.0)}</td></tr>
        <tr><td style="color:#9399b2">Exposure mult</td><td style="text-align:right">&times;{bd.get('exposure_multiplier', 1.0)}</td></tr>
        <tr><td style="color:#9399b2">KEV boost</td><td style="text-align:right">&times;{bd.get('kev_boost', 1.0)}</td></tr>
        <tr><td style="color:#9399b2">EPSS boost</td><td style="text-align:right">&times;{bd.get('epss_boost', 1.0)}</td></tr>
        <tr><td style="color:#9399b2">Controls factor</td><td style="text-align:right">&times;{bd.get('controls_factor', 1.0)}</td></tr>
      </table>"""

        # Compensating controls
        ctrls = dev.compensating_controls
        if ctrls:
            rows += '\n      <div style="margin-top:.3rem;font-size:.72rem;color:#a6e3a1">'
            for c in ctrls:
                rows += f'<div>&#x2713; {_h(c)}</div>'
            rows += "</div>"

        rows += "\n    </div>"
        return rows

    @staticmethod
    def _threat_alerts_html(dev: OTDevice) -> str:
        """Render threat alert cards for HTML device detail."""
        if not dev.threat_alerts:
            return ""
        parts: List[str] = []
        for a in dev.threat_alerts:
            sc = SEVERITY_COLOR.get(a.severity, SEVERITY_COLOR["unknown"])
            sb = SEVERITY_BG.get(a.severity, SEVERITY_BG["unknown"])
            mitre = f' <span style="color:#89b4fa;font-size:.7rem">[{a.mitre_technique}]</span>' if a.mitre_technique else ""
            type_badge = f'<span style="background:#31324480;padding:1px 6px;border-radius:3px;font-size:.68rem">{a.alert_type}</span>'
            parts.append(
                f'<div style="background:{sb};border-left:3px solid {sc};'
                f'padding:.4rem .6rem;margin-bottom:.3rem;border-radius:0 4px 4px 0">'
                f'<span style="color:{sc};font-weight:700;font-size:.75rem">'
                f'{a.severity.upper()}</span> {type_badge}{mitre} '
                f'<span style="font-size:.78rem">{_h(a.title)}</span>'
                f'<div style="font-size:.72rem;color:#9399b2;margin-top:.2rem">'
                f'{_h(a.description[:200])}</div>'
                f'</div>'
            )
        return "\n    ".join(parts)

    # ──────────────────────────────────────────────── device row builder ──

    @staticmethod
    def _remote_access_html(dev: OTDevice) -> str:
        """Render remote access sessions for HTML device detail."""
        if not dev.remote_access_sessions:
            return ""
        parts: List[str] = []
        for s in dev.remote_access_sessions:
            # Compliance badge color
            if s.compliance_status == "compliant":
                badge_c, badge_bg = "#a6e3a1", "#a6e3a120"
                badge_text = "COMPLIANT"
            elif s.compliance_status == "non_compliant":
                badge_c, badge_bg = "#f38ba8", "#f38ba820"
                badge_text = "NON-COMPLIANT"
            else:
                badge_c, badge_bg = "#fab387", "#fab38720"
                badge_text = "REVIEW"

            vpn_tag = ' <span style="color:#89b4fa;font-size:.68rem">[VPN]</span>' if s.is_vpn else ""
            enc_tag = ' <span style="color:#a6e3a1;font-size:.68rem">[ENC]</span>' if s.is_encrypted else ' <span style="color:#f38ba8;font-size:.68rem">[CLEARTEXT]</span>'

            dur = f"{s.duration_seconds:.0f}s" if s.duration_seconds else "N/A"
            issues_html = ""
            if s.compliance_issues:
                issues_html = '<div style="font-size:.7rem;color:#f38ba8;margin-top:.15rem">'
                for issue in s.compliance_issues:
                    issues_html += f"<div>&#x2717; {_h(issue)}</div>"
                issues_html += "</div>"

            parts.append(
                f'<div style="background:{badge_bg};border-left:3px solid {badge_c};'
                f'padding:.4rem .6rem;margin-bottom:.3rem;border-radius:0 4px 4px 0">'
                f'<span style="color:{badge_c};font-weight:700;font-size:.72rem">'
                f'{badge_text}</span> '
                f'<span style="font-size:.78rem">{s.protocol} from {s.src_ip}'
                f' → {s.dst_ip}:{s.port}</span>{vpn_tag}{enc_tag}'
                f'<div style="font-size:.72rem;color:#9399b2;margin-top:.15rem">'
                f'Duration: {dur} | Packets: {s.packet_count:,} | '
                f'Bytes: {s.byte_count:,} | L{s.src_purdue}→L{s.dst_purdue}</div>'
                f'{issues_html}'
                f'</div>'
            )
        return "\n    ".join(parts)

    @staticmethod
    def _config_drift_html(dev: OTDevice) -> str:
        """Render config drift alerts for HTML device detail."""
        if not dev.config_drift_alerts:
            return ""
        parts: List[str] = []
        for a in dev.config_drift_alerts:
            sc = SEVERITY_COLOR.get(a.severity, SEVERITY_COLOR["unknown"])
            sb = SEVERITY_BG.get(a.severity, SEVERITY_BG["unknown"])
            mitre = f' <span style="color:#89b4fa;font-size:.7rem">[{a.mitre_technique}]</span>' if a.mitre_technique else ""
            parts.append(
                f'<div style="background:{sb};border-left:3px solid {sc};'
                f'padding:.4rem .6rem;margin-bottom:.3rem;border-radius:0 4px 4px 0">'
                f'<span style="color:{sc};font-weight:700;font-size:.75rem">'
                f'{a.severity.upper()}</span>{mitre} '
                f'<span style="font-size:.78rem">{_h(a.title)}</span>'
                f'<div style="font-size:.72rem;color:#9399b2;margin-top:.15rem">'
                f'{_h(a.old_value)} &rarr; {_h(a.new_value)}</div>'
                f'</div>'
            )
        return "\n    ".join(parts)

    @staticmethod
    def _attack_paths_html(dev: OTDevice) -> str:
        """Render attack paths targeting this device for HTML detail card."""
        if not dev.attack_paths:
            return ""
        parts: List[str] = []
        for p in dev.attack_paths:
            sc = SEVERITY_COLOR.get(p.severity, SEVERITY_COLOR["unknown"])
            sb = SEVERITY_BG.get(p.severity, SEVERITY_BG["unknown"])

            # Path visualization: entry → hop1 → hop2 → TARGET
            hop_chain = " &rarr; ".join(
                f'<span style="color:{"#f38ba8" if i == len(p.hops)-1 else "#cdd6f4"}">'
                f'{h["ip"]} (L{h.get("purdue_level", "?")})</span>'
                for i, h in enumerate(p.hops)
            )

            # Kill chain badges
            kc_badges = " ".join(
                f'<span style="background:#31324480;padding:1px 5px;border-radius:3px;'
                f'font-size:.65rem;color:#89b4fa">{k["technique"]}</span>'
                for k in p.mitre_kill_chain
            )

            parts.append(
                f'<div style="background:{sb};border-left:3px solid {sc};'
                f'padding:.5rem .6rem;margin-bottom:.4rem;border-radius:0 4px 4px 0">'
                f'<span style="color:{sc};font-weight:700;font-size:.75rem">'
                f'{p.severity.upper()}</span> '
                f'<span style="font-size:.75rem">Score: {p.path_score}/100</span> '
                f'<span style="font-size:.7rem;color:#9399b2">'
                f'| {p.hop_count} hops | {p.auth_gaps} auth gaps | '
                f'{p.encryption_gaps} enc gaps</span>'
                f'<div style="font-size:.75rem;margin-top:.3rem">{hop_chain}</div>'
                f'<div style="margin-top:.2rem">{kc_badges}</div>'
                f'</div>'
            )
        return "\n    ".join(parts)

    # ──────────────────────────────────────────────── device row builder ──

    def _device_row(self, dev: OTDevice) -> str:
        uid   = dev.ip.replace(".", "_")
        rc    = SEVERITY_COLOR.get(dev.risk_level, SEVERITY_COLOR["unknown"])
        make  = dev.make or dev.vendor or "Unknown"
        model = _h((dev.model or "")[:22])
        mac   = dev.mac or "-"
        dtype = dev.device_type or "-"
        ptags = " ".join(
            f'<span class="proto-tag">{_h(p)}</span>'
            for p in dev.get_protocol_names()
        ) or "-"
        vcnt  = len(dev.vulnerabilities)

        # Vulnerability cards
        vuln_html = self._vuln_cards(dev.vulnerabilities)

        # Risk factor cards
        rf_html = "".join(
            f'<div class="risk-factor">{_h(f)}</div>'
            for f in dev.risk_factors
        ) if dev.risk_factors else '<em style="color:#a6e3a1">None identified</em>'

        # Info grid
        peers = sorted(dev.communicating_with)[:12]
        peers_str = ", ".join(peers)
        if len(dev.communicating_with) > 12:
            peers_str += f" ... (+{len(dev.communicating_with) - 12} more)"

        masters_str = ", ".join(sorted(dev.master_stations)) or "-"
        goose_str   = ", ".join(sorted(dev.goose_ids)) or "-"
        ln_str      = ", ".join(sorted(dev.logical_nodes)[:8]) or "-"

        proto_details_html = ""
        for p in dev.protocols:
            interesting = {k: v for k, v in p.details.items() if v is not None}
            if interesting:
                rows = "".join(
                    f'<div><span class="dl">{_h(str(k))}</span>'
                    f'<div class="dv">{_h(str(v))}</div></div>'
                    for k, v in interesting.items()
                )
                proto_details_html += (
                    f'<details style="margin:.2rem 0">'
                    f'<summary style="cursor:pointer;color:#89dceb;font-size:.78rem">'
                    f'{_h(p.protocol)} (port {p.port}, {p.packet_count} pkts, '
                    f'{p.confidence})</summary>'
                    f'<div class="detail-grid" style="margin-top:.4rem">{rows}</div>'
                    f'</details>'
                )

        detail_html = f"""<div class="detail-grid">
  <div>
    <span class="dl">IP</span><div class="dv">{dev.ip}</div>
    <span class="dl">MAC</span><div class="dv">{mac}</div>
    <span class="dl">Vendor Confidence</span><div class="dv">{dev.vendor_confidence}</div>
    <span class="dl">Firmware</span><div class="dv">{_h(dev.firmware or '-')}</div>
    <span class="dl">Hardware Version</span><div class="dv">{_h(dev.hardware_version or '-')}</div>
    <span class="dl">Serial Number</span><div class="dv">{_h(dev.serial_number or '-')}</div>
    <span class="dl">Product Code</span><div class="dv">{_h(dev.product_code or '-')}</div>
    <span class="dl">Rack / Slot</span><div class="dv">{f"{dev.rack} / {dev.slot}" if dev.rack is not None else '-'}</div>
    <span class="dl">CPU Info</span><div class="dv">{_h(dev.cpu_info or '-')}</div>
    <span class="dl">Modules</span><div class="dv">{f"{len(dev.modules)} module(s)" if dev.modules else '-'}</div>
    <span class="dl">Device Criticality</span><div class="dv">{_h(dev.device_criticality)}</div>
    <span class="dl">Comm Profile</span><div class="dv">{_h(self._comm_summary(dev))}</div>
    <span class="dl">DNP3 Address</span><div class="dv">{dev.dnp3_address or '-'}</div>
    <span class="dl">IEC-104 Common Address</span><div class="dv">{dev.iec104_common_address or '-'}</div>
    <span class="dl">GOOSE IDs</span><div class="dv">{_h(goose_str)}</div>
    <span class="dl">IEC 61850 Logical Nodes</span><div class="dv">{_h(ln_str)}</div>
    <span class="dl">Master Stations</span><div class="dv">{_h(masters_str)}</div>
    <span class="dl">Open OT Ports</span><div class="dv">{', '.join(str(p) for p in sorted(dev.open_ports)) or '-'}</div>
    <span class="dl">Peers ({len(dev.communicating_with)})</span><div class="dv" style="font-size:.72rem">{_h(peers_str) or '-'}</div>
    <span class="dl">First / Last Seen</span><div class="dv">
      {dev.first_seen.strftime('%H:%M:%S') if dev.first_seen else '-'} /
      {dev.last_seen.strftime('%H:%M:%S') if dev.last_seen else '-'}
    </div>
    <span class="dl">Risk Score</span><div class="dv">{dev.risk_score}</div>
    <span class="dl">Composite Risk</span><div class="dv">{dev.composite_risk_score}/100</div>
    {self._risk_breakdown_html(dev)}
  </div>
  <div>
    <span class="dl">Protocol Details</span>
    <div style="margin-top:.3rem">{proto_details_html or '<em style="color:#6c7086">No protocol details</em>'}</div>
    <span class="dl" style="margin-top:.8rem;display:block">Risk Factors</span>
    <div style="margin-top:.3rem">{rf_html}</div>
    <span class="dl" style="margin-top:.8rem;display:block">Vulnerability Findings ({vcnt})</span>
    <div style="margin-top:.3rem">{vuln_html or '<em style="color:#a6e3a1">No vulnerabilities detected</em>'}</div>
    <span class="dl" style="margin-top:.8rem;display:block">CVE Matches ({len(dev.cve_matches)})</span>
    <div style="margin-top:.3rem">{self._cve_matches_html(dev) or '<em style="color:#a6e3a1">No known CVEs matched</em>'}</div>
    <span class="dl" style="margin-top:.8rem;display:block">IT Protocols ({len(dev.it_protocols)})</span>
    <div style="margin-top:.3rem">{self._it_protocols_detail(dev) or '<em style="color:#a6e3a1">No IT protocols detected</em>'}</div>
    <span class="dl" style="margin-top:.8rem;display:block">Threat Alerts ({len(dev.threat_alerts)})</span>
    <div style="margin-top:.3rem">{self._threat_alerts_html(dev) or '<em style="color:#a6e3a1">No threat alerts</em>'}</div>
    <span class="dl" style="margin-top:.8rem;display:block">Remote Access Sessions ({len(dev.remote_access_sessions)})</span>
    <div style="margin-top:.3rem">{self._remote_access_html(dev) or '<em style="color:#a6e3a1">No remote access detected</em>'}</div>
    <span class="dl" style="margin-top:.8rem;display:block">Configuration Drift ({len(dev.config_drift_alerts)})</span>
    <div style="margin-top:.3rem">{self._config_drift_html(dev) or '<em style="color:#a6e3a1">No configuration changes</em>'}</div>
    <span class="dl" style="margin-top:.8rem;display:block">Attack Paths ({len(dev.attack_paths)})</span>
    <div style="margin-top:.3rem">{self._attack_paths_html(dev) or '<em style="color:#a6e3a1">No attack paths identified</em>'}</div>
  </div>
</div>"""

        return f"""      <tr>
        <td><strong>{dev.ip}</strong></td>
        <td style="font-family:monospace;font-size:.77rem">{mac}</td>
        <td>{_h(make)}</td>
        <td>{model}</td>
        <td>{_h(dtype)}</td>
        <td>{ptags}</td>
        <td style="text-align:center">
          <span style="color:{rc};font-weight:700">{vcnt}</span>
        </td>
        <td><span class="risk-pill" style="background:{rc}">{dev.risk_level.upper()}</span></td>
        <td style="text-align:right">{dev.packet_count:,}</td>
        <td><button class="expand-btn" onclick="toggle('{uid}')">expand</button></td>
      </tr>
      <tr id="dr_{uid}" class="detail-tr">
        <td colspan="10" class="detail-td">{detail_html}</td>
      </tr>"""

    def _vuln_cards(self, vulns: List[VulnerabilityFinding]) -> str:
        if not vulns:
            return ""
        cards = []
        for v in vulns:
            c  = SEVERITY_COLOR.get(v.severity, SEVERITY_COLOR["unknown"])
            bg = SEVERITY_BG.get(v.severity, SEVERITY_BG["unknown"])
            refs = " | ".join(v.references[:3]) if v.references else ""
            ev_rows = "".join(
                f'<span style="color:#6c7086">{_h(str(k))}:</span> '
                f'<span style="color:#a6adc8">{_h(str(val))}</span><br>'
                for k, val in list(v.evidence.items())[:6]
                if val is not None
            )
            cards.append(
                f'<div class="vuln-card" style="border-color:{c};background:{bg}">'
                f'<div class="vuln-id">{_h(v.vuln_id)}</div>'
                f'<div class="vuln-title" style="color:{c}">'
                f'<span class="risk-pill" style="background:{c}">{v.severity.upper()}</span> '
                f'{_h(v.title)}</div>'
                f'<div class="vuln-desc">{_h(v.description)}</div>'
                f'<details><summary style="cursor:pointer;color:#a6adc8;font-size:.72rem">'
                f'Evidence</summary>'
                f'<div style="padding:.3rem 0;font-size:.73rem">{ev_rows}</div></details>'
                f'<div class="vuln-rem"><strong>Fix:</strong> {_h(v.remediation)}</div>'
                f'<div class="vuln-ref">{_h(refs)}</div>'
                f'</div>'
            )
        return "\n".join(cards)


# ─────────────────────────────────────────────── module helpers ───────────────

def _h(s: str) -> str:
    """HTML-escape a string."""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))


def _risk_summary(devices: List[OTDevice]) -> dict:
    c: dict = {}
    for d in devices:
        c[d.risk_level] = c.get(d.risk_level, 0) + 1
    return c


def _vuln_summary(devices: List[OTDevice]) -> dict:
    c: dict = {}
    for d in devices:
        for v in d.vulnerabilities:
            c[v.severity] = c.get(v.severity, 0) + 1
    return c


def _proto_summary(devices: List[OTDevice]) -> dict:
    c: dict = {}
    for d in devices:
        for p in d.get_protocol_names():
            c[p] = c.get(p, 0) + 1
    return dict(sorted(c.items(), key=lambda x: -x[1]))


def _cve_summary(devices: List[OTDevice]) -> dict:
    all_cves = [c for d in devices for c in d.cve_matches]
    return {
        "total": len(all_cves),
        "now": sum(1 for c in all_cves if c.priority == "now"),
        "next": sum(1 for c in all_cves if c.priority == "next"),
        "never": sum(1 for c in all_cves if c.priority == "never"),
        "unique_cves": len(set(c.cve_id for c in all_cves)),
        "devices_with_cves": sum(1 for d in devices if d.cve_matches),
    }
