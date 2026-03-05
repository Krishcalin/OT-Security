"""
Report Generator — JSON, CSV, and standalone HTML reports for RTU/FRTU scan results.

HTML report highlights:
  • Vulnerability findings per device with severity colour-coding
  • Remediation guidance per finding
  • Standards references (IEC 62351, NERC CIP, etc.)
  • Device identity, protocol, and topology details
"""
import csv
import json
import os
from collections import Counter
from datetime import datetime
from typing import List

from ..models import RTUDevice, VulnerabilityFinding

SEVER_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#ca8a04",
    "low":      "#16a34a",
    "info":     "#6b7280",
    "unknown":  "#6b7280",
}
SEVER_BG = {
    "critical": "#fef2f2",
    "high":     "#fff7ed",
    "medium":   "#fefce8",
    "low":      "#f0fdf4",
    "info":     "#f9fafb",
    "unknown":  "#f9fafb",
}


class ReportGenerator:

    def __init__(self, devices: List[RTUDevice], scan_file: str = ""):
        self.devices   = devices
        self.scan_file = scan_file
        self.generated = datetime.now()

    # ──────────────────────────────────────────────────── console ────────

    def print_summary(self) -> None:
        try:
            from colorama import Fore, Style, init
            init(autoreset=True)
            _c = lambda t, s: {
                "critical": Fore.RED + Style.BRIGHT,
                "high":     Fore.YELLOW + Style.BRIGHT,
                "medium":   Fore.YELLOW,
                "low":      Fore.GREEN,
            }.get(s, "") + t + Style.RESET_ALL
        except ImportError:
            _c = lambda t, s: t

        width = 130
        print("─" * width)
        print(f"{'IP':<18} {'MAC':<20} {'Make':<24} {'Model':<20} "
              f"{'Protocols':<28} {'Vulns':>6} {'Risk':<10}")
        print("─" * width)

        for dev in self.devices:
            protos  = ", ".join(dev.get_protocol_names()) or "—"
            make    = dev.rtu_make or dev.vendor or "Unknown"
            model   = (dev.rtu_model or "")[:18]
            mac     = dev.mac or "—"
            v_count = len(dev.vulnerabilities)
            risk    = dev.risk_level.upper()
            row = (f"{dev.ip:<18} {mac:<20} {make:<24} {model:<20} "
                   f"{protos[:27]:<28} {v_count:>6} {risk:<10}")
            print(_c(row, dev.risk_level))

        print("─" * width)
        print()

        # Risk summary
        risk_c = Counter(d.risk_level for d in self.devices)
        print("Risk Summary:")
        for lvl in ("critical", "high", "medium", "low", "unknown"):
            n = risk_c.get(lvl, 0)
            if n:
                bar = "█" * n
                print(f"  {lvl.upper():<12} {bar} ({n})")

        # Vulnerability summary
        all_vulns = [v for d in self.devices for v in d.vulnerabilities]
        sev_c = Counter(v.severity for v in all_vulns)
        print(f"\nVulnerabilities Found: {len(all_vulns)}")
        for lvl in ("critical", "high", "medium", "low"):
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
        print()

    # ──────────────────────────────────────────────────────── JSON ────────

    def to_json(self, path: str) -> None:
        all_vulns = [v for d in self.devices for v in d.vulnerabilities]
        report = {
            "scan_metadata": {
                "pcap_file":        os.path.basename(self.scan_file),
                "generated":        self.generated.isoformat(),
                "tool":             "RTU/FRTU Passive Vulnerability Scanner v1.0",
                "total_devices":    len(self.devices),
                "total_vulns":      len(all_vulns),
            },
            "risk_summary":      _risk_summary(self.devices),
            "vuln_summary":      _vuln_summary(self.devices),
            "protocol_summary":  _proto_summary(self.devices),
            "devices":           [d.to_dict() for d in self.devices],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)

    # ──────────────────────────────────────────────────────── CSV ─────────

    def to_csv(self, path: str) -> None:
        fields = [
            "ip", "mac", "vendor", "rtu_make", "rtu_model", "firmware",
            "device_type", "role", "dnp3_address", "iec104_common_address",
            "protocols", "open_ports", "goose_ids",
            "first_seen", "last_seen", "packet_count",
            "risk_level", "risk_score",
            "vuln_count", "critical_vulns", "high_vulns",
            "vuln_ids", "master_stations",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for d in self.devices:
                sev = Counter(v.severity for v in d.vulnerabilities)
                w.writerow({
                    "ip":                    d.ip,
                    "mac":                   d.mac or "",
                    "vendor":                d.vendor or "",
                    "rtu_make":              d.rtu_make or "",
                    "rtu_model":             d.rtu_model or "",
                    "firmware":              d.firmware or "",
                    "device_type":           d.device_type,
                    "role":                  d.role,
                    "dnp3_address":          d.dnp3_address or "",
                    "iec104_common_address": d.iec104_common_address or "",
                    "protocols":             " | ".join(d.get_protocol_names()),
                    "open_ports":            " | ".join(str(p) for p in sorted(d.open_ports)),
                    "goose_ids":             " | ".join(sorted(d.goose_ids)),
                    "first_seen":            d.first_seen.isoformat() if d.first_seen else "",
                    "last_seen":             d.last_seen.isoformat()  if d.last_seen  else "",
                    "packet_count":          d.packet_count,
                    "risk_level":            d.risk_level,
                    "risk_score":            d.risk_score,
                    "vuln_count":            len(d.vulnerabilities),
                    "critical_vulns":        sev.get("critical", 0),
                    "high_vulns":            sev.get("high", 0),
                    "vuln_ids":              " | ".join(v.vuln_id for v in d.vulnerabilities),
                    "master_stations":       " | ".join(sorted(d.master_stations)),
                })

    # ──────────────────────────────────────────────────────── HTML ────────

    def to_html(self, path: str) -> None:
        all_vulns    = [v for d in self.devices for v in d.vulnerabilities]
        risk_counts  = _risk_summary(self.devices)
        proto_counts = _proto_summary(self.devices)
        vuln_summary = _vuln_summary(self.devices)

        risk_badges = " ".join(
            f'<span class="badge" style="background:{SEVER_COLOR[r]}">'
            f'{r.upper()}: {risk_counts.get(r,0)}</span>'
            for r in ("critical","high","medium","low") if risk_counts.get(r,0)
        )
        vuln_badges = " ".join(
            f'<span class="badge" style="background:{SEVER_COLOR[s]}">'
            f'{s.upper()}: {vuln_summary.get(s,0)}</span>'
            for s in ("critical","high","medium","low") if vuln_summary.get(s,0)
        )
        proto_rows = "".join(
            f"<tr><td>{p}</td><td>{c}</td></tr>" for p, c in proto_counts.items()
        )
        devices_html = "\n".join(self._device_row(d) for d in self.devices)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>RTU/FRTU Passive Vulnerability Scan Report</title>
<style>
* {{ box-sizing:border-box; margin:0; padding:0 }}
body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#0a0f1e; color:#e2e8f0 }}
header {{ background:linear-gradient(135deg,#0f2d4a 0%,#0a0f1e 100%);
          padding:2rem; border-bottom:2px solid #1e3a5f }}
header h1 {{ font-size:1.7rem; color:#f97316 }}
header .sub {{ color:#94a3b8; font-size:.85rem; margin-top:.4rem }}
.container {{ max-width:1500px; margin:0 auto; padding:1.5rem }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
         gap:1rem; margin:1.5rem 0 }}
.card {{ background:#0f1e30; border:1px solid #1e3a5f; border-radius:8px; padding:1.2rem }}
.card h3 {{ color:#94a3b8; font-size:.72rem; text-transform:uppercase;
            letter-spacing:.1em; margin-bottom:.5rem }}
.card .val {{ font-size:1.9rem; font-weight:700; color:#f8fafc }}
.badge {{ display:inline-block; padding:.2rem .65rem; border-radius:999px;
          color:#fff; font-size:.72rem; font-weight:700; margin:.12rem }}
.sec {{ color:#f97316; font-size:1.05rem; font-weight:600;
        margin:2rem 0 .8rem; border-bottom:1px solid #1e3a5f; padding-bottom:.3rem }}
table {{ width:100%; border-collapse:collapse }}
th {{ background:#0f1e30; color:#94a3b8; text-align:left; padding:.55rem .8rem;
      font-size:.72rem; text-transform:uppercase; letter-spacing:.05em;
      border-bottom:2px solid #1e3a5f; white-space:nowrap }}
td {{ padding:.5rem .8rem; border-bottom:1px solid #0f1e30; font-size:.82rem; vertical-align:top }}
tr:nth-child(even) td {{ background:#09111f }}
tr:hover td {{ background:#112035 }}
.risk-pill {{ display:inline-block; padding:.18rem .5rem; border-radius:4px;
              font-size:.7rem; font-weight:700; color:#fff }}
.proto-tag {{ display:inline-block; background:#0f2d4a; color:#7dd3fc;
              border-radius:4px; padding:.08rem .4rem; font-size:.7rem; margin:.08rem }}
.expand-btn {{ background:#0f2d4a; border:none; color:#f97316; cursor:pointer;
               padding:.22rem .55rem; border-radius:4px; font-size:.75rem }}
.detail-tr {{ display:none }}
.detail-td {{ background:#060d18 !important; padding:1rem 1.2rem }}
.detail-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:.5rem 2rem }}
.dl {{ color:#64748b; font-size:.7rem; text-transform:uppercase; margin-bottom:.1rem }}
.dv {{ color:#e2e8f0; font-size:.8rem; word-break:break-all; margin-bottom:.5rem }}
/* Vulnerability cards */
.vuln-card {{ border-left:3px solid; border-radius:0 6px 6px 0;
              padding:.6rem .8rem; margin:.35rem 0; font-size:.8rem }}
.vuln-title {{ font-weight:600; margin-bottom:.2rem }}
.vuln-desc {{ color:#94a3b8; font-size:.75rem; margin-bottom:.3rem }}
.vuln-rem {{ color:#7dd3fc; font-size:.73rem }}
.vuln-ref {{ color:#64748b; font-size:.7rem; margin-top:.2rem }}
.vuln-id {{ font-family:monospace; font-size:.68rem; color:#64748b }}
footer {{ text-align:center; color:#1e3a5f; font-size:.75rem;
          padding:2rem; border-top:1px solid #0f1e30; margin-top:3rem }}
</style>
</head>
<body>
<header>
  <h1>&#x26A1; RTU / FRTU Passive Vulnerability &amp; Misconfiguration Scan</h1>
  <div class="sub">
    <strong>PCAP:</strong> {os.path.basename(self.scan_file)} &nbsp;|&nbsp;
    <strong>Generated:</strong> {self.generated.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
    <strong>Tool:</strong> RTU/FRTU Passive Scanner v1.0 &nbsp;|&nbsp;
    <strong>Mode:</strong> Offline / Passive — no packets sent
  </div>
</header>

<div class="container">

  <div class="grid">
    <div class="card">
      <h3>Devices Found</h3>
      <div class="val">{len(self.devices)}</div>
    </div>
    <div class="card">
      <h3>Risk Distribution</h3>
      <div style="margin-top:.4rem">{risk_badges}</div>
    </div>
    <div class="card">
      <h3>Vulnerabilities</h3>
      <div class="val" style="font-size:1.5rem">{len(all_vulns)}</div>
      <div style="margin-top:.3rem">{vuln_badges}</div>
    </div>
    <div class="card">
      <h3>Protocols Detected</h3>
      <div class="val">{len(proto_counts)}</div>
    </div>
    <div class="card">
      <h3>Critical + High Risk</h3>
      <div class="val" style="color:{SEVER_COLOR['critical']}">
        {risk_counts.get('critical',0) + risk_counts.get('high',0)}
      </div>
    </div>
  </div>

  <div class="sec">Protocol Breakdown</div>
  <div style="overflow:auto;margin-bottom:1.5rem">
  <table style="width:auto;min-width:420px">
    <thead><tr><th>Protocol</th><th>Devices</th></tr></thead>
    <tbody>{proto_rows}</tbody>
  </table>
  </div>

  <div class="sec">Discovered Devices &amp; Vulnerability Findings</div>
  <div style="overflow:auto">
  <table>
    <thead>
      <tr>
        <th>IP Address</th><th>MAC</th><th>Make / Vendor</th>
        <th>Model</th><th>Type</th><th>Protocols</th>
        <th>Vulns</th><th>Risk</th><th>Details</th>
      </tr>
    </thead>
    <tbody>
{devices_html}
    </tbody>
  </table>
  </div>

</div>

<footer>
  RTU / FRTU Passive Vulnerability Scanner — Defensive OT Security Tool &nbsp;|&nbsp;
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

    # ──────────────────────────────────────────────── row builder ─────────

    def _device_row(self, dev: RTUDevice) -> str:
        uid   = dev.ip.replace(".", "_")
        rc    = SEVER_COLOR.get(dev.risk_level, SEVER_COLOR["unknown"])
        make  = dev.rtu_make or dev.vendor or "Unknown"
        model = (dev.rtu_model or "")[:22]
        mac   = dev.mac or "—"
        dtype = dev.device_type or "—"
        ptags = " ".join(f'<span class="proto-tag">{p}</span>'
                         for p in dev.get_protocol_names()) or "—"
        vcnt  = len(dev.vulnerabilities)

        # Vulnerability cards
        vuln_html = self._vuln_cards(dev.vulnerabilities)

        # Info grid
        peers = sorted(dev.communicating_with)[:12]
        peers_str = ", ".join(peers)
        if len(dev.communicating_with) > 12:
            peers_str += f" … (+{len(dev.communicating_with)-12} more)"

        masters_str = ", ".join(sorted(dev.master_stations)) or "—"
        goose_str   = ", ".join(sorted(dev.goose_ids)) or "—"
        ln_str      = ", ".join(sorted(dev.logical_nodes)[:8]) or "—"

        proto_details_html = ""
        for p in dev.protocols:
            interesting = {k: v for k, v in p.details.items() if v is not None}
            if interesting:
                rows = "".join(
                    f'<div><span class="dl">{k}</span>'
                    f'<div class="dv">{v}</div></div>'
                    for k, v in interesting.items()
                )
                proto_details_html += (
                    f'<details style="margin:.2rem 0">'
                    f'<summary style="cursor:pointer;color:#7dd3fc;font-size:.78rem">'
                    f'{p.protocol} (port {p.port}, {p.packet_count} pkts, '
                    f'{p.confidence})</summary>'
                    f'<div class="detail-grid" style="margin-top:.4rem">{rows}</div>'
                    f'</details>'
                )

        detail_html = f"""<div class="detail-grid">
  <div>
    <span class="dl">IP</span><div class="dv">{dev.ip}</div>
    <span class="dl">MAC</span><div class="dv">{mac}</div>
    <span class="dl">Vendor Confidence</span><div class="dv">{dev.vendor_confidence}</div>
    <span class="dl">Firmware</span><div class="dv">{dev.firmware or '—'}</div>
    <span class="dl">Serial Number</span><div class="dv">{dev.serial_number or '—'}</div>
    <span class="dl">DNP3 Outstation Addr</span><div class="dv">{dev.dnp3_address or '—'}</div>
    <span class="dl">IEC104 Common Address</span><div class="dv">{dev.iec104_common_address or '—'}</div>
    <span class="dl">GOOSE IDs</span><div class="dv">{goose_str}</div>
    <span class="dl">IEC 61850 Logical Nodes</span><div class="dv">{ln_str}</div>
    <span class="dl">Master Stations</span><div class="dv">{masters_str}</div>
    <span class="dl">Open OT Ports</span><div class="dv">{', '.join(str(p) for p in sorted(dev.open_ports)) or '—'}</div>
    <span class="dl">Peers ({len(dev.communicating_with)})</span><div class="dv" style="font-size:.72rem">{peers_str or '—'}</div>
    <span class="dl">First / Last Seen</span><div class="dv">
      {dev.first_seen.strftime('%H:%M:%S') if dev.first_seen else '—'} /
      {dev.last_seen.strftime('%H:%M:%S') if dev.last_seen else '—'}
    </div>
    <span class="dl">Risk Score</span><div class="dv">{dev.risk_score}</div>
  </div>
  <div>
    <span class="dl">Protocol Details</span>
    <div style="margin-top:.3rem">{proto_details_html or '<em style="color:#64748b">No protocol details</em>'}</div>
    <span class="dl" style="margin-top:.8rem;display:block">Vulnerability Findings ({vcnt})</span>
    <div style="margin-top:.3rem">{vuln_html or '<em style="color:#16a34a">No vulnerabilities detected</em>'}</div>
  </div>
</div>"""

        return f"""      <tr>
        <td><strong>{dev.ip}</strong></td>
        <td style="font-family:monospace;font-size:.77rem">{mac}</td>
        <td>{make}</td>
        <td>{model}</td>
        <td>{dtype}</td>
        <td>{ptags}</td>
        <td style="text-align:center">
          <span style="color:{rc};font-weight:700">{vcnt}</span>
        </td>
        <td><span class="risk-pill" style="background:{rc}">{dev.risk_level.upper()}</span></td>
        <td><button class="expand-btn" onclick="toggle('{uid}')">▼ expand</button></td>
      </tr>
      <tr id="dr_{uid}" class="detail-tr">
        <td colspan="9" class="detail-td">{detail_html}</td>
      </tr>"""

    def _vuln_cards(self, vulns: List[VulnerabilityFinding]) -> str:
        if not vulns:
            return ""
        cards = []
        for v in vulns:
            c  = SEVER_COLOR.get(v.severity, "#6b7280")
            refs = " · ".join(v.references[:3]) if v.references else ""
            ev_rows = "".join(
                f'<span style="color:#64748b">{k}:</span> '
                f'<span style="color:#94a3b8">{val}</span><br>'
                for k, val in list(v.evidence.items())[:6] if val is not None
            )
            cards.append(
                f'<div class="vuln-card" style="border-color:{c};background:{SEVER_BG.get(v.severity,SEVER_BG["info"])}20">'
                f'<div class="vuln-id">{v.vuln_id}</div>'
                f'<div class="vuln-title" style="color:{c}">'
                f'<span class="risk-pill" style="background:{c}">{v.severity.upper()}</span> '
                f'{v.title}</div>'
                f'<div class="vuln-desc">{v.description}</div>'
                f'<details><summary style="cursor:pointer;color:#94a3b8;font-size:.72rem">Evidence</summary>'
                f'<div style="padding:.3rem 0;font-size:.73rem">{ev_rows}</div></details>'
                f'<div class="vuln-rem"><strong>Fix:</strong> {v.remediation}</div>'
                f'<div class="vuln-ref">{refs}</div>'
                f'</div>'
            )
        return "\n".join(cards)


# ─────────────────────────────────────────────── module helpers ────────────

def _risk_summary(devices: List[RTUDevice]) -> dict:
    c: dict = {}
    for d in devices:
        c[d.risk_level] = c.get(d.risk_level, 0) + 1
    return c

def _vuln_summary(devices: List[RTUDevice]) -> dict:
    c: dict = {}
    for d in devices:
        for v in d.vulnerabilities:
            c[v.severity] = c.get(v.severity, 0) + 1
    return c

def _proto_summary(devices: List[RTUDevice]) -> dict:
    c: dict = {}
    for d in devices:
        for p in d.get_protocol_names():
            c[p] = c.get(p, 0) + 1
    return dict(sorted(c.items(), key=lambda x: -x[1]))
