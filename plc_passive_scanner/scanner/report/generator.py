"""
Report Generator — produces JSON, CSV, and standalone HTML reports
from the list of discovered PLCDevice objects.
"""
import csv
import json
import os
from collections import Counter
from datetime import datetime
from typing import List, Optional

from ..models import PLCDevice


RISK_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#ca8a04",
    "low":      "#16a34a",
    "unknown":  "#6b7280",
}

RISK_BG = {
    "critical": "#fef2f2",
    "high":     "#fff7ed",
    "medium":   "#fefce8",
    "low":      "#f0fdf4",
    "unknown":  "#f9fafb",
}


class ReportGenerator:
    """
    Generate scanner reports in multiple formats.

    Args:
        devices:   List of discovered PLCDevice objects.
        scan_file: Path to the PCAP file that was scanned (for metadata).
    """

    def __init__(self, devices: List[PLCDevice], scan_file: str = ""):
        self.devices   = devices
        self.scan_file = scan_file
        self.generated = datetime.now()

    # ------------------------------------------------------------------ console

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

        width = 120
        print("─" * width)
        print(f"{'IP Address':<18} {'MAC Address':<20} {'Make / Vendor':<28} {'Model':<26} "
              f"{'Protocols':<30} {'Risk':<8}")
        print("─" * width)

        for dev in self.devices:
            protocols = ", ".join(dev.get_protocol_names()) or "—"
            make      = dev.plc_make or dev.vendor or "Unknown"
            model     = (dev.plc_model or "")[:25]
            mac       = dev.mac or "—"
            risk_str  = dev.risk_level.upper()

            row = (f"{dev.ip:<18} {mac:<20} {make:<28} {model:<26} "
                   f"{protocols[:29]:<30} {risk_str:<8}")
            print(_color(row, dev.risk_level))

        print("─" * width)
        print()

        # Risk summary
        risk_counts = Counter(d.risk_level for d in self.devices)
        print("Risk Summary:")
        for level in ("critical", "high", "medium", "low", "unknown"):
            count = risk_counts.get(level, 0)
            if count:
                bar = "█" * count
                print(f"  {level.upper():<10} {bar} ({count})")

        # Protocol summary
        proto_counts: Counter = Counter()
        for dev in self.devices:
            for p in dev.get_protocol_names():
                proto_counts[p] += 1
        print("\nProtocol Summary:")
        for proto, count in proto_counts.most_common():
            print(f"  {proto:<30} {count} device(s)")
        print()

    # ------------------------------------------------------------------ JSON

    def to_json(self, path: str) -> None:
        report = {
            "scan_metadata": {
                "pcap_file":  os.path.basename(self.scan_file),
                "generated":  self.generated.isoformat(),
                "tool":       "PLC Passive Scanner v1.0",
                "total_devices": len(self.devices),
            },
            "risk_summary": _risk_summary(self.devices),
            "protocol_summary": _protocol_summary(self.devices),
            "devices": [d.to_dict() for d in self.devices],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)

    # ------------------------------------------------------------------ CSV

    def to_csv(self, path: str) -> None:
        fieldnames = [
            "ip", "mac", "vendor", "vendor_confidence",
            "plc_make", "plc_model", "firmware", "serial_number",
            "protocols", "open_ports", "communicating_with_count",
            "first_seen", "last_seen", "packet_count",
            "role", "risk_level", "risk_factors",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for d in self.devices:
                writer.writerow({
                    "ip":                      d.ip,
                    "mac":                     d.mac or "",
                    "vendor":                  d.vendor or "",
                    "vendor_confidence":       d.vendor_confidence,
                    "plc_make":                d.plc_make or "",
                    "plc_model":               d.plc_model or "",
                    "firmware":                d.firmware or "",
                    "serial_number":           d.serial_number or "",
                    "protocols":               " | ".join(d.get_protocol_names()),
                    "open_ports":              " | ".join(str(p) for p in sorted(d.open_ports)),
                    "communicating_with_count": len(d.communicating_with),
                    "first_seen":              d.first_seen.isoformat() if d.first_seen else "",
                    "last_seen":               d.last_seen.isoformat() if d.last_seen else "",
                    "packet_count":            d.packet_count,
                    "role":                    d.role,
                    "risk_level":              d.risk_level,
                    "risk_factors":            "; ".join(d.risk_factors),
                })

    # ------------------------------------------------------------------ HTML

    def to_html(self, path: str) -> None:
        risk_counts    = _risk_summary(self.devices)
        proto_counts   = _protocol_summary(self.devices)
        devices_html   = "\n".join(self._device_card(d) for d in self.devices)
        proto_rows     = "\n".join(
            f"<tr><td>{p}</td><td>{c}</td></tr>" for p, c in proto_counts.items()
        )
        risk_badges    = " ".join(
            f'<span class="badge" style="background:{RISK_COLORS[r]}">'
            f'{r.upper()}: {risk_counts.get(r, 0)}</span>'
            for r in ("critical", "high", "medium", "low")
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PLC Passive Scan Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }}
  header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
            padding: 2rem; border-bottom: 2px solid #334155; }}
  header h1 {{ font-size: 1.8rem; color: #38bdf8; letter-spacing: .05em; }}
  header .meta {{ margin-top: .5rem; color: #94a3b8; font-size: .85rem; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 1.5rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                   gap: 1rem; margin: 1.5rem 0; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px;
           padding: 1.2rem; }}
  .card h3 {{ color: #94a3b8; font-size: .75rem; text-transform: uppercase;
               letter-spacing: .1em; margin-bottom: .5rem; }}
  .card .value {{ font-size: 2rem; font-weight: 700; color: #f8fafc; }}
  .card .sub   {{ font-size: .8rem; color: #64748b; margin-top: .2rem; }}
  .badge {{ display: inline-block; padding: .25rem .7rem; border-radius: 999px;
            color: #fff; font-size: .75rem; font-weight: 600; margin: .15rem; }}
  .section-title {{ color: #38bdf8; font-size: 1.1rem; font-weight: 600;
                    margin: 2rem 0 1rem; border-bottom: 1px solid #334155;
                    padding-bottom: .4rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #1e293b; color: #94a3b8; text-align: left; padding: .6rem .8rem;
        font-size: .75rem; text-transform: uppercase; letter-spacing: .05em;
        border-bottom: 2px solid #334155; }}
  td {{ padding: .55rem .8rem; border-bottom: 1px solid #1e293b;
        font-size: .85rem; vertical-align: top; }}
  tr:nth-child(even) td {{ background: #0f172a; }}
  tr:hover td {{ background: #1a2540; }}
  .risk-pill {{ display: inline-block; padding: .2rem .55rem; border-radius: 4px;
                font-size: .72rem; font-weight: 700; color: #fff; }}
  .proto-tag {{ display: inline-block; background: #1e3a5f; color: #7dd3fc;
                border-radius: 4px; padding: .1rem .45rem; font-size: .72rem;
                margin: .1rem; }}
  .detail-row {{ background: #0d1829 !important; }}
  .detail-row td {{ padding: .8rem 1.2rem; color: #94a3b8; font-size: .82rem; }}
  .detail-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: .5rem 2rem; }}
  .detail-label {{ color: #64748b; font-size: .72rem; text-transform: uppercase; }}
  .detail-val   {{ color: #e2e8f0; font-size: .82rem; word-break: break-all; }}
  .risk-factor  {{ background: #2d1a1a; border-left: 3px solid #dc2626;
                   padding: .3rem .6rem; margin: .2rem 0; border-radius: 0 4px 4px 0;
                   font-size: .8rem; color: #fca5a5; }}
  details summary {{ cursor: pointer; color: #38bdf8; font-size: .8rem;
                     padding: .2rem 0; user-select: none; }}
  footer {{ text-align: center; color: #334155; font-size: .78rem; padding: 2rem;
            border-top: 1px solid #1e293b; margin-top: 3rem; }}
</style>
</head>
<body>
<header>
  <h1>&#x1F4E1; PLC Passive Scan Report</h1>
  <div class="meta">
    <strong>PCAP File:</strong> {os.path.basename(self.scan_file)} &nbsp;|&nbsp;
    <strong>Generated:</strong> {self.generated.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
    <strong>Tool:</strong> PLC Passive Scanner v1.0
  </div>
</header>

<div class="container">

  <!-- Summary Cards -->
  <div class="summary-grid">
    <div class="card">
      <h3>Devices Found</h3>
      <div class="value">{len(self.devices)}</div>
      <div class="sub">Industrial OT devices</div>
    </div>
    <div class="card">
      <h3>Protocols Detected</h3>
      <div class="value">{len(proto_counts)}</div>
      <div class="sub">{", ".join(list(proto_counts.keys())[:3])}</div>
    </div>
    <div class="card">
      <h3>Risk Distribution</h3>
      <div class="value" style="font-size:1rem; padding-top:.4rem">{risk_badges}</div>
    </div>
    <div class="card">
      <h3>Critical / High Risk</h3>
      <div class="value" style="color:{RISK_COLORS['critical']}">{risk_counts.get('critical',0) + risk_counts.get('high',0)}</div>
      <div class="sub">Require immediate attention</div>
    </div>
  </div>

  <!-- Protocol table -->
  <div class="section-title">Protocol Breakdown</div>
  <div style="overflow:auto">
  <table style="width:auto; min-width:400px">
    <thead><tr><th>Protocol</th><th>Device Count</th></tr></thead>
    <tbody>{proto_rows}</tbody>
  </table>
  </div>

  <!-- Devices table -->
  <div class="section-title">Discovered Devices</div>
  <div style="overflow:auto">
  <table id="deviceTable">
    <thead>
      <tr>
        <th>IP Address</th>
        <th>MAC Address</th>
        <th>Make / Vendor</th>
        <th>Model</th>
        <th>Protocols</th>
        <th>Pkts</th>
        <th>Risk</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody>
{devices_html}
    </tbody>
  </table>
  </div>

</div>
<footer>
  Generated by <strong>PLC Passive Scanner</strong> — OT Security Defensive Tool &nbsp;|&nbsp;
  {self.generated.strftime('%Y-%m-%d')}
</footer>
<script>
function toggleDetail(uid) {{
  var row = document.getElementById('detail_' + uid);
  if (row) {{
    row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
  }}
}}
</script>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)

    # ------------------------------------------------------------------ helpers

    def _device_card(self, dev: PLCDevice) -> str:
        risk_color = RISK_COLORS.get(dev.risk_level, RISK_COLORS["unknown"])
        risk_bg    = RISK_BG.get(dev.risk_level, RISK_BG["unknown"])
        risk_label = dev.risk_level.upper()
        make       = dev.plc_make or dev.vendor or "Unknown"
        model      = dev.plc_model or "—"
        mac        = dev.mac or "—"

        proto_tags = " ".join(
            f'<span class="proto-tag">{p}</span>'
            for p in dev.get_protocol_names()
        ) or "—"

        # Risk factors
        rf_html = "".join(
            f'<div class="risk-factor">⚠ {f}</div>' for f in dev.risk_factors
        ) if dev.risk_factors else "<em>None identified</em>"

        # Protocol details
        proto_details = ""
        for p in dev.protocols:
            interesting = {k: v for k, v in p.details.items()
                           if v is not None and k not in ("direction",)}
            if interesting:
                rows = "".join(
                    f'<div><span class="detail-label">{k}</span>'
                    f'<br><span class="detail-val">{v}</span></div>'
                    for k, v in interesting.items()
                )
                proto_details += (
                    f'<details><summary>{p.protocol} '
                    f'(port {p.port}, {p.packet_count} pkts, '
                    f'confidence: {p.confidence})</summary>'
                    f'<div class="detail-grid" style="margin-top:.5rem">{rows}</div>'
                    f'</details>'
                )

        peers = sorted(dev.communicating_with)[:10]
        peers_str = ", ".join(peers)
        if len(dev.communicating_with) > 10:
            peers_str += f" … (+{len(dev.communicating_with)-10} more)"

        detail_html = f"""<div class="detail-grid">
  <div>
    <div class="detail-label">IP Address</div><div class="detail-val">{dev.ip}</div>
    <br>
    <div class="detail-label">MAC Address</div><div class="detail-val">{mac}</div>
    <br>
    <div class="detail-label">Vendor Confidence</div><div class="detail-val">{dev.vendor_confidence}</div>
    <br>
    <div class="detail-label">Firmware</div><div class="detail-val">{dev.firmware or '—'}</div>
    <br>
    <div class="detail-label">Serial Number</div><div class="detail-val">{dev.serial_number or '—'}</div>
    <br>
    <div class="detail-label">Role</div><div class="detail-val">{dev.role}</div>
    <br>
    <div class="detail-label">Open OT Ports</div><div class="detail-val">{', '.join(str(p) for p in sorted(dev.open_ports)) or '—'}</div>
    <br>
    <div class="detail-label">First / Last Seen</div>
    <div class="detail-val">
      {dev.first_seen.strftime('%H:%M:%S') if dev.first_seen else '—'} /
      {dev.last_seen.strftime('%H:%M:%S') if dev.last_seen else '—'}
    </div>
    <br>
    <div class="detail-label">Communicating With ({len(dev.communicating_with)} peers)</div>
    <div class="detail-val" style="font-size:.78rem">{peers_str or '—'}</div>
  </div>
  <div>
    <div class="detail-label">Protocol Details</div>
    <div style="margin-top:.3rem">{proto_details or '<em>No details extracted</em>'}</div>
    <br>
    <div class="detail-label">Risk Factors</div>
    <div style="margin-top:.3rem">{rf_html}</div>
  </div>
</div>"""

        uid = dev.ip.replace(".", "_")
        return f"""      <tr>
        <td><strong>{dev.ip}</strong></td>
        <td style="font-family:monospace;font-size:.8rem">{mac}</td>
        <td>{make}</td>
        <td>{model}</td>
        <td>{proto_tags}</td>
        <td style="text-align:right">{dev.packet_count:,}</td>
        <td><span class="risk-pill" style="background:{risk_color}">{risk_label}</span></td>
        <td><button onclick="toggleDetail('{uid}')"
            style="background:#1e3a5f;border:none;color:#38bdf8;cursor:pointer;
                   padding:.25rem .6rem;border-radius:4px;font-size:.78rem">▼ expand</button></td>
      </tr>
      <tr id="detail_{uid}" class="detail-row" style="display:none">
        <td colspan="8">{detail_html}</td>
      </tr>"""


# ------------------------------------------------------------------ module helpers

def _risk_summary(devices: List[PLCDevice]) -> dict:
    counts: dict = {}
    for d in devices:
        counts[d.risk_level] = counts.get(d.risk_level, 0) + 1
    return counts


def _protocol_summary(devices: List[PLCDevice]) -> dict:
    counts: dict = {}
    for d in devices:
        for p in d.get_protocol_names():
            counts[p] = counts.get(p, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))
