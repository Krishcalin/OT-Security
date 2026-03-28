#!/usr/bin/env python3
"""
OT / ICS Passive Network Scanner v2.0
-----------------------------------------------------------------------
Unified passive scanner that identifies industrial OT devices (PLCs, RTUs,
FRTUs, IEDs, HMIs, gateways) and detects security vulnerabilities by
analysing captured network traffic (PCAP / PCAPNG).

No packets are ever sent to the network -- all analysis is offline, making
this safe to run in live OT/ICS environments where active scanning can
trigger protection relays or disrupt SCADA control.

Supported protocols (15):
  IP-layer:
    Modbus/TCP          TCP/502          (multi-vendor)
    S7comm / S7comm+    TCP/102          (Siemens exclusive)
    EtherNet/IP / CIP   TCP/44818        (Rockwell, Omron, Schneider ...)
    DNP3                TCP/UDP 20000    (ABB, GE, Honeywell, Schneider ...)
    Omron FINS          UDP/9600         (Omron exclusive)
    MELSEC MC Protocol  TCP/5006-5008    (Mitsubishi exclusive)
    IEC 60870-5-104     TCP/2404         (ABB, Siemens, Schneider ...)
    IEC 61850 MMS       TCP/102          (Substation automation IEDs)
    SEL Fast Message    TCP/702          (SEL IEDs)
    OPC-UA              TCP/4840-4843    (Cross-vendor, IEC 62541)
    BACnet/IP           UDP/47808        (Building automation)
    MQTT                TCP/1883, 8883   (IIoT messaging)
    PROFINET RT         UDP/34962-34964  (Siemens, multi-vendor)

  Layer-2:
    IEC 61850 GOOSE     EtherType 0x88B8 (Protection signalling)
    IEC 61850 SV        EtherType 0x88BA (Sampled Values / merging units)
    PROFINET DCP        EtherType 0x8892 (Device discovery)
-----------------------------------------------------------------------
"""
import argparse
import os
import sys
from pathlib import Path

__version__ = "2.0.0"

BANNER = r"""
   ____  _____   ____
  / __ \|_   _| / ___|  ___ __ _ _ __  _ __   ___ _ __
 | |  | | | |   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |__| | | |    ___) | (_| (_| | | | | | | |  __/ |
  \____/  |_|   |____/ \___\__,_|_| |_|_| |_|\___|_|
                                                v2.0.0
  Unified OT/ICS Passive Network Scanner
  15 Protocols | Asset Discovery | Vulnerability Detection
"""

VALID_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".pcap5"}

# Severity -> ANSI colour
_ANSI = {
    "critical": "\033[91m",   # bright red
    "high":     "\033[93m",   # bright yellow
    "medium":   "\033[33m",   # yellow
    "low":      "\033[32m",   # green
    "info":     "\033[37m",   # white
    "reset":    "\033[0m",
}


def _col(text: str, level: str) -> str:
    """Wrap text in ANSI colour for severity level (if stdout is a TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"{_ANSI.get(level, '')}{text}{_ANSI['reset']}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ot_scanner.py",
        description=(
            "Passively identify OT/ICS devices and security vulnerabilities "
            "from a captured network traffic file (PCAP/PCAPNG)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
  Full scan, all output formats to a directory:
      python ot_scanner.py substation_traffic.pcap -o reports/ -f all

  HTML report only:
      python ot_scanner.py capture.pcapng --html report.html

  JSON for pipeline integration:
      python ot_scanner.py traffic.pcap --json findings.json

  Verbose mode, minimum 3 packets per device:
      python ot_scanner.py traffic.pcap -v --min-packets 3

  Filter to CRITICAL and HIGH only:
      python ot_scanner.py traffic.pcap --severity high

OUTPUT FILES
  ot_scan_results.json  -- Machine-readable full detail (devices + vulns + flows)
  ot_scan_results.csv   -- Spreadsheet-friendly summary (one row per device)
  ot_scan_results.html  -- Interactive browser report with vulnerability cards

PROTOCOLS
  IP:  Modbus | S7comm | EtherNet/IP | DNP3 | FINS | MELSEC | IEC-104
       IEC 61850 MMS | SEL | OPC-UA | BACnet | MQTT | PROFINET RT
  L2:  GOOSE | Sampled Values | PROFINET DCP

TOPOLOGY
  Automatic Purdue model zone classification and cross-zone violation detection.
  GraphML export for visualization in Gephi, yEd, or Cytoscape.

POLICY EXPORT
  --policy DIR      Generate firewall rules (Palo Alto XML, Fortinet CLI, Cisco ACL, JSON)

SIEM INTEGRATION
  --cef FILE        CEF format for Splunk, ArcSight, Elastic SIEM
  --leef FILE       LEEF format for IBM QRadar

PLATFORM INTEGRATIONS
  --servicenow FILE   ServiceNow CMDB import JSON (CIs + relationships)
  --splunk-hec FILE   Splunk HTTP Event Collector NDJSON events
  --elastic-ecs FILE  Elastic Common Schema NDJSON for Elasticsearch/Kibana
  --webhook FILE      Webhook notification payload JSON (Slack, Teams, PagerDuty)

COMPLIANCE
  --compliance FILE  Generates NERC CIP, IEC 62443, NIST 800-82 assessment report

DELTA ANALYSIS
  --delta FILE      Compare current scan against a baseline JSON to detect changes
        """,
    )

    parser.add_argument(
        "pcap_file",
        metavar="PCAP_FILE",
        help="Path to the .pcap / .pcapng capture file",
    )

    # Individual report files
    parser.add_argument(
        "--json",
        metavar="FILE",
        dest="json_file",
        help="Save JSON report to FILE",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        dest="csv_file",
        help="Save CSV report to FILE",
    )
    parser.add_argument(
        "--html",
        metavar="FILE",
        dest="html_file",
        help="Save HTML report to FILE",
    )
    parser.add_argument(
        "--graphml",
        metavar="FILE",
        dest="graphml_file",
        help="Save network topology as GraphML (for Gephi / yEd / Cytoscape)",
    )
    parser.add_argument(
        "--cve-db",
        metavar="FILE",
        dest="cve_db_file",
        help="Load additional CVE entries from a JSON file (supplements built-in ICS CVE database)",
    )

    # SIEM export
    parser.add_argument(
        "--cef",
        metavar="FILE",
        dest="cef_file",
        help="Export findings as CEF syslog (for Splunk / ArcSight)",
    )
    parser.add_argument(
        "--leef",
        metavar="FILE",
        dest="leef_file",
        help="Export findings as LEEF syslog (for QRadar)",
    )
    parser.add_argument(
        "--stix",
        metavar="FILE",
        dest="stix_file",
        help="Export findings as STIX 2.1 JSON bundle",
    )
    # Integration platform exports
    parser.add_argument(
        "--servicenow",
        metavar="FILE",
        dest="servicenow_file",
        help="Export ServiceNow CMDB import JSON (Configuration Items + relationships)",
    )
    parser.add_argument(
        "--splunk-hec",
        metavar="FILE",
        dest="splunk_hec_file",
        help="Export Splunk HEC-compatible NDJSON events",
    )
    parser.add_argument(
        "--elastic-ecs",
        metavar="FILE",
        dest="elastic_ecs_file",
        help="Export Elastic Common Schema (ECS) NDJSON events",
    )
    parser.add_argument(
        "--webhook",
        metavar="FILE",
        dest="webhook_file",
        help="Export webhook notification payload JSON (for Slack, Teams, PagerDuty)",
    )
    # Compliance
    parser.add_argument(
        "--compliance",
        metavar="FILE",
        dest="compliance_file",
        help="Generate compliance report (NERC CIP + IEC 62443 + NIST 800-82)",
    )
    # Delta analysis
    parser.add_argument(
        "--delta",
        metavar="FILE",
        dest="delta_baseline",
        help="Compare against a baseline JSON scan file (delta analysis)",
    )
    # Configuration snapshots
    parser.add_argument(
        "--snapshot-dir",
        metavar="DIR",
        dest="snapshot_dir",
        help="Directory for persistent configuration snapshots (drift detection)",
    )
    parser.add_argument(
        "--set-baseline",
        action="store_true",
        dest="set_baseline",
        help="Mark current scan as 'last known good' configuration baseline",
    )

    # Directory-based output
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        help="Output directory for reports (auto-names based on pcap filename)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["json", "csv", "html", "all"],
        default="all",
        help="Report format when using -o (default: all)",
    )

    # Filtering
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        help="Filter findings by minimum severity (e.g. --severity high "
             "shows only CRITICAL and HIGH)",
    )

    # Analysis options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print per-packet protocol detections during analysis",
    )
    parser.add_argument(
        "--min-packets",
        type=int,
        default=2,
        metavar="N",
        help="Minimum packet count to include a device (default: 2)",
    )
    parser.add_argument(
        "--project-dir",
        metavar="DIR",
        dest="project_dir",
        help="Directory containing ICS project files "
             "(TIA Portal .zap16/.ap16, Studio 5000 .L5X, EcoStruxure .XEF) "
             "and/or CSV/JSON asset inventory for ground-truth enrichment",
    )
    parser.add_argument(
        "--policy",
        metavar="DIR",
        dest="policy_dir",
        help="Generate firewall policy recommendations to DIR "
             "(creates paloalto/, fortinet/, cisco/, json/ subdirectories)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def check_dependencies() -> None:
    """Verify at least one of scapy / dpkt is available."""
    has_scapy = False
    has_dpkt  = False
    try:
        import scapy          # noqa: F401
        has_scapy = True
    except ImportError:
        pass
    try:
        import dpkt           # noqa: F401
        has_dpkt = True
    except ImportError:
        pass

    if not has_scapy and not has_dpkt:
        print("[ERROR] Neither 'scapy' nor 'dpkt' is installed.")
        print("        Install at least one packet parsing library:")
        print("          pip install scapy")
        print("          pip install dpkt")
        sys.exit(1)

    if has_scapy:
        print("[*] Packet library : scapy")
    else:
        print("[*] Packet library : dpkt  (scapy not available, using fallback)")


def _filter_severity(devices, min_severity: str):
    """
    Remove vulnerability findings below the requested minimum severity.
    Does NOT remove devices -- just filters their vuln lists.
    """
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threshold = order.get(min_severity, 0)
    for dev in devices:
        dev.vulnerabilities = [
            v for v in dev.vulnerabilities
            if order.get(v.severity, 0) >= threshold
        ]


def _print_vuln_summary(devices) -> None:
    """Print a concise vulnerability count table to stdout."""
    total_vulns = sum(len(d.vulnerabilities) for d in devices)
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for d in devices:
        for v in d.vulnerabilities:
            sev = v.severity.lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

    print("\n+---------------------------------------------+")
    print("|            VULNERABILITY SUMMARY             |")
    print("+----------------------+----------------------+")
    print(f"|  Total findings      | {total_vulns:<20} |")
    print("+----------------------+----------------------+")
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt = by_severity[sev]
        label = sev.capitalize()
        coloured = _col(f"{cnt:<20}", sev)
        print(f"|  {label:<20}| {coloured} |")
    print("+----------------------+----------------------+")


def main() -> None:
    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    # ── Input validation ──────────────────────────────────────────────────
    pcap_path = Path(args.pcap_file)

    if not pcap_path.exists():
        print(f"[ERROR] File not found: {pcap_path}")
        sys.exit(1)

    if not pcap_path.is_file():
        print(f"[ERROR] Not a regular file: {pcap_path}")
        sys.exit(1)

    if pcap_path.suffix.lower() not in VALID_EXTENSIONS:
        print(f"[WARN]  Unexpected extension '{pcap_path.suffix}' -- "
              f"expected one of {', '.join(sorted(VALID_EXTENSIONS))}. "
              "Proceeding anyway ...")

    if args.min_packets < 1:
        print("[WARN]  --min-packets must be >= 1; using 1.")
        args.min_packets = 1

    check_dependencies()

    print(f"[*] Input       : {pcap_path.resolve()}")
    if args.verbose:
        print("[*] Verbose     : ON")
    if args.severity:
        print(f"[*] Min severity: {args.severity.upper()}")
    print(f"[*] Min packets : {args.min_packets}")
    print()

    # ── Lazy imports after validation ─────────────────────────────────────
    from scanner.core             import PCAPAnalyzer
    from scanner.report.generator import ReportGenerator

    # ── Analyse ───────────────────────────────────────────────────────────
    analyzer = PCAPAnalyzer(verbose=args.verbose, min_packets=args.min_packets)

    if args.cve_db_file:
        if not Path(args.cve_db_file).exists():
            print(f"[WARN] CVE database file not found: {args.cve_db_file}")
        else:
            analyzer.set_cve_database(args.cve_db_file)
            print(f"[*] External CVE DB: {args.cve_db_file}")

    # ── Project file enrichment ──────────────────────────────────────
    if args.project_dir:
        proj_dir = Path(args.project_dir)
        if not proj_dir.is_dir():
            print(f"[WARN] Project directory not found: {proj_dir}")
        else:
            try:
                from scanner.project_files.engine import ProjectFileEngine
                proj_engine = ProjectFileEngine()
                parsed_count = proj_engine.load_directory(str(proj_dir))
                proj_devices = proj_engine.get_devices()
                if proj_devices:
                    analyzer.set_project_devices(proj_devices)
                    print(f"[*] Project files: {parsed_count} file(s) parsed, "
                          f"{len(proj_devices)} device(s) loaded (ground-truth)")
                else:
                    print(f"[*] Project files: {parsed_count} file(s) parsed, "
                          "no devices with IP addresses found")
                for err in proj_engine.parse_errors[:5]:
                    print(f"    [WARN] {err}")
            except ImportError:
                print("[WARN] Project file module not available")
            except Exception as exc:
                print(f"[WARN] Project file loading failed: {exc}")

    devices, flows, zones, violations, edges = analyzer.analyze(str(pcap_path))

    if not devices:
        print("\n[!] No OT/ICS devices detected in this capture.")
        print("    Hints:")
        print("    - Verify the PCAP contains industrial protocol traffic")
        print("      (Modbus, S7comm, EtherNet/IP, DNP3, FINS, MELSEC, IEC-104,")
        print("       IEC 61850 GOOSE/MMS, SEL, OPC-UA, BACnet, MQTT, PROFINET)")
        print("    - GOOSE/SV require Ethernet frame access -- use a mirrored port / TAP")
        print("    - Try lowering --min-packets if the capture is short")
        sys.exit(0)

    print(f"\n[+] Discovered {len(devices)} OT/ICS device(s)")
    print(f"[+] Recorded {len(flows)} communication flow(s)")
    if zones:
        print(f"[+] Identified {len(zones)} network zone(s) (Purdue model)")
    if violations:
        print(f"[!] Detected {len(violations)} zone segmentation violation(s)")

    total_alerts = sum(len(d.threat_alerts) for d in devices)
    if total_alerts:
        crit_alerts = sum(1 for d in devices for a in d.threat_alerts if a.severity == "critical")
        malware_alerts = sum(1 for d in devices for a in d.threat_alerts if a.alert_type == "malware_signature")
        msg = f"[!] Threat detection: {total_alerts} alert(s)"
        if crit_alerts:
            msg += f" ({crit_alerts} CRITICAL)"
        if malware_alerts:
            msg += f", {malware_alerts} malware signature match(es)"
        print(msg)

    total_ra = sum(len(d.remote_access_sessions) for d in devices)
    if total_ra:
        non_compliant = sum(
            1 for d in devices for s in d.remote_access_sessions
            if s.compliance_status == "non_compliant"
        )
        jump_servers = sum(1 for d in devices if d.role == "jump_server")
        msg = f"[!] Remote access: {total_ra} session(s)"
        if non_compliant:
            msg += f" ({non_compliant} NON-COMPLIANT)"
        if jump_servers:
            msg += f", {jump_servers} jump server(s) identified"
        print(msg)

    # ── Attack path analysis ────────────────────────────────────────────
    try:
        from scanner.attack.engine import AttackPathEngine
        _ap_engine = AttackPathEngine(devices, flows, zones, edges, violations)
        attack_paths = _ap_engine.analyze()
        if attack_paths:
            # Attach paths to target devices
            _dev_map = {d.ip: d for d in devices}
            for ap in attack_paths:
                tgt = _dev_map.get(ap.target_ip)
                if tgt:
                    tgt.attack_paths.append(ap)
            crit_paths = sum(1 for p in attack_paths if p.severity == "critical")
            crown_jewels = len({p.target_ip for p in attack_paths})
            msg = f"[!] Attack paths: {len(attack_paths)} path(s) to {crown_jewels} crown jewel(s)"
            if crit_paths:
                msg += f" ({crit_paths} CRITICAL)"
            print(msg)
    except ImportError:
        pass
    except Exception as exc:
        if args.verbose:
            print(f"  [!] Attack path analysis error: {exc}")

    total_cves = sum(len(d.cve_matches) for d in devices)
    if total_cves:
        now_cves = sum(1 for d in devices for c in d.cve_matches if c.priority == "now")
        print(f"[+] Matched {total_cves} known CVE(s) ({now_cves} require immediate action)")

    total_it = sum(len(d.it_protocols) for d in devices)
    if total_it:
        high_risk_it = sum(1 for d in devices for h in d.it_protocols
                          if h.details.get("risk") == "high")
        print(f"[!] Detected {total_it} IT protocol hit(s) in OT network"
              + (f" ({high_risk_it} HIGH RISK)" if high_risk_it else ""))

    # ── Apply severity filter ────────────────────────────────────────────
    if args.severity:
        _filter_severity(devices, args.severity)

    # ── Console summary ──────────────────────────────────────────────────
    reporter = ReportGenerator(
        devices, flows=flows, zones=zones,
        violations=violations, edges=edges,
        pcap_file=str(pcap_path), version=__version__,
    )
    reporter.print_summary()
    _print_vuln_summary(devices)

    # ── Write reports ────────────────────────────────────────────────────
    written: list = []

    # Individual file arguments
    if args.json_file:
        reporter.to_json(args.json_file)
        written.append(args.json_file)

    if args.csv_file:
        reporter.to_csv(args.csv_file)
        written.append(args.csv_file)

    if args.html_file:
        reporter.to_html(args.html_file)
        written.append(args.html_file)

    if args.graphml_file:
        reporter.to_graphml(args.graphml_file)
        written.append(args.graphml_file)

    if args.cef_file:
        try:
            from scanner.export.siem import SIEMExporter
            SIEMExporter(devices).to_cef(args.cef_file)
            written.append(args.cef_file)
        except ImportError:
            print("[WARN] SIEM export module not available")

    if args.leef_file:
        try:
            from scanner.export.siem import SIEMExporter
            SIEMExporter(devices).to_leef(args.leef_file)
            written.append(args.leef_file)
        except ImportError:
            print("[WARN] SIEM export module not available")

    if args.stix_file:
        try:
            from scanner.export.stix import STIXExporter
            STIXExporter(devices).to_stix_bundle(args.stix_file)
            written.append(args.stix_file)
        except ImportError:
            print("[WARN] STIX export module not available")

    if args.servicenow_file:
        try:
            from scanner.export.servicenow import ServiceNowExporter
            ServiceNowExporter(devices, zones=zones, violations=violations).to_cmdb_json(args.servicenow_file)
            written.append(args.servicenow_file)
        except ImportError:
            print("[WARN] ServiceNow export module not available")

    if args.splunk_hec_file:
        try:
            from scanner.export.splunk import SplunkHECExporter
            SplunkHECExporter(devices, zones=zones, violations=violations).to_hec_json(args.splunk_hec_file)
            written.append(args.splunk_hec_file)
        except ImportError:
            print("[WARN] Splunk HEC export module not available")

    if args.elastic_ecs_file:
        try:
            from scanner.export.elastic import ElasticECSExporter
            ElasticECSExporter(devices, zones=zones, violations=violations).to_ecs_ndjson(args.elastic_ecs_file)
            written.append(args.elastic_ecs_file)
        except ImportError:
            print("[WARN] Elastic ECS export module not available")

    if args.webhook_file:
        try:
            from scanner.export.webhook import WebhookExporter
            WebhookExporter(devices, flows=flows, zones=zones, violations=violations, pcap_file=str(pcap_path)).to_payload_json(args.webhook_file)
            written.append(args.webhook_file)
        except ImportError:
            print("[WARN] Webhook export module not available")

    if args.compliance_file:
        try:
            from scanner.compliance.engine import ComplianceMapper
            mapper = ComplianceMapper(devices, zones=zones, violations=violations)
            results = mapper.assess()
            text = mapper.to_text()
            with open(args.compliance_file, "w", encoding="utf-8") as fh:
                fh.write(text)
            written.append(args.compliance_file)
            # Print summary
            total_checks = sum(len(v) for v in results.values())
            fails = sum(1 for v in results.values() for c in v if c.status == "fail")
            passes = sum(1 for v in results.values() for c in v if c.status == "pass")
            print(f"\n[+] Compliance: {passes} PASS, {fails} FAIL out of {total_checks} controls")
        except ImportError:
            print("[WARN] Compliance module not available")

    # Directory-based output (-o DIR -f FORMAT)
    if args.output:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = pcap_path.stem  # e.g. "substation_traffic"
        prefix = out_dir / f"ot_scan_{stem}"

        if args.format in ("json", "all"):
            out = f"{prefix}.json"
            reporter.to_json(out)
            written.append(out)

        if args.format in ("csv", "all"):
            out = f"{prefix}.csv"
            reporter.to_csv(out)
            written.append(out)

        if args.format in ("html", "all"):
            out = f"{prefix}.html"
            reporter.to_html(out)
            written.append(out)

        if args.format in ("all",):
            out = f"{prefix}.graphml"
            reporter.to_graphml(out)
            written.append(out)

    # If no output flags at all, default to writing all formats in cwd
    if not written and not args.json_file and not args.csv_file and not args.html_file and not args.graphml_file and not args.output:
        prefix = "ot_scan_results"
        reporter.to_json(f"{prefix}.json")
        reporter.to_csv(f"{prefix}.csv")
        reporter.to_html(f"{prefix}.html")
        reporter.to_graphml(f"{prefix}.graphml")
        written = [f"{prefix}.json", f"{prefix}.csv", f"{prefix}.html", f"{prefix}.graphml"]

    if written:
        print("\n[+] Reports written:")
        for w in written:
            print(f"    {Path(w).resolve()}")

    # ── Delta analysis (compare against baseline) ─────────────────────────
    if args.delta_baseline:
        try:
            from scanner.delta.engine import DeltaEngine
            # Find the JSON output we just wrote
            json_path = args.json_file
            if not json_path and args.output:
                json_path = f"{prefix}.json" if args.format in ("json", "all") else None
            if not json_path:
                json_path = "ot_scan_results.json"

            delta = DeltaEngine()
            report = delta.compare(args.delta_baseline, json_path)
            delta_text = report.to_text()
            print(f"\n{delta_text}")

            # Save delta report
            delta_path = json_path.replace(".json", "_delta.txt") if json_path else "ot_delta.txt"
            with open(delta_path, "w", encoding="utf-8") as fh:
                fh.write(delta_text)
            written.append(delta_path)
        except ImportError:
            print("[WARN] Delta analysis module not available")
        except Exception as exc:
            print(f"[WARN] Delta analysis failed: {exc}")

    # ── Policy recommendation engine ──────��─────────────────────────────
    if args.policy_dir:
        try:
            from scanner.policy.engine import PolicyEngine
            from scanner.policy.exporters import export_all_formats

            policy_engine = PolicyEngine(
                devices=devices,
                flows=flows,
                zones=zones,
                violations=violations,
                edges=edges,
                pcap_file=str(pcap_path),
            )
            ruleset = policy_engine.generate()
            policy_files = export_all_formats(ruleset, args.policy_dir)
            written.extend(policy_files)

            print(f"\n[+] Policy recommendations: {ruleset.total_rules} rule(s) "
                  f"across {ruleset.zone_count} zone(s)")
            print(f"    Formats: Palo Alto XML, Fortinet CLI, Cisco ACL, JSON")
            for pf in policy_files:
                print(f"    {Path(pf).resolve()}")
        except ImportError:
            print("[WARN] Policy recommendation module not available")
        except Exception as exc:
            print(f"[WARN] Policy generation failed: {exc}")

    # ── Configuration snapshot & drift detection ────────────────────────
    if args.snapshot_dir:
        try:
            from scanner.config.engine import ConfigSnapshotEngine

            snap_engine = ConfigSnapshotEngine(args.snapshot_dir)
            current_configs = snap_engine.capture(devices)

            # Load previous snapshot for drift comparison
            previous_configs = snap_engine.load_latest()
            if previous_configs:
                drift_by_ip = snap_engine.diff(previous_configs, current_configs)
                total_drift = sum(len(a) for a in drift_by_ip.values())
                if total_drift:
                    crit_drift = sum(
                        1 for alerts in drift_by_ip.values()
                        for a in alerts if a.severity == "critical"
                    )
                    # Attach to devices
                    for dev in devices:
                        dev.config_drift_alerts = drift_by_ip.get(dev.ip, [])
                    print(f"\n[!] Config drift: {total_drift} change(s) detected"
                          + (f" ({crit_drift} CRITICAL)" if crit_drift else ""))
                else:
                    print("\n[+] Config drift: no changes from previous snapshot")
            else:
                print("\n[+] Config snapshot: first scan (no baseline for comparison)")

            # Save current snapshot
            snap_path = snap_engine.save_snapshot(current_configs, str(pcap_path))
            written.append(snap_path)

            # Set as baseline if requested
            if args.set_baseline:
                snap_engine.set_baseline(snap_path)
                print(f"[+] Baseline set: {snap_path}")

        except ImportError:
            print("[WARN] Configuration snapshot module not available")
        except Exception as exc:
            print(f"[WARN] Configuration snapshot failed: {exc}")

    # ── Exit advisory ────────────────────────────────────────────────────
    all_vulns = [v for d in devices for v in d.vulnerabilities]
    crit_vulns = sum(1 for v in all_vulns if v.severity == "critical")
    high_vulns = sum(1 for v in all_vulns if v.severity == "high")
    crit_devs  = sum(1 for d in devices if d.risk_level == "critical")
    high_devs  = sum(1 for d in devices if d.risk_level == "high")

    if crit_vulns or high_vulns or crit_devs or high_devs:
        print()
        print(_col(
            f"[!] ACTION REQUIRED: {crit_devs} critical + {high_devs} "
            f"high-risk device(s), {crit_vulns} critical + {high_vulns} "
            "high-severity vulnerability findings.",
            "critical" if crit_vulns or crit_devs else "high",
        ))
        now_cve_count = sum(1 for d in devices for c in d.cve_matches if c.priority == "now")
        if now_cve_count:
            print(_col(
                f"    {now_cve_count} CVE(s) with NOW priority (known exploit, "
                "device reachable). Patch or mitigate immediately.",
                "critical",
            ))
        print("    Recommended immediate actions:")
        print("    1. Enable protocol authentication (DNP3 SAv5/SAv6, IEC 62351-5)")
        print("    2. Deploy TLS for IEC-104 (IEC 62351-3) and MMS (IEC 62351-4)")
        print("    3. Implement IEC 62351-6 authentication for GOOSE messages")
        print("    4. Segment OT networks -- restrict master station access (NERC CIP-005)")
        print("    5. Review the HTML report for device-specific remediation steps")
        # Exit code 1 for CI/CD pipeline gating
        sys.exit(1)
    else:
        print("\n[+] Scan complete. Open the HTML report for detailed findings.")
        sys.exit(0)


if __name__ == "__main__":
    main()
