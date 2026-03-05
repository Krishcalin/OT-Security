#!/usr/bin/env python3
"""
RTU / FRTU Passive Vulnerability Scanner v1.0
─────────────────────────────────────────────────────────────────────────────
Passively identifies RTUs (Remote Terminal Units) and FRTUs (Feeder RTUs),
detects security vulnerabilities and misconfigurations by analysing captured
network traffic (PCAP / PCAPNG).

No packets are ever sent to the network — all analysis is offline, making
this safe to run in live OT/ICS environments where active scanning can
trigger protection relays or disrupt SCADA control.

Supported protocols:
  DNP3                TCP/UDP 20000    (ABB, GE, Honeywell, Schneider …)
  IEC 60870-5-104     TCP/2404         (ABB, Siemens, Schneider, GE …)
  IEC 61850 MMS       TCP/102          (Substation automation IEDs)
  IEC 61850 GOOSE     EtherType 0x88B8 (Layer-2 protection signalling)
  IEC 61850 SV        EtherType 0x88BA (Sampled Values / merging units)
  Modbus/TCP          TCP/502          (Legacy / gateway devices)
  SEL Fast Message    TCP/702          (SEL IEDs)
  Omron FINS          UDP/9600         (Omron RTUs)
  MELSEC MC Protocol  TCP/5006-5007    (Mitsubishi RTUs)

Vulnerability categories detected:
  • Authentication — DNP3 Secure Authentication (SAv5/SAv6), IEC 62351-5
  • Encryption     — IEC 62351-3 (TLS for IEC-104), IEC 62351-4 (TLS/MMS)
  • GOOSE Security — IEC 62351-6, simulation flag, low TTL, confRev changes
  • Command Safety — Direct Operate (SBO bypass), unauthenticated commands
  • Configuration  — Multiple masters, excessive peers, cleartext protocols
─────────────────────────────────────────────────────────────────────────────
"""
import argparse
import sys
from pathlib import Path

BANNER = r"""
  ____  _____ _   _   ____
 |  _ \|_   _| | | | / ___|  ___ __ _ _ __  _ __   ___ _ __
 | |_) | | | | | | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  _ <  | | | |_| |  ___) | (_| (_| | | | | | | |  __/ |
 |_| \_\ |_|  \___/  |____/ \___\__,_|_| |_|_| |_|\___|_|

  RTU / FRTU Passive Vulnerability & Misconfiguration Scanner
  Offline PCAP Analysis  |  No Packets Sent  |  v1.0
  ─────────────────────────────────────────────────────────────
  Protocols: DNP3 · IEC-104 · IEC 61850 MMS/GOOSE/SV
             Modbus · SEL · FINS · MELSEC
"""

VALID_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".pcap5"}

# Severity → ANSI colour
_ANSI = {
    "critical": "\033[91m",   # bright red
    "high":     "\033[31m",   # red
    "medium":   "\033[33m",   # yellow
    "low":      "\033[36m",   # cyan
    "info":     "\033[37m",   # white
    "reset":    "\033[0m",
}


def _col(text: str, level: str) -> str:
    """Wrap *text* in ANSI colour for *level* (if stdout is a TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"{_ANSI.get(level, '')}{text}{_ANSI['reset']}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rtu_scanner.py",
        description=(
            "Passively detect RTU/FRTU devices and security vulnerabilities "
            "from a captured network traffic file (PCAP/PCAPNG)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
  Full scan, all output formats:
      python rtu_scanner.py substation_traffic.pcap

  HTML report only, custom filename prefix:
      python rtu_scanner.py capture.pcapng -f html -o rtu_report

  Verbose mode — print every protocol detection:
      python rtu_scanner.py traffic.pcap -v

  Require at least 3 packets before reporting a device:
      python rtu_scanner.py traffic.pcap --min-packets 3

  JSON output for pipeline integration:
      python rtu_scanner.py traffic.pcap -f json -o findings

OUTPUT FILES
  rtu_scan_results.json  — Machine-readable full detail (devices + vulns)
  rtu_scan_results.csv   — Spreadsheet-friendly summary (one row per device)
  rtu_scan_results.html  — Interactive browser report with vulnerability cards

VULNERABILITY IDs
  RTU-DNP3-001   No DNP3 Secure Authentication (SAv5/SAv6)
  RTU-DNP3-002   Unauthenticated Control Commands (DNP3)
  RTU-DNP3-003   Direct Operate bypasses Select-Before-Operate
  RTU-DNP3-004   Unauthenticated Restart / Maintenance Commands
  RTU-DNP3-005   Unauthenticated File Transfer (firmware injection risk)
  RTU-DNP3-006   Multiple DNP3 Masters (unauthorised access risk)
  RTU-DNP3-007   DNP3 over UDP (replay / injection risk)
  RTU-104-001    IEC-104 without TLS (IEC 62351-3 violation)
  RTU-104-002    Multiple IEC-104 Masters
  RTU-104-003    Cleartext Control Commands (IEC-104)
  RTU-104-004    Unauthenticated Clock Synchronisation
  RTU-104-005    Excessive General Interrogation Requests
  RTU-61850-001  GOOSE without IEC 62351-6 Authentication
  RTU-61850-002  GOOSE Simulation Flag in Live Traffic
  RTU-61850-003  GOOSE Low timeAllowedToLive (replay / DoS risk)
  RTU-61850-004  GOOSE confRev Changes Detected
  RTU-61850-006  MMS without TLS (IEC 62351-4 violation)
  RTU-GEN-001    Unencrypted Industrial Protocols Exposed
  RTU-GEN-002    Excessive Protocol Exposure
  RTU-GEN-003    Industrial Ports Detected — Protocol Unidentified
  RTU-GEN-004    Excessive Communication Peers

REFERENCES
  IEC 62351 (parts 3–6)   — OT security standards
  NERC CIP-005, CIP-007   — Cyber security for electric systems
  IEC 62443-3-3            — Security level requirements
  NIST SP 800-82 Rev. 3   — Guide to ICS security
        """,
    )

    parser.add_argument(
        "pcap_file",
        metavar="PCAP_FILE",
        help="Path to the .pcap / .pcapng capture file",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="PREFIX",
        default="rtu_scan_results",
        help="Output filename prefix  (default: rtu_scan_results)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["json", "csv", "html", "all"],
        default="all",
        help="Report format  (default: all)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print per-packet protocol detections during analysis",
    )
    parser.add_argument(
        "--min-packets",
        type=int,
        default=1,
        metavar="N",
        help="Minimum packet count to include a device  (default: 1)",
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


def _print_vuln_summary(devices) -> None:
    """Print a concise vulnerability count table to stdout."""
    total_vulns   = sum(len(d.vulnerabilities) for d in devices)
    by_severity   = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for d in devices:
        for v in d.vulnerabilities:
            sev = v.severity.lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

    print("\n┌─────────────────────────────────────────┐")
    print("│          VULNERABILITY SUMMARY          │")
    print("├─────────────────────┬───────────────────┤")
    print(f"│  Total findings     │ {total_vulns:<17} │")
    print("├─────────────────────┼───────────────────┤")
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt  = by_severity[sev]
        label = sev.capitalize()
        coloured = _col(f"{cnt:<17}", sev)
        print(f"│  {label:<19}│ {coloured} │")
    print("└─────────────────────┴───────────────────┘")


def _risk_label(level: str) -> str:
    return _col(level.upper(), level)


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
        print(f"[WARN]  Unexpected extension '{pcap_path.suffix}' — "
              f"expected one of {', '.join(sorted(VALID_EXTENSIONS))}. "
              "Proceeding anyway …")

    if args.min_packets < 1:
        print("[WARN]  --min-packets must be >= 1; using 1.")
        args.min_packets = 1

    check_dependencies()

    print(f"[*] Input  : {pcap_path.resolve()}")
    print(f"[*] Output : {args.output}.*")
    print(f"[*] Format : {args.format}")
    if args.verbose:
        print("[*] Verbose: ON")
    print()

    # ── Lazy imports after validation ─────────────────────────────────────
    from scanner.core             import PCAPAnalyzer
    from scanner.report.generator import ReportGenerator

    # ── Analyse ───────────────────────────────────────────────────────────
    analyzer = PCAPAnalyzer(verbose=args.verbose, min_packets=args.min_packets)
    devices  = analyzer.analyze(str(pcap_path))

    if not devices:
        print("\n[!] No RTU/FRTU devices detected in this capture.")
        print("    Hints:")
        print("    • Verify the PCAP contains OT protocol traffic")
        print("      (DNP3, IEC-104, IEC 61850 GOOSE/MMS, Modbus, SEL, FINS, MELSEC)")
        print("    • GOOSE requires Ethernet frame access — use a mirrored port / TAP")
        print("    • Try lowering --min-packets if the capture is short")
        sys.exit(0)

    print(f"[+] Discovered {len(devices)} RTU/FRTU device(s)")

    # ── Inline console summary ─────────────────────────────────────────────
    from scanner.report.generator import ReportGenerator
    reporter = ReportGenerator(devices, scan_file=str(pcap_path))
    reporter.print_summary()

    _print_vuln_summary(devices)

    # ── Risk-level overview ────────────────────────────────────────────────
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for d in devices:
        risk_counts[d.risk_level] = risk_counts.get(d.risk_level, 0) + 1

    print("\n[*] Device risk distribution:")
    for level in ("critical", "high", "medium", "low", "info"):
        cnt = risk_counts[level]
        if cnt:
            print(f"    {_risk_label(level):<30} {cnt} device(s)")

    # ── Write reports ─────────────────────────────────────────────────────
    written: list = []

    if args.format in ("json", "all"):
        out = f"{args.output}.json"
        reporter.to_json(out)
        written.append(out)

    if args.format in ("csv", "all"):
        out = f"{args.output}.csv"
        reporter.to_csv(out)
        written.append(out)

    if args.format in ("html", "all"):
        out = f"{args.output}.html"
        reporter.to_html(out)
        written.append(out)

    print("\n[+] Reports written:")
    for w in written:
        print(f"    {Path(w).resolve()}")

    # ── Exit advisory ─────────────────────────────────────────────────────
    critical_devs = risk_counts.get("critical", 0)
    high_devs     = risk_counts.get("high", 0)

    if critical_devs or high_devs:
        print()
        print(_col(
            f"[!] ACTION REQUIRED: {critical_devs} critical + {high_devs} "
            "high-risk device(s) detected.",
            "critical" if critical_devs else "high",
        ))
        print("    Recommended immediate actions:")
        print("    1. Enable DNP3 Secure Authentication (SAv5/SAv6) — RFC 7870")
        print("    2. Deploy IEC 62351-3 (TLS) for IEC-104 sessions")
        print("    3. Implement IEC 62351-6 authentication for GOOSE messages")
        print("    4. Segment RTU networks — restrict master station access")
        print("    5. Review the HTML report for device-specific remediation steps")
    else:
        print("\n[+] Scan complete. Open the HTML report for detailed findings.")


if __name__ == "__main__":
    main()
