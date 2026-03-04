#!/usr/bin/env python3
"""
PLC Passive Scanner v1.0
─────────────────────────────────────────────────────────────────────────────
Passively identifies industrial Programmable Logic Controllers (PLCs) and
related OT devices by analysing a PCAP / PCAPNG capture file.

No packets are ever sent to the network — all analysis is offline, making
this safe to use in live OT environments where active scanning can disrupt
production processes.

Supported vendors:
  Siemens | Rockwell Automation / Allen-Bradley | Schneider Electric |
  Mitsubishi Electric | Omron | ABB | Honeywell | GE Automation | Yokogawa

Supported protocols:
  Modbus/TCP          TCP/502      (multi-vendor)
  S7comm / S7comm+    TCP/102      (Siemens exclusive)
  EtherNet/IP / CIP   TCP/44818    (Rockwell, Omron, Schneider, Siemens …)
  DNP3                TCP/20000    (ABB, Honeywell, Schneider …)
  Omron FINS          UDP/9600     (Omron exclusive)
  MELSEC MC Protocol  TCP/5007     (Mitsubishi exclusive)
  IEC 60870-5-104     TCP/2404     (ABB, Siemens, Schneider …)
─────────────────────────────────────────────────────────────────────────────
"""
import argparse
import sys
from pathlib import Path

BANNER = r"""
  ____  _     ____   ____                           ____
 |  _ \| |   / ___| |  _ \ __ _ ___ ___(_) __   __|  _ \  ___  ___ _ __
 | |_) | |  | |     | |_) / _` / __/ __| \ \ \ / /| |_) |/ _ \/ __| '_ \
 |  __/| |__| |___  |  __/ (_| \__ \__ \ | |\ V / |  __/|  __/ (__| |_) |
 |_|   |_____\____| |_|   \__,_|___/___/_|_| \_/  |_|    \___|\___| .__/
                                                                     |_|
  Passive PLC & OT Device Scanner  |  Offline PCAP Analysis  |  v1.0
"""

VALID_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".pcap5"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="plc_scanner.py",
        description="Identify industrial PLCs from captured network traffic (PCAP).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES
  Basic scan (all output formats):
      python plc_scanner.py factory_traffic.pcap

  HTML report only, custom output name:
      python plc_scanner.py substation.pcapng -f html -o sub_report

  Verbose mode, minimum 5 packets per device:
      python plc_scanner.py capture.pcap -v --min-packets 5

  JSON only (useful for pipeline integration):
      python plc_scanner.py traffic.pcap -f json -o results

OUTPUT
  plc_scan_results.json  — Machine-readable full detail
  plc_scan_results.csv   — Spreadsheet-friendly summary
  plc_scan_results.html  — Interactive browser report

DETECTION NOTES
  - Devices are identified by protocol traffic, MAC OUI, and embedded
    device-identification strings (e.g. Modbus MEI, CIP ListIdentity).
  - S7comm traffic is Siemens-exclusive; FINS is Omron-exclusive;
    MELSEC is Mitsubishi-exclusive.
  - EtherNet/IP ListIdentity responses expose vendor ID, product name,
    firmware revision, and serial number.
  - Detection confidence: high = multiple corroborating signals;
    medium = single-source; low = port/heuristic only.
        """,
    )

    parser.add_argument(
        "pcap_file",
        metavar="PCAP_FILE",
        help="Path to the .pcap / .pcapng file to analyse",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="PREFIX",
        default="plc_scan_results",
        help="Output filename prefix  (default: plc_scan_results)",
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
        help="Minimum packet count to include a device in results  (default: 1)",
    )
    return parser


def check_dependencies() -> None:
    """Warn if neither scapy nor dpkt is installed."""
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
        print("        Install one of them first:")
        print("          pip install scapy")
        print("          pip install dpkt")
        sys.exit(1)

    if has_scapy:
        print("[*] Packet library: scapy")
    else:
        print("[*] Packet library: dpkt  (scapy not found, using fallback)")


def main() -> None:
    print(BANNER)
    parser  = build_parser()
    args    = parser.parse_args()

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
              f"expected one of {', '.join(VALID_EXTENSIONS)}.  Proceeding anyway …")

    if args.min_packets < 1:
        print("[WARN]  --min-packets must be >= 1; using 1.")
        args.min_packets = 1

    check_dependencies()

    print(f"[*] Input  : {pcap_path.resolve()}")
    print(f"[*] Output : {args.output}.*")
    print(f"[*] Format : {args.format}")
    if args.verbose:
        print("[*] Verbose mode ON")
    print()

    # ── Lazy imports after validation ─────────────────────────────────────
    from scanner.core            import PCAPAnalyzer
    from scanner.report.generator import ReportGenerator

    # ── Analyse ───────────────────────────────────────────────────────────
    analyzer = PCAPAnalyzer(verbose=args.verbose, min_packets=args.min_packets)
    devices  = analyzer.analyze(str(pcap_path))

    if not devices:
        print("\n[!] No industrial PLC devices detected.")
        print("    Hints:")
        print("    • Ensure the PCAP contains OT protocol traffic")
        print("      (Modbus, S7comm, EtherNet/IP, DNP3, FINS, MELSEC, IEC-104)")
        print("    • Try lowering --min-packets if the capture is short")
        sys.exit(0)

    print(f"\n[+] Discovered {len(devices)} industrial device(s)\n")

    # ── Report ────────────────────────────────────────────────────────────
    reporter = ReportGenerator(devices, scan_file=str(pcap_path))
    reporter.print_summary()

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

    # ── Exit summary ──────────────────────────────────────────────────────
    critical = sum(1 for d in devices if d.risk_level == "critical")
    high     = sum(1 for d in devices if d.risk_level == "high")
    if critical or high:
        print(f"\n[!] ACTION REQUIRED: {critical} critical + {high} high-risk device(s) found.")
        print("    Review the HTML report and apply appropriate network segmentation,")
        print("    access controls, and protocol-level mitigations.")
    else:
        print("\n[+] Scan complete.")


if __name__ == "__main__":
    main()
