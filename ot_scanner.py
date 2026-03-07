#!/usr/bin/env python3
"""
OT Security Scanner
======================
A PCAP-based offline security assessment tool for ICS/SCADA/OT networks.

Analyzes packet captures to detect vulnerabilities, misconfigurations,
and attack patterns across industrial protocols.

Supported Protocols:
  Modbus/TCP, Siemens S7comm, DNP3, BACnet/IP, OPC UA,
  EtherNet/IP (CIP), IEC 60870-5-104, PROFINET, MQTT

Compliance Mapping: IEC 62443, NIST SP 800-82, MITRE ATT&CK for ICS

Usage:
    python ot_scanner.py --data-dir ./sample_pcaps --output report.html
    python ot_scanner.py --data-dir ./captures --modules modbus s7 dnp3 --severity HIGH
"""

import argparse, json, sys, datetime
from pathlib import Path

from modules.pcap_parser import load_pcaps
from modules.modbus_analyzer import ModbusAnalyzer
from modules.s7comm_analyzer import S7commAnalyzer
from modules.dnp3_analyzer import Dnp3Analyzer
from modules.bacnet_analyzer import BacnetAnalyzer
from modules.opcua_analyzer import OpcuaAnalyzer
from modules.protocol_analyzers import EthernetIpAnalyzer, Iec104Analyzer, MqttAnalyzer
from modules.network_baseline import ProfinetAnalyzer, NetworkBaselineAnalyzer
from modules.compliance_mitre import Iec62443Analyzer, MitreIcsMapper
from modules.report_generator import ReportGenerator


def banner():
    print(r"""
  ╔══════════════════════════════════════════════════════════════════════╗
  ║   OT Security Scanner v1.0                                         ║
  ║   PCAP-Based ICS/SCADA Security Assessment                         ║
  ║                                                                    ║
  ║   Modbus · S7comm · DNP3 · BACnet · OPC UA · EtherNet/IP          ║
  ║   IEC 104 · PROFINET · MQTT · IEC 62443 · MITRE ATT&CK ICS       ║
  ╚══════════════════════════════════════════════════════════════════════╝
    """)


MODULE_MAP = {
    "modbus":   ("Modbus/TCP Analysis", ModbusAnalyzer, "modbus"),
    "s7":       ("Siemens S7comm Analysis", S7commAnalyzer, "s7comm"),
    "dnp3":     ("DNP3 Analysis", Dnp3Analyzer, "dnp3"),
    "bacnet":   ("BACnet/IP Analysis", BacnetAnalyzer, "bacnet"),
    "opcua":    ("OPC UA Analysis", OpcuaAnalyzer, "opcua"),
    "enip":     ("EtherNet/IP (CIP) Analysis", EthernetIpAnalyzer, "enip"),
    "iec104":   ("IEC 60870-5-104 Analysis", Iec104Analyzer, "iec104"),
    "profinet": ("PROFINET Analysis", ProfinetAnalyzer, "profinet"),
    "mqtt":     ("MQTT Analysis", MqttAnalyzer, "mqtt"),
    "baseline": ("Network Baseline & Asset Discovery", NetworkBaselineAnalyzer, None),
    "iec62443": ("IEC 62443 Compliance", Iec62443Analyzer, None),
    "mitre":    ("MITRE ATT&CK for ICS Mapping", MitreIcsMapper, None),
}


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="OT Security Scanner — PCAP-based ICS/SCADA assessment")
    parser.add_argument("--data-dir", required=True,
        help="Directory containing PCAP/PCAPNG files")
    parser.add_argument("--output", default="ot_security_report.html",
        help="Output HTML report filename")
    parser.add_argument("--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"], default="ALL")
    parser.add_argument("--modules", nargs="+",
        choices=list(MODULE_MAP.keys()) + ["all"], default=["all"],
        help="Which analysis modules to run")
    parser.add_argument("--config", default=None,
        help="Custom baseline config JSON")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"[ERROR] Directory not found: {data_dir}")
        sys.exit(1)

    print("[*] Loading PCAP files...")
    all_packets, protocol_counts = load_pcaps(args.data_dir)
    if not all_packets:
        print("[ERROR] No packets extracted from PCAP files")
        sys.exit(1)

    print(f"\n    Total packets: {len(all_packets)}")
    print(f"    Protocol distribution:")
    for proto, cnt in sorted(protocol_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"      {proto:20s} {cnt:>8,} packets")
    print()

    baseline = {}
    if args.config:
        with open(args.config) as f:
            baseline = json.load(f)
        print(f"[*] Loaded baseline from {args.config}")

    run_modules = list(MODULE_MAP.keys()) if "all" in args.modules else args.modules
    all_findings = []

    for mod_key in run_modules:
        if mod_key not in MODULE_MAP:
            continue
        label, cls, proto_filter = MODULE_MAP[mod_key]
        print(f"[*] Running {label}...")

        if proto_filter:
            filtered = [p for p in all_packets
                       if p.ot_protocol == proto_filter or
                       (proto_filter == "opcua" and p.ot_protocol in ("opcua", "opcua_tls")) or
                       (proto_filter == "mqtt" and p.ot_protocol in ("mqtt", "mqtt_tls"))]
        else:
            filtered = all_packets

        auditor = cls(filtered, all_packets, baseline)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        if findings:
            print(f"    Found {len(findings)} issue(s)")
        else:
            print(f"    No issues (0 relevant packets)")

    # Filter by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if args.severity != "ALL":
        t = sev_order.get(args.severity, 4)
        all_findings = [f for f in all_findings if sev_order.get(f["severity"], 4) <= t]

    scan_meta = {
        "scan_time": datetime.datetime.now().isoformat(),
        "data_directory": str(data_dir),
        "modules_run": run_modules,
        "severity_filter": args.severity,
        "total_packets": len(all_packets),
        "protocol_counts": protocol_counts,
    }

    print(f"\n[*] Generating report: {args.output}")
    ReportGenerator(all_findings, scan_meta).generate(args.output)

    c = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    h = sum(1 for f in all_findings if f["severity"] == "HIGH")
    m = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    l = sum(1 for f in all_findings if f["severity"] == "LOW")

    print(f"\n{'='*70}")
    print(f"  SCAN COMPLETE — {len(all_packets):,} packets analyzed, {len(all_findings)} finding(s)")
    print(f"  CRITICAL: {c}  |  HIGH: {h}  |  MEDIUM: {m}  |  LOW: {l}")
    print(f"  Report: {args.output}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
