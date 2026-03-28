<p align="center">
  <img src="banner.svg" alt="OT / ICS Passive Network Scanner" width="100%">
</p>

<p align="center">
  <strong>Purely passive, offline security scanners for Operational Technology &amp; Industrial Control Systems</strong><br>
  <sub>Asset discovery · Vulnerability detection · Purdue zone mapping · Compliance assessment · SIEM integration</sub>
</p>

<p align="center">
  <a href="#unified-ot-scanner-v20"><img src="https://img.shields.io/badge/version-2.0.0-22c55e?style=flat-square" alt="Version"></a>
  <a href="#supported-protocols"><img src="https://img.shields.io/badge/protocols-16-3b82f6?style=flat-square" alt="Protocols"></a>
  <a href="#vulnerability-detection"><img src="https://img.shields.io/badge/vuln%20rules-34-f97316?style=flat-square" alt="Rules"></a>
  <a href="#ics-cve-database"><img src="https://img.shields.io/badge/ICS%20CVEs-76-ef4444?style=flat-square" alt="CVEs"></a>
  <a href="#compliance-assessment"><img src="https://img.shields.io/badge/compliance-35%20controls-8b5cf6?style=flat-square" alt="Compliance"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-6c7086?style=flat-square" alt="License"></a>
</p>

---

## Overview

A collection of **purely passive** OT/ICS security scanners that analyse captured network traffic (PCAP / PCAPNG) to discover industrial devices, detect vulnerabilities, map network topology to the Purdue model, and assess compliance against ICS security frameworks. **No packets are ever sent to the network** -- all analysis is offline, making these tools safe for use in live production environments where active scanning can trip protection relays or disrupt SCADA control loops.

The project includes a **unified scanner** (v2.0) that merges and extends two earlier single-purpose scanners, adding CVE matching, topology analysis, compliance mapping, SIEM export, and delta baselining. All scanners require only Python 3.8+ and standard packet-parsing libraries (scapy or dpkt).

## Scanners

| Scanner | Directory | Version | Lines | Description |
|---------|-----------|---------|------:|-------------|
| **Unified OT Scanner** | [`ot_scanner/`](ot_scanner/) | 2.0.0 | ~15,900 | Full-featured scanner: 16 protocols, 34 vuln rules, 76 CVEs, Purdue zones, compliance, SIEM export |
| **PLC Passive Scanner** | [`plc_passive_scanner/`](plc_passive_scanner/) | 1.0 | ~1,500 | Device identification scanner for PLCs (7 protocols, vendor fingerprinting) |
| **RTU Passive Scanner** | [`rtu_passive_scanner/`](rtu_passive_scanner/) | 1.0 | ~2,500 | Vulnerability scanner for RTUs/IEDs (21 vuln rules, GOOSE/MMS) |

---

## Unified OT Scanner v2.0

The unified scanner merges the PLC and RTU scanner cores into a single modular engine that handles all 16 industrial protocols (13 IP-layer + 3 Layer-2), adds four new protocol analyzers (OPC-UA, BACnet/IP, MQTT, PROFINET), a curated ICS CVE database with Now/Next/Never prioritisation, automatic Purdue model topology mapping, compliance assessment across three frameworks, SIEM export in four formats, and delta analysis for change detection between scans.

### Quick Start

```bash
cd ot_scanner
pip install -r requirements.txt
python ot_scanner.py capture.pcap -o reports/ -f all
```

### Supported Protocols

**13 IP-layer protocols + 3 Layer-2 protocols**, plus detection of 30+ IT/enterprise protocols for convergence risk assessment.

| Protocol | Transport | Port / EtherType | Vendor Coverage |
|----------|-----------|------------------|-----------------|
| Modbus/TCP | TCP | 502 | Multi-vendor (Schneider, Rockwell, ABB, Siemens, ...) |
| Siemens S7comm / S7comm+ | TCP | 102 | Siemens-exclusive (S7-300/400/1200/1500) |
| EtherNet/IP / CIP | TCP / UDP | 44818 / 2222 | Rockwell, Omron, Schneider, Siemens |
| DNP3 | TCP / UDP | 20000 | ABB, GE, Honeywell, Schneider, SEL |
| Omron FINS | UDP | 9600 | Omron-exclusive |
| MELSEC MC Protocol | TCP | 5006-5008 | Mitsubishi-exclusive |
| IEC 60870-5-104 | TCP | 2404 | ABB, Siemens, Schneider, GE |
| IEC 61850 MMS | TCP | 102 | ABB, Siemens, GE, Schneider |
| SEL Fast Message | TCP | 702 | SEL-exclusive |
| OPC-UA | TCP | 4840 / 4843 | Cross-vendor (IEC 62541) |
| BACnet/IP | UDP | 47808 | Building automation |
| MQTT | TCP | 1883 / 8883 | IIoT messaging |
| PROFINET RT | UDP | 34962-34964 | Siemens, multi-vendor |
| IEC 61850 GOOSE | Ethernet | 0x88B8 | Protection signalling (L2) |
| IEC 61850 SV | Ethernet | 0x88BA | Sampled Values / merging units (L2) |
| PROFINET DCP | Ethernet | 0x8892 | Device discovery (L2) |

**IT protocol detection** (30+ protocols): HTTP/S, SSH, Telnet, RDP, VNC, TeamViewer, SMB, FTP, TFTP, DNS, DHCP, NTP, SNMP, Syslog, MSSQL, MySQL, PostgreSQL, Oracle, Redis, SMTP, POP3, IMAP, AMQP, and more -- flagged as IT/OT convergence risks when observed inside OT network segments.

### Vulnerability Detection

The scanner detects security issues through three complementary mechanisms: **behavioral vulnerability rules** that analyse protocol session state, **zone violation rules** that enforce Purdue model segmentation, and **IT/OT convergence rules** that flag enterprise protocols in control zones.

**34 behavioral vulnerability rules** across 4 protocol-specific check modules:

| Category | Rules | Vuln ID Prefix | Examples |
|----------|------:|----------------|----------|
| DNP3 Security | 7 | `RTU-DNP3-*` | No Secure Authentication (SAv5/SAv6), unauthenticated control, Direct Operate bypass, restart commands, file transfer, multiple masters, UDP transport |
| IEC 60870-5-104 Security | 5 | `RTU-104-*` | No TLS (IEC 62351-3), multiple masters, unauthenticated commands, clock sync abuse, general interrogation flooding |
| IEC 61850 Security | 6 | `RTU-61850-*` | GOOSE without IEC 62351-6, simulation flag abuse, low TTL replay window, confRev drift, MMS without TLS |
| General / Cross-Protocol | 12 | `OT-GEN-*`, `OT-OPCUA-*`, `OT-MQTT-*` | Cleartext protocols, excessive protocol exposure, OPC-UA without security policy, MQTT without TLS/auth |
| IT/OT Convergence | 5 | `OT-ITOT-*` | Remote access in OT (RDP/VNC), databases in control zone, Telnet, file sharing (SMB), excessive IT protocols |

**5 zone violation rules** (Purdue model enforcement):

| Rule | Severity | Description |
|------|----------|-------------|
| ZV-001 | High | Direct Level 1 to Level 3+ communication (bypassing supervisory layer) |
| ZV-002 | Critical | Control protocol crossing 2+ Purdue levels |
| ZV-003 | Medium | IT protocol in OT zone (Level 0-1) |
| ZV-004 | High | Outbound OT protocol from control zone toward Level 3+ |
| ZV-005 | Medium | Excessive cross-zone peers for Level 0-1 device |

### ICS CVE Database

**76 curated CVEs** across 11 vendor groups, each mapped to product patterns and firmware version ranges for automatic matching against discovered devices.

| Vendor | CVEs | Key Products |
|--------|-----:|-------------|
| Siemens | 15 | S7-1200, S7-1500, SIPROTEC, SICAM |
| Rockwell Automation | 10 | ControlLogix, CompactLogix, MicroLogix |
| Schneider Electric | 10 | Modicon M340/M580, EcoStruxure, SCADAPack |
| ABB | 8 | RTU560, RTU500, REF615, REL670 |
| GE / GE Grid Solutions | 6 | D20MX, UR-series, Mark VIe |
| SEL (Schweitzer) | 5 | SEL-3505, SEL-651R, SEL-421 |
| Omron | 5 | CJ-series, NJ-series, CP-series |
| Mitsubishi Electric | 5 | MELSEC iQ-R, GX Works |
| Honeywell | 4 | RTU2020, Experion PKS |
| Yokogawa | 3 | CENTUM VP, ProSafe-RS |
| Cross-vendor / Protocol | 5 | DNP3 SA bypass, Modbus/TCP, OPC-UA |

Each matched CVE is assigned a **Now / Next / Never priority** (inspired by Dragos) based on whether a public exploit exists and the device's network reachability. External CVE databases can be loaded via `--cve-db` to supplement the built-in entries.

### Network Topology (Purdue Model)

The topology engine performs automatic analysis of the OT network structure:

1. **Subnet inference** -- groups devices into /24 zones from observed IPs
2. **Purdue level assignment** -- classifies zones as Level 0 (Process) through Level 3+ (Operations/DMZ) using device roles, protocol heuristics, and master-station relationships
3. **Edge aggregation** -- builds a directed graph of all communication flows with control/cross-zone annotations
4. **Zone violation detection** -- flags segmentation breaches against IEC 62443-3-3 SR 5.1 and NERC CIP-005
5. **GraphML export** -- produces graph files for visualization in Gephi, yEd, or Cytoscape, with Purdue-level colour coding and cross-zone edge highlighting

The HTML report includes an interactive D3.js network topology visualization with device-level detail on hover.

### Compliance Assessment

**35 controls** mapped across 3 ICS/OT compliance frameworks, automatically evaluated against scan findings:

| Framework | Controls | Coverage |
|-----------|----------|----------|
| NERC CIP (v5-7) | 15 | CIP-002 R1, CIP-003 R4, CIP-005 R1/R1.5/R2/R2.4, CIP-007 R1/R2/R3/R4/R5, CIP-010 R1/R2, CIP-011 R1, CIP-013 R1 |
| IEC 62443-3-3 | 12 | SR 1.1, SR 1.13, SR 2.8, SR 3.1, SR 3.5, SR 4.1, SR 4.3, SR 5.1, SR 5.2, SR 7.1, SR 7.6, SR 7.7 |
| NIST SP 800-82 Rev 3 | 8 | Sections 5.1, 6.2.1, 6.2.5, 6.2.7, 6.2.8, 6.2.9, 6.3.3, 6.3.4 |

Each control is evaluated as **PASS**, **FAIL**, **WARNING**, or **N/A** based on the presence of related vulnerability findings, CVE matches, and zone violations. The compliance report includes per-control findings, recommendations, and linked vuln IDs.

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| JSON | `--json FILE` | Machine-readable full detail (devices, vulns, flows, CVEs, topology) |
| CSV | `--csv FILE` | Spreadsheet-friendly summary (one row per device) |
| HTML | `--html FILE` | Interactive browser report with vulnerability cards and topology graph |
| GraphML | `--graphml FILE` | Network topology for Gephi / yEd / Cytoscape |
| CEF | `--cef FILE` | Common Event Format syslog (Splunk, ArcSight, Elastic SIEM) |
| LEEF | `--leef FILE` | Log Event Extended Format syslog (IBM QRadar) |
| STIX 2.1 | `--stix FILE` | Threat intelligence bundle (ISACs, TAXII feeds) |
| Compliance | `--compliance FILE` | NERC CIP + IEC 62443 + NIST 800-82 assessment report |
| Delta | `--delta FILE` | Change detection against a baseline JSON scan |
| Console | *(default)* | Coloured summary with severity counts and action items |

### CLI Reference

```
usage: ot_scanner.py [-h] [--json FILE] [--csv FILE] [--html FILE]
                     [--graphml FILE] [--cve-db FILE] [--cef FILE]
                     [--leef FILE] [--stix FILE] [--compliance FILE]
                     [--delta FILE] [-o DIR] [-f {json,csv,html,all}]
                     [--severity {critical,high,medium,low}]
                     [-v] [--min-packets N] [--version]
                     PCAP_FILE
```

**Examples:**

```bash
# Full scan with all outputs to a directory
python ot_scanner.py capture.pcap -o reports/ -f all

# HTML report only
python ot_scanner.py capture.pcap --html report.html

# JSON for pipeline integration
python ot_scanner.py capture.pcap --json findings.json

# SIEM integration (Splunk / ArcSight)
python ot_scanner.py capture.pcap --cef findings.cef

# SIEM integration (IBM QRadar)
python ot_scanner.py capture.pcap --leef findings.leef

# Threat intelligence sharing (STIX 2.1)
python ot_scanner.py capture.pcap --stix bundle.json

# Compliance audit
python ot_scanner.py capture.pcap --compliance audit.txt

# External CVE database
python ot_scanner.py capture.pcap --cve-db custom_cves.json

# Delta analysis (compare against baseline)
python ot_scanner.py capture.pcap --delta baseline.json --json current.json

# Topology export for Gephi
python ot_scanner.py capture.pcap --graphml topology.graphml

# Verbose mode, filter high+ severity
python ot_scanner.py capture.pcap -v --severity high
```

**Exit codes:** `1` if CRITICAL or HIGH findings detected (for CI/CD pipeline gating), `0` otherwise.

### Architecture

```
ot_scanner/
├── ot_scanner.py                 CLI entry point + argument parsing
├── requirements.txt              scapy, dpkt, colorama
└── scanner/
    ├── core.py                   Unified PCAP analysis engine (scapy + dpkt readers)
    ├── models.py                 14 data types (OTDevice, VulnerabilityFinding, CommFlow, ...)
    ├── protocols/
    │   ├── base.py               BaseProtocolAnalyzer interface
    │   ├── modbus.py             Modbus/TCP analyzer (FC parsing, MEI identification)
    │   ├── s7comm.py             Siemens S7comm / S7comm+ analyzer
    │   ├── enip.py               EtherNet/IP / CIP analyzer
    │   ├── dnp3.py               DNP3 stateful analyzer (SA tracking, control commands)
    │   ├── fins.py               Omron FINS analyzer
    │   ├── melsec.py             Mitsubishi MELSEC MC analyzer (3E/4E frames)
    │   ├── iec104.py             IEC 60870-5-104 stateful analyzer
    │   ├── iec61850_mms.py       IEC 61850 MMS analyzer (ASN.1 BER, logical nodes)
    │   ├── sel_protocol.py       SEL Fast Message analyzer
    │   ├── opcua.py              OPC-UA Binary / TLS analyzer
    │   ├── bacnet.py             BACnet/IP analyzer
    │   ├── mqtt.py               MQTT v3.1.1 / v5.0 analyzer
    │   ├── profinet.py           PROFINET RT analyzer
    │   ├── goose.py              IEC 61850 GOOSE + Sampled Values (L2)
    │   ├── it_detect.py          IT protocol detector (30+ protocols)
    │   └── behavior.py           Deep packet inspection / function code statistics
    ├── fingerprint/
    │   ├── engine.py             7-step vendor fingerprinting pipeline
    │   └── oui_db.py             144 ICS-specific MAC OUI entries
    ├── vuln/
    │   ├── engine.py             Vulnerability orchestrator + risk scoring
    │   ├── dnp3_checks.py        7 DNP3 behavioral checks
    │   ├── iec104_checks.py      5 IEC-104 behavioral checks
    │   ├── iec61850_checks.py    6 IEC 61850 (GOOSE + MMS) checks
    │   └── general_checks.py     12 cross-protocol + 5 IT/OT convergence checks
    ├── topology/
    │   └── engine.py             Purdue zone inference, 5 violation rules, GraphML export
    ├── cvedb/
    │   ├── ics_cves.py           76 curated ICS CVEs across 11 vendor groups
    │   └── matcher.py            CVE-to-device matcher with Now/Next/Never prioritisation
    ├── export/
    │   ├── siem.py               CEF + LEEF syslog exporter
    │   └── stix.py               STIX 2.1 JSON bundle exporter
    ├── compliance/
    │   └── engine.py             35 controls (NERC CIP + IEC 62443 + NIST 800-82)
    ├── delta/
    │   └── engine.py             Baseline diff analysis (new devices, resolved vulns, risk changes)
    └── report/
        └── generator.py          JSON, CSV, HTML, GraphML report generation
```

### Vendor Fingerprinting

The fingerprinting engine uses a 7-step evidence pipeline (highest confidence first):

| Step | Source | Confidence | Example |
|------|--------|------------|---------|
| 1 | Exclusive protocol | High | S7comm -> Siemens, FINS -> Omron, MELSEC -> Mitsubishi |
| 2 | CIP Vendor ID | High | EtherNet/IP ListIdentity -> Rockwell / Allen-Bradley |
| 3 | Modbus MEI strings | High | Device Identification Object -> vendor, model, firmware |
| 4 | DNP3 Group 0 attributes | Medium | Device attribute strings -> vendor, serial |
| 5 | GOOSE gcbRef prefix | Medium | IED name encoding -> ABB (REF/REL), GE (P64/T60), SEL |
| 6 | Protocol detail substrings | Medium | Vendor keywords in protocol-extracted strings |
| 7 | MAC OUI database | Low | 144 ICS-specific OUI entries (Siemens, ABB, SEL, GE, ...) |

---

## Legacy Scanners

The unified OT scanner (v2.0) supersedes both legacy scanners. They remain in the repository for reference and for environments that only need a subset of capabilities.

### PLC Passive Scanner

A device-identification-focused scanner for industrial PLCs. Reads a PCAP file and builds a complete device inventory by analysing 7 industrial protocols (Modbus, S7comm, EtherNet/IP, DNP3, FINS, MELSEC, IEC-104). Outputs device inventory with vendor, model, firmware, and risk scoring in JSON, CSV, and HTML.

```bash
cd plc_passive_scanner
pip install -r requirements.txt
python plc_scanner.py capture.pcap -f html -o plc_report
```

### RTU Passive Scanner

A vulnerability-detection-focused scanner for RTUs, FRTUs, and IEDs. Analyses 9 protocols including Layer-2 GOOSE and Sampled Values, and runs 21 vulnerability checks covering DNP3 Secure Authentication, IEC 62351 encryption, GOOSE security, and command safety patterns.

```bash
cd rtu_passive_scanner
pip install -r requirements.txt
python rtu_scanner.py substation.pcap -f html -o rtu_report
```

---

## Why Passive Scanning?

Active network scanners (Nmap, Shodan-style probes) are **dangerous in OT environments**:

| Risk | Effect |
|------|--------|
| Unexpected TCP/UDP packets | PLCs crash or enter fault state |
| Unrecognised protocol frames | Safety systems and protection relays trip unexpectedly |
| Network flooding | Latency spikes break real-time control loops (< 4 ms determinism) |
| ARP probes | Disrupt deterministic PROFINET / EtherNet/IP I/O traffic |
| Injected connections | IEC-104 single-master sessions drop; DNP3 outstations fault |

Passive scanning from a PCAP eliminates all of these risks. Captures can be collected via:

- A **network TAP** on the OT switch uplink
- **Port mirroring (SPAN)** on a managed switch
- A dedicated **network sensor** (e.g., Raspberry Pi with tcpdump)
- Existing **IDS/NDR** appliances that export PCAP recordings

---

## Requirements

- Python **3.8+**
- **scapy >= 2.5.0** (recommended) or **dpkt >= 1.9.8** (fallback)
- Optional: **colorama >= 0.4.6** (coloured terminal output)

```bash
pip install scapy dpkt colorama
```

---

## Legal & Ethical Use

These tools are designed **exclusively for defensive security purposes**:

- **Asset inventory** -- document OT devices on your network
- **Security assessments** -- identify unencrypted protocols and vulnerabilities
- **Incident response** -- analyse captured traffic for suspicious patterns
- **Compliance audits** -- NERC CIP, IEC 62443, NIST 800-82, NIS2 assessments
- **CTF / training** -- practice ICS protocol analysis in lab environments

> **Important:** Always obtain explicit written authorisation before capturing or analysing traffic on any industrial network. Unauthorised interception of network communications may violate computer crime laws in your jurisdiction.

---

## License

MIT -- see [LICENSE](LICENSE) for details.
