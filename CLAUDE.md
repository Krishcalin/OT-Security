# CLAUDE.md — OT / ICS Passive Network Scanner

## Project Overview

A modular, offline-safe OT/ICS passive network scanner that identifies industrial
devices (PLCs, RTUs, FRTUs, IEDs, HMIs, gateways) and detects security
vulnerabilities by analysing captured PCAP / PCAPNG traffic. No packets are ever
sent to the network, making this safe to run in live OT environments where active
scanning can trigger protection relays or disrupt SCADA control.

The repository contains three scanner variants: a unified v2.0 scanner (primary)
and two legacy single-purpose scanners (PLC and RTU) that are superseded by v2.0.

**Repository**: https://github.com/Krishcalin/OT-Security
**License**: MIT
**Python**: 3.8+
**Dependencies**: `scapy >= 2.5.0` | `dpkt >= 1.9.8` (one required), `colorama >= 0.4.6` (optional)

## Scanner Inventory

| Scanner | Type | Version | Lines | Target | Dependencies |
|---------|------|---------|------:|--------|-------------|
| `ot_scanner/ot_scanner.py` | Unified OT | 2.0.0 | ~15,879 (package) | 15 ICS/SCADA protocols, L2 + IP | `scapy` or `dpkt` |
| `plc_passive_scanner/plc_scanner.py` | PLC-only | 1.0 | 227 | 7 PLC protocols (Modbus, S7comm, EtherNet/IP, DNP3, FINS, MELSEC, IEC-104) | `scapy` or `dpkt` |
| `rtu_passive_scanner/rtu_scanner.py` | RTU/IED-only | 1.0 | 332 | 9 RTU/IED protocols (DNP3, IEC-104, GOOSE, MMS, SV, Modbus, SEL, FINS, MELSEC) | `scapy` or `dpkt` |

**Total**: 3 scanners (~16,438 lines), 15 protocol analyzers, 34+ behavioral vulnerability rules, 76 ICS CVEs, 5 zone violation rules, 35 compliance controls.

## Unified OT Scanner Architecture (v2.0)

The unified scanner is a Python package (`ot_scanner/`) that merges PLC and RTU scanner
capabilities into a single multi-stage analysis pipeline. It uses a dual packet library
backend (scapy primary, dpkt fallback) and lazy-loads all sub-engines via `try/except ImportError`
so that missing modules degrade gracefully rather than crashing.

### Module Map

```
ot_scanner/
├── ot_scanner.py                   # CLI entry point, argparse, report dispatch (~560 lines)
├── scanner/
│   ├── __init__.py
│   ├── core.py                     # PCAPAnalyzer — dual scapy/dpkt backend (~814 lines)
│   ├── models.py                   # 14 data types (dataclasses) (~561 lines)
│   ├── protocols/
│   │   ├── __init__.py
│   │   ├── base.py                 # BaseProtocolAnalyzer + BaseL2Analyzer (~81 lines)
│   │   ├── modbus.py               # Modbus/TCP (TCP/502) (~217 lines)
│   │   ├── s7comm.py               # Siemens S7comm / S7comm+ (TCP/102) (~281 lines)
│   │   ├── enip.py                 # EtherNet/IP + CIP (TCP/44818) (~258 lines)
│   │   ├── dnp3.py                 # DNP3 — stateful sessions (TCP/UDP 20000) (~267 lines)
│   │   ├── fins.py                 # Omron FINS (UDP/9600) (~197 lines)
│   │   ├── melsec.py               # MELSEC MC 3E/4E (TCP/5006-5008) (~214 lines)
│   │   ├── iec104.py               # IEC 60870-5-104 — stateful (TCP/2404) (~235 lines)
│   │   ├── goose.py                # GOOSE + SV (L2 EtherType 0x88B8/0x88BA) (~269 lines)
│   │   ├── iec61850_mms.py         # IEC 61850 MMS (TCP/102) (~262 lines)
│   │   ├── sel_protocol.py         # SEL Fast Message (TCP/702) (~137 lines)
│   │   ├── opcua.py                # OPC-UA Binary (TCP/4840-4843) (~345 lines)
│   │   ├── profinet.py             # PROFINET DCP (L2) + RT (UDP/34962) (~356 lines)
│   │   ├── bacnet.py               # BACnet/IP (UDP/47808) (~515 lines)
│   │   ├── mqtt.py                 # MQTT (TCP/1883, 8883) (~521 lines)
│   │   ├── it_detect.py            # IT protocol detector (30+ protocols) (~282 lines)
│   │   └── behavior.py             # Protocol DPI behavior tracker (~550 lines)
│   ├── fingerprint/
│   │   ├── __init__.py
│   │   ├── engine.py               # 7-step vendor fingerprint pipeline (~587 lines)
│   │   └── oui_db.py               # 144 OUI entries (~351 lines)
│   ├── vuln/
│   │   ├── __init__.py
│   │   ├── engine.py               # VulnerabilityEngine orchestrator (~226 lines)
│   │   ├── dnp3_checks.py          # 7 DNP3 rules (RTU-DNP3-001..007) (~407 lines)
│   │   ├── iec104_checks.py        # 5 IEC-104 rules (RTU-104-001..005) (~265 lines)
│   │   ├── iec61850_checks.py      # 6 IEC 61850 rules (RTU-61850-001..006) (~287 lines)
│   │   └── general_checks.py       # 4 general + 3 OPC-UA/MQTT + 5 IT/OT convergence (~589 lines)
│   ├── topology/
│   │   ├── __init__.py
│   │   └── engine.py               # Purdue zones, zone violations, GraphML (~735 lines)
│   ├── cvedb/
│   │   ├── __init__.py
│   │   ├── ics_cves.py             # 76 ICS CVE entries, 12 vendor groups (~1,685 lines)
│   │   └── matcher.py              # CVEMatcher with Now/Next/Never priority (~591 lines)
│   ├── export/
│   │   ├── __init__.py
│   │   ├── siem.py                 # CEF + LEEF syslog export (~399 lines)
│   │   └── stix.py                 # STIX 2.1 JSON bundle (~338 lines)
│   ├── compliance/
│   │   ├── __init__.py
│   │   └── engine.py               # 35 controls (NERC CIP + IEC 62443 + NIST) (~689 lines)
│   ├── delta/
│   │   ├── __init__.py
│   │   └── engine.py               # Baseline diff analysis (~548 lines)
│   └── report/
│       ├── __init__.py
│       └── generator.py            # JSON, CSV, HTML, GraphML reports (~1,260 lines)
```

### Data Flow

The scanner operates as a multi-stage pipeline:

```
PCAP File
  │
  ├── scapy / dpkt packet reader (core.py)
  │     │
  │     ├── Layer-2 frames ──────────────→ L2 analyzers (GOOSE, SV, PROFINET DCP)
  │     │                                    │
  │     └── IP/TCP/UDP packets ──────────→ IP analyzers (Modbus, S7comm, ENIP, ...)
  │           │                              │
  │           └── IT protocol detector ──→ ITProtocolHit accumulation
  │
  ├── Per-device OTDevice registry (IP → OTDevice)
  ├── Communication flow table ((src, dst, proto, port) → CommFlow)
  │
  └── Finalisation pipeline (core._finalise):
        1. Collect stateful sessions (DNP3, IEC-104, GOOSE)
        2. Vendor fingerprinting (7-step pipeline)
        3. Protocol behavior analysis (DPI stats)
        4. IT protocol attachment
        5. Device filtering (min_packets threshold)
        6. Vulnerability assessment (4 check modules)
        7. CVE matching (Now/Next/Never)
        8. Topology analysis (Purdue zones, violations, edges)
        │
        └── Return: (devices, flows, zones, violations, edges)
              │
              ├── Console summary
              ├── JSON / CSV / HTML / GraphML reports
              ├── CEF / LEEF syslog export
              ├── STIX 2.1 bundle
              ├── Compliance report (NERC CIP + IEC 62443 + NIST)
              └── Delta analysis (compare against baseline)
```

### Key Data Types (models.py)

14 dataclasses model the scanner's domain:

| Type | Description |
|------|-------------|
| `ProtocolDetection` | A detected industrial protocol on a device (protocol, port, confidence, transport, details, timestamps) |
| `VulnerabilityFinding` | A security vulnerability or misconfiguration (vuln_id, title, severity, category, description, evidence, remediation) |
| `CommFlow` | A directional communication flow between two devices (src/dst IP, protocol, packet/byte counts) |
| `NetworkZone` | A /24 subnet inferred from observed IPs, mapped to a Purdue level (0-5) |
| `ZoneViolation` | A detected cross-zone communication that violates Purdue model segmentation |
| `CVEEntry` | A known ICS/SCADA CVE with vendor, product_pattern regex, affected_versions, CVSS score |
| `CVEMatch` | A CVE matched to a specific device with Now/Next/Never priority classification |
| `ProtocolStats` | Deep packet inspection statistics per protocol (function codes, read/write ratios, behavioral flags) |
| `ITProtocolHit` | An IT/enterprise protocol detected on an OT network segment |
| `TopologyEdge` | A directed edge in the network topology graph (protocols, counts, cross-zone flag) |
| `DNP3SessionState` | Per-session DNP3 state for vulnerability analysis (SA tracking, control commands, file transfers) |
| `IEC104SessionState` | Per-session IEC 60870-5-104 state (commands, clock syncs, interrogations) |
| `GOOSEPublisherState` | Per-publisher IEC 61850 GOOSE state (simulation bit, TTL, confRev) |
| `OTDevice` | Unified model for all OT devices (PLC/RTU/IED/HMI/gateway), combining identity, protocols, vulnerabilities, CVEs, risk scoring |

### Protocol Analyzers

Two abstract base classes in `protocols/base.py`:

- **`BaseProtocolAnalyzer`** (IP-layer): `can_analyze(sport, dport, proto, payload) -> bool`, `analyze(...) -> [(ip, ProtocolDetection)]`, `get_sessions() -> Dict`
- **`BaseL2Analyzer`** (Ethernet-layer): `can_analyze_frame(eth_type, payload) -> bool`, `analyze_frame(...) -> dict`, `get_sessions() -> Dict`

**IP-layer analyzers** (13):

| Analyzer | Protocol | Port(s) | Transport | Stateful | Vendor Scope |
|----------|----------|---------|-----------|----------|-------------|
| `ModbusAnalyzer` | Modbus/TCP | 502 | TCP | No | Multi-vendor |
| `S7CommAnalyzer` | S7comm / S7comm+ | 102 | TCP | No | Siemens |
| `EtherNetIPAnalyzer` | EtherNet/IP + CIP | 44818, 2222 | TCP/UDP | No | Rockwell, Omron, Schneider |
| `DNP3Analyzer` | DNP3 | 20000, 10001-10002 | TCP/UDP | Yes | ABB, GE, Honeywell, Schneider |
| `FINSAnalyzer` | Omron FINS | 9600 | UDP | No | Omron |
| `MELSECAnalyzer` | MELSEC MC 3E/4E | 5006-5008 | TCP | No | Mitsubishi |
| `IEC104Analyzer` | IEC 60870-5-104 | 2404 | TCP | Yes | ABB, Siemens, Schneider |
| `IEC61850MmsAnalyzer` | IEC 61850 MMS | 102 | TCP | No | Substation IEDs |
| `SELProtocolAnalyzer` | SEL Fast Message | 702 | TCP | No | SEL |
| `OPCUAAnalyzer` | OPC-UA Binary | 4840-4843 | TCP | No | Cross-vendor |
| `BACnetAnalyzer` | BACnet/IP | 47808 | UDP | No | Building automation |
| `MQTTAnalyzer` | MQTT | 1883, 8883 | TCP | No | IIoT messaging |
| `ProfinetRTAnalyzer` | PROFINET RT | 34962-34964 | UDP | No | Siemens, multi-vendor |

**Layer-2 analyzers** (3):

| Analyzer | Protocol | EtherType | Notes |
|----------|----------|-----------|-------|
| `GOOSEAnalyzer` | IEC 61850 GOOSE | 0x88B8 | Stateful publisher tracking, simulation/TTL/confRev detection |
| `SVAnalyzer` | IEC 61850 Sampled Values | 0x88BA | Merging unit identification |
| `ProfinetDCPAnalyzer` | PROFINET DCP | 0x8892 | Device discovery frames |

**Additional analyzers** (2):

| Analyzer | Purpose | Lines |
|----------|---------|-------|
| `ITProtocolDetector` | Detects 30+ IT protocols (HTTP, SSH, RDP, SMB, DNS, SNMP, databases, email, etc.) in OT traffic | 282 |
| `BehaviorAnalyzer` | Post-processing DPI stats: function code distributions, read/write ratios, program upload/download detection | 550 |

### Vulnerability Rules

34 behavioral vulnerability rules grouped across 4 check modules, plus 5 zone violations and 5 IT/OT convergence checks:

**DNP3 Checks** (`vuln/dnp3_checks.py`) -- 7 rules:

| Rule ID | Severity | Title |
|---------|----------|-------|
| RTU-DNP3-001 | HIGH | No DNP3 Secure Authentication (SAv5/SAv6) |
| RTU-DNP3-002 | CRITICAL | Unauthenticated DNP3 Control Commands |
| RTU-DNP3-003 | HIGH | Direct Operate (FC5) Bypasses Select-Before-Operate Safety |
| RTU-DNP3-004 | HIGH/MEDIUM | DNP3 Maintenance/Restart Commands Observed |
| RTU-DNP3-005 | CRITICAL/HIGH | DNP3 File Transfer -- Potential Firmware/Config Injection |
| RTU-DNP3-006 | HIGH | Multiple DNP3 Masters -- Potential Rogue Master Station |
| RTU-DNP3-007 | MEDIUM | DNP3 Transported over UDP (Stateless / Replay Risk) |

**IEC 60870-5-104 Checks** (`vuln/iec104_checks.py`) -- 5 rules:

| Rule ID | Severity | Title |
|---------|----------|-------|
| RTU-104-001 | HIGH | IEC 60870-5-104 Without TLS (IEC 62351-3) |
| RTU-104-002 | HIGH | Multiple IEC 104 Masters -- Potential Rogue Connection |
| RTU-104-003 | CRITICAL | Cleartext IEC 104 Control Commands (Switch/Set-point) |
| RTU-104-004 | MEDIUM | Unauthenticated Clock Synchronisation (C_CS_NA Type 103) |
| RTU-104-005 | LOW | Excessive General Interrogation (C_IC_NA) Requests |

**IEC 61850 Checks** (`vuln/iec61850_checks.py`) -- 6 rules:

| Rule ID | Severity | Title |
|---------|----------|-------|
| RTU-61850-001 | CRITICAL | IEC 61850 GOOSE Without Cryptographic Authentication (IEC 62351-6) |
| RTU-61850-002 | CRITICAL | GOOSE Simulation Flag TRUE -- Trip-Block Attack Risk |
| RTU-61850-003 | MEDIUM | GOOSE Very Low timeAllowedToLive |
| RTU-61850-004 | MEDIUM | GOOSE Configuration Revision (confRev) Changed |
| RTU-61850-005 | -- | GOOSE ndsCom (Needs Commissioning) -- reserved, not yet implemented |
| RTU-61850-006 | HIGH | IEC 61850 MMS Without TLS (IEC 62351-4) |

**General + OPC-UA + MQTT + IT/OT Convergence Checks** (`vuln/general_checks.py`) -- 12 rules:

| Rule ID | Severity | Title |
|---------|----------|-------|
| OT-GEN-001 | HIGH | Cleartext Industrial Protocols Expose OT Traffic |
| OT-GEN-002 | MEDIUM | Excessive Industrial Protocol Exposure (3+ protocols) |
| OT-GEN-003 | LOW | Device on OT Ports -- Protocol Unidentified |
| OT-GEN-004 | MEDIUM | Unusual Number of Communication Peers |
| OT-OPCUA-001 | HIGH | OPC-UA SecurityPolicy#None -- No Signing or Encryption |
| OT-MQTT-001 | HIGH | MQTT Without TLS (Cleartext on Port 1883) |
| OT-MQTT-002 | HIGH | MQTT CONNECT Without Authentication |
| OT-ITOT-001 | HIGH | Remote Access Protocol in OT Zone (RDP/VNC/TeamViewer) |
| OT-ITOT-002 | MEDIUM | Database Protocol in OT Zone |
| OT-ITOT-003 | CRITICAL | Telnet (Cleartext Remote Access) on OT Device |
| OT-ITOT-004 | CRITICAL/HIGH | File Sharing Protocol in OT Zone (SMB/FTP) |
| OT-ITOT-005 | MEDIUM | Excessive IT Protocol Activity on OT Device |

### Vulnerability Engine (`vuln/engine.py`)

Orchestrates all check modules on each device:

1. Dispatches to protocol-specific checks based on detected protocols
2. Runs general + OPC-UA + MQTT + IT/OT convergence checks on all devices
3. De-duplicates findings by `vuln_id` (keeps highest `packet_count`)
4. Calculates aggregate risk score: `critical=10, high=6, medium=3, low=1, info=0`
5. Assigns risk level: `>=20 critical, >=10 high, >=4 medium, else low`
6. Infers device role from protocols (plc, rtu, ied, building_controller, iot_device)

### Fingerprint Engine (`fingerprint/engine.py`)

7-step vendor identification pipeline (highest priority first):

1. **Exclusive protocols** -- S7comm -> Siemens, FINS -> Omron, MELSEC -> Mitsubishi, SEL FM -> SEL
2. **CIP vendor ID** -- from EtherNet/IP ListIdentity response
3. **Modbus MEI** -- device identification strings (vendor, product, firmware)
4. **DNP3 Group 0** -- device attribute strings
5. **IEC 61850 GOOSE** -- gcbRef prefix encodes IED vendor name
6. **Vendor substring matching** -- protocol detail strings
7. **MAC OUI lookup** -- 144-entry OUI database (lowest priority)

Each step enriches `vendor`, `make`, `model`, `firmware`, `serial_number`, `device_type`, `role`, and `vendor_confidence` on the OTDevice in-place.

### CVE Database (`cvedb/`)

76 curated ICS/SCADA CVEs across 12 vendor groups:

| Vendor | CVE Count |
|--------|-----------|
| Siemens | 15 |
| Rockwell Automation | 10 |
| Schneider Electric | 10 |
| ABB | 8 |
| GE / GE Grid Solutions | 6 |
| SEL (Schweitzer) | 5 |
| Omron | 5 |
| Mitsubishi Electric | 5 |
| Honeywell | 4 |
| Yokogawa | 3 |
| OPC Foundation | 3 |
| Generic / D-Link | 2 |

**CVE Matching** (`cvedb/matcher.py`):

- Matches devices by vendor + product_pattern (regex) + firmware version range
- Pre-compiles all product_pattern regexes at initialization
- Supports external CVE database loading via `--cve-db FILE` (JSON)
- Produces `CVEMatch` objects with Dragos-inspired priority classification:
  - **Now** -- CVE with known public exploit AND device is network-reachable
  - **Next** -- CVE confirmed but no public exploit, or mitigated by network position
  - **Never** -- Low confidence match, theoretical-only risk

### Topology Engine (`topology/engine.py`)

Analyses device inventory and communication flows to produce Purdue model mapping:

**Purdue levels** (ISA-95 / ISA-99 / IEC 62443):

| Level | Label | Device Roles | Protocols |
|-------|-------|-------------|-----------|
| 0 | Process | Sensors, actuators, safety systems | -- |
| 1 | Basic Control | PLCs, RTUs, FRTUs, IEDs, relays | Modbus, S7comm, DNP3, IEC-104, GOOSE, FINS, MELSEC, SEL, PROFINET, EtherNet/IP |
| 2 | Area Supervisory | HMIs, SCADA servers, engineering workstations | OPC-UA (combined with L1 protocols) |
| 3 | Site Operations | Historians, MES, OPC-UA aggregation | MQTT, BACnet/IP |
| 3.5 | DMZ | Data diodes, jump servers | -- |
| 4-5 | Enterprise/Internet | ERP, cloud SCADA | -- |

**Zone inference**: Groups devices by /24 subnet, assigns Purdue level from device roles and protocols.

**5 zone violation rules**:

| Rule ID | Severity | Title |
|---------|----------|-------|
| ZV-001 | HIGH | Direct L1 -> L3+ communication (bypassing supervisory) |
| ZV-002 | CRITICAL | Control protocol crossing 2+ Purdue levels |
| ZV-003 | HIGH | IT protocol in OT zone (L0-1) |
| ZV-004 | MEDIUM | Outbound OT protocol from control zone toward L3+ |
| ZV-005 | MEDIUM | Excessive cross-zone peers for L0-1 device |

**GraphML export**: Node colour by Purdue level (Catppuccin Mocha palette), edge colour by cross-zone severity. Compatible with Gephi, yEd, and Cytoscape.

### Compliance Mapper (`compliance/engine.py`)

Maps scan findings to 3 ICS/OT compliance frameworks, producing pass/fail/warning/not_assessed for each control:

**35 controls total**:

| Framework | Controls | Example Control IDs |
|-----------|----------|-------------------|
| NERC CIP (v5-7) | 15 | CIP-002-5.1 R1, CIP-005-6 R1, CIP-005-6 R2, CIP-007-6 R1-R5, CIP-010-3 R1-R2, CIP-011-2 R1, CIP-013-1 R1 |
| IEC 62443-3-3 | 12 | SR 1.1, SR 1.13, SR 3.1, SR 3.5, SR 4.1, SR 4.3, SR 5.1, SR 5.2, SR 7.1, SR 7.6, SR 7.7, SR 2.8 |
| NIST SP 800-82 Rev 3 | 8 | 5.1, 6.2.1, 6.2.5, 6.2.7, 6.2.8, 6.2.9, 6.3.3, 6.3.4 |

Each control links to specific vuln IDs, CVE priorities (`CVE:now`, `CVE:any`), zone violations (`ZV-*`), device identification status (`DEVICE_ID`), or passive assessment limitation (`PASSIVE`).

### SIEM Export (`export/siem.py`)

- **CEF** (Common Event Format) -- one log line per finding with structured key-value metadata. For Splunk, ArcSight, Elastic SIEM.
- **LEEF** (Log Event Extended Format) -- IBM QRadar format.
- Severity mapping: critical=10, high=8, medium=5, low=3, info=1.

### STIX Export (`export/stix.py`)

STIX 2.1 JSON bundle for threat intelligence sharing with ISACs, SOCs, and STIX/TAXII consumers:

- **Identity** -- scanner tool itself
- **Infrastructure** -- one per discovered OT device
- **Vulnerability** -- one per unique finding across all devices
- **Indicator** -- one per CVE match with NOW priority
- **Relationship** -- infrastructure `--has-->` vulnerability

Uses deterministic UUIDs (uuid5) for reproducible output.

### Delta Analysis (`delta/engine.py`)

Compares two JSON scan results (baseline vs current) to detect environment changes:

**10 change types**:

| Change Type | Description |
|-------------|-------------|
| `new_device` | Device appeared that was not in baseline |
| `removed_device` | Device from baseline no longer seen |
| `new_vuln` | New vulnerability finding on an existing device |
| `resolved_vuln` | Vulnerability from baseline no longer present |
| `new_cve` | New CVE match on a device |
| `new_protocol` | Device started using a new protocol |
| `removed_protocol` | Device stopped using a protocol |
| `risk_change` | Device risk level changed (escalation or reduction) |
| `firmware_change` | Device firmware version changed |
| `new_it_protocol` | New IT protocol detected on OT device |

### Report Generator (`report/generator.py`)

Produces 4 report formats from a single `ReportGenerator` instance:

- **JSON** -- full machine-readable detail (devices, vulnerabilities, flows, zones, violations, CVEs, topology edges)
- **CSV** -- spreadsheet-friendly summary (one row per device)
- **HTML** -- interactive browser report with Catppuccin Mocha dark theme (`#1e1e2e` bg, `#cdd6f4` text), summary cards, protocol breakdown, top flows, device detail cards, expandable vulnerability cards with severity badges
- **GraphML** -- network topology graph for Gephi / yEd / Cytoscape

## CLI Reference

```
python ot_scanner.py PCAP_FILE [options]

Positional:
  PCAP_FILE                  Path to .pcap / .pcapng capture file

Individual report files:
  --json FILE                Save JSON report
  --csv FILE                 Save CSV report
  --html FILE                Save HTML report
  --graphml FILE             Save GraphML topology

CVE database:
  --cve-db FILE              Load additional CVE entries from JSON

SIEM export:
  --cef FILE                 CEF syslog (Splunk / ArcSight)
  --leef FILE                LEEF syslog (QRadar)
  --stix FILE                STIX 2.1 JSON bundle

Compliance:
  --compliance FILE          NERC CIP + IEC 62443 + NIST 800-82 report

Delta analysis:
  --delta FILE               Compare against baseline JSON scan

Directory-based output:
  -o DIR, --output DIR       Output directory (auto-names based on pcap filename)
  -f {json,csv,html,all}     Report format when using -o (default: all)

Filtering:
  --severity {critical,high,medium,low}  Minimum severity filter

Analysis options:
  -v, --verbose              Print per-packet protocol detections
  --min-packets N            Minimum packet count per device (default: 2)
  --version                  Show version and exit
```

**Exit code**: `1` if CRITICAL or HIGH findings, `0` otherwise (CI/CD pipeline gating).

**Default behavior**: If no output flags are specified, writes all 4 report formats (`ot_scan_results.json`, `.csv`, `.html`, `.graphml`) to the current directory.

## Rule ID Conventions

| Prefix | Module | Count | Example |
|--------|--------|-------|---------|
| `RTU-DNP3-NNN` | `vuln/dnp3_checks.py` | 7 | RTU-DNP3-001 |
| `RTU-104-NNN` | `vuln/iec104_checks.py` | 5 | RTU-104-001 |
| `RTU-61850-NNN` | `vuln/iec61850_checks.py` | 6 | RTU-61850-001 |
| `OT-GEN-NNN` | `vuln/general_checks.py` | 4 | OT-GEN-001 |
| `OT-OPCUA-NNN` | `vuln/general_checks.py` | 1 | OT-OPCUA-001 |
| `OT-MQTT-NNN` | `vuln/general_checks.py` | 2 | OT-MQTT-001 |
| `OT-ITOT-NNN` | `vuln/general_checks.py` | 5 | OT-ITOT-001 |
| `ZV-NNN` | `topology/engine.py` | 5 | ZV-001 |

## Development Guidelines

### Adding New Protocol Analyzers

1. Create a new file in `scanner/protocols/` (e.g., `hart.py`).
2. Subclass `BaseProtocolAnalyzer` (IP-layer) or `BaseL2Analyzer` (Ethernet-layer).
3. Implement `can_analyze()` / `can_analyze_frame()` and `analyze()` / `analyze_frame()`.
4. Override `get_sessions()` if the analyzer tracks stateful sessions.
5. Register the import in `scanner/core.py`:
   - Always-available: add to `self._ip_analyzers` list in `__init__`.
   - Optional: add a `try/except ImportError` block to `_OPTIONAL_IP_ANALYZERS` or `_OPTIONAL_L2_ANALYZERS`.
6. Add the protocol's port(s) to `INDUSTRIAL_PORTS` in `core.py`.
7. If the analyzer extracts vendor/model info, update `fingerprint/engine.py` to use it.

### Adding New Vulnerability Rules

1. Create a new check function in the appropriate module (`vuln/dnp3_checks.py`, `vuln/iec104_checks.py`, `vuln/iec61850_checks.py`, or `vuln/general_checks.py`).
2. Follow the rule ID pattern:
   - Protocol-specific: `RTU-{PROTO}-{NNN}` (e.g., `RTU-DNP3-008`)
   - General OT: `OT-GEN-{NNN}`
   - Protocol-specific general: `OT-{PROTO}-{NNN}` (e.g., `OT-OPCUA-002`)
   - IT/OT convergence: `OT-ITOT-{NNN}`
3. Return a `VulnerabilityFinding` with all fields: `vuln_id`, `title`, `severity`, `category`, `description`, `evidence` (dict), `remediation`, `references` (list), `first_seen`, `packet_count`.
4. Wire the check function into the parent `run_*_checks()` dispatcher.
5. If the rule maps to compliance controls, add the vuln_id to the relevant control entries in `compliance/engine.py`.

### Adding New CVE Entries

1. Add a dict to `ICS_CVE_DATABASE` in `cvedb/ics_cves.py`.
2. Follow the existing format:
   ```python
   {
       "cve_id": "CVE-YYYY-NNNNN",
       "vendor": "Vendor Name",
       "product_pattern": r"regex matching model/product",
       "affected_versions": "<X.Y",  # supports <, <=, >, >=, comma-separated
       "severity": "critical|high|medium|low",
       "cvss_score": 9.8,
       "title": "Short title",
       "description": "Full description",
       "has_public_exploit": True,
       "ics_cert_advisory": "ICSA-YY-NNN-NN",
       "remediation": "Fix instructions",
       "references": ["url1", "url2"],
   }
   ```
3. The `product_pattern` is a regex matched against `device.model` (case-insensitive).
4. `affected_versions` uses the same `_parse_ver` / `_version_in_range` logic as SAST scanners.
5. Set `has_public_exploit: True` to elevate the CVE to NOW priority when matched.

### Adding Compliance Controls

1. Add a dict to `_NERC_CIP_CONTROLS`, `_IEC_62443_CONTROLS`, or `_NIST_800_82_CONTROLS` in `compliance/engine.py`.
2. Follow the format:
   ```python
   {
       "id": "CIP-NNN-N RN",
       "title": "Control Title",
       "severity": "critical|high|medium|low",
       "vulns": ["RTU-DNP3-001", "OT-GEN-001"],  # related vuln IDs
       "rec": "Recommendation text",
   }
   ```
3. Special `vulns` prefixes:
   - `"CVE:now"` -- any CVE match with priority=now
   - `"CVE:any"` -- any CVE match
   - `"ZV-NNN"` -- zone violation ID
   - `"DEVICE_ID"` -- device identification completeness
   - `"PASSIVE"` -- cannot be assessed from passive PCAP (always `not_assessed`)

### Conventions

- Python 3.8+ stdlib only, except for `scapy` / `dpkt` (one required) and `colorama` (optional).
- Dual packet library support: scapy primary, dpkt fallback. Both are loaded via `try/except ImportError`.
- All sub-engines (`fingerprint`, `vuln`, `topology`, `cvedb`, `export`, `compliance`, `delta`, `behavior`, `it_detect`) are loaded via `try/except ImportError` so missing modules degrade gracefully.
- `dataclasses` for all model types (not `__slots__` as in SAST scanners -- OTDevice has many optional fields).
- ANSI colour codes for console output (critical=bright red, high=bright yellow, medium=yellow, low=green, info=white).
- HTML reports use Catppuccin Mocha dark theme (`#1e1e2e` bg, `#cdd6f4` text).
- Exit code 1 on CRITICAL/HIGH findings for CI/CD pipeline gating.
- GraphML node fill colours mapped to Purdue levels using Catppuccin Mocha palette.
- Deterministic STIX UUIDs (uuid5) for reproducible export output.

## Legacy Scanners

### PLC Passive Scanner (`plc_passive_scanner/plc_scanner.py`) -- v1.0

Entry-point CLI (~227 lines) for a standalone PLC-only scanner. Supports 7 protocols
(Modbus/TCP, S7comm, EtherNet/IP, DNP3, FINS, MELSEC, IEC-104) with vendor fingerprinting
and basic risk scoring. Produces HTML, JSON, and CSV reports.

**Superseded by**: `ot_scanner/ot_scanner.py` v2.0, which includes all PLC protocols
plus GOOSE, SV, MMS, SEL, OPC-UA, BACnet, MQTT, PROFINET, vulnerability assessment,
CVE matching, topology analysis, compliance mapping, SIEM export, and delta analysis.

### RTU Passive Scanner (`rtu_passive_scanner/rtu_scanner.py`) -- v1.0

Entry-point CLI (~332 lines) for a standalone RTU/IED vulnerability scanner. Supports 9
protocols (DNP3, IEC-104, GOOSE, MMS, SV, Modbus, SEL, FINS, MELSEC) with stateful DNP3,
IEC-104, and GOOSE session tracking, vulnerability assessment (18 rules), and IEC 62351
compliance checking.

**Superseded by**: `ot_scanner/ot_scanner.py` v2.0, which merges all RTU/IED capabilities
into the unified scanner with additional OPC-UA, BACnet, MQTT, PROFINET, IT protocol
detection, CVE matching, topology analysis, and compliance mapping.

## Related Projects

| Project | Repo |
|---------|------|
| Static Application Security Testing (SAST) | [Static-Application-Security-Testing](https://github.com/Krishcalin/Static-Application-Security-Testing) |
| AWS CloudFormation + Terraform IaC | [AWS-Security-Scanner](https://github.com/Krishcalin/AWS-Security-Scanner) |
| Cisco IOS/IOS-XE Network Security | [Cisco-Network-Security](https://github.com/Krishcalin/Cisco-Network-Security) |
| Palo Alto PAN-OS Firewall | [PaloAlto-Network-Security](https://github.com/Krishcalin/PaloAlto-Network-Security) |
| Fortinet FortiGate Firewall | [Fortinet-Network-Security](https://github.com/Krishcalin/Fortinet-Network-Security) |
| Kubernetes KSPM | [Kubernetes-KSPM](https://github.com/Krishcalin/Kubernetes-Security-Posture-Management) |
| AI Security Posture Management | [AI-Secure-Posture-Management](https://github.com/Krishcalin/AI-Secure-Posture-Management) |
| OWASP API Security | [API-Security](https://github.com/Krishcalin/API-Security) |
| Cloud Detection & Response | [Cloud-Detection-Response](https://github.com/Krishcalin/Cloud-Detection-Response) |
| DAST Scanner | [Dynamic-Application-Security-Testing](https://github.com/Krishcalin/Dynamic-Application-Security-Testing) |
| Windows Red Teaming (MITRE ATT&CK) | [Windows-Red-Teaming](https://github.com/Krishcalin/Windows-Red-Teaming) |
