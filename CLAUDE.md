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

| Scanner | Type | Version | Lines | Target |
|---------|------|---------|------:|--------|
| `ot_scanner/ot_scanner.py` | Unified OT | 2.0.0 | ~22,700 (package) | 16 ICS/SCADA protocols, 9 analysis engines, 11 export formats |
| `plc_passive_scanner/plc_scanner.py` | PLC-only | 1.0 | 227 | 7 PLC protocols |
| `rtu_passive_scanner/rtu_scanner.py` | RTU/IED-only | 1.0 | 332 | 9 RTU/IED protocols |

## Unified OT Scanner Architecture (v2.0)

### Module Map

```
ot_scanner/
├── ot_scanner.py                   # CLI entry point (~750 lines)
├── scanner/
│   ├── core.py                     # PCAPAnalyzer — dual scapy/dpkt backend (~1,100 lines)
│   ├── models.py                   # 20+ data types (dataclasses) (~900 lines)
│   ├── protocols/
│   │   ├── base.py                 # BaseProtocolAnalyzer + BaseL2Analyzer
│   │   ├── modbus.py               # Modbus/TCP (TCP/502)
│   │   ├── s7comm.py               # S7comm / S7comm+ with SZL 0x0011/0x001C parsing
│   │   ├── enip.py                 # EtherNet/IP + CIP
│   │   ├── dnp3.py                 # DNP3 — stateful sessions + Group 0 attrs
│   │   ├── fins.py                 # Omron FINS
│   │   ├── melsec.py               # MELSEC MC 3E/4E
│   │   ├── iec104.py               # IEC 60870-5-104 — stateful
│   │   ├── goose.py                # GOOSE + SV (L2)
│   │   ├── iec61850_mms.py         # IEC 61850 MMS
│   │   ├── sel_protocol.py         # SEL Fast Message
│   │   ├── opcua.py                # OPC-UA Binary
│   │   ├── bacnet.py               # BACnet/IP
│   │   ├── mqtt.py                 # MQTT v3.1.1 / v5.0
│   │   ├── profinet.py             # PROFINET DCP (L2) + RT (UDP)
│   │   ├── it_detect.py            # IT protocol detector (36+ protocols incl. VPN)
│   │   └── behavior.py             # Protocol DPI behavior tracker
│   ├── fingerprint/
│   │   ├── engine.py               # 7-step vendor fingerprint pipeline
│   │   └── oui_db.py               # 144 OUI entries
│   ├── vuln/
│   │   ├── engine.py               # VulnerabilityEngine orchestrator + risk scoring
│   │   ├── dnp3_checks.py          # 7 DNP3 rules
│   │   ├── iec104_checks.py        # 5 IEC-104 rules
│   │   ├── iec61850_checks.py      # 6 IEC 61850 rules
│   │   └── general_checks.py       # 12 cross-protocol + 5 IT/OT convergence rules
│   ├── risk/
│   │   └── engine.py               # CompositeRiskEngine — multi-factor 0-100 scoring
│   ├── threat/
│   │   ├── engine.py               # ThreatDetectionEngine — 4 detection modules
│   │   └── signatures.py           # 9 ICS malware behavioral signatures
│   ├── attack/
│   │   └── engine.py               # AttackPathEngine — BFS pathfinding + kill chain
│   ├── access/
│   │   └── engine.py               # SecureAccessEngine — CIP-005 R2 compliance
│   ├── config/
│   │   └── engine.py               # ConfigSnapshotEngine — drift detection + LKG baselines
│   ├── policy/
│   │   ├── engine.py               # PolicyEngine — 6-stage rule generation
│   │   └── exporters.py            # Palo Alto XML, Fortinet CLI, Cisco ACL, JSON
│   ├── project_files/
│   │   ├── engine.py               # ProjectFileEngine — directory walker + dispatch
│   │   └── parsers.py              # TIA Portal, Rockwell L5X, Schneider XEF, CSV, JSON
│   ├── topology/
│   │   └── engine.py               # Purdue zones, zone violations, GraphML export
│   ├── cvedb/
│   │   ├── ics_cves.py             # 90 ICS CVEs with EPSS + CISA KEV + exploit maturity
│   │   └── matcher.py              # CVEMatcher with Now/Next/Never + KEV/EPSS boost
│   ├── export/
│   │   ├── siem.py                 # CEF + LEEF syslog export
│   │   ├── stix.py                 # STIX 2.1 JSON bundle
│   │   ├── servicenow.py           # ServiceNow CMDB Import Set JSON
│   │   ├── splunk.py               # Splunk HEC NDJSON events
│   │   ├── elastic.py              # Elastic Common Schema NDJSON
│   │   └── webhook.py              # Webhook notification payload
│   ├── compliance/
│   │   └── engine.py               # 35 controls (NERC CIP + IEC 62443 + NIST 800-82)
│   ├── delta/
│   │   └── engine.py               # Baseline diff analysis
│   └── report/
│       └── generator.py            # JSON, CSV, HTML, GraphML reports
```

### Data Flow

```
PCAP File
  │
  ├── scapy / dpkt packet reader (core.py)
  │     ├── Layer-2 frames → L2 analyzers (GOOSE, SV, PROFINET DCP)
  │     └── IP/TCP/UDP packets → IP analyzers (Modbus, S7comm, ENIP, ...)
  │           └── IT protocol detector → ITProtocolHit accumulation
  │
  ├── Per-device OTDevice registry (IP → OTDevice)
  ├── Communication flow table ((src, dst, proto, port) → CommFlow)
  │
  └── Finalisation pipeline (core._finalise):
        1.  Collect stateful sessions (DNP3, IEC-104, GOOSE)
        2.  GOOSE publisher → IP device linking
        3.  Merge project file ground-truth devices
        4.  Vendor fingerprinting (7-step pipeline, skip ground_truth)
        5.  Protocol behavior analysis (DPI stats)
        6.  IT protocol attachment
        7.  Asset criticality inference (safety/process/monitoring/support)
        8.  Communication profile computation (master/slave/peer)
        9.  Device filtering (min_packets threshold + ground_truth)
        10. Vulnerability assessment (4 check modules)
        11. CVE matching (Now/Next/Never with EPSS/KEV boost)
        12. Topology analysis (Purdue zones, violations, edges)
        13. Composite risk scoring (0-100 multi-factor)
        14. Threat detection (malware sigs, anomalies, recon, unauthorized cmds)
        15. Secure access audit (VPN/RDP/SSH, CIP-005 compliance)
        │
        └── Return: (devices, flows, zones, violations, edges)
              │
              ├── Console summary (with threat/attack/remote access alerts)
              ├── Attack path analysis (multi-hop BFS, kill chain, remediation)
              ├── Configuration snapshots (persistent store, drift detection)
              ├── JSON / CSV / HTML / GraphML reports
              ├── CEF / LEEF / STIX / ServiceNow / Splunk / Elastic / Webhook exports
              ├── Firewall policy generation (Palo Alto, Fortinet, Cisco, JSON)
              ├── Compliance report (NERC CIP + IEC 62443 + NIST 800-82)
              └── Delta analysis (compare against baseline)
```

### Key Data Types (models.py)

20+ dataclasses model the scanner's domain:

| Type | Description |
|------|-------------|
| `ProtocolDetection` | Detected industrial protocol on a device |
| `VulnerabilityFinding` | Security vulnerability with MITRE ATT&CK mapping |
| `CommFlow` | Directional communication flow between devices |
| `NetworkZone` | /24 subnet mapped to Purdue level (0-5) |
| `ZoneViolation` | Cross-zone communication breach |
| `CVEEntry` | Known ICS CVE with EPSS, CISA KEV, exploit maturity |
| `CVEMatch` | CVE matched to device with Now/Next/Never priority |
| `ProtocolStats` | DPI statistics per protocol (function codes, read/write/control) |
| `ITProtocolHit` | IT/enterprise protocol detected on OT network |
| `TopologyEdge` | Directed edge in network topology graph |
| `DNP3SessionState` | Per-session DNP3 state (SA, commands, file transfers) |
| `IEC104SessionState` | Per-session IEC-104 state (commands, clock syncs) |
| `GOOSEPublisherState` | Per-publisher GOOSE state (simulation, TTL, confRev) |
| `PolicyRule` | Firewall rule recommendation with compliance refs |
| `PolicyRuleSet` | Complete rule collection organized by zone |
| `ThreatAlert` | Threat detection alert with MITRE technique/tactic |
| `RemoteAccessSession` | Remote access session with CIP-005 compliance status |
| `DeviceConfig` | Point-in-time device configuration snapshot |
| `ConfigDriftAlert` | Configuration change alert with MITRE mapping |
| `AttackPath` | Multi-hop attack path with score and kill chain |
| `OTDevice` | Unified device model combining all fields |

### Analysis Engines (9 modules)

| Engine | Module | Purpose |
|--------|--------|---------|
| CompositeRiskEngine | `risk/engine.py` | Multi-factor 0-100 risk scoring (CVSS, EPSS, KEV, criticality, exposure) |
| ThreatDetectionEngine | `threat/engine.py` | 9 ICS malware signatures, anomaly baselines, recon detection |
| AttackPathEngine | `attack/engine.py` | BFS pathfinding, crown jewel identification, kill chain mapping |
| SecureAccessEngine | `access/engine.py` | Remote access audit, jump server detection, CIP-005 compliance |
| ConfigSnapshotEngine | `config/engine.py` | Persistent snapshots, drift detection, LKG baselines |
| PolicyEngine | `policy/engine.py` | 6-stage firewall rule generation, 4 export formats |
| ProjectFileEngine | `project_files/engine.py` | ICS project file parsing (TIA Portal, L5X, XEF, CSV, JSON) |
| TopologyEngine | `topology/engine.py` | Purdue zones, violation detection, GraphML |
| VulnerabilityEngine | `vuln/engine.py` | 29 behavioral rules, risk scoring, role inference |

### ICS Malware Signatures (threat/signatures.py)

| Malware | Year | Pattern | MITRE |
|---------|------|---------|-------|
| Industroyer/CrashOverride | 2016 | IEC-104 control + GI + clock sync | T0855, T0831 |
| TRITON/TRISIS | 2017 | SIS program download + firmware update | T0839, T0836 |
| Havex | 2014 | OPC-UA high peers + diagnostics | T0846 |
| BlackEnergy | 2015 | Multi-protocol + IT + program upload | T0869, T0859 |
| Pipedream/Incontroller | 2022 | S7comm download + Modbus writes | T0836, T0855 |
| Stuxnet | 2010 | S7comm upload + download (different sources) | T0843, T0845 |
| FrostyGoop | 2024 | Modbus writes from higher Purdue zone | T0855 |
| Fuxnet | 2024 | Modbus flood writes + diagnostics (PLC bricking) | T0831 |
| IOControl | 2024 | MQTT C2 + IT protocols on IoT gateways | T0869 |

### MITRE ATT&CK for ICS Techniques (14 mapped)

T0816, T0831, T0836, T0839, T0842, T0843, T0845, T0846, T0855, T0858, T0859, T0869, T0882, T0886

## CLI Reference

```
python ot_scanner.py PCAP_FILE [options]

Individual reports:
  --json FILE, --csv FILE, --html FILE, --graphml FILE

CVE database:
  --cve-db FILE              Load additional CVE entries from JSON

SIEM export:
  --cef FILE                 CEF syslog (Splunk / ArcSight)
  --leef FILE                LEEF syslog (QRadar)
  --stix FILE                STIX 2.1 JSON bundle

Platform integrations:
  --servicenow FILE          ServiceNow CMDB import JSON
  --splunk-hec FILE          Splunk HEC NDJSON events
  --elastic-ecs FILE         Elastic Common Schema NDJSON
  --webhook FILE             Webhook notification payload

Compliance & delta:
  --compliance FILE          NERC CIP + IEC 62443 + NIST 800-82
  --delta FILE               Compare against baseline JSON

Configuration snapshots:
  --snapshot-dir DIR         Persistent configuration snapshot directory
  --set-baseline             Mark current scan as "last known good"

Firewall policy:
  --policy DIR               Generate rules (Palo Alto, Fortinet, Cisco, JSON)

Project files:
  --project-dir DIR          ICS project files for ground-truth enrichment

Directory output:
  -o DIR, --output DIR       Output directory (auto-names)
  -f {json,csv,html,all}     Report format (default: all)

Filtering & analysis:
  --severity {critical,high,medium,low}
  -v, --verbose              Per-packet detections
  --min-packets N            Minimum packets per device (default: 2)
  --version
```

**Exit code**: `1` if CRITICAL or HIGH findings, `0` otherwise.

## Rule ID Conventions

| Prefix | Module | Count |
|--------|--------|-------|
| `RTU-DNP3-NNN` | `vuln/dnp3_checks.py` | 7 |
| `RTU-104-NNN` | `vuln/iec104_checks.py` | 5 |
| `RTU-61850-NNN` | `vuln/iec61850_checks.py` | 6 |
| `OT-GEN-NNN` | `vuln/general_checks.py` | 4 |
| `OT-OPCUA-NNN` | `vuln/general_checks.py` | 1 |
| `OT-MQTT-NNN` | `vuln/general_checks.py` | 2 |
| `OT-ITOT-NNN` | `vuln/general_checks.py` | 5 |
| `ZV-NNN` | `topology/engine.py` | 5 |
| `PR-NNN` | `policy/engine.py` | dynamic |
| `TA-NNN` | `threat/engine.py` | dynamic |
| `RA-NNN` | `access/engine.py` | dynamic |
| `CD-NNN` | `config/engine.py` | dynamic |
| `AP-NNN` | `attack/engine.py` | dynamic |

## Development Guidelines

### Adding New Protocol Analyzers

1. Create file in `scanner/protocols/`, subclass `BaseProtocolAnalyzer` or `BaseL2Analyzer`
2. Implement `can_analyze()` and `analyze()` returning `[(ip, ProtocolDetection)]`
3. Register in `scanner/core.py` (`_ip_analyzers` or `_OPTIONAL_IP_ANALYZERS`)
4. Add port(s) to `INDUSTRIAL_PORTS` in `core.py`

### Adding New Vulnerability Rules

1. Add check function to appropriate module (`vuln/dnp3_checks.py`, etc.)
2. Follow ID pattern: `{PREFIX}-{NNN}` (e.g., `RTU-DNP3-008`)
3. Return `VulnerabilityFinding` with all fields including `mitre_attack`
4. Wire into parent `run_*_checks()` dispatcher

### Adding New CVE Entries

1. Add dict to `ICS_CVE_DATABASE` in `cvedb/ics_cves.py`
2. Include: `cve_id`, `vendor`, `product_pattern` (regex), `affected_versions`, `severity`, `cvss_score`, `has_public_exploit`, `epss_score`, `is_cisa_kev`, `exploit_maturity`

### Conventions

- Python 3.8+ stdlib only (except scapy/dpkt + colorama)
- All sub-engines loaded via `try/except ImportError` for graceful degradation
- `dataclasses` for all model types with `to_dict()` methods
- HTML reports use Catppuccin Mocha dark theme
- Exit code 1 on CRITICAL/HIGH for CI/CD gating
- Deterministic STIX UUIDs (uuid5)

## Legacy Scanners

### PLC Passive Scanner (`plc_passive_scanner/`) -- v1.0
7 protocols, vendor fingerprinting, basic risk scoring. **Superseded by v2.0.**

### RTU Passive Scanner (`rtu_passive_scanner/`) -- v1.0
9 protocols, 21 vulnerability rules, GOOSE/MMS session tracking. **Superseded by v2.0.**
