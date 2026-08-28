# CLAUDE.md — OTSec

## Project Overview

**OTSec** is a passive OT/ICS security product. It identifies industrial devices
(PLCs, RTUs, FRTUs, IEDs, HMIs, gateways, ring switches) and their
vulnerabilities without ever sending a packet — safe in live plants where active
scanning trips protection relays.

It runs in two modes, and they share one analysis core:

| Mode | Entry point | What it is |
|---|---|---|
| **Offline scanner** | `ot_scanner/ot_scanner.py` | One PCAP in, reports out. The original v2.0 tool; still fully supported. |
| **Sensor fleet** | `ot_scanner/ot_collector.py` → `ot_server/` → `console/` | Raspberry Pi collectors capture continuously, ship distilled observations to a central server, and an operator reads the estate in a browser. |

The fleet is the product; the offline scanner is the same engine with a
different front door. `ot_scanner/scanner/` is imported by both.

**Repository**: https://github.com/Krishcalin/OT-Security
**License**: MIT
**Python**: 3.8+ (CI matrix: 3.8, 3.10, 3.12)
**Scanner dependencies**: `scapy >= 2.5.0` | `dpkt >= 1.9.8` (one required)
**Collector runtime dependency**: `dpkt` ALONE — `tests/test_collector_manifest.py`
fails if that changes, which is why `enrol.py` shells out to `openssl` rather
than importing `cryptography`.

---

## ⚠️ The one thing to read before changing anything

This product's entire claim is that it can tell **"we looked and saw nothing"**
apart from **"we did not look"**. Everything else is implementation.

That distinction has now been broken FOUR times, each in code that had passing
tests, and each found by RUNNING something rather than reading it:

| | The silence | Where it was fixed |
|---|---|---|
| 1 | A collector that had stopped reporting counted as a healthy one | `ot_server/health.py` |
| 2 | An asset never assessed against the CVE corpus reported as clean | `ot_server/vulnmatch.py` |
| 3 | A transport the decoder could not open reported as a quiet network | `ot_scanner/collector/decap.py` |
| 4 | A query truncated at its row limit reported as the whole estate | `ot_server/store.py` (`Page`) |

Every one was a **confident number over a question nobody asked**. When adding
anything that produces a count, a state or a clean verdict, the question to ask
is not "is this correct?" but "what does this look like when the thing that
produces it is not working?" If the answer is "the same", it is wrong.

The three-state model (`complete` / `degraded` / `unknown`) exists for this, and
`unknown` is never a synonym for zero.

---

## Deployment architecture (hub and spoke)

The fleet is sized for one central server and **~100 collectors**.

```
   substation / RMU ring (fibre, ERPS-protected)
   ┌─────────┬─────────┬─────────┐
   │ switch  │ switch  │ switch  │   MPLS-TP transport
   └────┬────┴────┬────┴────┬────┘
        │ RTU     │ FRTU    │ IED
        │
     [ SPAN/mirror port ]
        │
   ┌────▼──────────────────┐
   │ Raspberry Pi          │  tap NIC  — promiscuous, no IP, never transmits
   │ OTSec collector       │  mgmt NIC — mTLS to the server
   └────────┬──────────────┘
            │  observation batches (NOT pcap)
   ┌────────▼──────────────┐
   │ OTSec server + console│  PostgreSQL, 13-month retention
   └───────────────────────┘
```

**Two NICs per Pi.** The management NIC's own traffic must never be analysed as
estate traffic; `collector/self_exclusion.py` (OTS-CAP-006) filters it by MAC/IP
in BPF or userspace and COUNTS what it excluded.

**Observations, not packets.** The Pi ships distilled asset/flow/detection
records. Shipping pcap from 100 collectors would be tens of MB/minute each
across a utility WAN, 13 months of plant process data centralised, for
information the decoders have already extracted. If selective packet retention
is ever needed, the shape is a rolling local buffer uploaded only when a
detection fires — not a firehose.

## Scanner Inventory

| Scanner | Type | Version | Lines | Target |
|---------|------|---------|------:|--------|
| `ot_scanner/ot_scanner.py` | Unified OT | 2.0.0 | ~22,700 (package) | 20 ICS/SCADA protocols, 9 analysis engines, 11 export formats |
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
│   │   ├── hart_ip.py              # HART-IP (UDP/TCP 5094) — process instrumentation
│   │   ├── ge_srtp.py              # GE-SRTP (TCP 18245) — GE Series 90 / PACSystems
│   │   ├── niagara_fox.py          # Niagara Fox (TCP 1911/4911) — Tridium BAS (hello banner)
│   │   ├── knx_ip.py               # KNXnet/IP (UDP/TCP 3671) — KNX building automation
│   │   ├── lldp.py                 # LLDP (802.1AB) — the ONLY passive source that
│   │   │                           #   names ring switches; System Description ->
│   │   │                           #   make/model/OS version, Management Address -> IP
│   │   ├── snmp.py                 # SNMP v1/v2c — sysDescr -> OS version for devices
│   │   │                           #   whose industrial protocol carries no identity
│   │   ├── ring.py                 # G.8032 R-APS, RSTP/STP BPDUs — ring protection,
│   │   │                           #   because a protection switch changes what the
│   │   │                           #   collector can HEAR
│   │   ├── ber.py                  # Shared BER/ASN.1 reader (SNMP + MMS)
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
│   │   └── signatures.py           # 10 ICS malware behavioral signatures
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
│   │   ├── ics_cves.py             # 92 ICS CVEs with EPSS + CISA KEV + exploit maturity
│   │   ├── matcher.py              # CVEMatcher with Now/Next/Never + KEV/EPSS boost
│   │   └── cisa_importer.py        # CISA KEV (+EPSS) -> CVE JSON auto-refresh importer
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
├── tests/                          # 42 files, 791 tests — one suite covers the
│                                   #   scanner, collector, server AND console
│   ├── conftest.py                 # Shared fixtures (mock devices, zones, CVEs)
│   │
│   │   # the analysis engines
│   ├── test_models.py              # Dataclass validation
│   ├── test_risk_engine.py         # Composite scoring
│   ├── test_threat_engine.py       # Malware signatures
│   ├── test_attack_engine.py       # Attack path analysis
│   ├── test_cve_matcher.py         # CVE matching pipeline
│   ├── test_protocols.py           # Per-analyser synthetic packets
│   │
│   │   # what a passive listener can and cannot learn
│   ├── test_lldp.py                # Ring switches; refusing to guess a version
│   ├── test_snmp.py                # sysDescr; the community string is NEVER stored
│   ├── test_ring.py                # G.8032 / RSTP — protection as a coverage fact
│   ├── test_identification.py      # END TO END: a frame becomes an asset record
│   │
│   │   # the honesty model — read these before changing coverage
│   ├── test_decap.py               # MPLS-TP; an unopenable transport is counted
│   ├── test_collector_coverage.py  # complete / degraded / unknown
│   ├── test_scale.py               # 100 collectors; truncation cannot hide
│   ├── test_fleet_health.py        # a dead collector is not a clean one
│   ├── test_lifecycle.py           # no record is unknown, never "supported"
│   │
│   │   # the fleet plane
│   ├── test_fleet_enrolment.py     # tokens, CSRs, revocation
│   ├── test_operator_auth.py       # sign-in, TOTP, sessions
│   ├── test_console.py             # OTS-CON-004 is enforced by the TYPE CHECKER
│   └── test_branding.py            # the retired product name cannot come back
├── pytest.ini                      # Test configuration
└── requirements-dev.txt            # pytest, fastapi, psycopg, httpx, cryptography, Pillow
```

### The sensor fleet

```
ot_scanner/collector/               # runs on the Raspberry Pi
├── capture.py                      # SPAN capture; Frame, DropSnapshot
├── decap.py                        # MPLS / EoMPLS pseudowire decapsulation.
│                                   #   Refuses to guess: an encapsulation it
│                                   #   cannot follow is COUNTED, never dropped
├── analysis.py                     # IncrementalAnalyzer — drives scanner/core
├── coverage.py                     # Coverage(complete|degraded|unknown), windows
├── self_exclusion.py               # OTS-CAP-006 — the Pi's own mgmt traffic
├── service.py                      # the capture loop; owns windows, not decoding
├── spool.py / transport.py         # durable queue + mTLS upload
├── enrol.py / content.py           # certificate enrolment; signed content packs
└── observations.py                 # device -> asset/flow/detection records

ot_server/                          # the hub
├── api.py                          # FastAPI. NOTE: no `from __future__ import
│                                   #   annotations` in route modules — see traps
├── store.py                        # PostgreSQL; `Page` carries query completeness
├── estate.py                       # merge across collectors (union-find, site-scoped)
├── ingest.py / health.py           # batch acceptance; collector liveness
├── ca.py / enrolment.py            # fleet CA, one-time enrolment tokens
├── authn.py / authn_api.py / totp.py / qr.py   # operator sign-in + TOTP 2FA
├── vulnmatch.py / severity.py      # CVE matching; OT-corrected priority
├── containment.py / lifecycle.py   # segmentation advice; end-of-support
├── comms.py / zones.py             # conversations; Purdue zone derivation
└── packs.py                        # signed content packs (rules, corpus, lifecycle)

console/                            # the operator's browser
├── public/                         # index.html, login.html, otsec-*.png
└── src/                            # TypeScript; Measured<T> enforces OTS-CON-004
    └── screens/                    # estate, assets, findings, topology, comms,
                                    #   change, fleet, account
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
| ThreatDetectionEngine | `threat/engine.py` | 10 ICS malware signatures, anomaly baselines, recon detection |
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
| CosmicEnergy | 2023 | IEC-104 breaker control + master running MSSQL (PieHop C2) | T0855 |

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
3. CVE IDs must be **real and unique** (a test enforces uniqueness); never fabricate a CVE. Keep `epss_score` in 0.0–1.0.

### Refreshing CVEs from CISA KEV (auto-refresh)

`cvedb/cisa_importer.py` converts the authoritative **CISA KEV catalog** JSON
(+ optional FIRST.org **EPSS** CSV) into the same CVE-dict format, so the
scanner's "actively exploited" + EPSS data stays fresh from real sources without
hand curation. Two steps (the output feeds the existing `--cve-db` flag):

```bash
python -m scanner.cvedb.cisa_importer known_exploited_vulnerabilities.json \
    --epss epss_scores-current.csv -o ics_kev.json   # ICS-relevant KEV entries
python ot_scanner.py capture.pcap --cve-db ics_kev.json
```

By default only ICS-relevant entries are kept (known OT vendors + OT keywords);
`--all` keeps every KEV entry. KEV lacks CVSS, so imported entries carry
`cvss_score=0.0` but are flagged `is_cisa_kev` + `has_public_exploit` (→ "now"
priority). Pure functions (`parse_kev_catalog` / `parse_epss_csv` / `is_ics_entry`)
are unit-tested offline; only `fetch` touches the network (size-capped).

### Conventions

- Python 3.8+ stdlib only (except scapy/dpkt + colorama)
- All sub-engines loaded via `try/except ImportError` for graceful degradation
- `dataclasses` for all model types with `to_dict()` methods
- HTML reports use Catppuccin Mocha dark theme
- Exit code 1 on CRITICAL/HIGH for CI/CD gating
- Deterministic STIX UUIDs (uuid5)

## Testing

**791 tests.** Synthetic packets and mock data only — no PCAP files required.

```bash
cd ot_scanner
pip install -r requirements-dev.txt
python -m pytest -q                                   # 762 pass, 32 skip

# Everything. The two env vars are what stop tests from skipping SILENTLY —
# a skipped test on a CI summary page looks exactly like a passing one.
OT_TEST_DSN=postgresql://user:pw@127.0.0.1:5433/otsec \
OT_CONSOLE_REQUIRED=1 python -m pytest -q             # 791 pass, 3 skip
```

A throwaway database for the 25 store tests (5432 is usually taken):

```bash
docker run -d --name otsec-scale-db -p 127.0.0.1:5433:5432 \
  -e POSTGRES_PASSWORD=otsec -e POSTGRES_DB=otsec postgres:16-alpine
```

`OT_CONSOLE_REQUIRED=1` makes the console tests fail rather than skip when Node
is absent, and it is what proves `src/con004.expect-errors.ts` still REFUSES to
compile — the file whose job is to not compile.

| Test File | Tests | Coverage |
|-----------|------:|----------|
| `test_models.py` | 9 | Dataclass to_dict(), field defaults |
| `test_risk_engine.py` | 5 | Composite scoring, multipliers, compensating controls |
| `test_threat_engine.py` | 8 | All 10 malware signatures (incl. CosmicEnergy) + unauthorized command alerts |
| `test_attack_engine.py` | 6 | BFS pathfinding, crown jewels, path scoring, kill chain |
| `test_access_engine.py` | 4 | CIP-005 compliance, jump server detection |
| `test_config_engine.py` | 8 | Snapshot capture/save/load/diff, baseline, drift detection |
| `test_policy_engine.py` | 5 | Rule generation, priority ordering, safety isolation |
| `test_cve_matcher.py` | 11 | 92 CVEs loaded, unique IDs, EPSS/KEV propagation, matching pipeline |
| `test_cisa_importer.py` | 8 | CISA KEV -> CVE conversion, ICS filter, EPSS merge, matcher round-trip |
| `test_exporters.py` | 4 | ServiceNow, Splunk HEC, Elastic ECS, Webhook payloads |
| `test_protocols.py` | 8 | HART-IP / GE-SRTP / Niagara Fox / KNXnet/IP analyzers (synthetic packets) |

**CI Pipeline**: GitHub Actions (`.github/workflows/ci.yml`) runs on every push/PR against Python 3.8, 3.10, and 3.12.

## Traps, each of which cost a cycle

**FastAPI + postponed annotations.** A route module with
`from __future__ import annotations` makes FastAPI see `Request` as a string it
cannot resolve, treat it as a query parameter, and answer **422 on every
route**. The note is at the top of `api.py` and was still rediscovered once.
Modules imported by the route factory (`lifecycle.py`, `decap.py`) omit it too.

**Chassis ID and Port ID have different LLDP subtype registries** (802.1AB 8.5.2
vs 8.5.3). Subtype 5 is a network address on a chassis and an *interface name*
on a port. Sharing one table hex-encoded every Cisco port ID.

**MMS PDU tags.** ISO 9506-2 puts confirmed-Request/Response at `[0]`/`[1]`.
This file had them at `[8]`/`[9]` (cancel-Request, initiate-Response) for its
whole life, so real confirmed responses were never recognised. The identify
parser now locates its body by SHAPE, not by the enclosing tag.

**A TCN BPDU is exactly four octets** — protocol id, version, type, no body. A
length guard of five drops every topology-change notification on the ring.

**`min_packets` vs LLDP cadence.** The estate filter admits a device at
`packet_count >= 2`; LLDP's default interval is 30s and the window is 60s, so a
ring switch emits *exactly* two per window. A device that named itself now
bypasses the threshold — otherwise the estate flickers.

**Seed data is load-bearing.** The CVE corpus matches product patterns, so
`"M580"` matches nothing where `"Modicon M580"` matches five advisories; and
putting every Purdue level in one `/24` made every conversation read as
lateral. Wrong demo data hides real code paths.

## Legacy Scanners

### PLC Passive Scanner (`plc_passive_scanner/`) -- v1.0
7 protocols, vendor fingerprinting, basic risk scoring. **Superseded by v2.0.**

### RTU Passive Scanner (`rtu_passive_scanner/`) -- v1.0
9 protocols, 21 vulnerability rules, GOOSE/MMS session tracking. **Superseded by v2.0.**
