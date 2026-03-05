# RTU / FRTU Passive Vulnerability Scanner

A **purely passive**, offline OT security tool that reads captured network traffic (PCAP/PCAPNG) and identifies RTUs, FRTUs, and IEDs together with their specific **security vulnerabilities and misconfigurations** — without ever sending a packet to the network.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Why Passive Scanning?](#2-why-passive-scanning)
3. [Supported Protocols](#3-supported-protocols)
4. [Supported Vendors & Device Types](#4-supported-vendors--device-types)
5. [Vulnerability Detection](#5-vulnerability-detection)
6. [Installation](#6-installation)
7. [Usage](#7-usage)
8. [Output Formats](#8-output-formats)
9. [Detection & Analysis Pipeline](#9-detection--analysis-pipeline)
10. [Project Structure](#10-project-structure)
11. [Architecture Deep-Dive](#11-architecture-deep-dive)
12. [Vulnerability Reference](#12-vulnerability-reference)
13. [Risk Scoring Model](#13-risk-scoring-model)
14. [Vendor Fingerprinting](#14-vendor-fingerprinting)
15. [Protocol Analyzer Details](#15-protocol-analyzer-details)
16. [Extending the Scanner](#16-extending-the-scanner)
17. [Limitations](#17-limitations)
18. [Legal & Ethical Use](#18-legal--ethical-use)
19. [Dependencies](#19-dependencies)

---

## 1. Overview

RTUs (Remote Terminal Units) and FRTUs (Feeder Remote Terminal Units) are the workhorses of electric grid automation, water treatment, pipeline monitoring, and other critical infrastructure. Unlike PLCs, they:

- Often implement **IEC 60870-5-104** or **DNP3** as primary SCADA protocols
- May participate in **IEC 61850** substation automation (GOOSE protection signalling at Layer 2, MMS configuration over TCP/102)
- Are frequently deployed in harsh environments with limited patching capability
- Run on embedded firmware with long service lives (10–25 years)

This scanner helps security teams identify:

| What                           | How (passive)                                     |
|--------------------------------|---------------------------------------------------|
| RTU/FRTU device inventory      | Protocol fingerprinting, OUI lookup               |
| Missing Secure Authentication  | Absence of DNP3 SA function codes, no IEC 62351  |
| Unencrypted control channels   | Cleartext IEC-104, MMS without TLS detected       |
| GOOSE security weaknesses      | Simulation flag, low TTL, confRev drift           |
| Unsafe command patterns        | Direct Operate (bypass SBO), file transfers       |
| Network hygiene issues         | Multiple masters, excessive peers                 |

---

## 2. Why Passive Scanning?

Active scanners send probe packets. In OT environments this is dangerous:

- **Protection relays** can misinterpret unsolicited packets as control commands
- **DNP3 outstations** may trip into fault mode on malformed requests
- **GOOSE publishers** may flood on unexpected traffic bursts
- **IEC-104 sessions** are single-master — injected connections break live comms

This scanner reads a PCAP file captured via a **SPAN port**, **network TAP**, or **historian capture** and performs all analysis offline. Nothing is sent to the network. The same PCAP used for forensic investigation can be fed directly into this scanner.

---

## 3. Supported Protocols

| Protocol              | Transport                 | Port(s)           | Notes                                     |
|-----------------------|---------------------------|-------------------|-------------------------------------------|
| DNP3                  | TCP, UDP                  | 20000, 10001-10002| Stateful; tracks SA, control commands    |
| IEC 60870-5-104       | TCP                       | 2404              | Stateful; tracks masters, command types  |
| IEC 61850 MMS         | TCP                       | 102               | ASN.1 BER; identifies LN names           |
| IEC 61850 GOOSE       | Ethernet (EtherType 0x88B8)| —               | Layer-2; full PDU parsing                |
| IEC 61850 SV          | Ethernet (EtherType 0x88BA)| —               | Layer-2; presence detection              |
| Modbus/TCP            | TCP                       | 502               | MEI device identification                |
| SEL Fast Message      | TCP                       | 702               | SEL-exclusive; FC 0xB0 flagged           |
| Omron FINS            | UDP                       | 9600              | Omron-exclusive                          |
| MELSEC MC Protocol    | TCP                       | 5006, 5007        | Mitsubishi-exclusive; 3E/4E frames       |
| OPC-UA                | TCP                       | 4840              | Port tracking only                       |
| ICCP / TASE.2         | TCP                       | 2000, 2001        | Port tracking only                       |
| EtherNet/IP           | TCP                       | 44818             | Port tracking                            |
| BACnet/IP             | UDP                       | 47808             | Port tracking                            |
| Niagara Fox           | TCP                       | 1911              | Port tracking                            |

---

## 4. Supported Vendors & Device Types

### Vendors Fingerprinted

| Vendor                     | Method                              | Device Types Identified       |
|----------------------------|-------------------------------------|-------------------------------|
| ABB                        | OUI, DNP3/Modbus strings, GOOSE gcbRef (REF, REC, REL, RED, RET, RAR) | RTU560, RTU500, REF615, REL670 |
| GE Grid Solutions          | OUI, CIP vendor ID, GOOSE gcbRef (P64, T60, L90) | D20MX, D200, UR-series |
| Siemens                    | OUI, protocol strings, GOOSE gcbRef (7SL, 7SD, 7UT, 7SA) | SICAM RTU, SIPROTEC          |
| Schneider Electric         | OUI, Modbus MEI, GOOSE (PRO, P14, P24) | SCADAPack, Easergy, MiCOM   |
| SEL (Schweitzer)           | SEL Fast Message (exclusive), OUI, GOOSE (SEL) | SEL-3505, SEL-651R, SEL-421 |
| Emerson                    | OUI, protocol strings              | ROC-800, ControlWave, Bristol|
| Honeywell                  | OUI, protocol strings              | RTU2020, Experion            |
| Eaton / Cooper             | OUI                                | FRTU devices                 |
| Noja Power                 | OUI, protocol strings              | RC-10 FRTU                   |
| Landis+Gyr                 | OUI, protocol strings              | Advanced Metering devices    |
| Mitsubishi Electric        | MELSEC MC (exclusive)              | MELSEC RTU series            |
| Omron                      | FINS (exclusive)                   | CS1/CJ RTUs                  |
| Yokogawa                   | OUI, protocol strings              | Field controllers            |
| Hirschmann / Belden        | OUI                                | RUGGEDCOM gateways           |
| Rockwell Automation        | OUI, EtherNet/IP                   | RTU/PLC hybrids              |

### Device Type Classification

| Device Type    | Description                                                     |
|----------------|-----------------------------------------------------------------|
| RTU            | Remote Terminal Unit — SCADA field device (DNP3, IEC-104)      |
| FRTU           | Feeder RTU — Distribution automation device                    |
| IED            | Intelligent Electronic Device — Protection/control relay        |
| Relay          | Protection relay (SEL, Siemens SIPROTEC, GE Multilin)          |
| Gateway        | Protocol gateway or RTU concentrator                           |

---

## 5. Vulnerability Detection

Unlike the PLC scanner which focuses on device identification, this scanner performs **active vulnerability assessment** from passive traffic. Findings are generated when PCAP evidence confirms:

### DNP3 Vulnerabilities

| ID             | Severity  | Trigger Condition                                              |
|----------------|-----------|----------------------------------------------------------------|
| RTU-DNP3-001   | High      | No SA challenges (FC 0x20/0x21/0x83) ever seen in session     |
| RTU-DNP3-002   | Critical  | Control commands (FC 3–6) sent without preceding SA exchange   |
| RTU-DNP3-003   | High      | Direct Operate (FC 5) used — bypasses Select-Before-Operate    |
| RTU-DNP3-004   | High      | Cold/Warm Restart (FC 13/14), Stop/Start App (FC 17/18) sent  |
| RTU-DNP3-005   | Critical  | File Open (FC 25) observed — firmware injection risk           |
| RTU-DNP3-006   | High      | More than 2 distinct master IPs talking to the outstation      |
| RTU-DNP3-007   | Medium    | DNP3 session observed over UDP (replay-injection risk)         |

### IEC 60870-5-104 Vulnerabilities

| ID             | Severity  | Trigger Condition                                              |
|----------------|-----------|----------------------------------------------------------------|
| RTU-104-001    | High      | IEC-104 APDU seen without a TLS handshake (IEC 62351-3)       |
| RTU-104-002    | High      | More than 2 master IPs open STARTDT sessions                   |
| RTU-104-003    | Critical  | Control commands (type 45/46/47/48–50) observed in cleartext   |
| RTU-104-004    | Medium    | Clock Sync (type 103) not preceded by any authentication       |
| RTU-104-005    | Low       | General Interrogation (type 100) requested more than 20 times  |

### IEC 61850 Vulnerabilities

| ID             | Severity  | Trigger Condition                                              |
|----------------|-----------|----------------------------------------------------------------|
| RTU-61850-001  | Critical  | GOOSE frames have no IEC 62351-6 security tag (Reserved1 ≠ 0) |
| RTU-61850-002  | Critical  | GOOSE `simulation = TRUE` bit observed in live traffic         |
| RTU-61850-003  | Medium    | GOOSE `timeAllowedToLive` ≤ 2000 ms detected                  |
| RTU-61850-004  | Medium    | GOOSE `confRev` value changes across packets                   |
| RTU-61850-006  | High      | MMS (TCP/102) session detected without TLS (IEC 62351-4)       |

### General / Cross-Protocol Vulnerabilities

| ID             | Severity  | Trigger Condition                                              |
|----------------|-----------|----------------------------------------------------------------|
| RTU-GEN-001    | High      | Unencrypted industrial protocol(s) exposed on this device      |
| RTU-GEN-002    | Medium    | Three or more different protocols detected on one device       |
| RTU-GEN-003    | Low       | Industrial ports open but no protocol payload successfully parsed |
| RTU-GEN-004    | Medium    | More than 10 distinct IP peers communicating with this device  |

---

## 6. Installation

### Prerequisites

- Python **3.8 or later**
- One of: **scapy** (preferred) or **dpkt** (fallback)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or install individually:

```bash
pip install scapy>=2.5.0 dpkt>=1.9.8 colorama>=0.4.6
```

> **Windows note:** On Windows, scapy requires WinPcap or Npcap for live capture. For offline PCAP reading (the intended use case), Npcap is not required — scapy reads files natively.

### Capture Requirements

For best results, capture traffic from:

| Collection point              | Protocols captured                           |
|-------------------------------|----------------------------------------------|
| SPAN / mirror port on OT switch | All IP protocols + Layer-2 GOOSE/SV      |
| Network TAP (passive)         | All IP protocols + Layer-2 GOOSE/SV          |
| RTU serial port converter TAP | DNP3 serial / IEC-104 serial                 |
| Historian / data concentrator | IP-transported protocols (DNP3, IEC-104)     |

> **GOOSE requires Ethernet frame access.** If your capture tool discards Layer-2 frames before IP, GOOSE traffic will not be captured. Use a physical TAP or a mirror port that includes non-IP multicast traffic.

---

## 7. Usage

### Basic Scan

```bash
python rtu_scanner.py substation_traffic.pcap
```

Produces three files: `rtu_scan_results.json`, `rtu_scan_results.csv`, `rtu_scan_results.html`.

### HTML Report Only

```bash
python rtu_scanner.py capture.pcapng -f html -o substation_2024
```

### Verbose Mode

```bash
python rtu_scanner.py traffic.pcap -v
```

Prints each protocol detection as packets are processed — useful for debugging detection logic.

### Minimum Packet Threshold

```bash
python rtu_scanner.py traffic.pcap --min-packets 5
```

Suppresses devices seen in fewer than 5 packets (reduces noise from broadcast/ARP).

### JSON Output for Pipeline Integration

```bash
python rtu_scanner.py traffic.pcap -f json -o findings
python python-script.py findings.json  # post-process with your tooling
```

### Command Reference

```
usage: rtu_scanner.py [-h] [-o PREFIX] [-f {json,csv,html,all}] [-v] [--min-packets N] PCAP_FILE

positional arguments:
  PCAP_FILE             Path to the .pcap / .pcapng capture file

optional arguments:
  -h, --help            Show this help message and exit
  -o PREFIX, --output PREFIX
                        Output filename prefix (default: rtu_scan_results)
  -f {json,csv,html,all}, --format {json,csv,html,all}
                        Report format (default: all)
  -v, --verbose         Print per-packet protocol detections
  --min-packets N       Minimum packet count to include a device (default: 1)
```

---

## 8. Output Formats

### JSON

Full machine-readable report, one object per device. Includes all protocol detection details, all vulnerability findings (with evidence, remediation, and references), and risk scoring.

```json
{
  "scan_metadata": {
    "tool": "RTU / FRTU Passive Vulnerability Scanner",
    "version": "1.0",
    "scan_file": "substation_traffic.pcap",
    "timestamp": "2024-01-15T09:30:00",
    "total_devices": 4,
    "total_vulnerabilities": 12
  },
  "devices": [
    {
      "ip": "10.1.1.10",
      "mac": "00:1A:8C:12:34:56",
      "vendor": "ABB",
      "rtu_make": "ABB",
      "rtu_model": "RTU560",
      "device_type": "RTU",
      "dnp3_address": 5,
      "risk_level": "critical",
      "risk_score": 26,
      "vulnerabilities": [
        {
          "vuln_id": "RTU-DNP3-002",
          "title": "Unauthenticated DNP3 Control Commands",
          "severity": "critical",
          "category": "command-security",
          "description": "2 control command(s) observed with no Secure Authentication",
          "evidence": {
            "control_commands": 2,
            "auth_challenges": 0,
            "session_key": ["10.1.1.1", "10.1.1.10"]
          },
          "remediation": "Enable DNP3 Secure Authentication v5 or v6 per IEEE 1815-2012 and IEC 62351-5.",
          "references": ["IEC 62351-5", "IEEE 1815-2012", "NERC CIP-007"]
        }
      ]
    }
  ]
}
```

### CSV

One row per device, columns: `ip`, `mac`, `vendor`, `rtu_make`, `rtu_model`, `device_type`, `protocols`, `open_ports`, `dnp3_address`, `iec104_address`, `risk_level`, `risk_score`, `vuln_count`, `critical_vulns`, `high_vulns`, `medium_vulns`, `low_vulns`, `vuln_ids`, `master_stations`, `packet_count`.

Ideal for importing into Excel, Splunk, or a CMDB.

### HTML

Standalone dark-themed interactive report requiring no external dependencies. Features:

- **Summary banner** — total devices, total vulnerabilities, risk breakdown
- **Per-device cards** — expandable rows showing all detail
- **Vulnerability cards** — colour-coded by severity (red=critical, orange=high, yellow=medium, cyan=low)
- **Evidence collapsibles** — PCAP-derived data backing each finding
- **Remediation text** — actionable steps with regulatory references
- **Sortable protocol list** — all detected protocols per device

---

## 9. Detection & Analysis Pipeline

```
 PCAP / PCAPNG File
        │
        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                     PCAPAnalyzer                             │
 │                                                              │
 │  ┌─── For each Ethernet frame: ────────────────────────┐    │
 │  │                                                      │    │
 │  │   EtherType == 0x88B8 ──► GOOSEAnalyzer             │    │
 │  │   EtherType == 0x88BA ──► SVAnalyzer                 │    │
 │  │                                                      │    │
 │  │   EtherType == 0x0800 (IP)                           │    │
 │  │     │                                                │    │
 │  │     ├── TCP/20000  ──► DNP3Analyzer (stateful)       │    │
 │  │     ├── TCP/2404   ──► IEC104Analyzer (stateful)     │    │
 │  │     ├── TCP/102    ──► IEC61850MmsAnalyzer            │    │
 │  │     ├── TCP/502    ──► ModbusAnalyzer                 │    │
 │  │     ├── TCP/702    ──► SELProtocolAnalyzer            │    │
 │  │     ├── UDP/9600   ──► (port tracked)                 │    │
 │  │     └── TCP/5006-7 ──► (port tracked)                │    │
 │  └──────────────────────────────────────────────────────┘    │
 │                                                              │
 │  ┌─── Post-processing (after all packets): ─────────────┐   │
 │  │                                                       │   │
 │  │   Link GOOSE publishers to IP devices (by MAC)        │   │
 │  │   FingerprintEngine.fingerprint(device) per device    │   │
 │  │     → Exclusive protocol check                        │   │
 │  │     → Vendor string matching                          │   │
 │  │     → GOOSE gcbRef prefix lookup                      │   │
 │  │     → MAC OUI lookup (fallback)                       │   │
 │  │                                                       │   │
 │  │   VulnerabilityEngine.assess(device) per device       │   │
 │  │     → run_dnp3_checks()     (RTU-DNP3-001…007)        │   │
 │  │     → run_iec104_checks()   (RTU-104-001…005)         │   │
 │  │     → run_iec61850_checks() (RTU-61850-001…006)       │   │
 │  │     → run_general_checks()  (RTU-GEN-001…004)         │   │
 │  │     → De-duplicate, sort by severity                  │   │
 │  │     → Calculate risk score and risk level             │   │
 │  └───────────────────────────────────────────────────────┘   │
 └──────────────────────────────────────────────────────────────┘
        │
        ▼
 ┌──────────────────────────────────────┐
 │         ReportGenerator              │
 │  print_summary()                     │
 │  to_json(prefix.json)                │
 │  to_csv(prefix.csv)                  │
 │  to_html(prefix.html)                │
 └──────────────────────────────────────┘
```

**Key design principle:** Protocol analyzers for DNP3 and IEC-104 are **stateful**. They accumulate session state across all packets in the capture. After the last packet is processed, the vulnerability engine inspects the full accumulated state to detect patterns that span multiple packets (e.g., "control commands sent with no SA exchange in the entire session").

---

## 10. Project Structure

```
rtu_passive_scanner/
│
├── rtu_scanner.py                  ← CLI entry point (run this)
├── requirements.txt                ← Python dependencies
├── README.md                       ← This file
│
└── scanner/
    ├── __init__.py
    ├── models.py                   ← RTUDevice, VulnerabilityFinding,
    │                                  DNP3SessionState, IEC104SessionState,
    │                                  GOOSEPublisherState, ProtocolDetection
    ├── core.py                     ← PCAPAnalyzer: PCAP reading, packet dispatch,
    │                                  Layer-2 GOOSE/SV handling, finalisation
    │
    ├── protocols/
    │   ├── __init__.py
    │   ├── base.py                 ← BaseProtocolAnalyzer + BaseL2Analyzer ABCs
    │   ├── dnp3.py                 ← DNP3 analyzer (stateful; SA, command tracking)
    │   ├── iec104.py               ← IEC 60870-5-104 (stateful; command tracking)
    │   ├── iec61850_mms.py         ← IEC 61850 MMS over TCP/102 (ASN.1 BER)
    │   ├── goose.py                ← IEC 61850 GOOSE (Layer-2) + SV analyzer
    │   ├── modbus.py               ← Modbus/TCP with MEI device identification
    │   └── sel_protocol.py         ← SEL Fast Message over TCP/702
    │
    ├── vuln/
    │   ├── __init__.py
    │   ├── dnp3_checks.py          ← RTU-DNP3-001 … RTU-DNP3-007
    │   ├── iec104_checks.py        ← RTU-104-001  … RTU-104-005
    │   ├── iec61850_checks.py      ← RTU-61850-001 … RTU-61850-006
    │   ├── general_checks.py       ← RTU-GEN-001  … RTU-GEN-004
    │   └── engine.py               ← VulnerabilityEngine: orchestrate, score, rank
    │
    ├── fingerprint/
    │   ├── __init__.py
    │   ├── oui_db.py               ← 120+ ICS/RTU OUI entries, lookup_oui()
    │   └── engine.py               ← FingerprintEngine: multi-source identification
    │
    └── report/
        ├── __init__.py
        └── generator.py            ← ReportGenerator: JSON / CSV / HTML output
```

---

## 11. Architecture Deep-Dive

### 11.1 Stateful Protocol Analyzers

The PLC scanner uses stateless analyzers — each packet is analysed independently. The RTU scanner introduces **stateful analyzers** to detect multi-packet security patterns:

```python
# DNP3Analyzer maintains a dict of session states
self._sessions: Dict[Tuple[str, str], DNP3SessionState] = {}

# Per-session state accumulates across the entire capture
session.auth_challenges   # FC 0x20 count
session.direct_operate    # FC 5 occurrences (bypass SBO)
session.file_opens        # FC 25 occurrences (firmware injection)
```

The vulnerability engine is called **after all packets are processed** and receives the full accumulated state:

```python
# After all packets:
dnp3_sessions   = self._dnp3_analyzer.get_sessions()
iec104_sessions = self._iec104_analyzer.get_sessions()
goose_pubs      = self._goose_analyzer.get_sessions()

for device in results:
    self._vuln_engine.assess(
        device,
        dnp3_sessions=dnp3_sessions,
        iec104_sessions=iec104_sessions,
        goose_publishers=goose_pubs,
        mms_device_ips=self._mms_ips,
    )
```

### 11.2 Layer-2 GOOSE Handling

GOOSE operates below IP — it is a raw Ethernet multicast with EtherType `0x88B8`. The core engine handles this **before** the standard IP processing path:

```python
# In the scapy reader loop:
eth_type = pkt[Ether].type

if eth_type == ETH_GOOSE:        # 0x88B8
    raw = bytes(pkt[Ether].payload)
    result = self._goose_analyzer.analyze_frame(src_mac, dst_mac, eth_type, raw, ts)
    self._handle_goose_result(src_mac, result, ts)
    continue                      # Do not process as IP

if eth_type == ETH_SV:           # 0x88BA
    self._sv_analyzer.analyze_frame(src_mac, dst_mac, eth_type, raw, ts)
    continue
```

After all packets are processed, `_link_goose_to_devices()` matches each GOOSE publisher (keyed by `(src_mac, app_id)`) to an `RTUDevice` by MAC address.

### 11.3 GOOSE PDU Parsing

The GOOSE PDU is ASN.1 BER encoded. The scanner implements a full TLV parser:

```
GOOSE Frame on wire:
  ┌────────┬────────┬──────────┬──────────┬─────────────────────────┐
  │ AppID  │ Length │ Reserved1│ Reserved2│ PDU (ASN.1 Application  │
  │ 2 bytes│ 2 bytes│ 2 bytes  │ 2 bytes  │ [1] = tag 0x61)         │
  └────────┴────────┴──────────┴──────────┴─────────────────────────┘
                                          │
                                          ▼
                             ASN.1 context tags:
                             0x80 gocbRef   (source IED + control block)
                             0x81 TTL       (timeAllowedToLive, ms)
                             0x82 datSet    (dataset name)
                             0x83 goID      (GOOSE identifier)
                             0x84 t         (UTC timestamp)
                             0x85 stNum     (state number — trip detection)
                             0x86 sqNum     (sequence number)
                             0x87 simulation (TRUE = test mode in live = VULN)
                             0x88 confRev   (configuration revision)
                             0x89 ndsCom    (needs commissioning = misconfigured)
                             0x8A numDatSetEntries
                             0xAB allData   (actual values, not parsed)
```

Security tag detection: `Reserved1 != 0` indicates IEC 62351-6 authentication is present. If both Reserved fields are 0x0000, authentication is absent — **RTU-61850-001**.

### 11.4 Vulnerability Engine

The engine applies checks in module order, then applies post-processing:

```python
def assess(self, device, dnp3_sessions, iec104_sessions, goose_publishers, mms_device_ips):
    findings = []
    findings += run_dnp3_checks(device, dnp3_sessions)       # if DNP3 detected
    findings += run_iec104_checks(device, iec104_sessions)   # if IEC-104 detected
    findings += run_iec61850_checks(device, goose_publishers, mms_device_ips)
    findings += run_general_checks(device)                   # always

    # De-duplicate by vuln_id (keep highest packet_count)
    findings = _dedup(findings)

    # Sort: critical > high > medium > low > info
    findings.sort(key=lambda f: -SEVERITY_WEIGHT.get(f.severity, 0))

    # Aggregate score
    device.risk_score = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    device.risk_level = _score_to_level(device.risk_score)
```

### 11.5 Distinguishing MMS from S7comm

Both protocols run on TCP port 102. The MMS analyzer distinguishes them by inspecting the COTP DT payload for the S7 protocol ID byte (`0x32`). If present, the analyzer returns without processing (letting the PLC scanner's S7 analyzer handle it). If absent, the payload is parsed as MMS ASN.1.

---

## 12. Vulnerability Reference

### RTU-DNP3-001 — No DNP3 Secure Authentication

**Severity:** High
**Category:** Authentication

**What it means:** DNP3 Secure Authentication (SAv5 defined in IEEE 1815-2012 / IEC 62351-5) was never observed in the captured session. Without SA, any device on the OT network can send valid DNP3 control commands.

**Evidence collected:** Count of SA challenge frames (FC 0x20), SA reply frames (FC 0x21), and Aggressive Mode frames (FC 0x83) across the session.

**Remediation:**
- Upgrade RTU firmware to support DNP3 SAv5 or SAv6
- Configure master station to require authentication before accepting responses
- Apply HMAC-SHA-256 or AES-GMAC as the authentication algorithm

**References:** IEC 62351-5, IEEE 1815-2012, NERC CIP-007 R5

---

### RTU-DNP3-002 — Unauthenticated Control Commands

**Severity:** Critical
**Category:** Command Security

**What it means:** Control commands (Select FC 3, Operate FC 4, Direct Operate FC 5, Direct Operate No Ack FC 6) were observed in a session where no Secure Authentication exchange was ever recorded. An attacker with network access can replicate this pattern to send arbitrary control commands.

**Remediation:**
- Enable DNP3 Secure Authentication before allowing control commands
- Implement network segmentation (firewall between master station and RTUs)
- Deploy OT-aware intrusion detection to alert on control commands from unexpected sources

---

### RTU-DNP3-003 — Direct Operate Bypasses Select-Before-Operate

**Severity:** High
**Category:** Command Security

**What it means:** The master station uses Direct Operate (FC 5) which skips the mandatory Select-Before-Operate two-step safety mechanism. SBO ensures the outstation "selects" (arms) a point before it can be "operated" (commanded), providing a safety check window.

**Remediation:**
- Configure master station SCADA software to use SBO (Select + Operate, FC 3 + FC 4)
- Disable Direct Operate at the RTU if the vendor firmware supports this restriction

---

### RTU-DNP3-004 — Unauthenticated Restart / Maintenance Commands

**Severity:** High
**Category:** Availability

**What it means:** Restart (Cold Restart FC 13, Warm Restart FC 14) or application-level start/stop commands (FC 17, FC 18) were observed. Without authentication, an attacker can force RTU restarts, causing outages.

---

### RTU-DNP3-005 — Unauthenticated File Transfer

**Severity:** Critical
**Category:** Integrity

**What it means:** DNP3 File Open (FC 25) was observed — this mechanism is used for firmware uploads, configuration file transfers, and event log retrieval. Without authentication, an attacker can replace the RTU's firmware or configuration file.

---

### RTU-DNP3-006 — Multiple DNP3 Masters

**Severity:** High
**Category:** Misconfiguration

**What it means:** More than two distinct IP addresses are issuing DNP3 commands to this outstation. RTUs are typically served by a primary and backup master station. Additional masters may indicate an unauthorised system.

---

### RTU-DNP3-007 — DNP3 over UDP

**Severity:** Medium
**Category:** Protocol

**What it means:** DNP3 was detected over UDP rather than TCP. UDP provides no connection state, making sessions trivially spoofable. DNP3 over UDP is particularly vulnerable to replay attacks.

---

### RTU-104-001 — IEC-104 without TLS (IEC 62351-3 Violation)

**Severity:** High
**Category:** Encryption

**What it means:** IEC 60870-5-104 APDU was detected in cleartext without a preceding TLS handshake. IEC 62351-3 mandates TLS for IEC-104 to protect data confidentiality and integrity.

**Remediation:**
- Deploy IEC 62351-3 TLS 1.2 or 1.3 for all IEC-104 sessions
- Use client certificate authentication to prevent rogue master connections
- If TLS is not supportable on the existing RTU, implement a TLS-offloading gateway

---

### RTU-104-003 — Cleartext Control Commands (IEC-104)

**Severity:** Critical
**Category:** Command Security / Encryption

**What it means:** Control commands (Single Command type 45, Double Command type 46, Regulating Step type 47, Setpoint types 48–50) were observed in unencrypted IEC-104 sessions. These commands can open/close breakers and adjust setpoints.

---

### RTU-61850-001 — GOOSE without IEC 62351-6 Authentication

**Severity:** Critical
**Category:** Authentication / Protocol

**What it means:** IEC 61850 GOOSE messages carry protection trip signals (breaker open/close, fault notification) with no authentication. Any device on the substation LAN can inject a forged GOOSE message that causes a breaker to trip, potentially causing a blackout.

The lack of IEC 62351-6 authentication is detected by checking the `Reserved1` field in the GOOSE Ethernet header. When authentication is present, this field carries the security extension indicator (non-zero). When zero, no authentication is applied.

**Remediation:**
- Upgrade IED firmware to support IEC 62351-6 GOOSE authentication
- Deploy a GOOSE firewall / OT-aware switch that validates GOOSE message signatures
- VLAN-isolate substation LAN and restrict physical access

**References:** IEC 62351-6, IEC 61850-8-1, CIGRE WG B5.38

---

### RTU-61850-002 — GOOSE Simulation Flag in Live Traffic

**Severity:** Critical
**Category:** Protocol / Misconfiguration

**What it means:** The `simulation` bit in a GOOSE message was set to `TRUE` while the message was observed on the operational network. The IEC 61850 standard specifies that receivers **shall ignore** GOOSE messages with `simulation = TRUE` for actual control purposes. An attacker exploiting this can send trip signals that are accepted by test equipment but ignored by production IEDs — or conversely, can flood the network with simulation messages to trigger IED test routines.

**Remediation:**
- Verify that test/commissioning GOOSE publishers are isolated from the operational network
- Implement network segmentation between test and production segments
- Configure IEDs to reject simulation GOOSE on production VLANs

---

### RTU-61850-003 — GOOSE Low timeAllowedToLive

**Severity:** Medium
**Category:** Availability

**What it means:** The `timeAllowedToLive` (TTL) field in observed GOOSE messages was ≤ 2000 ms. This means if GOOSE messages stop (e.g., publisher RTU fails or link drops), the receiving IED will consider the data stale and take a default action within 2 seconds. Very low TTLs increase the risk of nuisance trips during brief network interruptions.

---

### RTU-61850-004 — GOOSE confRev Changes

**Severity:** Medium
**Category:** Misconfiguration

**What it means:** The `confRev` (configuration revision) field changed values across observed GOOSE messages from the same publisher. `confRev` increments when the GOOSE Control Block configuration changes. Unexpected changes may indicate an uncoordinated configuration update or an attempt to confuse IED receivers.

---

### RTU-61850-006 — MMS without TLS (IEC 62351-4 Violation)

**Severity:** High
**Category:** Encryption

**What it means:** IEC 61850 MMS (Manufacturing Message Specification) sessions were detected on TCP/102 without TLS encryption. MMS carries IED configuration, logical node status, and control messages. IEC 62351-4 mandates TLS for MMS.

---

## 13. Risk Scoring Model

Each vulnerability finding contributes a weighted score:

| Severity | Weight |
|----------|--------|
| Critical | 10     |
| High     | 6      |
| Medium   | 3      |
| Low      | 1      |
| Info     | 0      |

The aggregate score maps to a risk level:

| Score    | Risk Level |
|----------|------------|
| ≥ 20     | Critical   |
| ≥ 10     | High       |
| ≥ 4      | Medium     |
| ≥ 1      | Low        |

**Example:** A device with RTU-DNP3-002 (Critical=10) + RTU-104-001 (High=6) + RTU-61850-001 (Critical=10) = score 26 → **Critical risk level**.

De-duplication: If the same vulnerability ID is triggered by multiple sessions, only the highest-evidence instance is retained in the final report.

---

## 14. Vendor Fingerprinting

The fingerprinting engine applies four evidence sources in priority order:

### Source 1 — Exclusive Protocol (Highest Confidence)

Some protocols are used by only one vendor family:

| Protocol          | Vendor             | Confidence |
|-------------------|--------------------|------------|
| SEL Fast Message  | SEL                | High       |
| Omron FINS        | Omron              | High       |
| MELSEC MC Protocol| Mitsubishi Electric| High       |

### Source 2 — Embedded Vendor Strings

DNP3 Group 0 (Device Attributes) and Modbus MEI (FC43/0x0E) responses embed vendor names and product codes in plaintext. The engine extracts these and matches against a keyword table:

| Keyword     | Vendor Identified     |
|-------------|-----------------------|
| `schweitzer`| SEL                   |
| `sel-`      | SEL                   |
| `abb`       | ABB                   |
| `ge `       | GE Grid Solutions     |
| `multilin`  | GE Grid Solutions     |
| `siemens`   | Siemens               |
| `sicam`     | Siemens               |
| `schneider` | Schneider Electric    |
| `scadapack` | Schneider Electric    |
| `easergy`   | Schneider Electric    |
| `emerson`   | Emerson               |
| `bristol`   | Emerson (Bristol)     |
| `controlwave`| Emerson (ControlWave)|
| `honeywell` | Honeywell             |
| `noja`      | Noja Power            |
| `landis`    | Landis+Gyr            |

### Source 3 — GOOSE gcbRef Prefix

The GOOSE Control Block Reference (gcbRef) encodes the IED name, which follows vendor naming conventions:

| Prefix | Vendor             | Typical IED            |
|--------|--------------------|------------------------|
| `REF`  | ABB                | REF615 feeder protection|
| `REC`  | ABB                | REC615 bay controller  |
| `REL`  | ABB                | REL670 line protection  |
| `RED`  | ABB                | RED670 differential     |
| `RET`  | ABB                | RET670 transformer      |
| `SEL`  | SEL                | SEL-xxx IEDs           |
| `P64`  | GE Grid Solutions  | MiCOM P643             |
| `T60`  | GE Grid Solutions  | Transformer relay      |
| `7SL`  | Siemens            | SIPROTEC 7SL           |
| `7SD`  | Siemens            | SIPROTEC 7SD           |
| `7UT`  | Siemens            | SIPROTEC 7UT           |
| `7SA`  | Siemens            | SIPROTEC 7SA           |
| `PRO`  | Schneider Electric | MiCOM Pro series       |

### Source 4 — MAC OUI Lookup (Fallback)

The OUI database contains 120+ entries for ICS and RTU manufacturers. The scanner normalises all MAC formats (`00:1A:8C`, `00-1A-8C`, `001A8C`) before lookup.

---

## 15. Protocol Analyzer Details

### 15.1 DNP3 Analyzer

DNP3 (Distributed Network Protocol 3) is the dominant SCADA protocol for electric utilities in North America and increasingly worldwide.

**Frame structure:**

```
DNP3 Data Link Frame:
  ┌──────┬──────┬──────┬─────────┬──────────┬──────────┬─────────────┐
  │ 0x05 │ 0x64 │ LEN  │ CTRL    │ DST ADDR │ SRC ADDR │ CRC + Data  │
  │  1B  │  1B  │  1B  │  1B     │  2B LE   │  2B LE   │             │
  └──────┴──────┴──────┴─────────┴──────────┴──────────┴─────────────┘
  Sync bytes     Len   DL flags  Outstation   Master
```

**Security-relevant function codes tracked:**

| FC   | Hex  | Name                    | Security Relevance           |
|------|------|-------------------------|------------------------------|
| 3    | 0x03 | Select                  | Part of SBO — normal         |
| 4    | 0x04 | Operate                 | Part of SBO — normal         |
| 5    | 0x05 | Direct Operate          | **SBO bypass** — RTU-DNP3-003|
| 6    | 0x06 | Direct Operate No Ack   | SBO bypass + silent          |
| 13   | 0x0D | Cold Restart            | Service disruption           |
| 14   | 0x0E | Warm Restart            | Service disruption           |
| 17   | 0x11 | Start Application       | Remote code execution risk   |
| 18   | 0x12 | Stop Application        | Service disruption           |
| 25   | 0x19 | Open File               | **Firmware injection**        |
| 32   | 0x20 | Authenticate Challenge  | SA present (good)            |
| 33   | 0x21 | Authenticate Reply      | SA present (good)            |
| 131  | 0x83 | Aggressive Mode         | SAv5 present (good)          |

### 15.2 IEC 60870-5-104 Analyzer

IEC-104 is the dominant SCADA protocol in Europe and Asia-Pacific. It runs over TCP, typically on a dedicated connection between a single master station and each RTU.

**APDU structure:**

```
IEC-104 APDU:
  ┌───────┬──────┬──────────────────────────┐
  │ 0x68  │ LEN  │ APCI (4 bytes control)   │
  └───────┴──────┴──────────────────────────┘
               │
               ├── I-frame (Info): seq numbered data
               ├── S-frame (Supervisory): ACK
               └── U-frame (Unnumbered): STARTDT/STOPDT/TESTFR

I-frame ASDU:
  ┌─────────┬──────────┬──────┬───────────────────┐
  │ Type ID │ SQ+count │ COT  │ Common Address    │
  │  1 byte │  2 bytes │ 2B   │   2 bytes         │
  └─────────┴──────────┴──────┴───────────────────┘
```

**Control command type IDs tracked:**

| Type ID | Name                        | Severity       |
|---------|-----------------------------|----------------|
| 45      | Single Command              | Critical       |
| 46      | Double Command              | Critical       |
| 47      | Regulating Step Command     | Critical       |
| 48      | Setpoint (scaled)           | Critical       |
| 49      | Setpoint (normalised)       | Critical       |
| 50      | Setpoint (short float)      | Critical       |
| 51      | Bitstring Command           | High           |
| 100     | General Interrogation       | Low (if excessive) |
| 103     | Clock Synchronisation       | Medium         |

### 15.3 IEC 61850 GOOSE Analyzer

GOOSE (Generic Object Oriented Substation Event) is a Layer-2 multicast used for fast protection signalling. Trip signals must arrive within milliseconds — GOOSE achieves sub-millisecond delivery by bypassing TCP/IP.

**Destination MAC convention:**
- `01:0C:CD:01:XX:XX` — IEC 61850 GOOSE
- `01:0C:CD:02:XX:XX` — GSSE (obsolete, not analysed)
- `01:0C:CD:04:XX:XX` — Sampled Values

**Key GOOSE security observations:**

| Field          | Normal Value    | Anomaly Detected                        |
|----------------|-----------------|-----------------------------------------|
| Reserved1      | 0x0000          | 0x0000 → no IEC 62351-6 auth (RTU-61850-001) |
| simulation     | FALSE           | TRUE → test mode in live traffic (RTU-61850-002) |
| timeAllowedToLive | > 2000 ms    | ≤ 2000 ms → replay window risk (RTU-61850-003) |
| confRev        | Stable          | Changes observed → config drift (RTU-61850-004) |
| ndsCom         | FALSE           | TRUE → device needs commissioning       |

### 15.4 IEC 61850 MMS Analyzer

MMS (Manufacturing Message Specification, ISO 9506) is the application protocol for IEC 61850 station bus communication. It is used for IED configuration, logical node status reads, and control services.

The scanner identifies MMS by:
1. TCP destination or source port 102
2. Absence of the S7 protocol ID byte (0x32) in the COTP DT payload
3. Presence of ASN.1 application tags: 0x61 (MMS Initiate), 0xA8 (Confirmed-Request), 0xA9 (Confirmed-Response)

IEC 61850 Logical Node prefixes extracted from MMS traffic:

| Prefix | Function                       |
|--------|--------------------------------|
| XCBR   | Circuit breaker                |
| XSWI   | Switch / disconnector          |
| CSWI   | Switch controller              |
| RREC   | Autorecloser                   |
| PDIS   | Distance protection            |
| PTOC   | Overcurrent protection         |
| PDIF   | Differential protection        |
| RBRF   | Breaker failure                |
| MMXU   | Measurement unit               |
| LPHD   | Physical device header         |

### 15.5 SEL Fast Message Analyzer

SEL Fast Message is a proprietary binary protocol used by Schweitzer Engineering Labs (SEL) IEDs on TCP port 702. It is exclusive to SEL devices.

**Frame structure:**

```
SEL Fast Message:
  ┌─────┬──────┬──────┬──────────┬──────────┬──────────┐
  │ SOH │ MSG  │ LEN  │ Device   │ Function │ Data     │
  │0x01 │ Type │ 1B   │ ID 2B    │ Code 1B  │ variable │
  └─────┴──────┴──────┴──────────┴──────────┴──────────┘
```

**FC 0xB0 (Fast Operate Command):** Flagged as a security-relevant event — direct actuation of relay outputs.

---

## 16. Extending the Scanner

### Adding a New Protocol Analyzer

1. Create `scanner/protocols/myprotocol.py` inheriting from `BaseProtocolAnalyzer`:

```python
from .base import BaseProtocolAnalyzer, AnalysisResult

MY_PORT = 12345

class MyProtocolAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport, dport, proto, payload):
        return (proto == "TCP" and
                (sport == MY_PORT or dport == MY_PORT) and
                len(payload) >= 6)

    def analyze(self, src_ip, dst_ip, sport, dport, proto, payload, timestamp):
        device_ip = dst_ip if dport == MY_PORT else src_ip
        # Parse payload ...
        det = self._make_detection(
            protocol="My Protocol",
            port=MY_PORT,
            confidence="high",
            timestamp=timestamp,
            vendor_name="Acme Corp",
        )
        return [(device_ip, det)]
```

2. Register in `scanner/core.py`:

```python
from .protocols.myprotocol import MyProtocolAnalyzer

# In PCAPAnalyzer.__init__():
self._my_analyzer = MyProtocolAnalyzer()
self._ip_analyzers.append(self._my_analyzer)
```

3. Add the port to `INDUSTRIAL_PORTS` in `core.py`.

### Adding a New Vulnerability Check

1. Add a function to the appropriate check module (or create a new one):

```python
# scanner/vuln/myprotocol_checks.py
from ..models import RTUDevice, VulnerabilityFinding

def run_myprotocol_checks(device: RTUDevice, sessions: dict):
    findings = []
    for (master, rtu), sess in sessions.items():
        if rtu != device.ip:
            continue
        if sess.dangerous_condition:
            findings.append(VulnerabilityFinding(
                vuln_id="RTU-MY-001",
                title="My Dangerous Condition",
                severity="high",
                category="authentication",
                description=f"Dangerous condition observed: {sess.dangerous_condition}",
                evidence={"detail": sess.dangerous_condition},
                remediation="Apply fix X.",
                references=["IEC 62351-5", "NERC CIP-007"],
            ))
    return findings
```

2. Import and call from `scanner/vuln/engine.py`:

```python
from .myprotocol_checks import run_myprotocol_checks

# In VulnerabilityEngine.assess():
if "My Protocol" in proto_names:
    findings += run_myprotocol_checks(device, my_sessions)
```

### Adding OUI Entries

Edit `scanner/fingerprint/oui_db.py`:

```python
OUI_DATABASE = {
    # ...existing entries...
    "AC:DE:48": "Private",          # Format: first 3 octets, colon-separated
    "00:E0:4C": "Realtek",
}
```

---

## 17. Limitations

### What Passive Analysis Cannot Detect

| Limitation                               | Explanation                                    |
|------------------------------------------|------------------------------------------------|
| Vulnerabilities in encrypted sessions    | TLS-protected IEC-104/MMS traffic is opaque; presence of TLS is confirmed but content is not inspected |
| Firmware version enumeration             | Requires active querying or OOB data; passive capture only reveals what the device broadcasts in protocol headers |
| Authentication configuration at RTU      | SA may be configured but not yet used in the captured time window |
| Patched vs. unpatched firmware           | Cannot determine CVE exposure without firmware version + CPE matching |
| Physical security posture                | Network capture reveals no information about physical access controls |
| Out-of-band management channels          | Serial console, craft port, or cellular management not visible in Ethernet capture |

### Capture Duration Matters

Short captures (< 5 minutes) may miss:
- DNP3 SA exchanges (may occur only at session start)
- confRev changes (may be infrequent)
- Backup master station connections (activated only on primary failure)

For best results, capture at least 30–60 minutes of normal operational traffic, or capture across a known operational cycle.

### False Positives

- **RTU-DNP3-001:** A DNP3 SA session may have started before the capture window began. The scanner only sees what is in the PCAP.
- **RTU-GEN-004:** High peer counts in historian aggregators and gateway nodes are expected — apply `--min-packets` thresholds and review device role.

---

## 18. Legal & Ethical Use

This tool is designed for **authorised defensive security assessments** of OT/ICS infrastructure.

**Permitted use cases:**
- Security audits of infrastructure you own or manage
- Authorised penetration testing engagements with written permission
- Incident response investigations with appropriate authorisation
- Academic and laboratory research
- CTF competitions and training environments

**Always obtain written authorisation before:**
- Capturing traffic from operational OT networks
- Running any analysis tool in an OT environment
- Sharing captured PCAP files (they contain sensitive operational data)

**Regulatory considerations:**
- NERC CIP-002 through CIP-011 governs cybersecurity for bulk electric system assets
- IEC 62443 applies to industrial automation and control systems
- GDPR / local privacy laws may apply to traffic captures containing personal data
- Capture retention and handling procedures should align with your organisation's data classification policy

---

## 19. Dependencies

| Package         | Version  | Purpose                                      |
|-----------------|----------|----------------------------------------------|
| `scapy`         | ≥ 2.5.0  | Primary PCAP reader (preferred)              |
| `dpkt`          | ≥ 1.9.8  | Fallback PCAP reader if scapy unavailable    |
| `colorama`      | ≥ 0.4.6  | ANSI colour codes on Windows terminal        |

All dependencies are pure Python (no C extensions required for offline PCAP analysis).

**Python compatibility:** Python 3.8 and later. No `str | None` union syntax is used; all type hints use `Optional[str]` from `typing` for 3.8 compatibility.

```bash
# Verify dependencies
python -c "import scapy; print('scapy', scapy.__version__)"
python -c "import dpkt; print('dpkt', dpkt.__version__)"
```

---

*RTU/FRTU Passive Vulnerability Scanner — part of the OT-Security toolkit*
*Defensive use only. No packets sent. Analysis is purely offline.*
