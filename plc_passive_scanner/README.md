# PLC Passive Scanner

> Passively identify industrial Programmable Logic Controllers (PLCs) and OT devices from captured network traffic — without ever sending a single packet to the network.

```
  ____  _     ____   ____                           ____
 |  _ \| |   / ___| |  _ \ __ _ ___ ___(_) __   __|  _ \  ___  ___ _ __
 | |_) | |  | |     | |_) / _` / __/ __| \ \ \ / /| |_) |/ _ \/ __| '_ \
 |  __/| |__| |___  |  __/ (_| \__ \__ \ | |\ V / |  __/|  __/ (__| |_) |
 |_|   |_____\____| |_|   \__,_|___/___/_|_| \_/  |_|    \___|\___| .__/
                                                                     |_|
  Passive PLC & OT Device Scanner  |  Offline PCAP Analysis  |  v1.0
```

---

## Table of Contents

1. [Overview](#overview)
2. [Why Passive Scanning?](#why-passive-scanning)
3. [Supported Protocols](#supported-protocols)
4. [Supported Vendors](#supported-vendors)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Output Formats](#output-formats)
8. [Detection Engine](#detection-engine)
9. [Project Structure](#project-structure)
10. [Architecture Deep-Dive](#architecture-deep-dive)
11. [Risk Scoring](#risk-scoring)
12. [Vendor Fingerprinting](#vendor-fingerprinting)
13. [Protocol Analyzer Details](#protocol-analyzer-details)
14. [Extending the Scanner](#extending-the-scanner)
15. [Limitations](#limitations)
16. [Legal & Ethical Use](#legal--ethical-use)

---

## Overview

**PLC Passive Scanner** is a Python-based offline security analysis tool designed for Operational Technology (OT) / Industrial Control System (ICS) environments. It reads a standard **PCAP or PCAPNG** capture file and identifies industrial PLCs, RTUs, and related devices by analysing their network communications — without generating any network traffic itself.

Key outputs:
- Discovered device inventory (IP, MAC, vendor, model, firmware)
- Protocols in use and detected device roles
- Risk assessment with actionable risk factors
- Reports in **JSON**, **CSV**, and interactive **HTML**

---

## Why Passive Scanning?

Active network scanners (Nmap, Shodan-style probes) are **dangerous in OT environments**:

| Risk | Effect |
|---|---|
| Unexpected TCP/UDP packets | PLCs crash or enter fault state |
| Unrecognised protocol frames | Safety systems trip unexpectedly |
| Network flooding | Causes latency spikes that break real-time control loops |
| ARP probes | Can disrupt deterministic Profinet/EtherNet/IP I/O traffic |

Passive scanning from a PCAP eliminates all of these risks. The capture can be collected via:
- A **network TAP** on the OT switch uplink
- **Port mirroring (SPAN)** on a managed switch
- A dedicated **network sensor** (e.g., a Raspberry Pi with tcpdump)
- Existing **IDS/NDR** appliances that export PCAP recordings

---

## Supported Protocols

| Protocol | Transport | Port(s) | Spec / Standard |
|---|---|---|---|
| **Modbus/TCP** | TCP | 502 | Modbus Application Protocol Specification v1.1b3 |
| **Siemens S7comm** | TCP | 102 | Proprietary (ISO-TSAP / COTP / S7 PDU) |
| **Siemens S7comm+** | TCP | 102 | S7comm with TLS (S7-1200/1500 newer firmware) |
| **EtherNet/IP / CIP** | TCP / UDP | 44818 / 2222 | ODVA EtherNet/IP Specification, CIP Vol.1–3 |
| **DNP3** | TCP / UDP | 20000 | IEEE 1815-2012 |
| **Omron FINS** | UDP | 9600 | Omron W227-E1 FINS Communications Manual |
| **Mitsubishi MELSEC MC** | TCP | 5006, 5007, 5008 | Mitsubishi MELSEC MC Protocol 3E/4E Frame |
| **IEC 60870-5-104** | TCP | 2404 | IEC 60870-5-104:2006 |

Additional ports monitored (no deep parsing, port presence recorded):

| Port | Protocol |
|---|---|
| 4840 | OPC-UA |
| 47808 | BACnet/IP |
| 18245 | GE-SRTP |
| 1911 | Niagara Fox (Tridium) |
| 789 / 34962 / 34963 | Profinet DCP / RT |

---

## Supported Vendors

| Vendor | Primary Protocols | Key Product Lines |
|---|---|---|
| **Siemens** | S7comm, S7comm+, Modbus, IEC-104 | SIMATIC S7-300, S7-400, S7-1200, S7-1500, ET 200 |
| **Rockwell Automation / Allen-Bradley** | EtherNet/IP, Modbus | ControlLogix, CompactLogix, MicroLogix, PLC-5 |
| **Schneider Electric** | Modbus, EtherNet/IP, DNP3, IEC-104 | Modicon M340, M580, Quantum, Premium, EcoStruxure |
| **Mitsubishi Electric** | MELSEC MC Protocol | MELSEC Q, iQ-R, iQ-F (FX5U/FX5UC), L Series |
| **Omron** | FINS, EtherNet/IP | CJ1, CJ2, CS1, NJ, NX, CP Series (Sysmac) |
| **ABB** | Modbus, DNP3, IEC-104, EtherNet/IP | AC500, AC31, Freelance, 800xA |
| **Honeywell** | Modbus, DNP3, EtherNet/IP | ControlEdge PLC, HC900, Safety Manager |
| **GE Automation** | EtherNet/IP, DNP3, Modbus | PACSystems RX3i, RSTi-EP, MDS radios |
| **Yokogawa** | Modbus, EtherNet/IP | CENTUM VP, ProSafe-RS, FA-M3 |
| **Beckhoff** | EtherNet/IP, Modbus | TwinCAT, CX/BK/EK Terminals |
| **WAGO** | EtherNet/IP, Modbus | 750 Series I/O, PFC100/PFC200 |
| **Phoenix Contact** | EtherNet/IP, Modbus | RFC 460R, AXC F, Axioline |

Vendor identification also uses a curated **MAC OUI database** with 130+ ICS-specific entries covering the vendors above plus Moxa, Hirschmann/Belden, HMS/Anybus, Red Lion, Advantech, Pepperl+Fuchs, Turck, Festo, SEL, and others.

---

## Installation

### Requirements

- Python **3.8+**
- One of: **scapy** (recommended) or **dpkt** (fallback)
- Optional: **colorama** (coloured terminal output)

### Install

```bash
# Clone or copy the project
cd plc_passive_scanner

# Install all dependencies
pip install -r requirements.txt

# Or install individually
pip install scapy colorama
```

> **Windows note:** On Windows, scapy requires [Npcap](https://npcap.com/) for live capture — but for PCAP *analysis* (this tool's use case) Npcap is not required. Raw PCAP files are read directly.

> **Linux note:** Reading PCAP files with scapy does not require root/sudo.

### Verify Installation

```bash
python plc_scanner.py --help
```

---

## Usage

### Basic

```bash
python plc_scanner.py <pcap_file>
```

Produces three report files in the current directory:
- `plc_scan_results.json`
- `plc_scan_results.csv`
- `plc_scan_results.html`

### Full Syntax

```
python plc_scanner.py PCAP_FILE [-o PREFIX] [-f FORMAT] [-v] [--min-packets N]

Positional Arguments:
  PCAP_FILE             Path to the .pcap / .pcapng file to analyse

Optional Arguments:
  -o, --output PREFIX   Output filename prefix  (default: plc_scan_results)
  -f, --format FORMAT   Report format: json | csv | html | all  (default: all)
  -v, --verbose         Print per-packet protocol detections during analysis
  --min-packets N       Minimum packet count to include a device  (default: 1)
  -h, --help            Show help and exit
```

### Examples

```bash
# Scan factory traffic, all formats
python plc_scanner.py factory_capture.pcap

# HTML report only, custom output name
python plc_scanner.py substation.pcapng -f html -o substation_report

# Verbose mode — see every detection as it happens
python plc_scanner.py traffic.pcap -v

# Filter out noise — only report devices with 5+ packets
python plc_scanner.py long_capture.pcap --min-packets 5

# JSON only, useful for pipeline/SIEM integration
python plc_scanner.py capture.pcap -f json -o /tmp/plc_inventory
```

---

## Output Formats

### JSON (`plc_scan_results.json`)

Machine-readable, full-detail output. Structure:

```json
{
  "scan_metadata": {
    "pcap_file": "factory.pcap",
    "generated": "2026-03-04T14:30:00",
    "tool": "PLC Passive Scanner v1.0",
    "total_devices": 4
  },
  "risk_summary": { "critical": 1, "high": 2, "medium": 1 },
  "protocol_summary": { "Modbus/TCP": 3, "S7comm": 1 },
  "devices": [
    {
      "ip": "192.168.1.10",
      "mac": "00:1B:1B:AA:BB:CC",
      "vendor": "Siemens AG",
      "vendor_confidence": "high",
      "plc_make": "Siemens",
      "plc_model": "S7-1500",
      "firmware": null,
      "serial_number": null,
      "protocols": [
        {
          "protocol": "S7comm",
          "port": 102,
          "confidence": "high",
          "details": {
            "cotp_pdu_type": "0xE0",
            "rack": 0,
            "slot": 1,
            "connection_type": "Step 7 / TIA Portal"
          },
          "packet_count": 148
        }
      ],
      "open_ports": [102],
      "role": "plc",
      "risk_level": "high",
      "risk_factors": [
        "Unencrypted industrial protocol: S7comm",
        "Legacy S7comm (no confidentiality or integrity protection)"
      ]
    }
  ]
}
```

### CSV (`plc_scan_results.csv`)

Spreadsheet-compatible flat table with one row per device:

| Column | Description |
|---|---|
| `ip` | Device IP address |
| `mac` | MAC address |
| `vendor` | Identified vendor name |
| `vendor_confidence` | high / medium / low / unknown |
| `plc_make` | PLC manufacturer |
| `plc_model` | Specific model (if extracted) |
| `firmware` | Firmware version (if extracted) |
| `serial_number` | Serial number (if extracted) |
| `protocols` | Pipe-delimited protocol list |
| `open_ports` | Pipe-delimited port list |
| `communicating_with_count` | Number of distinct communication peers |
| `first_seen` / `last_seen` | Timestamps from PCAP |
| `packet_count` | Total packets involving device |
| `role` | plc / hmi / gateway / unknown |
| `risk_level` | critical / high / medium / low |
| `risk_factors` | Semicolon-delimited risk descriptions |

### HTML (`plc_scan_results.html`)

A standalone, self-contained **dark-theme interactive report**:

- **Summary cards** — device count, protocol count, risk distribution
- **Protocol breakdown** table
- **Device table** — sortable, with expandable rows per device
- **Expand button** per device reveals:
  - Full network details (MAC, ports, peers, timestamps)
  - Protocol-specific extracted data (CIP vendor, MEI strings, SZL details)
  - Risk factors with visual indicators
- No external dependencies — works fully offline, single `.html` file

---

## Detection Engine

The scanner uses a **three-layer detection pipeline**:

```
PCAP Packets
     │
     ▼
┌─────────────────────────────────────────┐
│  Layer 1 — Packet Dispatch              │
│  • Reads each packet via scapy / dpkt   │
│  • Extracts IP, MAC, sport, dport,      │
│    protocol (TCP/UDP), payload bytes    │
│  • Tracks all devices seen in traffic   │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  Layer 2 — Protocol Analyzers (×7)      │
│  Each analyzer:                          │
│  1. can_analyze() — port + magic check  │
│  2. analyze() — full PDU parse          │
│  3. Returns (device_ip, detection) pairs│
│                                          │
│  Modbus → parse MBAP + FC + MEI strings │
│  S7comm → parse COTP + S7 PDU + SZL    │
│  EtherNet/IP → parse EIP + CIP Identity│
│  DNP3 → parse DL frame + App layer      │
│  FINS → parse header + controller data  │
│  MELSEC → parse 3E/4E frame + CPU type  │
│  IEC-104 → parse APDU + ASDU           │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  Layer 3 — Fingerprinting & Scoring     │
│  • OUI database lookup (MAC → vendor)   │
│  • Protocol metadata → vendor/model     │
│  • Multi-source confidence merging      │
│  • Risk scoring (0-6+ → 4 levels)       │
└─────────────────────────────────────────┘
```

---

## Project Structure

```
plc_passive_scanner/
│
├── plc_scanner.py              # CLI entry point
│                               # argparse, banner, dependency check, report dispatch
│
├── requirements.txt            # scapy, dpkt, colorama
│
└── scanner/
    │
    ├── __init__.py
    │
    ├── models.py               # Data models
    │                           #   PLCDevice        — discovered device state
    │                           #   ProtocolDetection — single protocol observation
    │
    ├── core.py                 # PCAPAnalyzer — main orchestration engine
    │                           #   _analyze_with_scapy()  primary reader
    │                           #   _analyze_with_dpkt()   fallback reader
    │                           #   _handle_packet()       per-packet dispatcher
    │                           #   _apply_fingerprinting()
    │                           #   _score_risk()
    │
    ├── protocols/
    │   ├── __init__.py
    │   ├── base.py             # BaseProtocolAnalyzer ABC
    │   │                       #   can_analyze(sport, dport, proto, payload) → bool
    │   │                       #   analyze(...) → List[(ip, ProtocolDetection)]
    │   │
    │   ├── modbus.py           # Modbus/TCP — TCP 502
    │   │                       #   Parses MBAP header, all function codes
    │   │                       #   FC43/MEI (0x0E) device identification strings
    │   │                       #   Infers vendor from embedded name strings
    │   │
    │   ├── s7comm.py           # Siemens S7comm / S7comm+ — TCP 102
    │   │                       #   RFC 1006 TPKT + ISO 8073 COTP parsing
    │   │                       #   COTP CR/CC → TSAP extraction (rack/slot)
    │   │                       #   S7 PDU types: Job, Ack, Ack-Data, Userdata
    │   │                       #   SZL read detection (CPU identification queries)
    │   │                       #   CPU model family heuristic from SZL responses
    │   │
    │   ├── enip.py             # EtherNet/IP + CIP — TCP 44818 / UDP 2222
    │   │                       #   24-byte EIP encapsulation header parsing
    │   │                       #   ListIdentity (0x0063) response dissection
    │   │                       #   CIP Identity Item: vendor ID, device type,
    │   │                       #     product code, revision, serial, product name
    │   │                       #   130+ ODVA CIP vendor ID → name mappings
    │   │
    │   ├── dnp3.py             # DNP3 — TCP/UDP 20000
    │   │                       #   Data Link Layer frame (sync 0x0564)
    │   │                       #   Control byte, src/dst addresses, DL function
    │   │                       #   Application Layer: FC, object parsing
    │   │                       #   Group 0 Device Attributes (name, firmware)
    │   │
    │   ├── fins.py             # Omron FINS — UDP 9600
    │   │                       #   10-byte FINS header validation
    │   │                       #   Command code decoding (MRC/SRC pairs)
    │   │                       #   Controller Data Read (0x04/0x01) response parsing
    │   │                       #   CPU model string extraction and family mapping
    │   │
    │   ├── melsec.py           # Mitsubishi MELSEC MC Protocol — TCP 5006/5007/5008
    │   │                       #   3E frame (subheader 0x5000) and 4E frame parsing
    │   │                       #   Command/subcommand decoding
    │   │                       #   Read CPU Type Info (0x0631) response parsing
    │   │                       #   CPU type code → model name mapping (Q/iQ-R/FX5)
    │   │
    │   └── iec104.py           # IEC 60870-5-104 — TCP 2404
    │                           #   Start byte 0x68 + APDU length field
    │                           #   I-frame / S-frame / U-frame classification
    │                           #   U-frame: STARTDT/STOPDT/TESTFR parsing
    │                           #   I-frame ASDU: type ID, COT, common address
    │                           #   End of Initialization (type 70) detection
    │
    ├── fingerprint/
    │   ├── __init__.py
    │   ├── oui_db.py           # OUI Database
    │   │                       #   130+ ICS-specific MAC OUI → vendor mappings
    │   │                       #   Covers: Siemens, Rockwell, Schneider, Mitsubishi,
    │   │                       #     Omron, ABB, Honeywell, GE, Yokogawa, Beckhoff,
    │   │                       #     WAGO, Phoenix Contact, Moxa, Hirschmann, HMS,
    │   │                       #     Red Lion, Advantech, SEL, Turck, Pepperl+Fuchs
    │   │                       #   lookup_oui(mac) → vendor_str | None
    │   │
    │   └── engine.py           # FingerprintEngine
    │                           #   identify_from_protocols(device) → fingerprint dict
    │                           #   Multi-source evidence fusion:
    │                           #     Exclusive protocols (S7/FINS/MELSEC = known vendor)
    │                           #     CIP vendor IDs → vendor/make mapping
    │                           #     Modbus MEI string inference
    │                           #     DNP3 Group 0 attribute strings
    │                           #     OUI fallback
    │                           #   Confidence levels: high / medium / low
    │
    └── report/
        ├── __init__.py
        └── generator.py        # ReportGenerator
                                #   print_summary()  — coloured terminal table
                                #   to_json(path)    — full structured JSON
                                #   to_csv(path)     — flat CSV with all fields
                                #   to_html(path)    — standalone dark-theme HTML
                                #                      with expandable device cards
```

---

## Architecture Deep-Dive

### Packet Library Strategy

The scanner uses a **try-scapy, fallback-to-dpkt** strategy:

```python
# core.py
try:
    from scapy.all import PcapReader
    return self._analyze_with_scapy(pcap_file)
except ImportError:
    pass

import dpkt
return self._analyze_with_dpkt(pcap_file)
```

**Scapy** is preferred because it handles fragmented/overlapping TCP segments better and supports PCAPNG natively. **dpkt** is a lightweight fallback that works without any native dependencies.

### Device State Machine

Each unique source IP encountered in the PCAP creates a `PLCDevice` object that accumulates state across packets:

```
First packet from 192.168.1.10:
  → PLCDevice(ip="192.168.1.10") created
  → mac updated from Ethernet header
  → packet_count incremented
  → first_seen / last_seen timestamps set

Subsequent Modbus/TCP packets to port 502:
  → dst_device.open_ports.add(502)
  → ModbusAnalyzer.analyze() called
  → ProtocolDetection("Modbus/TCP") created or merged

After all packets processed:
  → FingerprintEngine.identify_from_protocols() called
  → Risk score calculated
```

### Protocol Analyzer Contract

Every analyzer implements the `BaseProtocolAnalyzer` ABC:

```python
class BaseProtocolAnalyzer(ABC):

    def can_analyze(self, sport, dport, proto, payload) -> bool:
        """Quick pre-filter. Called for EVERY packet — must be fast."""
        # Typical implementation: port check + magic-byte check
        return dport == 502 and len(payload) >= 8

    def analyze(self, src_ip, dst_ip, sport, dport, proto, payload, timestamp):
        """
        Full parse. Only called if can_analyze() returned True.
        Returns: List of (device_ip, ProtocolDetection) tuples
                 The device_ip is the controller/server side.
        """
```

The `can_analyze()` guard keeps overhead low — full parsing only runs when a packet plausibly matches the protocol.

### Confidence Levels

| Level | Meaning | Example |
|---|---|---|
| **high** | Multiple corroborating signals; definitive identification | CIP ListIdentity response with vendor ID + product name |
| **medium** | Single-source identification; strong but not confirmed | Modbus traffic on port 502, no MEI response captured |
| **low** | Heuristic or port-only detection | Known OT port traffic with unrecognised payload |

When multiple detections exist for the same protocol, `ProtocolDetection.merge()` upgrades to the highest confidence level seen.

---

## Risk Scoring

Risk is calculated after all packets are processed, using a weighted point system:

| Condition | Points | Rationale |
|---|---|---|
| Unencrypted industrial protocol in use | +2 per protocol | Modbus, S7comm, FINS, MELSEC, DNP3, IEC-104 send all data in cleartext |
| Legacy S7comm without S7comm+ | +1 | No confidentiality, integrity, or authentication |
| More than 2 industrial protocols | +1 | Increased attack surface |
| More than 15 communication peers | +1 | Unusual connectivity for a PLC |
| Device role is "plc" | +1 | Higher inherent consequence of compromise |

**Scoring thresholds:**

| Score | Risk Level | Recommended Action |
|---|---|---|
| 0 | `low` | Monitor; document in asset inventory |
| 1–2 | `medium` | Review network segmentation; apply ACLs |
| 3–4 | `high` | Isolate from untrusted networks; implement compensating controls |
| 5+ | `critical` | Immediate remediation; consider offline patching window |

---

## Vendor Fingerprinting

Vendor identification uses three evidence sources, applied in priority order:

### 1. Exclusive Protocol Identification (Highest Confidence)

Some protocols are vendor-exclusive and immediately identify the manufacturer:

| Protocol | Vendor |
|---|---|
| S7comm / S7comm+ | Siemens (always) |
| Omron FINS | Omron (always) |
| MELSEC MC Protocol | Mitsubishi Electric (always) |

### 2. Protocol-Embedded Identification Strings

Rich device information extracted from protocol responses:

**Modbus/TCP — FC43/MEI Read Device Identification (FC 0x2B, sub 0x0E):**
```
Object 0x00: VendorName      → "Schneider Electric"
Object 0x01: ProductCode     → "140CPU65160"
Object 0x02: FirmwareVersion → "V2.80"
Object 0x04: ProductName     → "Modicon Quantum"
```

**EtherNet/IP — CIP ListIdentity Response (Command 0x0063):**
```
CIP Vendor ID:    0x0001 → "Rockwell Automation"
CIP Device Type:  0x0010 → "Programmable Logic Controller"
CIP Product Code: 0x005A
CIP Revision:     20.13
CIP Serial:       0x00A3F2B1
CIP Product Name: "1756-L83E/B LOGIX5583E"
```

**Omron FINS — Controller Data Read (MRC 0x04, SRC 0x01):**
```
CPU Model: "CJ2H-CPU65" → CJ2H Series
Firmware:  "V1.50"
```

**Mitsubishi MELSEC — Read CPU Type Info (0x0631):**
```
CPU Name: "R04CPU        " → iQ-R Series
CPU Type Code: 0x0015 → R04CPU
```

**Siemens S7comm — COTP Connection + TSAP:**
```
Destination TSAP: 0x0300 → Rack 0, Slot 0, TIA Portal connection
SZL query 0x0011 → CPU Identification request
```

**DNP3 — Group 0 Device Attributes (if present):**
```
Variation 245: VendorName → "Schneider Electric"
Variation 242: ProductModel → "SCADAPack 350"
Variation 243: FirmwareVersion → "7.62"
```

### 3. MAC OUI Database (Fallback)

If no protocol-level vendor information is available, the scanner looks up the first 3 octets of the device MAC address against a curated ICS vendor OUI database.

```
MAC: 00:1B:1B:AA:BB:CC
OUI: 00:1B:1B → "Siemens AG"
```

---

## Protocol Analyzer Details

### Modbus/TCP (`protocols/modbus.py`)

**Frame structure parsed:**
```
MBAP Header (7 bytes):
  Transaction ID : 2 bytes BE
  Protocol ID   : 2 bytes BE  (must be 0x0000)
  Length        : 2 bytes BE  (PDU length)
  Unit ID       : 1 byte      (slave address / device ID)

PDU:
  Function Code : 1 byte
  Data          : variable
```

**Function codes recognised:** 0x01–0x18, 0x2B (MEI), error variants (0x81–0xAB)

**MEI Device Identification** (FC 43, sub 0x0E) response fields extracted:
- VendorName, ProductCode, FirmwareVersion, VendorURL, ProductName, ModelName, ApplicationName

---

### Siemens S7comm (`protocols/s7comm.py`)

**Layered structure parsed:**
```
TPKT (RFC 1006, 4 bytes):
  Version=3, Reserved=0, Length (2 bytes BE)

COTP (ISO 8073):
  CR (0xE0): Connection Request → TSAP extraction
  CC (0xD0): Connection Confirm
  DT (0xF0): Data Transfer → S7 PDU follows

S7 PDU (starts with 0x32):
  Protocol ID : 0x32
  ROSCTR      : 0x01 Job / 0x03 Ack-Data / 0x07 Userdata
  Reserved    : 2 bytes
  PDU Ref     : 2 bytes
  Param Len   : 2 bytes
  Data Len    : 2 bytes
  Parameters + Data
```

**TSAP decoding** (from COTP CR):
- Byte 0: Connection type (0x01=PG, 0x02=OP, 0x03=Step7/TIA)
- Byte 1: (Rack << 5) | Slot → physical PLC location

**SZL (System Status List) IDs detected:**
- `0x0011` CPU Identification — triggers model extraction
- `0x001C` Component Identification
- `0x0131` Communication Capability Parameters

---

### EtherNet/IP / CIP (`protocols/enip.py`)

**EIP Encapsulation Header (24 bytes):**
```
Command        : 2 bytes LE
Length         : 2 bytes LE
Session Handle : 4 bytes LE
Status         : 4 bytes LE
Sender Context : 8 bytes
Options        : 4 bytes LE
```

**Commands recognised:**
- `0x0063` ListIdentity — full CIP Identity item parsed
- `0x0064` ListInterfaces
- `0x0065` RegisterSession
- `0x006F` SendRRData (CIP messaging)
- `0x0070` SendUnitData (CIP I/O)

**CIP Identity Item (type 0x000C) fields:**
Encap version, Socket address (IP:port), Vendor ID, Device Type, Product Code, Revision (major.minor), Status, Serial Number, Product Name

**Known ODVA CIP Vendor IDs included:** 50+ vendor mappings covering all major OT automation manufacturers.

---

### DNP3 (`protocols/dnp3.py`)

**Data Link Frame:**
```
Sync    : 0x05 0x64
Length  : 1 byte
Control : 1 byte (DIR, PRM, FCB, FCV, FC)
Dest    : 2 bytes LE (outstation address)
Source  : 2 bytes LE (master address)
CRC     : 2 bytes
Data blocks (up to 16 bytes + CRC each)
```

**Application Layer parsed:**
- Transport Function byte (FIN/FIR/SEQ)
- Application Control + Function Code
- Object Group 0 (Device Attributes): variation 242 (model), 243 (firmware), 245 (vendor)

---

### Omron FINS (`protocols/fins.py`)

**FINS Header (10 bytes):**
```
ICF: bit7=response, bit6=1(always), bit0=ack-required
RSV: 0x00 (validation field)
GCT: gateway count (max hops)
DNA/DA1/DA2: destination network/node/unit
SNA/SA1/SA2: source network/node/unit
SID: service transaction ID
MRC + SRC: command codes (2 bytes)
```

**Commands decoded:** 30+ MRC/SRC pairs including Memory Area Read/Write, Controller Data Read (0x04/0x01), Controller Status, Clock, Program Area, Error Log.

**CPU model families recognised:** CJ1M, CJ1H, CJ2M, CJ2H, CS1H, CS1G, CP1L, CP1H, CP2E, NX1P, NX102, NJ101/301/501

---

### MELSEC MC Protocol (`protocols/melsec.py`)

**3E Frame:**
```
Sub Header  : 0x50 0x00
Serial No.  : 2 bytes LE
Reserved    : 0x00 0x00
Network No. : 1 byte
PC No.      : 1 byte (0xFF = own station)
I/O Req No. : 2 bytes LE (0x03FF = own station CPU)
Station No. : 1 byte
Data Len    : 2 bytes LE
CPU Timer   : 2 bytes LE
Command     : 2 bytes LE
Subcommand  : 2 bytes LE
Data        : variable
```

**4E Frame** adds a 4-byte access route serial + reserved prefix.

**Commands decoded:** 20+ including Batch Read/Write Bit/Word, Random Read/Write, Remote Run/Stop/Reset, Read CPU Type Info (0x0631).

**CPU type codes mapped:** Q02/Q04/Q06/Q13/Q26 UDCPU, R04/R08/R16/R32/R120 CPU (iQ-R), FX5U/FX5UC/FX5UJ

---

### IEC 60870-5-104 (`protocols/iec104.py`)

**APDU:**
```
Start  : 0x68
Length : 1 byte
Control: 4 bytes (determines frame type)
ASDU   : variable (I-frames only)
```

**Frame types:**
- **I-frame** — Information transfer (send/receive sequence numbers + ASDU)
- **S-frame** — Supervisory (flow control, receive sequence number)
- **U-frame** — Unnumbered control:
  - STARTDT act/con — data transfer start handshake (confirms active RTU)
  - STOPDT act/con — stop data transfer
  - TESTFR act/con — heartbeat / keepalive

**ASDU types decoded:** 70 type IDs including all standard measurement, command, and control types. End of Initialization (type 70) specifically detected as a device restart/power-on indicator.

---

## Extending the Scanner

### Adding a New Protocol Analyzer

1. Create `scanner/protocols/your_protocol.py`:

```python
from .base import BaseProtocolAnalyzer, AnalysisResult

class YourProtocolAnalyzer(BaseProtocolAnalyzer):

    def can_analyze(self, sport, dport, proto, payload):
        return dport == YOUR_PORT and len(payload) >= MINIMUM_LENGTH

    def analyze(self, src_ip, dst_ip, sport, dport, proto, payload, timestamp):
        # ... parse payload ...
        detection = self._make_detection(
            protocol="YourProtocol",
            port=YOUR_PORT,
            confidence="high",
            timestamp=timestamp,
            some_detail="value",
        )
        device_ip = dst_ip if dport == YOUR_PORT else src_ip
        return [(device_ip, detection)]
```

2. Register it in `scanner/core.py`:

```python
from .protocols.your_protocol import YourProtocolAnalyzer

# Inside PCAPAnalyzer.__init__():
self._analyzers = [
    ModbusAnalyzer(),
    S7CommAnalyzer(),
    # ...
    YourProtocolAnalyzer(),   # ← add here
]
```

### Adding OUI Entries

Edit `scanner/fingerprint/oui_db.py` and add to `OUI_DATABASE`:

```python
"AA:BB:CC": "Your Vendor Name",
```

OUI format: first 3 octets of MAC address, uppercase, colon-delimited.

### Adding CIP Vendor IDs

Edit `scanner/protocols/enip.py` and add to `CIP_VENDORS`:

```python
CIP_VENDORS = {
    # ...
    0x0200: "Your EIP Vendor Name",
}
```

Official ODVA vendor ID list: https://www.odva.org/technology-standards/odva-eip-conformance/odva-eip-vendor-ids/

---

## Limitations

| Limitation | Description |
|---|---|
| **Encrypted traffic** | S7comm+ (TLS), OPC-UA (TLS), or VPN-wrapped OT traffic cannot be deep-inspected. The connection is still detected, but no device details are extracted. |
| **Fragmented TCP** | Very large PDUs split across multiple TCP segments may not be fully reassembled. scapy handles this better than dpkt. |
| **UDP reliability** | UDP-based protocols (FINS, BACnet, some DNP3) may be missed if the capture only contains TCP. |
| **Short captures** | Very brief captures may miss ListIdentity broadcasts, MEI responses, or SZL reads that reveal device details. |
| **OUI database completeness** | The built-in OUI database covers major ICS vendors; some newer or lesser-known device MACs may not be mapped. |
| **Dynamic CIP** | CIP connections on non-standard ports (configured by user) are not detected. |
| **Proprietary sub-protocols** | Vendor-specific extensions within standard frames (e.g., Siemens TIA Portal extensions) may not be fully decoded. |

---

## Legal & Ethical Use

This tool is designed **exclusively for defensive security purposes**:

- **Asset inventory** — document what PLCs exist in your network
- **Security assessments** — identify unencrypted protocols and legacy devices
- **Incident response** — analyse captured traffic for suspicious patterns
- **Compliance audits** — demonstrate OT protocol visibility for IEC 62443, NERC CIP, or NIS2 assessments
- **CTF / training** — practice ICS protocol analysis in lab environments

> **Important:** Always obtain explicit written authorisation before capturing or analysing traffic on any industrial network. Unauthorised interception of network communications may violate computer crime laws in your jurisdiction (e.g., CFAA, Computer Misuse Act, EU Directive 2013/40/EU). The authors assume no liability for misuse.

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `scapy` | ≥ 2.5.0 | Primary PCAP reading and packet dissection |
| `dpkt` | ≥ 1.9.8 | Fallback PCAP reader (used if scapy unavailable) |
| `colorama` | ≥ 0.4.6 | Coloured terminal output (optional — gracefully degrades) |

All are available via PyPI: `pip install -r requirements.txt`

---

## Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-03-04 | Initial release — 7 protocol analyzers, 130+ OUI entries, JSON/CSV/HTML output |

---

*PLC Passive Scanner — OT Security Defensive Tool*
