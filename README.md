# OT Security — Passive Industrial Network Scanners

A collection of **purely passive**, offline security tools for Operational Technology (OT) and Industrial Control System (ICS) environments. All scanners analyse captured network traffic (PCAP/PCAPNG) — **no packets are ever sent to the network**, making them safe for use in live production environments.

---

## Scanners

| Scanner | Directory | Description |
|---|---|---|
| **PLC Passive Scanner** | [`plc_passive_scanner/`](plc_passive_scanner/) | Identifies PLCs and OT devices — vendor, model, firmware, protocols, risk scoring |
| **RTU / FRTU Passive Vulnerability Scanner** | [`rtu_passive_scanner/`](rtu_passive_scanner/) | Identifies RTUs, FRTUs, and IEDs with vulnerability and misconfiguration detection |

---

## PLC Passive Scanner

Reads a PCAP file and builds a complete device inventory of industrial PLCs by analysing their network communications.

### Supported Protocols

| Protocol | Transport | Port(s) |
|---|---|---|
| Modbus/TCP | TCP | 502 |
| Siemens S7comm / S7comm+ | TCP | 102 |
| EtherNet/IP / CIP | TCP / UDP | 44818 / 2222 |
| DNP3 | TCP / UDP | 20000 |
| Omron FINS | UDP | 9600 |
| Mitsubishi MELSEC MC | TCP | 5006–5008 |
| IEC 60870-5-104 | TCP | 2404 |

### Supported Vendors

Siemens, Rockwell Automation / Allen-Bradley, Schneider Electric, Mitsubishi Electric, Omron, ABB, Honeywell, GE Automation, Yokogawa, Beckhoff, WAGO, Phoenix Contact — plus 130+ ICS-specific MAC OUI entries for fallback identification.

### Key Outputs

- Discovered device inventory (IP, MAC, vendor, model, firmware)
- Protocols in use and detected device roles (PLC, HMI, gateway)
- Risk assessment with actionable risk factors
- Reports in **JSON**, **CSV**, and interactive **HTML**

### Usage

```bash
cd plc_passive_scanner
pip install -r requirements.txt

python plc_scanner.py <pcap_file>
python plc_scanner.py factory.pcap -f html -o factory_report
python plc_scanner.py capture.pcap -v --min-packets 5
```

---

## RTU / FRTU Passive Vulnerability Scanner

Reads a PCAP file and identifies RTUs, FRTUs, and IEDs together with their specific security vulnerabilities and misconfigurations — designed for electric grid automation, water treatment, pipeline monitoring, and substation environments.

### Supported Protocols

| Protocol | Transport | Port(s) / EtherType |
|---|---|---|
| DNP3 | TCP / UDP | 20000 |
| IEC 60870-5-104 | TCP | 2404 |
| IEC 61850 MMS | TCP | 102 |
| IEC 61850 GOOSE | Layer 2 | EtherType 0x88B8 |
| IEC 61850 SV (Sampled Values) | Layer 2 | EtherType 0x88BA |
| Modbus/TCP | TCP | 502 |
| SEL Fast Message | TCP | 702 |
| Omron FINS | UDP | 9600 |
| MELSEC MC Protocol | TCP | 5006–5007 |

### Vulnerability Categories

| Category | Examples |
|---|---|
| **Authentication** | DNP3 Secure Authentication (SAv5/SAv6), IEC 62351-5 |
| **Encryption** | IEC 62351-3 (TLS for IEC-104), IEC 62351-4 (TLS/MMS) |
| **GOOSE Security** | IEC 62351-6, simulation flag abuse, low TTL, confRev changes |
| **Command Safety** | Direct Operate (SBO bypass), unauthenticated commands |
| **Configuration** | Multiple masters, excessive peers, cleartext protocols |

### Key Outputs

- RTU/FRTU/IED device inventory with vendor fingerprinting
- Detected vulnerabilities mapped to severity levels
- Reports in **JSON**, **CSV**, and interactive **HTML**

### Usage

```bash
cd rtu_passive_scanner
pip install -r requirements.txt

python rtu_scanner.py <pcap_file>
python rtu_scanner.py substation.pcap -f html -o substation_report
python rtu_scanner.py capture.pcap -v --min-packets 3
```

---

## Why Passive Scanning?

Active network scanners (Nmap, Shodan-style probes) are **dangerous in OT environments**:

| Risk | Effect |
|---|---|
| Unexpected TCP/UDP packets | PLCs crash or enter fault state |
| Unrecognised protocol frames | Safety systems trip unexpectedly |
| Network flooding | Latency spikes break real-time control loops |
| ARP probes | Disrupt deterministic Profinet/EtherNet/IP I/O traffic |

Passive scanning from a PCAP eliminates all of these risks. Captures can be collected via:
- A **network TAP** on the OT switch uplink
- **Port mirroring (SPAN)** on a managed switch
- A dedicated **network sensor** (e.g., Raspberry Pi with tcpdump)
- Existing **IDS/NDR** appliances that export PCAP recordings

---

## Requirements

- Python **3.8+**
- **scapy** (recommended) or **dpkt** (fallback)
- Optional: **colorama** (coloured terminal output)

---

## Legal & Ethical Use

These tools are designed **exclusively for defensive security purposes**:

- **Asset inventory** — document OT devices on your network
- **Security assessments** — identify unencrypted protocols and vulnerabilities
- **Incident response** — analyse captured traffic for suspicious patterns
- **Compliance audits** — IEC 62443, NERC CIP, NIS2 assessments
- **CTF / training** — practice ICS protocol analysis in lab environments

> **Important:** Always obtain explicit written authorisation before capturing or analysing traffic on any industrial network. Unauthorised interception of network communications may violate computer crime laws in your jurisdiction.

---

## License

See [LICENSE](LICENSE) for details.
