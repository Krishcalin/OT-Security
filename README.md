<p align="center">
  <img src="docs/banner.svg" alt="OT Security Scanner" width="900"/>
</p>

<p align="center">
  <strong>A PCAP-based offline security assessment tool for ICS/SCADA/OT networks</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/protocols-9-e11d48?style=flat-square"/>
  <img src="https://img.shields.io/badge/IEC_62443-aligned-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-ICS-dc2626?style=flat-square"/>
</p>

---

## Overview

**OT Security Scanner** analyzes PCAP/PCAPNG packet captures from ICS/SCADA/OT networks to detect security vulnerabilities, protocol abuse, misconfigurations, and attack patterns. It covers 9 industrial protocols across 12 analysis modules with findings mapped to IEC 62443 and MITRE ATT&CK for ICS.

- **PCAP-based** — analyzes packet captures offline, no live network access needed
- **Pure Python** — zero external dependencies (no scapy, dpkt, or tshark)
- **9 industrial protocols** — Modbus, S7comm, DNP3, BACnet, OPC UA, EtherNet/IP, IEC 104, PROFINET, MQTT
- **12 analysis modules** — protocol-specific + network baseline + compliance + threat mapping
- **IEC 62443 + MITRE ATT&CK ICS** — all findings mapped to industry frameworks

---

## Supported Protocols & Devices

| Protocol | Port | Devices | Module |
|----------|------|---------|--------|
| **Modbus/TCP** | 502 | PLCs, RTUs, FRTUs (Schneider, ABB, Wago) | `modbus` |
| **Siemens S7comm** | 102 | Siemens S7-300/400/1200/1500 PLCs | `s7` |
| **DNP3** | 20000 | RTUs, outstations, SCADA masters (power/water) | `dnp3` |
| **BACnet/IP** | 47808 | Building automation controllers (Johnson, Honeywell) | `bacnet` |
| **OPC UA** | 4840/4843 | Industrial servers, historians, DCS | `opcua` |
| **EtherNet/IP (CIP)** | 44818 | Rockwell/Allen-Bradley PLCs, drives | `enip` |
| **IEC 60870-5-104** | 2404 | Power grid RTUs, substation automation | `iec104` |
| **PROFINET** | 34962-34964 | Siemens I/O, drives, controllers | `profinet` |
| **MQTT** | 1883/8883 | IIoT gateways, edge devices, sensors | `mqtt` |

---

## Analysis Modules (12)

| Module | Key | Focus |
|--------|-----|-------|
| 🔌 **Modbus/TCP** | `modbus` | Write operations, diagnostic abuse, Force Listen Only (DoS), reconnaissance, broadcast |
| ⚙️ **Siemens S7comm** | `s7` | CPU stop/start, program upload/download, write variables, auth brute-force, SZL enumeration |
| 🔋 **DNP3** | `dnp3` | Cold/warm restart, file transfer, control operations, Secure Auth detection |
| 🏢 **BACnet/IP** | `bacnet` | WriteProperty, ReinitializeDevice, DeviceCommunicationControl (DoS), Who-Is scanning |
| 🔧 **OPC UA** | `opcua` | SecurityMode=None, anonymous access, write operations, unencrypted sessions |
| 🏭 **EtherNet/IP** | `enip` | Program operations, configuration changes, unauthorized access |
| ⚡ **IEC 60870-5-104** | `iec104` | Control commands, setpoint changes, interrogation scanning |
| 📡 **PROFINET** | `profinet` | DCP identification, configuration changes, unencrypted traffic |
| 🌐 **MQTT** | `mqtt` | Unencrypted connections, anonymous access, wildcard subscriptions, sensitive topics |
| 📊 **Network Baseline** | `baseline` | Asset discovery, IT/OT crossover, insecure protocols, communication matrix |
| 🛡️ **IEC 62443 Compliance** | `iec62443` | Zone segmentation violations, unencrypted conduits, authentication gaps, audit trail |
| 🎯 **MITRE ATT&CK ICS** | `mitre` | Technique coverage mapping, initial access vectors, lateral movement detection |

---

## Quick Start

```bash
git clone https://github.com/Krishcalin/OT-Security.git
cd OT-Security

# Generate sample PCAP with synthetic OT traffic
python generate_sample_pcap.py

# Run the scanner
python ot_scanner.py --data-dir ./sample_pcaps --output report.html

# Scan specific protocols
python ot_scanner.py --data-dir ./captures --modules modbus s7 dnp3

# High severity only
python ot_scanner.py --data-dir ./captures --severity HIGH
```

### Getting PCAPs from Your OT Network

```bash
# Using tcpdump on a SPAN/mirror port
tcpdump -i eth0 -w ot_capture.pcap -c 100000

# Using Wireshark/tshark with OT protocol filters
tshark -i eth0 -f "port 502 or port 102 or port 20000 or port 47808 or port 44818" -w ot_capture.pcap
```

---

## Available Modules

```
modbus    — Modbus/TCP protocol analysis
s7        — Siemens S7comm protocol analysis
dnp3      — DNP3 protocol analysis
bacnet    — BACnet/IP protocol analysis
opcua     — OPC UA protocol analysis
enip      — EtherNet/IP (CIP) protocol analysis
iec104    — IEC 60870-5-104 protocol analysis
profinet  — PROFINET protocol analysis
mqtt      — MQTT protocol analysis
baseline  — Network baseline & asset discovery
iec62443  — IEC 62443 compliance assessment
mitre     — MITRE ATT&CK for ICS technique mapping
all       — Run everything (default)
```

---

## Project Structure

```
OT-Security/
├── ot_scanner.py                   # Main entry point
├── generate_sample_pcap.py         # Sample PCAP generator for testing
├── modules/
│   ├── pcap_parser.py             # Pure-Python PCAP/PCAPNG reader
│   ├── modbus_analyzer.py         # Modbus/TCP analysis
│   ├── s7comm_analyzer.py         # Siemens S7comm analysis
│   ├── dnp3_analyzer.py           # DNP3 analysis
│   ├── bacnet_analyzer.py         # BACnet/IP analysis
│   ├── opcua_analyzer.py          # OPC UA analysis
│   ├── protocol_analyzers.py      # EtherNet/IP, IEC 104, MQTT
│   ├── network_baseline.py        # Network baseline + PROFINET
│   ├── compliance_mitre.py        # IEC 62443 + MITRE ATT&CK ICS
│   └── report_generator.py        # HTML dashboard
├── sample_pcaps/                   # Generated test captures
├── docs/
│   └── banner.svg
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## References

- [IEC 62443 Series — Industrial Cybersecurity Standards](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)
- [NIST SP 800-82 Rev 3 — Guide to OT Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/techniques/ics/)
- [ICS-CERT / CISA Advisories](https://www.cisa.gov/news-events/ics-advisories)
- [Modbus Protocol Specification](https://modbus.org/specs.php)
- [IEEE 1815-2012 (DNP3 Secure Authentication)](https://standards.ieee.org/standard/1815-2012.html)
- [OPC UA Security Model (OPC 10000-4)](https://reference.opcfoundation.org/)
- [ASHRAE 135 — BACnet/SC](https://www.ashrae.org/technical-resources/bookstore/bacnet)

## Disclaimer

This tool is for **authorized OT security assessments only**. It performs offline PCAP analysis and does not connect to any live OT/ICS network or device. Always obtain proper authorization before capturing OT network traffic.

## License

MIT License — see [LICENSE](LICENSE).
