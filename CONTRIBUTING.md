# Contributing to OT Security Scanner
## Adding Protocol Support
1. Create analyzer module in modules/
2. Extend pcap_parser.py OT_PORTS for port mapping
3. Register in ot_scanner.py MODULE_MAP
4. Add sample PCAP generation in generate_sample_pcap.py
5. Update README

## Code Style
- Python 3.8+, zero external dependencies (no scapy/dpkt)
- Pure stdlib PCAP parsing
- MITRE ATT&CK for ICS mapping on all findings
- IEC 62443 references where applicable
