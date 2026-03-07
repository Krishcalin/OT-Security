"""
OT PCAP Parser — Zero-Dependency Packet Capture Reader
=========================================================
Reads PCAP and PCAPNG files using pure Python stdlib.
Extracts Ethernet → IP → TCP/UDP frames and classifies by OT protocol port.
"""

import struct
import socket
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, BinaryIO

# ── OT Protocol Port Mapping ─────────────────────────────────
OT_PORTS = {
    502:   "modbus",
    102:   "s7comm",
    20000: "dnp3",
    47808: "bacnet",
    4840:  "opcua",
    4843:  "opcua_tls",
    44818: "enip",
    2404:  "iec104",
    34962: "profinet",
    34963: "profinet",
    34964: "profinet",
    1883:  "mqtt",
    8883:  "mqtt_tls",
    161:   "snmp",
    162:   "snmp_trap",
    80:    "http",
    443:   "https",
    22:    "ssh",
    23:    "telnet",
    21:    "ftp",
    3389:  "rdp",
    5900:  "vnc",
    4911:  "niagara_fox",
    1911:  "niagara_fox",
    18245: "gds",           # GE SRTP
    789:   "crimson",       # Red Lion Crimson
    2222:  "ethernetip_io",
    48898: "ads_ams",       # Beckhoff ADS/AMS
    9600:  "omron_fins",
}

class Packet:
    """Represents a parsed network packet."""
    __slots__ = ('timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                 'protocol', 'ip_proto', 'payload', 'length', 'ot_protocol',
                 'raw_ethernet', 'src_mac', 'dst_mac', 'tcp_flags')

    def __init__(self):
        self.timestamp: float = 0.0
        self.src_ip: str = ""
        self.dst_ip: str = ""
        self.src_port: int = 0
        self.dst_port: int = 0
        self.protocol: str = ""      # tcp/udp/icmp
        self.ip_proto: int = 0
        self.payload: bytes = b""
        self.length: int = 0
        self.ot_protocol: str = ""
        self.src_mac: str = ""
        self.dst_mac: str = ""
        self.tcp_flags: int = 0

    def __repr__(self):
        return (f"<Pkt {self.src_ip}:{self.src_port}→{self.dst_ip}:{self.dst_port} "
                f"{self.ot_protocol or self.protocol} len={self.length}>")


def _read_u16(data, offset, big=False):
    return struct.unpack_from(">H" if big else "<H", data, offset)[0]

def _read_u32(data, offset, big=False):
    return struct.unpack_from(">I" if big else "<I", data, offset)[0]

def _mac_str(data, offset):
    return ":".join(f"{b:02x}" for b in data[offset:offset+6])

def _ip_str(data, offset):
    return socket.inet_ntoa(data[offset:offset+4])


def _parse_ethernet(raw: bytes) -> Optional[Packet]:
    """Parse Ethernet → IP → TCP/UDP from raw frame."""
    if len(raw) < 34:
        return None

    pkt = Packet()
    pkt.dst_mac = _mac_str(raw, 0)
    pkt.src_mac = _mac_str(raw, 6)
    eth_type = _read_u16(raw, 12, big=True)

    # Handle 802.1Q VLAN tag
    ip_offset = 14
    if eth_type == 0x8100:
        eth_type = _read_u16(raw, 16, big=True)
        ip_offset = 18

    if eth_type != 0x0800:  # Only IPv4 for now
        return None

    if len(raw) < ip_offset + 20:
        return None

    # IP header
    ip_ver_ihl = raw[ip_offset]
    ip_ihl = (ip_ver_ihl & 0x0F) * 4
    if ip_ihl < 20:
        return None

    pkt.ip_proto = raw[ip_offset + 9]
    pkt.src_ip = _ip_str(raw, ip_offset + 12)
    pkt.dst_ip = _ip_str(raw, ip_offset + 16)
    pkt.length = _read_u16(raw, ip_offset + 2, big=True)

    transport_offset = ip_offset + ip_ihl

    if pkt.ip_proto == 6:  # TCP
        if len(raw) < transport_offset + 20:
            return None
        pkt.protocol = "tcp"
        pkt.src_port = _read_u16(raw, transport_offset, big=True)
        pkt.dst_port = _read_u16(raw, transport_offset + 2, big=True)
        tcp_data_offset = ((raw[transport_offset + 12] >> 4) & 0x0F) * 4
        pkt.tcp_flags = raw[transport_offset + 13]
        payload_offset = transport_offset + tcp_data_offset
        pkt.payload = raw[payload_offset:] if payload_offset < len(raw) else b""

    elif pkt.ip_proto == 17:  # UDP
        if len(raw) < transport_offset + 8:
            return None
        pkt.protocol = "udp"
        pkt.src_port = _read_u16(raw, transport_offset, big=True)
        pkt.dst_port = _read_u16(raw, transport_offset + 2, big=True)
        pkt.payload = raw[transport_offset + 8:] if transport_offset + 8 < len(raw) else b""

    elif pkt.ip_proto == 1:  # ICMP
        pkt.protocol = "icmp"
        pkt.payload = raw[transport_offset:] if transport_offset < len(raw) else b""
    else:
        pkt.protocol = f"proto_{pkt.ip_proto}"
        return pkt

    # Classify OT protocol by port
    for port in (pkt.dst_port, pkt.src_port):
        if port in OT_PORTS:
            pkt.ot_protocol = OT_PORTS[port]
            break

    return pkt


def read_pcap(filepath: Path) -> List[Packet]:
    """Read a PCAP or PCAPNG file and return parsed packets."""
    packets = []
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            f.seek(0)

            if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                packets = _read_pcap_classic(f, magic)
            elif magic == b'\x0a\x0d\x0d\x0a':
                packets = _read_pcapng(f)
            else:
                print(f"    [WARN] Unknown file format: {filepath.name}")
    except Exception as e:
        print(f"    [WARN] Failed to read {filepath.name}: {e}")

    return packets


def _read_pcap_classic(f: BinaryIO, magic: bytes) -> List[Packet]:
    """Parse classic PCAP format."""
    big_endian = (magic == b'\xa1\xb2\xc3\xd4')
    fmt = ">" if big_endian else "<"

    header = f.read(24)
    if len(header) < 24:
        return []

    # version_major = struct.unpack_from(f"{fmt}H", header, 4)[0]
    # version_minor = struct.unpack_from(f"{fmt}H", header, 6)[0]
    # snaplen = struct.unpack_from(f"{fmt}I", header, 16)[0]
    link_type = struct.unpack_from(f"{fmt}I", header, 20)[0]

    packets = []
    while True:
        rec_hdr = f.read(16)
        if len(rec_hdr) < 16:
            break

        ts_sec = struct.unpack_from(f"{fmt}I", rec_hdr, 0)[0]
        ts_usec = struct.unpack_from(f"{fmt}I", rec_hdr, 4)[0]
        incl_len = struct.unpack_from(f"{fmt}I", rec_hdr, 8)[0]
        # orig_len = struct.unpack_from(f"{fmt}I", rec_hdr, 12)[0]

        raw = f.read(incl_len)
        if len(raw) < incl_len:
            break

        # Handle Linux cooked capture (SLL)
        if link_type == 113 and len(raw) > 16:
            eth_type = _read_u16(raw, 14, big=True)
            if eth_type == 0x0800:
                # Fake ethernet header
                raw = b'\x00' * 12 + b'\x08\x00' + raw[16:]

        pkt = _parse_ethernet(raw)
        if pkt:
            pkt.timestamp = ts_sec + ts_usec / 1_000_000
            pkt.raw_ethernet = raw
            packets.append(pkt)

    return packets


def _read_pcapng(f: BinaryIO) -> List[Packet]:
    """Parse PCAPNG format (simplified — handles SHB, IDB, EPB)."""
    packets = []

    while True:
        block_hdr = f.read(8)
        if len(block_hdr) < 8:
            break

        block_type = struct.unpack_from("<I", block_hdr, 0)[0]
        block_len = struct.unpack_from("<I", block_hdr, 4)[0]

        if block_len < 12:
            break

        body = f.read(block_len - 12)  # minus header(8) + trailer(4)
        trailer = f.read(4)

        if block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) >= 20:
                # interface_id = struct.unpack_from("<I", body, 0)[0]
                ts_high = struct.unpack_from("<I", body, 4)[0]
                ts_low = struct.unpack_from("<I", body, 8)[0]
                captured_len = struct.unpack_from("<I", body, 12)[0]
                # original_len = struct.unpack_from("<I", body, 16)[0]

                raw = body[20:20 + captured_len]
                pkt = _parse_ethernet(raw)
                if pkt:
                    ts = (ts_high << 32) | ts_low
                    pkt.timestamp = ts / 1_000_000  # Microsecond resolution assumed
                    pkt.raw_ethernet = raw
                    packets.append(pkt)

    return packets


def load_pcaps(data_dir: str) -> Tuple[List[Packet], Dict[str, int]]:
    """Load all PCAP/PCAPNG files from a directory."""
    all_packets = []
    protocol_counts: Dict[str, int] = {}
    data_path = Path(data_dir)

    for ext in ("*.pcap", "*.pcapng", "*.cap"):
        for f in sorted(data_path.glob(ext)):
            print(f"    Parsing: {f.name}...")
            pkts = read_pcap(f)
            print(f"      → {len(pkts)} packets extracted")
            all_packets.extend(pkts)

    # Count by OT protocol
    for pkt in all_packets:
        key = pkt.ot_protocol or pkt.protocol
        protocol_counts[key] = protocol_counts.get(key, 0) + 1

    return all_packets, protocol_counts


class BaseOTAuditor:
    """Base class for all OT protocol auditors."""
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"

    def __init__(self, packets: List[Packet], all_packets: List[Packet] = None,
                 baseline: Dict = None):
        self.packets = packets
        self.all_packets = all_packets or packets
        self.baseline = baseline or {}
        self.findings: List[Dict[str, Any]] = []

    def finding(self, check_id, title, severity, category, description,
                affected_items=None, remediation="", references=None,
                mitre_ics=None, details=None):
        f = {
            "check_id": check_id, "title": title, "severity": severity,
            "category": category, "description": description,
            "affected_items": affected_items or [],
            "affected_count": len(affected_items) if affected_items else 0,
            "remediation": remediation, "references": references or [],
            "mitre_ics": mitre_ics or [],
            "details": details or {},
            "timestamp": datetime.datetime.now().isoformat(),
        }
        self.findings.append(f)
        return f

    def run_all_checks(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def get_baseline(self, key, default):
        return self.baseline.get(key, default)

    def filter_by_port(self, port: int) -> List[Packet]:
        return [p for p in self.packets if p.src_port == port or p.dst_port == port]
