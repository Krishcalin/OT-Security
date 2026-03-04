"""
Core PCAP Analysis Engine.

Orchestrates packet reading (via Scapy or dpkt fallback) and dispatches
each packet to the appropriate protocol analyzers.  Tracks per-device state
and runs vendor fingerprinting after all packets are processed.
"""
import sys
import socket
import struct
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .models import PLCDevice, ProtocolDetection
from .protocols.modbus  import ModbusAnalyzer
from .protocols.s7comm  import S7CommAnalyzer
from .protocols.enip    import EtherNetIPAnalyzer
from .protocols.dnp3    import DNP3Analyzer
from .protocols.fins    import FINSAnalyzer
from .protocols.melsec  import MELSECAnalyzer
from .protocols.iec104  import IEC104Analyzer
from .fingerprint.engine import FingerprintEngine

# All industrial ports that we actively track (server-side)
INDUSTRIAL_PORTS: Dict[int, str] = {
    102:   "S7comm (ISO-TSAP)",
    502:   "Modbus/TCP",
    2222:  "EtherNet/IP (UDP I/O)",
    2404:  "IEC 60870-5-104",
    4840:  "OPC-UA",
    5006:  "MELSEC MC Protocol",
    5007:  "MELSEC MC Protocol",
    5008:  "MELSEC MC Protocol",
    9600:  "Omron FINS",
    18245: "GE-SRTP",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet/IP",
    1911:  "Niagara Fox",
    789:   "Profinet DCP",
    34962: "Profinet RT",
    34963: "Profinet RT",
}

# Risk scoring weights
UNENCRYPTED_PROTOCOLS = {
    "Modbus/TCP", "S7comm", "Omron FINS",
    "MELSEC MC Protocol", "DNP3", "IEC 60870-5-104",
}


class PCAPAnalyzer:
    """
    Main PCAP analysis engine.

    Usage:
        analyzer = PCAPAnalyzer(verbose=True)
        devices = analyzer.analyze("capture.pcap")
    """

    def __init__(self, verbose: bool = False, min_packets: int = 1):
        self.verbose      = verbose
        self.min_packets  = min_packets
        self._devices: Dict[str, PLCDevice] = {}
        self._analyzers   = [
            ModbusAnalyzer(),
            S7CommAnalyzer(),
            EtherNetIPAnalyzer(),
            DNP3Analyzer(),
            FINSAnalyzer(),
            MELSECAnalyzer(),
            IEC104Analyzer(),
        ]
        self._fingerprinter = FingerprintEngine()

    # ------------------------------------------------------------------ public

    def analyze(self, pcap_file: str) -> List[PLCDevice]:
        """
        Read a PCAP/PCAPNG file and return a sorted list of discovered
        industrial devices (only those with at least one protocol detection).
        """
        try:
            from scapy.all import PcapReader          # noqa: F401
            return self._analyze_with_scapy(pcap_file)
        except ImportError:
            pass

        try:
            import dpkt                               # noqa: F401
            return self._analyze_with_dpkt(pcap_file)
        except ImportError:
            pass

        print("[ERROR] No packet library found.")
        print("        Install scapy:  pip install scapy")
        print("        or dpkt:        pip install dpkt")
        sys.exit(1)

    # ------------------------------------------------------------------ scapy

    def _analyze_with_scapy(self, pcap_file: str) -> List[PLCDevice]:
        from scapy.all import PcapReader, IP, TCP, UDP, Ether

        total = 0
        print("[*] Using scapy to read PCAP …")

        try:
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    total += 1
                    if total % 10_000 == 0:
                        print(f"    {total:,} packets processed …", end="\r", flush=True)
                    try:
                        ts = datetime.fromtimestamp(float(pkt.time))
                    except Exception:
                        ts = datetime.now()

                    # Ethernet layer — extract MACs
                    src_mac = dst_mac = None
                    if pkt.haslayer(Ether):
                        src_mac = pkt[Ether].src.upper()
                        dst_mac = pkt[Ether].dst.upper()

                    if not pkt.haslayer(IP):
                        continue

                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    if pkt.haslayer(TCP):
                        sport   = pkt[TCP].sport
                        dport   = pkt[TCP].dport
                        proto   = "TCP"
                        payload = bytes(pkt[TCP].payload)
                    elif pkt.haslayer(UDP):
                        sport   = pkt[UDP].sport
                        dport   = pkt[UDP].dport
                        proto   = "UDP"
                        payload = bytes(pkt[UDP].payload)
                    else:
                        continue

                    self._handle_packet(src_ip, dst_ip, src_mac, dst_mac,
                                        sport, dport, proto, payload, ts)

        except FileNotFoundError:
            print(f"\n[ERROR] File not found: {pcap_file}")
            sys.exit(1)
        except Exception as exc:
            print(f"\n[ERROR] scapy failed to read PCAP: {exc}")
            sys.exit(1)

        print(f"[+] {total:,} packets processed.                    ")
        return self._finalise()

    # ------------------------------------------------------------------ dpkt

    def _analyze_with_dpkt(self, pcap_file: str) -> List[PLCDevice]:
        import dpkt

        total = 0
        print("[*] Using dpkt to read PCAP …")

        try:
            with open(pcap_file, "rb") as fh:
                try:
                    pcap = dpkt.pcap.Reader(fh)
                    linktype = pcap.datalink()
                except Exception:
                    fh.seek(0)
                    pcap = dpkt.pcapng.Reader(fh)
                    linktype = 1    # Assume Ethernet

                for raw_ts, buf in pcap:
                    total += 1
                    ts = datetime.fromtimestamp(raw_ts)
                    if total % 10_000 == 0:
                        print(f"    {total:,} packets processed …", end="\r", flush=True)

                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except Exception:
                        continue

                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip = eth.data
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    src_mac = ":".join(f"{b:02X}" for b in eth.src)
                    dst_mac = ":".join(f"{b:02X}" for b in eth.dst)

                    transport = ip.data
                    if isinstance(transport, dpkt.tcp.TCP):
                        sport, dport = transport.sport, transport.dport
                        proto        = "TCP"
                        payload      = bytes(transport.data)
                    elif isinstance(transport, dpkt.udp.UDP):
                        sport, dport = transport.sport, transport.dport
                        proto        = "UDP"
                        payload      = bytes(transport.data)
                    else:
                        continue

                    self._handle_packet(src_ip, dst_ip, src_mac, dst_mac,
                                        sport, dport, proto, payload, ts)

        except FileNotFoundError:
            print(f"\n[ERROR] File not found: {pcap_file}")
            sys.exit(1)
        except Exception as exc:
            print(f"\n[ERROR] dpkt failed to read PCAP: {exc}")
            sys.exit(1)

        print(f"[+] {total:,} packets processed.                    ")
        return self._finalise()

    # ------------------------------------------------------------------ core packet handling

    def _handle_packet(
        self,
        src_ip: str, dst_ip: str,
        src_mac: Optional[str], dst_mac: Optional[str],
        sport: int, dport: int,
        proto: str, payload: bytes,
        ts: datetime,
    ) -> None:
        """Update device state and dispatch to protocol analyzers."""

        # Track source device
        src_dev = self._get_device(src_ip)
        src_dev.packet_count += 1
        src_dev.update_time(ts)
        src_dev.communicating_with.add(dst_ip)
        if src_mac and _is_unicast_mac(src_mac) and not src_dev.mac:
            src_dev.mac = src_mac

        # Track destination device port (server side)
        if dport in INDUSTRIAL_PORTS:
            dst_dev = self._get_device(dst_ip)
            dst_dev.open_ports.add(dport)
            dst_dev.update_time(ts)
            dst_dev.communicating_with.add(src_ip)
            if dst_mac and _is_unicast_mac(dst_mac) and not dst_dev.mac:
                dst_dev.mac = dst_mac

        if not payload:
            return

        # Dispatch to each protocol analyzer
        for analyzer in self._analyzers:
            if not analyzer.can_analyze(sport, dport, proto, payload):
                continue
            try:
                results = analyzer.analyze(src_ip, dst_ip, sport, dport, proto, payload, ts)
                if results:
                    for device_ip, detection in results:
                        dev = self._get_device(device_ip)
                        dev.add_protocol(detection)
                        if self.verbose:
                            print(f"  [+] {device_ip}  {detection.protocol}  "
                                  f"({detection.confidence})")
            except Exception as exc:
                if self.verbose:
                    print(f"  [!] {analyzer.__class__.__name__} error: {exc}")

    # ------------------------------------------------------------------ finalisation

    def _finalise(self) -> List[PLCDevice]:
        """Apply fingerprinting, risk scoring, and return results."""
        self._apply_fingerprinting()

        results = [
            d for d in self._devices.values()
            if d.protocols and d.packet_count >= self.min_packets
        ]
        for device in results:
            self._score_risk(device)

        return sorted(results, key=lambda d: tuple(int(x) for x in d.ip.split(".")))

    def _apply_fingerprinting(self) -> None:
        """Run vendor/model fingerprinting on every tracked device."""
        for device in self._devices.values():
            # OUI lookup (highest priority source if protocols are absent)
            if device.mac:
                oui_vendor = self._fingerprinter.lookup_oui(device.mac)
                if oui_vendor and not device.vendor:
                    device.vendor            = oui_vendor
                    device.vendor_confidence = "medium"

            # Protocol-based identification (overrides / enriches OUI)
            if device.protocols:
                fp = self._fingerprinter.identify_from_protocols(device)
                if fp:
                    if fp.get("vendor"):
                        device.vendor            = fp["vendor"]
                        device.vendor_confidence = fp.get("confidence", "medium")
                    if fp.get("plc_make") and not device.plc_make:
                        device.plc_make = fp["plc_make"]
                    if fp.get("plc_model") and not device.plc_model:
                        device.plc_model = fp["plc_model"]
                    if fp.get("firmware") and not device.firmware:
                        device.firmware = fp["firmware"]
                    if fp.get("serial_number") and not device.serial_number:
                        device.serial_number = fp["serial_number"]
                    if fp.get("role") and device.role == "unknown":
                        device.role = fp["role"]

    def _score_risk(self, device: PLCDevice) -> None:
        """Assign a risk level and populate risk_factors."""
        score = 0
        factors: List[str] = []
        proto_names = device.get_protocol_names()

        for proto_name in proto_names:
            if proto_name in UNENCRYPTED_PROTOCOLS:
                score += 2
                factors.append(f"Unencrypted industrial protocol: {proto_name}")

        if "S7comm" in proto_names and "S7comm+" not in proto_names:
            score += 1
            factors.append("Legacy S7comm (no confidentiality or integrity protection)")

        if len(device.protocols) > 2:
            score += 1
            factors.append(f"Multiple industrial protocols exposed ({len(device.protocols)})")

        if len(device.communicating_with) > 15:
            score += 1
            factors.append(f"Unusually high number of communicating peers ({len(device.communicating_with)})")

        if device.role == "plc":
            score += 1      # PLCs have higher inherent consequence

        if score == 0:
            device.risk_level = "low"
        elif score <= 2:
            device.risk_level = "medium"
        elif score <= 4:
            device.risk_level = "high"
        else:
            device.risk_level = "critical"

        device.risk_factors = factors

    # ------------------------------------------------------------------ helpers

    def _get_device(self, ip: str) -> PLCDevice:
        if ip not in self._devices:
            self._devices[ip] = PLCDevice(ip=ip)
        return self._devices[ip]


def _is_unicast_mac(mac: str) -> bool:
    """Return True if the MAC is a unicast (non-broadcast/multicast) address."""
    if not mac:
        return False
    first_byte = mac.split(":")[0] if ":" in mac else mac[:2]
    try:
        return int(first_byte, 16) & 0x01 == 0 and mac.upper() != "FF:FF:FF:FF:FF:FF"
    except ValueError:
        return False
