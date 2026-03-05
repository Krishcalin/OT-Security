"""
Core PCAP Analysis Engine for RTU / FRTU Passive Scanner.

Key differences from the PLC scanner core:
  1. Layer-2 frame handling — GOOSE (0x88B8) and SV (0x88BA) are parsed
     directly from Ethernet frames, before any IP check.
  2. Stateful protocol analyzers — DNP3, IEC-104, and GOOSE analyzers
     accumulate session state across packets. The core queries that state
     after all packets are processed and feeds it to the VulnerabilityEngine.
  3. VulnerabilityEngine assessment — called once per device after analysis,
     populates device.vulnerabilities and device.risk_level.
"""
import sys
import socket
import struct
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from .models import RTUDevice, ProtocolDetection
from .protocols.dnp3         import DNP3Analyzer
from .protocols.iec104       import IEC104Analyzer
from .protocols.iec61850_mms import IEC61850MmsAnalyzer
from .protocols.goose        import GOOSEAnalyzer, SVAnalyzer
from .protocols.modbus       import ModbusAnalyzer
from .protocols.sel_protocol import SELProtocolAnalyzer
from .fingerprint.engine     import FingerprintEngine
from .vuln.engine            import VulnerabilityEngine

# Known RTU/FRTU OT ports tracked as server (device) ports
INDUSTRIAL_PORTS: Dict[int, str] = {
    102:   "IEC 61850 MMS / S7comm (ISO-TSAP)",
    502:   "Modbus/TCP",
    702:   "SEL Fast Message",
    2404:  "IEC 60870-5-104",
    4840:  "OPC-UA",
    5006:  "MELSEC MC Protocol",
    5007:  "MELSEC MC Protocol",
    9600:  "Omron FINS",
    20000: "DNP3",
    44818: "EtherNet/IP",
    47808: "BACnet/IP",
    1911:  "Niagara Fox",
    10001: "DNP3 (alt)",
    10002: "DNP3 (alt)",
    2000:  "ICCP / TASE.2",
    2001:  "ICCP / TASE.2",
}

# EtherTypes for Layer-2 protocols
ETH_GOOSE = 0x88B8
ETH_SV    = 0x88BA
ETH_VLAN  = 0x8100
ETH_QINQ  = 0x88A8


class PCAPAnalyzer:
    """
    Main PCAP analysis engine for RTU/FRTU passive scanning.

    Usage:
        analyzer = PCAPAnalyzer(verbose=True)
        devices  = analyzer.analyze("capture.pcap")
    """

    def __init__(self, verbose: bool = False, min_packets: int = 1):
        self.verbose     = verbose
        self.min_packets = min_packets

        # Per-IP device registry
        self._devices: Dict[str, RTUDevice] = {}

        # IP-transport protocol analyzers (stateful)
        self._dnp3_analyzer  = DNP3Analyzer()
        self._iec104_analyzer = IEC104Analyzer()
        self._mms_analyzer   = IEC61850MmsAnalyzer()
        self._modbus_analyzer = ModbusAnalyzer()
        self._sel_analyzer   = SELProtocolAnalyzer()
        self._ip_analyzers   = [
            self._dnp3_analyzer,
            self._iec104_analyzer,
            self._mms_analyzer,
            self._modbus_analyzer,
            self._sel_analyzer,
        ]

        # Layer-2 analyzers
        self._goose_analyzer = GOOSEAnalyzer()
        self._sv_analyzer    = SVAnalyzer()

        self._fingerprinter = FingerprintEngine()
        self._vuln_engine   = VulnerabilityEngine()

        # Track IPs seen doing MMS (for IEC 61850 MMS vuln check)
        self._mms_ips: Set[str] = set()

    # ─────────────────────────────────────────────────────── public API ──

    def analyze(self, pcap_file: str) -> List[RTUDevice]:
        """Read PCAP and return a sorted list of discovered RTU/FRTU devices."""
        try:
            from scapy.all import PcapReader   # noqa: F401
            return self._analyze_with_scapy(pcap_file)
        except ImportError:
            pass
        try:
            import dpkt                        # noqa: F401
            return self._analyze_with_dpkt(pcap_file)
        except ImportError:
            pass
        print("[ERROR] Install scapy (pip install scapy) or dpkt (pip install dpkt)")
        sys.exit(1)

    # ─────────────────────────────────────────────────── scapy reader ────

    def _analyze_with_scapy(self, pcap_file: str) -> List[RTUDevice]:
        from scapy.all import PcapReader, IP, TCP, UDP, Ether

        total = 0
        print("[*] Using scapy …")
        try:
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    total += 1
                    if total % 10_000 == 0:
                        print(f"    {total:,} packets …", end="\r", flush=True)
                    try:
                        ts = datetime.fromtimestamp(float(pkt.time))
                    except Exception:
                        ts = datetime.now()

                    # ── Layer-2 protocols first (GOOSE / SV) ─────────────
                    if pkt.haslayer(Ether):
                        src_mac = pkt[Ether].src.upper()
                        dst_mac = pkt[Ether].dst.upper()
                        eth_type = pkt[Ether].type

                        # Handle VLAN tagged frames
                        if eth_type in (ETH_VLAN, ETH_QINQ):
                            raw = bytes(pkt[Ether].payload)
                            if len(raw) >= 4:
                                eth_type = struct.unpack_from(">H", raw, 2)[0]
                                raw = raw[4:]
                            else:
                                eth_type = 0

                        if eth_type == ETH_GOOSE:
                            raw = bytes(pkt[Ether].payload)
                            result = self._goose_analyzer.analyze_frame(
                                src_mac, dst_mac, eth_type, raw, ts)
                            if result:
                                self._handle_goose_result(src_mac, result, ts)
                            continue

                        if eth_type == ETH_SV:
                            raw = bytes(pkt[Ether].payload)
                            self._sv_analyzer.analyze_frame(
                                src_mac, dst_mac, eth_type, raw, ts)
                            continue
                    else:
                        src_mac = dst_mac = None

                    # ── IP / TCP / UDP ─────────────────────────────────
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

                    self._handle_ip_packet(
                        src_ip, dst_ip, src_mac, dst_mac,
                        sport, dport, proto, payload, ts)

        except FileNotFoundError:
            print(f"\n[ERROR] File not found: {pcap_file}")
            sys.exit(1)
        except Exception as exc:
            print(f"\n[ERROR] scapy failed: {exc}")
            sys.exit(1)

        print(f"[+] {total:,} packets processed.                    ")
        return self._finalise()

    # ─────────────────────────────────────────────────── dpkt reader ─────

    def _analyze_with_dpkt(self, pcap_file: str) -> List[RTUDevice]:
        import dpkt

        total = 0
        print("[*] Using dpkt …")
        try:
            with open(pcap_file, "rb") as fh:
                try:
                    pcap = dpkt.pcap.Reader(fh)
                except Exception:
                    fh.seek(0)
                    pcap = dpkt.pcapng.Reader(fh)

                for raw_ts, buf in pcap:
                    total += 1
                    ts = datetime.fromtimestamp(raw_ts)
                    if total % 10_000 == 0:
                        print(f"    {total:,} packets …", end="\r", flush=True)
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except Exception:
                        continue

                    src_mac = ":".join(f"{b:02X}" for b in eth.src)
                    dst_mac = ":".join(f"{b:02X}" for b in eth.dst)
                    eth_type = eth.type

                    # GOOSE / SV at L2
                    if eth_type == ETH_GOOSE:
                        self._goose_analyzer.analyze_frame(
                            src_mac, dst_mac, eth_type, bytes(eth.data), ts)
                        continue
                    if eth_type == ETH_SV:
                        self._sv_analyzer.analyze_frame(
                            src_mac, dst_mac, eth_type, bytes(eth.data), ts)
                        continue

                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip     = eth.data
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
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

                    self._handle_ip_packet(
                        src_ip, dst_ip, src_mac, dst_mac,
                        sport, dport, proto, payload, ts)

        except FileNotFoundError:
            print(f"\n[ERROR] File not found: {pcap_file}")
            sys.exit(1)
        except Exception as exc:
            print(f"\n[ERROR] dpkt failed: {exc}")
            sys.exit(1)

        print(f"[+] {total:,} packets processed.                    ")
        return self._finalise()

    # ─────────────────────────────────────────────────────── handlers ─────

    def _handle_ip_packet(
        self,
        src_ip: str, dst_ip: str,
        src_mac: Optional[str], dst_mac: Optional[str],
        sport: int, dport: int,
        proto: str, payload: bytes,
        ts: datetime,
    ) -> None:
        # Update source device
        src_dev = self._get_device(src_ip)
        src_dev.packet_count += 1
        src_dev.update_time(ts)
        src_dev.communicating_with.add(dst_ip)
        if src_mac and _unicast(src_mac) and not src_dev.mac:
            src_dev.mac = src_mac

        # Track server-side ports
        if dport in INDUSTRIAL_PORTS:
            dst_dev = self._get_device(dst_ip)
            dst_dev.open_ports.add(dport)
            dst_dev.update_time(ts)
            dst_dev.communicating_with.add(src_ip)
            if dst_mac and _unicast(dst_mac) and not dst_dev.mac:
                dst_dev.mac = dst_mac
            # Track master→RTU relationship
            dst_dev.master_stations.add(src_ip)

        if not payload:
            return

        for analyzer in self._ip_analyzers:
            if not analyzer.can_analyze(sport, dport, proto, payload):
                continue
            try:
                results = analyzer.analyze(
                    src_ip, dst_ip, sport, dport, proto, payload, ts)
                if results:
                    for device_ip, detection in results:
                        dev = self._get_device(device_ip)
                        dev.add_protocol(detection)
                        if detection.protocol == "IEC 61850 MMS":
                            self._mms_ips.add(device_ip)
                        if self.verbose:
                            print(f"  [+] {device_ip}  {detection.protocol}  "
                                  f"({detection.confidence})")
            except Exception as exc:
                if self.verbose:
                    print(f"  [!] {analyzer.__class__.__name__}: {exc}")

    def _handle_goose_result(
        self, src_mac: str, result: dict, ts: datetime
    ) -> None:
        """Register a GOOSE publisher — link to an IP device if known."""
        # Try to find the device by MAC
        for dev in self._devices.values():
            if dev.mac and dev.mac.upper() == src_mac.upper():
                dev.update_time(ts)
                goose_id = result.get("goose_id", "")
                gcb_ref  = result.get("gcb_ref", "")
                if goose_id:
                    dev.goose_ids.add(goose_id)
                # Add GOOSE protocol detection
                det = ProtocolDetection(
                    protocol="IEC 61850 GOOSE",
                    port=0,
                    confidence="high",
                    transport="Ethernet",
                    details=result,
                    first_seen=ts,
                    last_seen=ts,
                    packet_count=1,
                )
                dev.add_protocol(det)
                return
        # GOOSE publisher not yet linked to an IP — store by MAC
        # It will be linked during fingerprinting if an IP later appears
        # with the same MAC.

    # ─────────────────────────────────────────── finalisation ────────────

    def _finalise(self) -> List[RTUDevice]:
        """Apply fingerprinting, vulnerability assessment, and return results."""
        # Collect all session state from protocol analyzers
        dnp3_sessions   = self._dnp3_analyzer.get_sessions()
        iec104_sessions = self._iec104_analyzer.get_sessions()
        goose_pubs      = self._goose_analyzer.get_sessions()

        # Link any GOOSE publishers found by MAC to their IP devices
        self._link_goose_to_devices(goose_pubs)

        for device in self._devices.values():
            # Fingerprint vendor / make / model
            self._fingerprinter.fingerprint(device)

            # Attach GOOSE logical device names from MMS analyzer
            ln_set = self._mms_analyzer.get_logical_nodes(device.ip)
            device.logical_nodes.update(ln_set)

        # Filter: only devices with protocol detections or OT ports
        results = [
            d for d in self._devices.values()
            if (d.protocols or d.open_ports)
            and d.packet_count >= self.min_packets
        ]

        # Vulnerability assessment
        for device in results:
            self._vuln_engine.assess(
                device,
                dnp3_sessions   = dnp3_sessions,
                iec104_sessions = iec104_sessions,
                goose_publishers= goose_pubs,
                mms_device_ips  = self._mms_ips,
            )

        return sorted(results, key=lambda d: tuple(int(x) for x in d.ip.split(".")))

    def _link_goose_to_devices(self, goose_pubs: dict) -> None:
        """
        For each GOOSE publisher, find the IP device with matching MAC and
        attach the GOOSE detection + goose_ids.
        """
        for (src_mac, app_id), pub in goose_pubs.items():
            for dev in self._devices.values():
                if dev.mac and dev.mac.upper() == src_mac.upper():
                    if pub.goose_id:
                        dev.goose_ids.add(pub.goose_id)
                    det = ProtocolDetection(
                        protocol="IEC 61850 GOOSE",
                        port=0,
                        confidence="high",
                        transport="Ethernet",
                        details={
                            "gcb_ref":    pub.gcb_ref,
                            "goose_id":   pub.goose_id,
                            "dat_set":    pub.dat_set,
                            "app_id":     f"0x{app_id:04X}",
                            "simulation": pub.simulation_seen,
                            "min_ttl_ms": pub.min_ttl_ms if pub.min_ttl_ms < 999999 else None,
                            "conf_rev_changes": pub.conf_rev_changes,
                        },
                        first_seen=pub.first_seen,
                        last_seen=pub.last_seen,
                        packet_count=pub.total_packets,
                    )
                    dev.add_protocol(det)
                    break

    # ─────────────────────────────────────────────────────── helpers ──────

    def _get_device(self, ip: str) -> RTUDevice:
        if ip not in self._devices:
            self._devices[ip] = RTUDevice(ip=ip)
        return self._devices[ip]


def _unicast(mac: str) -> bool:
    if not mac:
        return False
    try:
        first = int(mac.split(":")[0], 16)
        return (first & 0x01 == 0) and mac.upper() != "FF:FF:FF:FF:FF:FF"
    except (ValueError, IndexError):
        return False
