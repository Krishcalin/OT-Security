"""
Core PCAP Analysis Engine — Unified OT Passive Scanner v2.0.

Merges PLC and RTU scanner cores into a single engine that handles ALL 15
industrial protocol analyzers, both IP-layer and Layer-2.

Key capabilities:
  1. IP-layer analysis — Modbus, S7comm, EtherNet/IP, DNP3, FINS, MELSEC,
     IEC-104, IEC 61850 MMS, SEL Fast Message, OPC-UA, BACnet, MQTT,
     PROFINET RT
  2. Layer-2 frame analysis — GOOSE, Sampled Values, PROFINET DCP
  3. Communication flow tracking — bidirectional flow table with
     packet/byte counts for topology mapping
  4. Fingerprinting — vendor, model, firmware, serial from protocol data
  5. Vulnerability assessment — stateful checks against accumulated sessions
"""
import sys
import socket
import struct
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from .models import OTDevice, ProtocolDetection, CommFlow, NetworkZone, ZoneViolation, TopologyEdge

# ── IP-transport protocol analyzers ──────────────────────────────────────────
from .protocols.modbus       import ModbusAnalyzer
from .protocols.s7comm       import S7CommAnalyzer
from .protocols.enip         import EtherNetIPAnalyzer
from .protocols.opcua        import OPCUAAnalyzer

# The following analyzers are ported / will be ported into the unified package.
# Each import is wrapped in a try/except so the core does not crash if a
# protocol module has not yet been created — it simply skips that analyzer.

_OPTIONAL_IP_ANALYZERS = []
_OPTIONAL_L2_ANALYZERS = []

try:
    from .protocols.dnp3 import DNP3Analyzer
    _OPTIONAL_IP_ANALYZERS.append(("DNP3Analyzer", DNP3Analyzer))
except ImportError:
    pass

try:
    from .protocols.fins import FINSAnalyzer
    _OPTIONAL_IP_ANALYZERS.append(("FINSAnalyzer", FINSAnalyzer))
except ImportError:
    pass

try:
    from .protocols.melsec import MELSECAnalyzer
    _OPTIONAL_IP_ANALYZERS.append(("MELSECAnalyzer", MELSECAnalyzer))
except ImportError:
    pass

try:
    from .protocols.iec104 import IEC104Analyzer
    _OPTIONAL_IP_ANALYZERS.append(("IEC104Analyzer", IEC104Analyzer))
except ImportError:
    pass

try:
    from .protocols.iec61850_mms import IEC61850MmsAnalyzer
    _OPTIONAL_IP_ANALYZERS.append(("IEC61850MmsAnalyzer", IEC61850MmsAnalyzer))
except ImportError:
    pass

try:
    from .protocols.sel_protocol import SELProtocolAnalyzer
    _OPTIONAL_IP_ANALYZERS.append(("SELProtocolAnalyzer", SELProtocolAnalyzer))
except ImportError:
    pass

try:
    from .protocols.bacnet import BACnetAnalyzer
    _OPTIONAL_IP_ANALYZERS.append(("BACnetAnalyzer", BACnetAnalyzer))
except ImportError:
    pass

try:
    from .protocols.mqtt import MQTTAnalyzer
    _OPTIONAL_IP_ANALYZERS.append(("MQTTAnalyzer", MQTTAnalyzer))
except ImportError:
    pass

try:
    from .protocols.profinet_rt import ProfinetRTAnalyzer
    _OPTIONAL_IP_ANALYZERS.append(("ProfinetRTAnalyzer", ProfinetRTAnalyzer))
except ImportError:
    pass

# ── Layer-2 analyzers ────────────────────────────────────────────────────────

try:
    from .protocols.goose import GOOSEAnalyzer, SVAnalyzer
    _OPTIONAL_L2_ANALYZERS.append(("GOOSEAnalyzer", GOOSEAnalyzer))
    _OPTIONAL_L2_ANALYZERS.append(("SVAnalyzer", SVAnalyzer))
except ImportError:
    pass

try:
    from .protocols.profinet_dcp import ProfinetDCPAnalyzer
    _OPTIONAL_L2_ANALYZERS.append(("ProfinetDCPAnalyzer", ProfinetDCPAnalyzer))
except ImportError:
    pass

# ── Fingerprint & Vulnerability engines ──────────────────────────────────────

try:
    from .fingerprint.engine import FingerprintEngine
    _HAS_FINGERPRINT = True
except ImportError:
    _HAS_FINGERPRINT = False

try:
    from .vuln.engine import VulnerabilityEngine
    _HAS_VULN_ENGINE = True
except ImportError:
    _HAS_VULN_ENGINE = False

try:
    from .topology.engine import TopologyEngine
    _HAS_TOPOLOGY = True
except ImportError:
    _HAS_TOPOLOGY = False

try:
    from .cvedb.matcher import CVEMatcher
    _HAS_CVE_MATCHER = True
except ImportError:
    _HAS_CVE_MATCHER = False

try:
    from .protocols.it_detect import ITProtocolDetector
    _HAS_IT_DETECT = True
except ImportError:
    _HAS_IT_DETECT = False

try:
    from .protocols.behavior import BehaviorAnalyzer
    _HAS_BEHAVIOR = True
except ImportError:
    _HAS_BEHAVIOR = False


# ─────────────────────────────────────────────── Industrial Port Registry ─────
# Combined port map from PLC scanner + RTU scanner + new protocols.

INDUSTRIAL_PORTS: Dict[int, str] = {
    102:   "S7comm / IEC 61850 MMS (ISO-TSAP)",
    502:   "Modbus/TCP",
    702:   "SEL Fast Message",
    1883:  "MQTT",
    2404:  "IEC 60870-5-104",
    4840:  "OPC-UA",
    4843:  "OPC-UA (TLS)",
    5006:  "MELSEC MC Protocol",
    5007:  "MELSEC MC Protocol",
    5008:  "MELSEC MC Protocol",
    8883:  "MQTT (TLS)",
    9600:  "Omron FINS",
    10001: "DNP3 (alt)",
    10002: "DNP3 (alt)",
    18245: "GE-SRTP",
    20000: "DNP3",
    34962: "PROFINET RT",
    34963: "PROFINET RT",
    34964: "PROFINET RT",
    44818: "EtherNet/IP",
    47808: "BACnet/IP",
    1911:  "Niagara Fox",
    2000:  "ICCP / TASE.2",
    2001:  "ICCP / TASE.2",
    2222:  "EtherNet/IP (UDP I/O)",
    789:   "PROFINET DCP",
}

# ── Layer-2 EtherTypes ───────────────────────────────────────────────────────
ETH_GOOSE        = 0x88B8
ETH_SV           = 0x88BA
ETH_PROFINET_DCP = 0x8892
ETH_VLAN         = 0x8100
ETH_QINQ        = 0x88A8

L2_ETHERTYPES = {ETH_GOOSE, ETH_SV, ETH_PROFINET_DCP}

# ── Unencrypted protocol names (for risk scoring fallback) ───────────────────
UNENCRYPTED_PROTOCOLS = {
    "Modbus/TCP", "S7comm", "Omron FINS",
    "MELSEC MC Protocol", "DNP3", "IEC 60870-5-104",
    "EtherNet/IP", "BACnet/IP", "MQTT",
}


class PCAPAnalyzer:
    """
    Main PCAP analysis engine for the unified OT Passive Scanner.

    Handles all 15 protocol analyzers (IP + L2), tracks per-device state,
    records communication flows, and runs fingerprinting + vulnerability
    assessment after packet processing.

    Usage::

        analyzer = PCAPAnalyzer(verbose=True, min_packets=2)
        devices, flows = analyzer.analyze("capture.pcap")
    """

    def __init__(self, verbose: bool = False, min_packets: int = 2):
        self.verbose     = verbose
        self.min_packets = min_packets

        # Per-IP device registry
        self._devices: Dict[str, OTDevice] = {}

        # Communication flows: (src_ip, dst_ip, protocol, port) -> CommFlow
        self._flows: Dict[Tuple[str, str, str, int], CommFlow] = {}

        # ── IP-transport analyzers ───────────────────────────────────────
        # Always-available core analyzers
        self._modbus_analyzer  = ModbusAnalyzer()
        self._s7comm_analyzer  = S7CommAnalyzer()
        self._enip_analyzer    = EtherNetIPAnalyzer()
        self._opcua_analyzer   = OPCUAAnalyzer()

        self._ip_analyzers = [
            self._modbus_analyzer,
            self._s7comm_analyzer,
            self._enip_analyzer,
            self._opcua_analyzer,
        ]

        # Optional IP analyzers (loaded dynamically)
        self._dnp3_analyzer   = None
        self._iec104_analyzer = None
        self._mms_analyzer    = None

        for name, cls in _OPTIONAL_IP_ANALYZERS:
            instance = cls()
            self._ip_analyzers.append(instance)
            # Keep references to stateful analyzers
            if name == "DNP3Analyzer":
                self._dnp3_analyzer = instance
            elif name == "IEC104Analyzer":
                self._iec104_analyzer = instance
            elif name == "IEC61850MmsAnalyzer":
                self._mms_analyzer = instance

        # ── Layer-2 analyzers ────────────────────────────────────────────
        self._goose_analyzer = None
        self._sv_analyzer    = None
        self._pn_dcp_analyzer = None
        self._l2_analyzers   = []

        for name, cls in _OPTIONAL_L2_ANALYZERS:
            instance = cls()
            self._l2_analyzers.append((name, instance))
            if name == "GOOSEAnalyzer":
                self._goose_analyzer = instance
            elif name == "SVAnalyzer":
                self._sv_analyzer = instance
            elif name == "ProfinetDCPAnalyzer":
                self._pn_dcp_analyzer = instance

        # ── Fingerprint & vulnerability engines ──────────────────────────
        self._fingerprinter = FingerprintEngine() if _HAS_FINGERPRINT else None
        self._vuln_engine   = VulnerabilityEngine() if _HAS_VULN_ENGINE else None
        self._topology_engine = TopologyEngine() if _HAS_TOPOLOGY else None
        self._cve_matcher = CVEMatcher() if _HAS_CVE_MATCHER else None
        self._external_cve_db: Optional[str] = None
        self._it_detector = ITProtocolDetector() if _HAS_IT_DETECT else None
        self._behavior_analyzer = BehaviorAnalyzer() if _HAS_BEHAVIOR else None

        # Track IPs seen doing MMS (for IEC 61850 MMS vuln check)
        self._mms_ips: Set[str] = set()

        # Project file devices (injected via set_project_devices before analyze)
        self._project_devices: Dict[str, OTDevice] = {}

    def set_project_devices(self, devices: Dict[str, OTDevice]) -> None:
        """
        Inject ground-truth devices from ICS project file analysis.

        Must be called BEFORE analyze().  Devices are merged into the PCAP
        device registry during _finalise(), so PCAP traffic for matching IPs
        is fully correlated with project file identity data.
        """
        self._project_devices = devices

    def set_cve_database(self, path: str) -> None:
        """Load an external CVE database JSON file to supplement built-in CVEs."""
        if _HAS_CVE_MATCHER:
            self._cve_matcher = CVEMatcher(extra_cve_file=path)
            self._external_cve_db = path

    # ─────────────────────────────────────────────────────── public API ──

    def analyze(self, pcap_file: str) -> Tuple[List[OTDevice], List[CommFlow], List[NetworkZone], List[ZoneViolation], List[TopologyEdge]]:
        """
        Read a PCAP/PCAPNG file and return discovered devices, flows,
        network zones, zone violations, and topology edges.

        Tries scapy first; falls back to dpkt if scapy is not installed.
        """
        try:
            from scapy.all import PcapReader  # noqa: F401
            return self._analyze_with_scapy(pcap_file)
        except ImportError:
            pass
        try:
            import dpkt  # noqa: F401
            return self._analyze_with_dpkt(pcap_file)
        except ImportError:
            pass

        print("[ERROR] No packet library found.")
        print("        Install scapy:  pip install scapy")
        print("        or dpkt:        pip install dpkt")
        sys.exit(1)

    # ─────────────────────────────────────────────────── scapy reader ────

    def _analyze_with_scapy(
        self, pcap_file: str,
    ) -> Tuple[List[OTDevice], List[CommFlow], List[NetworkZone], List[ZoneViolation], List[TopologyEdge]]:
        from scapy.all import PcapReader, IP, TCP, UDP, Ether

        total = 0
        print("[*] Using scapy to read PCAP ...")
        try:
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    total += 1
                    if total % 10_000 == 0:
                        print(f"    {total:,} packets ...", end="\r", flush=True)
                    try:
                        ts = datetime.fromtimestamp(float(pkt.time))
                    except Exception:
                        ts = datetime.now()

                    # ── Layer-2 protocols first (GOOSE / SV / PROFINET DCP) ──
                    if pkt.haslayer(Ether):
                        src_mac = pkt[Ether].src.upper()
                        dst_mac = pkt[Ether].dst.upper()
                        eth_type = pkt[Ether].type

                        # Handle VLAN / QinQ tagged frames
                        raw_l2 = bytes(pkt[Ether].payload)
                        if eth_type in (ETH_VLAN, ETH_QINQ):
                            if len(raw_l2) >= 4:
                                eth_type = struct.unpack_from(">H", raw_l2, 2)[0]
                                raw_l2 = raw_l2[4:]
                            else:
                                eth_type = 0

                        if eth_type in L2_ETHERTYPES:
                            self._handle_l2_frame(
                                src_mac, dst_mac, eth_type, raw_l2, ts)
                            continue
                    else:
                        src_mac = dst_mac = None

                    # ── IP / TCP / UDP ───────────────────────────────────────
                    if not pkt.haslayer(IP):
                        continue

                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    pkt_len = len(pkt)

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
                        sport, dport, proto, payload, ts, pkt_len)

        except FileNotFoundError:
            print(f"\n[ERROR] File not found: {pcap_file}")
            sys.exit(1)
        except Exception as exc:
            print(f"\n[ERROR] scapy failed to read PCAP: {exc}")
            sys.exit(1)

        print(f"[+] {total:,} packets processed.                    ")
        return self._finalise()

    # ─────────────────────────────────────────────────── dpkt reader ─────

    def _analyze_with_dpkt(
        self, pcap_file: str,
    ) -> Tuple[List[OTDevice], List[CommFlow], List[NetworkZone], List[ZoneViolation], List[TopologyEdge]]:
        import dpkt

        total = 0
        print("[*] Using dpkt to read PCAP ...")
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
                        print(f"    {total:,} packets ...", end="\r", flush=True)
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except Exception:
                        continue

                    src_mac = ":".join(f"{b:02X}" for b in eth.src)
                    dst_mac = ":".join(f"{b:02X}" for b in eth.dst)
                    eth_type = eth.type

                    # ── Layer-2 protocols (GOOSE / SV / PROFINET DCP) ────
                    if eth_type in L2_ETHERTYPES:
                        self._handle_l2_frame(
                            src_mac, dst_mac, eth_type, bytes(eth.data), ts)
                        continue

                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip     = eth.data
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    pkt_len = len(buf)
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
                        sport, dport, proto, payload, ts, pkt_len)

        except FileNotFoundError:
            print(f"\n[ERROR] File not found: {pcap_file}")
            sys.exit(1)
        except Exception as exc:
            print(f"\n[ERROR] dpkt failed to read PCAP: {exc}")
            sys.exit(1)

        print(f"[+] {total:,} packets processed.                    ")
        return self._finalise()

    # ─────────────────────────────────────────────────── packet handlers ──

    def _handle_ip_packet(
        self,
        src_ip: str, dst_ip: str,
        src_mac: Optional[str], dst_mac: Optional[str],
        sport: int, dport: int,
        proto: str, payload: bytes,
        ts: datetime,
        pkt_len: int = 0,
    ) -> None:
        """Update device state, record flow, and dispatch to protocol analyzers."""
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
            # Track master -> device relationship
            dst_dev.master_stations.add(src_ip)

        # Record communication flow
        proto_name = INDUSTRIAL_PORTS.get(dport) or INDUSTRIAL_PORTS.get(sport) or proto
        flow_port = dport if dport in INDUSTRIAL_PORTS else sport
        self._record_flow(src_ip, dst_ip, proto_name, flow_port, proto, ts, pkt_len)

        if not payload:
            return

        # Dispatch to all IP protocol analyzers
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

        # IT protocol detection (after OT analyzers)
        if self._it_detector:
            try:
                self._it_detector.analyze(
                    src_ip, dst_ip, sport, dport, proto, payload, ts)
            except Exception:
                pass

    def _handle_l2_frame(
        self,
        src_mac: str, dst_mac: str,
        eth_type: int, payload: bytes,
        ts: datetime,
    ) -> None:
        """Dispatch Layer-2 frames to GOOSE, SV, and PROFINET DCP analyzers."""
        if eth_type == ETH_GOOSE and self._goose_analyzer:
            result = self._goose_analyzer.analyze_frame(
                src_mac, dst_mac, eth_type, payload, ts)
            if result:
                self._handle_goose_result(src_mac, result, ts)
            return

        if eth_type == ETH_SV and self._sv_analyzer:
            self._sv_analyzer.analyze_frame(
                src_mac, dst_mac, eth_type, payload, ts)
            return

        if eth_type == ETH_PROFINET_DCP and self._pn_dcp_analyzer:
            self._pn_dcp_analyzer.analyze_frame(
                src_mac, dst_mac, eth_type, payload, ts)
            return

    def _handle_goose_result(
        self, src_mac: str, result: dict, ts: datetime,
    ) -> None:
        """Register a GOOSE publisher -- link to an IP device if known."""
        for dev in self._devices.values():
            if dev.mac and dev.mac.upper() == src_mac.upper():
                dev.update_time(ts)
                goose_id = result.get("goose_id", "")
                if goose_id:
                    dev.goose_ids.add(goose_id)
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

    # ─────────────────────────────────────────── flow tracking ────────────

    def _record_flow(
        self,
        src_ip: str, dst_ip: str,
        protocol: str, port: int,
        transport: str,
        ts: datetime,
        pkt_len: int = 0,
    ) -> None:
        """Create or update a CommFlow entry."""
        key = (src_ip, dst_ip, protocol, port)
        if key not in self._flows:
            self._flows[key] = CommFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                port=port,
                transport=transport,
                first_seen=ts,
                last_seen=ts,
                packet_count=0,
                byte_count=0,
            )
        flow = self._flows[key]
        flow.packet_count += 1
        flow.byte_count += pkt_len
        if ts < (flow.first_seen or ts):
            flow.first_seen = ts
        if ts > (flow.last_seen or ts):
            flow.last_seen = ts

    # ─────────────────────────────────────────── finalisation ─────────────

    def _finalise(self) -> Tuple[List[OTDevice], List[CommFlow], List[NetworkZone], List[ZoneViolation], List[TopologyEdge]]:
        """Apply fingerprinting, vulnerability assessment, and return results."""
        # Collect session state from stateful protocol analyzers
        dnp3_sessions   = self._dnp3_analyzer.get_sessions() if self._dnp3_analyzer else {}
        iec104_sessions = self._iec104_analyzer.get_sessions() if self._iec104_analyzer else {}
        goose_pubs      = self._goose_analyzer.get_sessions() if self._goose_analyzer else {}

        # Link any GOOSE publishers found by MAC to their IP devices
        if goose_pubs:
            self._link_goose_to_devices(goose_pubs)

        # ── Merge project file ground-truth devices ─────────────────────
        self._merge_project_devices()

        # ── Fingerprinting (skip ground-truth devices) ───────────────────
        for device in self._devices.values():
            if self._fingerprinter and device.vendor_confidence != "ground_truth":
                self._fingerprinter.fingerprint(device)

            # Attach logical device names from MMS analyzer
            if self._mms_analyzer:
                try:
                    ln_set = self._mms_analyzer.get_logical_nodes(device.ip)
                    device.logical_nodes.update(ln_set)
                except Exception:
                    pass

        # ── Protocol behavior analysis (DPI stats) ────────────────────
        if self._behavior_analyzer:
            for device in self._devices.values():
                try:
                    device.protocol_stats = self._behavior_analyzer.analyze_device(device)
                except Exception:
                    pass

        # ── IT protocol attachment ─────────────────────────────────────
        if self._it_detector:
            for device in self._devices.values():
                try:
                    device.it_protocols = self._it_detector.get_device_hits(device.ip)
                except Exception:
                    pass

        # ── Asset criticality inference ──────────────────────────────
        for device in self._devices.values():
            self._infer_criticality(device)

        # ── Communication profile computation ────────────────────────
        for device in self._devices.values():
            self._compute_communication_profile(device)

        # ── Filter: OT devices + ground-truth project-file devices ────
        results = [
            d for d in self._devices.values()
            if (
                (d.protocols or d.open_ports)
                and d.packet_count >= self.min_packets
            )
            or d.vendor_confidence == "ground_truth"
        ]

        # ── Vulnerability assessment ─────────────────────────────────────
        for device in results:
            if self._vuln_engine:
                try:
                    self._vuln_engine.assess(
                        device,
                        dnp3_sessions=dnp3_sessions,
                        iec104_sessions=iec104_sessions,
                        goose_publishers=goose_pubs,
                        mms_device_ips=self._mms_ips,
                    )
                except TypeError:
                    # Fallback: vuln engine may have a simpler signature
                    try:
                        self._vuln_engine.assess(device)
                    except Exception:
                        pass
            else:
                # Basic risk scoring when vuln engine is not available
                self._score_risk(device)

        # ── CVE matching ──────────────────────────────────────────────
        if self._cve_matcher:
            for device in results:
                try:
                    matches = self._cve_matcher.match_device(device)
                    device.cve_matches = matches
                except Exception as exc:
                    if self.verbose:
                        print(f"  [!] CVE matching error for {device.ip}: {exc}")

        # Sort devices by IP
        devices_sorted = sorted(
            results,
            key=lambda d: tuple(int(x) for x in d.ip.split(".")),
        )

        # Sort flows by packet count (descending)
        flows_sorted = sorted(
            self._flows.values(),
            key=lambda f: -f.packet_count,
        )

        # ── Topology analysis ─────────────────────────────────────────
        zones: List[NetworkZone] = []
        violations: List[ZoneViolation] = []
        edges: List[TopologyEdge] = []
        if self._topology_engine:
            try:
                zones, violations, edges = self._topology_engine.analyze(
                    devices_sorted, flows_sorted)
            except Exception as exc:
                if self.verbose:
                    print(f"  [!] Topology analysis error: {exc}")

        # ── Composite risk scoring (needs zones for exposure multiplier) ──
        try:
            from .risk.engine import CompositeRiskEngine
            _risk_engine = CompositeRiskEngine(zones=zones)
            for device in devices_sorted:
                _risk_engine.score_device(device)
        except ImportError:
            pass
        except Exception as exc:
            if self.verbose:
                print(f"  [!] Composite risk scoring error: {exc}")

        # ── Threat detection & behavioral baselining ─────────────────────
        try:
            from .threat.engine import ThreatDetectionEngine
            _threat_engine = ThreatDetectionEngine(
                devices=devices_sorted,
                flows=flows_sorted,
                zones=zones,
                edges=edges,
                dnp3_sessions=dnp3_sessions,
                iec104_sessions=iec104_sessions,
                goose_publishers=goose_pubs,
            )
            alerts_by_ip = _threat_engine.analyze()
            for device in devices_sorted:
                device.threat_alerts = alerts_by_ip.get(device.ip, [])
        except ImportError:
            pass
        except Exception as exc:
            if self.verbose:
                print(f"  [!] Threat detection error: {exc}")

        # ── Secure access audit ────────────────────────────────────────
        try:
            from .access.engine import SecureAccessEngine
            _access_engine = SecureAccessEngine(
                devices=devices_sorted,
                flows=flows_sorted,
                zones=zones,
                edges=edges,
            )
            sessions_by_ip = _access_engine.audit()
            for device in devices_sorted:
                device.remote_access_sessions = sessions_by_ip.get(device.ip, [])
        except ImportError:
            pass
        except Exception as exc:
            if self.verbose:
                print(f"  [!] Secure access audit error: {exc}")

        return devices_sorted, flows_sorted, zones, violations, edges

    def _link_goose_to_devices(self, goose_pubs: dict) -> None:
        """
        For each GOOSE publisher, find the IP device with matching MAC and
        attach the GOOSE detection + goose_ids.
        """
        for key, pub in goose_pubs.items():
            # Key may be (src_mac, app_id) tuple
            if isinstance(key, tuple) and len(key) >= 1:
                src_mac = key[0]
                app_id  = key[1] if len(key) > 1 else 0
            else:
                continue

            for dev in self._devices.values():
                if dev.mac and dev.mac.upper() == src_mac.upper():
                    goose_id = getattr(pub, "goose_id", "")
                    if goose_id:
                        dev.goose_ids.add(goose_id)
                    det = ProtocolDetection(
                        protocol="IEC 61850 GOOSE",
                        port=0,
                        confidence="high",
                        transport="Ethernet",
                        details={
                            "gcb_ref":    getattr(pub, "gcb_ref", ""),
                            "goose_id":   goose_id,
                            "dat_set":    getattr(pub, "dat_set", ""),
                            "app_id":     f"0x{app_id:04X}" if isinstance(app_id, int) else str(app_id),
                            "simulation": getattr(pub, "simulation_seen", False),
                            "min_ttl_ms": getattr(pub, "min_ttl_ms", None),
                            "conf_rev_changes": getattr(pub, "conf_rev_changes", 0),
                        },
                        first_seen=getattr(pub, "first_seen", None),
                        last_seen=getattr(pub, "last_seen", None),
                        packet_count=getattr(pub, "total_packets", 1),
                    )
                    dev.add_protocol(det)
                    break

    def _score_risk(self, device: OTDevice) -> None:
        """
        Basic risk scoring when the full VulnerabilityEngine is not available.
        Uses the same heuristic as the PLC scanner.
        """
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
            factors.append(
                f"Multiple industrial protocols exposed ({len(device.protocols)})"
            )

        if len(device.communicating_with) > 15:
            score += 1
            factors.append(
                f"Unusually high number of communicating peers "
                f"({len(device.communicating_with)})"
            )

        if device.role in ("plc", "rtu", "frtu"):
            score += 1

        if device.vulnerabilities:
            # If vuln engine already ran partially, factor in existing vulns
            vuln_weight = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
            score += sum(vuln_weight.get(v.severity, 0) for v in device.vulnerabilities)

        if score == 0:
            device.risk_level = "low"
        elif score <= 2:
            device.risk_level = "medium"
        elif score <= 4:
            device.risk_level = "high"
        else:
            device.risk_level = "critical"

        device.risk_factors = factors
        device.risk_score = score

    # ──────────────────── project file merging ─────────────────────────

    def _merge_project_devices(self) -> None:
        """
        Merge project-file ground-truth devices into the PCAP device registry.

        Three cases:
          1. IP in both: project data overrides identity fields, enriches context
          2. IP only in project: added as new entry (ground_truth, no PCAP traffic)
          3. IP only in PCAP: unchanged
        """
        if not self._project_devices:
            return

        for ip, proj_dev in self._project_devices.items():
            if ip in self._devices:
                self._apply_ground_truth(self._devices[ip], proj_dev)
            else:
                proj_dev.vendor_confidence = "ground_truth"
                self._devices[ip] = proj_dev

    @staticmethod
    def _apply_ground_truth(pcap_dev: OTDevice, proj_dev: OTDevice) -> None:
        """
        Apply ground-truth project data onto a PCAP-discovered device.

        Ground-truth fields OVERRIDE whatever fingerprinting would have set.
        Business context fields are ADDED (they never come from PCAP).
        """
        _OVERRIDE = [
            "vendor", "make", "model", "firmware", "serial_number",
            "hardware_version", "product_code", "rack", "slot",
            "cpu_info", "device_type", "role",
        ]
        for attr in _OVERRIDE:
            proj_val = getattr(proj_dev, attr, None)
            if proj_val is not None and proj_val != "" and proj_val != "unknown":
                setattr(pcap_dev, attr, proj_val)

        pcap_dev.vendor_confidence = "ground_truth"

        _ENRICH = ["asset_owner", "location", "asset_tag", "device_criticality"]
        for attr in _ENRICH:
            cur = getattr(pcap_dev, attr, None)
            proj_val = getattr(proj_dev, attr, None)
            if (
                (cur is None or cur == "" or cur == "unknown")
                and proj_val
                and proj_val != "unknown"
            ):
                setattr(pcap_dev, attr, proj_val)

        if proj_dev.modules:
            pcap_dev.modules.extend(proj_dev.modules)
        pcap_dev.notes.extend(proj_dev.notes)

    # ────────────────────────── deep asset profiling ──────────────────────

    def _infer_criticality(self, device: OTDevice) -> None:
        """
        Auto-infer device_criticality from protocol evidence and behaviour.

        Categories (most critical first):
          safety_system   — SIS protocols, GOOSE trip logic, safety PLC vendors
          process_control — PLCs/RTUs with active control/write commands
          monitoring      — Read-heavy devices, historians, HMIs
          support         — Engineering stations, gateways, IT-heavy devices
          unknown         — Default
        """
        if device.device_criticality != "unknown":
            return  # already set externally

        proto_names = set(device.get_protocol_names())

        # ── Safety system indicators ──
        is_safety = False

        # CIP Safety device types
        for proto in device.protocols:
            cip_dt = proto.details.get("cip_device_type")
            if cip_dt and isinstance(cip_dt, str) and "safety" in cip_dt.lower():
                is_safety = True
                break

        # GOOSE with trip / protection related IDs
        if not is_safety and device.goose_ids:
            safety_kw = {
                "trip", "prot", "cbfail", "busbar", "diff",
                "dist", "overcurrent", "oc", "ef",
            }
            for gid in device.goose_ids:
                if any(kw in gid.lower() for kw in safety_kw):
                    is_safety = True
                    break

        # Safety PLC vendor names
        if not is_safety:
            safety_vendors = {"pilz", "hima", "triconex", "tricon", "prosafe"}
            combined_id = " ".join(
                filter(None, [device.vendor, device.make, device.model])
            ).lower()
            if any(sv in combined_id for sv in safety_vendors):
                is_safety = True

        if is_safety:
            device.device_criticality = "safety_system"
            return

        # ── Process control indicators ──
        has_control = False
        for ps in device.protocol_stats:
            if ps.write_count > 0 or ps.control_count > 0:
                has_control = True
                break

        if has_control and device.role in (
            "plc", "rtu", "frtu", "ied", "relay",
        ):
            device.device_criticality = "process_control"
            return

        # ── Monitoring indicators ──
        if device.role == "historian":
            device.device_criticality = "monitoring"
            return

        if device.role in ("hmi", "master_station"):
            device.device_criticality = "process_control" if has_control else "monitoring"
            return

        if device.role in ("plc", "rtu", "frtu", "ied"):
            read_total = sum(ps.read_count for ps in device.protocol_stats)
            if read_total > 0 and not has_control:
                device.device_criticality = "monitoring"
            else:
                device.device_criticality = "process_control"
            return

        # ── Support indicators ──
        if device.role in ("engineering_station", "gateway"):
            device.device_criticality = "support"
            return

        if device.it_protocols:
            device.device_criticality = "support"
            return

    def _compute_communication_profile(self, device: OTDevice) -> None:
        """
        Compute a communication profile summary for the device.

        Aggregates flow data, behavioural stats, and master/slave
        relationships into a single dict on device.communication_profile.
        """
        peer_count = len(device.communicating_with)
        protocol_list = device.get_protocol_names()

        # Aggregate bytes from flows
        total_bytes_out = 0
        total_bytes_in = 0
        for flow in self._flows.values():
            if flow.src_ip == device.ip:
                total_bytes_out += flow.byte_count
            elif flow.dst_ip == device.ip:
                total_bytes_in += flow.byte_count

        # Aggregate read/write/control from behaviour stats
        total_reads = sum(ps.read_count for ps in device.protocol_stats)
        total_writes = sum(ps.write_count for ps in device.protocol_stats)
        total_controls = sum(ps.control_count for ps in device.protocol_stats)
        total_ops = total_reads + total_writes + total_controls

        control_ratio = round(total_controls / total_ops, 3) if total_ops > 0 else 0.0
        if total_writes > 0:
            rw_ratio: object = round(total_reads / total_writes, 2)
        elif total_reads > 0:
            rw_ratio = "read_only"
        else:
            rw_ratio = 0.0

        # Master/slave classification
        sends_controls = total_controls > 0 and len(device.master_stations) == 0
        receives_controls = len(device.master_stations) > 0

        if sends_controls and not receives_controls:
            role_class = "master"
        elif receives_controls and not sends_controls:
            role_class = "slave"
        else:
            role_class = "peer"

        # Detect program events from behaviour stats
        for ps in device.protocol_stats:
            if ps.has_program_upload and not device.last_program_event:
                device.last_program_event = "upload"
            if ps.has_program_download:
                device.last_program_event = "download"  # download overrides

        device.communication_profile = {
            "peer_count":      peer_count,
            "protocols":       protocol_list,
            "total_bytes_out": total_bytes_out,
            "total_bytes_in":  total_bytes_in,
            "control_ratio":   control_ratio,
            "read_write_ratio": rw_ratio,
            "is_master":       role_class == "master",
            "is_slave":        role_class == "slave",
            "is_peer":         role_class == "peer",
        }

    # ─────────────────────────────────────────────────────── helpers ──────

    def _get_device(self, ip: str) -> OTDevice:
        if ip not in self._devices:
            self._devices[ip] = OTDevice(ip=ip)
        return self._devices[ip]


def _is_unicast_mac(mac: str) -> bool:
    """Return True if the MAC is a unicast (non-broadcast/multicast) address."""
    if not mac:
        return False
    first_byte = mac.split(":")[0] if ":" in mac else mac[:2]
    try:
        return int(first_byte, 16) & 0x01 == 0 and mac.upper() != "FF:FF:FF:FF:FF:FF"
    except (ValueError, IndexError):
        return False
