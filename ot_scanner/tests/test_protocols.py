"""Tests for the industrial protocol analyzers (synthetic packets; no PCAP)."""
import struct
from datetime import datetime

from scanner.protocols.hart_ip import HartIPAnalyzer
from scanner.protocols.ge_srtp import GESRTPAnalyzer
from scanner.protocols.niagara_fox import NiagaraFoxAnalyzer
from scanner.protocols.knx_ip import KNXnetIPAnalyzer

TS = datetime(2026, 1, 1)


class TestHartIP:
    def test_session_initiate(self):
        a = HartIPAnalyzer()
        # ver=1, type=0(request), id=0(session-initiate), status=0, seq=1, byte_count=8
        pkt = struct.pack(">BBBBHH", 1, 0, 0, 0, 1, 8)
        assert a.can_analyze(40000, 5094, "UDP", pkt)
        res = a.analyze("10.0.0.1", "10.0.0.2", 40000, 5094, "UDP", pkt, TS)
        assert res and res[0][0] == "10.0.0.2"
        det = res[0][1]
        assert det.protocol == "HART-IP" and det.confidence == "high"
        assert det.details["message_id"] == "session-initiate"
        assert det.transport == "UDP"

    def test_rejects_bad_version(self):
        a = HartIPAnalyzer()
        pkt = struct.pack(">BBBBHH", 9, 0, 0, 0, 1, 8)   # version 9 is invalid
        assert a.analyze("10.0.0.1", "10.0.0.2", 40000, 5094, "UDP", pkt, TS) is None

    def test_ignores_other_ports(self):
        assert not HartIPAnalyzer().can_analyze(1234, 5678, "UDP", b"\x00" * 8)


class TestGESRTP:
    def test_request(self):
        a = GESRTPAnalyzer()
        pkt = bytes([0x02]) + b"\x00" * 55           # 56-byte SRTP header
        assert a.can_analyze(50000, 18245, "TCP", pkt)
        res = a.analyze("10.0.0.3", "10.0.0.4", 50000, 18245, "TCP", pkt, TS)
        det = res[0][1]
        assert res[0][0] == "10.0.0.4"
        assert det.protocol == "GE-SRTP" and det.confidence == "high"
        assert det.details["inferred_make"] == "GE Automation"


class TestNiagaraFox:
    BANNER = (b"fox a 0 -1 fox hello\n{\n"
              b"fox.version=s:1.0.1\nhostName=s:jace-01\nstation.name=s:MainStation\n"
              b"app.name=s:Niagara\napp.version=s:4.10\nbrandId=s:Tridium\n}\n")

    def test_hello_banner(self):
        a = NiagaraFoxAnalyzer()
        assert a.can_analyze(1911, 50000, "TCP", self.BANNER)
        res = a.analyze("10.0.0.5", "10.0.0.6", 1911, 50000, "TCP", self.BANNER, TS)
        det = res[0][1]
        assert res[0][0] == "10.0.0.5"               # station is on Fox port 1911 (src here)
        assert det.protocol == "Niagara Fox" and det.confidence == "high"
        assert det.details["vendor"] == "Tridium"
        assert det.details["host_name"] == "jace-01"
        assert det.details["station_name"] == "MainStation"
        assert det.details["app_version"] == "4.10"

    def test_foxs_tls_port_only(self):
        a = NiagaraFoxAnalyzer()
        res = a.analyze("10.0.0.5", "10.0.0.6", 4911, 50000, "TCP",
                        b"\x16\x03\x01\x00\x50enc", TS)   # TLS ClientHello bytes
        det = res[0][1]
        assert det.protocol == "Niagara Foxs" and det.confidence == "medium"


class TestKNXnetIP:
    def test_routing_indication(self):
        a = KNXnetIPAnalyzer()
        pkt = bytes([0x06, 0x10]) + struct.pack(">HH", 0x0530, 6)   # header only, total_len=6
        assert a.can_analyze(3671, 3671, "UDP", pkt)
        res = a.analyze("10.0.0.7", "224.0.23.12", 3671, 3671, "UDP", pkt, TS)
        det = res[0][1]
        assert res[0][0] == "10.0.0.7"
        assert det.protocol == "KNXnet/IP" and det.confidence == "high"
        assert det.details["service_name"] == "ROUTING_INDICATION"

    def test_rejects_non_knx_header(self):
        a = KNXnetIPAnalyzer()
        assert a.analyze("10.0.0.7", "10.0.0.8", 3671, 3671, "UDP", b"\xffhelloxx", TS) is None
