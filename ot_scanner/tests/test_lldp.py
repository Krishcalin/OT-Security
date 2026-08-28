"""
LLDP — the transport network naming itself.

The load-bearing test is `test_an_unrecognised_description_yields_no_version`.

Everything else checks that a known switch is identified. That one checks the
switch nobody wrote a pattern for, and it is the one that matters, because the
version extracted here is matched against a CVE corpus. A regex loose enough to
pull a version out of any description pulls the WRONG version out of most of
them, and a wrong firmware version produces either a vulnerability the device
does not have or silence about one it does.

The System Descriptions below are in the shape the vendors actually emit.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.protocols.lldp import (ETH_LLDP, LLDPAnalyzer,      # noqa: E402
                                    device_type_for, identify)

TS = datetime(2026, 8, 28, 12, 0, 0)


# ── building an LLDPDU ─────────────────────────────────────────────────────

def tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack(">H", (tlv_type << 9) | len(value)) + value


def chassis(mac: str = "00:80:63:AA:BB:CC") -> bytes:
    return tlv(1, bytes([4]) + bytes.fromhex(mac.replace(":", "")))


def port(name: str = "Gi1/0/1") -> bytes:
    return tlv(2, bytes([5]) + name.encode())


def ttl(seconds: int = 120) -> bytes:
    return tlv(3, struct.pack(">H", seconds))


def mgmt(ip: str = "10.50.1.1") -> bytes:
    body = bytes([5, 1]) + socket.inet_aton(ip) + bytes([2]) + \
        struct.pack(">I", 1) + bytes([0])
    return tlv(8, body)


def capabilities(supported: int = 0x0014, enabled: int = 0x0004) -> bytes:
    # bit 2 = bridge, bit 4 = router
    return tlv(7, struct.pack(">HH", supported, enabled))


def lldpdu(*parts: bytes) -> bytes:
    return b"".join(parts) + tlv(0, b"")


def advert(description: str, name: str = "SUBSTN-A-SW01",
           ip: str = "10.50.1.1") -> bytes:
    return lldpdu(chassis(), port(), ttl(), tlv(5, name.encode()),
                  tlv(6, description.encode()), capabilities(), mgmt(ip))


# ── real System Descriptions ───────────────────────────────────────────────

CISCO = ("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
         "Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)")
HIRSCHMANN = ("Hirschmann RSP20 Railswitch, SW: HiOS-2A-08.5.02, "
              "HW: 1.00, Serial: 942034999000012345")
SCALANCE = ("Siemens, SIMATIC NET, SCALANCE XM416-4C, 6GK5 416-4GS00-2AM2, "
            "HW: 3, FW: V06.02.00")
RUGGEDCOM = "RuggedCom RSG2100 (ROS v4.3.4), Serial 1234567890"
MOXA = "Moxa EDS-408A-MM-SC, V3.9 build 19010211"
WESTERMO = "Westermo Lynx-3510, WeOS 4.32.3"


# ── the parser ─────────────────────────────────────────────────────────────

def test_a_switch_advertises_the_ip_an_operator_would_reach_it_on():
    """The Management Address TLV is why a switch can be inventoried BY IP at
    all. Without it a ring switch is a MAC and nothing more."""
    parsed = LLDPAnalyzer().parse(advert(CISCO, ip="10.50.7.2"))
    assert parsed["management_ip"] == "10.50.7.2"
    assert parsed["management_addresses"] == ["10.50.7.2"]


def test_the_chassis_id_and_system_name_are_read():
    parsed = LLDPAnalyzer().parse(advert(CISCO, name="MARCHWOOD-SW01"))
    assert parsed["chassis_id"] == "00:80:63:AA:BB:CC"
    assert parsed["system_name"] == "MARCHWOOD-SW01"
    assert parsed["port_id"] == "Gi1/0/1"
    assert parsed["ttl"] == 120


def test_capabilities_distinguish_enabled_from_merely_supported():
    """A box that CAN route but is not routing is a switch. Reporting the
    supported set would type half a substation as routers."""
    parsed = LLDPAnalyzer().parse(advert(CISCO))
    assert parsed["capabilities"] == ["bridge"]
    assert "router" in parsed["capabilities_supported"]
    assert device_type_for(parsed["capabilities"]) == "Switch"


# ── identification, per vendor ─────────────────────────────────────────────

@pytest.mark.parametrize("description,make,model,version", [
    (CISCO, "Cisco", "C2960", "15.0(2)SE11"),
    (HIRSCHMANN, "Hirschmann", "RSP20", "08.5.02"),
    (SCALANCE, "Siemens", "XM416-4C", "06.02.00"),
    (RUGGEDCOM, "RuggedCom", "RSG2100", "4.3.4"),
    (MOXA, "Moxa", "EDS-408A-MM-SC", "3.9"),
    (WESTERMO, "Westermo", "Lynx-3510", "4.32.3"),
])
def test_known_ring_switches_are_identified(description, make, model, version):
    found = identify(description)
    assert found["make"] == make
    assert found["model"] == model
    assert found["os_version"] == version
    assert found["firmware"] == version


def test_the_os_name_is_the_platform_not_the_marketing_string():
    """The CVE corpus is keyed on the platform. "Cisco IOS" matches advisories;
    "C2960 Software" matches nothing."""
    assert identify(CISCO)["os_name"] == "Cisco IOS"
    assert identify(HIRSCHMANN)["os_name"] == "HiOS"
    assert identify(RUGGEDCOM)["os_name"] == "ROS"


# ── refusing to guess ──────────────────────────────────────────────────────

def test_an_unrecognised_description_yields_no_version():
    """THE test. A switch family nobody wrote a pattern for must produce NO
    make, model or firmware — never an approximate one, because the version is
    matched against a CVE corpus."""
    found = identify("SomeVendor MegaSwitch 9000, build 7, kernel 2.6.32")
    assert found == {}


def test_an_unrecognised_description_is_still_recorded_verbatim():
    """Refusing to parse it is not refusing to keep it. An operator must be
    able to read exactly what the switch said."""
    text = "SomeVendor MegaSwitch 9000, build 7"
    parsed = LLDPAnalyzer().parse(advert(text))
    assert parsed["system_description"] == text
    assert parsed["identification"] == "unrecognised system description"
    assert "firmware" not in parsed and "model" not in parsed


def test_an_empty_description_is_not_an_identification():
    assert identify("") == {}
    assert identify("   ") == {}


# ── robustness on a live ring ──────────────────────────────────────────────

def test_a_frame_that_is_not_lldp_is_declined():
    analyzer = LLDPAnalyzer()
    assert not analyzer.can_analyze_frame(0x0800, b"\x45\x00")
    assert analyzer.analyze_frame("aa", "bb", 0x0800, b"x", TS) is None


def test_an_lldpdu_without_a_chassis_id_is_not_a_device():
    """Arbitrary 0x88CC traffic must not become an inventory entry."""
    assert LLDPAnalyzer().parse(lldpdu(ttl(), tlv(5, b"impostor"))) is None


def test_a_truncated_tlv_keeps_what_was_already_read():
    """A partial advertisement on a flapping ring still names the switch."""
    good = lldpdu(chassis(), port(), ttl(), tlv(5, b"SUBSTN-A-SW01"))
    # Claim a longer TLV than the bytes that follow it.
    broken = good[:-2] + struct.pack(">H", (6 << 9) | 200) + b"short"
    parsed = LLDPAnalyzer().parse(broken)
    assert parsed["system_name"] == "SUBSTN-A-SW01"
    assert parsed["truncated"] is True


def test_parsing_never_raises_on_arbitrary_input():
    """This runs on every 0x88CC frame on the ring."""
    analyzer = LLDPAnalyzer()
    for length in (0, 1, 2, 3, 17, 64, 300):
        for _ in range(20):
            analyzer.parse(os.urandom(length))


def test_a_padded_string_does_not_keep_its_padding():
    parsed = LLDPAnalyzer().parse(
        lldpdu(chassis(), ttl(), tlv(5, b"SW01\x00\x00\x00")))
    assert parsed["system_name"] == "SW01"


# ── the analyser keeps neighbours ──────────────────────────────────────────

def test_neighbours_are_keyed_on_the_chassis_rather_than_the_port_mac():
    """A switch advertises from every port with a different source MAC. Keying
    on the source would inventory one switch as twenty-four."""
    analyzer = LLDPAnalyzer()
    for source in ("00:80:63:AA:BB:01", "00:80:63:AA:BB:02"):
        analyzer.analyze_frame(source, "01:80:C2:00:00:0E", ETH_LLDP,
                               advert(CISCO), TS)
    assert len(analyzer.get_sessions()) == 1
