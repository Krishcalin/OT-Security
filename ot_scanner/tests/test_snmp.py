"""
SNMP — the OS version for devices with no identification service.

Two tests carry this file.

`test_the_community_string_is_never_recorded` — v1/v2c send a credential in the
clear. Reading it off the mirror is the point; WRITING it into an observation
batch, a database with 13-month retention and an HTML report would create the
exposure this exists to report.

`test_snmpv3_is_observed_but_not_identified` — v3 is unreadable by design. A
device seen speaking it must not look the same as a device never seen at all.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.protocols.snmp import (SNMPAnalyzer,                # noqa: E402
                                    vendor_from_sysobjectid)

TS = datetime(2026, 8, 28, 12, 0, 0)


# ── BER builders ───────────────────────────────────────────────────────────

def ber(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + value


def integer(n: int) -> bytes:
    size = max(1, (n.bit_length() + 8) // 8)
    return ber(0x02, n.to_bytes(size, "big", signed=True))


def octets(text: str) -> bytes:
    return ber(0x04, text.encode())


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part < 0x80:
            body += bytes([part])
        else:
            chunks = []
            while part:
                chunks.insert(0, part & 0x7F)
                part >>= 7
            body += bytes([c | 0x80 for c in chunks[:-1]] + [chunks[-1]])
    return ber(0x06, body)


def varbind(name: str, value: bytes) -> bytes:
    return ber(0x30, oid(name) + value)


def message(version=1, community="public", pdu_tag=0xA2, varbinds=b"") -> bytes:
    pdu = ber(pdu_tag, integer(1) + integer(0) + integer(0)
              + ber(0x30, varbinds))
    return ber(0x30, integer(version) + octets(community) + pdu)


CISCO = ("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
         "Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)")
HIRSCHMANN = "Hirschmann RSP20 Railswitch, SW: HiOS-2A-08.5.02, HW: 1.00"


def response(description=CISCO, name="SUBSTN-A-SW01",
             sysobjectid="1.3.6.1.4.1.9.1.1208", community="public"):
    binds = varbind("1.3.6.1.2.1.1.1.0", octets(description))
    if sysobjectid:
        binds += varbind("1.3.6.1.2.1.1.2.0", oid(sysobjectid))
    if name:
        binds += varbind("1.3.6.1.2.1.1.5.0", octets(name))
    return message(community=community, varbinds=binds)


# ── identification ─────────────────────────────────────────────────────────

def test_sysdescr_yields_the_os_version():
    """The whole reason this module exists: an OS version for a device whose
    industrial protocol carries none."""
    parsed = SNMPAnalyzer().parse(response())
    assert parsed["make"] == "Cisco"
    assert parsed["model"] == "C2960"
    assert parsed["os_version"] == "15.0(2)SE11"
    assert parsed["identified_by"] == "snmp-sysdescr"


def test_sysdescr_is_read_by_the_same_table_as_lldp():
    """LLDP's System Description TLV IS the sysDescr MIB object. Two tables
    would drift, and one switch would be two different models depending on
    which road its identity arrived by."""
    from scanner.protocols.lldp import identify
    over_snmp = SNMPAnalyzer().parse(response(HIRSCHMANN))
    over_lldp = identify(HIRSCHMANN)
    assert over_snmp["model"] == over_lldp["model"] == "RSP20"
    assert over_snmp["os_version"] == over_lldp["os_version"] == "08.5.02"


def test_the_hostname_comes_from_sysname():
    parsed = SNMPAnalyzer().parse(response(name="MARCHWOOD-RTU-01"))
    assert parsed["hostname"] == "MARCHWOOD-RTU-01"


def test_sysobjectid_names_the_vendor_when_sysdescr_does_not():
    parsed = SNMPAnalyzer().parse(
        response(description="unparseable", sysobjectid="1.3.6.1.4.1.248.14.1"))
    assert parsed["vendor"] == "Hirschmann"


def test_an_unknown_enterprise_is_reported_as_its_number():
    """Never as a guessed vendor. An operator can look up 99999; they cannot
    un-read an invented name."""
    found = vendor_from_sysobjectid("1.3.6.1.4.1.99999.1.1")
    assert found["vendor_enterprise"] == 99999
    assert "vendor" not in found
    assert "look it up" in found["identification"]


def test_an_unrecognised_sysdescr_yields_no_version():
    parsed = SNMPAnalyzer().parse(response(description="MegaSwitch build 7"))
    assert "os_version" not in parsed and "model" not in parsed
    assert parsed["identification"] == "unrecognised sysDescr"


# ── the credential ─────────────────────────────────────────────────────────

def test_the_community_string_is_never_recorded():
    """THE test. It is a live credential, and this record is written to a
    database kept for 13 months and rendered into reports."""
    raw = response(community="s3cret-plant-community")
    parsed = SNMPAnalyzer().parse(raw)
    assert parsed["community_observed"] is True
    flat = repr(parsed)
    assert "s3cret" not in flat and "plant-community" not in flat


def test_a_default_community_is_flagged():
    """Read-only access to the plant's topology for anyone with a port."""
    assert SNMPAnalyzer().parse(response(community="public"))["community_is_default"]
    assert SNMPAnalyzer().parse(response(community="private"))["community_is_default"]


def test_a_non_default_community_is_not_flagged():
    parsed = SNMPAnalyzer().parse(response(community="7f3a-plant-ro"))
    assert parsed["community_is_default"] is False


# ── v3 ─────────────────────────────────────────────────────────────────────

def test_snmpv3_is_observed_but_not_identified():
    """THE other test. Unreadable by design is the correct outcome — but
    "encrypted, therefore unidentified" must not look like "absent"."""
    parsed = SNMPAnalyzer().parse(message(version=3))
    assert parsed["version"] == "v3"
    assert "os_version" not in parsed
    assert "was observed; it was not identified" in parsed["identification"]


# ── which end is the device ────────────────────────────────────────────────

def test_a_response_identifies_its_source_not_its_destination():
    """Identification belongs to the device that spoke about itself. Attaching
    a response's sysDescr to the NMS would inventory the polling station as
    every switch it polls."""
    result = SNMPAnalyzer().analyze(
        "10.50.1.1", "10.50.0.9", 161, 40000, "UDP", response(), TS)
    assert result and result[0][0] == "10.50.1.1"


def test_a_request_is_attributed_to_the_device_being_polled():
    request = message(pdu_tag=0xA0,
                      varbinds=varbind("1.3.6.1.2.1.1.1.0", ber(0x05, b"")))
    result = SNMPAnalyzer().analyze(
        "10.50.0.9", "10.50.1.1", 40000, 161, "UDP", request, TS)
    assert result and result[0][0] == "10.50.1.1"


# ── robustness ─────────────────────────────────────────────────────────────

def test_non_snmp_traffic_is_declined():
    analyzer = SNMPAnalyzer()
    assert not analyzer.can_analyze(80, 1234, "TCP", b"GET / HTTP/1.1")
    assert not analyzer.can_analyze(161, 40000, "UDP", b"\x99not-ber")


def test_parsing_never_raises_on_arbitrary_input():
    analyzer = SNMPAnalyzer()
    for length in (0, 1, 2, 8, 64, 512):
        for _ in range(20):
            analyzer.parse(os.urandom(length))


def test_a_truncated_message_returns_nothing_rather_than_half_a_device():
    full = response()
    for cut in (4, 12, 30, len(full) - 3):
        SNMPAnalyzer().parse(full[:cut])       # must not raise
