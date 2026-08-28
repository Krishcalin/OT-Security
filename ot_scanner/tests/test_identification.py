"""
Identification end to end: a frame on the ring becomes an inventoried device.

Every serious defect this system has had lived in a seam, not in a component.
The decoders had tests, the estate had tests, and detections still never
attached; the CVE pipeline had tests and had never matched; the collector had
tests and read a dead sensor as clean. Each component was right and the joint
between two of them was not.

So these tests start at a frame and end at the asset record that reaches the
server, through the real analyser. `test_a_ring_switch_becomes_an_inventoried_
device` is the load-bearing one: it is the whole reason the LLDP work exists,
and it exercises four separate joins that each looked fine in isolation.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.analysis import IncrementalAnalyzer                # noqa: E402
from collector.capture import Frame                               # noqa: E402
from collector.observations import ObservationBuilder             # noqa: E402
from scanner.protocols.iec61850_mms import (                      # noqa: E402
    parse_identify_response)
from scanner.protocols.lldp import ETH_LLDP                       # noqa: E402

TS = datetime(2026, 8, 28, 12, 0, 0)

CISCO = ("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), "
         "Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)")


# ── frame builders ─────────────────────────────────────────────────────────

def tlv(kind, value):
    return struct.pack(">H", (kind << 9) | len(value)) + value


def lldp_frame(description=CISCO, name="MARCHWOOD-SW01", ip="10.50.7.2",
               src="00:80:63:AA:BB:01"):
    mgmt = tlv(8, bytes([5, 1]) + socket.inet_aton(ip) + bytes([2])
               + struct.pack(">I", 1) + bytes([0]))
    body = (tlv(1, bytes([4]) + bytes.fromhex("008063AABBCC"))
            + tlv(2, bytes([5]) + b"Gi1/0/1")
            + tlv(3, struct.pack(">H", 120))
            + tlv(5, name.encode())
            + tlv(6, description.encode())
            + tlv(7, struct.pack(">HH", 0x0014, 0x0004))
            + mgmt + tlv(0, b""))
    return (bytes.fromhex("0180C200000E") + bytes.fromhex(src.replace(":", ""))
            + struct.pack(">H", ETH_LLDP) + body)


# ── the load-bearing test ──────────────────────────────────────────────────

def test_a_ring_switch_becomes_an_inventoried_device():
    """THE test. A switch speaks no industrial protocol and its management
    traffic may never cross the mirror. LLDP is the only thing that puts it in
    the inventory, and this exercises every join between the frame and the
    asset record:

        collector L2_ETHERTYPES  ->  the frame is forwarded rather than dropped
        core._handle_l2_frame    ->  an LLDP branch exists at all
        _handle_lldp_result      ->  a device is CREATED, not merely enriched
        ObservationBuilder.asset ->  make/os_version survive to the server

    Three of those four were absent when this work started.
    """
    analyzer = IncrementalAnalyzer(collector_id="pi-marchwood")
    analyzer.feed([Frame(raw=lldp_frame(), timestamp=1.0)] * 3)
    devices, _flows = analyzer._finalise()

    assert devices, "the switch never reached the inventory"
    switch = next(d for d in devices if getattr(d, "ip", "") == "10.50.7.2")
    assert switch.make == "Cisco"
    assert switch.model == "C2960"
    assert switch.os_version == "15.0(2)SE11"
    assert switch.hostname == "MARCHWOOD-SW01"
    assert switch.device_type == "Switch"
    assert switch.identified_by == "lldp-system-description"


def test_the_asset_record_carries_the_identification_to_the_server():
    """A device identified on the Pi and an asset row that drops the fields is
    the same as never having identified it."""
    analyzer = IncrementalAnalyzer(collector_id="pi-marchwood")
    analyzer.feed([Frame(raw=lldp_frame(), timestamp=1.0)])
    devices, _ = analyzer._finalise()
    switch = next(d for d in devices if getattr(d, "ip", "") == "10.50.7.2")

    record = ObservationBuilder(collector_id="pi-marchwood").asset(
        switch, "w-1", "complete", seen_at=1.0)
    attrs = record.attributes
    assert attrs["make"] == "Cisco"
    assert attrs["model"] == "C2960"
    assert attrs["os_version"] == "15.0(2)SE11"
    assert attrs["hostname"] == "MARCHWOOD-SW01"
    assert attrs["identified_by"] == "lldp-system-description"
    assert attrs["asset_identifier"] == "00:80:63:AA:BB:CC"


def test_a_switch_with_no_management_address_is_still_inventoried():
    """Keyed on its MAC. A switch known only as a MAC is still a switch, and
    dropping it would be the silence this system exists to prevent."""
    frame = lldp_frame()
    # Strip the Management Address TLV by rebuilding without it.
    body = (tlv(1, bytes([4]) + bytes.fromhex("008063AABBCC"))
            + tlv(3, struct.pack(">H", 120))
            + tlv(6, CISCO.encode()) + tlv(0, b""))
    frame = frame[:14] + body
    analyzer = IncrementalAnalyzer(collector_id="pi-marchwood")
    analyzer.feed([Frame(raw=frame, timestamp=1.0)])
    devices, _ = analyzer._finalise()
    assert devices, "a switch with no management IP vanished"
    assert any(d.make == "Cisco" for d in devices)


def test_an_unrecognised_switch_is_inventoried_without_a_version():
    """Present in the estate, with no invented firmware. The device is real;
    the version would not have been."""
    analyzer = IncrementalAnalyzer(collector_id="pi-marchwood")
    analyzer.feed([Frame(raw=lldp_frame(description="MegaSwitch build 7"),
                         timestamp=1.0)])
    devices, _ = analyzer._finalise()
    switch = next(d for d in devices if getattr(d, "ip", "") == "10.50.7.2")
    assert switch.os_version is None and switch.model is None
    assert switch.hostname == "MARCHWOOD-SW01", "it is still a known device"


def test_one_switch_advertising_from_many_ports_is_one_device():
    """A 24-port switch sends LLDP out of every port with a different source
    MAC. Keying on the source would inventory it twenty-four times."""
    analyzer = IncrementalAnalyzer(collector_id="pi-marchwood")
    analyzer.feed([Frame(raw=lldp_frame(src="00:80:63:AA:BB:%02x" % port),
                         timestamp=1.0) for port in range(1, 25)])
    devices, _ = analyzer._finalise()
    assert len([d for d in devices if getattr(d, "ip", "") == "10.50.7.2"]) == 1


# ── MMS Identify ───────────────────────────────────────────────────────────

def ber(tag, value):
    return bytes([tag, len(value)]) + value


def identify_response(vendor=b"SIEMENS", model=b"SIPROTEC 5 7SJ85",
                      revision=b"V08.30"):
    body = ber(0x80, vendor) + ber(0x81, model) + ber(0x82, revision)
    service = ber(0xA2, body)
    return ber(0xA1, ber(0x02, b"\x01") + service)


def test_an_ied_names_itself_over_mms_identify():
    """The richest identification a 61850 IED gives a passive listener. The
    service was already recognised here and the response thrown away, so an
    estate of relays reported an OUI-guessed vendor and no model at all."""
    found = parse_identify_response(identify_response())
    assert found["vendor"] == "SIEMENS"
    assert found["model"] == "SIPROTEC 5 7SJ85"
    assert found["firmware"] == "V08.30"
    assert found["os_version"] == "V08.30"
    assert found["identified_by"] == "mms-identify"


def test_the_identify_body_is_found_behind_osi_wrappers():
    """How many presentation and session layers sit in front of the MMS PDU
    varies by vendor, so the body is located by walking, not by an offset."""
    wrapped = b"\x03\x00\x00\x40" + b"\x02\xf0\x80" + b"\x01\x00\x01\x00" \
        + identify_response()
    assert parse_identify_response(wrapped)["model"] == "SIPROTEC 5 7SJ85"


def test_a_revision_with_no_vendor_or_model_is_not_identification():
    """A bare version on a device of unknown make is matched against the CVE
    corpus and matches the wrong thing."""
    lonely = ber(0xA1, ber(0x02, b"\x01") + ber(0xA2, ber(0x82, b"V08.30")))
    assert parse_identify_response(lonely) == {}


def test_a_non_identify_response_yields_nothing():
    other = ber(0xA1, ber(0x02, b"\x01") + ber(0xA1, ber(0x80, b"x")))
    assert parse_identify_response(other) == {}


def test_identify_parsing_never_raises_on_arbitrary_input():
    for length in (0, 1, 4, 32, 256):
        for _ in range(20):
            parse_identify_response(os.urandom(length))
