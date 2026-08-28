"""
Transport decapsulation (MPLS-TP pseudowires).

The load-bearing test is `test_an_unfollowable_encapsulation_is_not_understood`.

Everything else here checks that a frame is opened correctly. That one checks
what happens when it CANNOT be, and it is the one that matters, because the
failure this module was written for was not "the frame decoded wrongly" — it was
"50,000 frames decoded into nothing, nothing was counted, and the window was
reported COMPLETE over an empty estate".

A decapsulator that guesses is worse than one that refuses. Inventing devices
out of transport headers produces an estate nobody can tell is wrong; refusing
produces a number an operator can act on.
"""
from __future__ import annotations

import os
import socket
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector import decap                                     # noqa: E402
from collector.analysis import IncrementalAnalyzer              # noqa: E402
from collector.capture import Frame                             # noqa: E402
from collector.coverage import (Coverage, DropSnapshot,         # noqa: E402
                                WindowAccountant)

RTU_MAC = "aabbccddeeff"
RTU_IP = "10.20.30.41"
FEP_IP = "10.20.30.1"
PE_MAC = "001122334455"


# ── builders, in the shape a distribution network puts on the wire ─────────

def eth(dst=PE_MAC, src="0011aabbccdd", ethertype=0x0800, payload=b""):
    return (bytes.fromhex(dst) + bytes.fromhex(src)
            + struct.pack(">H", ethertype) + payload)


def ipv4(src=RTU_IP, dst=FEP_IP, proto=6, payload=b""):
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64,
                       proto, 0, socket.inet_aton(src),
                       socket.inet_aton(dst)) + payload


def tcp(sport=50000, dport=2404, payload=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x18,
                       8192, 0, 0) + payload


def mpls(label, bottom, payload):
    return struct.pack(">I", (label << 12) | (bottom << 8) | 64) + payload


def vlan(vid, inner_type, payload):
    return struct.pack(">HH", vid, inner_type) + payload


#: An IEC 60870-5-104 STARTDT act — what an FRTU session opens with.
IEC104 = tcp(payload=b"\x68\x04\x07\x00\x00\x00")
INNER_IP = ipv4(payload=IEC104)
INNER_ETH = eth(dst=RTU_MAC, src="aabbcc112233", payload=INNER_IP)


# ── the shapes that already worked, which must keep working ────────────────

def test_an_unencapsulated_frame_is_returned_untouched():
    """The collector may well be tapped on an access port. Calling this on
    every frame must cost nothing there."""
    frame = eth(payload=INNER_IP)
    result = decap.decapsulate(frame)
    assert result.understood
    assert result.frame == frame
    assert result.layers == ()
    assert not result.encapsulated


def test_a_vlan_tagged_frame_is_left_for_dpkt():
    """dpkt already unwraps 802.1Q. Stripping it here would be duplicated work
    and a second place for the two to disagree."""
    frame = eth(ethertype=0x8100, payload=vlan(100, 0x0800, INNER_IP))
    result = decap.decapsulate(frame)
    assert result.understood
    assert result.frame == frame
    assert result.layers == ("vlan:100",)


# ── the label stack ────────────────────────────────────────────────────────

def test_a_single_label_over_ip_is_opened():
    result = decap.decapsulate(eth(ethertype=0x8847, payload=mpls(16000, 1, INNER_IP)))
    assert result.understood
    assert result.labels == (16000,)
    assert result.frame.endswith(IEC104)


def test_a_transport_and_pseudowire_label_are_both_recorded():
    """MPLS-TP carries at least two: the tunnel and the service."""
    result = decap.decapsulate(
        eth(ethertype=0x8847, payload=mpls(16000, 0, mpls(100, 1, INNER_IP))))
    assert result.understood
    assert result.labels == (16000, 100)
    assert decap.describe(result) == "mpls:16000 / mpls:100 / ipv4"


def test_vlan_outside_the_label_stack_is_handled():
    frame = eth(ethertype=0x8100,
                payload=vlan(300, 0x8847, mpls(16000, 1, INNER_IP)))
    result = decap.decapsulate(frame)
    assert result.understood
    assert result.layers[0] == "vlan:300"
    assert result.labels == (16000,)


# ── the pseudowire, which is what this was written for ─────────────────────

def test_an_ethernet_pseudowire_yields_the_rtus_own_mac():
    """THE case. Before this module these frames produced nothing at all.

    The inner MAC is the RTU's; the outer is the provider edge router's. An
    inventory built from the outer MACs would list the routers and miss every
    device in the substation."""
    frame = eth(ethertype=0x8847,
                payload=mpls(16000, 0,
                             mpls(100, 1, b"\x00\x00\x00\x00" + INNER_ETH)))
    result = decap.decapsulate(frame)
    assert result.understood
    assert "pw-cw" in result.layers and "eompls" in result.layers
    assert result.frame == INNER_ETH
    assert result.frame[0:6] == bytes.fromhex(RTU_MAC)


def test_an_ethernet_pseudowire_without_a_control_word_is_still_opened():
    """The control word is recommended, not required. Accepted here only
    because the payload carries a plausible EtherType."""
    frame = eth(ethertype=0x8847, payload=mpls(16000, 0, mpls(100, 1, INNER_ETH)))
    result = decap.decapsulate(frame)
    assert result.understood
    assert "eompls" in result.layers
    assert result.frame == INNER_ETH


def test_an_ip_pseudowire_keeps_the_provider_edge_macs():
    """A routed pseudowire carries no inner MAC. Reporting the router's is
    honest; inventing one for the RTU would not be."""
    frame = eth(ethertype=0x8847,
                payload=mpls(16000, 1, b"\x00\x00\x00\x00" + INNER_IP))
    result = decap.decapsulate(frame)
    assert result.understood
    assert result.frame[0:6] == bytes.fromhex(PE_MAC)
    assert result.frame.endswith(IEC104)


# ── refusing to guess ──────────────────────────────────────────────────────

def test_an_unfollowable_encapsulation_is_not_understood():
    """THE test. A payload under the label stack that is neither IP nor a
    plausible Ethernet frame must come back `understood=False` so the caller
    counts it — never as a frame that silently decoded to nothing."""
    # Deterministic: a random payload here would pass or fail by luck.
    # EtherType 0x1234 is not one this collector knows.
    junk = bytes([0x33] + [0x00] * 11 + [0x12, 0x34] + [0xAB] * 46)
    result = decap.decapsulate(eth(ethertype=0x8847, payload=mpls(16000, 1, junk)))
    assert not result.understood
    assert result.reason
    assert "no known pseudowire encapsulation" in result.reason


def test_a_frame_claiming_ipv4_with_an_impossible_header_is_refused():
    """A first nibble of 4 is not proof — a unicast MAC may legally start with
    one. The header has to agree."""
    lying = bytes([0x45, 0x00, 0xFF, 0xFF]) + b"\x00" * 16   # length >> buffer
    result = decap.decapsulate(eth(ethertype=0x8847, payload=mpls(16000, 1, lying)))
    assert not result.understood


def test_a_label_stack_with_no_bottom_bit_is_refused_rather_than_walked():
    """Garbage that looks like an endless stack must terminate, and must not
    be reported as a frame that decoded."""
    endless = b"".join(mpls(50 + i, 0, b"") for i in range(20)) + b"\x00" * 40
    result = decap.decapsulate(eth(ethertype=0x8847, payload=endless))
    assert not result.understood
    assert "deeper than" in result.reason


@pytest.mark.parametrize("payload,why", [
    (b"", "no payload"),
    (b"\x00\x00\x00\x00", "control word with no payload"),
])
def test_truncated_encapsulation_is_refused(payload, why):
    result = decap.decapsulate(eth(ethertype=0x8847, payload=mpls(16000, 1, payload)))
    assert not result.understood, why


def test_a_runt_frame_is_refused():
    assert not decap.decapsulate(b"\x00" * 8).understood


def test_decapsulation_never_raises_on_arbitrary_input():
    """A malformed frame is normal on a live network. This runs on every frame
    the collector sees; an exception here would stop capture."""
    for length in (0, 1, 13, 14, 15, 63, 64, 1500):
        for _ in range(20):
            decap.decapsulate(os.urandom(length))


# ── the honesty chain: decap -> analyser -> coverage ───────────────────────
#
# The decapsulator on its own is only half the fix. What made an unreadable
# transport dangerous was that nothing downstream was obliged to mention it.
# These tests run the whole chain, because that is where the failure lived.

def _window(frames, packets=None):
    """Account one window over `frames` with no packet loss at all."""
    packets = len(frames) if packets is None else packets
    before = DropSnapshot(interface_rx_packets=0, interface_rx_dropped=0,
                          interface_rx_missed=0, capture_received=0,
                          capture_dropped=0)
    after = DropSnapshot(interface_rx_packets=packets, interface_rx_dropped=0,
                         interface_rx_missed=0, capture_received=packets,
                         capture_dropped=0)
    accountant = WindowAccountant(collector_id="pi-A", window_seconds=60.0)
    accountant.open_window("w1", 0.0, before)
    analyzer = IncrementalAnalyzer(collector_id="pi-A")
    analyzer.feed([Frame(raw=raw, timestamp=1.0) for raw in frames])
    accountant.record_packets(packets)
    counters = analyzer.take_decode_counters()
    accountant.record_decode(decoded=counters.decoded,
                             unreadable=counters.unreadable,
                             transports=counters.transports)
    return analyzer, accountant.close_window(60.0, after)


PSEUDOWIRE = eth(ethertype=0x8847,
                 payload=mpls(16000, 0,
                              mpls(100, 1, b"\x00\x00\x00\x00" + INNER_ETH)))
UNOPENABLE = eth(ethertype=0x8847,
                 payload=mpls(16000, 1,
                              bytes([0x33] + [0x00] * 11 + [0x12, 0x34]
                                    + [0xAB] * 46)))


def test_pseudowire_traffic_now_reaches_the_decoders():
    """Measured before this existed: 0 of 200 decoded. The frames were intact
    and the RTU was three layers down."""
    analyzer, window = _window([PSEUDOWIRE] * 200)
    assert analyzer.stats.frames_decoded == 200
    assert analyzer.stats.frames_decapsulated == 200
    assert analyzer.stats.frames_unreadable == 0
    assert window.coverage is Coverage.COMPLETE


def test_a_window_that_could_not_be_read_is_never_complete():
    """THE regression. 200 frames arrive intact, nothing is lost at the NIC,
    and nothing can be interpreted. Before this, that window reported COMPLETE
    and trustworthy over an empty estate."""
    analyzer, window = _window([UNOPENABLE] * 200)
    assert analyzer.stats.frames_decoded == 0
    assert analyzer.stats.frames_unreadable == 200
    assert window.drops.total_lost == 0          # nothing was LOST …
    assert window.coverage is Coverage.DEGRADED  # … and it is still not clean
    assert not window.is_trustworthy
    assert window.readable_fraction == 0.0


def test_the_explanation_names_the_tap_rather_than_the_network():
    """An operator reading an empty estate has to be told which of the two it
    is, on the window itself, without going looking."""
    _analyzer, window = _window([UNOPENABLE] * 200)
    text = window.explain()
    assert "could not open" in text
    assert "mpls:16000" in text, "the operator is not told WHICH transport"
    assert "means the tap, not the network" in text


def test_a_partly_readable_window_reports_the_share():
    analyzer, window = _window([PSEUDOWIRE] * 190 + [UNOPENABLE] * 10)
    assert analyzer.stats.frames_decoded == 190
    assert window.coverage is Coverage.DEGRADED
    assert window.readable_fraction == pytest.approx(0.95)
    assert "95.0%" in window.explain()


def test_ordinary_uninteresting_traffic_does_not_degrade_a_window():
    """ARP is not an unreadable transport. If it counted as one, every window
    on every real network would be degraded and the signal would be worthless."""
    arp = eth(ethertype=0x0806, payload=b"\x00\x01\x08\x00\x06\x04" + b"\x00" * 22)
    analyzer, window = _window([PSEUDOWIRE] * 50 + [arp] * 50)
    assert analyzer.stats.frames_not_analysed == 50
    assert analyzer.stats.frames_unreadable == 0
    assert window.coverage is Coverage.COMPLETE


def test_the_decode_counters_reset_between_windows():
    """A window carries ITS OWN outcome. Accumulating would make the second
    window inherit the first one's unreadable frames for ever."""
    analyzer = IncrementalAnalyzer(collector_id="pi-A")
    analyzer.feed([Frame(raw=UNOPENABLE, timestamp=1.0)] * 5)
    first = analyzer.take_decode_counters()
    analyzer.feed([Frame(raw=PSEUDOWIRE, timestamp=2.0)] * 5)
    second = analyzer.take_decode_counters()
    assert first.unreadable == 5 and first.decoded == 0
    assert second.unreadable == 0 and second.decoded == 5


def test_the_window_dict_carries_readability_to_the_server():
    """Coverage travels with every finding. If readability stops at the
    collector, the console cannot tell a quiet plant from a blind sensor."""
    _analyzer, window = _window([UNOPENABLE] * 10)
    payload = window.to_dict()
    assert payload["frames_unreadable"] == 10
    assert payload["readable_fraction"] == 0.0
    assert payload["unreadable_transports"]["mpls:16000"] == 10
    assert payload["coverage"] == "degraded"
