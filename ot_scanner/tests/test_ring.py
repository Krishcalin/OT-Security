"""
Ring protection, and why a security tool watches it.

The load-bearing test is `test_a_protecting_window_says_a_silent_device_may_
have_moved_out_of_earshot`.

A fibre ring changes which traffic reaches the collector. When ERPS protects,
a conversation that went one way round the ring now goes the other — possibly
past no mirror at all. Nothing is lost at the NIC, no counter moves, and a
device reporting every 30 seconds goes quiet.

Downstream that is indistinguishable from a device that stopped talking. It is
not: it is a device the collector stopped being able to hear. This system has
already made that class of mistake three times — a dead collector counted
healthy, an unassessed asset counted clean, an unreadable transport counted
quiet — so the window has to carry the difference.
"""
from __future__ import annotations

import os
import struct
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.protocols.ring import (BPDU_MULTICAST, ETH_CFM,      # noqa: E402
                                    RingAnalyzer, parse_bpdu, parse_raps)

TS = datetime(2026, 8, 28, 14, 6, 0)
NODE = "00:80:63:11:22:33"


# ── builders ───────────────────────────────────────────────────────────────

def raps(request=0xB, node=NODE):
    """A CFM frame carrying R-APS: level/version, opcode 40, flags, TLV off."""
    header = bytes([0x00, 40, 0x00, 0x20])
    body = bytes([(request << 4) | 0x00, 0x00]) \
        + bytes.fromhex(node.replace(":", "")) + b"\x00" * 24
    return header + body


def bpdu(bpdu_type=0x02, flags=0x00, root="00:80:63:AA:BB:CC"):
    if bpdu_type == 0x80:
        return b"\x42\x42\x03" + struct.pack(">HBB", 0, 0, 0x80)
    body = (struct.pack(">HBB", 0, 0, bpdu_type) + bytes([flags])
            + struct.pack(">H", 0x8000) + bytes.fromhex(root.replace(":", ""))
            + b"\x00" * 4                                   # root path cost
            + struct.pack(">H", 0x8000) + b"\x00" * 6       # bridge id
            + b"\x00" * 10)
    return b"\x42\x42\x03" + body


# ── ERPS ───────────────────────────────────────────────────────────────────

def test_a_signal_fail_is_a_protection_switch():
    event = parse_raps(raps(request=0xB))
    assert event.protocol == "G.8032 R-APS"
    assert event.kind == "signal-fail"
    assert event.protecting is True
    assert event.node == NODE.upper()


def test_a_no_request_message_is_the_ring_idling():
    """R-APS is sent continuously. Treating every message as an event would
    make every window on a healthy ring look like an incident."""
    event = parse_raps(raps(request=0x0))
    assert event.kind == "no-request"
    assert event.protecting is False


@pytest.mark.parametrize("code,name,protecting", [
    (0x0, "no-request", False),
    (0x7, "manual-switch", True),
    (0xB, "signal-fail", True),
    (0xD, "forced-switch", True),
    (0xE, "event", False),
])
def test_the_request_field_is_read_correctly(code, name, protecting):
    event = parse_raps(raps(request=code))
    assert event.kind == name and event.protecting is protecting


def test_a_frame_that_is_not_raps_is_declined():
    assert parse_raps(bytes([0x00, 5, 0x00, 0x20]) + b"\x00" * 32) is None
    assert parse_raps(b"") is None


# ── spanning tree ──────────────────────────────────────────────────────────

def test_a_topology_change_flag_is_a_topology_change():
    event = parse_bpdu(bpdu(flags=0x01))
    assert event.protocol == "RSTP"
    assert event.kind == "topology-change"
    assert event.protecting is True


def test_an_ordinary_bpdu_is_not_an_event():
    event = parse_bpdu(bpdu(flags=0x00))
    assert event.protecting is False
    assert event.node == "00:80:63:AA:BB:CC"


def test_a_topology_change_notification_is_read():
    event = parse_bpdu(bpdu(bpdu_type=0x80))
    assert event.kind == "topology-change-notification"


def test_the_llc_header_is_optional():
    """A mirror hands over either shape depending on the switch."""
    with_llc = bpdu(flags=0x01)
    assert parse_bpdu(with_llc).kind == "topology-change"
    assert parse_bpdu(with_llc[3:]).kind == "topology-change"


# ── the window ─────────────────────────────────────────────────────────────

def _window(frames):
    analyzer = RingAnalyzer()
    for eth_type, dst, payload in frames:
        analyzer.analyze_frame("aa:bb:cc:dd:ee:ff", dst, eth_type, payload, TS)
    return analyzer.take_state()


def test_a_quiet_ring_is_stable_and_says_so_plainly():
    state = _window([(ETH_CFM, "01:19:A7:00:00:01", raps(request=0x0))] * 20)
    assert state.stable
    assert "ring stable" in state.explain()


def test_a_protecting_window_says_a_silent_device_may_have_moved_out_of_earshot():
    """THE test. The sentence an operator needs beside "this RTU went silent at
    14:07" is "the ring protected at 14:06"."""
    state = _window([(ETH_CFM, "01:19:A7:00:00:01", raps(request=0xB))])
    assert not state.stable
    assert state.protection_switches == 1
    text = state.explain()
    assert "took a different path" in text
    assert "out of earshot rather than stopped talking" in text


def test_spanning_tree_changes_are_counted_apart_from_ring_protection():
    """Different mechanisms, different fixes. Summing them into one number
    would tell an operator to look in the wrong place."""
    state = _window([
        (ETH_CFM, "01:19:A7:00:00:01", raps(request=0xB)),
        (0x0026, BPDU_MULTICAST, bpdu(flags=0x01)),
    ])
    assert state.protection_switches == 1
    assert state.topology_changes == 1


def test_two_bridges_claiming_root_is_reported():
    """Either a reconvergence or a bridge that should not be on this ring.
    From the wire those look the same, and both are worth a look."""
    state = _window([
        (0x0026, BPDU_MULTICAST, bpdu(root="00:80:63:AA:BB:CC")),
        (0x0026, BPDU_MULTICAST, bpdu(root="00:11:22:33:44:55")),
    ])
    assert len(state.roots) == 2


def test_state_resets_between_windows():
    """Last window's protection switch says nothing about this one."""
    analyzer = RingAnalyzer()
    analyzer.analyze_frame("aa", "01:19:A7:00:00:01", ETH_CFM,
                           raps(request=0xB), TS)
    assert analyzer.take_state().protection_switches == 1
    assert analyzer.take_state().protection_switches == 0


def test_a_bpdu_not_addressed_to_the_bridge_group_is_ignored():
    """The destination is what identifies a BPDU; an 802.3 frame to any other
    address is somebody else's protocol."""
    state = _window([(0x0026, "01:00:0C:CC:CC:CD", bpdu(flags=0x01))])
    assert state.stable


def test_parsing_never_raises_on_arbitrary_input():
    analyzer = RingAnalyzer()
    for length in (0, 1, 4, 8, 35, 64, 256):
        for _ in range(20):
            payload = os.urandom(length)
            analyzer.analyze_frame("aa", BPDU_MULTICAST, 0x0026, payload, TS)
            analyzer.analyze_frame("aa", "01:19:A7:00:00:01", ETH_CFM,
                                   payload, TS)
