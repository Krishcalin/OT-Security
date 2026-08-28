"""
Ring protection: ERPS (ITU-T G.8032), RSTP and MRP.

WHY A PASSIVE SECURITY TOOL WATCHES RING PROTECTION
───────────────────────────────────────────────────
A fibre ring is not a redundancy detail that belongs to somebody else. It
changes, second by second, WHICH TRAFFIC REACHES THE COLLECTOR — and this tool's
entire claim rests on knowing what it did and did not see.

An ERPS ring keeps one link blocked so the topology stays loop-free. Traffic
between two substations takes one way round; the mirror sees it. The link fails,
the ring protection switches, the blocked port opens, and the same conversation
now takes the other way round — possibly past a different switch, possibly past
no mirror at all. Nothing was lost at the NIC, no counter moved, and a device
that was reporting every 30 seconds goes quiet.

That reads, to everything downstream, exactly like a device that stopped
talking. It is not. It is a device the collector stopped being able to hear.
Reporting the second as the first is the same class of mistake as a dead
collector counted healthy or an unreadable transport counted quiet, and this
system has now made that mistake three times in other places.

So a protection switch is recorded as an EVENT ON THE WINDOW, and the window
carries it to the server, where an operator reading "this RTU went silent at
14:07" can also read "the ring protected at 14:06".

WHAT IS SECURITY-RELEVANT IN ITS OWN RIGHT
──────────────────────────────────────────
A ring that flaps repeatedly is a fault, and a fault on a distribution ring is
worth reporting whatever caused it. But two things here are specifically
security findings:

  * R-APS and BPDUs are UNAUTHENTICATED on almost every deployment. Anything
    with a port on the ring can inject a topology change and move traffic — a
    denial of service that needs no exploit, and a way to steer conversations
    past a chosen point.
  * An RSTP topology change from an unexpected bridge, or a root bridge that
    changes identity, is what a rogue switch inserted into a substation looks
    like from the wire.

This module reports what it saw. It does not act, and it does not decide that a
protection switch was an attack — a ring on a distribution network protects for
mundane reasons constantly, and crying wolf on every one would guarantee the
real one is ignored.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from .base import BaseL2Analyzer

#: ITU-T G.8032 R-APS travels inside a CFM/Y.1731 frame.
ETH_CFM = 0x8902
#: 802.1D/w/s BPDUs are LLC (802.3 length field), not an EtherType. The
#: destination address is what identifies them.
BPDU_MULTICAST = "01:80:C2:00:00:00"
#: Media Redundancy Protocol (IEC 62439-2), Hirschmann's ring protocol.
ETH_MRP = 0x88E3

#: G.8032 R-APS request/state field (clause 10.1.1), high nibble.
RAPS_REQUESTS = {
    0x0: "no-request",
    0x7: "manual-switch",
    0xB: "signal-fail",
    0xD: "forced-switch",
    0xE: "event",
}

#: The states that mean the ring is NOT in its normal topology, so what the
#: collector can hear has changed.
RAPS_PROTECTING = frozenset(("signal-fail", "forced-switch", "manual-switch"))

#: BPDU types (802.1D 9.3).
BPDU_TYPES = {0x00: "configuration", 0x02: "rstp", 0x80: "topology-change"}

#: The topology-change flag in an RSTP BPDU's flags octet.
BPDU_FLAG_TOPOLOGY_CHANGE = 0x01
BPDU_FLAG_TOPOLOGY_CHANGE_ACK = 0x80


@dataclass
class RingEvent:
    """One protection message, in the terms an operator would use."""

    protocol: str = ""
    kind: str = ""
    #: True when this message means the ring is away from its normal topology.
    protecting: bool = False
    node: str = ""
    detail: str = ""
    seen_at: str = ""

    def to_dict(self) -> Dict:
        return {"protocol": self.protocol, "kind": self.kind,
                "protecting": self.protecting, "node": self.node,
                "detail": self.detail, "seen_at": self.seen_at}


@dataclass
class RingState:
    """What the ring has done during this window.

    `protection_switches` is the number that matters downstream: a window with
    any is a window in which what the collector could hear CHANGED, and a
    device that went quiet in it must not be reported as a device that stopped
    talking.
    """

    events: List[RingEvent] = field(default_factory=list)
    protection_switches: int = 0
    topology_changes: int = 0
    #: Bridge identities seen claiming to be root. More than one in a window is
    #: either a reconvergence or a bridge that should not be there.
    roots: List[str] = field(default_factory=list)

    @property
    def stable(self) -> bool:
        return not self.protection_switches and not self.topology_changes

    def explain(self) -> str:
        if self.stable:
            return "ring stable — no protection switch or topology change seen"
        parts = []
        if self.protection_switches:
            parts.append("%d ring protection switch(es)"
                         % self.protection_switches)
        if self.topology_changes:
            parts.append("%d spanning-tree topology change(s)"
                         % self.topology_changes)
        if len(self.roots) > 1:
            parts.append("%d different root bridges claimed (%s)"
                         % (len(self.roots), ", ".join(sorted(self.roots))))
        return ("; ".join(parts)
                + ". Traffic took a different path during this window, so a "
                  "device that went quiet may have moved out of earshot rather "
                  "than stopped talking.")

    def to_dict(self) -> Dict:
        return {"events": [e.to_dict() for e in self.events],
                "protection_switches": self.protection_switches,
                "topology_changes": self.topology_changes,
                "roots": sorted(self.roots),
                "stable": self.stable,
                "explain": self.explain()}


def parse_raps(payload: bytes) -> Optional[RingEvent]:
    """An R-APS message out of a CFM/Y.1731 frame (G.8032 clause 10.1.1).

    CFM common header is 4 octets (MD level + version, opcode, flags, TLV
    offset); opcode 40 is R-APS, and the 32-octet specific information follows.
    """
    if len(payload) < 8 or payload[1] != 40:          # opcode 40 = R-APS
        return None
    body = payload[4:]
    if len(body) < 8:
        return None
    request = (body[0] >> 4) & 0x0F
    name = RAPS_REQUESTS.get(request, "unknown(0x%X)" % request)
    node = ":".join("%02X" % b for b in body[2:8])
    return RingEvent(
        protocol="G.8032 R-APS", kind=name,
        protecting=name in RAPS_PROTECTING, node=node,
        detail=("ring node %s signalled %s" % (node, name)))


def parse_bpdu(payload: bytes) -> Optional[RingEvent]:
    """A spanning-tree BPDU, after the 802.3 LLC header.

    The LLC header (DSAP 0x42, SSAP 0x42, control 0x03) is stripped by the
    caller if present; both shapes are accepted because a mirror may hand over
    either depending on how the switch encapsulates.
    """
    if payload[:3] == b"\x42\x42\x03":
        payload = payload[3:]
    # A TCN BPDU is EXACTLY four octets: protocol id (2), version (1),
    # type (1). It carries no body at all, so a guard of five drops every
    # topology-change notification on the ring — which is the one BPDU that
    # most needs to be seen.
    if len(payload) < 4:
        return None
    protocol_id = struct.unpack(">H", payload[0:2])[0]
    if protocol_id != 0:                              # 802.1D protocol id
        return None
    bpdu_type = payload[3]
    kind = BPDU_TYPES.get(bpdu_type, "unknown(0x%02X)" % bpdu_type)

    if bpdu_type == 0x80:                             # TCN, no body
        return RingEvent(protocol="STP", kind="topology-change-notification",
                         detail="a bridge signalled a topology change")
    if len(payload) < 35:
        return None
    flags = payload[4]
    root = ":".join("%02X" % b for b in payload[7:13])
    changed = bool(flags & BPDU_FLAG_TOPOLOGY_CHANGE)
    return RingEvent(
        protocol="RSTP" if bpdu_type == 0x02 else "STP",
        kind="topology-change" if changed else kind,
        protecting=changed, node=root,
        detail=("root bridge %s%s" % (root, ", topology change flag set"
                                      if changed else "")))


class RingAnalyzer(BaseL2Analyzer):
    """Watches ring protection so coverage can account for it."""

    def __init__(self):
        self._state = RingState()

    def can_analyze_frame(self, eth_type: int, payload: bytes) -> bool:
        return eth_type in (ETH_CFM, ETH_MRP) or eth_type < 0x0600

    def analyze_frame(self, src_mac: str, dst_mac: str, eth_type: int,
                      payload: bytes, timestamp: datetime) -> Optional[dict]:
        event = None
        if eth_type == ETH_CFM:
            event = parse_raps(payload)
        elif eth_type < 0x0600 and dst_mac.upper() == BPDU_MULTICAST:
            # An 802.3 length field rather than an EtherType, addressed to the
            # bridge group address: a spanning-tree BPDU.
            event = parse_bpdu(payload)
        if event is None:
            return None

        event.seen_at = timestamp.isoformat()
        self._state.events.append(event)
        if event.protecting:
            if event.protocol.startswith("G.8032"):
                self._state.protection_switches += 1
            else:
                self._state.topology_changes += 1
        if event.node and event.protocol in ("RSTP", "STP") \
                and event.node not in self._state.roots:
            self._state.roots.append(event.node)
        return event.to_dict()

    def get_sessions(self) -> Dict:
        return self._state.to_dict()

    def take_state(self) -> RingState:
        """This window's ring state, then reset.

        Per window, like the decode counters, because the question a window
        answers is "could this window hear the estate" — and last window's
        protection switch says nothing about this one.
        """
        taken, self._state = self._state, RingState()
        return taken
