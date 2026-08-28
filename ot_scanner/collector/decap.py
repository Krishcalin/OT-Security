"""
Strip transport encapsulation until an Ethernet frame the decoders understand.

WHY THIS EXISTS
───────────────
A collector on a distribution network is rarely handed clean access-port
traffic. On an MPLS-TP backbone the mirror may sit on an NNI, where substation
LANs travel as Ethernet pseudowires: the frame on the wire is

    outer Ethernet │ MPLS label │ MPLS label │ control word │ INNER ETHERNET │ IP │ …

and every address that matters — the RTU's MAC, its IP, the IEC 104 session —
is behind three layers the decoder never opens.

Measured before this module existed: dpkt unwraps a plain MPLS label stack to
IP on its own, so routed MPLS already worked. **Ethernet pseudowires did not.**
50,000 pseudowire frames produced 0 decodes, 0 devices, and — because the
dispatcher returned silently on anything that was not IP — 0 recorded failures.
The window was reported COMPLETE and trustworthy over an empty estate.

That is the third appearance in this system of one bug: a dead collector read as
clean, an unassessed asset reported clean, and now an unreadable transport
reported as a quiet network. So this module does two things, and the second
matters more than the first: it opens the encapsulation, and when it CANNOT, it
says so in a way the coverage model is obliged to carry.

TELLING THE PAYLOAD APART
─────────────────────────
After the bottom-of-stack label, what follows is not self-describing. There is
no type field. RFC 4385 §4 makes the first nibble the discriminator, which is
why a pseudowire control word is defined to begin with four zero bits:

    0x4…  IPv4          (routed MPLS / IP pseudowire)
    0x6…  IPv6
    0x0…  control word  → 4 bytes, then the inner Ethernet frame
    else  inner Ethernet with no control word

The last branch is a guess, and this module refuses to guess blindly. Two
earlier versions of that guess were wrong and the tests caught both:

  * "any EtherType ≥ 0x0600 is an Ethernet frame" accepts **97.7% of random
    bytes**. It passed 60 bytes of urandom and reported a decapsulated
    pseudowire. An inner frame is now accepted only on a KNOWN EtherType and a
    source MAC whose group bit is clear — two independent signals.
  * Testing Ethernet BEFORE IP misreads inner IPv4, because bytes 12..13 of an
    IPv4 header are the first half of the source address: a packet from
    10.20.0.0/16 presents "EtherType 0x0A14", and one from 8.0.0.0/16 presents
    0x0800 exactly. IP is therefore tested first, and validated against its own
    version, IHL and total length rather than its first nibble.

Anything that satisfies none of them is returned `understood=False` and COUNTED.
A wrong guess here would invent devices out of transport headers, which is worse
than seeing nothing — and unlike seeing nothing, nobody would ever notice.

The ambiguity is inherent to pseudowires that omit the control word; this
narrows it as far as the encapsulation allows and never silently resolves it.

No dependency is added. `manifest.RUNTIME_REQUIRES` stays at dpkt alone, and
this module is pure stdlib so it runs wherever the collector does.
"""
import struct
from dataclasses import dataclass
from typing import List, Tuple

#: MPLS over Ethernet.
ETH_MPLS_UNICAST = 0x8847
ETH_MPLS_MULTICAST = 0x8848
#: VLAN tags, which may sit outside the label stack on a trunk.
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8
ETH_QINQ_LEGACY = 0x9100

#: An EtherType is >= 0x0600; below that the field is an 802.3 length. This is
#: necessary but nowhere near sufficient — see KNOWN_ETHERTYPES.
MIN_ETHERTYPE = 0x0600

#: Accepting "any value >= 0x0600" as an inner Ethernet frame accepts 97.7% of
#: RANDOM BYTES, which is not a test, it is a rubber stamp. Measured: it passed
#: 60 bytes of urandom and reported a decapsulated pseudowire.
#:
#: So an inner frame is accepted only on an EtherType this collector could
#: actually do something with. The cost is that a pseudowire carrying a
#: protocol absent from this list reads as not-understood — which is the honest
#: answer, since the decoders would have made nothing of it either, and it is
#: COUNTED rather than silently dropped.
KNOWN_ETHERTYPES = frozenset((
    0x0800,   # IPv4
    0x0806,   # ARP
    0x86DD,   # IPv6
    0x8100,   # 802.1Q
    0x88A8,   # 802.1ad
    0x9100,   # legacy QinQ
    0x8847,   # MPLS unicast (a pseudowire inside a pseudowire)
    0x8848,   # MPLS multicast
    0x88B8,   # IEC 61850 GOOSE
    0x88BA,   # IEC 61850 Sampled Values
    0x8892,   # PROFINET
    0x88CC,   # LLDP
    0x88F7,   # PTP / IEEE 1588
    0x88A4,   # EtherCAT
    0x8035,   # RARP
))

#: A label stack deeper than this is not a network, it is a malformed frame.
#: Real MPLS-TP rarely exceeds three (transport + pseudowire + entropy).
MAX_LABEL_DEPTH = 8

#: Bytes in one MPLS shim header, and in a pseudowire control word.
LABEL_BYTES = 4
CONTROL_WORD_BYTES = 4

ETHERNET_HEADER_BYTES = 14


@dataclass
class Decapsulated:
    """The innermost Ethernet frame, and an account of getting there."""

    #: The frame the decoders should parse. Equals the input when nothing was
    #: stripped. Meaningless when `understood` is False.
    frame: bytes = b""
    #: Encapsulation removed, outermost first: ("mpls:16000", "pw-cw", …).
    layers: Tuple[str, ...] = ()
    #: MPLS labels in stack order. Empty for an unencapsulated frame.
    labels: Tuple[int, ...] = ()
    #: False when the encapsulation could not be followed to an inner frame.
    #: The caller MUST count these rather than dropping them silently.
    understood: bool = True
    #: Why not, when not. One short clause, for an operator.
    reason: str = ""

    @property
    def encapsulated(self) -> bool:
        return bool(self.layers)


def _plausible_ipv4(buf: bytes) -> bool:
    """A first nibble of 4 is not proof. Confirm against the header itself."""
    if len(buf) < 20 or (buf[0] >> 4) != 4:
        return False
    ihl = (buf[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(buf):
        return False
    total = struct.unpack(">H", buf[2:4])[0]
    # Trailing padding is normal; a total length longer than the buffer is not.
    return ihl <= total <= len(buf)


def _plausible_ipv6(buf: bytes) -> bool:
    if len(buf) < 40 or (buf[0] >> 4) != 6:
        return False
    payload = struct.unpack(">H", buf[4:6])[0]
    return 40 + payload <= len(buf) + 8       # allow for truncated capture


def _plausible_ethernet(buf: bytes) -> bool:
    """Accept as an inner Ethernet frame only on two independent signals.

    A KNOWN EtherType, and a source MAC that is not multicast — the group bit
    in a source address is always zero, which no sender may violate, so it
    costs nothing on real traffic and halves the space of accidental matches.

    Both are needed. Either alone lets an inner IPv4 packet through: bytes
    12..13 of an IPv4 header are the first half of the SOURCE ADDRESS, so a
    packet from 8.0.0.0/16 presents EtherType 0x0800 exactly. That is why IP is
    tested BEFORE this function is ever called.
    """
    if len(buf) < ETHERNET_HEADER_BYTES:
        return False
    if buf[6] & 0x01:                       # multicast bit set in the source
        return False
    return struct.unpack(">H", buf[12:14])[0] in KNOWN_ETHERTYPES


def _synthetic_ethernet(dst: bytes, src: bytes, ethertype: int,
                        payload: bytes) -> bytes:
    """Re-frame a bare IP payload so downstream sees one uniform shape.

    The MACs are the OUTER ones — the provider edge, not the RTU. That is what
    was actually on the wire: a routed pseudowire carries no inner MAC, and
    inventing one would be worse than reporting the router's.
    """
    return dst + src + struct.pack(">H", ethertype) + payload


def _skip_vlans(buf: bytes, offset: int, layers: List[str]) -> int:
    """Advance past any stacked VLAN tags, recording each."""
    while offset + 4 <= len(buf):
        ethertype = struct.unpack(">H", buf[offset - 2:offset])[0]
        if ethertype not in (ETH_VLAN, ETH_QINQ, ETH_QINQ_LEGACY):
            return offset
        vid = struct.unpack(">H", buf[offset:offset + 2])[0] & 0x0FFF
        layers.append("vlan:%d" % vid)
        offset += 4
    return offset


def decapsulate(raw: bytes) -> Decapsulated:
    """Peel MPLS and pseudowire encapsulation off `raw`.

    Returns the original frame untouched when there is nothing to peel, so this
    is safe to call on every frame regardless of where the collector is tapped.
    """
    if len(raw) < ETHERNET_HEADER_BYTES:
        return Decapsulated(frame=raw, understood=False,
                            reason="frame shorter than an Ethernet header")

    dst, src = raw[0:6], raw[6:12]
    ethertype = struct.unpack(">H", raw[12:14])[0]
    offset = ETHERNET_HEADER_BYTES
    layers: List[str] = []

    # VLAN tags outside the label stack are common on a trunk port.
    while ethertype in (ETH_VLAN, ETH_QINQ, ETH_QINQ_LEGACY):
        if offset + 4 > len(raw):
            return Decapsulated(frame=raw, layers=tuple(layers),
                                understood=False,
                                reason="truncated VLAN tag")
        vid = struct.unpack(">H", raw[offset:offset + 2])[0] & 0x0FFF
        layers.append("vlan:%d" % vid)
        ethertype = struct.unpack(">H", raw[offset + 2:offset + 4])[0]
        offset += 4

    if ethertype not in (ETH_MPLS_UNICAST, ETH_MPLS_MULTICAST):
        # Nothing of ours. Hand back the frame as it came, minus nothing: the
        # VLAN case is left for dpkt, which already handles it.
        return Decapsulated(frame=raw, layers=tuple(layers), understood=True)

    # ── the label stack ────────────────────────────────────────────────────
    labels: List[int] = []
    while True:
        if offset + LABEL_BYTES > len(raw):
            return Decapsulated(frame=raw, layers=tuple(layers),
                                labels=tuple(labels), understood=False,
                                reason="truncated MPLS label stack")
        shim = struct.unpack(">I", raw[offset:offset + LABEL_BYTES])[0]
        label = shim >> 12
        bottom = (shim >> 8) & 0x01
        labels.append(label)
        layers.append("mpls:%d" % label)
        offset += LABEL_BYTES
        if bottom:
            break
        if len(labels) >= MAX_LABEL_DEPTH:
            return Decapsulated(
                frame=raw, layers=tuple(layers), labels=tuple(labels),
                understood=False,
                reason="MPLS label stack deeper than %d — probably not a label "
                       "stack" % MAX_LABEL_DEPTH)

    payload = raw[offset:]
    if not payload:
        return Decapsulated(frame=raw, layers=tuple(layers),
                            labels=tuple(labels), understood=False,
                            reason="MPLS label stack with no payload")

    # ── what is under the bottom label ─────────────────────────────────────
    nibble = payload[0] >> 4

    if nibble == 0:
        # RFC 4385 control word. Defined to start with four zero bits precisely
        # so it cannot be confused with IPv4 or IPv6.
        if len(payload) <= CONTROL_WORD_BYTES:
            return Decapsulated(frame=raw, layers=tuple(layers),
                                labels=tuple(labels), understood=False,
                                reason="pseudowire control word with no payload")
        layers.append("pw-cw")
        inner = payload[CONTROL_WORD_BYTES:]
        # IP FIRST. Its check validates version, IHL and total length against
        # the buffer, so it is far harder to satisfy by accident than an
        # EtherType lookup — and an inner IPv4 packet can present a valid-
        # looking EtherType out of its own source address.
        if _plausible_ipv4(inner):
            return Decapsulated(
                frame=_synthetic_ethernet(dst, src, 0x0800, inner),
                layers=tuple(layers + ["ip-pw"]), labels=tuple(labels),
                understood=True)
        if _plausible_ipv6(inner):
            return Decapsulated(
                frame=_synthetic_ethernet(dst, src, 0x86DD, inner),
                layers=tuple(layers + ["ip-pw"]), labels=tuple(labels),
                understood=True)
        if _plausible_ethernet(inner):
            layers.append("eompls")
            return Decapsulated(frame=inner, layers=tuple(layers),
                                labels=tuple(labels), understood=True)
        return Decapsulated(
            frame=raw, layers=tuple(layers), labels=tuple(labels),
            understood=False,
            reason="pseudowire payload is neither an Ethernet frame nor IP")

    if nibble == 4 and _plausible_ipv4(payload):
        return Decapsulated(
            frame=_synthetic_ethernet(dst, src, 0x0800, payload),
            layers=tuple(layers + ["ipv4"]), labels=tuple(labels),
            understood=True)

    if nibble == 6 and _plausible_ipv6(payload):
        return Decapsulated(
            frame=_synthetic_ethernet(dst, src, 0x86DD, payload),
            layers=tuple(layers + ["ipv6"]), labels=tuple(labels),
            understood=True)

    # No control word, not IP. An Ethernet pseudowire may legally omit the
    # control word, so accept it only on a plausible EtherType.
    if _plausible_ethernet(payload):
        layers.append("eompls")
        return Decapsulated(frame=payload, layers=tuple(layers),
                            labels=tuple(labels), understood=True)

    return Decapsulated(
        frame=raw, layers=tuple(layers), labels=tuple(labels),
        understood=False,
        reason="payload under the MPLS stack matched no known pseudowire "
               "encapsulation")


def describe(result: Decapsulated) -> str:
    """One line naming the transport, for a coverage reason or an operator."""
    if not result.layers:
        return "unencapsulated Ethernet"
    return " / ".join(result.layers)
