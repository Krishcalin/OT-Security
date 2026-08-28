"""
Excluding the collector's own management traffic (OTS-CAP-006).

WHY THIS IS NOT OPTIONAL
────────────────────────
The management NIC talks to the server continuously — TLS, heartbeats, batches.
If the switch mirrors that traffic onto the SPAN port, the collector captures
its own conversation and then:

  * inventories ITSELF as a discovered asset on the OT network,
  * reports the server as an OT device,
  * counts its own upload as plant traffic, inflating every flow statistic,
  * and, because the volume scales with how much it has to report, gets noisier
    exactly when the network is busiest.

None of that looks like a bug on screen. It looks like an extra asset.

COUNTED, NOT SILENT
───────────────────
Whichever mechanism is used, the number of excluded frames is recorded and
travels with the window. A filter that silently matches nothing and a network
with no self-traffic produce identical output otherwise, and the difference
matters: the first means the exclusion is misconfigured and the asset list is
about to grow a phantom.

TWO MECHANISMS
──────────────
  BPF        the kernel drops the frames before they reach us. Cheapest, and on
             a Pi the capture budget is the scarce resource. But the kernel does
             not tell us how many it dropped for us, so the count is unavailable.
  USERSPACE  we see every frame and decide. Costs CPU per frame, gives an exact
             count.

Neither is right in every case, so the choice is explicit and recorded. The
default is BPF with a periodic userspace audit window, which keeps the steady
state cheap while still proving the filter matches something.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


class ExclusionMode(str, Enum):
    BPF = "bpf"
    USERSPACE = "userspace"
    AUDIT = "audit"          # BPF off, userspace counting on, for verification
    DISABLED = "disabled"


class ExclusionError(ValueError):
    """Refuses a malformed identity rather than building a filter that silently
    matches nothing."""


@dataclass
class SelfIdentity:
    """What the collector must not mistake for a plant asset.

    MAC is primary: it catches the collector's frames at layer 2 regardless of
    addressing, including ARP and IPv6 traffic an IPv4-only filter would miss.
    """

    mgmt_mac: Optional[str] = None
    mgmt_ipv4: Optional[str] = None
    server_ipv4: Optional[str] = None

    def __post_init__(self):
        if self.mgmt_mac is not None:
            if not _MAC_RE.match(self.mgmt_mac):
                raise ExclusionError(
                    "management MAC %r is not a MAC address; a filter built from "
                    "it would match nothing and the collector would inventory "
                    "itself" % (self.mgmt_mac,))
            self.mgmt_mac = self.mgmt_mac.lower()
        for name in ("mgmt_ipv4", "server_ipv4"):
            value = getattr(self, name)
            if value is not None and not _IPV4_RE.match(value):
                raise ExclusionError("%s %r is not an IPv4 address" % (name, value))

    @property
    def is_empty(self) -> bool:
        return not (self.mgmt_mac or self.mgmt_ipv4 or self.server_ipv4)


def build_bpf(identity: SelfIdentity) -> Optional[str]:
    """A capture filter excluding the collector's own traffic.

    Returns None when there is nothing to exclude, so the caller can tell
    "no filter needed" from "filter that matches everything".
    """
    if identity.is_empty:
        return None
    clauses: List[str] = []
    if identity.mgmt_mac:
        clauses.append("ether host %s" % identity.mgmt_mac)
    if identity.mgmt_ipv4:
        clauses.append("host %s" % identity.mgmt_ipv4)
    if identity.server_ipv4:
        clauses.append("host %s" % identity.server_ipv4)
    return "not (%s)" % " or ".join(clauses)


@dataclass
class SelfExclusion:
    """Applies and accounts for self-traffic exclusion."""

    identity: SelfIdentity = field(default_factory=SelfIdentity)
    mode: ExclusionMode = ExclusionMode.BPF
    excluded_frames: int = 0
    inspected_frames: int = 0

    @property
    def bpf(self) -> Optional[str]:
        """The filter to hand the capture backend, or None."""
        if self.mode in (ExclusionMode.BPF,) and not self.identity.is_empty:
            return build_bpf(self.identity)
        return None

    @property
    def counts_in_userspace(self) -> bool:
        return self.mode in (ExclusionMode.USERSPACE, ExclusionMode.AUDIT)

    def matches_self(self, src_mac: Optional[str] = None,
                     dst_mac: Optional[str] = None,
                     src_ip: Optional[str] = None,
                     dst_ip: Optional[str] = None) -> bool:
        ident = self.identity
        if ident.mgmt_mac:
            mac = ident.mgmt_mac
            if (src_mac or "").lower() == mac or (dst_mac or "").lower() == mac:
                return True
        for addr in (ident.mgmt_ipv4, ident.server_ipv4):
            if addr and (src_ip == addr or dst_ip == addr):
                return True
        return False

    def should_analyse(self, **frame) -> bool:
        """True if this frame is plant traffic and should be analysed."""
        if not self.counts_in_userspace or self.identity.is_empty:
            return True
        self.inspected_frames += 1
        if self.matches_self(**frame):
            self.excluded_frames += 1
            return False
        return True

    def reset_window(self) -> None:
        self.excluded_frames = 0
        self.inspected_frames = 0

    def to_dict(self) -> dict:
        """Recorded on every window so the exclusion is auditable.

        `excluded_frames` is None under BPF because the kernel does not report
        what it filtered on our behalf — and reporting 0 there would claim the
        collector saw no self-traffic when it simply could not count it.
        """
        return {
            "mode": self.mode.value,
            "bpf": self.bpf,
            "configured": not self.identity.is_empty,
            "excluded_frames": (self.excluded_frames
                                if self.counts_in_userspace else None),
            "inspected_frames": (self.inspected_frames
                                 if self.counts_in_userspace else None),
        }

    def warnings(self) -> List[str]:
        out: List[str] = []
        if self.identity.is_empty:
            out.append(
                "self-exclusion is not configured (OTS-CAP-006): if the SPAN "
                "mirrors the management VLAN, the collector will inventory "
                "itself and the server as OT assets")
        elif not self.identity.mgmt_mac:
            out.append(
                "self-exclusion has no management MAC, so ARP and IPv6 frames "
                "from this collector will still be analysed")
        if (self.counts_in_userspace and self.inspected_frames > 0
                and self.excluded_frames == 0 and not self.identity.is_empty):
            out.append(
                "self-exclusion matched nothing across %d inspected frames — "
                "either the SPAN does not mirror the management VLAN (fine) or "
                "the configured identity is wrong (not fine)"
                % self.inspected_frames)
        return out
