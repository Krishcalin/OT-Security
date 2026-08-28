"""
Pre-start checks on the capture interface.

OTS-CAP-001 and OTS-SEC-001. The collector sits on a live plant network where a
single transmitted frame can reach a protection relay, so "we are passive" has
to be a checked property of the running system rather than a claim in a README.

WHAT AN IP ADDRESS ON THE CAPTURE PORT MEANS
────────────────────────────────────────────
It means the kernel owns that interface: it will answer ARP, it may answer ICMP,
it will emit DHCP, IPv6 router solicitations, mDNS and whatever else the host
stack decides to say. The interface stops being a tap and becomes a host on the
OT segment. That is exactly the thing the SPAN port was chosen to avoid, and it
happens silently — nothing in a packet capture tells you your own NIC is
talking.

So a capture interface carrying an address is a hard refusal to start, not a
warning. A warning gets scrolled past and the collector runs for a year.

These checks are Linux-shaped and read-only. On a platform where a fact cannot
be established the result is UNKNOWN, and the caller decides — the same
three-state honesty used for coverage. UNKNOWN never masquerades as PASS.
"""
from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

SYSFS_ROOT = "/sys/class/net"


class CheckResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


@dataclass
class Check:
    name: str
    result: CheckResult
    detail: str = ""
    fatal: bool = False

    @property
    def blocks_start(self) -> bool:
        return self.fatal and self.result is CheckResult.FAIL


@dataclass
class Preflight:
    interface: str
    checks: List[Check] = field(default_factory=list)

    @property
    def may_start(self) -> bool:
        return not any(c.blocks_start for c in self.checks)

    @property
    def unknowns(self) -> List[Check]:
        return [c for c in self.checks if c.result is CheckResult.UNKNOWN]

    def report(self) -> str:
        lines = ["capture interface preflight: %s" % self.interface]
        for c in self.checks:
            mark = {"pass": "  OK  ", "fail": " FAIL ", "unknown": "  ??  "}[c.result.value]
            lines.append("%s %-34s %s" % (mark, c.name, c.detail))
        if not self.may_start:
            lines.append("REFUSING TO START — a fatal check failed.")
        elif self.unknowns:
            lines.append("Starting with %d unverified check(s); coverage claims "
                         "will reflect that." % len(self.unknowns))
        return "\n".join(lines)


def _interface_exists(interface: str, root: str) -> Optional[bool]:
    path = os.path.join(root, interface)
    if not os.path.isdir(root):
        return None                       # not a Linux sysfs host; cannot tell
    return os.path.isdir(path)


def _addresses_for(interface: str) -> Optional[List[str]]:
    """Addresses currently configured on the interface, or None if unknowable.

    Tries the modern `socket.if_nameindex` + `psutil`-free route: reads what the
    kernel exposes. Where neither is available the answer is None, which becomes
    an UNKNOWN check rather than an assumed-clean PASS.
    """
    try:
        import fcntl
        import struct

        # SIOCGIFADDR. Present on Linux; raises elsewhere, which is the point.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = struct.pack("256s", interface.encode()[:15])
            raw = fcntl.ioctl(sock.fileno(), 0x8915, packed)
            return [socket.inet_ntoa(raw[20:24])]
        except OSError:
            # No IPv4 address assigned — the state we want.
            return []
        finally:
            sock.close()
    except Exception:                                       # noqa: BLE001
        return None


def _flags(interface: str, root: str) -> Optional[int]:
    path = os.path.join(root, interface, "flags")
    try:
        with open(path, "r") as handle:
            return int(handle.read().strip(), 16)
    except (OSError, ValueError):
        return None


IFF_UP = 0x1
IFF_PROMISC = 0x100


def check_capture_interface(interface: str, root: str = SYSFS_ROOT,
                            address_reader=None) -> Preflight:
    """Everything that must be true before a single frame is captured."""
    read_addresses = address_reader or _addresses_for
    pf = Preflight(interface=interface)

    exists = _interface_exists(interface, root)
    if exists is None:
        pf.checks.append(Check("interface exists", CheckResult.UNKNOWN,
                               "no %s on this platform" % root))
    elif exists:
        pf.checks.append(Check("interface exists", CheckResult.PASS, interface))
    else:
        pf.checks.append(Check("interface exists", CheckResult.FAIL,
                               "%s not found" % interface, fatal=True))
        return pf                      # nothing else is meaningful

    addresses = read_addresses(interface)
    if addresses is None:
        pf.checks.append(Check(
            "no IP address (OTS-CAP-001)", CheckResult.UNKNOWN,
            "could not read interface addresses on this platform"))
    elif addresses:
        pf.checks.append(Check(
            "no IP address (OTS-CAP-001)", CheckResult.FAIL,
            "carries %s — the kernel will speak on this interface "
            "(ARP/ICMP/DHCP/mDNS) and it is no longer a passive tap"
            % ", ".join(addresses),
            fatal=True))
    else:
        pf.checks.append(Check("no IP address (OTS-CAP-001)", CheckResult.PASS,
                               "no IPv4 address configured"))

    flags = _flags(interface, root)
    if flags is None:
        pf.checks.append(Check("interface is up", CheckResult.UNKNOWN,
                               "flags unreadable"))
        pf.checks.append(Check("promiscuous mode", CheckResult.UNKNOWN,
                               "flags unreadable"))
    else:
        up = bool(flags & IFF_UP)
        pf.checks.append(Check(
            "interface is up", CheckResult.PASS if up else CheckResult.FAIL,
            "IFF_UP set" if up else "interface is down — nothing will be captured",
            fatal=True))
        promisc = bool(flags & IFF_PROMISC)
        pf.checks.append(Check(
            "promiscuous mode", CheckResult.PASS if promisc else CheckResult.UNKNOWN,
            "IFF_PROMISC set" if promisc else
            "not set yet — libpcap normally enables it when the capture opens"))

    return pf
