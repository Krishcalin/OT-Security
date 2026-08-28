"""
Drop-counter sources.

The only platform-dependent part of coverage accounting. Everything in
`coverage.py` is handed snapshots and can be tested anywhere; this is the seam
where a Linux NIC is actually required, so the collector's honesty logic does
not become untestable off a Raspberry Pi.

WHERE THE NUMBERS COME FROM
───────────────────────────
  /sys/class/net/<if>/statistics/rx_packets        offered to the kernel
                                   rx_dropped      kernel discarded it
                                   rx_missed_errors NIC ring overran

  AF_PACKET getsockopt(PACKET_STATISTICS)          tp_packets / tp_drops
  libpcap   pcap_stats()                           ps_recv / ps_drop

Interface and capture loss are DIFFERENT failures — see coverage.py — so they
are read from different places and never merged here.

A COUNTER THAT CANNOT BE READ RETURNS None
──────────────────────────────────────────
Not zero. Zero is a measurement; None is the absence of one, and the difference
decides whether a window may be called clean. Every read here is written so a
missing file, a permission error or an unsupported platform yields None rather
than a plausible-looking zero.
"""
from __future__ import annotations

import os
from typing import Callable, Optional

from .coverage import DropSnapshot

SYSFS_ROOT = "/sys/class/net"


def _read_int(path: str) -> Optional[int]:
    """A sysfs counter, or None if it cannot be read for any reason."""
    try:
        with open(path, "r") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        # Missing file, no permission, not Linux, or a non-numeric body. All of
        # them mean the same thing to the caller: this counter is unavailable.
        return None


class SysfsInterfaceCounters:
    """Interface-level loss from /sys/class/net/<iface>/statistics.

    Available unprivileged on Linux. Absent on Windows and macOS, where every
    read returns None and coverage becomes UNKNOWN — which is the correct
    outcome, not a bug: a collector that cannot measure loss must not claim
    there was none.
    """

    def __init__(self, interface: str, root: str = SYSFS_ROOT):
        self.interface = interface
        self.root = root

    def _stat(self, name: str) -> Optional[int]:
        return _read_int(os.path.join(self.root, self.interface, "statistics", name))

    def read(self) -> DropSnapshot:
        return DropSnapshot(
            interface_rx_packets=self._stat("rx_packets"),
            interface_rx_dropped=self._stat("rx_dropped"),
            interface_rx_missed=self._stat("rx_missed_errors"),
            source="sysfs:%s" % self.interface,
        )

    @property
    def available(self) -> bool:
        return os.path.isdir(os.path.join(self.root, self.interface, "statistics"))


class PacketSocketCounters:
    """Capture-buffer loss from AF_PACKET's PACKET_STATISTICS.

    Reading it CLEARS it on Linux, so the accumulated total is kept here and
    returned as a monotonic counter — otherwise every read would look like a
    counter reset to `DropDelta.between`, and every window would be UNKNOWN.
    """

    SOL_PACKET = 263
    PACKET_STATISTICS = 6

    def __init__(self, sock=None):
        self._sock = sock
        self._packets = 0
        self._drops = 0

    def read(self) -> DropSnapshot:
        if self._sock is None:
            return DropSnapshot(source="packet-socket:absent")
        try:
            import struct

            raw = self._sock.getsockopt(self.SOL_PACKET, self.PACKET_STATISTICS, 8)
            packets, drops = struct.unpack("II", raw)
            # Deltas since the last read; accumulate to stay monotonic.
            self._packets += packets
            self._drops += drops
            return DropSnapshot(capture_received=self._packets,
                                capture_dropped=self._drops,
                                source="packet-socket")
        except Exception:                                   # noqa: BLE001
            return DropSnapshot(source="packet-socket:unreadable")


class PcapStatsCounters:
    """Capture-buffer loss from libpcap's pcap_stats(), via a live scapy socket.

    scapy does not expose pcap_stats uniformly across its backends, so this
    probes for it and degrades to None rather than guessing.
    """

    def __init__(self, pcap_handle=None):
        self._handle = pcap_handle

    def read(self) -> DropSnapshot:
        handle = self._handle
        if handle is None:
            return DropSnapshot(source="pcap-stats:absent")
        try:
            stats = handle.stats()
            received = getattr(stats, "ps_recv", None)
            dropped = getattr(stats, "ps_drop", None)
            if received is None and isinstance(stats, (tuple, list)) and len(stats) >= 2:
                received, dropped = stats[0], stats[1]
            return DropSnapshot(capture_received=received, capture_dropped=dropped,
                                source="pcap-stats")
        except Exception:                                   # noqa: BLE001
            return DropSnapshot(source="pcap-stats:unreadable")


class NullCounters:
    """Reads nothing. Every window it accounts for is UNKNOWN.

    The honest default when no counter source could be established, and what a
    developer machine without a capture NIC gets.
    """

    def read(self) -> DropSnapshot:
        return DropSnapshot(source="null")


class CombinedCounters:
    """Interface counters and capture counters merged into one snapshot.

    Neither source alone is sufficient: sysfs cannot see userspace buffer loss,
    and the socket cannot see what the NIC discarded before it.
    """

    def __init__(self, interface_source=None, capture_source=None):
        self.interface_source = interface_source or NullCounters()
        self.capture_source = capture_source or NullCounters()

    def read(self) -> DropSnapshot:
        iface = self.interface_source.read()
        cap = self.capture_source.read()
        sources = [s for s in (iface.source, cap.source) if s]
        return DropSnapshot(
            interface_rx_packets=iface.interface_rx_packets,
            interface_rx_dropped=iface.interface_rx_dropped,
            interface_rx_missed=iface.interface_rx_missed,
            capture_received=cap.capture_received,
            capture_dropped=cap.capture_dropped,
            source="+".join(sources),
        )


def build_counters(interface: str, sock=None, pcap_handle=None,
                   sysfs_root: str = SYSFS_ROOT) -> CombinedCounters:
    """The best counter set available for this interface on this platform."""
    iface_src = SysfsInterfaceCounters(interface, root=sysfs_root)
    if not iface_src.available:
        iface_src = NullCounters()

    if sock is not None:
        cap_src = PacketSocketCounters(sock)
    elif pcap_handle is not None:
        cap_src = PcapStatsCounters(pcap_handle)
    else:
        cap_src = NullCounters()

    return CombinedCounters(iface_src, cap_src)
