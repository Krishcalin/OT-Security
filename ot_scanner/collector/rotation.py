"""
Rolling pcap retention (OTS-CAP-002, OTS-OPS-002).

Continuous capture writes forever; the disk does not. So retention is bounded by
a byte ceiling with oldest-first eviction, and the eviction is COUNTED — an
operator asking "do we still have the traffic from Tuesday" gets an answer
rather than a guess.

TWO FAILURES THIS IS SHAPED AROUND
──────────────────────────────────
1. Filling the disk. A collector that fills its root filesystem stops capturing,
   and on a Pi may stop booting. The ceiling is enforced before each new file,
   not after, so the high-water mark is bounded rather than merely tidied up.

2. Wearing out the SD card. Continuous pcap writing to the boot SD card is a
   predictable death: weeks to months. `warn_if_on_boot_media` exists so the
   collector says so at start-up instead of failing mysteriously in the field.

Rotation is by size AND age: size protects the disk, age bounds how much traffic
one file can hide, so a corrupt final file loses minutes rather than hours.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

PCAP_SUFFIX = ".pcap"
_NAME_RE = re.compile(r"^(?P<prefix>.+)-(?P<seq>\d{6})-(?P<ts>\d+)\.pcap$")


@dataclass
class Eviction:
    """One deleted file, kept so retention can be reported rather than assumed."""

    path: str
    bytes_freed: int
    started_at: Optional[int] = None


#: Q5a. Fits a 1TB USB SSD alongside the OS and the observation spool.
DEFAULT_MAX_BYTES = 512 * 1024 ** 3


@dataclass
class RetentionState:
    files: List[str] = field(default_factory=list)
    total_bytes: int = 0
    evictions: int = 0
    bytes_evicted: int = 0
    oldest_start: Optional[int] = None

    def achieved_days(self, now: Optional[float] = None) -> Optional[float]:
        """How much history the budget is CURRENTLY buying.

        Returns None when it cannot be known -- no files yet, or a clock that
        disagrees with the filenames. A retention figure is only useful if it is
        measured: the same 512 GB holds nine days at 5 Mbps and under one during
        a sustained burst, so a configured day-count would be a promise broken
        silently by a busy afternoon.
        """
        if self.oldest_start is None:
            return None
        import time as _time

        stamp = _time.time() if now is None else now
        span = stamp - self.oldest_start
        if span <= 0:
            return None
        return span / 86400.0

    def describe(self, now: Optional[float] = None) -> str:
        gib = self.total_bytes / 1024 ** 3
        days = self.achieved_days(now)
        if days is None:
            return "%.1f GiB across %d file(s); window not yet measurable" % (
                gib, len(self.files))
        return "%.1f GiB across %d file(s); holding %.1f days" % (
            gib, len(self.files), days)


class RollingPcapStore:
    """A directory of size-capped, time-capped pcap files with oldest-first eviction.

    Deliberately does NOT write packets — it owns naming, rotation policy and
    eviction, all of which are pure decisions over a filesystem listing and are
    therefore testable without a capture NIC. The writer plugs in via
    `open_writer`, so scapy/dpkt/AF_PACKET stay out of the retention logic.
    """

    def __init__(self, directory: str, prefix: str = "capture",
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 max_file_bytes: int = 256 * 1024 ** 2,
                 max_file_seconds: float = 900.0,
                 lister: Optional[Callable[[str], List[str]]] = None,
                 sizer: Optional[Callable[[str], int]] = None,
                 remover: Optional[Callable[[str], None]] = None):
        if max_file_bytes > max_bytes:
            raise ValueError("max_file_bytes exceeds the whole retention budget")
        self.directory = directory
        self.prefix = prefix
        self.max_bytes = max_bytes
        self.max_file_bytes = max_file_bytes
        self.max_file_seconds = max_file_seconds
        self._list = lister or self._default_list
        self._size = sizer or (lambda p: os.path.getsize(p))
        self._remove = remover or os.remove
        self._seq = 0

    # ── naming ────────────────────────────────────────────────────────────
    def _default_list(self, directory: str) -> List[str]:
        try:
            return [os.path.join(directory, n) for n in sorted(os.listdir(directory))
                    if n.endswith(PCAP_SUFFIX)]
        except OSError:
            return []

    def next_name(self, started_at: int) -> str:
        self._seq += 1
        return os.path.join(
            self.directory,
            "%s-%06d-%d%s" % (self.prefix, self._seq, int(started_at), PCAP_SUFFIX))

    @staticmethod
    def parse_name(path: str) -> Optional[Tuple[int, int]]:
        """(sequence, start epoch) from a managed filename, else None."""
        m = _NAME_RE.match(os.path.basename(path))
        if not m:
            return None
        return int(m.group("seq")), int(m.group("ts"))

    # ── policy ────────────────────────────────────────────────────────────
    def should_rotate(self, current_bytes: int, age_seconds: float) -> bool:
        return current_bytes >= self.max_file_bytes or age_seconds >= self.max_file_seconds

    def state(self) -> RetentionState:
        files = self._managed_files()
        total = 0
        oldest: Optional[int] = None
        for path, (_, started) in files:
            try:
                total += self._size(path)
            except OSError:
                continue
            if oldest is None or started < oldest:
                oldest = started
        return RetentionState(files=[p for p, _ in files], total_bytes=total,
                              oldest_start=oldest)

    def _managed_files(self) -> List[Tuple[str, Tuple[int, int]]]:
        """Only files this store named. Anything else in the directory is left
        alone — eviction must never delete a file it does not recognise."""
        out = []
        for path in self._list(self.directory):
            parsed = self.parse_name(path)
            if parsed is not None:
                out.append((path, parsed))
        out.sort(key=lambda item: (item[1][1], item[1][0]))   # oldest first
        return out

    def enforce(self, incoming_bytes: int = 0) -> List[Eviction]:
        """Evict oldest-first until the ceiling would hold with `incoming_bytes`.

        Called BEFORE opening a new file, so the ceiling bounds the high-water
        mark rather than being restored after it has already been exceeded.
        """
        evicted: List[Eviction] = []
        files = self._managed_files()
        total = 0
        sizes = {}
        for path, _ in files:
            try:
                sizes[path] = self._size(path)
            except OSError:
                sizes[path] = 0
            total += sizes[path]

        for path, (_, started) in files:
            if total + incoming_bytes <= self.max_bytes:
                break
            try:
                self._remove(path)
            except OSError:
                continue          # gone already, or not ours to delete
            freed = sizes.get(path, 0)
            total -= freed
            evicted.append(Eviction(path=path, bytes_freed=freed, started_at=started))
        return evicted


def warn_if_on_boot_media(directory: str) -> Optional[str]:
    """A warning when capture would be written to the boot SD card.

    Continuous pcap writing to SD is a predictable failure measured in weeks.
    Returns the warning text, or None when the location looks like attached
    storage — or when it cannot be determined, because guessing "this is fine"
    is the one answer that helps nobody.
    """
    try:
        real = os.path.realpath(directory)
    except OSError:
        return None
    for mount in ("/media", "/mnt", "/srv", "/data"):
        if real.startswith(mount):
            return None
    if not os.path.exists("/sys/class/net"):
        return None                        # not a Linux host; not a Pi concern
    return ("capture directory %s looks like it is on the boot filesystem. "
            "Continuous pcap writing wears out an SD card in weeks — put it on "
            "attached storage (OTS-OPS-002)." % real)
