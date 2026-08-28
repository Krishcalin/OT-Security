"""
Capture coverage accounting — what the collector actually saw.

WHY THIS MODULE EXISTS
──────────────────────
A passive sensor that drops frames under load still produces a report, and that
report looks exactly like one from a network that is genuinely clean. On a
substation network that is the worst failure this system can have: an operator
reads "no findings" and cannot tell it apart from "we did not see the traffic".

So coverage is not a diagnostic printed at the end of a run. It is a property of
every window, it travels with every finding derived from that window, and it has
THREE states rather than two:

    COMPLETE   counters were read at both ends and showed no loss
    DEGRADED   loss was measured
    UNKNOWN    the counters could not be read

UNKNOWN is the one that matters and the one usually missing. If the collector
cannot measure loss, it does not know whether there was any — and reporting that
as COMPLETE is a claim it has not earned. Unknown coverage is treated as
not-clean everywhere downstream (see `is_trustworthy`).

TWO INDEPENDENT PLACES FRAMES ARE LOST
──────────────────────────────────────
They are different failures with different fixes, so they are counted
separately rather than summed into one number:

  * INTERFACE loss — the NIC or kernel discarded the frame before libpcap saw
    it (`rx_dropped`, `rx_missed_errors`). Usually the link is faster than the
    hardware or the ring is too small.
  * CAPTURE loss — libpcap/AF_PACKET received it and the userspace buffer was
    full when it arrived. Usually analysis is too slow, or the snap buffer is
    undersized.

A window is degraded if EITHER is non-zero.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Coverage(str, Enum):
    """How much of the window's traffic the collector can account for."""

    COMPLETE = "complete"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


#: Coverage states a finding may be presented as clean evidence from. UNKNOWN is
#: deliberately absent: "we could not tell" is not "we looked and it was fine".
TRUSTWORTHY = (Coverage.COMPLETE,)


@dataclass(frozen=True)
class DropSnapshot:
    """Counters read at one instant. Monotonic since interface/process start.

    `None` means THIS COUNTER COULD NOT BE READ, which is not the same as zero
    and must never be coerced to zero. A missing counter is what produces
    Coverage.UNKNOWN.
    """

    interface_rx_packets: Optional[int] = None
    interface_rx_dropped: Optional[int] = None
    interface_rx_missed: Optional[int] = None
    capture_received: Optional[int] = None
    capture_dropped: Optional[int] = None
    source: str = ""

    @property
    def interface_readable(self) -> bool:
        return (self.interface_rx_dropped is not None
                and self.interface_rx_missed is not None)

    @property
    def capture_readable(self) -> bool:
        return self.capture_dropped is not None


def _delta(later: Optional[int], earlier: Optional[int]) -> Optional[int]:
    """Difference between two readings of a monotonic counter.

    Returns None if either reading is missing, or if the counter went BACKWARDS
    — which means it was reset (interface bounced, process restarted) and the
    interval is no longer measurable. Reporting a negative or clamped value here
    would manufacture a zero-loss window out of a counter reset.
    """
    if later is None or earlier is None:
        return None
    if later < earlier:
        return None
    return later - earlier


@dataclass(frozen=True)
class DropDelta:
    """Loss over one interval, as the difference of two snapshots."""

    interface_dropped: Optional[int] = None
    interface_missed: Optional[int] = None
    capture_received: Optional[int] = None
    capture_dropped: Optional[int] = None
    counter_reset: bool = False

    @classmethod
    def between(cls, start: DropSnapshot, end: DropSnapshot) -> "DropDelta":
        iface_d = _delta(end.interface_rx_dropped, start.interface_rx_dropped)
        iface_m = _delta(end.interface_rx_missed, start.interface_rx_missed)
        cap_r = _delta(end.capture_received, start.capture_received)
        cap_d = _delta(end.capture_dropped, start.capture_dropped)

        # A counter that was readable at both ends but moved backwards was reset.
        reset = False
        for later, earlier, computed in (
            (end.interface_rx_dropped, start.interface_rx_dropped, iface_d),
            (end.interface_rx_missed, start.interface_rx_missed, iface_m),
            (end.capture_dropped, start.capture_dropped, cap_d),
        ):
            if later is not None and earlier is not None and computed is None:
                reset = True

        return cls(interface_dropped=iface_d, interface_missed=iface_m,
                   capture_received=cap_r, capture_dropped=cap_d,
                   counter_reset=reset)

    @property
    def total_lost(self) -> Optional[int]:
        """Frames lost in the interval, or None if that cannot be known."""
        parts = [self.interface_dropped, self.interface_missed, self.capture_dropped]
        if any(p is None for p in parts):
            return None
        return sum(p for p in parts if p is not None)

    @property
    def measurable(self) -> bool:
        return self.total_lost is not None and not self.counter_reset


@dataclass
class CaptureWindow:
    """One accounting interval, and what may honestly be said about it."""

    window_id: str
    started_at: float
    ended_at: float
    packets_analysed: int = 0
    drops: DropDelta = field(default_factory=DropDelta)
    reasons: List[str] = field(default_factory=list)
    collector_id: str = ""

    @property
    def coverage(self) -> Coverage:
        if not self.drops.measurable:
            return Coverage.UNKNOWN
        lost = self.drops.total_lost or 0
        return Coverage.DEGRADED if lost > 0 else Coverage.COMPLETE

    @property
    def degraded(self) -> bool:
        """True unless the window is provably complete.

        Note the asymmetry: UNKNOWN counts as degraded. Anything consuming this
        should treat an unmeasurable window as unsafe to call clean.
        """
        return self.coverage is not Coverage.COMPLETE

    @property
    def is_trustworthy(self) -> bool:
        return self.coverage in TRUSTWORTHY

    @property
    def lost(self) -> Optional[int]:
        return self.drops.total_lost

    @property
    def observed_fraction(self) -> Optional[float]:
        """Share of offered frames that reached analysis, or None if unknowable.

        Deliberately returns None rather than 1.0 when nothing can be measured:
        a confident 100% is precisely the lie this module exists to prevent.
        """
        lost = self.drops.total_lost
        if lost is None:
            return None
        offered = self.packets_analysed + lost
        if offered <= 0:
            return None
        return self.packets_analysed / offered

    def explain(self) -> str:
        """One line an operator can act on."""
        if self.coverage is Coverage.COMPLETE:
            return "complete — %d packets, no loss measured" % self.packets_analysed
        if self.coverage is Coverage.UNKNOWN:
            why = "; ".join(self.reasons) or "drop counters unreadable"
            return ("UNKNOWN — %d packets analysed, but loss could not be "
                    "measured (%s). This window cannot be reported as clean."
                    % (self.packets_analysed, why))
        bits = []
        if self.drops.interface_dropped:
            bits.append("%d dropped at the interface" % self.drops.interface_dropped)
        if self.drops.interface_missed:
            bits.append("%d missed (NIC ring overrun)" % self.drops.interface_missed)
        if self.drops.capture_dropped:
            bits.append("%d dropped by the capture buffer" % self.drops.capture_dropped)
        frac = self.observed_fraction
        seen = " — saw %.2f%% of offered frames" % (frac * 100) if frac is not None else ""
        return "DEGRADED — " + ", ".join(bits) + seen

    def to_dict(self) -> Dict:
        """The shape that travels with every finding from this window."""
        return {
            "window_id": self.window_id,
            "collector_id": self.collector_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "packets_analysed": self.packets_analysed,
            "coverage": self.coverage.value,
            "degraded": self.degraded,
            "packets_lost": self.drops.total_lost,
            "observed_fraction": self.observed_fraction,
            "interface_dropped": self.drops.interface_dropped,
            "interface_missed": self.drops.interface_missed,
            "capture_dropped": self.drops.capture_dropped,
            "counter_reset": self.drops.counter_reset,
            "reasons": list(self.reasons),
        }


class WindowAccountant:
    """Turns a stream of counter readings into accounted windows.

    Holds no packets and does no I/O: it is handed snapshots. That keeps the
    part of the collector that decides *what may be claimed* testable on any
    machine, while only the counter source needs a Linux NIC.
    """

    def __init__(self, collector_id: str = "", window_seconds: float = 60.0):
        self.collector_id = collector_id
        self.window_seconds = window_seconds
        self._open: Optional[Dict] = None

    def open_window(self, window_id: str, at: float,
                    snapshot: DropSnapshot) -> None:
        reasons: List[str] = []
        if not snapshot.interface_readable:
            reasons.append("interface counters unreadable at window start")
        if not snapshot.capture_readable:
            reasons.append("capture counters unreadable at window start")
        self._open = {"id": window_id, "at": at, "snap": snapshot,
                      "reasons": reasons, "packets": 0}

    def record_packets(self, count: int) -> None:
        if self._open is not None:
            self._open["packets"] += count

    def close_window(self, at: float, snapshot: DropSnapshot) -> CaptureWindow:
        if self._open is None:
            raise RuntimeError("close_window called with no window open")
        start = self._open
        reasons = list(start["reasons"])
        if not snapshot.interface_readable:
            reasons.append("interface counters unreadable at window end")
        if not snapshot.capture_readable:
            reasons.append("capture counters unreadable at window end")

        delta = DropDelta.between(start["snap"], snapshot)
        if delta.counter_reset:
            reasons.append("a drop counter went backwards — interface or capture "
                           "process restarted, so this interval is not measurable")

        window = CaptureWindow(
            window_id=start["id"],
            started_at=start["at"],
            ended_at=at,
            packets_analysed=start["packets"],
            drops=delta,
            reasons=reasons,
            collector_id=self.collector_id,
        )
        self._open = None
        return window
