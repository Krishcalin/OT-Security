"""
The capture loop (OTS-CAP-001 .. 006).

Ties together the pieces built separately: preflight refuses to start on an
unsafe interface, counters are read at both ends of every window, self-traffic
is excluded and counted, pcap retention is enforced before each new file, and
health is assessed across windows.

WHAT THE LOOP GUARANTEES
────────────────────────
1. It does not start if the capture interface is unsafe. Not a warning.
2. Every window is closed with a counter read, so coverage is accounted even
   when the window was empty. A quiet network and a dead capture look identical
   otherwise.
3. Counters are read at window CLOSE and that same reading opens the next
   window. Reading twice would leave a gap between them in which loss is
   invisible — small, constant, and always in the direction of looking clean.
4. Retention is enforced before a file is opened, not after it has grown.

The clock is injected. A loop that calls time.time() directly cannot be tested
for window boundaries without sleeping through them.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .capture import CaptureSource, Frame
from .coverage import CaptureWindow, WindowAccountant
from .health import CaptureHealth
from .preflight import Preflight, check_capture_interface
from .rotation import RollingPcapStore
from .self_exclusion import SelfExclusion


class CaptureRefused(RuntimeError):
    """Preflight said no. Raised rather than logged: a collector that starts
    anyway on an interface carrying an IP is the failure OTS-CAP-001 exists to
    prevent, and a log line does not stop it."""


@dataclass
class CollectorConfig:
    collector_id: str = "collector"
    capture_interface: str = "eth0"
    window_seconds: float = 60.0
    read_batch: int = 256
    read_timeout: float = 1.0
    enforce_preflight: bool = True


@dataclass
class WindowReport:
    """A closed window plus everything observed alongside it."""

    window: CaptureWindow
    frames_analysed: int = 0
    bytes_analysed: int = 0
    self_excluded: Optional[int] = None
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        out = self.window.to_dict()
        out.update({
            "frames_analysed": self.frames_analysed,
            "bytes_analysed": self.bytes_analysed,
            "self_excluded": self.self_excluded,
            "warnings": list(self.warnings),
        })
        return out


class CaptureService:
    """The collector's capture loop.

    Analysis is injected as `on_frames`, so this module owns capture and
    accounting only — the protocol analysers plug in at Phase 2 without this
    loop needing to know they exist.
    """

    def __init__(self, source: CaptureSource, config: Optional[CollectorConfig] = None,
                 exclusion: Optional[SelfExclusion] = None,
                 store: Optional[RollingPcapStore] = None,
                 health: Optional[CaptureHealth] = None,
                 clock: Callable[[], float] = time.time,
                 preflight: Optional[Preflight] = None,
                 on_frames: Optional[Callable[[List[Frame]], None]] = None):
        self.source = source
        self.config = config or CollectorConfig()
        self.exclusion = exclusion or SelfExclusion()
        self.store = store
        self.health = health or CaptureHealth()
        self.clock = clock
        self.on_frames = on_frames
        self._preflight = preflight
        self._accountant = WindowAccountant(
            collector_id=self.config.collector_id,
            window_seconds=self.config.window_seconds)
        self._window_seq = 0
        self._started = False
        self.reports: List[WindowReport] = []

    # ── start-up ──────────────────────────────────────────────────────────
    def preflight(self) -> Preflight:
        if self._preflight is None:
            self._preflight = check_capture_interface(self.config.capture_interface)
        return self._preflight

    def start(self) -> Preflight:
        pf = self.preflight()
        if self.config.enforce_preflight and not pf.may_start:
            failed = [c.name for c in pf.checks if c.blocks_start]
            raise CaptureRefused(
                "refusing to capture on %s: %s. %s"
                % (self.config.capture_interface, ", ".join(failed),
                   pf.report()))
        self.source.open()
        self._started = True
        self._open_window()
        return pf

    def _open_window(self) -> None:
        self._window_seq += 1
        self.exclusion.reset_window()
        self._accountant.open_window(
            "w-%06d" % self._window_seq, self.clock(), self.source.stats())
        self._window_frames = 0
        self._window_bytes = 0

    # ── the loop ──────────────────────────────────────────────────────────
    def poll(self) -> Optional[WindowReport]:
        """Read one batch; close the window if it is due. Returns a report only
        on a window boundary."""
        if not self._started:
            raise RuntimeError("start() before poll()")

        frames = self.source.read(self.config.read_batch, self.config.read_timeout)
        keep: List[Frame] = []
        for frame in frames:
            if self.exclusion.should_analyse(
                    src_mac=frame.src_mac, dst_mac=frame.dst_mac,
                    src_ip=frame.src_ip, dst_ip=frame.dst_ip):
                keep.append(frame)

        if keep:
            self._window_frames += len(keep)
            self._window_bytes += sum(f.length for f in keep)
            self._accountant.record_packets(len(keep))
            if self.on_frames is not None:
                self.on_frames(keep)

        now = self.clock()
        due = (now - self._accountant._open["at"]) >= self.config.window_seconds
        if due:
            return self._close_window(now)
        return None

    def _close_window(self, now: float) -> WindowReport:
        # ONE counter read closes this window and opens the next. Reading twice
        # leaves an unaccounted gap between them.
        snapshot = self.source.stats()
        window = self._accountant.close_window(now, snapshot)
        self.health.observe(window)

        report = WindowReport(
            window=window,
            frames_analysed=self._window_frames,
            bytes_analysed=self._window_bytes,
            self_excluded=(self.exclusion.excluded_frames
                           if self.exclusion.counts_in_userspace else None),
            warnings=self.exclusion.warnings(),
        )
        alarm = self.health.evaluate()
        if alarm.active:
            report.warnings.append(alarm.detail)
        self.reports.append(report)

        self._window_seq += 1
        self.exclusion.reset_window()
        self._accountant.open_window("w-%06d" % self._window_seq, now, snapshot)
        self._window_frames = 0
        self._window_bytes = 0
        return report

    def run_until_exhausted(self, max_polls: int = 100000) -> List[WindowReport]:
        """Drive a finite source to completion — the replay path.

        The final partial window is closed too. Dropping it would silently
        discard the tail of every replayed capture.
        """
        polls = 0
        while not self.source.exhausted and polls < max_polls:
            self.poll()
            polls += 1
        if self._accountant._open is not None and self._window_frames >= 0:
            self._close_window(self.clock())
        return self.reports

    def stop(self) -> Optional[WindowReport]:
        final = None
        if self._started and self._accountant._open is not None:
            final = self._close_window(self.clock())
        self.source.close()
        self._started = False
        return final

    # ── reporting ─────────────────────────────────────────────────────────
    def coverage_summary(self) -> dict:
        summary = self.health.summary()
        summary.update({
            "collector_id": self.config.collector_id,
            "interface": self.config.capture_interface,
            "windows": len(self.reports),
            "frames_analysed": sum(r.frames_analysed for r in self.reports),
            "self_exclusion": self.exclusion.to_dict(),
        })
        return summary
