"""
Collector health (OTS-CAP-005).

Capture loss is a HEALTH problem, not a security finding, and the distinction
matters operationally: a security alert goes to an analyst who will look for an
attacker, while sustained drops need an engineer to resize a ring buffer or move
the sensor. Filing one as the other wastes both.

WHY SUSTAINED RATHER THAN ANY
─────────────────────────────
A burst of drops during a switch reconvergence is noise; the same rate for an
hour means the collector is structurally undersized and a proportion of the
plant's traffic is simply not being examined. Alarming on every drop trains
operators to ignore the alarm, so the alarm is raised on a rate sustained across
consecutive windows.

UNKNOWN COVERAGE ALSO ALARMS
────────────────────────────
A run of windows whose counters could not be read is not quiet — it is blind,
and blind looks identical to clean on every screen downstream. It gets its own
alarm rather than being folded into the drop alarm, because the fix is different
(a counter source is missing, not a buffer).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from .coverage import CaptureWindow, Coverage


class AlarmState(str, Enum):
    OK = "ok"
    LOSS = "loss"
    BLIND = "blind"


@dataclass
class HealthAlarm:
    state: AlarmState
    detail: str
    windows: int = 0
    worst_loss_fraction: Optional[float] = None

    @property
    def active(self) -> bool:
        return self.state is not AlarmState.OK


@dataclass
class CaptureHealth:
    """Rolling assessment over the last N accounted windows."""

    loss_fraction_threshold: float = 0.001      # 0.1% of offered frames
    sustained_windows: int = 3
    history_size: int = 20
    _recent: List[CaptureWindow] = field(default_factory=list)

    def observe(self, window: CaptureWindow) -> None:
        self._recent.append(window)
        if len(self._recent) > self.history_size:
            self._recent.pop(0)

    @property
    def windows_seen(self) -> int:
        return len(self._recent)

    def _loss_fraction(self, window: CaptureWindow) -> Optional[float]:
        observed = window.observed_fraction
        return None if observed is None else 1.0 - observed

    def evaluate(self) -> HealthAlarm:
        if not self._recent:
            return HealthAlarm(AlarmState.OK, "no windows accounted yet")

        tail = self._recent[-self.sustained_windows:]

        # Blind first: if we cannot measure, a loss verdict would be invented.
        if len(tail) >= self.sustained_windows and all(
                w.coverage is Coverage.UNKNOWN for w in tail):
            return HealthAlarm(
                AlarmState.BLIND,
                "%d consecutive windows with unreadable drop counters — capture "
                "coverage is unknown, so nothing from this collector may be "
                "reported as clean" % len(tail),
                windows=len(tail))

        losses = [self._loss_fraction(w) for w in tail]
        measured = [l for l in losses if l is not None]
        if (len(tail) >= self.sustained_windows and len(measured) == len(tail)
                and all(l > self.loss_fraction_threshold for l in measured)):
            worst = max(measured)
            return HealthAlarm(
                AlarmState.LOSS,
                "packet loss above %.3f%% across %d consecutive windows "
                "(worst %.2f%%) — the collector is not seeing all traffic"
                % (self.loss_fraction_threshold * 100, len(tail), worst * 100),
                windows=len(tail), worst_loss_fraction=worst)

        return HealthAlarm(AlarmState.OK, "capture healthy",
                           windows=len(self._recent))

    def summary(self) -> dict:
        alarm = self.evaluate()
        measured = [w for w in self._recent if w.coverage is not Coverage.UNKNOWN]
        return {
            "state": alarm.state.value,
            "detail": alarm.detail,
            "windows_accounted": len(self._recent),
            "windows_measurable": len(measured),
            "windows_degraded": sum(1 for w in self._recent
                                    if w.coverage is Coverage.DEGRADED),
            "windows_unknown": sum(1 for w in self._recent
                                   if w.coverage is Coverage.UNKNOWN),
        }
