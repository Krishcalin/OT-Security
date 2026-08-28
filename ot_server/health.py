"""
Fleet health — the question coverage cannot answer (OTS-CAP-005, server side).

THE DEFECT THIS EXISTS TO FIX
─────────────────────────────
Coverage is computed over the windows that ARRIVED. Nothing in it looks at
*when*: `store.recent_windows` returns the last fifty rows ordered by receipt
with no time filter, and `ingest.summarise_coverage` has no notion of now.

So a collector that stopped reporting a week ago still has fifty complete
windows in the table. It summarises as trustworthy, `estate_coverage` counts it
among the healthy, and the estate screen shows a clean plant — indefinitely, for
a sensor that is switched off.

That is precisely the failure this system is built to refuse, arriving through
the one dimension the coverage model never considered. "We looked and saw
nothing" and "we stopped looking last Tuesday" are indistinguishable to a model
that only measures what was delivered.

So silence is a first-class state here, and a silent collector's stored coverage
is explicitly *not* believable — `coverage_is_believable` is what the estate
endpoint consults before counting anybody as healthy.

WHY SUSTAINED, NOT INSTANT
──────────────────────────
`collector/health.py` reached the same conclusion on the capture side and for
the same reason: a burst of drops during a switch reconvergence is noise, and
alarming on every one trains an operator to ignore the alarm. A missed heartbeat
is a lost packet or a busy link; six missed heartbeats is a collector that is
not coming back on its own.

WHAT AN ALARM IS FOR
────────────────────
Every alarm here names something a person can go and do. A collector that is
capturing but not delivering needs a link looked at; one whose queue is growing
needs that link looked at *sooner*, before the spool wraps and observations are
lost for good; one that is silent needs somebody at the cabinet. An alarm that
does not distinguish those is a page at 3am that begins with an hour of
guessing.
"""
# NOTE: no `from __future__ import annotations` — imported by api.py's route
# factory, where postponed evaluation breaks FastAPI's annotation resolution.

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: How often a collector is expected to announce itself. The transport sends a
#: heartbeat alongside its delivery cycle; this is the interval the server
#: measures silence against.
HEARTBEAT_INTERVAL_SECONDS = 300

#: Missed twice: a lost packet, a busy link, a restart. Worth showing, not worth
#: waking anybody.
LATE_AFTER = 2 * HEARTBEAT_INTERVAL_SECONDS

#: Missed six times. Half an hour of nothing from a device whose entire job is
#: to report continuously. It is not coming back on its own.
SILENT_AFTER = 6 * HEARTBEAT_INTERVAL_SECONDS

#: A spool this deep means the collector is capturing faster than it can deliver.
#: The observations are not lost yet — that is the point of alarming here rather
#: than after the spool wraps.
QUEUE_WARNING = 500
QUEUE_CRITICAL = 5000

REPORTING = "reporting"
LATE = "late"
SILENT = "silent"
NEVER_REPORTED = "never_reported"
DISABLED = "disabled"


@dataclass
class Alarm:
    """Something a person can go and do."""

    collector_id: str
    kind: str
    severity: str            # info | warning | critical
    detail: str
    action: str


@dataclass
class CollectorHealth:
    collector_id: str
    site: str
    state: str
    seconds_since_heartbeat: Optional[float]
    capture_state: str
    queue_depth: int
    alarms: List[Alarm] = field(default_factory=list)

    @property
    def coverage_believable(self) -> bool:
        return coverage_is_believable(self.state)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collector_id": self.collector_id,
            "site": self.site,
            "state": self.state,
            "seconds_since_heartbeat": (
                None if self.seconds_since_heartbeat is None
                else round(self.seconds_since_heartbeat)),
            "capture_state": self.capture_state,
            "queue_depth": self.queue_depth,
            "coverage_believable": self.coverage_believable,
            "alarms": [{"kind": a.kind, "severity": a.severity,
                        "detail": a.detail, "action": a.action}
                       for a in self.alarms],
        }


def coverage_is_believable(state: str) -> bool:
    """Whether this collector's STORED coverage may be counted.

    A silent collector's fifty complete windows describe last Tuesday. Counting
    them is how a switched-off sensor reports a clean plant, so the answer is no
    — and a collector that has never reported has nothing to believe either way.
    """
    return state in (REPORTING, LATE)


@dataclass
class FleetHealth:
    collectors: List[CollectorHealth] = field(default_factory=list)

    @property
    def alarms(self) -> List[Alarm]:
        return [alarm for c in self.collectors for alarm in c.alarms]

    @property
    def silent(self) -> List[str]:
        return [c.collector_id for c in self.collectors if c.state == SILENT]

    @property
    def never_reported(self) -> List[str]:
        return [c.collector_id for c in self.collectors
                if c.state == NEVER_REPORTED]

    @property
    def unbelievable(self) -> List[str]:
        """Collectors whose stored coverage must not be counted."""
        return [c.collector_id for c in self.collectors
                if not c.coverage_believable and c.state != DISABLED]

    @property
    def healthy(self) -> bool:
        return not self.alarms

    def explain(self) -> str:
        if not self.collectors:
            return "no collectors are enrolled"
        if self.healthy:
            return ("%d collector(s), all reporting"
                    % len(self.collectors))

        critical = [a for a in self.alarms if a.severity == "critical"]
        parts = []
        if self.silent:
            parts.append("%d silent (%s)"
                         % (len(self.silent), ", ".join(self.silent)))
        if self.never_reported:
            parts.append("%d never reported (%s)"
                         % (len(self.never_reported),
                            ", ".join(self.never_reported)))
        other = [a for a in self.alarms
                 if a.kind not in ("silent", "never_reported")]
        if other:
            parts.append("%d other alarm(s)" % len(other))
        return ("%d collector(s): %s%s"
                % (len(self.collectors), "; ".join(parts),
                   " — a silent collector's stored coverage still reads as "
                   "complete, so it is not counted" if critical else ""))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collectors": [c.to_dict() for c in self.collectors],
            "alarms": [{"collector_id": a.collector_id, "kind": a.kind,
                        "severity": a.severity, "detail": a.detail,
                        "action": a.action} for a in self.alarms],
            "silent": self.silent,
            "never_reported": self.never_reported,
            "coverage_not_believable": self.unbelievable,
            "healthy": self.healthy,
            "explain": self.explain(),
        }


def _age(last_heartbeat, now: datetime.datetime) -> Optional[float]:
    if last_heartbeat is None:
        return None
    if isinstance(last_heartbeat, (int, float)):
        return max(0.0, now.timestamp() - float(last_heartbeat))
    if last_heartbeat.tzinfo is None:
        last_heartbeat = last_heartbeat.replace(tzinfo=datetime.timezone.utc)
    return max(0.0, (now - last_heartbeat).total_seconds())


def assess_collector(row: Dict[str, Any],
                     now: Optional[datetime.datetime] = None,
                     content_behind_by: int = 0) -> CollectorHealth:
    """One collector's state and whatever a person should do about it."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    collector_id = str(row.get("collector_id") or "")
    age = _age(row.get("last_heartbeat"), now)
    queue = int(row.get("queue_depth") or 0)
    capture = str(row.get("capture_state") or "unknown")
    enabled = row.get("enabled", True)

    if not enabled:
        state = DISABLED
    elif age is None:
        state = NEVER_REPORTED
    elif age >= SILENT_AFTER:
        state = SILENT
    elif age >= LATE_AFTER:
        state = LATE
    else:
        state = REPORTING

    health = CollectorHealth(
        collector_id=collector_id, site=str(row.get("site") or ""),
        state=state, seconds_since_heartbeat=age, capture_state=capture,
        queue_depth=queue)

    if state == DISABLED:
        # Deliberately no alarms. A collector somebody switched off is not a
        # fault, and alarming on it is how an operator learns to dismiss the
        # list without reading it.
        return health

    if state == SILENT:
        health.alarms.append(Alarm(
            collector_id, "silent", "critical",
            "nothing heard for %d minutes; its stored windows still read as "
            "complete and are no longer counted" % (age // 60),
            "check the collector and its link to the server — this site is not "
            "being monitored and nothing in its own output says so"))
    elif state == LATE:
        health.alarms.append(Alarm(
            collector_id, "late", "warning",
            "no heartbeat for %d minutes" % (age // 60),
            "usually a restart or a busy link; worth watching rather than "
            "acting on"))
    elif state == NEVER_REPORTED:
        health.alarms.append(Alarm(
            collector_id, "never_reported", "warning",
            "enrolled but has never announced itself",
            "confirm the collector was actually started after enrolment"))

    if state in (REPORTING, LATE):
        if capture == "unknown":
            health.alarms.append(Alarm(
                collector_id, "capture_unmeasurable", "critical",
                "the collector cannot read its own drop counters",
                "a window whose loss cannot be measured supports no clean "
                "result; check the capture interface and its driver"))
        elif capture == "degraded":
            health.alarms.append(Alarm(
                collector_id, "capture_degraded", "warning",
                "frames are being dropped at capture",
                "resize the ring buffer or move the sensor; every count from "
                "this site is a floor rather than a total"))

        if queue >= QUEUE_CRITICAL:
            health.alarms.append(Alarm(
                collector_id, "queue_critical", "critical",
                "%d batches waiting to deliver" % queue,
                "the collector is capturing faster than it can deliver; fix "
                "the link before the spool wraps and observations are lost "
                "for good"))
        elif queue >= QUEUE_WARNING:
            health.alarms.append(Alarm(
                collector_id, "queue_growing", "warning",
                "%d batches waiting to deliver" % queue,
                "delivery is falling behind capture; check the link"))

    if content_behind_by > 0 and state in (REPORTING, LATE):
        health.alarms.append(Alarm(
            collector_id, "content_behind", "warning",
            "running detection content %d version(s) behind"
            % content_behind_by,
            "this collector will not report what the newer pack would have "
            "found, and nothing in its own output says so"))

    return health


def assess(rows: List[Dict[str, Any]],
           now: Optional[datetime.datetime] = None,
           behind: Optional[Dict[str, int]] = None) -> FleetHealth:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    behind = behind or {}
    return FleetHealth(collectors=[
        assess_collector(row, now,
                         content_behind_by=int(behind.get(
                             str(row.get("collector_id") or ""), 0)))
        for row in sorted(rows, key=lambda r: str(r.get("collector_id") or ""))
    ])
