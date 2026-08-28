"""
Ingest decisions (OTS-TRN-004, OTS-SRV-004, OTS-SRV-005).

Pure functions over a submitted payload: what is valid, what is a duplicate,
what a record means for the stored state. No database, no framework — so the
rules that decide what the server believes are testable anywhere, and the SQL
layer stays thin enough to read.

WHAT THE SERVER MUST NOT DO WITH A GAP
──────────────────────────────────────
A collector that loses observations during an outage reports the interval
explicitly. The server's job is to keep that visible. Accepting a
`delivery_gap` and then rendering the asset timeline as continuous would
discard the collector's honesty at the last step and make every safeguard
upstream decorative.

So a gap is stored as a first-class record, and coverage is computed from what
was actually received rather than from what is present.

ABSENCE IS NOT DELETION
───────────────────────
An asset that stops appearing has not necessarily gone. A passive sensor cannot
distinguish a decommissioned device from one that did not speak during the
window, so `OTS-SRV-005` says an absent asset is marked NOT OBSERVED and kept.
Deleting on absence would make a quiet PLC disappear from the inventory, which
is the inverse of what an OT operator needs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

MAX_RECORDS_PER_BATCH = 50000
VALID_COVERAGE = ("complete", "degraded", "unknown")
VALID_KINDS = ("asset", "flow", "detection", "event")


class Verdict(str, Enum):
    ACCEPT = "accept"
    DUPLICATE = "duplicate"
    REJECT = "reject"


class AssetState(str, Enum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"


@dataclass
class Decision:
    verdict: Verdict
    reason: str = ""
    batch_id: str = ""
    collector_id: str = ""
    window_id: str = ""
    coverage: str = "unknown"
    records: List[Dict] = field(default_factory=list)
    gap: Optional[Dict] = None

    @property
    def ok(self) -> bool:
        return self.verdict in (Verdict.ACCEPT, Verdict.DUPLICATE)

    @property
    def http_status(self) -> int:
        return {Verdict.ACCEPT: 202, Verdict.DUPLICATE: 409,
                Verdict.REJECT: 400}[self.verdict]


def validate(payload: Dict[str, Any]) -> Optional[str]:
    """Why this payload is unacceptable, or None.

    Rejection is loud and specific. A server that quietly accepts a malformed
    batch and stores part of it produces an inventory nobody can account for,
    and the collector — which believes it delivered — will never resend.
    """
    if not isinstance(payload, dict):
        return "payload is not an object"

    if "gap" in payload:
        gap = payload.get("gap")
        if not isinstance(gap, dict):
            return "gap is not an object"
        if not payload.get("collector_id") and not gap.get("collector_id"):
            return "gap without a collector_id cannot be attributed"
        return None

    for field_name in ("batch_id", "collector_id", "window_id"):
        if not payload.get(field_name):
            return "missing %s" % field_name

    coverage = payload.get("coverage", "unknown")
    if coverage not in VALID_COVERAGE:
        # An unrecognised coverage value must not be coerced to "complete" or
        # silently normalised: the whole point of the field is that its three
        # states mean different things.
        return "unknown coverage value %r" % (coverage,)

    records = payload.get("records")
    if records is None or not isinstance(records, list):
        return "records must be a list"
    if len(records) > MAX_RECORDS_PER_BATCH:
        return "batch exceeds %d records" % MAX_RECORDS_PER_BATCH

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            return "record %d is not an object" % index
        if not record.get("key"):
            return "record %d has no key" % index
        if record.get("kind") not in VALID_KINDS:
            return "record %d has unknown kind %r" % (index, record.get("kind"))
    return None


def decide(payload: Dict[str, Any], known_batch_ids) -> Decision:
    """Accept, recognise as a replay, or reject.

    `known_batch_ids` is anything supporting `in` — the store's uniqueness
    check. The duplicate answer is deliberately a SUCCESS for the collector
    (`OTS-TRN-004`): a retry whose first acknowledgement was lost must be able
    to clear its queue, or it will resend forever.
    """
    problem = validate(payload)
    if problem is not None:
        return Decision(Verdict.REJECT, reason=problem)

    if "gap" in payload:
        gap = dict(payload["gap"])
        collector = payload.get("collector_id") or gap.get("collector_id")
        return Decision(Verdict.ACCEPT, reason="delivery gap recorded",
                        collector_id=collector, gap=gap)

    batch_id = payload["batch_id"]
    if batch_id in known_batch_ids:
        return Decision(Verdict.DUPLICATE, reason="batch already ingested",
                        batch_id=batch_id,
                        collector_id=payload["collector_id"],
                        window_id=payload["window_id"])

    return Decision(
        Verdict.ACCEPT, reason="accepted", batch_id=batch_id,
        collector_id=payload["collector_id"], window_id=payload["window_id"],
        coverage=payload.get("coverage", "unknown"),
        records=list(payload.get("records") or []))


def split_records(records: List[Dict]) -> Dict[str, List[Dict]]:
    """Group by kind, so the store writes each to its own table."""
    out: Dict[str, List[Dict]] = {kind: [] for kind in VALID_KINDS}
    for record in records:
        out.setdefault(record.get("kind", "event"), []).append(record)
    return out


# ── coverage, computed from what arrived ───────────────────────────────────

@dataclass
class CoverageSummary:
    """What a collector's recent history actually supports.

    `OTS-SRV-004`. Deliberately reports the three window states separately
    rather than a single percentage: a run of unknown windows and a run of
    complete ones are not two points on one scale, and averaging them produces
    a number that means nothing.
    """

    collector_id: str = ""
    windows: int = 0
    complete: int = 0
    degraded: int = 0
    unknown: int = 0
    gaps: int = 0
    records_lost: int = 0

    @property
    def trustworthy(self) -> bool:
        """True only when every window was measured clean and nothing was lost.

        Anything else means a finding of "no issues" from this collector is not
        the same as "no issues exist".
        """
        return (self.windows > 0 and self.complete == self.windows
                and self.gaps == 0)

    def explain(self) -> str:
        if self.windows == 0:
            return ("no windows received from %s — nothing from this collector "
                    "may be reported as clean" % self.collector_id)
        if self.trustworthy:
            return "%d window(s), all complete, no delivery gaps" % self.windows
        parts = []
        if self.degraded:
            parts.append("%d degraded" % self.degraded)
        if self.unknown:
            parts.append("%d unmeasurable" % self.unknown)
        if self.gaps:
            parts.append("%d delivery gap(s), %d record(s) never arrived"
                         % (self.gaps, self.records_lost))
        return ("%d window(s): %s — results from this collector are incomplete"
                % (self.windows, ", ".join(parts)))


def summarise_coverage(collector_id: str, windows: List[Dict],
                       gaps: List[Dict]) -> CoverageSummary:
    summary = CoverageSummary(collector_id=collector_id, windows=len(windows))
    for window in windows:
        state = window.get("coverage", "unknown")
        if state == "complete":
            summary.complete += 1
        elif state == "degraded":
            summary.degraded += 1
        else:
            summary.unknown += 1
    summary.gaps = len(gaps)
    summary.records_lost = sum(int(g.get("records_lost") or 0) for g in gaps)
    return summary


def asset_state(last_observed_window: str, latest_window: str) -> AssetState:
    """OTS-SRV-005. Absent from the latest window means NOT OBSERVED, not gone.

    A passive sensor cannot distinguish a decommissioned device from one that
    did not speak. Deleting on absence would make a quiet PLC vanish from the
    inventory — the inverse of what an operator needs, and unrecoverable once
    done.
    """
    if not latest_window or last_observed_window == latest_window:
        return AssetState.OBSERVED
    return AssetState.NOT_OBSERVED
