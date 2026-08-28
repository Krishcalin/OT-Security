"""
Severity corrected for where the device actually sits (Dragos ledger #2).

A CVSS score is a property of the vulnerability. What an operator needs is the
property of the vulnerability ON THIS DEVICE, IN THIS PLANT — a critical remote
code execution on a relay that nothing outside its zone has ever reached is a
different problem from the same CVE on a historian that half the site talks to.

Dragos publishes "xOT-corrected CVSS" from their own researchers, and asks you
to trust them. That is a reasonable thing for them to sell and not a reasonable
thing to copy: nobody has a reason to trust a correction from this codebase.
So the correction is made INSPECTABLE instead — every adjustment names the
observations that moved it, in the same idiom a zone's Purdue level names its
basis, and a correction resting on a guessed boundary is refused outright.

THE ASYMMETRY THIS IS BUILT AROUND
──────────────────────────────────
Lowering urgency and raising it are not the same act and must not need the same
evidence.

**Lowering requires complete coverage.** The reason to lower is that no path
into this device was observed from outside its zone — and on a degraded or
unmeasurable window, not observing a path is not evidence that none exists. It
is the same sentence the whole system is built on, applied to prioritisation:
absence of a finding is not evidence of absence. Lowering on that basis would
quietly de-escalate a genuinely exposed relay because the collector dropped
frames, which is the worst direction for this system to be wrong in.

**Raising does not.** Being wrong upward costs an operator attention; being
wrong downward costs them the finding. So a correction that raises urgency is
made on the evidence available, and one that would lower it is WITHHELD when the
coverage behind it will not carry the claim — withheld visibly, with the reason,
rather than silently not applied.

WHAT IT WILL NOT DO
───────────────────
It will not invent a number. There is no recomputed CVSS vector here, because
this system has no basis for one — it adjusts the priority BAND, which is the
thing an operator acts on, and shows its working.

It will not lower anything to NEVER. `never` means the finding does not apply to
the observed firmware, which is a matching judgement; exposure has nothing to
say about it. The most a correction can do downward is NOW to NEXT.

It will not raise a NEVER. Same reason, from the other side.
"""
# NOTE: no `from __future__ import annotations` — imported by api.py's route
# factory, where postponed evaluation breaks FastAPI's annotation resolution.

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

APPLIED = "applied"
#: The zone this device sits in was mostly guessed. No correction is offered.
REFUSED = "refused"
#: A lowering was justified by the observations and not by the coverage.
WITHHELD = "withheld"
#: Nothing about this device's position changes the priority.
UNCHANGED = "unchanged"

NOW = "now"
NEXT = "next"
NEVER = "never"
UNKNOWN = "unknown"

#: Purdue levels at or below this are process-facing: a failure has physical
#: consequence rather than an informational one.
PROCESS_FACING = 1


@dataclass
class Correction:
    cve: str
    original: str
    corrected: str
    state: str = UNCHANGED
    direction: str = UNCHANGED
    #: The observations that moved it, each a sentence an operator can check.
    basis: List[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"cve": self.cve, "original": self.original,
                "corrected": self.corrected, "state": self.state,
                "direction": self.direction, "basis": list(self.basis),
                "reason": self.reason}


@dataclass
class Position:
    """Where a device sits, and what has been observed reaching it.

    Assembled by the caller from the zone derivation and the observed flows —
    the same two inputs containment uses, because they are the same question
    asked twice: what could reach this, and what would it take to stop it.
    """

    zone_id: str = ""
    purdue_level: int = -1
    zone_basis: str = "unknown"
    #: Whether anything outside this device's zone was observed reaching it.
    reached_across_zone: bool = False
    #: Sources observed reaching it at all. Empty means nothing was seen.
    observed_sources: int = 0
    #: The coverage of the window those observations came from.
    coverage: str = UNKNOWN


def correct(hit: Dict[str, Any], position: Position) -> Correction:
    """One CVE's priority, corrected for one device's position."""
    cve = str(hit.get("cve") or "")
    original = str(hit.get("priority") or UNKNOWN)
    result = Correction(cve=cve, original=original, corrected=original)

    if position.zone_basis == "defaulted":
        result.state = REFUSED
        result.reason = (
            "this device's Purdue level came from the topology engine's "
            "fallback rather than an observed role or protocol. A severity "
            "corrected for a position we guessed is a number with a false "
            "provenance, so the raw priority stands.")
        return result

    if original in (NEVER, UNKNOWN):
        result.state = UNCHANGED
        result.reason = (
            "%r is a judgement about whether this CVE applies at all, which is "
            "a matching question rather than a positional one" % original)
        return result

    if position.observed_sources == 0:
        result.state = UNCHANGED
        result.reason = (
            "nothing has been observed reaching this device, so there is no "
            "evidence about its exposure in either direction — which is a gap "
            "in the monitoring, not a reason to move the priority")
        return result

    # ── raising ──────────────────────────────────────────────────────────
    if (original == NEXT and position.reached_across_zone
            and 0 <= position.purdue_level <= PROCESS_FACING):
        result.corrected = NOW
        result.state = APPLIED
        result.direction = "raised"
        result.basis = [
            "reached from outside its own zone, so the path does not require a "
            "foothold in this zone first",
            "sits at Purdue level %d, where a failure has physical consequence "
            "rather than an informational one" % position.purdue_level,
        ]
        result.reason = ("raised because the path exists and the consequence is "
                         "physical")
        return result

    # ── lowering, which needs the coverage to carry it ───────────────────
    if original == NOW and not position.reached_across_zone:
        justification = [
            "nothing outside this device's zone was observed reaching it, so "
            "an attacker needs a foothold inside zone %s first"
            % (position.zone_id or "this one"),
        ]
        if position.coverage != "complete":
            # The sentence the whole system is built on, applied to
            # prioritisation. Lowering here would de-escalate a genuinely
            # exposed relay because a collector dropped frames.
            result.state = WITHHELD
            result.basis = justification
            result.reason = (
                "this would have been lowered to NEXT — nothing outside its "
                "zone was seen reaching it — but that observation came from a "
                "%s window. Not seeing a path is not evidence there is none, "
                "so the priority stands at NOW." % position.coverage)
            return result

        result.corrected = NEXT
        result.state = APPLIED
        result.direction = "lowered"
        result.basis = justification + [
            "capture was complete over the observed window, so the absence of "
            "a cross-zone path is an observation rather than a gap",
        ]
        result.reason = ("lowered to NEXT: known-exploited, but no path into it "
                         "from outside its zone was observed over a fully "
                         "measured window")
        return result

    result.state = UNCHANGED
    result.reason = "this device's position does not change the priority"
    return result


def position_from(asset: Dict[str, Any], zone, zone_basis: str,
                  inbound: List[Dict[str, Any]]) -> Position:
    """Assemble a `Position` from what the estate already computed."""
    return Position(
        zone_id=str(getattr(zone, "zone_id", "") or ""),
        purdue_level=int(getattr(zone, "purdue_level", -1) or -1),
        zone_basis=zone_basis or "unknown",
        reached_across_zone=any(bool(f.get("crosses_zone")) for f in inbound),
        observed_sources=len(inbound),
        coverage=str(asset.get("coverage") or UNKNOWN))


def summarise(corrections: List[Correction]) -> Dict[str, Any]:
    raised = [c for c in corrections if c.direction == "raised"]
    lowered = [c for c in corrections if c.direction == "lowered"]
    withheld = [c for c in corrections if c.state == WITHHELD]
    refused = [c for c in corrections if c.state == REFUSED]
    return {
        "raised": len(raised),
        "lowered": len(lowered),
        "withheld": len(withheld),
        "refused": len(refused),
        "explain": _explain(len(corrections), len(raised), len(lowered),
                            len(withheld), len(refused)),
    }


def _explain(total: int, raised: int, lowered: int, withheld: int,
             refused: int) -> str:
    if not total:
        return "nothing has matched, so there is nothing to correct"
    parts = []
    if raised:
        parts.append("%d raised on an observed path to a process-facing device"
                     % raised)
    if lowered:
        parts.append("%d lowered because no path from outside the zone was "
                     "observed over a complete window" % lowered)
    if withheld:
        parts.append("%d lowering(s) WITHHELD because the window behind them "
                     "would not carry the claim" % withheld)
    if refused:
        parts.append("%d refused because the device's zone was mostly guessed"
                     % refused)
    if not parts:
        return ("%d finding(s): none of them moved — position changed nothing"
                % total)
    return "%d finding(s): %s" % (total, "; ".join(parts))
