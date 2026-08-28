"""
Severity corrected for position (D12), and the asymmetry it turns on.

The load-bearing test is `test_a_lowering_is_withheld_when_the_window_cannot
_carry_it`.

The reason to lower a priority is that no path into the device was observed from
outside its zone. On a degraded or unmeasurable window, not observing a path is
not evidence that none exists — it is the sentence this whole system is built
on, arriving at prioritisation. Lowering there would quietly de-escalate a
genuinely exposed relay because a collector dropped frames, which is the worst
direction for this system to be wrong in.

Raising is different and deliberately cheaper: being wrong upward costs an
operator attention, being wrong downward costs them the finding.
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ot_server import severity                              # noqa: E402


def _hit(cve="CVE-2019-13945", priority="now"):
    return {"cve": cve, "priority": priority}


def _position(**kwargs):
    defaults = dict(zone_id="zone_a", purdue_level=1, zone_basis="role",
                    reached_across_zone=False, observed_sources=2,
                    coverage="complete")
    defaults.update(kwargs)
    return severity.Position(**defaults)


# ── the asymmetry ──────────────────────────────────────────────────────────

def test_a_lowering_needs_a_complete_window():
    """Known-exploited, but nothing outside its zone was seen reaching it, and
    the window was fully measured. That is an observation."""
    result = severity.correct(_hit(priority="now"),
                              _position(coverage="complete"))
    assert result.state == severity.APPLIED
    assert result.direction == "lowered"
    assert result.corrected == "next"
    assert any("complete over the observed window" in b for b in result.basis)


@pytest.mark.parametrize("coverage", ["degraded", "unknown"])
def test_a_lowering_is_withheld_when_the_window_cannot_carry_it(coverage):
    """THE test. Not seeing a path is not evidence there is none — and lowering
    on that basis de-escalates a genuinely exposed relay because a collector
    dropped frames."""
    result = severity.correct(_hit(priority="now"),
                              _position(coverage=coverage))
    assert result.state == severity.WITHHELD
    assert result.corrected == "now", "the priority moved anyway"
    assert "not evidence there is none" in result.reason
    assert coverage in result.reason


def test_a_withheld_lowering_still_shows_its_working():
    """Withheld visibly, not silently not applied. An operator should be able
    to see that a correction was available and why it was not taken."""
    result = severity.correct(_hit(priority="now"),
                              _position(coverage="degraded"))
    assert result.basis, "the withheld justification was discarded"
    assert "would have been lowered" in result.reason


@pytest.mark.parametrize("coverage", ["complete", "degraded", "unknown"])
def test_raising_does_not_wait_for_perfect_coverage(coverage):
    """Being wrong upward costs attention; being wrong downward costs the
    finding. The evidence bar is deliberately lower."""
    result = severity.correct(
        _hit(priority="next"),
        _position(reached_across_zone=True, purdue_level=1, coverage=coverage))
    assert result.state == severity.APPLIED
    assert result.direction == "raised"
    assert result.corrected == "now"


# ── what raises ────────────────────────────────────────────────────────────

def test_a_path_alone_does_not_raise_a_supervisory_device():
    """Reached across a boundary, but at Purdue 3 a failure is informational
    rather than physical."""
    result = severity.correct(
        _hit(priority="next"),
        _position(reached_across_zone=True, purdue_level=3))
    assert result.state == severity.UNCHANGED
    assert result.corrected == "next"


def test_a_process_facing_device_alone_does_not_raise_without_a_path():
    result = severity.correct(
        _hit(priority="next"),
        _position(reached_across_zone=False, purdue_level=0))
    assert result.direction != "raised"


# ── the refusals and the limits ────────────────────────────────────────────

def test_a_guessed_zone_gets_no_correction():
    """A severity corrected for a position we guessed is a number with a false
    provenance."""
    result = severity.correct(_hit(priority="now"),
                              _position(zone_basis="defaulted"))
    assert result.state == severity.REFUSED
    assert result.corrected == result.original
    assert "false provenance" in result.reason


def test_nothing_observed_reaching_it_moves_nothing():
    """No evidence in either direction — a gap in the monitoring, not a reason
    to move the priority."""
    result = severity.correct(_hit(priority="now"),
                              _position(observed_sources=0))
    assert result.state == severity.UNCHANGED
    assert "gap in the monitoring" in result.reason


@pytest.mark.parametrize("priority", ["never", "unknown"])
def test_a_matching_judgement_is_not_a_positional_one(priority):
    """`never` means the CVE does not apply to the observed firmware. Exposure
    has nothing to say about that."""
    result = severity.correct(_hit(priority=priority),
                              _position(reached_across_zone=True))
    assert result.state == severity.UNCHANGED
    assert result.corrected == priority


def test_nothing_is_ever_lowered_to_never():
    """The most a correction may do downward is NOW to NEXT."""
    for coverage in ("complete", "degraded", "unknown"):
        for priority in ("now", "next"):
            result = severity.correct(
                _hit(priority=priority),
                _position(coverage=coverage, reached_across_zone=False))
            assert result.corrected != "never"


def test_no_correction_invents_a_score():
    """It adjusts the band an operator acts on. There is no recomputed CVSS
    vector here, because this system has no basis for one."""
    result = severity.correct(_hit(priority="now"), _position())
    assert not hasattr(result, "cvss")
    assert result.corrected in ("now", "next", "never", "unknown")


# ── assembling a position from the estate ──────────────────────────────────

class _Zone:
    zone_id = "zone_a"
    purdue_level = 1


def test_a_position_is_assembled_from_what_the_estate_already_computed():
    position = severity.position_from(
        {"coverage": "degraded"}, _Zone(), "role",
        [{"src_ip": "10.0.0.60", "crosses_zone": False},
         {"src_ip": "10.1.0.5", "crosses_zone": True}])
    assert position.zone_id == "zone_a" and position.purdue_level == 1
    assert position.reached_across_zone is True
    assert position.observed_sources == 2
    assert position.coverage == "degraded"


# ── the summary ────────────────────────────────────────────────────────────

def test_the_summary_keeps_withheld_apart_from_unchanged():
    """"We could have lowered this and would not" is a different statement from
    "position changed nothing", and an operator reading a total needs them
    apart."""
    corrections = [
        severity.correct(_hit(priority="now"), _position(coverage="degraded")),
        severity.correct(_hit(priority="now"), _position(coverage="complete")),
        severity.correct(_hit(priority="next"),
                         _position(reached_across_zone=True, purdue_level=1)),
        severity.correct(_hit(priority="now"),
                         _position(zone_basis="defaulted")),
    ]
    summary = severity.summarise(corrections)
    assert summary == {
        "raised": 1, "lowered": 1, "withheld": 1, "refused": 1,
        "explain": summary["explain"],
    }
    assert "WITHHELD" in summary["explain"]
    assert "would not carry the claim" in summary["explain"]


def test_nothing_matched_says_so():
    assert "nothing to correct" in severity.summarise([])["explain"]
