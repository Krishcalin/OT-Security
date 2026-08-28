"""
Phase 5 — the console (OTS-CON-001..006).

The interesting requirement is OTS-CON-004: every screen presenting counts or
clean states must display the coverage those numbers rest on, and a degraded
window must be visibly marked rather than footnoted.

A rule like that, enforced by review, survives about three sprints. Someone adds
a summary tile in a hurry, the number renders alone, and it looks exactly like
every other number on the page — the failure the collector, the spool and the
estate merge have all been built to prevent, arriving at the last step where a
person actually reads it.

So it is enforced by the TYPE CHECKER, and this file is what proves the
enforcement still bites. `src/con004.expect-errors.ts` contains code that MUST
NOT compile; if it ever does, OTS-CON-004 has quietly become a convention again.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONSOLE = os.path.join(_ROOT, "console")
SRC = os.path.join(CONSOLE, "src")

pytestmark = pytest.mark.skipif(
    not os.path.isdir(os.path.join(CONSOLE, "node_modules")),
    reason="console dependencies not installed (npm install in console/)")


def _tsc(*args, cwd=CONSOLE):
    npx = shutil.which("npx") or shutil.which("npx.cmd")
    if npx is None:
        pytest.skip("npx not on PATH")
    return subprocess.run([npx, "tsc", *args], cwd=cwd, capture_output=True,
                          text=True, timeout=600)


# ── the console builds ─────────────────────────────────────────────────────

def test_the_console_type_checks():
    proc = _tsc("--noEmit")
    assert proc.returncode == 0, proc.stdout[-2000:]


def test_strictness_is_actually_on():
    """noUncheckedIndexedAccess caught a real bug here — a lookup returning
    undefined would have written the literal text "undefined" into the page. The
    settings are load-bearing, not decorative."""
    import json

    with open(os.path.join(CONSOLE, "tsconfig.json"), encoding="utf-8") as fh:
        cfg = json.load(fh)
    options = cfg["compilerOptions"]
    for flag in ("strict", "noUncheckedIndexedAccess",
                 "exactOptionalPropertyTypes"):
        assert options.get(flag) is True, "%s is off" % flag


# ── OTS-CON-004 is structural ──────────────────────────────────────────────

def test_every_expected_error_actually_errors():
    """The proof. Each EXPECT-ERROR line must produce a compiler error, and the
    counts must match — a file that fails for one reason while three other
    violations slipped through would still pass a naive check."""
    path = os.path.join(SRC, "con004.expect-errors.ts")
    with open(path, encoding="utf-8") as fh:
        expected = len(re.findall(r"^// EXPECT-ERROR", fh.read(), re.M))
    assert expected >= 4, "the harness lost its cases"

    proc = _tsc("--noEmit", "--strict", "--target", "ES2022",
                "--module", "ES2022", "--moduleResolution", "bundler",
                "--lib", "ES2022,DOM", "src/con004.expect-errors.ts")
    assert proc.returncode != 0, (
        "code that must not compile now compiles — OTS-CON-004 has stopped "
        "being structural and is a convention again")
    errors = len(re.findall(r"error TS", proc.stdout))
    assert errors == expected, (
        "expected %d compiler errors, got %d:\n%s"
        % (expected, errors, proc.stdout[-1500:]))


def test_the_harness_is_excluded_from_the_real_build():
    """Otherwise the console could never build."""
    import json

    with open(os.path.join(CONSOLE, "tsconfig.json"), encoding="utf-8") as fh:
        cfg = json.load(fh)
    assert any("expect-errors" in pattern for pattern in cfg.get("exclude", []))


# ── the rendering rules, read from source ──────────────────────────────────

def _read(name):
    with open(os.path.join(SRC, name), encoding="utf-8") as fh:
        return fh.read()


def test_nothing_renders_a_bare_number():
    """`metric` is the only headline-number path and it takes Measured<number>.
    An overload accepting a plain number would reopen the hole."""
    src = _read("render.ts")
    assert "m: Measured<number>" in src
    assert "value: number)" not in src


def test_unknown_coverage_is_an_alarm_not_a_neutral_grey():
    """'We could not tell' is the state most likely to be mistaken for 'fine'.
    Rendering it quietly restores the ambiguity the three-state model removes."""
    src = _read("coverage.ts")
    assert 'tone: "alarm"' in src
    unknown = src[src.index('case "unknown"'):]
    assert '"alarm"' in unknown[:400]


def test_a_zero_is_qualified_when_coverage_is_not_complete():
    """'0 findings' and 'no findings were observable' are different claims, and
    on a substation network the difference is the whole product."""
    src = _read("coverage.ts")
    assert "not evidence of absence" in src


def test_a_measured_value_cannot_be_built_without_a_basis():
    """A blank basis satisfies the type and defeats the point: the operator sees
    a coverage badge with nothing behind it."""
    src = _read("coverage.ts")
    assert "needs a basis" in src


def test_combining_measured_values_takes_the_weakest_coverage():
    """There is deliberately no way to combine and keep the better coverage."""
    src = _read("coverage.ts")
    assert "weakest(parts.map" in src


def test_a_fail_closed_api_is_surfaced_not_rendered_as_empty():
    """A 503 from the fail-closed estate plane must not become an empty, clean
    looking estate."""
    src = _read("api.ts")
    assert "503" in src and "fail-closed" in src


def test_an_unassessed_estate_is_unknown_not_zero_actionable():
    """With no corpus loaded, 'actionable: 0' would be a confident claim built
    on no assessment at all."""
    src = _read("api.ts")
    assert "has established nothing" in src or "nothing has been assessed" in src


def test_an_absent_asset_renders_as_a_state_not_a_deletion():
    src = _read("render.ts")
    assert "not observed" in src
    assert "did not speak" in src


def test_engine_limitations_are_rendered_not_hidden():
    """OTS-SRV-003 results carry what they could not consider; the console must
    show it rather than collapsing everything to a status chip."""
    src = _read("render.ts")
    assert "limitations" in src and "limits" in src
