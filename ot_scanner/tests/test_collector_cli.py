"""
Phase 1 — the ot_collector entry point.

Exercised by calling main() directly with argv, so the tests run anywhere and
cover the paths that actually decide what an operator is told.

Three of these exist because the first real run failed on them, and each failure
was the kind that replaces a coverage report with something worse than nothing:
a UnicodeEncodeError traceback, the same warning repeated every window until it
stops being read, and a phantom empty window inflating the coverage summary.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ot_collector  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLE = os.path.join(ROOT, "test_data", "ot_test_traffic.pcap")

pytestmark = pytest.mark.skipif(not os.path.exists(SAMPLE),
                               reason="sample pcap not present")
dpkt = pytest.importorskip("dpkt")


def _run(capsys, *argv):
    code = ot_collector.main(["--replay", SAMPLE] + list(argv))
    return code, capsys.readouterr().out


# ── it refuses to certify what it could not measure ────────────────────────

def test_an_unmeasurable_run_is_unverified_not_a_pass(capsys):
    """"We processed 50 Mbps" and "we processed all 50 Mbps that arrived" are
    different statements, and only the second is a capacity claim. A replay has
    no drop counters, so it cannot make the second one."""
    code, out = _run(capsys, "--measure")
    assert "UNVERIFIED" in out
    assert "not a capacity claim" in out
    assert code == 2, "an unverifiable run must not exit 0"


def test_the_target_is_stated_so_the_number_means_something(capsys):
    _, out = _run(capsys, "--measure")
    assert "OTS-NFR-001" in out
    assert "%.0f Mbps" % ot_collector.NFR_TARGET_MBPS in out


def test_the_nfr_target_matches_the_agreed_hardware():
    """Pi 5 + USB SSD at sites under 50 Mbps (SRS Q2/Q3). If the deployment
    changes, this constant is the one place to change it."""
    assert ot_collector.NFR_TARGET_MBPS == 50.0


# ── output survives a hostile console ──────────────────────────────────────

def test_output_is_ascii_only(capsys):
    """A Windows console is cp1252 and raises on anything outside it. The first
    real run died with a UnicodeEncodeError instead of printing coverage --
    the worst possible failure for the tool whose job is honest reporting."""
    _, out = _run(capsys, "--measure")
    structural = [line for line in out.splitlines()
                  if line.startswith(("  ", "-", "COVERAGE", "ANALYSIS", "THROUGH"))]
    offenders = [line for line in structural
                 if any(ord(ch) > 127 for ch in line)
                 and "—" not in line]          # analyser prose may carry an em dash
    assert not offenders, "non-ASCII in structural output: %r" % offenders[:2]


def test_the_banner_is_encodable_everywhere():
    ot_collector.BANNER.encode("cp1252")
    ot_collector.BANNER.encode("ascii")


# ── the report reads honestly ──────────────────────────────────────────────

def test_coverage_is_reported_before_anything_else(capsys):
    """Everything else is conditional on it."""
    _, out = _run(capsys)
    assert out.index("COVERAGE") < out.index("ANALYSIS")


def test_a_replay_produces_exactly_one_window(capsys):
    """run_until_exhausted closes the final window; stopping again would open and
    close an empty one, inflating the count and adding a phantom UNKNOWN."""
    _, out = _run(capsys)
    assert "windows            1 " in out
    assert out.count("w-000002") == 0


def test_a_configuration_warning_is_printed_once(capsys):
    """Repeating a config warning every window is how an operator learns to stop
    reading warnings. Health alarms still repeat -- those describe the window."""
    _, out = _run(capsys, "--mgmt-mac", "aa:bb:cc:dd:ee:ff",
                  "--exclusion-mode", "userspace")
    assert out.count("matched nothing") <= 1


def test_an_unconfigured_exclusion_is_called_out(capsys):
    _, out = _run(capsys)
    assert "NOT CONFIGURED (OTS-CAP-006)" in out


def test_the_rulepack_version_is_reported(capsys):
    """A detection is untraceable without knowing which rules produced it."""
    _, out = _run(capsys)
    assert "rulepack" in out


def test_analysis_can_be_skipped_for_a_pure_capture_measurement(capsys):
    code, out = _run(capsys, "--no-analysis")
    assert "ANALYSIS" not in out
    assert "COVERAGE" in out


def test_observation_batches_are_written_as_jsonl(tmp_path, capsys):
    import json

    out_path = tmp_path / "batches.jsonl"
    _run(capsys, "--out", str(out_path))
    lines = [l for l in out_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines, "no batches written"
    batch = json.loads(lines[0])
    assert batch["collector_id"] and batch["batch_id"]
    assert batch["coverage"] == "unknown", "a replay cannot claim complete coverage"
    assert batch["records"], "the sample should yield records"


def test_written_records_carry_no_payload(tmp_path, capsys):
    import json

    out_path = tmp_path / "b.jsonl"
    _run(capsys, "--out", str(out_path))
    for line in out_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        for record in json.loads(line)["records"]:
            for name in record["attributes"]:
                assert name.lower() not in {"payload", "raw", "packet", "frame"}


# ── argument handling ──────────────────────────────────────────────────────

def test_a_malformed_mgmt_mac_is_refused_at_startup(capsys):
    """Better than building a filter that silently matches nothing."""
    from collector.self_exclusion import ExclusionError

    with pytest.raises(ExclusionError):
        ot_collector.main(["--replay", SAMPLE, "--mgmt-mac", "nonsense"])


def test_preflight_only_requires_an_interface(capsys):
    code = ot_collector.main(["--replay", SAMPLE, "--preflight-only"])
    assert code == 1
    assert "needs --interface" in capsys.readouterr().out


def test_a_source_must_be_chosen():
    with pytest.raises(SystemExit):
        ot_collector.main([])
