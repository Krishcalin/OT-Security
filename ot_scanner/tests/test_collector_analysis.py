"""
Phase 1 §6.2 — incremental analysis (OTS-ANL-001..005).

The load-bearing test here is parity: the same pcap analysed by the existing
file path and by the live path must produce the same assets and the same
findings. If they ever diverge, the collector is quietly a different product
from the scanner it was built out of, and every finding in the field becomes
unreproducible on a desk.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector import rulepack  # noqa: E402
from collector.analysis import IncrementalAnalyzer  # noqa: E402
from collector.capture import Frame, ReplaySource  # noqa: E402
from collector.observations import (ObservationBuilder, RecordKind,  # noqa: E402
                                    asset_key, scrub)
from collector.preflight import Check, CheckResult, Preflight  # noqa: E402
from collector.service import CaptureService, CollectorConfig  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLE = os.path.join(ROOT, "test_data", "ot_test_traffic.pcap")

dpkt = pytest.importorskip("dpkt")
pytestmark = pytest.mark.skipif(not os.path.exists(SAMPLE),
                                reason="sample pcap not present")


def _run_incremental(collector_id="pi-01"):
    an = IncrementalAnalyzer(collector_id=collector_id)
    svc = CaptureService(
        ReplaySource(SAMPLE),
        CollectorConfig(window_seconds=1e9, enforce_preflight=False),
        clock=lambda: 0.0,
        preflight=Preflight("x", [Check("s", CheckResult.PASS)]),
        on_frames=an.feed)
    svc.start()
    reports = svc.run_until_exhausted()
    return an, reports


def _run_file_path():
    from scanner.core import PCAPAnalyzer

    return PCAPAnalyzer(verbose=False).analyze(SAMPLE)


# ── OTS-ANL-001: the analysers are the same analysers ──────────────────────

def test_the_live_path_finds_the_same_assets_as_the_file_path():
    """Parity. A second decoder would drift from the first, silently."""
    an, _ = _run_incremental()
    live_devices, _ = an._finalise()
    file_devices = _run_file_path()[0]

    live = sorted(d.ip for d in live_devices if getattr(d, "ip", None))
    from_file = sorted(d.ip for d in file_devices if getattr(d, "ip", None))
    assert live == from_file, "live capture and file analysis disagree on assets"


def test_the_live_path_finds_the_same_findings_as_the_file_path():
    an, _ = _run_incremental()
    live_devices, _ = an._finalise()
    file_devices = _run_file_path()[0]

    def fingerprint(devices):
        out = []
        for d in devices:
            for v in getattr(d, "vulnerabilities", []) or []:
                out.append((getattr(d, "ip", ""), getattr(v, "title", ""),
                            str(getattr(v, "severity", ""))))
        return sorted(out)

    assert fingerprint(live_devices) == fingerprint(file_devices)


def test_every_frame_in_the_sample_decodes():
    an, _ = _run_incremental()
    assert an.stats.frames_seen > 0
    assert an.stats.decode_failures == 0
    assert an.stats.frames_decoded == an.stats.frames_seen


def test_a_malformed_frame_is_counted_not_swallowed():
    """Live networks carry junk. It must not stop capture, but a decoder that
    fails on everything has to be visible rather than looking like a quiet link."""
    an = IncrementalAnalyzer()
    an.feed([Frame(raw=b"\x00\x01\x02", timestamp=0.0)])
    assert an.stats.frames_seen == 1
    assert an.stats.undecodable_fraction == 1.0


# ── state across window boundaries ─────────────────────────────────────────

def test_repeated_finalise_does_not_duplicate_findings():
    """A window is an accounting boundary, not an analysis one, so _finalise
    runs once per window over accumulated state. It assigns rather than appends
    -- an append here would inflate every count on a long-running collector and
    nothing else would notice."""
    an, _ = _run_incremental()
    first, _ = an._finalise()
    counts_first = {d.ip: len(d.vulnerabilities or []) for d in first}
    for _ in range(4):
        again, _ = an._finalise()
    counts_again = {d.ip: len(d.vulnerabilities or []) for d in again}
    assert counts_first == counts_again


def test_one_analyzer_instance_spans_all_windows():
    """DNP3/IEC-104/GOOSE sessions live on the analyser. A session opened in one
    window and exploited in the next must still be one session."""
    an, reports = _run_incremental()
    assert len(reports) >= 1
    devices, _ = an._finalise()
    assert devices, "state did not survive to the end of the run"


# ── OTS-ANL-002: no payloads leave the plant ───────────────────────────────

def test_no_record_carries_a_payload():
    an, reports = _run_incremental()
    w = reports[-1]
    batch = an.build_batch(w.window.window_id, w.window.coverage.value)
    for record in batch.records:
        for name, value in record.attributes.items():
            assert not isinstance(value, (bytes, bytearray)), (
                "record %s carries binary in %r" % (record.key, name))
            assert name.lower() not in {"payload", "raw", "packet", "frame"}


def test_scrub_drops_payload_fields_and_bytes():
    """Belt and braces for a future analyser attaching a payload by accident.
    Bytes are removed rather than encoded -- base64 of a payload is the payload."""
    cleaned = scrub({"ip": "10.0.0.1", "payload": "secret", "raw": b"\x01",
                     "blob": b"\x02\x03", "vendor": "Siemens"})
    assert cleaned == {"ip": "10.0.0.1", "vendor": "Siemens"}


# ── OTS-ANL-004: provenance travels ────────────────────────────────────────

def test_records_carry_first_seen_last_seen_and_a_count():
    b = ObservationBuilder(collector_id="pi-01", rulepack_version="v1")
    first = b.observe("ip:10.0.0.1", RecordKind.ASSET, {}, "w-1", "complete",
                      seen_at=100.0)
    second = b.observe("ip:10.0.0.1", RecordKind.ASSET, {}, "w-2", "complete",
                       seen_at=200.0)
    assert first.observation_count == 1 and second.observation_count == 2
    assert second.first_seen == 100.0, (
        "first_seen must survive across windows -- recomputing it on the server "
        "turns a device present for a year into one discovered today")
    assert second.last_seen == 200.0


def test_coverage_travels_with_every_record():
    an, reports = _run_incremental()
    w = reports[-1]
    batch = an.build_batch(w.window.window_id, w.window.coverage.value)
    assert batch.records
    for record in batch.records:
        assert record.provenance.coverage == w.window.coverage.value
        assert record.provenance.collector_id == "pi-01"


def test_a_degraded_window_is_not_presented_as_complete():
    b = ObservationBuilder(collector_id="pi-01")
    rec = b.observe("ip:1.1.1.1", RecordKind.DETECTION, {}, "w-9", "degraded")
    assert rec.provenance.from_complete_window is False


def test_an_l2_only_device_keys_on_mac():
    """A GOOSE publisher has no IP. Keying on a hash of both would make one
    device look like two to collectors that see only one of them."""
    assert asset_key("", "AA:BB:CC:DD:EE:FF") == "mac:aa:bb:cc:dd:ee:ff"
    assert asset_key("10.0.0.1", "AA:BB:CC:DD:EE:FF") == "ip:10.0.0.1"


def test_the_batch_id_is_content_derived():
    """Idempotency (OTS-TRN-004): a replayed batch must be recognisable as the
    same batch rather than creating duplicate assets."""
    an, reports = _run_incremental()
    w = reports[-1]
    one = an.build_batch(w.window.window_id, w.window.coverage.value)
    two = an.build_batch(w.window.window_id, w.window.coverage.value)
    assert one.batch_id == two.batch_id


# ── OTS-ANL-005: rule-pack versioning ──────────────────────────────────────

def test_every_detection_names_the_rulepack_that_produced_it():
    an, reports = _run_incremental()
    w = reports[-1]
    batch = an.build_batch(w.window.window_id, w.window.coverage.value)
    detections = [r for r in batch.records if r.kind is RecordKind.DETECTION]
    assert detections, "the sample should produce detections"
    for det in detections:
        assert det.provenance.rulepack_version
        assert det.attributes["rule_id"]


def test_the_version_changes_when_a_rule_changes(tmp_path):
    """A version someone must remember to bump is wrong exactly when it matters
    -- the hotfix, the threshold tweak. Hashing the sources removes the choice."""
    root = tmp_path / "scanner"
    for rel in rulepack.RULE_SOURCES:
        path = root.joinpath(*rel.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# rule\n")
    before = rulepack.compute(str(root))
    assert before.complete and before.files == len(rulepack.RULE_SOURCES)

    root.joinpath("vuln", "dnp3_checks.py").write_text("# rule\n# changed\n")
    after = rulepack.compute(str(root))
    assert after.version != before.version


def test_line_endings_do_not_change_the_version(tmp_path):
    """A checkout on Windows and one on the Pi must agree on the rules they hold."""
    def build(newline):
        root = tmp_path / ("s" + str(len(newline)))
        for rel in rulepack.RULE_SOURCES:
            p = root.joinpath(*rel.split("/"))
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(("# rule" + newline).encode())
        return rulepack.compute(str(root)).version

    assert build("\n") == build("\r\n")


def test_a_missing_rule_source_is_declared_not_skipped(tmp_path):
    """Hashing six files when seven were expected yields a version that looks
    fine and describes a different pack."""
    root = tmp_path / "scanner"
    for rel in rulepack.RULE_SOURCES[:-1]:
        p = root.joinpath(*rel.split("/"))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# rule\n")
    pack = rulepack.compute(str(root))
    assert pack.complete is False
    assert pack.version.startswith("partial-")
    assert "MISSING" in pack.describe()


def test_the_real_rulepack_resolves_completely():
    pack = rulepack.compute()
    assert pack.complete, pack.describe()
    assert len(pack.version) == 12
