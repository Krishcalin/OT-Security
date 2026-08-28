"""
Phase 1 §6.1 — the capture loop and self-exclusion (OTS-CAP-001..006, SEC-001).

Runs with no NIC, no root and no scapy: the loop is driven by a synthetic source
and by replaying the repository's own sample pcap, so the behaviour that decides
what a collector may claim is exercised on every developer machine rather than
only on a Raspberry Pi.
"""
from __future__ import annotations

import ast
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector import capture as capture_mod  # noqa: E402
from collector.capture import Frame, ReplaySource, SyntheticSource  # noqa: E402
from collector.coverage import Coverage, DropSnapshot  # noqa: E402
from collector.preflight import Check, CheckResult, Preflight  # noqa: E402
from collector.self_exclusion import (ExclusionError, ExclusionMode,  # noqa: E402
                                      SelfExclusion, SelfIdentity, build_bpf)
from collector.service import (CaptureRefused, CaptureService,  # noqa: E402
                               CollectorConfig)

SAMPLE_PCAP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "test_data", "ot_test_traffic.pcap")

MGMT_MAC = "aa:bb:cc:dd:ee:ff"


def _frame(src_mac="00:11:22:33:44:55", dst_mac="00:11:22:33:44:66",
           src_ip="10.0.0.1", dst_ip="10.0.0.2", size=100):
    return Frame(raw=b"\x00" * size, timestamp=0.0, src_mac=src_mac,
                 dst_mac=dst_mac, src_ip=src_ip, dst_ip=dst_ip)


def _snap(drop=0, recv=0):
    return DropSnapshot(interface_rx_dropped=drop, interface_rx_missed=0,
                        capture_received=recv, capture_dropped=0, source="t")


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt
        return self.t


def _service(frames=None, stats=None, clock=None, exclusion=None, **cfg):
    clock = clock or _Clock()
    src = SyntheticSource(frames or [], stats_sequence=stats)
    conf = CollectorConfig(window_seconds=60.0, enforce_preflight=False, **cfg)
    ok = Preflight("eth0", [Check("stub", CheckResult.PASS)])
    return CaptureService(src, conf, exclusion=exclusion, clock=clock,
                          preflight=ok), clock


# ── OTS-SEC-001: nothing here can transmit ─────────────────────────────────

#: scapy/socket entry points that put a frame on the wire.
_SEND_NAMES = {"send", "sendp", "sendto", "sr", "sr1", "srp", "srp1",
               "L2socket", "L3socket"}


def _called_names(module) -> set:
    """Every function/attribute actually CALLED in a module, from the AST.

    Read from the syntax tree rather than by scanning text: a substring search
    matches the word "L2socket" inside a comment explaining why L2socket is not
    used, and would equally miss a real call spelled across a line break. This
    guard is about what the code DOES.
    """
    tree = ast.parse(inspect.getsource(module))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                names.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                names.add(fn.attr)
    return names


def test_no_capture_source_can_transmit():
    """The capture interface is the one place a bug could put a frame onto a
    live plant network. Pinned by inspection rather than trusted to review."""
    offenders = _called_names(capture_mod) & _SEND_NAMES
    assert not offenders, (
        "capture.py calls %s — the capture path must have no send capability "
        "(OTS-SEC-001)" % sorted(offenders))


def test_the_transmit_guard_would_catch_a_real_send():
    """A guard that cannot fail is decoration. This proves it fires."""
    leaking = "def leak(sock):\n    sock.sendp(payload)\n"
    tree = ast.parse(leaking)
    names = {n.func.attr for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert names & _SEND_NAMES == {"sendp"}


def test_the_live_source_uses_a_listening_socket():
    src = inspect.getsource(capture_mod.ScapyLiveSource)
    assert "L2listen" in src


# ── OTS-CAP-001: refusal to start ──────────────────────────────────────────

def test_the_loop_refuses_to_start_when_preflight_fails():
    bad = Preflight("eth0", [Check("no IP address (OTS-CAP-001)", CheckResult.FAIL,
                                   "carries 10.0.0.9", fatal=True)])
    svc = CaptureService(SyntheticSource([]),
                         CollectorConfig(enforce_preflight=True), preflight=bad)
    with pytest.raises(CaptureRefused) as exc:
        svc.start()
    assert "OTS-CAP-001" in str(exc.value)


def test_refusal_can_be_overridden_only_deliberately():
    bad = Preflight("eth0", [Check("no IP", CheckResult.FAIL, "", fatal=True)])
    svc = CaptureService(SyntheticSource([]),
                         CollectorConfig(enforce_preflight=False), preflight=bad)
    svc.start()
    assert svc._started is True


# ── OTS-CAP-006: self-exclusion ────────────────────────────────────────────

def test_a_malformed_management_mac_is_refused():
    """A filter built from a typo matches nothing, and the collector quietly
    inventories itself. Refuse at configuration time instead."""
    with pytest.raises(ExclusionError):
        SelfIdentity(mgmt_mac="not-a-mac")


def test_the_bpf_excludes_mac_and_both_addresses():
    bpf = build_bpf(SelfIdentity(mgmt_mac=MGMT_MAC, mgmt_ipv4="10.9.0.5",
                                 server_ipv4="10.9.0.1"))
    assert bpf.startswith("not (")
    assert "ether host %s" % MGMT_MAC in bpf
    assert "host 10.9.0.5" in bpf and "host 10.9.0.1" in bpf


def test_no_identity_means_no_filter_rather_than_a_filter_matching_all():
    assert build_bpf(SelfIdentity()) is None


def test_self_traffic_is_excluded_and_counted():
    ex = SelfExclusion(SelfIdentity(mgmt_mac=MGMT_MAC), ExclusionMode.USERSPACE)
    svc, clock = _service(
        frames=[_frame(), _frame(src_mac=MGMT_MAC), _frame(),
                _frame(dst_mac=MGMT_MAC)],
        exclusion=ex)
    svc.start()
    svc.poll()
    clock.advance(60.0)
    report = svc.poll()
    assert report.frames_analysed == 2, "plant frames only"
    assert report.self_excluded == 2, "both self frames counted, not silently dropped"


def test_excluding_by_ip_catches_traffic_to_the_server():
    ex = SelfExclusion(SelfIdentity(server_ipv4="10.9.0.1"), ExclusionMode.USERSPACE)
    assert ex.should_analyse(src_ip="10.0.0.1", dst_ip="10.9.0.1") is False
    assert ex.should_analyse(src_ip="10.0.0.1", dst_ip="10.0.0.2") is True


def test_bpf_mode_reports_the_excluded_count_as_unknown():
    """The kernel does not say how many frames it filtered for us. Reporting 0
    would claim the collector saw no self-traffic when it could not count."""
    ex = SelfExclusion(SelfIdentity(mgmt_mac=MGMT_MAC), ExclusionMode.BPF)
    d = ex.to_dict()
    assert d["excluded_frames"] is None and d["bpf"] is not None


def test_an_unconfigured_exclusion_warns():
    ex = SelfExclusion()
    assert any("will inventory itself" in w for w in ex.warnings())


def test_a_filter_that_never_matches_is_surfaced():
    """Distinguishes "the SPAN does not mirror management" (fine) from "the
    configured identity is wrong" (a phantom asset is coming)."""
    ex = SelfExclusion(SelfIdentity(mgmt_mac=MGMT_MAC), ExclusionMode.USERSPACE)
    for _ in range(50):
        ex.should_analyse(src_mac="00:11:22:33:44:55")
    assert any("matched nothing" in w for w in ex.warnings())


# ── OTS-CAP-003/004: windows and counters ──────────────────────────────────

def test_a_window_closes_on_the_boundary_and_carries_coverage():
    svc, clock = _service(frames=[_frame() for _ in range(10)],
                          stats=[_snap(), _snap(drop=4)])
    svc.start()
    assert svc.poll() is None, "no report before the boundary"
    clock.advance(60.0)
    report = svc.poll()
    assert report is not None
    assert report.window.coverage is Coverage.DEGRADED
    assert report.window.lost == 4


def test_an_empty_window_is_still_accounted():
    """A quiet network and a dead capture look identical unless every window is
    closed with a counter read."""
    svc, clock = _service(frames=[], stats=[_snap(), _snap()])
    svc.start()
    clock.advance(60.0)
    report = svc.poll()
    assert report is not None and report.frames_analysed == 0
    assert report.window.coverage is Coverage.COMPLETE


def test_windows_are_contiguous_with_no_unaccounted_gap():
    """One counter read closes a window and opens the next. Reading twice leaves
    a gap in which loss is invisible -- small, constant, always flattering."""
    src = inspect.getsource(CaptureService._close_window)
    assert src.count("self.source.stats()") == 1, (
        "close and re-open must share one counter reading")


def test_a_replayed_capture_reports_unknown_coverage():
    """A pcap cannot tell you what the tap missed while it was recorded, so a
    replayed window is UNKNOWN -- never COMPLETE."""
    if not os.path.exists(SAMPLE_PCAP):
        pytest.skip("sample pcap not present")
    pytest.importorskip("dpkt")
    clock = _Clock()
    svc = CaptureService(ReplaySource(SAMPLE_PCAP),
                         CollectorConfig(window_seconds=1e9,
                                         enforce_preflight=False),
                         clock=clock,
                         preflight=Preflight("x", [Check("s", CheckResult.PASS)]))
    svc.start()
    reports = svc.run_until_exhausted()
    assert reports, "the replay produced no window"
    assert reports[-1].window.coverage is Coverage.UNKNOWN
    assert reports[-1].frames_analysed > 0, "real frames were analysed"


def test_the_final_partial_window_is_not_discarded():
    """Dropping the tail would silently lose the end of every replayed capture."""
    svc, clock = _service(frames=[_frame() for _ in range(5)])
    svc.start()
    reports = svc.run_until_exhausted()
    assert sum(r.frames_analysed for r in reports) == 5


def test_analysis_is_invoked_only_with_plant_frames():
    seen = []
    ex = SelfExclusion(SelfIdentity(mgmt_mac=MGMT_MAC), ExclusionMode.USERSPACE)
    svc, clock = _service(frames=[_frame(), _frame(src_mac=MGMT_MAC)], exclusion=ex)
    svc.on_frames = lambda batch: seen.extend(batch)
    svc.start()
    svc.poll()
    assert len(seen) == 1
    assert seen[0].src_mac != MGMT_MAC


def test_the_summary_carries_exclusion_and_health():
    ex = SelfExclusion(SelfIdentity(mgmt_mac=MGMT_MAC), ExclusionMode.USERSPACE)
    svc, clock = _service(frames=[_frame()], stats=[_snap(), _snap()], exclusion=ex)
    svc.start()
    svc.poll()
    clock.advance(60.0)
    svc.poll()
    s = svc.coverage_summary()
    assert s["windows"] == 1
    assert s["self_exclusion"]["mode"] == "userspace"
    assert s["windows_accounted"] == 1


def test_a_degraded_window_carries_its_state_into_the_record():
    svc, clock = _service(frames=[_frame()], stats=[_snap(), _snap(drop=9)])
    svc.start()
    svc.poll()
    clock.advance(60.0)
    d = svc.poll().to_dict()
    assert d["degraded"] is True and d["packets_lost"] == 9
    assert d["coverage"] == "degraded"
