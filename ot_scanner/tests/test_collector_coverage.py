"""
Phase 1 — capture coverage accounting (OTS-CAP-001..006, OTS-OPS-002).

Every test here runs without a capture NIC, without root and on any OS. That is
a design property, not a convenience: the logic being tested decides what the
collector may claim to have seen, and if it could only be exercised on a
Raspberry Pi it would never be exercised at all.

The behaviour under test, stated once: a passive sensor that drops frames still
produces a report, and that report is indistinguishable from one taken on a
clean network. Everything below exists to make that distinction visible.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.coverage import (CaptureWindow, Coverage, DropDelta,  # noqa: E402
                                DropSnapshot, WindowAccountant)
from collector.counters import (CombinedCounters, NullCounters,  # noqa: E402
                                SysfsInterfaceCounters, build_counters)
from collector.health import AlarmState, CaptureHealth  # noqa: E402
from collector.preflight import CheckResult, check_capture_interface  # noqa: E402
from collector.rotation import RollingPcapStore  # noqa: E402


def _snap(iface_drop=0, iface_miss=0, cap_recv=0, cap_drop=0):
    return DropSnapshot(interface_rx_packets=cap_recv,
                        interface_rx_dropped=iface_drop,
                        interface_rx_missed=iface_miss,
                        capture_received=cap_recv,
                        capture_dropped=cap_drop,
                        source="test")


def _window(start_snap, end_snap, packets=1000):
    acc = WindowAccountant(collector_id="c1")
    acc.open_window("w1", 0.0, start_snap)
    acc.record_packets(packets)
    return acc.close_window(60.0, end_snap)


# ── the three states ───────────────────────────────────────────────────────

def test_no_loss_measured_is_complete():
    w = _window(_snap(), _snap(cap_recv=1000))
    assert w.coverage is Coverage.COMPLETE
    assert w.degraded is False and w.is_trustworthy


def test_measured_loss_is_degraded():
    w = _window(_snap(), _snap(iface_drop=17, cap_recv=1000))
    assert w.coverage is Coverage.DEGRADED
    assert w.lost == 17 and not w.is_trustworthy


def test_unreadable_counters_are_unknown_not_clean():
    """The state usually missing. A collector that cannot measure loss has not
    established there was none, and must not be presented as clean."""
    w = _window(DropSnapshot(source="null"), DropSnapshot(source="null"))
    assert w.coverage is Coverage.UNKNOWN
    assert w.lost is None
    assert w.degraded is True, "unknown coverage must not read as clean"
    assert not w.is_trustworthy


def test_unknown_reports_no_observed_fraction():
    """Returning 1.0 here would be a confident 100% coverage claim built on no
    measurement at all -- the exact lie this module exists to prevent."""
    w = _window(DropSnapshot(source="null"), DropSnapshot(source="null"))
    assert w.observed_fraction is None


def test_a_partially_readable_window_is_unknown():
    """Interface counters readable, capture counters not: total loss is still
    unknowable, so the window cannot be complete."""
    start = DropSnapshot(interface_rx_dropped=0, interface_rx_missed=0, source="t")
    end = DropSnapshot(interface_rx_dropped=0, interface_rx_missed=0, source="t")
    w = _window(start, end)
    assert w.coverage is Coverage.UNKNOWN
    assert any("capture counters unreadable" in r for r in w.reasons)


# ── counter resets ─────────────────────────────────────────────────────────

def test_a_counter_going_backwards_is_a_reset_not_zero_loss():
    """An interface bounce resets the kernel counters. Subtracting naively gives
    a negative, and clamping it to zero manufactures a clean window out of an
    interval nobody measured."""
    w = _window(_snap(iface_drop=500), _snap(iface_drop=3, cap_recv=1000))
    assert w.drops.counter_reset is True
    assert w.coverage is Coverage.UNKNOWN
    assert any("backwards" in r for r in w.reasons)


def test_delta_between_identical_snapshots_is_zero_not_none():
    d = DropDelta.between(_snap(iface_drop=9), _snap(iface_drop=9))
    assert d.total_lost == 0 and d.measurable


# ── what travels with a finding ────────────────────────────────────────────

def test_the_window_record_carries_coverage_to_the_server():
    """OTS-CAP-004: degradation travels with every finding derived from the
    window. If it is not in this dict it does not reach the server or console."""
    w = _window(_snap(), _snap(iface_drop=5, iface_miss=2, cap_drop=1, cap_recv=1000))
    d = w.to_dict()
    assert d["coverage"] == "degraded"
    assert d["degraded"] is True
    assert d["packets_lost"] == 8
    assert d["interface_dropped"] == 5 and d["interface_missed"] == 2
    assert d["capture_dropped"] == 1
    assert d["collector_id"] == "c1"


def test_interface_and_capture_loss_stay_separate():
    """Different failures with different fixes: a NIC ring overrun needs a
    bigger ring, a capture drop means analysis is too slow. Summing them into
    one number hides which."""
    w = _window(_snap(), _snap(iface_miss=40, cap_drop=3, cap_recv=1000))
    assert w.drops.interface_missed == 40
    assert w.drops.capture_dropped == 3
    assert "ring overrun" in w.explain()


def test_explain_says_a_window_cannot_be_called_clean():
    w = _window(DropSnapshot(source="null"), DropSnapshot(source="null"))
    assert "cannot be reported as clean" in w.explain()


# ── counter sources ────────────────────────────────────────────────────────

def test_missing_sysfs_yields_none_not_zero(tmp_path):
    """On a machine with no /sys/class/net every counter is None, so coverage is
    UNKNOWN. A zero here would make every developer machine report clean."""
    src = SysfsInterfaceCounters("eth0", root=str(tmp_path))
    snap = src.read()
    assert snap.interface_rx_dropped is None
    assert src.available is False


def test_sysfs_counters_are_read_when_present(tmp_path):
    stats = tmp_path / "eth0" / "statistics"
    stats.mkdir(parents=True)
    (stats / "rx_packets").write_text("12345\n")
    (stats / "rx_dropped").write_text("7\n")
    (stats / "rx_missed_errors").write_text("2\n")
    snap = SysfsInterfaceCounters("eth0", root=str(tmp_path)).read()
    assert (snap.interface_rx_packets, snap.interface_rx_dropped,
            snap.interface_rx_missed) == (12345, 7, 2)


def test_a_corrupt_counter_file_reads_as_unavailable(tmp_path):
    stats = tmp_path / "eth0" / "statistics"
    stats.mkdir(parents=True)
    (stats / "rx_dropped").write_text("not-a-number")
    assert SysfsInterfaceCounters("eth0", root=str(tmp_path)).read().interface_rx_dropped is None


def test_build_counters_degrades_to_null_off_linux(tmp_path):
    c = build_counters("eth0", sysfs_root=str(tmp_path))
    assert isinstance(c, CombinedCounters)
    assert c.read().interface_rx_dropped is None


# ── preflight: the passive guarantee ───────────────────────────────────────

def _iface(tmp_path, name="eth0", flags=0x101):
    d = tmp_path / name
    (d / "statistics").mkdir(parents=True)
    (d / "flags").write_text(hex(flags))
    return str(tmp_path)


def test_an_ip_on_the_capture_port_is_a_refusal_to_start(tmp_path):
    """OTS-CAP-001. With an address the kernel owns the interface and will
    speak on it -- ARP, DHCP, mDNS -- so it is no longer a tap. A warning would
    be scrolled past and the collector would run for a year."""
    root = _iface(tmp_path)
    pf = check_capture_interface("eth0", root=root,
                                 address_reader=lambda _i: ["10.0.0.9"])
    assert pf.may_start is False
    ip_check = [c for c in pf.checks if "OTS-CAP-001" in c.name][0]
    assert ip_check.result is CheckResult.FAIL and ip_check.fatal


def test_a_clean_capture_port_passes(tmp_path):
    root = _iface(tmp_path)
    pf = check_capture_interface("eth0", root=root, address_reader=lambda _i: [])
    assert pf.may_start is True
    assert all(c.result is not CheckResult.FAIL for c in pf.checks)


def test_an_unreadable_address_is_unknown_not_pass(tmp_path):
    """Not being able to check is not the same as having checked."""
    root = _iface(tmp_path)
    pf = check_capture_interface("eth0", root=root, address_reader=lambda _i: None)
    ip_check = [c for c in pf.checks if "OTS-CAP-001" in c.name][0]
    assert ip_check.result is CheckResult.UNKNOWN
    assert pf.may_start is True and pf.unknowns


def test_a_down_interface_blocks_start(tmp_path):
    root = _iface(tmp_path, flags=0x0)
    pf = check_capture_interface("eth0", root=root, address_reader=lambda _i: [])
    assert pf.may_start is False


def test_a_missing_interface_blocks_start(tmp_path):
    (tmp_path / "eth0" / "statistics").mkdir(parents=True)
    pf = check_capture_interface("eth9", root=str(tmp_path),
                                 address_reader=lambda _i: [])
    assert pf.may_start is False


# ── retention ──────────────────────────────────────────────────────────────

class _FakeDisk:
    def __init__(self):
        self.sizes = {}
        self.removed = []

    def list(self, _d):
        return sorted(self.sizes)

    def size(self, p):
        return self.sizes[p]

    def remove(self, p):
        self.removed.append(p)
        del self.sizes[p]


def _store(disk, **kw):
    kw.setdefault("max_bytes", 1000)
    kw.setdefault("max_file_bytes", 250)
    return RollingPcapStore("/cap", lister=disk.list, sizer=disk.size,
                            remover=disk.remove, **kw)


def test_eviction_is_oldest_first():
    disk = _FakeDisk()
    for seq, ts in ((1, 100), (2, 200), (3, 300), (4, 400)):
        disk.sizes["/cap/capture-%06d-%d.pcap" % (seq, ts)] = 250
    evicted = _store(disk).enforce(incoming_bytes=250)
    assert [e.started_at for e in evicted] == [100]
    assert "/cap/capture-000001-100.pcap" in disk.removed


def test_the_ceiling_bounds_the_high_water_mark():
    """Eviction runs BEFORE the new file opens, so the ceiling is never exceeded
    and then tidied up -- on a Pi, exceeding it can fill the boot filesystem."""
    disk = _FakeDisk()
    for seq, ts in ((1, 100), (2, 200), (3, 300), (4, 400)):
        disk.sizes["/cap/capture-%06d-%d.pcap" % (seq, ts)] = 250
    store = _store(disk)
    store.enforce(incoming_bytes=250)
    assert sum(disk.sizes.values()) + 250 <= store.max_bytes


def test_eviction_never_touches_a_file_it_did_not_name():
    """A capture directory may hold an operator's own evidence copy. Retention
    deletes only files matching its own naming scheme."""
    disk = _FakeDisk()
    disk.sizes["/cap/capture-000001-100.pcap"] = 900
    disk.sizes["/cap/incident-evidence.pcap"] = 900
    disk.sizes["/cap/notes.txt"] = 10
    _store(disk).enforce(incoming_bytes=250)
    assert disk.removed == ["/cap/capture-000001-100.pcap"]
    assert "/cap/incident-evidence.pcap" in disk.sizes


def test_rotation_triggers_on_size_or_age():
    store = _store(_FakeDisk(), max_file_seconds=900.0)
    assert store.should_rotate(current_bytes=250, age_seconds=1) is True
    assert store.should_rotate(current_bytes=1, age_seconds=900) is True
    assert store.should_rotate(current_bytes=1, age_seconds=1) is False


def test_a_file_budget_larger_than_the_whole_ceiling_is_rejected():
    with pytest.raises(ValueError):
        RollingPcapStore("/cap", max_bytes=100, max_file_bytes=200)


def test_names_round_trip():
    store = RollingPcapStore("/cap")
    name = store.next_name(1700000000)
    assert store.parse_name(name) == (1, 1700000000)


# ── health ─────────────────────────────────────────────────────────────────

def _lossy_window(lost, packets=1000):
    return _window(_snap(), _snap(iface_drop=lost, cap_recv=packets), packets=packets)


def test_a_single_burst_of_loss_does_not_alarm():
    """Alarming on every drop trains operators to ignore the alarm."""
    h = CaptureHealth(sustained_windows=3)
    h.observe(_lossy_window(50))
    h.observe(_window(_snap(), _snap(cap_recv=1000)))
    assert h.evaluate().state is AlarmState.OK


def test_sustained_loss_alarms():
    h = CaptureHealth(sustained_windows=3)
    for _ in range(3):
        h.observe(_lossy_window(50))
    alarm = h.evaluate()
    assert alarm.state is AlarmState.LOSS and alarm.active
    assert "not seeing all traffic" in alarm.detail


def test_sustained_unknown_coverage_raises_its_own_alarm():
    """Blind is not quiet. A run of unmeasurable windows looks identical to a
    clean network on every screen downstream, and the fix differs from a loss
    alarm -- a counter source is missing, not a buffer."""
    h = CaptureHealth(sustained_windows=3)
    for _ in range(3):
        h.observe(_window(DropSnapshot(source="null"), DropSnapshot(source="null")))
    alarm = h.evaluate()
    assert alarm.state is AlarmState.BLIND
    assert "may be reported as clean" in alarm.detail


def test_health_summary_counts_each_state():
    h = CaptureHealth()
    h.observe(_window(_snap(), _snap(cap_recv=1000)))
    h.observe(_lossy_window(5))
    h.observe(_window(DropSnapshot(source="null"), DropSnapshot(source="null")))
    s = h.summary()
    assert s["windows_accounted"] == 3
    assert s["windows_degraded"] == 1 and s["windows_unknown"] == 1


# ── retention window: configured in bytes, MEASURED in days (Q5a) ──────────

def test_the_default_ceiling_is_the_agreed_budget():
    """Q5a: 512 GiB, sized to fit a 1TB USB SSD alongside the OS and spool."""
    from collector.rotation import DEFAULT_MAX_BYTES

    assert DEFAULT_MAX_BYTES == 512 * 1024 ** 3


def test_the_retention_window_is_measured_not_promised():
    """A day-count is a promise a busy day breaks silently: the same 512 GB
    holds ~9 days at 5 Mbps and under one during a sustained 50 Mbps burst. The
    budget is configured; the window it buys is reported."""
    from collector.rotation import RetentionState

    state = RetentionState(files=["a"], total_bytes=300 * 1024 ** 3,
                           oldest_start=1_700_000_000)
    assert round(state.achieved_days(now=1_700_000_000 + 9.3 * 86400), 1) == 9.3
    assert "holding 9.3 days" in state.describe(now=1_700_000_000 + 9.3 * 86400)


def test_an_unmeasurable_window_says_so_rather_than_reporting_zero():
    """Zero days and "we cannot tell yet" are different, and only one of them
    should make an operator go looking for the capture."""
    from collector.rotation import RetentionState

    assert RetentionState().achieved_days() is None
    assert "not yet measurable" in RetentionState().describe()


def test_a_clock_behind_the_filenames_does_not_report_negative_history():
    from collector.rotation import RetentionState

    state = RetentionState(oldest_start=1_700_000_000)
    assert state.achieved_days(now=1_699_000_000) is None
