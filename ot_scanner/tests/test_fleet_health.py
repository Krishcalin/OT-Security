"""
Fleet health, and the defect it exists to fix (OTS-CAP-005, server side).

The load-bearing test is `test_a_collector_that_died_last_week_read_as_clean`.

Coverage is computed over the windows that ARRIVED, and nothing in it looks at
when: `recent_windows` returns the last fifty rows with no time filter, and
`summarise_coverage` has no notion of now. So a collector switched off a week
ago still has fifty complete windows in the table, summarises as trustworthy,
and the estate screen shows a clean plant — indefinitely, for a site nobody is
watching.

That is the exact failure this system is built to refuse, arriving through the
one dimension the coverage model never considered.
"""
from __future__ import annotations

import datetime
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ot_server import health                                # noqa: E402
from ot_server import ingest, estate                        # noqa: E402


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _row(collector_id="pi-a", site="Alderley", ago_seconds=0,
         capture="complete", queue=0, enabled=True, never=False):
    return {
        "collector_id": collector_id, "site": site,
        "last_heartbeat": None if never
        else _now() - datetime.timedelta(seconds=ago_seconds),
        "capture_state": capture, "queue_depth": queue, "enabled": enabled,
        "rulepack_version": "1", "collector_version": "0.1.0",
    }


# ── the states ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ago,expected", [
    (0, health.REPORTING),
    (health.LATE_AFTER - 1, health.REPORTING),
    (health.LATE_AFTER + 1, health.LATE),
    (health.SILENT_AFTER + 1, health.SILENT),
])
def test_silence_is_measured_in_missed_heartbeats(ago, expected):
    """Sustained, not instant. A missed heartbeat is a lost packet or a busy
    link; six missed is a collector that is not coming back on its own."""
    assert health.assess_collector(_row(ago_seconds=ago)).state == expected


def test_never_reported_is_not_the_same_as_silent():
    """One is a collector somebody forgot to start; the other is one that was
    working and stopped. Different problems, different first move."""
    never = health.assess_collector(_row(never=True))
    silent = health.assess_collector(_row(ago_seconds=health.SILENT_AFTER + 1))
    assert never.state == health.NEVER_REPORTED
    assert silent.state == health.SILENT
    assert never.alarms[0].kind != silent.alarms[0].kind


def test_a_disabled_collector_raises_nothing():
    """Somebody switched it off. Alarming on it is how an operator learns to
    dismiss the list without reading it."""
    assessed = health.assess_collector(_row(enabled=False, ago_seconds=999999))
    assert assessed.state == health.DISABLED
    assert assessed.alarms == []


# ── the correction ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("state,believable", [
    (health.REPORTING, True),
    (health.LATE, True),
    (health.SILENT, False),
    (health.NEVER_REPORTED, False),
])
def test_only_a_collector_still_reporting_has_believable_coverage(state,
                                                                  believable):
    assert health.coverage_is_believable(state) is believable


def test_a_silent_collector_raises_no_stale_capture_alarms():
    """Its last-known capture state describes last Tuesday. Alarming on a
    week-old reading sends somebody to fix a ring buffer on a device that is
    not running."""
    assessed = health.assess_collector(
        _row(ago_seconds=health.SILENT_AFTER + 1, capture="degraded",
             queue=9000))
    assert [a.kind for a in assessed.alarms] == ["silent"]


# ── what a person should do ────────────────────────────────────────────────

def test_unmeasurable_capture_is_critical_and_dropped_frames_are_not():
    """A window whose loss cannot be measured supports no clean result at all;
    one that dropped frames is a floor rather than a total."""
    unknown = health.assess_collector(_row(capture="unknown"))
    degraded = health.assess_collector(_row(capture="degraded"))
    assert unknown.alarms[0].severity == "critical"
    assert degraded.alarms[0].severity == "warning"


@pytest.mark.parametrize("queue,severity", [
    (health.QUEUE_WARNING - 1, None),
    (health.QUEUE_WARNING, "warning"),
    (health.QUEUE_CRITICAL, "critical"),
])
def test_a_growing_queue_is_alarmed_before_the_spool_wraps(queue, severity):
    """The observations are not lost yet. That is the point of alarming here
    rather than after."""
    alarms = health.assess_collector(_row(queue=queue)).alarms
    if severity is None:
        assert alarms == []
    else:
        assert alarms[0].severity == severity
        assert "before the spool wraps" in alarms[0].action or severity == "warning"


def test_every_alarm_names_something_to_do():
    """An alarm without an action is a page at 3am that begins with an hour of
    guessing."""
    fleet = health.assess([
        _row("pi-silent", ago_seconds=health.SILENT_AFTER + 1),
        _row("pi-queue", queue=health.QUEUE_CRITICAL),
        _row("pi-blind", capture="unknown"),
        _row("pi-new", never=True),
    ])
    assert fleet.alarms
    for alarm in fleet.alarms:
        assert alarm.action.strip(), alarm.kind
        assert alarm.detail.strip(), alarm.kind


def test_content_drift_is_an_alarm_on_a_live_collector():
    fleet = health.assess([_row("pi-a")], behind={"pi-a": 3})
    kinds = [a.kind for a in fleet.alarms]
    assert "content_behind" in kinds


def test_a_healthy_fleet_says_so_plainly():
    fleet = health.assess([_row("pi-a"), _row("pi-b")])
    assert fleet.healthy is True
    assert "all reporting" in fleet.explain()


# ── THE regression ─────────────────────────────────────────────────────────

class _StaleStore:
    """A collector that stopped a week ago, with a full history of complete
    windows still in the table — which is exactly what the database looks like
    the morning after a collector is switched off."""

    def __init__(self, ago_seconds):
        self.ago = ago_seconds

    def collector_ids(self):
        return ["pi-dead"]

    def collector_sites(self):
        return {"pi-dead": "Alderley"}

    def recent_windows(self, collector_id):
        # Fifty complete windows. All of them real, all of them old, and
        # nothing in the row says when they arrived.
        return [{"coverage": "complete"}] * 50

    def recent_gaps(self, collector_id):
        return []

    def collectors_health(self):
        return [_row("pi-dead", ago_seconds=self.ago)]

    def latest_pack_version(self, kind):
        return 0

    def reported_pack_versions(self):
        return {}


def test_the_old_coverage_model_calls_a_dead_collector_trustworthy():
    """First, prove the defect is real rather than theoretical.

    This is `estate_coverage` on its own, exactly as the endpoint used to call
    it: fifty stored complete windows, no notion of time, and a confident yes.
    """
    store = _StaleStore(ago_seconds=7 * 24 * 3600)
    summaries = [ingest.summarise_coverage(cid, store.recent_windows(cid),
                                           store.recent_gaps(cid))
                 for cid in store.collector_ids()]
    coverage = estate.estate_coverage(summaries)
    assert coverage.trustworthy is True, (
        "the premise of this test no longer holds — coverage has become "
        "time-aware on its own, and the correction below may be redundant")


def test_a_collector_that_died_last_week_read_as_clean():
    """THE regression. The endpoint must now refuse what the model alone says.

    A site nobody is watching is not a site with nothing wrong.
    """
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    store = _StaleStore(ago_seconds=7 * 24 * 3600)
    client = TestClient(create_app(store, require_operator=lambda r: "op",
                                   console_dir=""))
    body = client.get("/api/v1/estate/coverage").json()

    assert body["trustworthy"] is False, "a switched-off sensor read as clean"
    assert body["silent_collectors"] == ["pi-dead"]
    assert "stopped reporting" in body["explain"]
    assert "switched-off sensor reads as a clean plant" in body["explain"]


def test_a_reporting_collector_is_still_trustworthy():
    """The correction must not make every estate untrustworthy — an alarm that
    is always on is an alarm nobody reads."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    store = _StaleStore(ago_seconds=0)
    client = TestClient(create_app(store, require_operator=lambda r: "op",
                                   console_dir=""))
    body = client.get("/api/v1/estate/coverage").json()
    assert body["trustworthy"] is True
    assert body["silent_collectors"] == []


# ── the route ──────────────────────────────────────────────────────────────

def test_the_health_route_reports_what_to_go_and_look_at():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    store = _StaleStore(ago_seconds=7 * 24 * 3600)
    client = TestClient(create_app(store, require_operator=lambda r: "op",
                                   console_dir=""))
    body = client.get("/api/v1/estate/health").json()

    assert body["healthy"] is False
    assert body["silent"] == ["pi-dead"]
    assert body["coverage_not_believable"] == ["pi-dead"]
    assert body["alarms"][0]["severity"] == "critical"
    assert body["alarms"][0]["action"]


def test_the_health_route_is_fail_closed():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    client = TestClient(create_app(_StaleStore(0), console_dir=""))
    assert client.get("/api/v1/estate/health").status_code == 503
