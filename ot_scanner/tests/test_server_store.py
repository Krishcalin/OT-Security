"""
Phase 3 (server half) — the PostgreSQL store, against a real PostgreSQL.

Skipped unless `OT_TEST_DSN` points at a database. That is deliberate: a
hand-written in-memory double for a database is a second implementation, and it
passes while production fails. Q1 chose PostgreSQL only precisely to avoid
maintaining two dialects, and a test double would reintroduce one through the
back door.

    docker run -d --name ot-pg -e POSTGRES_PASSWORD=... -e POSTGRES_DB=otfleet \
        -e POSTGRES_USER=otfleet -p 127.0.0.1:55432:5432 postgres:16-alpine
    OT_TEST_DSN=postgresql://otfleet:...@127.0.0.1:55432/otfleet pytest

What is checked here is the behaviour the SQL is responsible for and the pure
layer cannot be: idempotency enforced by the database rather than the
application, first_seen surviving a merge, and absence never becoming deletion.
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

DSN = os.environ.get("OT_TEST_DSN")
pytestmark = pytest.mark.skipif(
    not DSN, reason="set OT_TEST_DSN to run the PostgreSQL store tests")

if DSN:
    psycopg = pytest.importorskip("psycopg")
    from ot_server import ingest            # noqa: E402
    from ot_server.store import Store       # noqa: E402


@pytest.fixture()
def store():
    conn = psycopg.connect(DSN)
    s = Store(conn)
    with conn.cursor() as cur:
        for table in ("detection", "flow", "asset", "delivery_gap",
                      "observation_window", "batch", "collector",
                      "schema_version"):
            cur.execute("DROP TABLE IF EXISTS %s CASCADE" % table)
    conn.commit()
    s.migrate()
    yield s
    conn.close()


def _decision(bid="b1", window="w-1", coverage="complete", records=None):
    payload = {"batch_id": bid, "collector_id": "pi-01", "window_id": window,
               "coverage": coverage,
               "records": records if records is not None else [
                   {"key": "ip:10.0.0.1", "kind": "asset",
                    "first_seen": 100.0, "last_seen": 200.0,
                    "observation_count": 5,
                    "attributes": {"ip": "10.0.0.1", "vendor": "Siemens"},
                    "provenance": {"rulepack_version": "abc123"}}]}
    return ingest.decide(payload, set()), payload


def test_migrate_is_idempotent(store):
    assert store.migrate() == store.migrate()


def test_a_batch_round_trips(store):
    decision, payload = _decision()
    store.write_batch(decision, {"packets_analysed": 58})
    assert store.has_batch("b1")
    assets = store.assets("pi-01")
    assert len(assets) == 1 and assets[0]["attributes"]["vendor"] == "Siemens"


def test_the_database_enforces_idempotency_not_the_application(store):
    """Two ingest workers racing the same retry would both pass an application
    check. The unique constraint is what actually prevents double-counting."""
    decision, _ = _decision()
    store.write_batch(decision, {})
    store.write_batch(decision, {})          # replay
    with store.conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM batch WHERE batch_id = 'b1'")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT observation_count FROM asset")
        assert cur.fetchone()[0] == 5, "a replay must not inflate the count"


def test_first_seen_survives_a_merge(store):
    """Recomputing first_seen from arrival time turns a device present for a
    year into one discovered today — exactly the signal an operator watches."""
    first, _ = _decision(bid="b1", window="w-1")
    store.write_batch(first, {})
    later = ingest.decide(
        {"batch_id": "b2", "collector_id": "pi-01", "window_id": "w-2",
         "coverage": "complete",
         "records": [{"key": "ip:10.0.0.1", "kind": "asset",
                      "first_seen": 900.0, "last_seen": 1000.0,
                      "observation_count": 9, "attributes": {},
                      "provenance": {}}]}, set())
    store.write_batch(later, {})
    asset = store.assets("pi-01")[0]
    assert asset["first_seen"] == 100.0, "first_seen moved forward"
    assert asset["last_seen"] == 1000.0


def test_coverage_is_stored_verbatim_for_each_window(store):
    for i, coverage in enumerate(("complete", "degraded", "unknown")):
        decision, _ = _decision(bid="b%d" % i, window="w-%d" % i,
                                coverage=coverage)
        store.write_batch(decision, {})
    states = sorted(w["coverage"] for w in store.recent_windows("pi-01"))
    assert states == ["complete", "degraded", "unknown"]


def test_a_delivery_gap_is_stored_as_a_record(store):
    store.write_gap("pi-01", {"first_window": "w-0", "last_window": "w-2",
                              "batches_lost": 3, "records_lost": 12,
                              "reason": "spool ceiling reached"})
    gaps = store.recent_gaps("pi-01")
    assert len(gaps) == 1 and gaps[0]["records_lost"] == 12


def test_coverage_summary_joins_windows_and_gaps(store):
    """The end-to-end honesty check: a collector whose windows were all complete
    but which lost data in transit is NOT trustworthy."""
    for i in range(3):
        decision, _ = _decision(bid="b%d" % i, window="w-%d" % i)
        store.write_batch(decision, {})
    summary = ingest.summarise_coverage("pi-01", store.recent_windows("pi-01"),
                                        store.recent_gaps("pi-01"))
    assert summary.trustworthy

    store.write_gap("pi-01", {"batches_lost": 1, "records_lost": 4})
    summary = ingest.summarise_coverage("pi-01", store.recent_windows("pi-01"),
                                        store.recent_gaps("pi-01"))
    assert not summary.trustworthy


def test_an_absent_asset_is_kept_and_marked_not_observed(store):
    """OTS-SRV-005. The row must still be there after it stops appearing."""
    decision, _ = _decision(bid="b1", window="w-1")
    store.write_batch(decision, {})

    later = ingest.decide(
        {"batch_id": "b2", "collector_id": "pi-01", "window_id": "w-2",
         "coverage": "complete",
         "records": [{"key": "ip:10.0.0.99", "kind": "asset",
                      "first_seen": 1.0, "last_seen": 2.0,
                      "observation_count": 1, "attributes": {},
                      "provenance": {}}]}, set())
    store.write_batch(later, {})

    latest = store.latest_window("pi-01")
    rows = {a["asset_key"]: a for a in store.assets("pi-01")}
    assert "ip:10.0.0.1" in rows, "the absent asset was deleted"
    assert ingest.asset_state(rows["ip:10.0.0.1"]["last_observed_window"],
                              latest) is ingest.AssetState.NOT_OBSERVED
    assert ingest.asset_state(rows["ip:10.0.0.99"]["last_observed_window"],
                              latest) is ingest.AssetState.OBSERVED


def test_a_detection_records_the_rulepack_that_produced_it(store):
    decision = ingest.decide(
        {"batch_id": "bd", "collector_id": "pi-01", "window_id": "w-1",
         "coverage": "degraded",
         "records": [{"key": "det:ip:10.0.0.1:TELNET", "kind": "detection",
                      "first_seen": 1.0, "last_seen": 2.0,
                      "observation_count": 1,
                      "attributes": {"rule_id": "TELNET", "severity": "high",
                                     "asset": "ip:10.0.0.1"},
                      "provenance": {"rulepack_version": "54b4d37fc7d9"}}]},
        set())
    store.write_batch(decision, {})
    with store.conn.cursor() as cur:
        cur.execute("SELECT rulepack_version, last_coverage, severity "
                    "FROM detection")
        row = cur.fetchone()
    assert row == ("54b4d37fc7d9", "degraded", "high"), (
        "a finding must carry the rules that produced it and the coverage it "
        "was derived from")


def test_heartbeat_keeps_the_last_thing_a_collector_said(store):
    """A collector that stops reporting must not look healthy by absence of
    news."""
    store.record_heartbeat({"collector_id": "pi-01", "queue_depth": 7,
                            "rulepack_version": "abc",
                            "capture_health": {"state": "loss"}})
    with store.conn.cursor() as cur:
        cur.execute("SELECT capture_state, queue_depth FROM collector")
        assert cur.fetchone() == ("loss", 7)
