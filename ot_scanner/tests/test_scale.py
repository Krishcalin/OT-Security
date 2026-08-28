"""
The hub-and-spoke deployment: 100 collectors, one server.

Skipped unless `OT_TEST_DSN` points at a database, for the same reason as
test_server_store.py — a truncation test that silently skips is a truncation
test that never ran.

WHAT THIS EXISTS TO CATCH
─────────────────────────
Every estate route reads the whole estate through `all_assets`, `all_flows` or
`all_detections`, and every one of those carries a LIMIT. Measured on a
100-collector fleet at 120 devices per ring: 12,000 asset rows in the database
and 5,000 returned, 40,000 flows and 20,000 returned — with nothing anywhere in
the response to say the inventory was a fraction of itself.

At 50 devices per ring the same fleet lands on exactly 5,000 rows: the limit,
to the row. One more device per substation and it truncates. A deployment can
sit on that edge for months and then cross it silently.

The ordering makes it worse rather than better. Rows come back `last_seen DESC`,
so what is dropped first is what was seen longest ago — and on a distribution
network the quietest device is an FRTU on a ring main unit that only transmits
on a fault. Truncation discards precisely the devices worth having.
"""
from __future__ import annotations

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

DSN = os.environ.get("OT_TEST_DSN")
pytestmark = pytest.mark.skipif(
    not DSN, reason="set OT_TEST_DSN to run the fleet-scale tests")

if DSN:
    from ot_server import estate as estate_merge      # noqa: E402
    from ot_server import schema, store as store_mod  # noqa: E402

#: The deployment this is sized for.
COLLECTORS = 100


@pytest.fixture()
def store():
    import psycopg
    conn = psycopg.connect(DSN)
    with conn.cursor() as cur:
        for statement in schema.DDL:
            cur.execute(statement)
        for table in ("flow", "detection", "asset", "observation_window",
                      "delivery_gap", "batch", "collector"):
            cur.execute("TRUNCATE %s CASCADE" % table)
    conn.commit()
    yield store_mod.Store(conn)
    conn.close()


def _populate(store, assets_per_collector, flows_per_collector=0):
    now = time.time()
    with store.conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO collector (collector_id, site) VALUES (%s, %s) "
            "ON CONFLICT (collector_id) DO NOTHING",
            [("pi-%03d" % c, "ring-%03d" % c) for c in range(COLLECTORS)])
        for c in range(COLLECTORS):
            cid = "pi-%03d" % c
            cur.executemany(
                "INSERT INTO asset (asset_key, collector_id, first_seen, "
                "last_seen, observation_count, last_observed_window, "
                "last_coverage, attributes) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                [("10.%d.%d.%d" % (c // 250, (a // 250) % 250, a % 250), cid,
                  now - 7200, now - ((a * 37 + c) % 86400), 10, "w-1",
                  "complete", "{}")
                 for a in range(assets_per_collector)])
            if flows_per_collector:
                cur.executemany(
                    "INSERT INTO flow (flow_key, collector_id, first_seen, "
                    "last_seen, observation_count, attributes) "
                    "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                    [("f-%d-%d" % (c, f), cid, now - 900, now - (f % 600), 5,
                      "{}") for f in range(flows_per_collector)])
    store.conn.commit()


# ── the fleet fits, and says so ────────────────────────────────────────────

def test_a_fleet_within_the_limit_reports_a_complete_read(store):
    _populate(store, assets_per_collector=20)
    page = store.all_assets()
    assert len(page) == COLLECTORS * 20
    assert page.complete
    assert page.missing == 0
    assert page.explain() == ""


# ── the fleet does not fit, and says THAT ──────────────────────────────────

def test_a_truncated_read_is_never_reported_as_complete(store):
    """THE test. 12,000 rows stored, 5,000 returned. Before Page existed the
    console was handed a confident inventory of exactly 5,000 devices."""
    _populate(store, assets_per_collector=120)
    page = store.all_assets()
    assert page.total == COLLECTORS * 120
    assert len(page) == 5000
    assert not page.complete
    assert page.missing == 7000
    assert "showing 5000 of 12000" in page.explain()


def test_the_explanation_says_which_devices_were_dropped(store):
    """Not just how many. An operator has to know that the rows omitted are the
    quiet ones, because on this network those are the ones that matter."""
    _populate(store, assets_per_collector=120)
    text = store.all_assets().explain()
    assert "least recently seen" in text
    assert "speak rarely" in text


def test_flows_truncate_far_sooner_than_assets(store):
    """A ring carries many more conversations than devices, so the comms screen
    hits its limit first."""
    _populate(store, assets_per_collector=50, flows_per_collector=400)
    assets, flows = store.all_assets(), store.all_flows()
    assert assets.complete, "50 per ring is exactly 5000 — on the edge, not over"
    assert not flows.complete
    assert flows.total == COLLECTORS * 400
    assert flows.missing == 20000


def test_the_fleet_sits_exactly_on_the_limit_at_fifty_devices_a_ring(store):
    """Recorded because it is the dangerous case: complete today, silently
    truncating the day a substation gains one device."""
    _populate(store, assets_per_collector=50)
    page = store.all_assets()
    assert page.total == 5000 and len(page) == 5000
    assert page.complete, "at the limit, not over it"


# ── an unknown total is not a complete read ────────────────────────────────

def test_an_uncounted_page_is_not_complete(store):
    """Same asymmetry as Coverage.UNKNOWN: not knowing whether rows were
    dropped is not the same as knowing none were."""
    page = store_mod.Page([{"a": 1}], total=None, limit=10)
    assert not page.complete


# ── the merge still holds at fleet scale ───────────────────────────────────

def test_the_estate_merge_survives_a_hundred_collectors(store):
    """Union-find over site-scoped identities, across the whole fleet. Two
    rings must not fuse just because they both use 10.0.x.x."""
    _populate(store, assets_per_collector=20)
    merged = estate_merge.merge(store.all_assets(), store.collector_sites())
    assert len(merged) == COLLECTORS * 20, "sites bled into each other"
    assert all(a.seen_by == 1 for a in merged)
