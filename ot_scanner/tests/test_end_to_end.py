"""
End to end: a real pcap through the real collector, over the real ingest path,
into real PostgreSQL, out through the real estate merge.

WHY THIS EXISTS
───────────────
Every phase so far was verified against a double. The collector's transport was
tested with a StubSender, the server's ingest with a _FakeStore, the console by
reading its source. Each half is internally consistent; until now nothing
checked that the two halves agree with EACH OTHER.

That gap has already cost once. Phase 3 tested ingest logic thoroughly and the
HTTP surface not at all, and every estate route answered 422 for a whole phase
before a Phase 4 test called one.

Four seams are exercised here that no other test touches:

    collector record   -> server validator
    batch window dict  -> write_batch
    stored rows        -> estate merge
    merged assets      -> the JSON the console consumes

NO DOUBLES. The only synthetic element is the drop counters, and that is
deliberate: a replayed pcap can only ever report UNKNOWN coverage, because a
file cannot tell you what the tap missed while it was recording. Driving the
counters lets the COMPLETE and DEGRADED paths — the two an operator actually
sees in production — be exercised through the whole stack instead of only the
one a file can produce.
"""
from __future__ import annotations

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "ot_scanner"))

DSN = os.environ.get("OT_TEST_DSN")
SAMPLE = os.path.join(_ROOT, "test_data", "ot_test_traffic.pcap")

pytestmark = [
    pytest.mark.skipif(not DSN, reason="set OT_TEST_DSN for the end-to-end test"),
    pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample pcap absent"),
]

if DSN:
    psycopg = pytest.importorskip("psycopg")
    dpkt = pytest.importorskip("dpkt")

    from collector.analysis import IncrementalAnalyzer
    from collector.capture import ReplaySource
    from collector.coverage import DropSnapshot
    from collector.preflight import Check, CheckResult, Preflight
    from collector.service import CaptureService, CollectorConfig
    from collector.spool import Spool
    from ot_server import estate, ingest, vulnmatch
    from ot_server.store import Store

    class _CountedReplay(ReplaySource):
        """Real frames from a real pcap, with drop counters the test controls.

        Composition rather than a mock: the frames, the parsing and the analysers
        are all genuine. Only the counters are supplied, because a file has none —
        and without them only the UNKNOWN coverage path would ever be reached.
        """

        name = "replay+counters"

        def __init__(self, path, snapshots):
            super().__init__(path)
            self._snaps = list(snapshots)
            self._i = 0

        def stats(self) -> "DropSnapshot":
            snap = self._snaps[min(self._i, len(self._snaps) - 1)]
            self._i += 1
            return snap



def _snap(drop=0, recv=0):
    return DropSnapshot(interface_rx_dropped=drop, interface_rx_missed=0,
                        capture_received=recv, capture_dropped=0, source="e2e")


def _collect(collector_id, snapshots):
    """Run the REAL collector over the sample pcap and return its batch."""
    analyzer = IncrementalAnalyzer(collector_id=collector_id)
    service = CaptureService(
        _CountedReplay(SAMPLE, snapshots),
        CollectorConfig(collector_id=collector_id, window_seconds=1e9,
                        enforce_preflight=False),
        clock=lambda: 0.0,
        preflight=Preflight("x", [Check("stub", CheckResult.PASS)]),
        on_frames=analyzer.feed)
    service.start()
    reports = service.run_until_exhausted()
    report = reports[-1]
    batch = analyzer.build_batch(report.window.window_id,
                                 report.window.coverage.value,
                                 report.to_dict())
    return batch, report


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


def _ingest(store, batch, window):
    """Push a collector batch through the REAL server ingest path."""
    payload = batch.to_dict()
    decision = ingest.decide(payload, _Known(store))
    assert decision.verdict is not ingest.Verdict.REJECT, decision.reason
    if decision.verdict is ingest.Verdict.ACCEPT:
        store.write_batch(decision, payload.get("window") or window)
    return decision


class _Known:
    def __init__(self, store):
        self.store = store

    def __contains__(self, batch_id):
        return self.store.has_batch(batch_id)


# ── the seam the doubles never checked ─────────────────────────────────────

def test_a_real_collector_batch_passes_the_real_server_validator(store):
    """The collector's record shape has only ever been checked against a
    hand-written dict on the server side."""
    batch, report = _collect("pi-a", [_snap(), _snap(recv=58)])
    problem = ingest.validate(batch.to_dict())
    assert problem is None, "the server rejects what the collector emits: %s" % problem


def test_the_whole_pipeline_carries_a_finding_from_pcap_to_estate(store):
    """pcap -> analysers -> record -> validator -> PostgreSQL -> merge."""
    batch, report = _collect("pi-a", [_snap(), _snap(recv=58)])
    store.set_site("pi-a", "Substation A")
    _ingest(store, batch, report.to_dict())

    assets = estate.merge(store.all_assets(), store.collector_sites())
    assert assets, "nothing survived the round trip"

    with store.conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM detection")
        detections = cur.fetchone()[0]
    assert detections > 0, "the collector's detections did not reach the store"


def test_the_window_dict_the_collector_emits_is_what_the_store_reads(store):
    """Both sides were written against hand-made dicts and never compared."""
    batch, report = _collect("pi-a", [_snap(), _snap(recv=58)])
    _ingest(store, batch, report.to_dict())
    windows = store.recent_windows("pi-a")
    assert len(windows) == 1
    assert windows[0]["packets_analysed"] > 0, (
        "packets_analysed did not survive the collector -> store hop")


# ── coverage survives the whole stack, in all three states ─────────────────

@pytest.mark.parametrize("expected", ["complete", "degraded", "unknown"])
def test_each_coverage_state_reaches_the_estate_intact(store, expected):
    """The spine of the product. A degraded window must still read as degraded
    after crossing the wire, the database and the merge — if it is normalised
    away at any hop, every safeguard upstream was decorative.

    Parametrised on the state rather than on snapshot objects: decorator
    arguments are evaluated at COLLECTION time, before the guarded imports
    exist, and the skipif marker cannot prevent that.
    """
    snapshots = {
        "complete": [_snap(), _snap(recv=58)],
        "degraded": [_snap(), _snap(drop=7, recv=58)],
        # No counters at all — the state a real replay produces unaided.
        "unknown": [DropSnapshot(source="none"), DropSnapshot(source="none")],
    }[expected]
    batch, report = _collect("pi-a", snapshots)
    assert report.window.coverage.value == expected
    _ingest(store, batch, report.to_dict())

    assert store.recent_windows("pi-a")[0]["coverage"] == expected
    asset = estate.merge(store.all_assets(), store.collector_sites())[0]
    assert asset.coverage == expected

    summary = ingest.summarise_coverage("pi-a", store.recent_windows("pi-a"),
                                        store.recent_gaps("pi-a"))
    assert summary.trustworthy is (expected == "complete")


# ── the merge trap, through the whole stack ────────────────────────────────

def test_the_same_pcap_at_two_sites_stays_two_estates_worth_of_assets(store):
    """The trap, end to end rather than in a unit test with hand-built dicts:
    identical traffic at two plants must not fuse into one inventory."""
    for cid, site in (("pi-a", "Substation A"), ("pi-b", "Substation B")):
        batch, report = _collect(cid, [_snap(), _snap(recv=58)])
        store.set_site(cid, site)
        _ingest(store, batch, report.to_dict())

    per_collector = store.all_assets()
    merged = estate.merge(per_collector, store.collector_sites())
    assert len(merged) == len(per_collector), (
        "assets from two different plants were fused: %d rows became %d"
        % (len(per_collector), len(merged)))
    assert {a.site for a in merged} == {"Substation A", "Substation B"}


def test_the_same_pcap_at_one_site_does_merge(store):
    """The other half of the rule: two collectors with overlapping SPANs at the
    same plant see one device, not two."""
    for cid in ("pi-a1", "pi-a2"):
        batch, report = _collect(cid, [_snap(), _snap(recv=58)])
        store.set_site(cid, "Substation A")
        _ingest(store, batch, report.to_dict())

    merged = estate.merge(store.all_assets(), store.collector_sites())
    assert len(merged) < len(store.all_assets())
    assert all(a.seen_by == 2 for a in merged)


# ── idempotency, with a real batch id ──────────────────────────────────────

def test_replaying_a_real_batch_does_not_double_count(store):
    """A retry after a lost acknowledgement. The id is content-derived by the
    collector and enforced by a unique constraint in the database."""
    batch, report = _collect("pi-a", [_snap(), _snap(recv=58)])
    _ingest(store, batch, report.to_dict())
    before = len(store.all_assets())

    second = ingest.decide(batch.to_dict(), _Known(store))
    assert second.verdict is ingest.Verdict.DUPLICATE
    assert len(store.all_assets()) == before


# ── a spooled batch is the same batch ──────────────────────────────────────

def test_a_batch_survives_the_spool_unchanged(store, tmp_path):
    """The collector persists batches to disk before sending. A round trip
    through the spool must not alter what the server receives."""
    batch, report = _collect("pi-a", [_snap(), _snap(recv=58)])
    spool = Spool(str(tmp_path / "spool"))
    spool.append(batch.to_dict())
    name, restored = spool.peek()

    assert restored == batch.to_dict(), "the spool changed the batch"
    assert ingest.validate(restored) is None


# ── the JSON the console consumes ──────────────────────────────────────────

def test_the_api_shape_matches_the_console_interfaces(store):
    """Nothing has ever compared the TypeScript interfaces with the JSON the
    server emits — they were written from the Python by eye."""
    import json
    import re

    batch, report = _collect("pi-a", [_snap(), _snap(recv=58)])
    store.set_site("pi-a", "Substation A")
    _ingest(store, batch, report.to_dict())

    asset = estate.merge(store.all_assets(), store.collector_sites())[0].to_dict()

    ts_path = os.path.join(_ROOT, "console", "src", "api.ts")
    with open(ts_path, encoding="utf-8") as fh:
        block = re.search(r"interface EstateAssetRow \{(.*?)\}", fh.read(), re.S)
    assert block, "EstateAssetRow interface not found"
    declared = set(re.findall(r"^\s*(\w+)\s*[?:]", block.group(1), re.M))

    missing = declared - set(asset)
    assert not missing, (
        "the console expects fields the API does not emit: %s" % sorted(missing))

    # Round-trips as JSON: the console receives this over the wire.
    json.loads(json.dumps(asset, default=str))


def test_the_vulnerability_shape_matches_too(store):
    batch, report = _collect("pi-a", [_snap(), _snap(recv=58)])
    _ingest(store, batch, report.to_dict())
    assets = [a.to_dict()
              for a in estate.merge(store.all_assets(), store.collector_sites())]
    matches = vulnmatch.match_estate(assets, vulnmatch.load_corpus())
    assert matches
    for key in ("estate_id", "state", "priority", "corpus_version",
                "observation_coverage", "note", "hits"):
        assert key in matches[0].to_dict(), "VulnMatch is missing %s" % key
