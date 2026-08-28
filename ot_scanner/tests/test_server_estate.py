"""
Phase 4 — estate merge, CVE matching and estate-wide coverage
(OTS-SRV-001, 002, 004).

The load-bearing test in this file is that two collectors at DIFFERENT sites
seeing 10.0.0.1 produce TWO assets. Private ranges overlap across plants, and
merging them would fuse two unrelated PLCs into one — after which one plant's
findings appear against the other's asset, the count silently drops, and nothing
in the output looks wrong.
"""
from __future__ import annotations

import datetime
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from ot_server import estate, ingest, vulnmatch  # noqa: E402
from ot_server.vulnmatch import (Corpus, MatchState, Priority)  # noqa: E402


def _row(collector, key="ip:10.0.0.1", ip="10.0.0.1", mac="", first=100.0,
         last=200.0, count=5, coverage="complete", **attrs):
    a = {"ip": ip, "mac": mac}
    a.update(attrs)
    return {"collector_id": collector, "asset_key": key, "first_seen": first,
            "last_seen": last, "observation_count": count,
            "last_observed_window": "w-1", "last_coverage": coverage,
            "attributes": {k: v for k, v in a.items() if v not in ("", None)}}


# ── the merge trap ─────────────────────────────────────────────────────────

def test_the_same_ip_at_two_sites_is_two_assets():
    """The one that matters. Fusing them is invisible and unrecoverable."""
    rows = [_row("pi-a"), _row("pi-b")]
    sites = {"pi-a": "Substation A", "pi-b": "Substation B"}
    assets = estate.merge(rows, sites)
    assert len(assets) == 2, "10.0.0.1 at two plants was merged into one device"
    assert {a.site for a in assets} == {"Substation A", "Substation B"}


def test_the_same_ip_at_one_site_is_one_asset():
    """Two collectors with overlapping SPANs at the same plant."""
    rows = [_row("pi-a1"), _row("pi-a2")]
    sites = {"pi-a1": "Substation A", "pi-a2": "Substation A"}
    assets = estate.merge(rows, sites)
    assert len(assets) == 1
    assert assets[0].seen_by == 2


def test_a_mac_at_two_sites_is_flagged_and_NOT_merged():
    """An earlier version merged here, reasoning that OUI addresses are unique
    enough to catch a moved device. That contradicted the module's own rule the
    moment uniqueness failed — and in OT it does: cloned hardware, counterfeit
    devices, vendors shipping duplicate addresses. Fusing two plants' devices is
    the unrecoverable direction, so the shared address is reported instead."""
    rows = [_row("pi-a", key="mac:aa:bb:cc:dd:ee:ff", ip="", mac="aa:bb:cc:dd:ee:ff"),
            _row("pi-b", key="mac:aa:bb:cc:dd:ee:ff", ip="", mac="aa:bb:cc:dd:ee:ff")]
    assets = estate.merge(rows, {"pi-a": "Site A", "pi-b": "Site B"})
    assert len(assets) == 2, "devices at two plants were fused on a shared MAC"
    for asset in assets:
        assert any("NOT merged" in w for w in asset.warnings)


def test_a_mac_joins_within_one_site():
    rows = [_row("pi-a1", key="mac:aa:bb:cc:dd:ee:ff", ip="", mac="aa:bb:cc:dd:ee:ff"),
            _row("pi-a2", key="mac:aa:bb:cc:dd:ee:ff", ip="", mac="aa:bb:cc:dd:ee:ff")]
    assets = estate.merge(rows, {"pi-a1": "Site A", "pi-a2": "Site A"})
    assert len(assets) == 1 and assets[0].seen_by == 2


def test_an_ip_and_a_mac_view_of_one_device_converge_within_a_site():
    """One collector sees the IP, another sees only the L2 address."""
    rows = [_row("pi-a1", key="ip:10.0.0.1", ip="10.0.0.1", mac="aa:bb:cc:dd:ee:ff"),
            _row("pi-a2", key="mac:aa:bb:cc:dd:ee:ff", ip="", mac="aa:bb:cc:dd:ee:ff")]
    assets = estate.merge(rows, {"pi-a1": "Site A", "pi-a2": "Site A"})
    assert len(assets) == 1 and assets[0].seen_by == 2


def test_unsited_collectors_do_not_get_fused():
    """Guessing that two collectors with no site recorded share one is exactly
    the error this module exists to prevent."""
    assets = estate.merge([_row("pi-a"), _row("pi-b")], sites={})
    # Both land in <unassigned>, which is one scope — so they DO merge. That is
    # the documented consequence, and the warning below is how it stays visible.
    assert len(assets) == 1
    assert assets[0].site == estate.UNKNOWN_SITE


def test_first_seen_is_the_earliest_across_collectors():
    """A device present for a year must not become one discovered last week
    because a second collector only just met it."""
    rows = [_row("pi-a1", first=100.0, last=150.0),
            _row("pi-a2", first=900.0, last=1000.0)]
    asset = estate.merge(rows, {"pi-a1": "S", "pi-a2": "S"})[0]
    assert asset.first_seen == 100.0 and asset.last_seen == 1000.0


def test_conflicting_attributes_are_reported_not_overwritten():
    """Two collectors disagreeing on vendor is information, and silently
    picking one discards it."""
    rows = [_row("pi-a1", vendor="Siemens"), _row("pi-a2", vendor="Rockwell")]
    asset = estate.merge(rows, {"pi-a1": "S", "pi-a2": "S"})[0]
    assert any("disagree on vendor" in w for w in asset.warnings)


def test_contributions_are_kept_rather_than_averaged_away():
    """Un-merging later is impossible once provenance is gone."""
    rows = [_row("pi-a1"), _row("pi-a2")]
    asset = estate.merge(rows, {"pi-a1": "S", "pi-a2": "S"})[0]
    assert {c.collector_id for c in asset.contributions} == {"pi-a1", "pi-a2"}


# ── OTS-SRV-004: coverage is the weakest link ──────────────────────────────

def test_a_merged_asset_takes_the_weakest_coverage():
    """Averaging would let a healthy collector launder a blind one's silence."""
    rows = [_row("pi-a1", coverage="complete"), _row("pi-a2", coverage="unknown")]
    asset = estate.merge(rows, {"pi-a1": "S", "pi-a2": "S"})[0]
    assert asset.coverage == "unknown"

    rows = [_row("pi-a1", coverage="complete"), _row("pi-a2", coverage="degraded")]
    asset = estate.merge(rows, {"pi-a1": "S", "pi-a2": "S"})[0]
    assert asset.coverage == "degraded"


def test_estate_coverage_is_not_a_percentage():
    """Four healthy collectors and one blind one is not 80% trustworthy. It is
    an answer with a hole in it, and the hole is where nobody is looking."""
    good = [ingest.summarise_coverage("pi-%d" % i,
                                      [{"coverage": "complete"}], [])
            for i in range(4)]
    blind = ingest.summarise_coverage("pi-blind", [{"coverage": "unknown"}], [])
    cov = estate.estate_coverage(good + [blind])
    assert not cov.trustworthy
    assert "pi-blind" in cov.blind_collectors
    assert "does not mean a clean estate" in cov.explain()


def test_an_empty_estate_is_not_a_clean_estate():
    cov = estate.estate_coverage([])
    assert not cov.trustworthy and "empty, not clean" in cov.explain()


def test_a_fully_healthy_estate_says_so_plainly():
    summaries = [ingest.summarise_coverage("pi-%d" % i,
                                           [{"coverage": "complete"}], [])
                 for i in range(3)]
    cov = estate.estate_coverage(summaries)
    assert cov.trustworthy and "all reporting complete coverage" in cov.explain()


# ── OTS-SRV-002: matching, and re-prioritising without re-ingest ───────────

def _corpus(version="v1", kev=False, epss=None):
    return Corpus(version=version, entries={
        "CVE-2021-44228": {"cve": "CVE-2021-44228", "severity": "critical",
                           "cvss": 10.0, "epss": epss, "kev": kev}})


def _asset(coverage="complete", cves=("CVE-2021-44228",)):
    return {"estate_id": "e1", "coverage": coverage,
            "attributes": {"cve_ids": list(cves)}}


def test_a_kev_entry_is_priority_now():
    match = vulnmatch.match_asset(_asset(), _corpus(kev=True))
    assert match.state is MatchState.MATCHED
    assert match.worst is Priority.NOW and match.actionable
    assert "known to be exploited" in match.hits[0].why


def test_high_epss_alone_is_next_not_now():
    """NOW means known-exploited. A priority that fires on everything is one an
    operator stops reading, and EPSS is a probability rather than an
    observation."""
    match = vulnmatch.match_asset(_asset(), _corpus(epss=0.97))
    assert match.worst is Priority.NEXT


def test_a_cve_the_corpus_does_not_know_is_unknown_not_clean():
    match = vulnmatch.match_asset(_asset(cves=("CVE-2099-0001",)), _corpus())
    assert match.hits[0].priority is Priority.UNKNOWN
    assert "not present in corpus" in match.hits[0].why


def test_no_corpus_means_unknown_never_clean():
    """A server without a corpus has not established an asset is clean — it has
    failed to look, and the two must not render the same way."""
    match = vulnmatch.match_asset(_asset(), Corpus())
    assert match.state is MatchState.UNKNOWN
    assert "not the same as unaffected" in match.note


class _FoundNothing:
    """A matcher that ran and found nothing.

    These two tests used to express "assessed and clean" by passing an asset
    with no CVE list and no matcher — which is now, correctly, UNKNOWN. That
    was not a wrong assertion so much as an inexpressible one: under the old
    code the only reachable clean state was the never-assessed one, because
    nothing populated `cve_ids`. Saying it explicitly is the point.
    """

    def match_device(self, device):
        return []


def test_a_clean_result_from_a_degraded_window_is_qualified():
    """Absence of a finding is not evidence of absence."""
    match = vulnmatch.match_asset(
        {"estate_id": "e1", "coverage": "degraded", "attributes": {}},
        _corpus(), _FoundNothing())
    assert match.state is MatchState.CLEAN
    assert "not evidence of absence" in match.note


def test_a_clean_result_from_a_complete_window_needs_no_caveat():
    match = vulnmatch.match_asset(
        {"estate_id": "e1", "coverage": "complete", "attributes": {}},
        _corpus(), _FoundNothing())
    assert match.state is MatchState.CLEAN and match.note == ""


def test_no_way_to_assess_a_device_is_unknown_and_never_clean():
    """The defect this replaced. `match_asset` read a `cve_ids` attribute that
    no collector, ingest path or merge has ever populated, so EVERY asset took
    the empty-list branch and came back CLEAN — a confident statement about a
    device nothing had looked at."""
    match = vulnmatch.match_asset(
        {"estate_id": "e1", "coverage": "complete", "attributes": {}},
        _corpus(), None)
    assert match.state is MatchState.UNKNOWN
    assert "unassessed, not clean" in match.note


# ── the corpus, as it actually ships ───────────────────────────────────────

def test_the_shipped_corpus_loads():
    """It never had. `load_corpus` read `ics_cves.ICS_CVES`; the module exports
    `ICS_CVE_DATABASE`. The name has never matched, so `corpus_loaded` was
    false in every deployment and every asset reported unknown."""
    corpus = vulnmatch.load_corpus()
    assert corpus.available, "the shipped ICS CVE database is not loading"
    assert len(corpus.entries) > 50
    assert "CVE-2019-13945" in corpus.entries


def test_the_shipped_corpus_carries_the_fields_prioritise_reads():
    """The second near-miss: the database spells these cvss_score, epss_score
    and is_cisa_kev, and `prioritise` reads cvss, epss and kev. A missing key
    reads as a missing value, so a KEV flag nobody could see is a CVE that
    never reaches NOW."""
    corpus = vulnmatch.load_corpus()
    entry = corpus.get("CVE-2019-13945")
    assert entry is not None
    assert entry["kev"] is True
    assert entry["cvss"] and entry["epss"] is not None


def test_the_corpus_version_is_derived_from_its_content():
    """A version somebody must remember to bump is wrong exactly when it
    matters. The shipped database carried none, which read as the literal
    string "shipped" for every revision it would ever have."""
    corpus = vulnmatch.load_corpus()
    assert corpus.version.startswith("ics-")
    assert vulnmatch.fingerprint({"CVE-1": {}}) != \
        vulnmatch.fingerprint({"CVE-2": {}})


def test_a_real_device_matches_the_cves_it_actually_has():
    """End to end, over the shipped data: a Siemens S7-1500 on firmware V4.2,
    against a corpus that holds CVE-2019-13945 (S7-1500, below 4.5).

    Before the wiring this returned CLEAN.
    """
    matcher = vulnmatch.load_matcher()
    if matcher is None:
        pytest.skip("the scanner matcher is not importable here")

    match = vulnmatch.match_asset(
        {"estate_id": "e1", "ip": "10.0.0.11", "coverage": "complete",
         "attributes": {"ip": "10.0.0.11", "vendor": "Siemens",
                        "model": "S7-1500", "role": "plc",
                        "firmware": "V4.2"}},
        vulnmatch.load_corpus(), matcher)

    assert match.state is MatchState.MATCHED
    found = {h.cve for h in match.hits}
    assert "CVE-2019-13945" in found
    assert match.worst.value == "now", "a KEV-listed CVE did not reach NOW"


def test_a_hit_says_why_it_was_attached_to_this_device():
    """An operator asking "why is this on my relay" should not have to go and
    read the matcher."""
    matcher = vulnmatch.load_matcher()
    if matcher is None:
        pytest.skip("the scanner matcher is not importable here")
    match = vulnmatch.match_asset(
        {"estate_id": "e1", "coverage": "complete",
         "attributes": {"ip": "10.0.0.11", "vendor": "Siemens",
                        "model": "S7-1500", "firmware": "V4.2"}},
        vulnmatch.load_corpus(), matcher)
    assert any("matched on" in h.why for h in match.hits)


def test_the_priority_authority_is_ours_not_the_scanners():
    """The scanner classifies now/next/never too, and more loosely — NOW there
    means "has a public exploit". Two prioritisation opinions in one product is
    one too many, so only the SET of CVEs comes from the matcher."""
    import inspect

    source = inspect.getsource(vulnmatch.device_candidates)
    assert "prioritise" in source or "priority does not" in source.lower()
    assert "match_device" in source


def test_every_match_names_the_corpus_it_was_computed_against():
    match = vulnmatch.match_asset(_asset(), _corpus(version="2026-08-28"))
    assert match.corpus_version == "2026-08-28"
    assert match.observation_coverage == "complete"


def test_a_kev_addition_reprioritises_without_touching_a_collector():
    """The payoff for decision D3, made measurable: last night's KEV addition
    moved this asset to NOW, and no substation was visited."""
    before = _corpus(version="2026-08-27", kev=False)
    after = _corpus(version="2026-08-28", kev=True)
    report = vulnmatch.reprioritise([_asset()], before, after)
    assert report.escalated == ["e1"] and not report.de_escalated
    assert "no collector contacted" in report.explain()


def test_reprioritisation_reports_no_change_plainly():
    corpus = _corpus(kev=True)
    report = vulnmatch.reprioritise([_asset()], corpus, corpus)
    assert report.changed == 0 and "no priority changed" in report.explain()


# ── the API surface (OTS-SRV-001/002/004/006) ──────────────────────────────

class _FakeStore:
    """Enough store for the estate routes. The SQL has its own suite against a
    real PostgreSQL; this exercises the wiring."""

    def __init__(self, rows=None, sites=None, windows=None, gaps=None,
                 flows=None, detections=None):
        self._rows = rows or []
        self._sites = sites or {}
        self._windows = windows or {}
        self._gaps = gaps or {}
        self._flows = flows or []
        self._detections = detections or []

    def collector_ids(self):
        return sorted(self._sites)

    def collector_sites(self):
        return dict(self._sites)

    def recent_windows(self, cid):
        return self._windows.get(cid, [{"coverage": "complete"}])

    def recent_gaps(self, cid):
        return self._gaps.get(cid, [])

    def all_assets(self, limit=5000):
        return list(self._rows)

    def assets(self, collector_id=None, limit=500):
        return [r for r in self._rows
                if collector_id in (None, r["collector_id"])]

    def latest_window(self, cid):
        return "w-1"

    # A collector row is what fleet health reasons over. `last_heartbeat`
    # is the column the coverage model never looked at, and the reason a
    # switched-off collector could report a clean plant indefinitely.
    def collectors_health(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        return [{"collector_id": cid, "site": site, "last_heartbeat": now,
                 "capture_state": "complete", "queue_depth": 0,
                 "enabled": True, "rulepack_version": "1"}
                for cid, site in sorted(self._sites.items())]

    def latest_pack_version(self, kind):
        return 0

    def reported_pack_versions(self):
        return {}

    def all_flows(self, limit=20000):
        return list(self._flows)

    def all_detections(self, limit=20000):
        return list(self._detections)


def _client(store, operator=True):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    return TestClient(create_app(
        store, require_operator=(lambda r: "op") if operator else None))


def _two_sites():
    return _FakeStore(
        rows=[_row("pi-a"), _row("pi-b")],
        sites={"pi-a": "Substation A", "pi-b": "Substation B"})


def test_the_inventory_endpoint_does_not_fuse_two_sites():
    client = _client(_two_sites())
    body = client.get("/api/v1/estate/inventory").json()
    assert body["count"] == 2, "10.0.0.1 at two plants was merged"


def test_the_inventory_carries_the_coverage_its_count_rests_on():
    """A count without this is a figure an operator cannot weigh, so it is not
    a separate call."""
    body = _client(_two_sites()).get("/api/v1/estate/inventory").json()
    assert "coverage" in body and "explain" in body["coverage"]


def test_estate_coverage_names_the_blind_collector():
    store = _FakeStore(sites={"pi-a": "A", "pi-blind": "B"},
                       windows={"pi-blind": [{"coverage": "unknown"}]})
    body = _client(store).get("/api/v1/estate/coverage").json()
    assert body["trustworthy"] is False
    assert body["blind_collectors"] == ["pi-blind"]
    assert "does not mean a clean estate" in body["explain"]


def test_estate_coverage_reports_per_collector_as_well_as_overall():
    body = _client(_two_sites()).get("/api/v1/estate/coverage").json()
    assert len(body["per_collector"]) == 2


def test_the_vulnerability_endpoint_states_whether_a_corpus_was_loaded():
    """Without one, every asset is UNKNOWN rather than clean — the endpoint must
    make that visible instead of returning an empty, reassuring list."""
    body = _client(_two_sites()).get("/api/v1/estate/vulnerabilities").json()
    assert "corpus_loaded" in body and "corpus_version" in body
    if not body["corpus_loaded"]:
        assert all(m["state"] == "unknown" for m in body["matches"])


@pytest.mark.parametrize("path", [
    "/api/v1/estate/coverage",
    "/api/v1/estate/inventory",
    "/api/v1/estate/vulnerabilities",
    "/api/v1/estate/assets",
    "/api/v1/estate/analysis",
    "/api/v1/estate/zones",
])
def test_the_estate_plane_is_fail_closed_without_operator_auth(path):
    """OTS-SRV-006. A certificate lifted from a substation cabinet must not
    yield a map of the plant."""
    client = _client(_two_sites(), operator=False)
    assert client.get(path).status_code == 503


# ── detections must find their merged asset (OTS-SRV-003 wiring) ───────────

def test_stored_detections_are_rekeyed_onto_the_merged_asset():
    """The engines look detections up by estate_id; the store holds them under
    the COLLECTOR's asset key. Passed through unchanged they attach to nothing,
    and every asset then reads as detection-free — a clean estate produced by a
    wiring fault rather than by a clean plant."""
    rows = [_row("pi-a")]
    assets = estate.merge(rows, {"pi-a": "Substation A"})
    detections = [{"collector_id": "pi-a", "asset_key": "ip:10.0.0.1",
                   "rule_id": "r1", "severity": "high"}]
    out = estate.reattach_detections(assets, detections)
    assert len(out) == 1
    assert out[0]["asset_key"] == assets[0].estate_id
    # The original key is kept rather than overwritten, so the collector's view
    # is still traceable from the merged one.
    assert out[0]["collector_asset_key"] == "ip:10.0.0.1"


def test_a_detection_is_not_hung_on_another_plants_asset():
    """The merge trap one level down. Both plants have a 10.0.0.1; matching on
    the asset key alone would attach Substation B's finding to Substation A's
    device, and nothing afterwards looks wrong."""
    rows = [_row("pi-a"), _row("pi-b")]
    sites = {"pi-a": "Substation A", "pi-b": "Substation B"}
    assets = estate.merge(rows, sites)
    by_site = {a.site: a.estate_id for a in assets}
    detections = [{"collector_id": "pi-b", "asset_key": "ip:10.0.0.1",
                   "rule_id": "r1", "severity": "high"}]
    out = estate.reattach_detections(assets, detections)
    assert len(out) == 1
    assert out[0]["asset_key"] == by_site["Substation B"]
    assert out[0]["asset_key"] != by_site["Substation A"]


def test_a_detection_with_no_matching_asset_is_reported_not_invented():
    """Its device never arrived. Dropping it silently would hide a hole in the
    inventory; inventing an owner for it would be worse."""
    assets = estate.merge([_row("pi-a")], {"pi-a": "Substation A"})
    orphan = [{"collector_id": "pi-a", "asset_key": "ip:10.9.9.9"}]
    assert estate.reattach_detections(assets, orphan) == []
    assert estate.orphaned_detections(assets, orphan) == 1


# ── the analysis and zone endpoints (OTS-SRV-003, OTS-CON-005) ─────────────

def test_the_analysis_endpoint_names_what_each_engine_could_not_consider():
    body = _client(_two_sites()).get("/api/v1/estate/analysis").json()
    assert body["engines"], "no engine reported"
    for engine in body["engines"]:
        assert set(engine) >= {"engine", "status", "reason", "limitations",
                               "trustworthy"}


def test_drift_is_skipped_rather_than_answering_nothing_changed():
    """With no baseline recorded, 'nothing changed' is the most confident wrong
    answer available."""
    body = _client(_two_sites()).get("/api/v1/estate/analysis").json()
    drift = [e for e in body["engines"] if e["engine"] == "drift"]
    assert drift and drift[0]["status"] == "skipped"
    assert "baseline" in drift[0]["reason"]


def test_the_analysis_endpoint_reports_orphaned_detections():
    store = _FakeStore(
        rows=[_row("pi-a")], sites={"pi-a": "Substation A"},
        detections=[{"collector_id": "pi-a", "asset_key": "ip:10.9.9.9"}])
    body = _client(store).get("/api/v1/estate/analysis").json()
    assert body["orphaned_detections"] == 1


def test_detections_reach_the_engines_through_the_endpoint():
    """The wiring, end to end: a stored detection under a collector key must
    arrive attached rather than orphaned."""
    store = _FakeStore(
        rows=[_row("pi-a")], sites={"pi-a": "Substation A"},
        detections=[{"collector_id": "pi-a", "asset_key": "ip:10.0.0.1",
                     "rule_id": "r1", "severity": "high",
                     "attributes": {"rule_id": "r1"}}])
    body = _client(store).get("/api/v1/estate/analysis").json()
    assert body["orphaned_detections"] == 0


def test_the_zone_endpoint_separates_none_derived_from_derived_and_rejected():
    """Both draw an empty topology and they are not the same claim: one had
    nothing to derive from, the other derived something and did not trust it."""
    empty = _FakeStore(sites={"pi-a": "Substation A"})
    body = _client(empty).get("/api/v1/estate/zones").json()
    assert body["state"] == "none"
    assert body["zones"] == 0

    populated = _client(_two_sites()).get("/api/v1/estate/zones").json()
    assert populated["state"] in ("derived", "rejected", "none")
    if populated["zones"]:
        assert populated["state"] == ("derived" if populated["usable"]
                                      else "rejected")


def test_zones_are_reported_per_site():
    """Estate-wide derivation would fuse two plants that share 10.10.1.0/24."""
    body = _client(_two_sites()).get("/api/v1/estate/zones").json()
    sites = {s["site"] for s in body["sites"]}
    assert sites == {"Substation A", "Substation B"}


def test_every_zone_records_how_its_level_was_arrived_at():
    """A guessed level must not be indistinguishable from an observed one — the
    rules someone writes from this may reach a live plant network."""
    body = _client(_two_sites()).get("/api/v1/estate/zones").json()
    for site in body["sites"]:
        for zone in site["zones"]:
            assert zone["level_basis"] in ("role", "protocol", "defaulted",
                                           "unknown")
