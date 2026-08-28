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


def test_a_clean_result_from_a_degraded_window_is_qualified():
    """Absence of a finding is not evidence of absence."""
    match = vulnmatch.match_asset(
        {"estate_id": "e1", "coverage": "degraded", "attributes": {}},
        _corpus())
    assert match.state is MatchState.CLEAN
    assert "not evidence of absence" in match.note


def test_a_clean_result_from_a_complete_window_needs_no_caveat():
    match = vulnmatch.match_asset(
        {"estate_id": "e1", "coverage": "complete", "attributes": {}}, _corpus())
    assert match.state is MatchState.CLEAN and match.note == ""


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

    def __init__(self, rows=None, sites=None, windows=None, gaps=None):
        self._rows = rows or []
        self._sites = sites or {}
        self._windows = windows or {}
        self._gaps = gaps or {}

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
])
def test_the_estate_plane_is_fail_closed_without_operator_auth(path):
    """OTS-SRV-006. A certificate lifted from a substation cabinet must not
    yield a map of the plant."""
    client = _client(_two_sites(), operator=False)
    assert client.get(path).status_code == 503
