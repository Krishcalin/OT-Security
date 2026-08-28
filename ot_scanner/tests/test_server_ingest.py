"""
Phase 3 (server half) — ingest rules and the estate API.

The rules that decide what the server BELIEVES are pure functions, so they are
tested here without a database or a driver. The SQL that stores those beliefs is
tested separately against a real PostgreSQL (`test_server_store.py`), because a
hand-written test double for a database is a second implementation that passes
while production fails.

The behaviour under test throughout: the server must be able to distinguish
"we looked and saw nothing" from "we did not look". The collector goes to
considerable trouble to report degraded windows and delivery gaps; accepting
that and then rendering a continuous timeline would discard it at the last step
and make every safeguard upstream decorative.
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from ot_server import ingest  # noqa: E402
from ot_server.api import AuthError, collector_identity  # noqa: E402
from ot_server.ingest import AssetState, Verdict  # noqa: E402


def _batch(bid="b1", window="w-1", coverage="complete", records=None):
    return {"batch_id": bid, "collector_id": "pi-01", "window_id": window,
            "coverage": coverage,
            "records": records if records is not None else
            [{"key": "ip:10.0.0.1", "kind": "asset", "attributes": {},
              "provenance": {}}]}


# ── validation is loud and specific ────────────────────────────────────────

@pytest.mark.parametrize("missing", ["batch_id", "collector_id", "window_id"])
def test_a_batch_without_identity_is_rejected(missing):
    payload = _batch()
    del payload[missing]
    assert ingest.validate(payload) == "missing %s" % missing


def test_an_unknown_coverage_value_is_rejected_not_normalised():
    """The whole point of the field is that its three states mean different
    things. Coercing an unrecognised value to "complete" would invent the one
    claim the system exists to avoid making."""
    problem = ingest.validate(_batch(coverage="probably-fine"))
    assert problem and "coverage" in problem


def test_a_record_without_a_key_is_rejected():
    assert "no key" in ingest.validate(
        _batch(records=[{"kind": "asset"}]))


def test_a_record_of_unknown_kind_is_rejected():
    assert "unknown kind" in ingest.validate(
        _batch(records=[{"key": "x", "kind": "telemetry"}]))


def test_an_oversized_batch_is_rejected():
    big = [{"key": "k%d" % i, "kind": "asset"}
           for i in range(ingest.MAX_RECORDS_PER_BATCH + 1)]
    assert "exceeds" in ingest.validate(_batch(records=big))


# ── OTS-TRN-004: a replay is a success ─────────────────────────────────────

def test_a_new_batch_is_accepted():
    d = ingest.decide(_batch(), known_batch_ids=set())
    assert d.verdict is Verdict.ACCEPT and d.http_status == 202


def test_a_replayed_batch_is_a_duplicate_not_an_error():
    """A retry whose first acknowledgement was lost must be able to clear its
    queue, or it resends forever."""
    d = ingest.decide(_batch(bid="b1"), known_batch_ids={"b1"})
    assert d.verdict is Verdict.DUPLICATE
    assert d.http_status == 409 and d.ok


def test_a_malformed_batch_is_rejected_rather_than_partly_stored():
    """A server that quietly stores part of a bad batch produces an inventory
    nobody can account for, and the collector — believing it delivered — never
    resends."""
    d = ingest.decide({"batch_id": "b", "records": "not-a-list"}, set())
    assert d.verdict is Verdict.REJECT and d.http_status == 400


# ── the delivery gap is honoured, not merely accepted ──────────────────────

def test_a_gap_payload_is_recognised():
    gap = {"kind": "delivery_gap", "batches_lost": 3, "records_lost": 12,
           "first_window": "w-0", "last_window": "w-2"}
    d = ingest.decide({"gap": gap, "collector_id": "pi-01"}, set())
    assert d.verdict is Verdict.ACCEPT
    assert d.gap["records_lost"] == 12


def test_a_gap_without_a_collector_cannot_be_attributed():
    assert "attributed" in ingest.validate({"gap": {"batches_lost": 1}})


def test_coverage_counts_a_gap_against_trustworthiness():
    """This is the join between the two halves. A collector whose windows were
    all complete but which LOST windows in transit has not delivered a complete
    picture, and the estate view must not say it did."""
    windows = [{"coverage": "complete"} for _ in range(5)]
    clean = ingest.summarise_coverage("pi-01", windows, [])
    assert clean.trustworthy

    with_gap = ingest.summarise_coverage(
        "pi-01", windows, [{"records_lost": 12, "batches_lost": 3}])
    assert not with_gap.trustworthy
    assert "never arrived" in with_gap.explain()


def test_a_degraded_window_makes_the_collector_untrustworthy():
    summary = ingest.summarise_coverage(
        "pi-01", [{"coverage": "complete"}, {"coverage": "degraded"}], [])
    assert not summary.trustworthy and "degraded" in summary.explain()


def test_no_windows_means_nothing_may_be_called_clean():
    summary = ingest.summarise_coverage("pi-01", [], [])
    assert not summary.trustworthy
    assert "may be reported as clean" in summary.explain()


def test_the_three_states_are_reported_separately_not_averaged():
    """A run of unknown windows and a run of complete ones are not two points
    on one scale; averaging them produces a number that means nothing."""
    summary = ingest.summarise_coverage(
        "pi-01", [{"coverage": "complete"}, {"coverage": "degraded"},
                  {"coverage": "unknown"}], [])
    assert (summary.complete, summary.degraded, summary.unknown) == (1, 1, 1)


# ── OTS-SRV-005: absence is a state, not a deletion ────────────────────────

def test_an_asset_absent_from_the_latest_window_is_not_observed():
    """A passive sensor cannot tell a decommissioned device from one that did
    not speak. Deleting on absence would make a quiet PLC vanish."""
    assert ingest.asset_state("w-5", "w-9") is AssetState.NOT_OBSERVED
    assert ingest.asset_state("w-9", "w-9") is AssetState.OBSERVED


def test_with_no_latest_window_an_asset_is_not_marked_missing():
    """Before anything has been received, "not observed" would be a claim about
    a window that does not exist."""
    assert ingest.asset_state("w-1", "") is AssetState.OBSERVED


# ── OTS-SRV-006 / OTS-TRN-002: identity comes from the certificate ─────────

def test_the_collector_identity_comes_from_the_client_certificate():
    ident = collector_identity({"X-Client-Subject": "CN=pi-substation-01,O=Acme"})
    assert ident == "pi-substation-01"


def test_a_request_without_a_verified_identity_is_refused():
    """These endpoints are reachable only through the mTLS terminator."""
    with pytest.raises(AuthError):
        collector_identity({"X-Collector-Id": "pi-01"})


def test_the_payload_cannot_choose_the_collector_identity():
    """A collector able to name itself in the body could impersonate another
    site and poison its inventory, and the request would look ordinary."""
    import inspect

    from ot_server import api

    src = inspect.getsource(api.create_app)
    assert "payload claims collector_id" in src
    assert 'payload["collector_id"] = collector' in src


def test_the_estate_api_is_fail_closed_without_operator_auth():
    """Ingest credentials must not grant console access (OTS-SRV-006). Until an
    operator check is wired, the estate plane refuses rather than serving."""
    import inspect

    from ot_server import api

    src = inspect.getsource(api.create_app)
    assert "fail-closed" in src and "503" in src
