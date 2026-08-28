"""
Containment — what to do about a vulnerability you cannot patch.

Three tests carry this file, and all three are refusals.

`test_a_guessed_zone_produces_no_rule` — a firewall rule built on a boundary the
topology engine defaulted to may be applied to a live plant network by somebody
who trusts it. The same line D6 draws for the policy engine, drawn per zone.

`test_a_device_nobody_has_seen_talking_gets_no_allow_list` — an allow-list for a
device with no observed traffic is a list somebody invented, and applying it is
as likely to cut control communication as to contain anything.

`test_the_rule_always_says_what_it_cannot_see` — passive observation sees what
spoke. The quarterly maintenance laptop did not, and a deny-everything-else rule
will deny it. A firewall change handed over without that sentence is an outage
with a delay fuse.
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
_SCANNER = os.path.join(_ROOT, "ot_scanner")
if _SCANNER not in sys.path:
    sys.path.insert(0, _SCANNER)

from ot_server import containment                           # noqa: E402
from ot_server.zones import SiteTopology                    # noqa: E402
from scanner.models import NetworkZone                      # noqa: E402


def _zone(zone_id="zone_10.0.0.0/24", subnet="10.0.0.0/24", level=1,
          ips=("10.0.0.11", "10.0.0.12")):
    return NetworkZone(zone_id=zone_id, subnet=subnet, purdue_level=level,
                       purdue_label="Basic Control", device_ips=set(ips),
                       device_count=len(ips), dominant_role="plc")


def _topology(basis="role", zones=None, site="Alderley"):
    zones = zones or [_zone()]
    return SiteTopology(site=site, zones=zones,
                        basis_by_zone={z.zone_id: basis for z in zones})


def _flow(src, dst, protocol="s7comm", port=102):
    return {"src_ip": src, "dst_ip": dst, "protocol": protocol, "port": port}


def _asset(estate_id="e1", ip="10.0.0.11", site="Alderley",
           coverage="complete"):
    return {"estate_id": estate_id, "ip": ip, "site": site,
            "coverage": coverage}


def _match(estate_id="e1", state="matched", priority="now", hits=1):
    return {"estate_id": estate_id, "state": state, "priority": priority,
            "hits": [{"cve": "CVE-2026-0001", "priority": priority}] * hits}


# ── the refusals ───────────────────────────────────────────────────────────

def test_a_guessed_zone_produces_no_rule():
    """A level that came from the fallback describes the network no better than
    the subnet does. A rule built on it may reach a live plant."""
    result = containment.contain(
        _match(), _asset(), _topology(basis="defaulted"),
        [_flow("10.0.0.60", "10.0.0.11")])
    assert result.state == containment.REFUSED
    assert result.rules == []
    assert "guessed boundary" in result.reason
    assert "live plant network" in result.reason


def test_one_guessed_zone_does_not_suppress_advice_about_a_good_one():
    """Per zone, not per estate. A well-derived neighbour still gets a rule."""
    good = _zone("zone_10.0.0.0/24", "10.0.0.0/24", ips=("10.0.0.11",))
    bad = _zone("zone_10.9.0.0/24", "10.9.0.0/24", ips=("10.9.0.5",))
    topology = SiteTopology(
        site="Alderley", zones=[good, bad],
        basis_by_zone={good.zone_id: "role", bad.zone_id: "defaulted"})

    ok = containment.contain(_match(), _asset(ip="10.0.0.11"), topology,
                             [_flow("10.0.0.60", "10.0.0.11")])
    refused = containment.contain(_match("e2"), _asset("e2", ip="10.9.0.5"),
                                  topology, [_flow("10.9.0.9", "10.9.0.5")])
    assert ok.state == containment.PROPOSED
    assert refused.state == containment.REFUSED


def test_a_device_nobody_has_seen_talking_gets_no_allow_list():
    """Applying an invented allow-list is as likely to cut control traffic as
    to contain anything."""
    result = containment.contain(_match(), _asset(), _topology(), flows=[])
    assert result.state == containment.UNKNOWN
    assert result.rules == []
    assert "would be invented" in result.reason
    assert "nobody is watching" in result.reason


def test_a_device_outside_every_derived_zone_gets_no_rule():
    result = containment.contain(
        _match(), _asset(ip="192.168.50.7"), _topology(),
        [_flow("10.0.0.60", "192.168.50.7")])
    assert result.state == containment.UNKNOWN
    assert "invent the boundary" in result.reason


def test_no_topology_at_all_is_a_refusal_not_a_crash():
    result = containment.contain(_match(), _asset(), None, [])
    assert result.state == containment.UNKNOWN


# ── the rule ───────────────────────────────────────────────────────────────

def test_the_allow_list_comes_first_and_the_deny_last():
    """A bare deny on a controller is an outage. Reading top to bottom must
    read as 'keep these working, stop everything else'."""
    result = containment.contain(
        _match(), _asset(), _topology(),
        [_flow("10.0.0.60", "10.0.0.11"), _flow("10.0.0.61", "10.0.0.11")])
    assert result.state == containment.PROPOSED
    assert [r["action"] for r in result.rules] == ["allow", "allow", "deny"]
    assert result.rules[-1]["src_ip"] == "any"
    assert [r["order"] for r in result.rules] == [1, 2, 3]


def test_every_allow_rule_says_what_denying_it_would_cost():
    result = containment.contain(
        _match(), _asset(), _topology(), [_flow("10.0.0.60", "10.0.0.11")])
    allow = result.rules[0]
    assert "observed traffic" in allow["rationale"]
    assert "happening today" in allow["rationale"]


def test_the_deny_names_what_it_is_containing():
    result = containment.contain(
        _match(priority="now"), _asset(), _topology(),
        [_flow("10.0.0.60", "10.0.0.11")])
    assert "now-priority findings" in result.rules[-1]["rationale"]
    assert "cannot be patched" in result.rules[-1]["rationale"]


def test_traffic_crossing_a_zone_boundary_is_marked():
    """The cross-zone sources are the interesting half — they are what the
    segmentation is supposed to be controlling."""
    inside = _zone("zone_a", "10.0.0.0/24", ips=("10.0.0.11", "10.0.0.12"))
    outside = _zone("zone_b", "10.1.0.0/24", level=2, ips=("10.1.0.5",))
    topology = SiteTopology(site="Alderley", zones=[inside, outside],
                            basis_by_zone={"zone_a": "role", "zone_b": "role"})
    result = containment.contain(
        _match(), _asset(ip="10.0.0.11"), topology,
        [_flow("10.0.0.12", "10.0.0.11"), _flow("10.1.0.5", "10.0.0.11")])
    crossing = {a["src_ip"]: a["crosses_zone"] for a in result.allow}
    assert crossing == {"10.0.0.12": False, "10.1.0.5": True}


def test_only_inbound_traffic_shapes_the_rule():
    """What this device REACHES is a different question from what reaches it,
    and only the second is what a containment restricts."""
    result = containment.contain(
        _match(), _asset(), _topology(),
        [_flow("10.0.0.11", "10.0.0.99"), _flow("10.0.0.60", "10.0.0.11")])
    assert [a["src_ip"] for a in result.allow] == ["10.0.0.60"]


# ── the caveat ─────────────────────────────────────────────────────────────

def test_the_rule_always_says_what_it_cannot_see():
    """Even on complete coverage. An allow-list built from a perfect window is
    still only as complete as the window is long."""
    result = containment.contain(
        _match(), _asset(coverage="complete"), _topology(),
        [_flow("10.0.0.60", "10.0.0.11")])
    assert "quarterly" in result.caveat
    assert "will be denied" in result.caveat
    assert "complete over the observed window" in result.caveat


@pytest.mark.parametrize("coverage,phrase", [
    ("degraded", "more likely to be missing a legitimate source"),
    ("unknown", "not as a change to apply"),
])
def test_worse_coverage_makes_the_caveat_louder(coverage, phrase):
    result = containment.contain(
        _match(), _asset(coverage=coverage), _topology(),
        [_flow("10.0.0.60", "10.0.0.11")])
    assert phrase in result.caveat


# ── across the estate ──────────────────────────────────────────────────────

def test_only_assets_with_a_match_get_a_containment():
    """An asset with nothing against it needs no firewall change, and producing
    one anyway buries the handful that matter."""
    matches = [_match("e1", state="matched"), _match("e2", state="clean"),
               _match("e3", state="unknown")]
    assets = [_asset("e1"), _asset("e2", ip="10.0.0.12"),
              _asset("e3", ip="10.0.0.13")]
    out = containment.contain_estate(
        matches, assets, [_topology()],
        {"Alderley": [_flow("10.0.0.60", "10.0.0.11")]})
    assert list(out) == ["e1"]


def test_the_summary_counts_the_refusals_separately():
    """"We will not advise here" and "we cannot" are different answers, and an
    operator reading a total needs them apart."""
    good = _zone("zone_a", "10.0.0.0/24", ips=("10.0.0.11",))
    guessed = _zone("zone_b", "10.9.0.0/24", ips=("10.9.0.5",))
    topology = SiteTopology(
        site="Alderley", zones=[good, guessed],
        basis_by_zone={"zone_a": "role", "zone_b": "defaulted"})
    matches = [_match("e1"), _match("e2"), _match("e3")]
    assets = [_asset("e1", ip="10.0.0.11"), _asset("e2", ip="10.9.0.5"),
              _asset("e3", ip="10.0.0.11")]
    flows = {"Alderley": [_flow("10.0.0.60", "10.0.0.11")]}

    out = containment.contain_estate(matches, assets, [topology], flows)
    summary = containment.summarise(out)
    assert summary["proposed"] == 2 and summary["refused"] == 1
    assert "refused because the zone was mostly guessed" in summary["explain"]


def test_nothing_matched_says_so_rather_than_reporting_zero_risk():
    summary = containment.summarise({})
    assert "nothing to contain" in summary["explain"]
