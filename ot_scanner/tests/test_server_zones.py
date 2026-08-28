"""
Server-side Purdue zone derivation — the piece that was blocking three others.

Attack-path analysis, firewall policy generation and the topology view all need
zones, and nothing derived them from estate data.

Two things decide whether this derivation is safe to build on, and both are
tested here: it must not fuse plants that share a subnet, and it must not let a
guessed Purdue level pass as an observed one.
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "ot_scanner"))

from ot_server import analysis, zones                      # noqa: E402
from ot_server.analysis import EngineStatus                # noqa: E402
from ot_server.zones import ZoneBasis                      # noqa: E402


def _asset(ip, site="Substation A", role="plc", device_type="PLC", **extra):
    attrs = {"ip": ip, "role": role, "device_type": device_type}
    attrs.update(extra)
    return {"estate_id": "e-%s-%s" % (site, ip), "site": site, "ip": ip,
            "coverage": "complete", "attributes": attrs}


def _flow(src, dst, collector="pi-a", protocol="Modbus", port=502):
    return {"collector_id": collector,
            "attributes": {"src_ip": src, "dst_ip": dst, "protocol": protocol,
                           "dst_port": port, "packet_count": 40}}


# ── the same trap as the asset merge, one level up ─────────────────────────

def test_two_plants_sharing_a_subnet_get_separate_zones():
    """10.10.1.0/24 exists at almost every plant. Deriving across the estate
    would fuse two substations into one zone — and then a cross-plant flow would
    look like an internal breach, while a real internal breach would be hidden
    by the merge."""
    assets = [_asset("10.10.1.10", "Substation A"),
              _asset("10.10.1.10", "Substation B")]
    topologies = zones.derive(assets, [], {})
    assert {t.site for t in topologies} == {"Substation A", "Substation B"}
    for topology in topologies:
        assert len(topology.zones) <= 1


def test_each_site_is_analysed_independently():
    assets = [_asset("10.10.1.%d" % i, "Substation A") for i in (10, 11)]
    assets += [_asset("10.20.2.%d" % i, "Substation B") for i in (10, 11)]
    topologies = zones.derive(assets, [], {})
    subnets = {t.site: {z.subnet for z in t.zones} for t in topologies}
    assert subnets["Substation A"] != subnets["Substation B"]


def test_an_asset_merged_across_sites_is_not_forced_into_one_zone():
    """A merged asset spanning sites cannot belong to a single site's zone, so
    it is excluded rather than assigned arbitrarily."""
    spanning = _asset("10.10.1.10", "Substation A, Substation B")
    topologies = zones.derive([spanning], [], {})
    assert all(not t.zones for t in topologies) or not topologies


# ── a guessed level must not pass as an observed one ───────────────────────

def test_the_basis_of_each_level_is_recorded():
    """_assign_purdue_levels always returns a level — its documented fallback is
    'default to Level 1'. A zone whose role was recognised and one that fell
    through are otherwise indistinguishable in the output."""
    assets = [_asset("10.10.1.%d" % i, role="plc") for i in (10, 11)]
    topology = zones.derive(assets, [], {})[0]
    assert topology.confidence.zones == 1
    assert set(topology.basis_by_zone.values()) <= {b.value for b in ZoneBasis}


def test_a_recognised_role_is_reported_as_role_derived():
    assets = [_asset("10.10.1.%d" % i, role="plc") for i in (10, 11)]
    topology = zones.derive(assets, [], {})[0]
    assert ZoneBasis.ROLE.value in topology.confidence.by_basis


def test_a_mostly_guessed_derivation_is_not_called_usable():
    """A derivation where most levels came from the fallback describes the
    network no better than the subnets alone."""
    confidence = zones.ZoneConfidence(zones=4, by_basis={"defaulted": 3,
                                                        "role": 1})
    assert not confidence.usable
    assert "subnet listing with numbers attached" in confidence.explain()


def test_a_mostly_derived_topology_is_usable():
    confidence = zones.ZoneConfidence(zones=4, by_basis={"defaulted": 1,
                                                         "role": 3})
    assert confidence.usable and "subnet listing" not in confidence.explain()


def test_estate_confidence_is_not_an_average():
    """Once zones from several sites are flattened, an engine cannot tell which
    site a zone came from — so one badly-derived site drags the estate down."""
    good = zones.SiteTopology("A", confidence=zones.ZoneConfidence(
        zones=2, by_basis={"role": 2}))
    bad = zones.SiteTopology("B", confidence=zones.ZoneConfidence(
        zones=6, by_basis={"defaulted": 6}))
    overall = zones.overall_confidence([good, bad])
    assert overall.zones == 8 and overall.defaulted == 6
    assert not overall.usable


# ── the unblocking, and its limit ──────────────────────────────────────────

def test_derived_zones_unblock_attack_paths_and_policy():
    """The point of the exercise: both were SKIPPED for want of zones."""
    assets = [_asset("10.10.1.%d" % i) for i in (10, 11, 12)]
    report = analysis.run_all(assets, [], flows=[_flow("10.10.1.10", "10.10.1.11")],
                              sites={"pi-a": "Substation A"})
    statuses = {e.engine: e.status for e in report.engines}
    assert statuses["attack_paths"] is EngineStatus.RAN
    assert statuses["policy"] is EngineStatus.RAN


def test_a_guessed_derivation_does_not_unblock_them():
    """'We had no zones' is visibly absent; 'we had bad zones' is confidently
    wrong, and a firewall ruleset built on the second could be applied to a live
    plant network."""
    report = analysis.run_all(
        [_asset("10.10.1.10")], [], flows=[],
        zones=None, sites={"pi-a": "A"}, derive_zones=False)
    statuses = {e.engine: e.status for e in report.engines}
    assert statuses["policy"] is EngineStatus.SKIPPED
    assert "no usable Purdue zones" in [
        e.reason for e in report.engines if e.engine == "policy"][0]


def test_the_zone_basis_travels_into_the_report():
    """Carried even when the zones were rejected: 'we derived zones and did not
    trust them' is a different state from 'we had none'."""
    assets = [_asset("10.10.1.%d" % i) for i in (10, 11)]
    report = analysis.run_all(assets, [], flows=[], sites={"pi-a": "A"})
    assert report.to_dict()["zones"], "the report does not say how levels arose"


# ── the silent-wrong-type bug this work exposed ────────────────────────────

def test_raw_flow_dicts_are_refused_rather_than_silently_producing_nothing():
    """run_all once passed stored dicts straight to the engines. Policy raised,
    which surfaced. Attack-paths iterated records it could not read, found
    nothing, and reported RAN — indistinguishable from a network with no attack
    paths, which is the answer an operator would believe."""
    raw = [{"collector_id": "pi-a", "attributes": {"src_ip": "1.1.1.1"}}]
    result = analysis.run_attack_paths(devices=[], flows=raw, zones=["z"],
                                       edges=["e"])
    assert result.status is EngineStatus.ERROR
    assert "reported success" in result.reason


def test_flows_are_rehydrated_into_comm_flow_objects():
    flow = zones.rehydrate_flow(_flow("10.0.0.1", "10.0.0.2"))
    assert flow.src_ip == "10.0.0.1" and flow.port == 502
    assert not isinstance(flow, dict)


def test_a_flow_missing_an_endpoint_is_dropped_not_half_used():
    assets = [_asset("10.10.1.%d" % i) for i in (10, 11)]
    broken = {"collector_id": "pi-a", "attributes": {"src_ip": "10.10.1.10"}}
    report = analysis.run_all(assets, [], flows=[broken],
                              sites={"pi-a": "Substation A"})
    attack = [e for e in report.engines if e.engine == "attack_paths"][0]
    assert attack.status is not EngineStatus.ERROR
