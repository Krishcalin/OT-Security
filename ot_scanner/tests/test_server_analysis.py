"""
Phase 4 — server-side engines over merged estate data (OTS-SRV-003).

These engines were written against the rich `OTDevice` a scan builds in memory.
The estate holds a normalised, serialised view, so wiring them is a REHYDRATION
and rehydration is lossy.

An engine handed a device missing most of its fields still produces output, and
that output looks exactly like output from a full scan. Everything here exists
to keep those two distinguishable.
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from ot_server import analysis                       # noqa: E402
from ot_server.analysis import EngineStatus          # noqa: E402


def _asset(estate_id="e1", **attrs):
    base = {"ip": "10.0.0.1", "vendor": "Siemens", "criticality": "high"}
    base.update(attrs)
    return {"estate_id": estate_id, "ip": base.get("ip", ""),
            "coverage": "complete", "attributes": base}


# ── the loss is measured, not assumed ──────────────────────────────────────

def test_the_wire_format_cost_is_measured_against_the_real_model():
    """A hardcoded number would drift the moment OTDevice gained a field."""
    f = analysis.device_fidelity()
    assert f.total > 40, "OTDevice model not found"
    assert 0 < f.shipped < f.total
    assert "cannot consider the rest" in f.explain()


def test_every_shipped_field_is_a_real_device_field():
    """setattr on a name the dataclass does not have is silently dropped, so the
    device rehydrates looking complete with the value missing."""
    import dataclasses

    from scanner.models import OTDevice

    names = {f.name for f in dataclasses.fields(OTDevice)}
    assert set(analysis.SHIPPED_FIELDS) <= names, (
        "SHIPPED_FIELDS names something OTDevice does not have: %s"
        % sorted(set(analysis.SHIPPED_FIELDS) - names))


def test_the_two_vocabularies_are_reconciled():
    """The collector says `criticality`, the model says `device_criticality`.
    Rehydrating by name alone dropped it silently, and every engine downstream
    then scored the device as ordinary."""
    device = analysis.rehydrate(_asset(criticality="high"), [])
    assert device.device_criticality == "high"


def test_detections_are_reattached_as_vulnerabilities():
    """They were computed on the collector where the packets were, and are the
    one derived thing that does travel."""
    device = analysis.rehydrate(
        _asset(), [{"asset_key": "e1",
                    "attributes": {"rule_id": "TELNET", "severity": "high",
                                   "title": "Telnet on OT device"}}])
    assert len(device.vulnerabilities) == 1
    assert device.vulnerabilities[0].severity == "high"


def test_absent_fields_are_left_empty_not_invented():
    device = analysis.rehydrate(_asset(), [])
    assert not getattr(device, "it_protocols", None)
    assert not getattr(device, "attack_paths", None)


# ── an engine that ran without its inputs says so ──────────────────────────

def test_compliance_runs_but_declares_what_it_could_not_assess():
    """Zones withheld explicitly. They are derived by default now, so relying on
    their absence would make this test stop meaning anything."""
    report = analysis.run_all([_asset()], [], flows=[], derive_zones=False)
    compliance = [e for e in report.engines if e.engine == "compliance"][0]
    assert compliance.status is EngineStatus.DEGRADED
    assert not compliance.trustworthy
    assert any("zone" in lim.lower() for lim in compliance.limitations), (
        "segmentation controls must not be counted as passing when zones are "
        "unavailable")


def test_compliance_still_declares_its_field_gaps_once_zones_exist():
    """Zones remove one limitation; they do not make the device model complete.
    10 of 49 fields still survive the wire."""
    report = analysis.run_all([_asset()], [], flows=[])
    compliance = [e for e in report.engines if e.engine == "compliance"][0]
    assert compliance.status is EngineStatus.DEGRADED
    assert any("communication_profile" in lim for lim in compliance.limitations)


def test_risk_names_the_specific_fields_it_lacked():
    """'Results may be incomplete' is not actionable. 'Risk wants cve_matches'
    tells you exactly what to widen the wire format with."""
    report = analysis.run_all([_asset()], [], flows=[])
    risk = [e for e in report.engines if e.engine == "risk"][0]
    assert risk.status is EngineStatus.DEGRADED
    assert any("cve_matches" in lim for lim in risk.limitations)


# ── an engine without its required inputs is SKIPPED, not run on nothing ───

def test_attack_paths_is_skipped_without_zones():
    """An attack path is a claim about reachability. Reachability without
    segmentation data is a guess wearing the shape of a finding."""
    report = analysis.run_all([_asset()], [], flows=[], derive_zones=False)
    attack = [e for e in report.engines if e.engine == "attack_paths"][0]
    assert attack.status is EngineStatus.SKIPPED
    assert "guess" in attack.reason


def test_policy_is_skipped_without_zones():
    """A generated ruleset that does not know the segmentation it enforces could
    be applied to a live plant network."""
    report = analysis.run_all([_asset()], [], flows=[], derive_zones=False)
    policy = [e for e in report.engines if e.engine == "policy"][0]
    assert policy.status is EngineStatus.SKIPPED
    assert "live plant network" in policy.reason


def test_drift_is_skipped_without_a_baseline():
    """'Nothing changed' against no baseline is the most confident wrong answer
    available here."""
    report = analysis.run_all([_asset()], [], flows=[], derive_zones=False)
    drift = [e for e in report.engines if e.engine == "drift"][0]
    assert drift.status is EngineStatus.SKIPPED
    assert "confident wrong answer" in drift.reason


def test_drift_runs_with_a_baseline_and_does_not_call_absence_removal():
    """OTS-SRV-005 again: an asset that stopped appearing is not observed, not
    necessarily gone."""
    baseline = [_asset("e1"), _asset("e2")]
    report = analysis.run_all([_asset("e1")], [], flows=[], baseline=baseline)
    drift = [e for e in report.engines if e.engine == "drift"][0]
    assert drift.status is EngineStatus.RAN
    assert drift.result["disappeared"] == ["e2"]
    assert any("NOT OBSERVED" in lim for lim in drift.limitations)


# ── the report as a whole ──────────────────────────────────────────────────

def test_no_engine_reports_trustworthy_on_a_partial_estate():
    """Compliance and risk consume the device model, and 10 of 49 fields survive
    the wire — so neither may ever report itself trustworthy, zones or not.

    attack_paths and policy are excluded from this claim deliberately: they
    consume zones and flows rather than the lossy device fields, so once zones
    exist they legitimately CAN be trustworthy. Asserting otherwise would have
    forced a permanent false limitation onto two honest engines."""
    report = analysis.run_all([_asset()], [], flows=[])
    model_consumers = [e for e in report.engines
                       if e.engine in ("compliance", "risk")]
    assert model_consumers and not any(e.trustworthy for e in model_consumers)


def test_the_report_names_what_was_skipped():
    report = analysis.run_all([_asset()], [], flows=[], derive_zones=False)
    assert set(report.to_dict()["skipped"]) == {"attack_paths", "policy", "drift"}


def test_derived_zones_leave_only_drift_skipped():
    """What the zone derivation bought: two engines that were blocked now run."""
    assets = [{"estate_id": "e%d" % i, "site": "S", "ip": "10.10.1.%d" % i,
               "coverage": "complete",
               "attributes": {"ip": "10.10.1.%d" % i, "role": "plc",
                              "device_type": "PLC"}} for i in (10, 11)]
    flows = [{"collector_id": "pi-a",
              "attributes": {"src_ip": "10.10.1.10", "dst_ip": "10.10.1.11",
                             "protocol": "Modbus", "dst_port": 502}}]
    report = analysis.run_all(assets, [], flows=flows, sites={"pi-a": "S"})
    assert set(report.to_dict()["skipped"]) == {"drift"}


def test_the_report_carries_the_coverage_it_was_computed_from():
    report = analysis.run_all([_asset()], [], flows=[],
                              coverage_explain="3 windows, all complete")
    assert report.to_dict()["coverage"] == "3 windows, all complete"


def test_an_engine_that_raises_is_reported_not_swallowed():
    result = analysis.run_compliance(devices=object(), zones=None)
    assert result.status is EngineStatus.ERROR


def test_a_detection_that_cannot_be_rebuilt_is_surfaced_not_dropped():
    """The failure this module committed against itself: a bare except turned a
    constructor TypeError into a silent None, every collector detection was
    discarded on the way into the engines, and the device looked clean."""
    device = analysis.rehydrate(_asset(), [{"asset_key": "e1", "attributes": None}])
    # An unusable record must leave a trace on the device, not vanish.
    assert device.vulnerabilities or any(
        "could not be reconstructed" in n for n in device.notes)
