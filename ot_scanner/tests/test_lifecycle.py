"""
Asset lifecycle (Dragos ledger #5), and the default that decides it.

The load-bearing test is `test_no_record_is_unknown_and_never_supported`.

A device with no lifecycle record has not been assessed. Rendering that as
"supported" is the same failure as reporting an unassessed asset as clean, or a
switched-off collector as a healthy one — both of which this system has already
made, in code that was tested. Here it is refused by construction.

The second is `test_no_lifecycle_data_ships_with_this_product`. Vendor
end-of-support dates cannot be verified from inside this repository, and a
plausible-looking table of them would produce a screen that says a relay is out
of support on a date nobody checked — against which somebody may schedule a
replacement.
"""
from __future__ import annotations

import datetime
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ot_server import lifecycle                             # noqa: E402

TODAY = datetime.date(2026, 8, 28)


def _asset(estate_id="e1", vendor="Siemens", model="S7-300"):
    attrs = {}
    if vendor:
        attrs["vendor"] = vendor
    if model:
        attrs["model"] = model
    return {"estate_id": estate_id, "attributes": attrs}


def _records(**overrides):
    record = {"vendor": "Siemens", "product_pattern": r"S7-300|SIMATIC\s*S7-300",
              "status": "supported", "end_of_sale": "", "end_of_support": "",
              "source": "vendor advisory 2026-01"}
    record.update(overrides)
    return lifecycle.load_records({"lifecycle": [record]})


# ── the default ────────────────────────────────────────────────────────────

def test_no_record_is_unknown_and_never_supported():
    """THE test. Nobody has told this server either way."""
    result = lifecycle.assess(_asset(model="S7-1500"), _records(), TODAY)
    assert result.status == lifecycle.UNKNOWN
    assert "NOT a statement that it is supported" in result.reason
    assert result.fixes_are_coming is None


def test_an_unidentified_device_is_not_the_same_as_an_unknown_one():
    """One is a gap in the lifecycle data; the other is a gap in what was
    observed. Different problems, different fixes."""
    unknown = lifecycle.assess(_asset(model="S7-1500"), _records(), TODAY)
    unidentified = lifecycle.assess(_asset(vendor="", model=""), [], TODAY)
    assert unknown.status == lifecycle.UNKNOWN
    assert unidentified.status == lifecycle.UNIDENTIFIED
    assert "no vendor or model in the inventory" in unidentified.reason


@pytest.mark.parametrize("vendor,model,phrase", [
    ("Siemens", "", "no model"),
    ("", "S7-300", "no vendor"),
])
def test_a_half_identified_device_says_which_half_is_missing(vendor, model,
                                                             phrase):
    result = lifecycle.assess(_asset(vendor=vendor, model=model), [], TODAY)
    assert result.status == lifecycle.UNIDENTIFIED
    assert phrase in result.reason


def test_fixes_are_coming_is_three_valued_not_a_bool():
    """"We do not know whether a fix is coming" is not "no fix is coming", and
    a bare bool cannot hold the difference."""
    assert lifecycle.assess(_asset(), _records(), TODAY).fixes_are_coming is True
    assert lifecycle.assess(_asset(model="X"), _records(),
                            TODAY).fixes_are_coming is None
    assert lifecycle.assess(
        _asset(), _records(end_of_support="2020-01-01"),
        TODAY).fixes_are_coming is False


# ── the states ─────────────────────────────────────────────────────────────

def test_a_date_in_the_past_ends_support():
    result = lifecycle.assess(
        _asset(), _records(end_of_support="2024-06-30"), TODAY)
    assert result.status == lifecycle.END_OF_SUPPORT
    assert "2024-06-30" in result.reason


def test_a_date_in_the_future_does_not():
    result = lifecycle.assess(
        _asset(), _records(end_of_support="2030-06-30"), TODAY)
    assert result.status == lifecycle.SUPPORTED


def test_end_of_sale_is_not_end_of_support():
    """No longer buyable, still fixed. Worth planning around, not worth
    alarming on."""
    result = lifecycle.assess(
        _asset(),
        _records(end_of_sale="2023-01-01", end_of_support="2030-01-01"), TODAY)
    assert result.status == lifecycle.END_OF_SALE
    assert "plan the migration" in result.bearing_on_findings


def test_a_vendor_may_say_retired_without_naming_a_day():
    result = lifecycle.assess(_asset(), _records(status="end_of_life"), TODAY)
    assert result.status == lifecycle.END_OF_LIFE


def test_an_unparseable_date_does_not_decide_anything():
    result = lifecycle.assess(
        _asset(), _records(end_of_support="soon"), TODAY)
    assert result.status == lifecycle.SUPPORTED


# ── what it means for a finding ────────────────────────────────────────────

def test_past_end_of_support_makes_containment_the_only_option():
    """Not a maintenance note. No fix is coming for anything found on it —
    not this quarter, not ever."""
    result = lifecycle.assess(
        _asset(), _records(end_of_support="2024-01-01"), TODAY)
    assert "the only" in result.bearing_on_findings
    assert "containment" in result.bearing_on_findings


def test_a_supported_device_carries_no_bearing():
    """An advisory on every row is an advisory nobody reads."""
    result = lifecycle.assess(_asset(), _records(), TODAY)
    assert result.bearing_on_findings == ""


# ── matching ───────────────────────────────────────────────────────────────

def test_the_source_of_a_claim_travels_with_it():
    """An operator reading "end of support" should know whose claim it is."""
    result = lifecycle.assess(
        _asset(), _records(end_of_support="2024-01-01",
                           source="acme maintenance contract"), TODAY)
    assert result.source == "acme maintenance contract"
    assert "acme maintenance contract" in result.reason


def test_a_record_with_no_product_pattern_is_discarded():
    """A record matched to everything would be worse than none."""
    assert lifecycle.load_records(
        {"lifecycle": [{"vendor": "Siemens", "product_pattern": ""}]}) == []


def test_a_broken_pattern_matches_nothing_rather_than_everything():
    """A record whose regex will not compile must not become a wildcard."""
    records = lifecycle.load_records(
        {"lifecycle": [{"vendor": "Siemens", "product_pattern": "S7-[",
                        "status": "end_of_life"}]})
    assert lifecycle.assess(_asset(), records, TODAY).status == lifecycle.UNKNOWN


def test_matching_tolerates_how_a_device_announces_itself():
    records = _records(product_pattern=r"S7-300|SIMATIC\s*S7-300")
    for model in ("S7-300", "SIMATIC S7-300", "simatic s7-300"):
        assert lifecycle.assess(_asset(model=model), records,
                                TODAY).status != lifecycle.UNKNOWN


def test_a_malformed_pack_yields_no_records_rather_than_bad_ones():
    assert lifecycle.load_records(None) == []
    assert lifecycle.load_records({"lifecycle": ["not an object"]}) == []
    assert lifecycle.load_records({"wrong_section": [{}]}) == []


# ── no data ships ──────────────────────────────────────────────────────────

def test_no_lifecycle_data_ships_with_this_product():
    """Vendor end-of-support dates cannot be verified from inside this
    repository, and a plausible-looking table of them would produce a screen
    that says a relay is out of support on a date nobody checked — against
    which somebody may schedule a replacement."""
    assert lifecycle.load_records({}) == []
    module = os.path.join(_ROOT, "ot_server", "lifecycle.py")
    with open(module, encoding="utf-8") as fh:
        source = fh.read()
    assert "end_of_support\": \"20" not in source, (
        "a hardcoded end-of-support date appeared in the module")


def test_with_no_records_the_estate_is_unassessed_not_supported():
    results = lifecycle.assess_estate(
        [_asset("e1"), _asset("e2", vendor="ABB", model="RTU560")], [], TODAY)
    assert {r.status for r in results.values()} == {lifecycle.UNKNOWN}
    summary = lifecycle.summarise(results, 0)
    assert "not a supported estate" in summary["explain"]
    assert "unassessed one" in summary["explain"]


# ── the summary ────────────────────────────────────────────────────────────

def test_the_summary_separates_unknown_from_unidentified():
    records = _records(end_of_support="2024-01-01")
    results = lifecycle.assess_estate(
        [_asset("e1"),                                   # end of support
         _asset("e2", model="S7-1500"),                  # unknown
         _asset("e3", vendor="", model="")],             # unidentified
        records, TODAY)
    summary = lifecycle.summarise(results, len(records))
    assert summary["counts"][lifecycle.END_OF_SUPPORT] == 1
    assert summary["counts"][lifecycle.UNKNOWN] == 1
    assert summary["counts"][lifecycle.UNIDENTIFIED] == 1
    assert summary["unsupported"] == ["e1"]
    assert "unassessed rather than supported" in summary["explain"]
    assert "could not identify" in summary["explain"]
