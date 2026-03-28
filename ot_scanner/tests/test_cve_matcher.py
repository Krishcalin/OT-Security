"""Tests for CVEMatcher — matching pipeline and priority classification."""

from scanner.models import OTDevice
from scanner.cvedb.matcher import CVEMatcher
from scanner.cvedb.ics_cves import ICS_CVE_DATABASE


class TestCVEDatabase:
    def test_loads_90_cves(self):
        assert len(ICS_CVE_DATABASE) == 90

    def test_all_have_epss_and_kev(self):
        for entry in ICS_CVE_DATABASE:
            assert "epss_score" in entry, f"{entry['cve_id']} missing epss_score"
            assert "is_cisa_kev" in entry, f"{entry['cve_id']} missing is_cisa_kev"
            assert "exploit_maturity" in entry, f"{entry['cve_id']} missing exploit_maturity"

    def test_epss_range(self):
        for entry in ICS_CVE_DATABASE:
            assert 0.0 <= entry["epss_score"] <= 1.0, f"{entry['cve_id']} EPSS out of range"


class TestMatcherLoading:
    def test_matcher_loads_all_entries(self):
        matcher = CVEMatcher()
        assert len(matcher.entries) == 90

    def test_external_cve_file_missing_is_ok(self):
        matcher = CVEMatcher(extra_cve_file=None)
        assert len(matcher.entries) == 90


class TestDeviceMatching:
    def test_siemens_s7_matches(self):
        matcher = CVEMatcher()
        dev = OTDevice(ip="10.0.0.1")
        dev.vendor = "Siemens"; dev.model = "S7-1500"; dev.firmware = "V2.0"
        matches = matcher.match_device(dev)
        assert len(matches) > 0
        cve_ids = {m.cve_id for m in matches}
        assert "CVE-2019-13945" in cve_ids

    def test_kev_propagated_to_match(self):
        matcher = CVEMatcher()
        dev = OTDevice(ip="10.0.0.1")
        dev.vendor = "Siemens"; dev.model = "S7-1500"; dev.firmware = "V2.0"
        matches = matcher.match_device(dev)
        kev_match = next((m for m in matches if m.cve_id == "CVE-2019-13945"), None)
        assert kev_match is not None
        assert kev_match.is_cisa_kev is True
        assert kev_match.epss_score > 0.5

    def test_kev_boosts_to_now_priority(self):
        matcher = CVEMatcher()
        dev = OTDevice(ip="10.0.0.1")
        dev.vendor = "Siemens"; dev.model = "S7-1500"; dev.firmware = "V2.0"
        matches = matcher.match_device(dev)
        kev_matches = [m for m in matches if m.is_cisa_kev]
        for m in kev_matches:
            assert m.priority == "now", f"{m.cve_id} KEV should be 'now' priority"

    def test_no_match_for_unknown_vendor(self):
        matcher = CVEMatcher()
        dev = OTDevice(ip="10.0.0.1")
        dev.vendor = "NonexistentVendor"; dev.model = "NoModel"
        matches = matcher.match_device(dev)
        assert len(matches) == 0
