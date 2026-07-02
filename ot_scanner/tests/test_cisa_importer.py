"""Tests for the CISA KEV -> ICS CVE importer (offline; synthetic KEV data)."""
import json
import re

from scanner.cvedb.cisa_importer import (
    parse_kev_catalog, parse_epss_csv, is_ics_entry,
)
from scanner.cvedb.matcher import CVEMatcher
from scanner.models import OTDevice


_KEV = {
    "title": "CISA Catalog",
    "vulnerabilities": [
        {"cveID": "CVE-2023-6448", "vendorProject": "Unitronics",
         "product": "Vision and Samba Series",
         "vulnerabilityName": "Unitronics Vision/Samba Default Password",
         "shortDescription": "Default administrative password.",
         "requiredAction": "Change the default password.",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2021-22681", "vendorProject": "Rockwell Automation",
         "product": "Studio 5000 Logix Designer",
         "vulnerabilityName": "Rockwell Logix Auth Bypass",
         "shortDescription": "Poorly protected key.",
         "requiredAction": "Apply mitigations.",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2024-99999", "vendorProject": "Acme",
         "product": "SCADA HMI Server",
         "vulnerabilityName": "Acme SCADA HMI RCE",
         "shortDescription": "OT keyword match.",
         "requiredAction": "Patch.",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2024-11111", "vendorProject": "Microsoft",
         "product": "Windows",
         "vulnerabilityName": "Windows Kernel EoP",
         "shortDescription": "Pure IT, should be excluded.",
         "requiredAction": "Patch.",
         "knownRansomwareCampaignUse": "Known"},
    ],
}


class TestIcsFilter:
    def test_vendor_and_keyword_and_it(self):
        assert is_ics_entry("Siemens", "SIMATIC S7", "")          # known ICS vendor
        assert is_ics_entry("Acme", "SCADA HMI", "")              # OT keyword
        assert not is_ics_entry("Microsoft", "Windows", "Kernel EoP")


class TestKevParsing:
    def test_ics_only_excludes_pure_it(self):
        ids = {e["cve_id"] for e in parse_kev_catalog(_KEV, ics_only=True)}
        assert {"CVE-2023-6448", "CVE-2021-22681", "CVE-2024-99999"} <= ids
        assert "CVE-2024-11111" not in ids

    def test_all_includes_it(self):
        assert len(parse_kev_catalog(_KEV, ics_only=False)) == 4

    def test_kev_flags_and_severity_and_invariants(self):
        entries = {e["cve_id"]: e for e in parse_kev_catalog(_KEV)}
        rock = entries["CVE-2021-22681"]
        assert rock["is_cisa_kev"] and rock["has_public_exploit"]
        assert rock["exploit_maturity"] == "high"
        assert rock["severity"] == "critical"                     # ransomware = Known
        assert entries["CVE-2023-6448"]["severity"] == "high"     # ransomware Unknown
        for e in entries.values():                                # DB invariants hold
            assert 0.0 <= e["epss_score"] <= 1.0
            assert e["is_cisa_kev"] and "exploit_maturity" in e

    def test_product_pattern_matches_model(self):
        entries = {e["cve_id"]: e for e in parse_kev_catalog(_KEV)}
        assert re.compile(entries["CVE-2023-6448"]["product_pattern"], re.I).search("Vision V570")


class TestEpss:
    def test_parse_epss_csv_skips_header_and_junk(self):
        csv = "#model_version:v1\ncve,epss,percentile\nCVE-2023-6448,0.812,0.99\nbad,line\n"
        scores = parse_epss_csv(csv)
        assert scores == {"CVE-2023-6448": 0.812}

    def test_epss_merged(self):
        entries = {e["cve_id"]: e for e in parse_kev_catalog(_KEV, {"CVE-2023-6448": 0.812})}
        assert entries["CVE-2023-6448"]["epss_score"] == 0.812
        assert entries["CVE-2021-22681"]["epss_score"] == 0.0


class TestRoundTripIntoMatcher:
    def test_output_loads_and_matches(self, tmp_path):
        base = CVEMatcher().cve_count
        out = tmp_path / "kev.json"
        out.write_text(json.dumps(parse_kev_catalog(_KEV)), encoding="utf-8")
        matcher = CVEMatcher(extra_cve_file=str(out))
        # only the Acme CVE is new; the 2 Rockwell/Unitronics IDs override built-ins
        assert matcher.cve_count == base + 1
        dev = OTDevice(ip="10.0.0.9")
        dev.vendor = "Acme"; dev.model = "SCADA HMI Server"
        assert any(m.cve_id == "CVE-2024-99999" for m in matcher.match_device(dev))
