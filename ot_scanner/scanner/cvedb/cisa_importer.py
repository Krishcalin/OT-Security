"""
CISA KEV -> ICS CVE importer for the OT Passive Scanner.

Converts the authoritative, machine-readable **CISA Known Exploited
Vulnerabilities (KEV) catalog** (and, optionally, FIRST.org **EPSS** scores) into
the CVE-dict format the CVEMatcher already loads via ``--cve-db``. This keeps the
scanner's "actively exploited" (KEV) and probability-of-exploitation (EPSS) data
fresh from real sources instead of hand curation — the auto-refresh path.

Data sources (public, stable schemas):
  * KEV  : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  * EPSS : https://epss.cyentia.com/epss_scores-current.csv.gz  (decompress first)
           or the FIRST.org API CSV (columns: cve,epss,percentile)

Usage (two-step; the output feeds the scanner's existing --cve-db flag):

    python -m scanner.cvedb.cisa_importer known_exploited_vulnerabilities.json \\
        --epss epss_scores-current.csv -o ics_kev.json
    python ot_scanner.py capture.pcap --cve-db ics_kev.json

Pure functions (``parse_kev_catalog`` / ``parse_epss_csv`` / ``is_ics_entry``) do
the work and are unit-tested offline; only ``fetch`` touches the network.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from typing import Dict, List, Optional

# Known ICS/OT vendors (lowercased substrings matched against KEV vendorProject).
ICS_VENDORS = {
    "siemens", "schneider", "rockwell", "allen-bradley", "abb", "ge ",
    "general electric", "ge grid", "honeywell", "yokogawa", "emerson",
    "mitsubishi", "omron", "unitronics", "moxa", "phoenix contact", "wago",
    "beckhoff", "hitachi energy", "schweitzer", "sel ", "advantech",
    "delta electronics", "codesys", "iconics", "aveva", "wonderware",
    "inductive automation", "opto 22", "red lion", "prosoft", "ewon",
    "triconex", "foxboro", "johnson controls", "fuji electric", "festo",
    "pilz", "bosch rexroth", "danfoss", "vipa", "weintek", "kepware",
    "matrikon", "bently nevada", "b&r", "hms networks", "nozomi",
}

# OT-relevant keywords in product / vulnerability names (lowercased).
_OT_KEYWORDS = (
    "plc", "scada", " rtu", "hmi", " ics", "operational technology", "modbus",
    "dnp3", "iec 61850", "iec-104", "iec 60870", "profinet", "ethernet/ip",
    " opc", "safety instrumented", "engineering workstation", "industrial control",
    "programmable logic", "building automation", "bacnet", "distributed control",
    "protection relay", "controller", "codesys", "simatic", "controllogix",
)

# Words too generic to make a useful product-match regex token.
_STOP = {
    "series", "and", "the", "plc", "hmi", "rtu", "ics", "scada", "controller",
    "controllers", "software", "suite", "system", "systems", "module", "modules",
    "device", "devices", "product", "products", "version", "versions", "prior",
    "before", "for", "with", "family", "line", "server", "client", "manager",
}


def is_ics_entry(vendor: str, product: str, name: str) -> bool:
    """True if a KEV entry is OT/ICS-relevant (by vendor or OT keyword)."""
    v = (vendor or "").lower()
    if any(known in v for known in ICS_VENDORS):
        return True
    hay = " ".join(x for x in (vendor, product, name) if x).lower()
    return any(kw in hay for kw in _OT_KEYWORDS)


def _product_pattern(product: str) -> str:
    """Build a regex of the distinctive product tokens for CVEMatcher matching."""
    tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9.\-/]{2,}", product or "")
    kept: List[str] = []
    for t in tokens:
        if t.lower() in _STOP:
            continue
        esc = re.escape(t)
        if esc not in kept:
            kept.append(esc)
    return "|".join(kept) if kept else re.escape((product or "").strip())


def parse_epss_csv(text: str) -> Dict[str, float]:
    """Parse a FIRST.org EPSS CSV (``cve,epss,percentile``; ``#`` comment lines
    and a header row are skipped) into {CVE-ID: epss_probability}."""
    out: Dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        cve = parts[0].strip().upper()
        if not cve.startswith("CVE-"):
            continue
        try:
            score = float(parts[1].strip())
        except ValueError:
            continue
        out[cve] = max(0.0, min(1.0, score))
    return out


def parse_kev_catalog(
    kev: Dict,
    epss: Optional[Dict[str, float]] = None,
    ics_only: bool = True,
) -> List[Dict]:
    """Convert a parsed CISA KEV catalog into CVEMatcher-compatible CVE dicts.

    KEV lacks CVSS, so ``cvss_score`` is left 0.0 (enrich via NVD if needed); every
    entry is flagged ``is_cisa_kev`` + ``has_public_exploit`` (KEV = exploited in
    the wild) with ``exploit_maturity='high'``, and EPSS is merged when supplied.
    """
    epss = epss or {}
    out: List[Dict] = []
    for v in (kev.get("vulnerabilities") or []):
        if not isinstance(v, dict):
            continue
        cve = (v.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        vendor = (v.get("vendorProject") or "").strip()
        product = (v.get("product") or "").strip()
        name = (v.get("vulnerabilityName") or "").strip()
        if ics_only and not is_ics_entry(vendor, product, name):
            continue
        ransomware = (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
        out.append({
            "cve_id": cve,
            "vendor": vendor or "Generic",
            "product_pattern": _product_pattern(product),
            "affected_versions": "*",
            "severity": "critical" if ransomware else "high",
            "cvss_score": 0.0,  # not provided by KEV
            "title": name or f"{vendor} {product}".strip() or cve,
            "description": (v.get("shortDescription") or "").strip(),
            "has_public_exploit": True,           # KEV = exploited in the wild
            "epss_score": float(epss.get(cve, 0.0)),
            "is_cisa_kev": True,
            "exploit_maturity": "high",
            "ics_cert_advisory": "",
            "remediation": (v.get("requiredAction") or "").strip(),
            "references": [
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                f"https://nvd.nist.gov/vuln/detail/{cve}",
            ],
        })
    return out


def fetch(url: str, timeout: int = 30, max_bytes: int = 64 * 1024 * 1024) -> str:
    """Read a URL with a size cap (a huge/hostile feed can't exhaust memory)."""
    req = urllib.request.Request(url, headers={"User-Agent": "OT-Scanner-CISA-Importer"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 — user-supplied source
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"response exceeds the {max_bytes}-byte limit")
    return data.decode("utf-8", "replace")


def _read_source(src: str) -> str:
    if src.startswith(("http://", "https://")):
        return fetch(src)
    with open(src, "r", encoding="utf-8") as fh:
        return fh.read()


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Convert the CISA KEV catalog (+ optional EPSS) into an "
                    "ICS CVE JSON for the OT scanner's --cve-db flag.")
    ap.add_argument("kev", help="CISA KEV catalog JSON (file path or http(s) URL)")
    ap.add_argument("--epss", help="FIRST.org EPSS CSV (file path or URL) to enrich scores")
    ap.add_argument("-o", "--output", required=True, help="output CVE JSON file")
    ap.add_argument("--all", action="store_true",
                    help="include non-ICS KEV entries too (default: ICS-relevant only)")
    args = ap.parse_args(argv)

    try:
        kev = json.loads(_read_source(args.kev))
    except (OSError, ValueError) as exc:
        print(f"[!] failed to read KEV catalog: {exc}", file=sys.stderr)
        return 2
    epss = None
    if args.epss:
        try:
            epss = parse_epss_csv(_read_source(args.epss))
        except (OSError, ValueError) as exc:
            print(f"[!] failed to read EPSS file: {exc}", file=sys.stderr)
            return 2

    entries = parse_kev_catalog(kev, epss, ics_only=not args.all)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)
    scope = "all" if args.all else "ICS-relevant"
    print(f"[+] wrote {len(entries)} {scope} CVE entries to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
