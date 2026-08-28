"""
Server-side CVE / KEV / EPSS matching (OTS-SRV-002, decision D3).

THIS IS WHAT KEEPING `cvedb/` OFF THE COLLECTOR BUYS
────────────────────────────────────────────────────
The corpus changes daily. Because collectors ship observations rather than
verdicts about vulnerability, a KEV addition re-prioritises the whole estate by
re-running this over stored assets — no collector is touched, no substation is
visited, and no answer depends on when a particular Pi was last updated.

`OTS-SRV-002` states the requirement as: a corpus refresh SHALL re-prioritise
existing findings WITHOUT re-ingest. So matching is a pure function of
(stored assets, current corpus), never a side effect of receiving a batch.

A PRIORITY IS A CLAIM, AND CLAIMS CARRY THEIR EVIDENCE
──────────────────────────────────────────────────────
Every match records the corpus version it was computed against and the coverage
of the observation it was computed from. "This asset is not affected" from a
window that dropped frames is a materially weaker statement than the same words
from a complete one, and an operator deciding whether to take an outage deserves
to know which they are reading.

WHEN THE CORPUS IS ABSENT
─────────────────────────
`UNKNOWN`, never "no vulnerabilities". A server without a corpus has not
established that an asset is clean — it has failed to look, and the two must
not render the same way.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional


class MatchState(str, Enum):
    MATCHED = "matched"
    CLEAN = "clean"                 # looked, found nothing
    UNKNOWN = "unknown"             # could not look


class Priority(str, Enum):
    NOW = "now"                     # known-exploited and reachable
    NEXT = "next"
    NEVER = "never"
    UNKNOWN = "unknown"


@dataclass
class CveHit:
    cve: str
    severity: str = ""
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev: bool = False
    priority: Priority = Priority.UNKNOWN
    why: str = ""

    def to_dict(self) -> Dict:
        return {"cve": self.cve, "severity": self.severity, "cvss": self.cvss,
                "epss": self.epss, "kev": self.kev,
                "priority": self.priority.value, "why": self.why}


@dataclass
class AssetMatch:
    estate_id: str
    state: MatchState = MatchState.UNKNOWN
    hits: List[CveHit] = field(default_factory=list)
    corpus_version: str = ""
    observation_coverage: str = "unknown"
    note: str = ""

    @property
    def worst(self) -> Priority:
        for level in (Priority.NOW, Priority.NEXT, Priority.NEVER):
            if any(h.priority is level for h in self.hits):
                return level
        return Priority.UNKNOWN

    @property
    def actionable(self) -> bool:
        return self.state is MatchState.MATCHED and self.worst is Priority.NOW

    def to_dict(self) -> Dict:
        return {
            "estate_id": self.estate_id,
            "state": self.state.value,
            "priority": self.worst.value,
            "hits": [h.to_dict() for h in self.hits],
            "corpus_version": self.corpus_version,
            "observation_coverage": self.observation_coverage,
            "note": self.note,
        }


@dataclass
class Corpus:
    """The vulnerability data, however it is loaded.

    Injected rather than imported so matching is testable without the 3,170-line
    cvedb package, and so a refresh is a data change rather than a code path.
    """

    version: str = ""
    #: cve id -> {severity, cvss, epss, kev}
    entries: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return bool(self.entries)

    def get(self, cve: str) -> Optional[Dict[str, Any]]:
        return self.entries.get(cve.upper())


def load_corpus(loader: Optional[Callable[[], Corpus]] = None) -> Corpus:
    """The shipped corpus, or an empty one.

    An empty corpus is returned rather than raised, because the server must
    still serve — but every asset it touches is then UNKNOWN rather than clean,
    which is the honest consequence.
    """
    if loader is not None:
        return loader()
    try:
        from scanner.cvedb import ics_cves            # noqa: PLC0415

        entries = {}
        for raw in getattr(ics_cves, "ICS_CVE_DATABASE", None) or []:
            cve = str(raw.get("cve_id") or "").upper()
            if cve:
                entries[cve] = _normalise(cve, raw)
        return Corpus(version=fingerprint(entries), entries=entries)
    except Exception:                                  # noqa: BLE001
        return Corpus()


def _normalise(cve: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """The corpus entry in the shape `prioritise` reads.

    Normalised HERE, once, rather than by teaching `prioritise` another set of
    aliases. The shipped database spells these `cvss_score`, `epss_score` and
    `is_cisa_kev`; `prioritise` reads `cvss`, `epss` and `kev`. Every one of
    those near-misses is silent — a missing key reads as a missing value, so an
    entry with a KEV flag it cannot see is simply a CVE that never reaches NOW.
    One translation at the boundary is auditable; three sets of aliases spread
    through the matcher are not.
    """
    return {
        "cve": cve,
        "severity": raw.get("severity", ""),
        "cvss": raw.get("cvss_score"),
        "epss": raw.get("epss_score"),
        "kev": bool(raw.get("is_cisa_kev")),
        "title": raw.get("title", ""),
        "remediation": raw.get("remediation", ""),
        "advisory": raw.get("ics_cert_advisory", ""),
        "vendor": raw.get("vendor", ""),
    }


def fingerprint(entries: Dict[str, Dict[str, Any]]) -> str:
    """A version derived from the content, not written down beside it.

    Same reasoning as `collector/rulepack.py`: a version string somebody must
    remember to bump is a version string that is wrong, and it is wrong exactly
    when it matters — the urgent KEV addition, the quick correction. The shipped
    database carried no version at all, which `load_corpus` read as the literal
    string "shipped" for every revision it would ever have.
    """
    import hashlib

    digest = hashlib.sha256(
        "|".join(sorted(entries)).encode("utf-8")).hexdigest()
    return "ics-%d-%s" % (len(entries), digest[:8])


def load_matcher(loader: Optional[Callable[[], Any]] = None):
    """The device-to-CVE matcher, or None.

    `Corpus` says which CVEs exist and how bad they are. It does not say which
    of them apply to a Siemens S7-1500 on firmware V4.2, and nothing in the
    estate ever told it: `match_asset` read a `cve_ids` attribute that no
    collector, ingest path or merge has ever populated. The scanner has carried
    a working matcher — vendor, product pattern, firmware range — the whole
    time, and the server never called it.

    Returning None is honest and NOT harmless: see `match_asset`, where no
    matcher means UNKNOWN rather than clean.
    """
    if loader is not None:
        return loader()
    try:
        from scanner.cvedb.matcher import CVEMatcher   # noqa: PLC0415

        return CVEMatcher()
    except Exception:                                  # noqa: BLE001
        return None


def device_candidates(asset: Dict, matcher) -> Dict[str, str]:
    """Which CVEs this device matches, and why each one matched.

    Only the SET of CVEs comes from the scanner's matcher. Their priority does
    not: `prioritise` here is the single authority on Now/Next/Never, and it is
    deliberately more conservative than the scanner's — NOW means
    known-exploited, not "has a public exploit". Two prioritisation opinions in
    one product is one too many.
    """
    if matcher is None:
        return {}
    try:
        from .analysis import rehydrate                # noqa: PLC0415

        device = rehydrate(asset, [])
        return {str(m.cve_id).upper(): str(getattr(m, "match_reason", "") or "")
                for m in matcher.match_device(device)}
    except Exception:                                  # noqa: BLE001
        # A device the matcher cannot read is not a device with no CVEs. The
        # caller turns an empty result into UNKNOWN, not CLEAN.
        return {}


def prioritise(entry: Dict[str, Any], internet_facing: bool = False,
               criticality: str = "") -> CveHit:
    """Now / Next / Never for one CVE on one asset.

    Deliberately conservative about NOW: it means known-exploited, because a
    priority that fires on everything is one an operator stops reading. EPSS
    alone is a probability, not an observation of exploitation.
    """
    cve = str(entry.get("cve") or entry.get("id") or "").upper()
    kev = bool(entry.get("kev") or entry.get("cisa_kev"))
    epss = entry.get("epss")
    cvss = entry.get("cvss") or entry.get("cvss_score")
    severity = str(entry.get("severity") or "")

    if kev:
        return CveHit(cve, severity, cvss, epss, True, Priority.NOW,
                      "on the CISA KEV list — known to be exploited")
    try:
        epss_value = float(epss) if epss is not None else None
    except (TypeError, ValueError):
        epss_value = None
    if epss_value is not None and epss_value >= 0.5:
        return CveHit(cve, severity, cvss, epss, False, Priority.NEXT,
                      "EPSS %.2f — exploitation is likely but not observed"
                      % epss_value)
    if severity.lower() in ("critical", "high"):
        return CveHit(cve, severity, cvss, epss, False, Priority.NEXT,
                      "%s severity" % severity.lower())
    return CveHit(cve, severity, cvss, epss, False, Priority.NEVER,
                  "no exploitation signal; schedule with routine patching")


def match_asset(asset: Dict, corpus: Corpus, matcher=None) -> AssetMatch:
    """Match one estate asset against the current corpus."""
    estate_id = asset.get("estate_id", "")
    coverage = asset.get("coverage", "unknown")
    result = AssetMatch(estate_id=estate_id, corpus_version=corpus.version,
                        observation_coverage=coverage)

    if not corpus.available:
        result.state = MatchState.UNKNOWN
        result.note = ("no vulnerability corpus is loaded — this asset has not "
                       "been assessed, which is not the same as unaffected")
        return result

    attrs = asset.get("attributes") or {}
    cves = attrs.get("cve_ids") or attrs.get("cves") or []
    if isinstance(cves, str):
        cves = [cves]

    # Where the CVEs actually come from. An asset carrying its own `cve_ids` is
    # honoured first — that is how a caller supplies them directly — and
    # otherwise they are derived from what the device IS.
    reasons: Dict[str, str] = {}
    if not cves:
        reasons = device_candidates(asset, matcher)
        cves = sorted(reasons)

    if not cves and matcher is None:
        # THE correction. A corpus loaded with no means of applying it is not a
        # clean estate; it is an estate nobody has assessed. Reporting CLEAN
        # here would be the confidently-wrong answer this whole system exists
        # to refuse — and it is what this function did, silently, for every
        # asset, because `cve_ids` was never populated by anything.
        result.state = MatchState.UNKNOWN
        result.note = ("a corpus is loaded but this device could not be "
                       "matched against it — no CVE list on the asset and no "
                       "matcher available. That is unassessed, not clean.")
        return result

    internet_facing = bool(attrs.get("internet_facing"))
    criticality = str(attrs.get("criticality") or "")

    for cve in cves:
        entry = corpus.get(str(cve))
        if entry is None:
            # A CVE the corpus does not know is not a clean CVE.
            result.hits.append(CveHit(str(cve).upper(), priority=Priority.UNKNOWN,
                                      why="not present in corpus %s"
                                          % (corpus.version or "<unversioned>")))
            continue
        hit = prioritise(entry, internet_facing, criticality)
        reason = reasons.get(str(cve).upper())
        if reason:
            # Why this CVE was attached to this device, alongside why it got
            # the priority it did. An operator asking "why is this on my relay"
            # should not have to go and read the matcher.
            hit.why = "%s; matched on %s" % (hit.why, reason) if hit.why \
                else "matched on %s" % reason
        result.hits.append(hit)

    result.state = MatchState.MATCHED if result.hits else MatchState.CLEAN
    if result.state is MatchState.CLEAN and coverage != "complete":
        # The distinction the whole system exists to preserve, applied here.
        result.note = ("no CVEs matched, but this was derived from a %s "
                       "observation window — absence of a finding is not "
                       "evidence of absence" % coverage)
    return result


def match_estate(assets: Iterable[Dict], corpus: Corpus,
                 matcher=None) -> List[AssetMatch]:
    return [match_asset(asset, corpus, matcher) for asset in assets]


@dataclass
class RepriorisationReport:
    """What changed when the corpus was refreshed, without re-ingest.

    The point of D3 made measurable: an operator can see that last night's KEV
    addition moved four assets to NOW without a single collector being touched.
    """

    from_version: str = ""
    to_version: str = ""
    assets_assessed: int = 0
    escalated: List[str] = field(default_factory=list)
    de_escalated: List[str] = field(default_factory=list)

    @property
    def changed(self) -> int:
        return len(self.escalated) + len(self.de_escalated)

    def explain(self) -> str:
        if not self.changed:
            return ("corpus %s -> %s: no priority changed across %d asset(s)"
                    % (self.from_version, self.to_version, self.assets_assessed))
        return ("corpus %s -> %s: %d escalated, %d de-escalated across %d "
                "asset(s), with no collector contacted"
                % (self.from_version, self.to_version, len(self.escalated),
                   len(self.de_escalated), self.assets_assessed))


_ORDER = {Priority.NOW: 3, Priority.NEXT: 2, Priority.NEVER: 1,
          Priority.UNKNOWN: 0}


def reprioritise(assets: List[Dict], before: Corpus,
                 after: Corpus) -> RepriorisationReport:
    """Re-run matching against a new corpus and report what moved."""
    report = RepriorisationReport(from_version=before.version,
                                  to_version=after.version,
                                  assets_assessed=len(assets))
    old = {m.estate_id: m.worst for m in match_estate(assets, before)}
    for match in match_estate(assets, after):
        was = old.get(match.estate_id, Priority.UNKNOWN)
        now = match.worst
        if _ORDER[now] > _ORDER[was]:
            report.escalated.append(match.estate_id)
        elif _ORDER[now] < _ORDER[was]:
            report.de_escalated.append(match.estate_id)
    return report
