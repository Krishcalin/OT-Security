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
        for entry in getattr(ics_cves, "ICS_CVES", []) or []:
            cve = str(entry.get("cve") or entry.get("id") or "").upper()
            if cve:
                entries[cve] = entry
        return Corpus(version=str(getattr(ics_cves, "VERSION", "shipped")),
                      entries=entries)
    except Exception:                                  # noqa: BLE001
        return Corpus()


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


def match_asset(asset: Dict, corpus: Corpus) -> AssetMatch:
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
        result.hits.append(prioritise(entry, internet_facing, criticality))

    result.state = MatchState.MATCHED if result.hits else MatchState.CLEAN
    if result.state is MatchState.CLEAN and coverage != "complete":
        # The distinction the whole system exists to preserve, applied here.
        result.note = ("no CVEs matched, but this was derived from a %s "
                       "observation window — absence of a finding is not "
                       "evidence of absence" % coverage)
    return result


def match_estate(assets: Iterable[Dict], corpus: Corpus) -> List[AssetMatch]:
    return [match_asset(asset, corpus) for asset in assets]


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
