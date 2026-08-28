"""
Estate asset merge (OTS-SRV-001).

The same physical device seen by two collectors must be one asset. The trap is
that the obvious key is wrong.

WHY MERGING ON IP ALONE CORRUPTS THE INVENTORY
──────────────────────────────────────────────
Collectors emit `ip:10.0.0.1`. Private ranges overlap across plants: a PLC at
Substation A and an unrelated one at Substation B are both very likely to be
10.0.0.1. Merging on that key fuses two devices into one, and the result is
worse than either error it replaces —

  * one plant's findings appear against the other's asset,
  * the asset count silently drops,
  * and nothing in the output looks wrong.

Un-merging afterwards is not possible without re-ingesting history, because the
provenance of each contribution has already been averaged away.

THE RULE
────────
  * BOTH identities are scoped to a SITE. `10.0.0.1` at Substation A and
    `10.0.0.1` at Substation B are two assets, always — and so are two devices
    sharing a MAC at different plants.
  * An asset carrying both identities links them, so a collector that sees only
    the IP and one that sees only the MAC still converge — within the site.

WHEN IN DOUBT, DO NOT MERGE
───────────────────────────
Two assets that are really one is a visible, recoverable error: an operator sees
a duplicate and says so. One asset that is really two is invisible and
unrecoverable. Every ambiguity therefore resolves toward keeping them apart, and
the ambiguity is reported rather than silently settled.

WHY MAC IS NOT A GLOBAL KEY, THOUGH IT LOOKS LIKE ONE
─────────────────────────────────────────────────────
An earlier version merged on MAC across sites, on the reasoning that OUI-assigned
addresses are unique enough to catch a device that moved. That contradicted the
rule above the moment the uniqueness assumption failed — and in OT it does fail:
cloned and counterfeit hardware, virtualised devices, and vendors shipping
duplicate addresses are all real. The result would be two plants' devices fused,
each carrying the other's findings, unrecoverably.

So a MAC seen at another site is REPORTED on both assets and merges neither. A
device that genuinely moved appears twice with a warning naming the other site,
which is the recoverable error and the one an operator can act on.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

UNKNOWN_SITE = "<unassigned>"


class _Union:
    """Union-find over identity strings. Small, and the merge is a graph."""

    def __init__(self):
        self.parent: Dict[str, str] = {}

    def add(self, item: str) -> None:
        self.parent.setdefault(item, item)

    def find(self, item: str) -> str:
        self.add(item)
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:            # path compression
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def scoped_ip_identity(site: str, ip: str) -> str:
    """An IP identity is only meaningful inside its site."""
    return "site:%s/ip:%s" % (site or UNKNOWN_SITE, ip)


def scoped_mac_identity(site: str, mac: str) -> str:
    """A MAC identity, scoped to its site. See the module docstring for why this
    is not global."""
    return "site:%s/mac:%s" % (site or UNKNOWN_SITE, mac.lower())


@dataclass
class Contribution:
    """One collector's view of an asset, kept rather than averaged away."""

    collector_id: str
    site: str
    asset_key: str
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    observation_count: int = 0
    last_observed_window: str = ""
    last_coverage: str = "unknown"
    attributes: Dict = field(default_factory=dict)


@dataclass
class EstateAsset:
    """One physical device, as seen by one or more collectors."""

    estate_id: str
    site: str = ""
    ip: str = ""
    mac: str = ""
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    observation_count: int = 0
    collectors: List[str] = field(default_factory=list)
    sites: List[str] = field(default_factory=list)
    attributes: Dict = field(default_factory=dict)
    contributions: List[Contribution] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def seen_by(self) -> int:
        return len(self.collectors)

    @property
    def coverage(self) -> str:
        """The WEAKEST coverage of any contributing observation.

        An estate answer is only as good as its worst input: if one collector's
        window was unmeasurable, the merged asset cannot be presented as
        confirmed. Averaging coverage across collectors would let a healthy one
        launder a blind one's silence.
        """
        states = {c.last_coverage for c in self.contributions}
        if "unknown" in states or not states:
            return "unknown"
        if "degraded" in states:
            return "degraded"
        return "complete"

    def to_dict(self) -> Dict:
        return {
            "estate_id": self.estate_id,
            "site": self.site,
            "ip": self.ip,
            "mac": self.mac,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observation_count": self.observation_count,
            "collectors": sorted(self.collectors),
            "sites": sorted(self.sites),
            "seen_by": self.seen_by,
            "coverage": self.coverage,
            "attributes": dict(self.attributes),
            "warnings": list(self.warnings),
        }


def _identities(site: str, row: Dict) -> List[str]:
    """Every identity this observation asserts."""
    attrs = row.get("attributes") or {}
    out: List[str] = []
    ip = str(attrs.get("ip") or "").strip()
    mac = str(attrs.get("mac") or "").strip()

    key = row.get("asset_key", "")
    if key.startswith("ip:") and not ip:
        ip = key[3:]
    if key.startswith("mac:") and not mac:
        mac = key[4:]

    if ip:
        out.append(scoped_ip_identity(site, ip))
    if mac:
        out.append(scoped_mac_identity(site, mac))
    if not out:
        out.append("key:%s/%s" % (site or UNKNOWN_SITE, key))
    return out


def merge(rows: Iterable[Dict], sites: Optional[Dict[str, str]] = None
          ) -> List[EstateAsset]:
    """Collapse per-collector asset rows into estate assets.

    `sites` maps collector_id -> site. A collector with no site recorded lands
    in `<unassigned>`, which is deliberately its OWN scope: guessing that two
    unsited collectors share a site is precisely the fusing error this exists to
    prevent.
    """
    sites = sites or {}
    rows = list(rows)

    union = _Union()
    per_row: List[Tuple[Dict, str, List[str]]] = []
    for row in rows:
        site = sites.get(row.get("collector_id", ""), "") or UNKNOWN_SITE
        idents = _identities(site, row)
        for ident in idents:
            union.add(ident)
        for other in idents[1:]:
            union.union(idents[0], other)          # an asset links its own ids
        per_row.append((row, site, idents))

    grouped: Dict[str, List[Tuple[Dict, str, List[str]]]] = {}
    for row, site, idents in per_row:
        grouped.setdefault(union.find(idents[0]), []).append((row, site, idents))

    assets: List[EstateAsset] = []
    for estate_id, members in sorted(grouped.items()):
        assets.append(_build(estate_id, members))
    _flag_cross_site_macs(assets)
    return assets


def _flag_cross_site_macs(assets: List[EstateAsset]) -> None:
    """Report a MAC seen at more than one site, on every asset that has it.

    Not a merge — see the module docstring. The operator is told the same
    hardware address appears at two plants and can decide whether that is a
    device that moved, a clone, or spoofing. The system does not guess.
    """
    by_mac: Dict[str, List[EstateAsset]] = {}
    for asset in assets:
        if asset.mac:
            by_mac.setdefault(asset.mac.lower(), []).append(asset)
    for mac, sharing in by_mac.items():
        sites = sorted({a.site for a in sharing})
        if len(sites) < 2:
            continue
        for asset in sharing:
            others = [s for s in sites if s != asset.site]
            asset.warnings.append(
                "MAC %s also appears at %s. NOT merged — a shared address across "
                "plants is a moved device, a clone, or spoofing, and fusing them "
                "would be unrecoverable. Confirm before treating as one device."
                % (mac, ", ".join(others)))


def _build(estate_id: str, members) -> EstateAsset:
    asset = EstateAsset(estate_id=estate_id)
    seen_sites: Set[str] = set()
    ips: Set[str] = set()
    macs: Set[str] = set()

    for row, site, _idents in members:
        attrs = dict(row.get("attributes") or {})
        contribution = Contribution(
            collector_id=row.get("collector_id", ""), site=site,
            asset_key=row.get("asset_key", ""),
            first_seen=row.get("first_seen"), last_seen=row.get("last_seen"),
            observation_count=int(row.get("observation_count") or 0),
            last_observed_window=row.get("last_observed_window", ""),
            last_coverage=row.get("last_coverage", "unknown"),
            attributes=attrs)
        asset.contributions.append(contribution)

        seen_sites.add(site)
        if attrs.get("ip"):
            ips.add(str(attrs["ip"]))
        if attrs.get("mac"):
            macs.add(str(attrs["mac"]).lower())
        if contribution.collector_id:
            if contribution.collector_id not in asset.collectors:
                asset.collectors.append(contribution.collector_id)

        # Earliest first_seen wins: a device present for a year must not become
        # one discovered today because a second collector met it last week.
        if contribution.first_seen is not None:
            asset.first_seen = (contribution.first_seen if asset.first_seen is None
                                else min(asset.first_seen, contribution.first_seen))
        if contribution.last_seen is not None:
            asset.last_seen = (contribution.last_seen if asset.last_seen is None
                               else max(asset.last_seen, contribution.last_seen))
        asset.observation_count += contribution.observation_count

        # Attributes merge, but a CONFLICT is reported rather than overwritten.
        for name, value in attrs.items():
            if value in (None, "", []):
                continue
            existing = asset.attributes.get(name)
            if existing in (None, "", []):
                asset.attributes[name] = value
            elif existing != value and name in ("vendor", "model", "firmware",
                                                "device_type"):
                asset.warnings.append(
                    "collectors disagree on %s: %r vs %r — the merge kept %r"
                    % (name, existing, value, existing))

    asset.sites = sorted(seen_sites)
    asset.site = asset.sites[0] if len(asset.sites) == 1 else ", ".join(asset.sites)
    asset.ip = sorted(ips)[0] if ips else ""
    asset.mac = sorted(macs)[0] if macs else ""

    if len(ips) > 1:
        asset.warnings.append(
            "multiple addresses on one device: %s" % ", ".join(sorted(ips)))
    return asset


# ── estate-wide coverage ───────────────────────────────────────────────────

@dataclass
class EstateCoverage:
    """What the estate view as a whole is worth.

    The weakest link, not an average. An estate answer built from four healthy
    collectors and one blind one is not 80% trustworthy — it is an answer with a
    hole in it, and the hole is exactly where nobody is looking.
    """

    collectors: int = 0
    trustworthy_collectors: int = 0
    blind_collectors: List[str] = field(default_factory=list)
    degraded_collectors: List[str] = field(default_factory=list)
    collectors_with_gaps: List[str] = field(default_factory=list)

    @property
    def trustworthy(self) -> bool:
        return (self.collectors > 0
                and self.trustworthy_collectors == self.collectors)

    def explain(self) -> str:
        if self.collectors == 0:
            return "no collectors have reported — the estate view is empty, not clean"
        if self.trustworthy:
            return "%d collector(s), all reporting complete coverage" % self.collectors
        parts = []
        if self.blind_collectors:
            parts.append("%d could not measure capture loss (%s)"
                         % (len(self.blind_collectors),
                            ", ".join(sorted(self.blind_collectors))))
        if self.degraded_collectors:
            parts.append("%d dropped frames (%s)"
                         % (len(self.degraded_collectors),
                            ", ".join(sorted(self.degraded_collectors))))
        if self.collectors_with_gaps:
            parts.append("%d lost observations in transit (%s)"
                         % (len(self.collectors_with_gaps),
                            ", ".join(sorted(self.collectors_with_gaps))))
        return ("%d collector(s): %s — the estate view is incomplete and a "
                "clean result here does not mean a clean estate"
                % (self.collectors, "; ".join(parts)))


def estate_coverage(summaries) -> EstateCoverage:
    """Fold per-collector coverage into one honest estate statement."""
    out = EstateCoverage()
    for summary in summaries:
        out.collectors += 1
        if summary.trustworthy:
            out.trustworthy_collectors += 1
        if summary.unknown or summary.windows == 0:
            out.blind_collectors.append(summary.collector_id)
        if summary.degraded:
            out.degraded_collectors.append(summary.collector_id)
        if summary.gaps:
            out.collectors_with_gaps.append(summary.collector_id)
    return out
