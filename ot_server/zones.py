"""
Server-side Purdue zone derivation (unblocks OTS-SRV-003 and OTS-CON-005).

One missing piece was blocking three: attack-path analysis, firewall policy
generation and the topology view. All three need zones, and nothing derived them
from estate data.

ZONES ARE DERIVED PER SITE, NEVER ACROSS THE ESTATE
───────────────────────────────────────────────────
The same trap as the asset merge, one level up. `TopologyEngine` groups devices
into /24 subnets, and 10.10.1.0/24 exists at almost every plant. Deriving across
the estate would fuse two substations' subnets into one zone — and then a
cross-zone violation between plants would look like a segmentation breach inside
one, while a real breach inside a plant would be hidden by the merge.

So each site is analysed independently and the zones carry their site.

A PURDUE LEVEL IS AN INFERENCE, AND THE ENGINE DOES NOT SAY WHICH
─────────────────────────────────────────────────────────────────
`_assign_purdue_levels` has a documented fallback: "Default to Level 1 for any
zone with OT protocols." It always returns a level. A zone whose role was
recognised and a zone that fell through to the default are indistinguishable in
the output, and both are then consumed by attack-path analysis and by a firewall
rule generator whose output someone may apply to a live plant network.

This module does not change that engine — the local scanner's behaviour stays
as it is — but it classifies each zone's BASIS afterwards by re-running the same
predicates, and reports how many levels were guessed. Downstream engines receive
that as a stated limitation rather than inheriting a confident number.

    ROLE      the dominant device role mapped directly — the strongest signal
    PROTOCOL  inferred from the protocol mix
    DEFAULTED the fallback fired; this level is a guess

A derivation that is mostly DEFAULTED is not a segmentation model. It is a
subnet listing with numbers attached, and saying so is the difference between a
useful analysis and a confident wrong one.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCANNER_ROOT = os.path.join(os.path.dirname(_HERE), "ot_scanner")
if _SCANNER_ROOT not in sys.path:
    sys.path.insert(0, _SCANNER_ROOT)

from .analysis import rehydrate  # noqa: E402

UNKNOWN_SITE = "<unassigned>"


class ZoneBasis(str, Enum):
    ROLE = "role"
    PROTOCOL = "protocol"
    DEFAULTED = "defaulted"


@dataclass
class ZoneConfidence:
    """How much of this derivation was observed versus guessed."""

    zones: int = 0
    by_basis: Dict[str, int] = field(default_factory=dict)

    @property
    def defaulted(self) -> int:
        return self.by_basis.get(ZoneBasis.DEFAULTED.value, 0)

    @property
    def guessed_fraction(self) -> Optional[float]:
        return None if not self.zones else self.defaulted / self.zones

    @property
    def usable(self) -> bool:
        """Whether this is a segmentation model or a subnet listing.

        A derivation where most levels came from the fallback describes the
        network no better than the subnets alone, and feeding it to a policy
        generator would dress a guess as a control.
        """
        frac = self.guessed_fraction
        return frac is not None and frac < 0.5

    def explain(self) -> str:
        if self.zones == 0:
            return "no zones could be derived — no assets with addresses"
        parts = ["%d %s" % (count, basis)
                 for basis, count in sorted(self.by_basis.items())]
        note = "" if self.usable else (
            " — more than half the levels came from the fallback, so this is a "
            "subnet listing with numbers attached rather than a segmentation "
            "model")
        return "%d zone(s): %s%s" % (self.zones, ", ".join(parts), note)


@dataclass
class SiteTopology:
    site: str
    zones: List[Any] = field(default_factory=list)
    violations: List[Any] = field(default_factory=list)
    edges: List[Any] = field(default_factory=list)
    confidence: ZoneConfidence = field(default_factory=ZoneConfidence)
    basis_by_zone: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "site": self.site,
            "zones": [
                {"zone_id": z.zone_id, "subnet": z.subnet,
                 "purdue_level": z.purdue_level, "purdue_label": z.purdue_label,
                 "device_count": z.device_count,
                 "dominant_role": z.dominant_role,
                 "level_basis": self.basis_by_zone.get(z.zone_id, "unknown")}
                for z in self.zones],
            "violations": len(self.violations),
            "edges": len(self.edges),
            "confidence": {
                "zones": self.confidence.zones,
                "defaulted": self.confidence.defaulted,
                "usable": self.confidence.usable,
                "explain": self.confidence.explain(),
            },
        }


def rehydrate_flow(row: Dict):
    """A stored flow record as the CommFlow the topology engine expects."""
    from scanner.models import CommFlow

    attrs = row.get("attributes") or {}
    return CommFlow(
        src_ip=str(attrs.get("src_ip") or ""),
        dst_ip=str(attrs.get("dst_ip") or ""),
        protocol=str(attrs.get("protocol") or ""),
        port=int(attrs.get("dst_port") or 0) if str(
            attrs.get("dst_port") or "").isdigit() else 0,
        packet_count=int(attrs.get("packet_count") or 0),
        byte_count=int(attrs.get("byte_count") or 0))


def _basis_for(engine, zone, device_map) -> ZoneBasis:
    """Which rule actually decided this zone's level.

    Re-runs the engine's own predicates rather than guessing, so the
    classification cannot drift from the assignment it describes.
    """
    try:
        if engine._purdue_from_role(zone.dominant_role) is not None:
            return ZoneBasis.ROLE
    except Exception:                                      # noqa: BLE001
        pass
    try:
        from scanner.topology.engine import DEFAULT_PURDUE_LEVEL  # type: ignore

        default_level = DEFAULT_PURDUE_LEVEL
    except Exception:                                      # noqa: BLE001
        default_level = 1                                  # documented fallback
    try:
        level = engine._purdue_from_protocols(zone, device_map)
    except Exception:                                      # noqa: BLE001
        return ZoneBasis.DEFAULTED
    # The protocol path itself ends in the same fallback, so a level equal to
    # the default with no OT-protocol evidence is a guess, not an inference.
    if level == default_level and not zone.protocols_seen:
        return ZoneBasis.DEFAULTED
    return ZoneBasis.PROTOCOL


def derive_for_site(site: str, assets: List[Dict],
                    flows: List[Dict]) -> SiteTopology:
    """Zones, violations and edges for ONE site."""
    from scanner.topology.engine import TopologyEngine

    devices = [rehydrate(a, []) for a in assets]
    devices = [d for d in devices if getattr(d, "ip", "")]
    comm = [rehydrate_flow(f) for f in flows]
    comm = [f for f in comm if f.src_ip and f.dst_ip]

    topology = SiteTopology(site=site)
    if not devices:
        return topology

    engine = TopologyEngine()
    zones, violations, edges = engine.analyze(devices, comm)
    topology.zones = zones
    topology.violations = violations
    topology.edges = edges

    device_map = {d.ip: d for d in devices}
    counts: Dict[str, int] = {}
    for zone in zones:
        basis = _basis_for(engine, zone, device_map)
        topology.basis_by_zone[zone.zone_id] = basis.value
        counts[basis.value] = counts.get(basis.value, 0) + 1
    topology.confidence = ZoneConfidence(zones=len(zones), by_basis=counts)
    return topology


def derive(assets: List[Dict], flows: List[Dict],
           sites: Optional[Dict[str, str]] = None) -> List[SiteTopology]:
    """Per-site topology across the estate.

    Assets carry their site from the merge; flows are attributed by the
    collector that reported them. A flow whose collector has no site lands in
    `<unassigned>`, with the same reasoning as the asset merge: guessing that
    two unsited collectors share a plant is the error this avoids.
    """
    sites = sites or {}
    by_site_assets: Dict[str, List[Dict]] = {}
    for asset in assets:
        site = asset.get("site") or UNKNOWN_SITE
        # A merged asset spanning sites cannot belong to one zone; it is
        # excluded rather than assigned arbitrarily.
        if "," in site:
            continue
        by_site_assets.setdefault(site, []).append(asset)

    by_site_flows: Dict[str, List[Dict]] = {}
    for flow in flows:
        site = sites.get(flow.get("collector_id", ""), "") or UNKNOWN_SITE
        by_site_flows.setdefault(site, []).append(flow)

    return [derive_for_site(site, site_assets, by_site_flows.get(site, []))
            for site, site_assets in sorted(by_site_assets.items())]


def flatten(topologies: List[SiteTopology]) -> Tuple[List, List, List]:
    """All zones, violations and edges across sites, for engines that take them
    as flat lists. The per-site derivation is what matters; this is only the
    hand-off."""
    zones: List = []
    violations: List = []
    edges: List = []
    for topology in topologies:
        zones.extend(topology.zones)
        violations.extend(topology.violations)
        edges.extend(topology.edges)
    return zones, violations, edges


def overall_confidence(topologies: List[SiteTopology]) -> ZoneConfidence:
    """Estate-wide, and — as everywhere else here — not an average.

    One site derived entirely from defaults drags the whole estate's usability
    down, because the engines consuming these zones cannot tell which site a
    given zone came from once the lists are flattened.
    """
    total = ZoneConfidence()
    for topology in topologies:
        total.zones += topology.confidence.zones
        for basis, count in topology.confidence.by_basis.items():
            total.by_basis[basis] = total.by_basis.get(basis, 0) + count
    return total
