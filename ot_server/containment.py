"""
What to do about a vulnerability you cannot patch (Dragos ledger #3).

Most OT vulnerabilities are not going to be patched this quarter, and often not
this year — the device is a relay in a substation, the vendor's fix needs an
outage, and the outage needs a season. "Patch it" is advice an operator has
already discounted before they finish reading it.

So the useful answer is the other one: what would CONTAIN this, given how the
plant is actually segmented and what this device actually talks to. That answer
needs two things the estate already holds and which have never been joined —
the derived zones and the observed flows — plus the one thing that makes it
trustworthy, which is knowing when not to give it.

THREE REFUSALS, AND EACH IS THE POINT
─────────────────────────────────────
**A guessed boundary produces a guessed rule.** Zones carry the basis of their
Purdue level (D6), and a level that came from the topology engine's fallback
describes the network no better than the subnet does. A firewall rule built on
that may be applied to a live plant network by somebody who trusts it, so it is
refused rather than qualified. `zones.ZoneConfidence.usable` already draws this
line for the policy engine; this uses the same one, per zone rather than per
estate, because one guessed zone should not suppress advice about a well-derived
one.

**No observed traffic means no safe rule.** An allow-list for a device nobody
has seen communicate is a list somebody invented. Applying it is as likely to
cut control traffic as to contain anything, so the answer is that we do not know
this device's communication profile — which is a real finding about the
monitoring, not a gap in the advice.

**An allow-list is only as complete as the window it was built from.** This is
the one that matters most and is easiest to miss. Passive observation sees what
spoke. A maintenance laptop that connects quarterly, a backup master that only
runs during a failover, an engineering workstation used twice a year — none of
them appear, and a rule that denies everything not observed will deny them. The
containment therefore always carries what it rests on, and when the coverage
behind it was degraded or unmeasurable it says so in the same breath as the
rule. Handing somebody a firewall change without that is handing them an outage
with a delay fuse.
"""
# NOTE: no `from __future__ import annotations` — imported by api.py's route
# factory, where postponed evaluation breaks FastAPI's annotation resolution.

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: A containment was produced and rests on a derived boundary.
PROPOSED = "proposed"
#: The zone this asset sits in was mostly guessed. No rule is offered.
REFUSED = "refused"
#: Nothing is known about what this device talks to, or which zone it is in.
UNKNOWN = "unknown"


@dataclass
class Containment:
    estate_id: str
    site: str = ""
    zone_id: str = ""
    purdue_level: int = -1
    #: How this zone's Purdue level was arrived at: role, protocol, defaulted.
    zone_basis: str = ""
    state: str = UNKNOWN
    reason: str = ""
    #: Sources observed talking to this asset from OUTSIDE its zone. These are
    #: what a containment rule has to keep working.
    allow: List[Dict[str, Any]] = field(default_factory=list)
    #: The rule that contains the vulnerability. Always an allow-list plus a
    #: deny, never a bare deny — a bare deny on a controller is an outage.
    rules: List[Dict[str, Any]] = field(default_factory=list)
    #: What this rule rests on, and what it cannot see.
    caveat: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "estate_id": self.estate_id, "site": self.site,
            "zone_id": self.zone_id, "purdue_level": self.purdue_level,
            "zone_basis": self.zone_basis, "state": self.state,
            "reason": self.reason, "allow": self.allow, "rules": self.rules,
            "caveat": self.caveat,
        }


def _zone_for(ip: str, topology) -> Optional[Any]:
    """The zone an address sits in, within one site's topology."""
    if not ip:
        return None
    for zone in getattr(topology, "zones", []) or []:
        if ip in (getattr(zone, "device_ips", None) or set()):
            return zone
    # Fall back to subnet containment, which is how TopologyEngine grouped them
    # in the first place.
    prefix = ".".join(ip.split(".")[:3])
    for zone in getattr(topology, "zones", []) or []:
        subnet = str(getattr(zone, "subnet", "") or "")
        if subnet.startswith(prefix + "."):
            return zone
    return None


def _coverage_caveat(coverage: str) -> str:
    """What the allow-list is worth, given the coverage it was built from.

    Always present, never only when things went wrong. An allow-list built from
    a COMPLETE window is still only as complete as the window's length, and an
    operator applying a rule needs that sentence either way.
    """
    base = ("This allow-list contains only sources observed talking to this "
            "device. A master that connects quarterly, a backup that runs "
            "during failover, or a maintenance laptop will not appear and will "
            "be denied.")
    if coverage == "complete":
        return base + " Capture was complete over the observed window."
    if coverage == "degraded":
        return (base + " Capture was DEGRADED over this window — frames were "
                "lost, so the list is a floor and is more likely to be missing "
                "a legitimate source than usual.")
    return (base + " Capture loss over this window could not be measured, so "
            "there is no basis for believing the list is complete. Treat it as "
            "a starting point for a conversation with operations, not as a "
            "change to apply.")


def contain(match: Dict[str, Any], asset: Dict[str, Any], topology,
            flows: List[Dict[str, Any]]) -> Containment:
    """The segmentation change that would contain one asset's vulnerabilities.

    `match` is an `AssetMatch.to_dict()`; `asset` an `EstateAsset.to_dict()`;
    `topology` that site's `SiteTopology`; `flows` the rehydrated CommFlows for
    the site.
    """
    estate_id = str(asset.get("estate_id") or match.get("estate_id") or "")
    site = str(asset.get("site") or "")
    ip = str(asset.get("ip") or "")
    result = Containment(estate_id=estate_id, site=site)

    if topology is None or not ip:
        result.state = UNKNOWN
        result.reason = (
            "no zone could be derived for this device, so there is no boundary "
            "to contain it at" if ip else
            "this device has no address in the estate, so no rule can name it")
        return result

    zone = _zone_for(ip, topology)
    if zone is None:
        result.state = UNKNOWN
        result.reason = ("this device is not inside any derived zone; a rule "
                         "would have to invent the boundary it enforces")
        return result

    result.zone_id = str(getattr(zone, "zone_id", "") or "")
    result.purdue_level = int(getattr(zone, "purdue_level", -1) or -1)
    result.zone_basis = str(
        (getattr(topology, "basis_by_zone", None) or {}).get(
            result.zone_id, "unknown"))

    if result.zone_basis == "defaulted":
        # The same line the policy engine draws, per zone rather than per
        # estate. One guessed zone must not suppress advice about a
        # well-derived neighbour, and must not produce advice about itself.
        result.state = REFUSED
        result.reason = (
            "this zone's Purdue level came from the topology engine's "
            "fallback rather than from an observed role or protocol. A "
            "firewall rule built on a guessed boundary may be applied to a "
            "live plant network, so none is offered.")
        return result

    inbound = [f for f in flows
               if str(f.get("dst_ip") or "") == ip
               and str(f.get("src_ip") or "")]
    if not inbound:
        result.state = UNKNOWN
        result.reason = (
            "nothing has been observed talking to this device, so any "
            "allow-list would be invented. That is a finding about the "
            "monitoring rather than a gap in the advice — a device nobody has "
            "seen communicate is a device nobody is watching.")
        return result

    for flow in sorted(inbound, key=lambda f: (str(f.get("src_ip")),
                                               int(f.get("port") or 0))):
        source = str(flow.get("src_ip") or "")
        source_zone = _zone_for(source, topology)
        result.allow.append({
            "src_ip": source,
            "src_zone": str(getattr(source_zone, "zone_id", "") or "outside"),
            "protocol": str(flow.get("protocol") or "").lower(),
            "port": int(flow.get("port") or 0),
            "crosses_zone": (source_zone is None
                             or getattr(source_zone, "zone_id", None)
                             != getattr(zone, "zone_id", None)),
        })

    worst = str(match.get("priority") or "unknown")
    result.rules = _rules(ip, result, worst)
    result.state = PROPOSED
    result.reason = (
        "contains %d vulnerability finding(s) at priority %s by restricting "
        "this device to the sources already observed reaching it"
        % (len(match.get("hits") or []), worst))
    result.caveat = _coverage_caveat(str(asset.get("coverage") or "unknown"))
    return result


def _rules(ip: str, result: Containment, priority: str) -> List[Dict[str, Any]]:
    """An allow-list followed by a deny, never a bare deny.

    A bare deny on a controller is an outage. The allow rules come first and
    carry the observed traffic; the deny is what actually contains the
    vulnerability, and it is last so that reading the list top to bottom reads
    as "keep these working, stop everything else".
    """
    rules: List[Dict[str, Any]] = []
    for index, allowed in enumerate(result.allow, start=1):
        rules.append({
            "order": index,
            "action": "allow",
            "src_ip": allowed["src_ip"],
            "dst_ip": ip,
            "protocol": allowed["protocol"] or "any",
            "port": allowed["port"] or 0,
            "rationale": ("observed traffic from %s%s — denying this would cut "
                          "control communication that is happening today"
                          % (allowed["src_ip"],
                             " across a zone boundary" if allowed["crosses_zone"]
                             else " inside the zone")),
        })
    rules.append({
        "order": len(rules) + 1,
        "action": "deny",
        "src_ip": "any",
        "dst_ip": ip,
        "protocol": "any",
        "port": 0,
        "rationale": ("this is the containment: everything not observed above "
                      "is denied to a device carrying %s-priority findings that "
                      "cannot be patched on the plant's timescale" % priority),
    })
    return rules


def contain_estate(matches: List[Dict[str, Any]],
                   assets: List[Dict[str, Any]],
                   topologies: List[Any],
                   flows_by_site: Dict[str, List[Dict[str, Any]]]
                   ) -> Dict[str, Containment]:
    """Containments for every asset with something worth containing.

    Only assets with a MATCHED vulnerability get one. An asset with nothing
    against it needs no containment, and producing one anyway would bury the
    handful that matter under a firewall change for every device in the plant.
    """
    by_site = {str(getattr(t, "site", "")): t for t in topologies or []}
    by_id = {str(a.get("estate_id") or ""): a for a in assets or []}

    out: Dict[str, Containment] = {}
    for match in matches or []:
        if str(match.get("state") or "") != "matched":
            continue
        estate_id = str(match.get("estate_id") or "")
        asset = by_id.get(estate_id)
        if asset is None:
            continue
        site = str(asset.get("site") or "")
        out[estate_id] = contain(match, asset, by_site.get(site),
                                 flows_by_site.get(site) or [])
    return out


def summarise(containments: Dict[str, Containment]) -> Dict[str, Any]:
    """What the console needs to say about the set as a whole."""
    values = list(containments.values())
    return {
        "proposed": sum(1 for c in values if c.state == PROPOSED),
        "refused": sum(1 for c in values if c.state == REFUSED),
        "unknown": sum(1 for c in values if c.state == UNKNOWN),
        "explain": _summary_line(values),
    }


def _summary_line(values: List[Containment]) -> str:
    if not values:
        return ("nothing has matched a vulnerability, so there is nothing to "
                "contain")
    proposed = sum(1 for c in values if c.state == PROPOSED)
    refused = sum(1 for c in values if c.state == REFUSED)
    unknown = sum(1 for c in values if c.state == UNKNOWN)
    parts = ["%d with a containment" % proposed]
    if refused:
        parts.append("%d refused because the zone was mostly guessed" % refused)
    if unknown:
        parts.append("%d where nothing was observed talking to the device"
                     % unknown)
    return "%d device(s) with findings: %s" % (len(values), "; ".join(parts))
