"""
Who talks to whom (Dragos ledger #6).

Flows have been stored since Phase 3 and rehydrated since Phase 4. They feed the
zone derivation, the attack paths, the policy engine, and — since D11 and D12 —
every containment rule and every corrected severity in the product. Nothing has
ever shown them to an operator.

That is a strange gap: the evidence under half the console's conclusions was
invisible, so a containment rule could say "denying this would cut control
communication happening today" without the operator being able to look at the
communication in question.

DIRECTION IS THE ANALYTIC, NOT VOLUME
─────────────────────────────────────
A list of conversations sorted by packet count is a network graph, and a
substation operator already has one of those. What they do not have is the
answer to "is anything reaching down into the control layer from above", which
is what segmentation exists to prevent and what an incident usually looks like
on the way in.

Purdue levels run 0 (process) to 5 (internet). A flow from a HIGHER level to a
LOWER one is enterprise reaching toward the process — `downstream` here, because
that is the direction of consequence rather than the direction of the number.

AND IT IS ONLY AN ANALYTIC WHERE BOTH LEVELS WERE DERIVED
─────────────────────────────────────────────────────────
Calling a flow a segmentation concern when one of its two Purdue levels came
from the topology engine's fallback would be the same error D6, D11 and D12 all
refuse — a confident statement resting on a guess. A flow whose endpoints do not
both sit in a derived zone is reported with direction `undetermined`, which is
visibly not the same as `lateral`.

WHAT AN EMPTY LIST MEANS
────────────────────────
What was observed, over windows whose coverage is stated. A conversation that
did not happen during the window does not appear, and neither does one that
happened while a collector was dropping frames. So the count is a floor, and on
anything short of complete coverage it says so — the same rule as every other
count in this console.
"""
# NOTE: no `from __future__ import annotations` — imported by api.py's route
# factory, where postponed evaluation breaks FastAPI's annotation resolution.

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Toward the process: a higher Purdue level reaching a lower one. The direction
#: segmentation exists to control.
DOWNSTREAM = "downstream"
#: Toward the enterprise: a controller reporting upward, which is ordinary.
UPSTREAM = "upstream"
#: Within one level.
LATERAL = "lateral"
#: At least one endpoint's level was not derived, so there is no direction to
#: state. Deliberately not "lateral".
UNDETERMINED = "undetermined"


@dataclass
class Endpoint:
    ip: str = ""
    estate_id: str = ""
    label: str = ""
    zone_id: str = ""
    purdue_level: int = -1
    zone_basis: str = "unknown"
    #: True when this address talked but the inventory holds no device for it.
    unknown_device: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"ip": self.ip, "estate_id": self.estate_id,
                "label": self.label, "zone_id": self.zone_id,
                "purdue_level": self.purdue_level,
                "zone_basis": self.zone_basis,
                "unknown_device": self.unknown_device}


@dataclass
class Conversation:
    site: str = ""
    protocol: str = ""
    port: int = 0
    packets: int = 0
    src: Endpoint = field(default_factory=Endpoint)
    dst: Endpoint = field(default_factory=Endpoint)
    direction: str = UNDETERMINED
    crosses_zone: bool = False
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"site": self.site, "protocol": self.protocol,
                "port": self.port, "packets": self.packets,
                "src": self.src.to_dict(), "dst": self.dst.to_dict(),
                "direction": self.direction, "crosses_zone": self.crosses_zone,
                "note": self.note}


def _label(asset: Optional[Dict[str, Any]], ip: str) -> str:
    """How a person recognises the device, not how the system stores it."""
    if asset is None:
        return ip
    attrs = asset.get("attributes") or {}
    parts = [str(attrs.get("vendor") or ""), str(attrs.get("model") or "")]
    role = str(attrs.get("role") or "")
    name = " ".join(p for p in parts if p).strip()
    if name and role:
        return "%s (%s)" % (name, role)
    return name or role or ip


def _endpoint(ip: str, assets_by_ip: Dict[str, Dict[str, Any]],
              zone_lookup) -> Endpoint:
    asset = assets_by_ip.get(ip)
    zone, basis = zone_lookup(ip)
    return Endpoint(
        ip=ip,
        estate_id=str((asset or {}).get("estate_id") or ""),
        label=_label(asset, ip),
        zone_id=str(getattr(zone, "zone_id", "") or ""),
        purdue_level=int(getattr(zone, "purdue_level", -1) or -1),
        zone_basis=basis,
        # An address that talked and has no device in the inventory. Same
        # family as an orphaned detection: the estate has evidence of a device
        # it cannot show.
        unknown_device=asset is None)


def direction_of(src: Endpoint, dst: Endpoint) -> str:
    """Which way this conversation runs, in consequence rather than in number.

    `undetermined` when either level was not derived. Calling that `lateral`
    would be a confident statement resting on a guess.
    """
    if (src.purdue_level < 0 or dst.purdue_level < 0
            or src.zone_basis == "defaulted" or dst.zone_basis == "defaulted"):
        return UNDETERMINED
    if src.purdue_level > dst.purdue_level:
        return DOWNSTREAM
    if src.purdue_level < dst.purdue_level:
        return UPSTREAM
    return LATERAL


def conversations(flows: List[Dict[str, Any]], assets: List[Dict[str, Any]],
                  sites: Dict[str, str], zone_lookup_for) -> List[Conversation]:
    """Every observed conversation, with both endpoints resolved.

    `zone_lookup_for(site)` returns a callable mapping an address to
    `(zone, basis)` — the same lookup containment and severity use, passed in
    rather than recomputed.
    """
    by_site_ip: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for asset in assets or []:
        ip = str(asset.get("ip") or "")
        if ip:
            by_site_ip.setdefault(str(asset.get("site") or ""), {})[ip] = asset

    out: List[Conversation] = []
    for flow in flows or []:
        attrs = flow.get("attributes") or {}
        source = str(attrs.get("src_ip") or "")
        destination = str(attrs.get("dst_ip") or "")
        if not source or not destination:
            continue
        site = sites.get(str(flow.get("collector_id") or ""), "") or ""
        lookup = zone_lookup_for(site)
        assets_by_ip = by_site_ip.get(site, {})

        src = _endpoint(source, assets_by_ip, lookup)
        dst = _endpoint(destination, assets_by_ip, lookup)
        port = attrs.get("dst_port") or 0
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = 0

        conversation = Conversation(
            site=site, protocol=str(attrs.get("protocol") or "").lower(),
            port=port,
            packets=int(attrs.get("packet_count")
                        or flow.get("observation_count") or 0),
            src=src, dst=dst, direction=direction_of(src, dst),
            crosses_zone=bool(src.zone_id and dst.zone_id
                              and src.zone_id != dst.zone_id))
        if src.unknown_device or dst.unknown_device:
            conversation.note = (
                "an endpoint here talked but the inventory holds no device for "
                "it — the estate has evidence of a device it cannot show")
        out.append(conversation)

    out.sort(key=lambda c: (c.direction != DOWNSTREAM, -c.packets, c.src.ip))
    return out


def summarise(items: List[Conversation], coverage_explain: str,
              trustworthy: bool) -> Dict[str, Any]:
    downstream = [c for c in items if c.direction == DOWNSTREAM]
    undetermined = [c for c in items if c.direction == UNDETERMINED]
    unknown_endpoints = sorted({
        endpoint.ip for c in items for endpoint in (c.src, c.dst)
        if endpoint.unknown_device})

    return {
        "observed": len(items),
        "downstream": len(downstream),
        "crossing_zones": sum(1 for c in items if c.crosses_zone),
        "undetermined": len(undetermined),
        "unknown_endpoints": unknown_endpoints,
        "coverage_explain": coverage_explain,
        "trustworthy": trustworthy,
        "explain": _explain(len(items), len(downstream), len(undetermined),
                            len(unknown_endpoints), trustworthy),
    }


def _explain(total: int, downstream: int, undetermined: int,
             unknown_endpoints: int, trustworthy: bool) -> str:
    if total == 0:
        return ("no conversations have been observed. That is what the windows "
                "held, not a statement that the plant is quiet")

    parts = ["%d conversation(s) observed" % total]
    if downstream:
        parts.append("%d reaching down toward the process from a higher level"
                     % downstream)
    if undetermined:
        parts.append("%d whose direction cannot be stated because a Purdue "
                     "level was not derived" % undetermined)
    if unknown_endpoints:
        parts.append("%d address(es) talking that the inventory has no device "
                     "for" % unknown_endpoints)

    tail = ("" if trustworthy else
            " — and this is a floor rather than a total: a conversation that "
            "happened while a collector was dropping frames does not appear")
    return "; ".join(parts) + tail
