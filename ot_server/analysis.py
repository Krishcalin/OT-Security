"""
Server-side analysis engines over merged estate data (OTS-SRV-003).

Wires compliance, risk, attack-path and policy to the estate. Each was written
against the rich `OTDevice` a scan builds in memory; the estate holds a
normalised, serialised view. So this is a REHYDRATION, and rehydration is lossy.

THE NUMBER THAT MATTERS
───────────────────────
`OTDevice` has 49 fields. The collector's asset record feeds 10 of them.

The other 39 — session state, protocol detail, communication profile, logical
nodes, IT-protocol hits — either never leave the collector by design (they are
derived from packets, and packets stay in the plant) or were never in the wire
format. An engine handed a device missing three quarters of its fields will
still produce output, and that output will look exactly like output from a full
scan.

That is the failure this module refuses. Every engine result carries what it
could NOT consider, and an engine whose required inputs are absent is reported
SKIPPED rather than run on nothing.

WHY NOT JUST SHIP MORE FIELDS
─────────────────────────────
Some of them should be shipped, and that is a deliberate next step rather than
an oversight — widening the record is a change to the collector, the schema and
the server together, and doing it blind would guess at which fields matter. The
fidelity report here names exactly which absent fields each engine wanted, so
the widening can be driven by evidence instead of by intuition.

ZONES AND TOPOLOGY ARE NOT COMPUTED SERVER-SIDE YET
──────────────────────────────────────────────────
`topology/` is server-side by the partition but nothing yet derives Purdue zones
from estate data. Attack-path and policy require zones, so both are SKIPPED
rather than run. An attack path is a claim about reachability, and reachability
without segmentation data is a guess presented in the shape of a finding; a
generated firewall ruleset that does not know the segmentation it enforces could
be applied to a live plant network.

TWO VOCABULARIES THAT HAD DRIFTED
─────────────────────────────────
The collector calls a field `criticality`; `OTDevice` calls it
`device_criticality`. Rehydrating by name alone dropped it SILENTLY — the device
came back looking complete, criticality at its default, and every engine
downstream scored it as ordinary. `ATTRIBUTE_ALIASES` maps the two, and
`SHIPPED_FIELDS` is checked against the real dataclass by test rather than
trusted.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# The scanner package sits beside this one.
_HERE = os.path.dirname(os.path.abspath(__file__))
_SCANNER_ROOT = os.path.join(os.path.dirname(_HERE), "ot_scanner")
if _SCANNER_ROOT not in sys.path:
    sys.path.insert(0, _SCANNER_ROOT)

#: Fields the collector's asset record carries. Everything else in OTDevice is
#: absent after rehydration, and the engines are told so.
SHIPPED_FIELDS: Tuple[str, ...] = (
    "ip", "mac", "vendor", "model", "firmware", "device_type", "role",
    "device_criticality", "risk_score", "risk_level",
)

#: The collector's attribute name -> the OTDevice field it feeds. The two
#: vocabularies drifted apart (`criticality` vs `device_criticality`), and
#: setattr on a name the dataclass does not have fails silently — the device
#: would rehydrate looking fine and missing its criticality.
ATTRIBUTE_ALIASES: Dict[str, str] = {
    "criticality": "device_criticality",
}


class EngineStatus(str, Enum):
    RAN = "ran"
    DEGRADED = "degraded"       # ran, but without inputs it wanted
    SKIPPED = "skipped"         # required inputs absent; running would mislead
    ERROR = "error"


@dataclass
class Fidelity:
    """How much of a device survived the wire."""

    shipped: int = 0
    total: int = 0
    missing: List[str] = field(default_factory=list)

    @property
    def fraction(self) -> Optional[float]:
        return None if not self.total else self.shipped / self.total

    def explain(self) -> str:
        if self.fraction is None:
            return "device model unavailable"
        return ("%d of %d device fields survived the wire (%.0f%%); engines "
                "cannot consider the rest" % (self.shipped, self.total,
                                              self.fraction * 100))


@dataclass
class EngineResult:
    engine: str
    status: EngineStatus
    reason: str = ""
    limitations: List[str] = field(default_factory=list)
    result: Any = None

    @property
    def usable(self) -> bool:
        return self.status in (EngineStatus.RAN, EngineStatus.DEGRADED)

    @property
    def trustworthy(self) -> bool:
        """RAN with nothing missing. Anything else is a qualified answer."""
        return self.status is EngineStatus.RAN and not self.limitations

    def to_dict(self) -> Dict:
        return {"engine": self.engine, "status": self.status.value,
                "reason": self.reason, "limitations": list(self.limitations),
                "trustworthy": self.trustworthy}


def device_fidelity() -> Fidelity:
    """What the wire format costs, measured rather than assumed."""
    try:
        import dataclasses

        from scanner.models import OTDevice

        names = {f.name for f in dataclasses.fields(OTDevice)}
    except Exception:                                      # noqa: BLE001
        return Fidelity()
    shipped = set(SHIPPED_FIELDS) & names
    return Fidelity(shipped=len(shipped), total=len(names),
                    missing=sorted(names - shipped))


def rehydrate(asset: Dict, detections: Optional[List[Dict]] = None):
    """An estate asset as an OTDevice the engines can consume.

    Detections are re-attached as `vulnerabilities`, because they were computed
    on the collector where the packets were and are the one derived thing that
    does travel. Everything the wire format does not carry is left at its
    default — visibly empty rather than invented.
    """
    from scanner.models import OTDevice

    attrs = asset.get("attributes") or {}
    device = OTDevice(ip=asset.get("ip") or attrs.get("ip") or "")
    for name, value in attrs.items():
        target = ATTRIBUTE_ALIASES.get(name, name)
        if value in (None, "", []) or target not in SHIPPED_FIELDS:
            continue
        if hasattr(device, target):
            try:
                setattr(device, target, value)
            except Exception:                              # noqa: BLE001
                continue
    if asset.get("mac") and hasattr(device, "mac"):
        device.mac = asset["mac"]

    dropped = []
    for detection in detections or []:
        d_attrs = detection.get("attributes") or {}
        finding = _finding(d_attrs)
        if finding is None:
            dropped.append(str(d_attrs.get("rule_id") or "<unnamed>"))
        else:
            device.vulnerabilities.append(finding)
    if dropped:
        # Surfaced on the device rather than logged and forgotten. A detection
        # the collector raised and the server could not reconstruct must not
        # simply vanish between them.
        device.notes.append(
            "%d detection(s) could not be reconstructed server-side and are "
            "NOT reflected in any engine result: %s"
            % (len(dropped), ", ".join(sorted(dropped))))
    return device


def _finding(attrs: Dict):
    """A VulnerabilityFinding from a detection record, or None.

    The model requires vuln_id, title, severity, category and description. An
    earlier version supplied three of the five, raised TypeError, and a bare
    `except` turned that into a silent `None` — every collector detection was
    discarded on the way into the engines and the device looked clean. The
    caller now counts what it could not rebuild.
    """
    try:
        from scanner.models import VulnerabilityFinding

        rule_id = str(attrs.get("rule_id") or "")
        return VulnerabilityFinding(
            vuln_id=rule_id or "UNKNOWN",
            title=str(attrs.get("title") or rule_id or "unnamed detection"),
            severity=str(attrs.get("severity") or "info"),
            category=str(attrs.get("category") or attrs.get("protocol") or "ot"),
            description=str(attrs.get("description") or ""),
            remediation=str(attrs.get("remediation") or ""))
    except Exception:                                      # noqa: BLE001
        return None


# ── the engines ────────────────────────────────────────────────────────────

def _lost(fidelity: Fidelity, wanted: Tuple[str, ...]) -> List[str]:
    """Which fields this engine wanted and did not get.

    Named individually so widening the wire format can be driven by evidence:
    "compliance wants communication_profile" is actionable, "results may be
    incomplete" is not.
    """
    missing = set(fidelity.missing)
    return sorted(name for name in wanted if name in missing)


def run_compliance(devices, zones=None, violations=None,
                   fidelity: Optional[Fidelity] = None) -> EngineResult:
    """35 NERC CIP / IEC 62443 / NIST 800-82 controls over the estate."""
    fidelity = fidelity or device_fidelity()
    wanted = ("communication_profile", "it_protocols", "compensating_controls",
              "asset_owner", "config_drift_alerts")
    limitations = []
    lost = _lost(fidelity, wanted)
    if lost:
        limitations.append(
            "assessed without %s — controls depending on these are evaluated "
            "on partial evidence" % ", ".join(lost))
    if not zones:
        limitations.append(
            "no Purdue zones: segmentation controls (CIP-005, IEC 62443 "
            "zone/conduit) cannot be assessed and are not counted as passing")
    try:
        from scanner.compliance.engine import ComplianceMapper

        result = ComplianceMapper(devices, zones or [], violations or []).assess()
    except Exception as exc:                               # noqa: BLE001
        return EngineResult("compliance", EngineStatus.ERROR,
                            reason=type(exc).__name__)
    status = EngineStatus.DEGRADED if limitations else EngineStatus.RAN
    return EngineResult("compliance", status,
                        reason="assessed %d device(s)" % len(devices),
                        limitations=limitations, result=result)


def run_risk(devices, zones=None,
             fidelity: Optional[Fidelity] = None) -> EngineResult:
    """Composite multi-factor risk scoring."""
    fidelity = fidelity or device_fidelity()
    limitations = []
    lost = _lost(fidelity, ("cve_matches", "attack_paths", "it_protocols",
                            "communication_profile"))
    if lost:
        limitations.append(
            "scored without %s — the composite is computed from fewer factors "
            "than a local scan would use" % ", ".join(lost))
    if not zones:
        limitations.append("no zones: the exposure factor falls back to a "
                           "default rather than an observed Purdue level")
    try:
        from scanner.risk.engine import CompositeRiskEngine

        engine = CompositeRiskEngine(zones or [])
        for device in devices:
            engine.score_device(device)
    except Exception as exc:                               # noqa: BLE001
        return EngineResult("risk", EngineStatus.ERROR, reason=type(exc).__name__)
    status = EngineStatus.DEGRADED if limitations else EngineStatus.RAN
    return EngineResult("risk", status,
                        reason="scored %d device(s)" % len(devices),
                        limitations=limitations,
                        result=[getattr(d, "composite_risk_score", None)
                                for d in devices])


def _flows_are_typed(flows) -> bool:
    """True if these are CommFlow objects rather than stored dicts.

    Checked because the failure mode is silent: an engine handed dicts finds no
    attribute it recognises, produces nothing, and reports success.
    """
    return all(hasattr(f, "src_ip") and not isinstance(f, dict) for f in flows)


def run_attack_paths(devices, flows, zones=None, edges=None,
                     violations=None) -> EngineResult:
    """BFS pathfinding across the estate.

    SKIPPED without zones and edges. An attack path is a claim about
    reachability, and reachability without segmentation data is a guess — one
    that would be presented in the same shape as a real finding.
    """
    if not _flows_are_typed(flows):
        return EngineResult(
            "attack_paths", EngineStatus.ERROR,
            reason="flows were not rehydrated into CommFlow objects; the engine "
                   "would have found nothing and reported success")
    if not zones or not edges:
        return EngineResult(
            "attack_paths", EngineStatus.SKIPPED,
            reason="no usable Purdue zones. Either none could be derived, or the "
                   "derivation was mostly fallback levels and was rejected — see "
                   "the zone basis. An attack path computed without segmentation "
                   "data is a guess wearing the shape of a finding.")
    try:
        from scanner.attack.engine import AttackPathEngine

        paths = AttackPathEngine(devices, flows, zones, edges,
                                 violations or []).analyze()
    except Exception as exc:                               # noqa: BLE001
        return EngineResult("attack_paths", EngineStatus.ERROR,
                            reason=type(exc).__name__)
    return EngineResult("attack_paths", EngineStatus.RAN,
                        reason="%d path(s)" % len(paths), result=paths)


def run_policy(devices, flows, zones=None, violations=None,
               edges=None) -> EngineResult:
    """Firewall rule generation.

    SKIPPED without zones: a generated ruleset that does not know the
    segmentation it is enforcing is worse than none, because somebody may apply
    it to a live plant network.
    """
    if not _flows_are_typed(flows):
        return EngineResult(
            "policy", EngineStatus.ERROR,
            reason="flows were not rehydrated into CommFlow objects")
    if not zones:
        return EngineResult(
            "policy", EngineStatus.SKIPPED,
            reason="no usable Purdue zones. A ruleset generated without knowing "
                   "the segmentation it enforces could be applied to a live "
                   "plant network, so a mostly-guessed derivation is rejected "
                   "rather than used.")
    try:
        from scanner.policy.engine import PolicyEngine

        ruleset = PolicyEngine(devices, flows, zones, violations or [],
                               edges or []).generate()
    except Exception as exc:                               # noqa: BLE001
        return EngineResult("policy", EngineStatus.ERROR,
                            reason=type(exc).__name__)
    return EngineResult("policy", EngineStatus.RAN, reason="ruleset generated",
                        result=ruleset)


def run_drift(current: List[Dict], baseline: Optional[List[Dict]]) -> EngineResult:
    """Configuration drift against a baseline.

    SKIPPED without one. "Nothing changed" computed against no baseline is the
    most confident wrong answer available here.
    """
    if baseline is None:
        return EngineResult(
            "drift", EngineStatus.SKIPPED,
            reason="no baseline recorded; 'nothing changed' against no baseline "
                   "is a confident wrong answer")
    current_keys = {a.get("estate_id") for a in current}
    baseline_keys = {a.get("estate_id") for a in baseline}
    appeared = sorted(current_keys - baseline_keys)
    disappeared = sorted(baseline_keys - current_keys)
    return EngineResult(
        "drift", EngineStatus.RAN,
        reason="%d appeared, %d no longer observed"
               % (len(appeared), len(disappeared)),
        limitations=(["assets that disappeared are NOT OBSERVED, not "
                      "necessarily removed (OTS-SRV-005)"] if disappeared else []),
        result={"appeared": appeared, "disappeared": disappeared})


@dataclass
class AnalysisReport:
    fidelity: Fidelity = field(default_factory=Fidelity)
    engines: List[EngineResult] = field(default_factory=list)
    coverage_explain: str = ""
    #: How the Purdue levels underneath these results were arrived at. Carried
    #: even when the zones were rejected, because "we derived zones and did not
    #: trust them" is a different state from "we had none".
    zone_basis: str = ""

    @property
    def any_trustworthy(self) -> bool:
        return any(e.trustworthy for e in self.engines)

    def to_dict(self) -> Dict:
        return {
            "fidelity": {"shipped": self.fidelity.shipped,
                         "total": self.fidelity.total,
                         "explain": self.fidelity.explain()},
            "coverage": self.coverage_explain,
            "zones": self.zone_basis,
            "engines": [e.to_dict() for e in self.engines],
            "skipped": [e.engine for e in self.engines
                        if e.status is EngineStatus.SKIPPED],
        }


def run_all(assets: List[Dict], detections: Optional[List[Dict]] = None,
            flows: Optional[List[Dict]] = None,
            zones=None, edges=None, violations=None,
            baseline: Optional[List[Dict]] = None,
            coverage_explain: str = "",
            sites: Optional[Dict[str, str]] = None,
            derive_zones: bool = True) -> AnalysisReport:
    """Every server-side engine over the merged estate, each stating its limits.

    Zones are derived per site when not supplied. A derivation whose levels came
    mostly from the topology engine's fallback does NOT unblock the engines that
    need segmentation: "we had no zones" is visibly absent, "we had bad zones" is
    confidently wrong, and the second is the worse failure.
    """
    fidelity = device_fidelity()
    zone_note = ""
    if zones is None and derive_zones:
        from . import zones as zone_derivation

        topologies = zone_derivation.derive(assets, flows or [], sites)
        confidence = zone_derivation.overall_confidence(topologies)
        zone_note = confidence.explain()
        if confidence.usable:
            zones, violations_derived, edges_derived = zone_derivation.flatten(
                topologies)
            violations = violations if violations is not None else violations_derived
            edges = edges if edges is not None else edges_derived
        else:
            # Derived, but not good enough to build a firewall rule on.
            zones = None
    by_asset: Dict[str, List[Dict]] = {}
    for detection in detections or []:
        by_asset.setdefault(detection.get("asset_key", ""), []).append(detection)

    devices = [rehydrate(a, by_asset.get(a.get("estate_id", ""), []))
               for a in assets]

    # Rehydrated ONCE, here. Passing the stored dicts straight through let
    # attack-paths iterate records it could not read, find nothing, and report
    # RAN — indistinguishable from a network with no attack paths.
    from . import zones as _zone_module

    comm_flows = [_zone_module.rehydrate_flow(f) for f in (flows or [])]
    comm_flows = [f for f in comm_flows if f.src_ip and f.dst_ip]

    report = AnalysisReport(fidelity=fidelity, coverage_explain=coverage_explain,
                            zone_basis=zone_note)
    report.engines = [
        run_compliance(devices, zones, violations, fidelity),
        run_risk(devices, zones, fidelity),
        run_attack_paths(devices, comm_flows, zones, edges, violations),
        run_policy(devices, comm_flows, zones, violations, edges),
        run_drift(assets, baseline),
    ]
    return report
