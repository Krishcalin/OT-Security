"""
Normalised observation records (OTS-ANL-002, ANL-004, ANL-005).

What a collector puts on the wire. This is the contract between the plant and
the server, and it is deliberately narrow.

WHAT IS NOT IN HERE
───────────────────
Packet payloads. A collector sits inside an operator's process network, and the
bytes on that network are the plant's business — setpoints, tag names, sometimes
credentials in cleartext protocols that predate authentication. Shipping them to
a central server by default would make this system a data-exfiltration path with
a security label on it, and in many jurisdictions the pcap cannot leave the site
at all. Raw frames stay on the collector; only what was *concluded* travels
(OTS-TRN-006 governs the per-incident exception).

EVERY RECORD CARRIES ITS OWN PROVENANCE
───────────────────────────────────────
first_seen / last_seen / observation_count, the collector that saw it, and the
window's coverage. The server merges records from several collectors and cannot
reconstruct any of that afterwards — a merge that invents `first_seen` from
arrival time turns a device present for a year into one discovered today, which
is precisely the signal an operator watches for.

COVERAGE TRAVELS WITH THE FINDING
─────────────────────────────────
Each record names the window it came from and that window's coverage state. A
detection derived from a window that dropped frames is not the same claim as one
from a complete window, and the difference has to survive the trip to the server
or it is not a property of the finding at all.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RecordKind(str, Enum):
    ASSET = "asset"
    FLOW = "flow"
    EVENT = "event"
    DETECTION = "detection"


@dataclass
class Provenance:
    """Where a record came from and how much to trust it."""

    collector_id: str = ""
    window_id: str = ""
    coverage: str = "unknown"
    rulepack_version: str = ""
    analyzer_version: str = ""

    @property
    def from_complete_window(self) -> bool:
        return self.coverage == "complete"


@dataclass
class Observation:
    """Fields every record carries, whatever it describes."""

    key: str                                  # stable identity for merging
    kind: RecordKind = RecordKind.ASSET
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    observation_count: int = 0
    provenance: Provenance = field(default_factory=Provenance)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "kind": self.kind.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observation_count": self.observation_count,
            "provenance": asdict(self.provenance),
            "attributes": dict(self.attributes),
        }


def asset_key(ip: str = "", mac: str = "") -> str:
    """Identity for merging the same device seen by two collectors.

    IP first because it is what the protocol analysers key on; MAC as the
    fallback for L2-only devices (a GOOSE publisher has no IP). Never a hash of
    both — two collectors on different VLANs may see one and not the other, and
    a combined key would make them two assets.
    """
    if ip:
        return "ip:%s" % ip
    if mac:
        return "mac:%s" % mac.lower()
    return "unknown"


def flow_key(src: str, dst: str, proto: str, port: Any) -> str:
    return "flow:%s>%s/%s/%s" % (src, dst, proto, port)


def detection_key(asset: str, rule_id: str) -> str:
    return "det:%s:%s" % (asset, rule_id)


#: Attributes never emitted, whatever an analyser attaches to a device. Payload
#: bytes are the plant's data, not the finding.
_FORBIDDEN_ATTRS = frozenset({
    "payload", "raw", "raw_bytes", "packet", "packets", "buffer", "data",
    "plugin_output", "frame",
})


def scrub(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """Drop payload-bearing fields and anything binary.

    Belt and braces: the builders below never put payloads in, and this makes it
    so a future analyser attaching one cannot leak it by accident. Bytes are
    removed rather than encoded — base64 of a payload is still the payload.
    """
    out: Dict[str, Any] = {}
    for name, value in attributes.items():
        if name.lower() in _FORBIDDEN_ATTRS:
            continue
        if isinstance(value, (bytes, bytearray, memoryview)):
            continue
        out[name] = value
    return out


class ObservationBuilder:
    """Turns analyser output into records, keeping identity stable across windows.

    Holds the first_seen/observation_count history so a device seen in ten
    consecutive windows reports one record with a count of ten rather than ten
    records that look like ten discoveries.
    """

    def __init__(self, collector_id: str = "", rulepack_version: str = "",
                 analyzer_version: str = ""):
        self.collector_id = collector_id
        self.rulepack_version = rulepack_version
        self.analyzer_version = analyzer_version
        self._history: Dict[str, Dict[str, Any]] = {}

    def _provenance(self, window_id: str, coverage: str) -> Provenance:
        return Provenance(collector_id=self.collector_id, window_id=window_id,
                          coverage=coverage,
                          rulepack_version=self.rulepack_version,
                          analyzer_version=self.analyzer_version)

    def _track(self, key: str, seen_at: Optional[float]) -> Dict[str, Any]:
        entry = self._history.setdefault(
            key, {"first_seen": seen_at, "count": 0})
        if entry["first_seen"] is None:
            entry["first_seen"] = seen_at
        entry["count"] += 1
        entry["last_seen"] = seen_at
        return entry

    def observe(self, key: str, kind: RecordKind, attributes: Dict[str, Any],
                window_id: str, coverage: str,
                seen_at: Optional[float] = None) -> Observation:
        entry = self._track(key, seen_at)
        return Observation(
            key=key, kind=kind,
            first_seen=entry["first_seen"], last_seen=entry["last_seen"],
            observation_count=entry["count"],
            provenance=self._provenance(window_id, coverage),
            attributes=scrub(attributes))

    # ── shapes ────────────────────────────────────────────────────────────
    def asset(self, device, window_id: str, coverage: str,
              seen_at: Optional[float] = None) -> Observation:
        attrs = {
            "ip": getattr(device, "ip", "") or "",
            "mac": getattr(device, "mac", "") or "",
            "vendor": getattr(device, "vendor", "") or "",
            # `make` is not `vendor`: vendor is who wrote the firmware,
            # make is the badge on the front. "Schneider Electric" vs
            # "Schneider Electric (Modicon)". The CVE corpus matches on both.
            "make": getattr(device, "make", "") or "",
            "model": getattr(device, "model", "") or "",
            "firmware": getattr(device, "firmware", "") or "",
            "os_name": getattr(device, "os_name", "") or "",
            "os_version": getattr(device, "os_version", "") or "",
            "hostname": getattr(device, "hostname", "") or "",
            "serial_number": getattr(device, "serial_number", "") or "",
            # The station address, not the IP. See OTDevice.asset_identifier.
            "asset_identifier": getattr(device, "asset_identifier", "") or "",
            # An identification with no provenance is a claim. This is what
            # lets the console show a version and say where it came from.
            "identified_by": getattr(device, "identified_by", "") or "",
            "device_type": str(getattr(device, "device_type", "") or ""),
            "role": getattr(device, "role", "") or "",
            "criticality": getattr(device, "criticality", "") or "",
            "purdue_level": getattr(device, "purdue_level", None),
            "protocols": sorted(_protocol_names(device)),
            "risk_score": getattr(device, "risk_score", None),
            "risk_level": getattr(device, "risk_level", None),
            "vendor_confidence": getattr(device, "vendor_confidence", "") or "",
        }
        return self.observe(asset_key(attrs["ip"], attrs["mac"]),
                            RecordKind.ASSET, attrs, window_id, coverage, seen_at)

    def flow(self, flow, window_id: str, coverage: str,
             seen_at: Optional[float] = None) -> Observation:
        src = getattr(flow, "src_ip", "") or ""
        dst = getattr(flow, "dst_ip", "") or ""
        proto = getattr(flow, "protocol", "") or ""
        port = getattr(flow, "dst_port", "") or ""
        attrs = {
            "src_ip": src, "dst_ip": dst, "protocol": proto, "dst_port": port,
            "packet_count": getattr(flow, "packet_count", None),
            "byte_count": getattr(flow, "byte_count", None),
        }
        return self.observe(flow_key(src, dst, proto, port), RecordKind.FLOW,
                            attrs, window_id, coverage, seen_at)

    def detection(self, device_key: str, finding, window_id: str, coverage: str,
                  seen_at: Optional[float] = None) -> Observation:
        rule_id = (getattr(finding, "id", None)
                   or getattr(finding, "check_id", None)
                   or getattr(finding, "title", "") or "unknown")
        attrs = {
            "rule_id": rule_id,
            "title": getattr(finding, "title", "") or "",
            "severity": str(getattr(finding, "severity", "") or ""),
            "description": getattr(finding, "description", "") or "",
            "remediation": getattr(finding, "remediation", "") or "",
            "protocol": getattr(finding, "protocol", "") or "",
            "asset": device_key,
        }
        return self.observe(detection_key(device_key, rule_id),
                            RecordKind.DETECTION, attrs, window_id, coverage,
                            seen_at)


def _protocol_names(device) -> List[str]:
    out = []
    for det in getattr(device, "protocols", []) or []:
        name = getattr(det, "protocol", None) or getattr(det, "name", None)
        if name:
            out.append(str(name))
    return out


@dataclass
class ObservationBatch:
    """What one window ships. Idempotency key is content-derived so a replayed
    batch is recognisably the same batch (OTS-TRN-004)."""

    collector_id: str
    window_id: str
    coverage: str
    records: List[Observation] = field(default_factory=list)
    window: Dict[str, Any] = field(default_factory=dict)

    @property
    def batch_id(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.collector_id.encode())
        digest.update(self.window_id.encode())
        for record in self.records:
            digest.update(record.key.encode())
        return digest.hexdigest()[:32]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "collector_id": self.collector_id,
            "window_id": self.window_id,
            "coverage": self.coverage,
            "window": dict(self.window),
            "records": [r.to_dict() for r in self.records],
        }

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for record in self.records:
            out[record.kind.value] = out.get(record.kind.value, 0) + 1
        return out
