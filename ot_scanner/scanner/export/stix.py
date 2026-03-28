"""
STIX 2.1 bundle exporter for OT Passive Scanner findings.

Generates a STIX 2.1 JSON bundle containing observed indicators from
the scan.  Intended for sharing threat intelligence with ISACs, SOCs,
and downstream STIX/TAXII consumers.

STIX object types produced:
  - Identity       (scanner tool itself)
  - Infrastructure (one per discovered OT device)
  - Vulnerability  (one per unique finding across all devices)
  - Indicator      (one per CVE match with NOW priority)
  - Relationship   (infrastructure --has--> vulnerability)
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

from ..models import OTDevice


# ────────────────────────────────────────────────── Helpers ──

_NAMESPACE = uuid.NAMESPACE_URL
_SPEC_VERSION = "2.1"


def _deterministic_uuid(prefix: str, seed: str) -> str:
    """Generate a deterministic STIX ID using uuid5.

    Parameters
    ----------
    prefix : str
        STIX object type (e.g. ``"infrastructure"``, ``"vulnerability"``).
    seed : str
        Unique string for this object (e.g. device IP, vuln ID).

    Returns
    -------
    str
        A STIX identifier like ``"infrastructure--<uuid>"``.
    """
    return f"{prefix}--{uuid.uuid5(_NAMESPACE, f'{prefix}:{seed}')}"


def _now_iso() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _base_sdo(sdo_type: str, sdo_id: str, **kwargs: Any) -> Dict[str, Any]:
    """Create a base STIX Domain Object dict with common properties."""
    ts = _now_iso()
    obj: Dict[str, Any] = {
        "type": sdo_type,
        "spec_version": _SPEC_VERSION,
        "id": sdo_id,
        "created": ts,
        "modified": ts,
    }
    obj.update(kwargs)
    return obj


# ────────────────────────────────────────────────── Exporter ──

class STIXExporter:
    """
    Export OT scan results as a STIX 2.1 JSON bundle.

    Parameters
    ----------
    devices : list[OTDevice]
        Discovered devices with their vulnerability findings and CVE matches.
    scanner_identity : str
        Name string embedded in the scanner Identity SDO.
    scanner_version : str
        Version appended to the identity name.
    """

    def __init__(
        self,
        devices: List[OTDevice],
        scanner_identity: str = "OT Passive Scanner",
        scanner_version: str = "2.0.0",
    ) -> None:
        self.devices = devices
        self.scanner_identity = scanner_identity
        self.scanner_version = scanner_version

    # ── public API ───────────────────────────────────────────────────

    def to_stix_bundle(self, path: str) -> None:
        """Export scan results as a STIX 2.1 JSON bundle file.

        The bundle contains:
          - 1 Identity (the scanner)
          - 1 Infrastructure per device
          - 1 Vulnerability per unique finding
          - 1 Indicator per NOW-priority CVE match
          - Relationship objects linking infrastructure to vulnerabilities

        Parameters
        ----------
        path : str
            Destination file path for the JSON bundle.
        """
        objects: List[Dict[str, Any]] = []

        # 1. Scanner identity
        identity_id = _deterministic_uuid("identity", self.scanner_identity)
        objects.append(self._build_identity(identity_id))

        # Track unique vulnerabilities to avoid duplicates
        seen_vuln_ids: Set[str] = set()
        # Collect relationships
        relationships: List[Dict[str, Any]] = []

        for dev in self.devices:
            # 2. Infrastructure (one per device)
            infra_id = _deterministic_uuid("infrastructure", dev.ip)
            objects.append(self._build_infrastructure(dev, infra_id, identity_id))

            # 3. Vulnerabilities + relationships
            for vuln in dev.vulnerabilities:
                vuln_stix_id = _deterministic_uuid("vulnerability", vuln.vuln_id)

                if vuln.vuln_id not in seen_vuln_ids:
                    seen_vuln_ids.add(vuln.vuln_id)
                    objects.append(self._build_vulnerability(vuln, vuln_stix_id))

                relationships.append(
                    self._build_relationship(infra_id, vuln_stix_id, "has")
                )

            # 4. Indicators from NOW-priority CVE matches
            for cve in dev.cve_matches:
                if cve.priority != "now":
                    continue

                indicator_id = _deterministic_uuid(
                    "indicator", f"{cve.cve_id}:{dev.ip}"
                )
                objects.append(
                    self._build_indicator(cve, dev.ip, indicator_id, identity_id)
                )

                # Also emit the CVE as a vulnerability if not already present
                cve_vuln_id = _deterministic_uuid("vulnerability", cve.cve_id)
                if cve.cve_id not in seen_vuln_ids:
                    seen_vuln_ids.add(cve.cve_id)
                    objects.append(self._build_cve_vulnerability(cve, cve_vuln_id))

                relationships.append(
                    self._build_relationship(infra_id, cve_vuln_id, "has")
                )
                relationships.append(
                    self._build_relationship(indicator_id, cve_vuln_id, "indicates")
                )

        objects.extend(relationships)

        # 5. Bundle wrapper
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2, ensure_ascii=False)

    # ── SDO builders ─────────────────────────────────────────────────

    def _build_identity(self, identity_id: str) -> Dict[str, Any]:
        """Build the scanner Identity SDO."""
        return _base_sdo(
            "identity",
            identity_id,
            name=f"{self.scanner_identity} v{self.scanner_version}",
            identity_class="system",
            description=(
                "OT Passive Scanner -- agentless PCAP-based ICS/SCADA "
                "vulnerability detection tool."
            ),
        )

    def _build_infrastructure(
        self,
        dev: OTDevice,
        infra_id: str,
        created_by: str,
    ) -> Dict[str, Any]:
        """Build an Infrastructure SDO for a discovered OT device."""
        name_parts = []
        if dev.vendor:
            name_parts.append(dev.vendor)
        if dev.model:
            name_parts.append(dev.model)
        name_parts.append(f"({dev.ip})")
        name = " ".join(name_parts)

        desc_parts = [f"IP: {dev.ip}"]
        if dev.mac:
            desc_parts.append(f"MAC: {dev.mac}")
        if dev.firmware:
            desc_parts.append(f"Firmware: {dev.firmware}")
        if dev.role and dev.role != "unknown":
            desc_parts.append(f"Role: {dev.role}")
        protocols = dev.get_protocol_names()
        if protocols:
            desc_parts.append(f"Protocols: {', '.join(protocols)}")

        # Map device role to STIX infrastructure type
        infra_type = "scada"
        role_map = {
            "plc": "scada",
            "rtu": "scada",
            "frtu": "scada",
            "ied": "scada",
            "relay": "scada",
            "hmi": "workstation",
            "engineering_station": "workstation",
            "historian": "workstation",
            "gateway": "routers-switches",
            "master_station": "scada",
        }
        if dev.role in role_map:
            infra_type = role_map[dev.role]

        return _base_sdo(
            "infrastructure",
            infra_id,
            name=name,
            infrastructure_types=[infra_type],
            description="; ".join(desc_parts),
            created_by_ref=created_by,
        )

    def _build_vulnerability(
        self,
        vuln: Any,
        vuln_id: str,
    ) -> Dict[str, Any]:
        """Build a Vulnerability SDO from a VulnerabilityFinding."""
        ext_refs = []
        for ref in getattr(vuln, "references", []):
            if ref.startswith("CVE-"):
                ext_refs.append({"source_name": "cve", "external_id": ref})
            elif ref.startswith("http"):
                ext_refs.append({"source_name": "url", "url": ref})
            else:
                ext_refs.append({"source_name": "other", "description": ref})

        obj = _base_sdo(
            "vulnerability",
            vuln_id,
            name=vuln.vuln_id,
            description=vuln.title,
        )
        if ext_refs:
            obj["external_references"] = ext_refs
        return obj

    def _build_cve_vulnerability(
        self,
        cve: Any,
        vuln_id: str,
    ) -> Dict[str, Any]:
        """Build a Vulnerability SDO from a CVEMatch."""
        ext_refs = [{"source_name": "cve", "external_id": cve.cve_id}]
        for ref in getattr(cve, "references", []):
            if ref.startswith("http"):
                ext_refs.append({"source_name": "url", "url": ref})

        advisory = getattr(cve, "ics_cert_advisory", "")
        if advisory:
            ext_refs.append({
                "source_name": "ics-cert",
                "external_id": advisory,
            })

        return _base_sdo(
            "vulnerability",
            vuln_id,
            name=cve.cve_id,
            description=cve.title or cve.description or cve.cve_id,
            external_references=ext_refs,
        )

    def _build_indicator(
        self,
        cve: Any,
        device_ip: str,
        indicator_id: str,
        created_by: str,
    ) -> Dict[str, Any]:
        """Build an Indicator SDO for a NOW-priority CVE match."""
        pattern = f"[ipv4-addr:value = '{device_ip}']"

        return _base_sdo(
            "indicator",
            indicator_id,
            name=f"{cve.cve_id} on {device_ip}",
            description=(
                f"{cve.title or cve.cve_id} -- "
                f"CVSS {cve.cvss_score}, priority NOW, "
                f"public exploit: {cve.has_public_exploit}"
            ),
            pattern=pattern,
            pattern_type="stix",
            indicator_types=["compromised"],
            valid_from=_now_iso(),
            created_by_ref=created_by,
        )

    def _build_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str,
    ) -> Dict[str, Any]:
        """Build a Relationship SRO linking two SDOs."""
        rel_id = _deterministic_uuid(
            "relationship", f"{source_ref}:{target_ref}:{relationship_type}"
        )
        return _base_sdo(
            "relationship",
            rel_id,
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
        )
