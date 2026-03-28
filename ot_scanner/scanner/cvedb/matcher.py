"""
ICS/SCADA CVE Matcher Engine for the OT Passive Scanner.

Matches discovered OTDevice instances against the curated ICS CVE database
using vendor, product, firmware version, and protocol-based heuristics.

Produces CVEMatch results with Dragos-inspired Now/Next/Never prioritization:
  now   -- CVE with known public exploit AND device is network-reachable
  next  -- CVE confirmed but no public exploit, or not network-reachable
  never -- Low confidence match, or theoretical-only risk
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple

from ..models import OTDevice, CVEEntry, CVEMatch
from .ics_cves import ICS_CVE_DATABASE

logger = logging.getLogger(__name__)


class CVEMatcher:
    """Match OT devices against a curated ICS CVE database."""

    # Priority ordering for sort: lower index = higher priority
    _PRIORITY_ORDER = {"now": 0, "next": 1, "never": 2}

    def __init__(self, extra_cve_file: Optional[str] = None) -> None:
        """
        Load the built-in ICS CVE database and optionally merge an external
        JSON file containing additional CVEEntry-compatible dicts.

        Args:
            extra_cve_file: Path to a JSON file with a list of CVE dicts.
                            External entries override built-in entries with the
                            same CVE ID.
        """
        # Build CVEEntry objects from the built-in database
        self._entries: Dict[str, CVEEntry] = {}
        for raw in ICS_CVE_DATABASE:
            entry = self._dict_to_entry(raw)
            if entry:
                self._entries[entry.cve_id] = entry

        # Merge external CVE file if provided
        if extra_cve_file:
            self._load_external(extra_cve_file)

        # Pre-compile product_pattern regexes for performance
        self._compiled_patterns: Dict[str, Optional[re.Pattern]] = {}
        for cve_id, entry in self._entries.items():
            if entry.product_pattern:
                try:
                    self._compiled_patterns[cve_id] = re.compile(
                        entry.product_pattern, re.IGNORECASE
                    )
                except re.error:
                    logger.warning(
                        "Invalid regex in CVE %s product_pattern: %s",
                        cve_id, entry.product_pattern,
                    )
                    self._compiled_patterns[cve_id] = None
            else:
                self._compiled_patterns[cve_id] = None

        logger.info("CVEMatcher loaded %d CVE entries", len(self._entries))

    # ── Public API ──────────────────────────────────────────────────

    def match_device(
        self, device: OTDevice, network_reachable: bool = True
    ) -> List[CVEMatch]:
        """
        Match a single OT device against the CVE database.

        Returns a de-duplicated, prioritized list of CVEMatch objects sorted
        by priority (now > next > never) then by CVSS score descending.

        Args:
            device: The discovered OTDevice to match.
            network_reachable: Whether the device is reachable from untrusted
                               networks (affects now/next classification).
        """
        matches: Dict[str, CVEMatch] = {}

        for cve_id, entry in self._entries.items():
            match = self._try_match(device, entry, network_reachable)
            if match is not None:
                # De-duplicate: keep the highest-confidence match per CVE
                existing = matches.get(cve_id)
                if existing is None or self._confidence_rank(
                    match.match_confidence
                ) > self._confidence_rank(existing.match_confidence):
                    matches[cve_id] = match

        result = list(matches.values())
        result.sort(
            key=lambda m: (
                self._PRIORITY_ORDER.get(m.priority, 9),
                -m.cvss_score,
            )
        )
        return result

    def match_all(
        self, devices: List[OTDevice], network_reachable: bool = True
    ) -> Dict[str, List[CVEMatch]]:
        """
        Match all devices against the CVE database.

        Returns a dict mapping each device IP to its list of CVEMatch results.

        Args:
            devices: List of discovered OTDevice instances.
            network_reachable: Default reachability assumption for all devices.
        """
        results: Dict[str, List[CVEMatch]] = {}
        for device in devices:
            device_matches = self.match_device(device, network_reachable)
            if device_matches:
                results[device.ip] = device_matches
        return results

    @property
    def cve_count(self) -> int:
        """Return the total number of CVE entries in the database."""
        return len(self._entries)

    @property
    def entries(self) -> List[CVEEntry]:
        """Return all CVE entries as a list."""
        return list(self._entries.values())

    # ── Matching Logic ──────────────────────────────────────────────

    def _try_match(
        self,
        device: OTDevice,
        entry: CVEEntry,
        network_reachable: bool,
    ) -> Optional[CVEMatch]:
        """
        Attempt to match a single CVE entry against a device.

        Matching pipeline:
          1. Vendor match (required — unless protocol-only CVE)
          2. Product/model match via regex
          3. Version/firmware range check
          4. Confidence & priority assignment

        Returns a CVEMatch if matched, None otherwise.
        """
        vendor_matched = self._match_vendor(device, entry)
        product_matched = self._match_product(device, entry)
        protocol_only = self._is_protocol_match(device, entry)

        # Must match at least vendor+product, or protocol-only
        if not (vendor_matched and product_matched) and not protocol_only:
            return None

        # Determine version match status
        version_status = self._check_version(device, entry)

        # If version is explicitly NOT affected, skip
        if version_status == "not_affected":
            return None

        # Assign confidence
        confidence = self._assign_confidence(
            vendor_matched, product_matched, protocol_only, version_status
        )

        # Build match reason
        reason = self._build_reason(
            device, entry, vendor_matched, product_matched,
            protocol_only, version_status,
        )

        # Classify priority
        priority = self._classify_priority(
            entry, confidence, network_reachable
        )

        return CVEMatch(
            cve_id=entry.cve_id,
            device_ip=device.ip,
            priority=priority,
            severity=entry.severity,
            cvss_score=entry.cvss_score,
            title=entry.title,
            description=entry.description,
            match_confidence=confidence,
            match_reason=reason,
            has_public_exploit=entry.has_public_exploit,
            ics_cert_advisory=entry.ics_cert_advisory,
            remediation=entry.remediation,
            references=list(entry.references),
        )

    def _match_vendor(self, device: OTDevice, entry: CVEEntry) -> bool:
        """
        Case-insensitive vendor match.
        Checks device.vendor and device.make against entry.vendor.
        Supports partial/substring matching.
        """
        if not entry.vendor:
            return False

        entry_vendor = entry.vendor.lower()

        # Special case: "Generic" vendor matches everything
        if entry_vendor == "generic":
            return True

        for field in (device.vendor, device.make):
            if field and entry_vendor in field.lower():
                return True
            if field and field.lower() in entry_vendor:
                return True

        return False

    def _match_product(self, device: OTDevice, entry: CVEEntry) -> bool:
        """
        Regex product match against device model, make, product_code,
        and firmware fields.
        """
        pattern = self._compiled_patterns.get(entry.cve_id)
        if pattern is None:
            # No product pattern means vendor-only match is sufficient
            return True

        # Fields to check for product match
        fields_to_check = [
            device.model,
            device.make,
            device.product_code,
            device.firmware,
            device.hostname,
        ]

        for field_value in fields_to_check:
            if field_value and pattern.search(field_value):
                return True

        return False

    def _is_protocol_match(self, device: OTDevice, entry: CVEEntry) -> bool:
        """
        Check if this is a protocol-level CVE that matches based on
        the device's detected protocols rather than vendor/model.
        """
        pattern = self._compiled_patterns.get(entry.cve_id)
        if pattern is None:
            return False

        # Check against protocol names
        protocol_names = device.get_protocol_names()
        for proto in protocol_names:
            if pattern.search(proto):
                return True

        return False

    def _check_version(self, device: OTDevice, entry: CVEEntry) -> str:
        """
        Check whether the device firmware falls within the CVE's affected
        version range.

        Returns:
            "affected"     -- firmware confirmed in vulnerable range
            "not_affected" -- firmware confirmed NOT in vulnerable range
            "unknown"      -- firmware version not available or unparseable
        """
        if entry.affected_versions == "*":
            return "affected"

        if not device.firmware:
            return "unknown"

        device_version = self._parse_version(device.firmware)
        if device_version is None:
            return "unknown"

        try:
            in_range = self._version_in_range(
                device_version, entry.affected_versions
            )
        except Exception:
            logger.debug(
                "Version range check failed for %s against %s",
                device.firmware, entry.affected_versions,
            )
            return "unknown"

        return "affected" if in_range else "not_affected"

    def _assign_confidence(
        self,
        vendor_matched: bool,
        product_matched: bool,
        protocol_only: bool,
        version_status: str,
    ) -> str:
        """
        Assign a confidence level based on how strongly the CVE matched.

        Returns: "high", "medium", or "low"
        """
        if protocol_only and not (vendor_matched and product_matched):
            return "low"

        if vendor_matched and product_matched and version_status == "affected":
            return "high"

        if vendor_matched and product_matched:
            # Product matched but version unknown
            return "medium"

        return "low"

    def _classify_priority(
        self, cve: CVEEntry, confidence: str, network_reachable: bool
    ) -> str:
        """
        Dragos-inspired Now/Next/Never classification:

          now   -- CVE with known public exploit AND device is
                   network-reachable AND confidence >= medium
          next  -- CVE confirmed (confidence >= medium) but no public
                   exploit, or not network-reachable
          never -- Low confidence match, or theoretical-only risk
        """
        if confidence == "low":
            return "never"
        if (
            cve.has_public_exploit
            and network_reachable
            and confidence in ("high", "medium")
        ):
            return "now"
        if confidence in ("high", "medium"):
            return "next"
        return "never"

    # ── Version Parsing & Comparison ────────────────────────────────

    @staticmethod
    def _parse_version(firmware: str) -> Optional[Tuple[int, ...]]:
        """
        Extract a version tuple from a firmware string.

        Handles formats like:
          "V4.5.2", "4.5", "FW 3.2.1", "v2.0", "R6.09",
          "v2.0.1-beta", "V4.5 HF1", "33.017"

        Returns a tuple of ints, e.g. (4, 5, 2), or None if unparseable.
        """
        if not firmware:
            return None

        # Strip common prefixes: V, v, FW, fw, R, r, Version, Firmware
        cleaned = re.sub(
            r"^(?:Version|Firmware|FW|[VvRr])\s*", "", firmware.strip()
        )

        # Extract the first version-like sequence (digits separated by dots)
        match = re.search(r"(\d+(?:\.\d+)*)", cleaned)
        if not match:
            return None

        version_str = match.group(1)
        try:
            return tuple(int(x) for x in version_str.split("."))
        except (ValueError, OverflowError):
            return None

    @staticmethod
    def _parse_range_version(range_part: str) -> Optional[Tuple[int, ...]]:
        """
        Parse a version from a range expression like '<4.5', '>=V3.10'.

        Strips comparison operators and version prefixes, then extracts
        the version tuple.
        """
        # Remove comparison operators
        cleaned = re.sub(r"^[<>=]+\s*", "", range_part.strip())
        # Remove version prefixes
        cleaned = re.sub(
            r"^(?:Version|Firmware|FW|[VvRr])\s*", "", cleaned.strip()
        )
        # Extract version numbers
        match = re.search(r"(\d+(?:\.\d+)*)", cleaned)
        if not match:
            return None
        try:
            return tuple(int(x) for x in match.group(1).split("."))
        except (ValueError, OverflowError):
            return None

    @classmethod
    def _version_in_range(
        cls, version: Tuple[int, ...], range_str: str
    ) -> bool:
        """
        Check whether a version tuple falls within a version range.

        Supports:
          "<4.5"          -- strictly less than 4.5
          "<=4.5"         -- less than or equal to 4.5
          ">2.0"          -- strictly greater than 2.0
          ">=2.0"         -- greater than or equal to 2.0
          ">=2.0,<3.1"    -- compound: 2.0 <= ver < 3.1
          "*"             -- all versions (always True)
          "<V8.0"         -- handles V prefix in range

        Returns True if the version is in the affected range.
        """
        if range_str.strip() == "*":
            return True

        # Split by comma for compound conditions
        conditions = [c.strip() for c in range_str.split(",") if c.strip()]

        for cond in conditions:
            if not cls._check_single_condition(version, cond):
                return False

        return True

    @classmethod
    def _check_single_condition(
        cls, version: Tuple[int, ...], condition: str
    ) -> bool:
        """
        Evaluate a single version condition like '<4.5' or '>=2.0'.
        """
        condition = condition.strip()
        if not condition or condition == "*":
            return True

        # Determine operator and parse the target version
        if condition.startswith("<="):
            op = "<="
            target = cls._parse_range_version(condition[2:])
        elif condition.startswith(">="):
            op = ">="
            target = cls._parse_range_version(condition[2:])
        elif condition.startswith("<"):
            op = "<"
            target = cls._parse_range_version(condition[1:])
        elif condition.startswith(">"):
            op = ">"
            target = cls._parse_range_version(condition[1:])
        else:
            # Treat as exact match or try parsing the whole thing
            target = cls._parse_range_version(condition)
            op = "=="

        if target is None:
            # Cannot parse the condition; assume it matches (be conservative)
            return True

        # Pad tuples to the same length for correct comparison
        max_len = max(len(version), len(target))
        padded_ver = version + (0,) * (max_len - len(version))
        padded_tgt = target + (0,) * (max_len - len(target))

        if op == "<":
            return padded_ver < padded_tgt
        elif op == "<=":
            return padded_ver <= padded_tgt
        elif op == ">":
            return padded_ver > padded_tgt
        elif op == ">=":
            return padded_ver >= padded_tgt
        elif op == "==":
            return padded_ver == padded_tgt

        return True

    # ── Helpers ─────────────────────────────────────────────────────

    def _build_reason(
        self,
        device: OTDevice,
        entry: CVEEntry,
        vendor_matched: bool,
        product_matched: bool,
        protocol_only: bool,
        version_status: str,
    ) -> str:
        """Build a human-readable match reason string."""
        parts: List[str] = []

        if protocol_only and not vendor_matched:
            parts.append(f"Protocol match ({entry.product_pattern})")
        else:
            if vendor_matched:
                parts.append(f"Vendor: {entry.vendor}")
            if product_matched:
                matched_field = "model"
                for name, val in [
                    ("model", device.model),
                    ("make", device.make),
                    ("product_code", device.product_code),
                ]:
                    if val:
                        pattern = self._compiled_patterns.get(entry.cve_id)
                        if pattern and pattern.search(val):
                            matched_field = name
                            break
                parts.append(f"Product matched on {matched_field}")

        if version_status == "affected":
            parts.append(
                f"Firmware {device.firmware or 'N/A'} in affected range "
                f"({entry.affected_versions})"
            )
        elif version_status == "unknown":
            parts.append("Firmware version unknown (conservative match)")

        return "; ".join(parts)

    @staticmethod
    def _confidence_rank(confidence: str) -> int:
        """Numeric rank for confidence comparison (higher is better)."""
        return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)

    @staticmethod
    def _dict_to_entry(raw: Dict) -> Optional[CVEEntry]:
        """Convert a raw dict from the database to a CVEEntry dataclass."""
        try:
            return CVEEntry(
                cve_id=raw["cve_id"],
                vendor=raw["vendor"],
                product_pattern=raw.get("product_pattern", ""),
                affected_versions=raw.get("affected_versions", "*"),
                severity=raw.get("severity", "medium"),
                cvss_score=raw.get("cvss_score", 0.0),
                title=raw.get("title", ""),
                description=raw.get("description", ""),
                has_public_exploit=raw.get("has_public_exploit", False),
                ics_cert_advisory=raw.get("ics_cert_advisory", ""),
                remediation=raw.get("remediation", ""),
                references=raw.get("references", []),
            )
        except (KeyError, TypeError) as exc:
            logger.warning("Skipping malformed CVE entry: %s", exc)
            return None

    def _load_external(self, filepath: str) -> None:
        """
        Load an external JSON CVE file and merge with the built-in database.

        External entries with matching CVE IDs override the built-in entries.

        Expected format:
            [
                {"cve_id": "CVE-...", "vendor": "...", ...},
                ...
            ]
        """
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to load external CVE file %s: %s", filepath, exc)
            return

        if not isinstance(data, list):
            logger.error(
                "External CVE file must contain a JSON array, got %s",
                type(data).__name__,
            )
            return

        loaded = 0
        for raw in data:
            if not isinstance(raw, dict):
                continue
            entry = self._dict_to_entry(raw)
            if entry:
                self._entries[entry.cve_id] = entry
                loaded += 1

        logger.info(
            "Loaded %d external CVE entries from %s", loaded, filepath
        )
