"""
Project File Analysis Engine for the OT Passive Scanner.

Scans a directory of ICS engineering project files and generic inventory
exports (CSV/JSON) to build a ground-truth device registry.  Every device
parsed from a project file receives ``vendor_confidence="ground_truth"`` so
the downstream fingerprinting pipeline knows NOT to override these fields.

Supported formats:
  - Siemens TIA Portal  (.zap16 / .ap16)  — ZIP containing XML station configs
  - Rockwell Studio 5000 (.L5X)            — Plain XML export
  - Schneider EcoStruxure (.XEF)           — Plain XML export
  - Generic CSV (.csv)                     — User-provided asset inventory
  - Generic JSON (.json)                   — User-provided asset inventory

Zero external dependencies — uses only Python stdlib.
"""

import logging
import os
from pathlib import Path
from typing import Dict, List

from ..models import OTDevice

from .parsers import (
    parse_tia_portal,
    parse_rockwell_l5x,
    parse_schneider_xef,
    parse_csv_inventory,
    parse_json_inventory,
)

logger = logging.getLogger(__name__)


# Extension -> parser dispatch table
_EXTENSION_MAP = {
    ".zap16": parse_tia_portal,
    ".ap16":  parse_tia_portal,
    ".l5x":   parse_rockwell_l5x,
    ".xef":   parse_schneider_xef,
    ".csv":   parse_csv_inventory,
    ".json":  parse_json_inventory,
}


class ProjectFileEngine:
    """
    Scans a directory for ICS project files and builds a ground-truth
    device registry keyed by IP address.

    Usage::

        engine = ProjectFileEngine()
        count = engine.load_directory("/path/to/project_files")
        devices = engine.get_devices()   # Dict[str, OTDevice]
    """

    def __init__(self) -> None:
        self._devices: Dict[str, OTDevice] = {}
        self._files_parsed: int = 0
        self._parse_errors: List[str] = []

    # ── public API ───────────────────────────────────────────────────

    def load_directory(self, path: str) -> int:
        """
        Recursively scan *path* for supported project files.

        Returns the number of files successfully parsed.
        Tolerates per-file errors — logs warnings and continues.
        """
        dir_path = Path(path)
        if not dir_path.is_dir():
            logger.warning("Project directory does not exist: %s", path)
            return 0

        parsed = 0
        for root, _dirs, files in os.walk(str(dir_path)):
            for fname in files:
                ext = Path(fname).suffix.lower()
                parser_fn = _EXTENSION_MAP.get(ext)
                if parser_fn is None:
                    continue

                fpath = os.path.join(root, fname)
                try:
                    devices = parser_fn(fpath)
                    self._ingest(devices, source=fpath)
                    parsed += 1
                    logger.info("Parsed %s (%d devices)", fpath, len(devices))
                except Exception as exc:
                    msg = f"Failed to parse {fpath}: {exc}"
                    logger.warning(msg)
                    self._parse_errors.append(msg)

        self._files_parsed = parsed
        return parsed

    def get_devices(self) -> Dict[str, OTDevice]:
        """Return the merged device registry (IP -> OTDevice)."""
        return dict(self._devices)

    @property
    def files_parsed(self) -> int:
        return self._files_parsed

    @property
    def parse_errors(self) -> List[str]:
        return list(self._parse_errors)

    # ── internal ─────────────────────────────────────────────────────

    def _ingest(self, devices: List[OTDevice], source: str) -> None:
        """
        Merge a list of parsed OTDevices into the internal registry.

        If the same IP appears in multiple project files, later files
        enrich (fill None fields) but do NOT overwrite already-set fields.
        """
        for dev in devices:
            if not dev.ip:
                continue

            dev.vendor_confidence = "ground_truth"
            dev.notes.append(f"Source: {os.path.basename(source)}")

            if dev.ip in self._devices:
                self._merge_into_existing(self._devices[dev.ip], dev)
            else:
                self._devices[dev.ip] = dev

    @staticmethod
    def _merge_into_existing(existing: OTDevice, new: OTDevice) -> None:
        """
        Enrich *existing* from *new* — fill None/empty fields only.
        Does NOT overwrite already-populated fields.
        """
        _FILL_FIELDS = [
            "vendor", "make", "model", "firmware", "hardware_version",
            "serial_number", "product_code", "rack", "slot", "cpu_info",
            "device_type", "role", "asset_owner", "location", "asset_tag",
            "device_criticality",
        ]
        for attr in _FILL_FIELDS:
            cur = getattr(existing, attr, None)
            nv = getattr(new, attr, None)
            if (
                (cur is None or cur == "" or cur == "unknown")
                and nv is not None
                and nv != ""
                and nv != "unknown"
            ):
                setattr(existing, attr, nv)

        # Merge module lists
        if new.modules:
            existing.modules.extend(new.modules)

        # Merge notes
        existing.notes.extend(new.notes)
