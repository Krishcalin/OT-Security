"""
Configuration Snapshot Engine for the OT Passive Scanner.

Captures point-in-time device configuration snapshots, persists them to
a JSON store, and computes configuration drift between snapshots to detect
unauthorized changes (firmware updates, program modifications, function
code profile shifts, new protocols, peer changes).

Drift alerts map to MITRE ATT&CK for ICS techniques:
  T0839 — Module Firmware (firmware/module changes)
  T0836 — Modify Program (program download detected)
  T0843 — Program Download (program upload/download events)
  T0855 — Unauthorized Command Message (function code shifts)
  T0869 — Standard Application Layer Protocol (new protocols)
  T0886 — Remote Services (new communication peers)

Usage:
    engine = ConfigSnapshotEngine("/path/to/snapshots")
    configs = engine.capture(devices)
    snap_path = engine.save_snapshot(configs, "capture.pcap")

    # On next scan:
    previous = engine.load_latest()
    current = engine.capture(devices)
    drift = engine.diff(previous, current)  # Dict[ip, List[ConfigDriftAlert]]

Zero external dependencies — uses only Python stdlib.
"""

import json
import logging
import os
import shutil
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set

from ..models import ConfigDriftAlert, DeviceConfig, OTDevice

logger = logging.getLogger(__name__)

# ── Severity ordering for risk escalation ────────────────────────────────
_RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


class ConfigSnapshotEngine:
    """
    Persistent configuration snapshot store with drift detection.

    Usage::

        engine = ConfigSnapshotEngine("./snapshots")
        configs = engine.capture(devices)
        path = engine.save_snapshot(configs, "capture.pcap")
        engine.set_baseline(path)
    """

    def __init__(self, snapshot_dir: str) -> None:
        self._dir = snapshot_dir
        os.makedirs(self._dir, exist_ok=True)
        self._index_path = os.path.join(self._dir, "index.json")
        self._baseline_path = os.path.join(self._dir, "baseline.json")

    # ── public API ───────────────────────────────────────────────────

    def capture(self, devices: List[OTDevice]) -> List[DeviceConfig]:
        """Extract configuration snapshot from current scan results."""
        now = datetime.now().isoformat()
        configs: List[DeviceConfig] = []

        for dev in devices:
            # Build function code profile: {protocol: {fc_name: count}}
            fc_profile: Dict[str, Dict[str, int]] = {}
            program_state = {
                "has_program_upload": False,
                "has_program_download": False,
                "has_firmware_update": False,
                "has_config_change": False,
            }
            dp_counts: Dict[str, int] = {}

            for ps in dev.protocol_stats:
                fc_profile[ps.protocol] = dict(ps.function_codes)
                dp_counts[ps.protocol] = ps.unique_data_points
                if ps.has_program_upload:
                    program_state["has_program_upload"] = True
                if ps.has_program_download:
                    program_state["has_program_download"] = True
                if ps.has_firmware_update:
                    program_state["has_firmware_update"] = True
                if ps.has_config_change:
                    program_state["has_config_change"] = True

            snap_id = f"SNAP-{now.replace(':', '').replace('-', '').split('.')[0]}-{dev.ip}"

            configs.append(DeviceConfig(
                device_ip=dev.ip,
                snapshot_id=snap_id,
                timestamp=now,
                firmware=dev.firmware or "",
                hardware_version=dev.hardware_version or "",
                product_code=dev.product_code or "",
                serial_number=dev.serial_number or "",
                modules=list(dev.modules),
                function_code_profile=fc_profile,
                program_state=program_state,
                protocol_list=sorted(dev.get_protocol_names()),
                data_point_counts=dp_counts,
                communication_peers=sorted(dev.communicating_with),
                master_stations=sorted(dev.master_stations),
                open_ports=sorted(dev.open_ports),
                risk_level=dev.risk_level,
                composite_risk_score=dev.composite_risk_score,
            ))

        return configs

    def save_snapshot(self, configs: List[DeviceConfig], pcap_file: str = "") -> str:
        """Persist snapshot to JSON file and update index. Returns file path."""
        now = datetime.now()
        snap_id = f"snap_{now.strftime('%Y%m%dT%H%M%S')}"
        filename = f"{snap_id}.json"
        filepath = os.path.join(self._dir, filename)

        data = {
            "snapshot_id": snap_id,
            "timestamp": now.isoformat(),
            "pcap_file": os.path.basename(pcap_file) if pcap_file else "",
            "device_count": len(configs),
            "configs": [c.to_dict() for c in configs],
        }

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

        # Update index
        self._update_index(snap_id, now.isoformat(), pcap_file, filename)

        logger.info("Saved snapshot %s with %d device configs", snap_id, len(configs))
        return filepath

    def load_snapshot(self, path: str) -> List[DeviceConfig]:
        """Load a snapshot from a JSON file."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        configs: List[DeviceConfig] = []
        for raw in data.get("configs", []):
            configs.append(DeviceConfig(
                device_ip=raw.get("device_ip", ""),
                snapshot_id=raw.get("snapshot_id", ""),
                timestamp=raw.get("timestamp", ""),
                firmware=raw.get("firmware", ""),
                hardware_version=raw.get("hardware_version", ""),
                product_code=raw.get("product_code", ""),
                serial_number=raw.get("serial_number", ""),
                modules=raw.get("modules", []),
                function_code_profile=raw.get("function_code_profile", {}),
                program_state=raw.get("program_state", {}),
                protocol_list=raw.get("protocol_list", []),
                data_point_counts=raw.get("data_point_counts", {}),
                communication_peers=raw.get("communication_peers", []),
                master_stations=raw.get("master_stations", []),
                open_ports=raw.get("open_ports", []),
                risk_level=raw.get("risk_level", "unknown"),
                composite_risk_score=raw.get("composite_risk_score", 0.0),
            ))
        return configs

    def load_latest(self) -> Optional[List[DeviceConfig]]:
        """Load the most recent snapshot, or baseline if no snapshots exist."""
        # Try baseline first
        if os.path.exists(self._baseline_path):
            return self.load_snapshot(self._baseline_path)

        # Fall back to most recent in index
        index = self._load_index()
        snapshots = index.get("snapshots", [])
        if not snapshots:
            return None

        latest = snapshots[-1]
        path = os.path.join(self._dir, latest["path"])
        if os.path.exists(path):
            return self.load_snapshot(path)
        return None

    def set_baseline(self, path: str) -> None:
        """Mark a snapshot as the 'last known good' baseline."""
        shutil.copy2(path, self._baseline_path)

        # Update index to mark this snapshot
        index = self._load_index()
        basename = os.path.basename(path)
        for snap in index.get("snapshots", []):
            snap["is_baseline"] = (snap["path"] == basename)
        self._save_index(index)

        logger.info("Set baseline: %s", path)

    def diff(
        self,
        old_configs: List[DeviceConfig],
        new_configs: List[DeviceConfig],
    ) -> Dict[str, List[ConfigDriftAlert]]:
        """
        Compute configuration drift between two snapshots.
        Returns alerts grouped by device IP.
        """
        old_map: Dict[str, DeviceConfig] = {c.device_ip: c for c in old_configs}
        new_map: Dict[str, DeviceConfig] = {c.device_ip: c for c in new_configs}

        all_alerts: List[ConfigDriftAlert] = []
        now = datetime.now().isoformat()

        # Compare devices present in both snapshots
        common_ips = set(old_map.keys()) & set(new_map.keys())
        for ip in sorted(common_ips):
            old = old_map[ip]
            new = new_map[ip]
            all_alerts.extend(self._diff_device(old, new, now))

        # Assign sequential IDs
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_alerts.sort(key=lambda a: (sev_order.get(a.severity, 5), a.device_ip))
        for idx, alert in enumerate(all_alerts, 1):
            alert.alert_id = f"CD-{idx:03d}"

        # Group by IP
        by_ip: Dict[str, List[ConfigDriftAlert]] = defaultdict(list)
        for alert in all_alerts:
            by_ip[alert.device_ip].append(alert)

        logger.info("Config drift: %d alert(s) across %d device(s)",
                     len(all_alerts), len(by_ip))
        return dict(by_ip)

    # ── private: per-device drift comparison ─────────────────────────

    def _diff_device(
        self, old: DeviceConfig, new: DeviceConfig, ts: str,
    ) -> List[ConfigDriftAlert]:
        """Compare two snapshots for the same device."""
        alerts: List[ConfigDriftAlert] = []
        ip = old.device_ip

        # 1. Firmware change
        if old.firmware and new.firmware and old.firmware != new.firmware:
            alerts.append(ConfigDriftAlert(
                device_ip=ip, drift_type="firmware_change", severity="high",
                title=f"Firmware changed on {ip}",
                description=(
                    f"Firmware version changed from '{old.firmware}' "
                    f"to '{new.firmware}'. Unauthorized firmware updates "
                    f"may compromise device integrity."
                ),
                old_value=old.firmware, new_value=new.firmware,
                mitre_technique="T0839", mitre_tactic="Inhibit Response Function",
                timestamp=ts,
            ))

        # 2. Module change
        old_mods = json.dumps(old.modules, sort_keys=True)
        new_mods = json.dumps(new.modules, sort_keys=True)
        if old_mods != new_mods and (old.modules or new.modules):
            alerts.append(ConfigDriftAlert(
                device_ip=ip, drift_type="module_change", severity="high",
                title=f"Module configuration changed on {ip}",
                description=(
                    f"I/O module inventory changed: was {len(old.modules)} "
                    f"module(s), now {len(new.modules)}."
                ),
                old_value=f"{len(old.modules)} modules",
                new_value=f"{len(new.modules)} modules",
                mitre_technique="T0839", mitre_tactic="Inhibit Response Function",
                timestamp=ts,
            ))

        # 3. Program events (False→True transitions)
        for flag, label, technique in [
            ("has_program_download", "Program download", "T0843"),
            ("has_program_upload", "Program upload", "T0843"),
            ("has_firmware_update", "Firmware update", "T0839"),
            ("has_config_change", "Configuration change", "T0836"),
        ]:
            old_val = old.program_state.get(flag, False)
            new_val = new.program_state.get(flag, False)
            if not old_val and new_val:
                sev = "critical" if "program" in flag or "firmware" in flag else "high"
                alerts.append(ConfigDriftAlert(
                    device_ip=ip, drift_type="program_event", severity=sev,
                    title=f"{label} detected on {ip}",
                    description=(
                        f"{label} activity not present in baseline but "
                        f"detected in current scan."
                    ),
                    old_value="Not detected", new_value="Detected",
                    mitre_technique=technique,
                    mitre_tactic="Execution",
                    timestamp=ts,
                ))

        # 4. Function code shift (>20% new FCs)
        for proto, old_fcs in old.function_code_profile.items():
            new_fcs = new.function_code_profile.get(proto, {})
            if not old_fcs:
                continue
            old_set = set(old_fcs.keys())
            new_set = set(new_fcs.keys())
            new_codes = new_set - old_set
            if new_codes and len(new_codes) > len(old_set) * 0.2:
                alerts.append(ConfigDriftAlert(
                    device_ip=ip, drift_type="function_code_shift", severity="medium",
                    title=f"New function codes on {ip} ({proto})",
                    description=(
                        f"{len(new_codes)} new function code(s) appeared on "
                        f"{proto}: {', '.join(sorted(new_codes)[:5])}"
                    ),
                    old_value=f"{len(old_set)} FCs",
                    new_value=f"{len(new_set)} FCs (+{len(new_codes)} new)",
                    mitre_technique="T0855",
                    mitre_tactic="Execution",
                    timestamp=ts,
                ))

        # 5. New protocols
        old_protos = set(old.protocol_list)
        new_protos = set(new.protocol_list) - old_protos
        for proto in sorted(new_protos):
            alerts.append(ConfigDriftAlert(
                device_ip=ip, drift_type="new_protocol", severity="medium",
                title=f"New protocol on {ip}: {proto}",
                description=(
                    f"Protocol '{proto}' was not present in the baseline "
                    f"configuration for this device."
                ),
                old_value="Not present",
                new_value=proto,
                mitre_technique="T0869",
                mitre_tactic="Execution",
                timestamp=ts,
            ))

        # 6. New communication peers
        old_peers = set(old.communication_peers)
        new_peers = set(new.communication_peers) - old_peers
        if new_peers:
            alerts.append(ConfigDriftAlert(
                device_ip=ip, drift_type="peer_change", severity="low",
                title=f"New communication peers for {ip}",
                description=(
                    f"{len(new_peers)} new peer(s) not in baseline: "
                    f"{', '.join(sorted(new_peers)[:5])}"
                ),
                old_value=f"{len(old_peers)} peers",
                new_value=f"{len(set(new.communication_peers))} peers (+{len(new_peers)})",
                mitre_technique="T0886",
                mitre_tactic="Lateral Movement",
                timestamp=ts,
            ))

        # 7. Risk escalation
        old_risk = _RISK_ORDER.get(old.risk_level, 0)
        new_risk = _RISK_ORDER.get(new.risk_level, 0)
        if new_risk > old_risk:
            alerts.append(ConfigDriftAlert(
                device_ip=ip, drift_type="risk_escalation", severity="high",
                title=f"Risk escalated on {ip}: {old.risk_level} -> {new.risk_level}",
                description=(
                    f"Device risk level increased from {old.risk_level} "
                    f"to {new.risk_level}."
                ),
                old_value=old.risk_level,
                new_value=new.risk_level,
                mitre_technique="",
                mitre_tactic="",
                timestamp=ts,
            ))

        return alerts

    # ── private: index management ────────────────────────────────────

    def _load_index(self) -> Dict:
        if os.path.exists(self._index_path):
            with open(self._index_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return {"snapshots": []}

    def _save_index(self, index: Dict) -> None:
        with open(self._index_path, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2, default=str)

    def _update_index(
        self, snap_id: str, timestamp: str, pcap_file: str, filename: str,
    ) -> None:
        index = self._load_index()
        index["snapshots"].append({
            "id": snap_id,
            "timestamp": timestamp,
            "pcap_file": os.path.basename(pcap_file) if pcap_file else "",
            "path": filename,
            "is_baseline": False,
        })
        self._save_index(index)
