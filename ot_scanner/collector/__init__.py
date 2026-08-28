"""
Collector — the Raspberry Pi half of the OT sensor fleet (OTS-SRS-001).

Phase 1 delivers capture coverage accounting: the part that decides what the
collector may honestly claim to have seen. It is deliberately separable from
packet capture itself, because the logic must be testable on any machine while
only the counter source needs a Linux NIC.

The organising idea is that coverage has three states, not two — complete,
degraded, and UNKNOWN — and that a collector which cannot measure its own packet
loss must say so rather than report a clean network.
"""
from . import rulepack
from .analysis import AnalysisStats, IncrementalAnalyzer
from .capture import CaptureSource, Frame, ReplaySource, SyntheticSource
from .coverage import (Coverage, CaptureWindow, DropDelta, DropSnapshot,
                       WindowAccountant)
from .observations import (Observation, ObservationBatch, ObservationBuilder,
                           Provenance, RecordKind, asset_key, scrub)
from .self_exclusion import ExclusionMode, SelfExclusion, SelfIdentity
from .spool import Spool, SpoolLoss, SpoolStats, backoff_delay
from .transport import (SendResult, Transport, TransportConfig, TransportError)
from .service import (CaptureRefused, CaptureService, CollectorConfig,
                      WindowReport)
from .counters import (CombinedCounters, NullCounters, PacketSocketCounters,
                       PcapStatsCounters, SysfsInterfaceCounters, build_counters)
from .health import AlarmState, CaptureHealth, HealthAlarm
from .preflight import Check, CheckResult, Preflight, check_capture_interface
from .rotation import (DEFAULT_MAX_BYTES, Eviction, RetentionState,
                       RollingPcapStore, warn_if_on_boot_media)

__all__ = [
    "Coverage", "CaptureWindow", "DropDelta", "DropSnapshot", "WindowAccountant",
    "CombinedCounters", "NullCounters", "PacketSocketCounters",
    "PcapStatsCounters", "SysfsInterfaceCounters", "build_counters",
    "AlarmState", "CaptureHealth", "HealthAlarm",
    "Check", "CheckResult", "Preflight", "check_capture_interface",
    "DEFAULT_MAX_BYTES", "Eviction", "RetentionState", "RollingPcapStore",
    "warn_if_on_boot_media",
    "rulepack", "AnalysisStats", "IncrementalAnalyzer",
    "CaptureSource", "Frame", "ReplaySource", "SyntheticSource",
    "Observation", "ObservationBatch", "ObservationBuilder", "Provenance",
    "RecordKind", "asset_key", "scrub",
    "ExclusionMode", "SelfExclusion", "SelfIdentity",
    "Spool", "SpoolLoss", "SpoolStats", "backoff_delay",
    "SendResult", "Transport", "TransportConfig", "TransportError",
    "CaptureRefused", "CaptureService", "CollectorConfig", "WindowReport",
]
