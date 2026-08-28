"""
Incremental analysis (OTS-ANL-001, ANL-003).

Drives the existing PCAPAnalyzer from a live frame stream instead of a file, and
emits observation records at each window boundary.

THE ANALYSERS ARE NOT MODIFIED
──────────────────────────────
`PCAPAnalyzer._handle_ip_packet` and `._handle_l2_frame` are already the
per-packet entry points; `analyze()` is only a file reader wrapped around them.
So this feeds the same handlers from a different source. All 18 protocol
analysers, the fingerprinter, the vulnerability engine and the threat engine run
exactly as they do today — which is the point of ANL-001. A reimplementation
would be a second decoder to keep in step with the first, and the two would
diverge silently.

STATEFUL SESSIONS SURVIVE WINDOW BOUNDARIES
───────────────────────────────────────────
DNP3, IEC-104 and GOOSE state lives on the analyser instance, and this holds one
instance for the life of the collector. A window is an ACCOUNTING boundary, not
an analysis one: a DNP3 session opened at 10:59 and exploited at 11:01 must
still be one session, or the exploit is evaluated against a session that appears
to have no history.

`_finalise()` is safe to call per window because it ASSIGNS rather than appends
— `device.vulnerabilities = findings`, not `+=` — so findings are recomputed
from accumulated state rather than piling up. `test_repeated_finalise_does_not_
duplicate_findings` pins that, since an append here would inflate every count on
a long-running collector and nothing else would notice.

WHAT IS EMITTED
───────────────
Records, not packets. See observations.py.
"""
from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from . import rulepack
from .capture import Frame
from .observations import (ObservationBatch, ObservationBuilder, asset_key)

# The scanner package sits alongside this one.
_HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.dirname(_HERE) not in sys.path:
    sys.path.insert(0, os.path.dirname(_HERE))

L2_ETHERTYPES = (0x88B8, 0x88BA, 0x8892)          # GOOSE, SV, PROFINET


@dataclass
class AnalysisStats:
    frames_seen: int = 0
    frames_decoded: int = 0
    frames_l2: int = 0
    frames_ip: int = 0
    decode_failures: int = 0

    @property
    def undecodable_fraction(self) -> Optional[float]:
        if self.frames_seen == 0:
            return None
        return self.decode_failures / self.frames_seen


class IncrementalAnalyzer:
    """Feeds frames to the existing analyser and emits records per window."""

    def __init__(self, collector_id: str = "collector",
                 analyzer: Any = None, verbose: bool = False,
                 scanner_root: Optional[str] = None):
        self.collector_id = collector_id
        self.stats = AnalysisStats()
        self.rulepack = rulepack.compute(scanner_root)
        self._analyzer = analyzer if analyzer is not None else self._build(verbose)
        self.builder = ObservationBuilder(
            collector_id=collector_id,
            rulepack_version=self.rulepack.version,
            analyzer_version=self._analyzer_version())

    @staticmethod
    def _build(verbose: bool):
        from scanner.core import PCAPAnalyzer

        return PCAPAnalyzer(verbose=verbose)

    def _analyzer_version(self) -> str:
        try:
            from scanner import core

            return str(getattr(core, "VERSION", "") or "")
        except Exception:                                  # noqa: BLE001
            return ""

    # ── ingest ────────────────────────────────────────────────────────────
    def feed(self, frames: List[Frame]) -> None:
        """Decode and dispatch a batch, mirroring PCAPAnalyzer's own dpkt path."""
        try:
            import dpkt
        except ImportError:
            self.stats.frames_seen += len(frames)
            self.stats.decode_failures += len(frames)
            return

        for frame in frames:
            self.stats.frames_seen += 1
            try:
                self._dispatch(dpkt, frame)
            except Exception:                              # noqa: BLE001
                # A malformed frame is normal on a live network and must not
                # stop capture. It is COUNTED, so a decoder that silently fails
                # on everything is visible rather than looking like a quiet link.
                self.stats.decode_failures += 1

    def _dispatch(self, dpkt, frame: Frame) -> None:
        eth = dpkt.ethernet.Ethernet(frame.raw)
        ts = datetime.fromtimestamp(frame.timestamp or 0)
        src_mac = ":".join("%02X" % b for b in eth.src)
        dst_mac = ":".join("%02X" % b for b in eth.dst)

        if eth.type in L2_ETHERTYPES:
            self._analyzer._handle_l2_frame(
                src_mac, dst_mac, eth.type, bytes(eth.data), ts)
            self.stats.frames_l2 += 1
            self.stats.frames_decoded += 1
            return

        if not isinstance(eth.data, dpkt.ip.IP):
            return

        ip = eth.data
        transport = ip.data
        if isinstance(transport, dpkt.tcp.TCP):
            proto = "TCP"
        elif isinstance(transport, dpkt.udp.UDP):
            proto = "UDP"
        else:
            return

        self._analyzer._handle_ip_packet(
            socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst),
            src_mac, dst_mac, transport.sport, transport.dport,
            proto, bytes(transport.data), ts, len(frame.raw))
        self.stats.frames_ip += 1
        self.stats.frames_decoded += 1

    # ── emit ──────────────────────────────────────────────────────────────
    def build_batch(self, window_id: str, coverage: str,
                    window: Optional[Dict[str, Any]] = None,
                    seen_at: Optional[float] = None) -> ObservationBatch:
        """Recompute findings over accumulated state and emit this window's records."""
        devices, flows = self._finalise()

        batch = ObservationBatch(collector_id=self.collector_id,
                                 window_id=window_id, coverage=coverage,
                                 window=dict(window or {}))
        for device in devices:
            batch.records.append(
                self.builder.asset(device, window_id, coverage, seen_at))
            key = asset_key(getattr(device, "ip", "") or "",
                            getattr(device, "mac", "") or "")
            for finding in getattr(device, "vulnerabilities", []) or []:
                batch.records.append(
                    self.builder.detection(key, finding, window_id, coverage,
                                           seen_at))
        for flow in flows:
            batch.records.append(
                self.builder.flow(flow, window_id, coverage, seen_at))
        return batch

    def _finalise(self):
        result = self._analyzer._finalise()
        # _finalise returns (devices, flows, zones, violations, edges); zones and
        # topology are server-side (they need the whole estate), so they are not
        # emitted here.
        devices = result[0] if len(result) > 0 else []
        flows = result[1] if len(result) > 1 else []
        return devices, flows

    def summary(self) -> Dict[str, Any]:
        return {
            "frames_seen": self.stats.frames_seen,
            "frames_decoded": self.stats.frames_decoded,
            "frames_l2": self.stats.frames_l2,
            "frames_ip": self.stats.frames_ip,
            "decode_failures": self.stats.decode_failures,
            "undecodable_fraction": self.stats.undecodable_fraction,
            "rulepack": self.rulepack.version,
            "rulepack_complete": self.rulepack.complete,
        }
