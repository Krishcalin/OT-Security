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

from . import decap, rulepack
from .capture import Frame
from .observations import (ObservationBatch, ObservationBuilder, asset_key)

# The scanner package sits alongside this one.
_HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.dirname(_HERE) not in sys.path:
    sys.path.insert(0, os.path.dirname(_HERE))

# GOOSE, SV, PROFINET, LLDP. LLDP earns its place here for a reason the
# others do not need: it is the ONLY passive source that names the ring
# switches carrying the MPLS-TP transport. They speak no industrial protocol,
# and their management traffic may never cross the mirror at all.
L2_ETHERTYPES = (0x88B8, 0x88BA, 0x8892, 0x88CC, 0x8902)

#: 802.1D spanning-tree BPDUs carry an 802.3 LENGTH where an EtherType would
#: be, so no ethertype list can select them. They are identified by their
#: destination — the bridge group address — and they matter because a topology
#: change moves traffic, and traffic that moves may move out of earshot.
BRIDGE_GROUP_ADDRESS = "01:80:C2:00:00:00"


@dataclass
class DecodeCounters:
    """What one window made of the frames it was handed.

    `unreadable` is narrow ON PURPOSE: it counts only frames whose TRANSPORT
    could not be opened — an MPLS pseudowire in a shape this collector cannot
    follow. Frames that decoded perfectly well and simply were not interesting
    (ARP, STP) land in `not_analysed` and say nothing about coverage.

    Keeping them apart is what lets any non-zero `unreadable` degrade a window
    without every window being degraded by ordinary background traffic.
    """

    decoded: int = 0
    unreadable: int = 0
    not_analysed: int = 0
    #: Encapsulation we could not follow -> how many frames of it, so the
    #: operator is told WHAT is unreadable rather than only how much.
    transports: Dict[str, int] = field(default_factory=dict)


@dataclass
class AnalysisStats:
    frames_seen: int = 0
    frames_decoded: int = 0
    frames_l2: int = 0
    frames_ip: int = 0
    #: Frames whose transport encapsulation could not be followed. Before this
    #: existed, 50,000 pseudowire frames produced 0 devices, 0 recorded
    #: failures, and a window reported COMPLETE over an empty estate.
    frames_unreadable: int = 0
    #: Decoded, but not a protocol this analyser acts on. Benign.
    frames_not_analysed: int = 0
    #: Frames that arrived already wrapped in MPLS, decoded successfully.
    frames_decapsulated: int = 0
    decode_failures: int = 0

    @property
    def undecodable_fraction(self) -> Optional[float]:
        """Share of frames this analyser could make NOTHING of.

        Two routes reach that outcome and both belong here: a decoder that
        raised (`decode_failures`), and a transport that could not be opened in
        the first place (`frames_unreadable`). They are separate counters
        because they need separate fixes — one is a malformed frame, the other
        is a tap on the wrong side of a pseudowire — but a caller asking "is
        this link readable at all?" must not be told 0% by a number that only
        counts one of them.
        """
        if self.frames_seen == 0:
            return None
        return (self.decode_failures + self.frames_unreadable) / self.frames_seen


class IncrementalAnalyzer:
    """Feeds frames to the existing analyser and emits records per window."""

    def __init__(self, collector_id: str = "collector",
                 analyzer: Any = None, verbose: bool = False,
                 scanner_root: Optional[str] = None):
        self.collector_id = collector_id
        self.stats = AnalysisStats()
        self._window = DecodeCounters()
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
        # Open any transport encapsulation FIRST. On an MPLS-TP NNI the RTU's
        # own MAC, IP and IEC 104 session are all behind a label stack and a
        # pseudowire control word; parsing the outer frame yields the provider
        # edge router and nothing else.
        opened = decap.decapsulate(frame.raw)
        if not opened.understood:
            # NOT a silent return. This is the frame shape that made an
            # unreadable transport look like a quiet network.
            self.stats.frames_unreadable += 1
            self._window.unreadable += 1
            where = decap.describe(opened)
            self._window.transports[where] = \
                self._window.transports.get(where, 0) + 1
            return
        if opened.encapsulated:
            self.stats.frames_decapsulated += 1

        eth = dpkt.ethernet.Ethernet(opened.frame)
        ts = datetime.fromtimestamp(frame.timestamp or 0)
        src_mac = ":".join("%02X" % b for b in eth.src)
        dst_mac = ":".join("%02X" % b for b in eth.dst)

        if (eth.type < 0x0600
                and dst_mac.upper() == BRIDGE_GROUP_ADDRESS):
            # An 802.3 frame to the bridge group address: a BPDU. Forwarded on
            # its destination rather than its type, because it has no type.
            self._analyzer._handle_l2_frame(
                src_mac, dst_mac, eth.type, bytes(eth.data), ts)
            self.stats.frames_l2 += 1
            self.stats.frames_decoded += 1
            self._window.decoded += 1
            return

        if eth.type in L2_ETHERTYPES:
            self._analyzer._handle_l2_frame(
                src_mac, dst_mac, eth.type, bytes(eth.data), ts)
            self.stats.frames_l2 += 1
            self.stats.frames_decoded += 1
            self._window.decoded += 1
            return

        if not isinstance(eth.data, dpkt.ip.IP):
            # Decoded fine, just not ours — ARP, STP and friends. Counted
            # separately from `unreadable` so ordinary background traffic does
            # not degrade every window.
            self.stats.frames_not_analysed += 1
            self._window.not_analysed += 1
            return

        ip = eth.data
        transport = ip.data
        if isinstance(transport, dpkt.tcp.TCP):
            proto = "TCP"
        elif isinstance(transport, dpkt.udp.UDP):
            proto = "UDP"
        else:
            self.stats.frames_not_analysed += 1
            self._window.not_analysed += 1
            return

        self._analyzer._handle_ip_packet(
            socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst),
            src_mac, dst_mac, transport.sport, transport.dport,
            proto, bytes(transport.data), ts, len(frame.raw))
        self.stats.frames_ip += 1
        self.stats.frames_decoded += 1
        self._window.decoded += 1

    # ── readability accounting ────────────────────────────────────────────
    def take_ring_state(self):
        """This window's ring protection activity, then reset.

        Pulled per window like the decode counters, and for the same reason:
        the question a window answers is "could this window hear the estate",
        and last window's protection switch says nothing about this one.

        Returns None when no ring analyser is present, which is not the same as
        a stable ring — a collector that cannot see R-APS has not established
        that the ring did not protect.
        """
        analyzer = getattr(self._analyzer, "_ring_analyzer", None)
        if analyzer is None:
            return None
        return analyzer.take_state()

    def take_decode_counters(self) -> DecodeCounters:
        """This window's decode outcome, and reset for the next one.

        Injected into the capture service so a window that could not be READ
        cannot be reported as one that was clean. The service owns capture and
        the analyser owns decoding; this is the one number that has to cross
        between them, and it crosses as a pull rather than by giving the
        service a reference to the analyser.
        """
        taken, self._window = self._window, DecodeCounters()
        return taken

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
