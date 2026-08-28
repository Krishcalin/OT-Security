"""
Capture sources (OTS-CAP-002).

A source yields frames and, where it can, the counters that say how many it
lost. Everything else in the collector is written against this interface, so the
capture loop can be exercised on any machine with a synthetic source while the
live backends need a Linux NIC.

Three implementations:

  ScapyLiveSource   live SPAN capture via scapy; compiles the BPF filter through
                    libpcap and exposes pcap_stats.
  ReplaySource      reads an existing pcap. Not a test double — this is the
                    offline-analysis path, and it makes every capture-loop test
                    run against real frames.
  SyntheticSource   frames from a list, with drop counters the test controls.
                    The only way to exercise loss handling without a busy NIC.

WHAT A SOURCE MUST NOT DO
─────────────────────────
Transmit. `OTS-SEC-001` is a property of the whole collector, and the capture
interface is the one place a bug could put a frame onto a live plant network. No
source here has a send path, and `test_no_capture_source_can_transmit` pins that
by inspecting the source of every class in this module.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, List, Optional

from .coverage import DropSnapshot


@dataclass
class Frame:
    """One captured frame, in the shape the loop needs.

    `raw` is the bytes for the protocol analysers; the addressing fields are
    lifted out so self-exclusion can decide without re-parsing.
    """

    raw: bytes = b""
    timestamp: float = 0.0
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    @property
    def length(self) -> int:
        return len(self.raw)


class CaptureSource:
    """Interface every source implements."""

    name = "abstract"

    def open(self) -> None:            # pragma: no cover - trivial
        pass

    def read(self, max_frames: int = 256, timeout: float = 1.0) -> List[Frame]:
        raise NotImplementedError

    def stats(self) -> DropSnapshot:
        return DropSnapshot(source=self.name)

    def close(self) -> None:           # pragma: no cover - trivial
        pass

    @property
    def exhausted(self) -> bool:
        """True when the source will never yield another frame (a finite replay).
        A live source is never exhausted."""
        return False


class SyntheticSource(CaptureSource):
    """Frames from a list, with counters the caller controls.

    Exists so loss handling is testable: on a real NIC you cannot ask for
    exactly seventeen dropped frames.
    """

    name = "synthetic"

    def __init__(self, frames: Optional[Iterable[Frame]] = None,
                 stats_sequence: Optional[List[DropSnapshot]] = None):
        self._frames = list(frames or [])
        self._pos = 0
        self._stats = list(stats_sequence or [])
        self._stat_pos = 0

    def read(self, max_frames: int = 256, timeout: float = 1.0) -> List[Frame]:
        batch = self._frames[self._pos:self._pos + max_frames]
        self._pos += len(batch)
        return batch

    def stats(self) -> DropSnapshot:
        if not self._stats:
            return DropSnapshot(source=self.name)
        snap = self._stats[min(self._stat_pos, len(self._stats) - 1)]
        self._stat_pos += 1
        return snap

    @property
    def exhausted(self) -> bool:
        return self._pos >= len(self._frames)


class ReplaySource(CaptureSource):
    """An existing pcap, replayed through the same loop as live capture.

    The offline-analysis path from the SRS, and the reason capture-loop tests can
    run against genuine frames rather than only synthetic ones.

    Drop counters are deliberately absent: a file has no loss to report, and the
    honest consequence is that replayed windows are UNKNOWN rather than
    COMPLETE. A file cannot tell you what the tap missed when it was recorded.
    """

    name = "replay"

    def __init__(self, path: str):
        self.path = path
        self._iter: Optional[Iterator] = None
        self._done = False

    def open(self) -> None:
        try:
            import dpkt                                    # noqa: F401
        except ImportError:
            dpkt = None                                    # type: ignore
        self._iter = self._frames()

    def _frames(self) -> Iterator[Frame]:
        import dpkt

        with open(self.path, "rb") as handle:
            try:
                reader = dpkt.pcap.Reader(handle)
            except ValueError:
                handle.seek(0)
                reader = dpkt.pcapng.Reader(handle)
            for ts, buf in reader:
                yield Frame(raw=buf, timestamp=ts, **_addresses(buf))

    def read(self, max_frames: int = 256, timeout: float = 1.0) -> List[Frame]:
        if self._iter is None:
            self.open()
        out: List[Frame] = []
        for _ in range(max_frames):
            try:
                out.append(next(self._iter))               # type: ignore[arg-type]
            except StopIteration:
                self._done = True
                break
        return out

    @property
    def exhausted(self) -> bool:
        return self._done


def _addresses(buf: bytes) -> dict:
    """Layer 2/3 addresses, best effort. Never raises: a frame we cannot parse
    is still a frame that was captured, and dropping it here would understate
    what the collector saw."""
    out = {"src_mac": None, "dst_mac": None, "src_ip": None, "dst_ip": None}
    try:
        import dpkt

        eth = dpkt.ethernet.Ethernet(buf)
        out["src_mac"] = _mac(eth.src)
        out["dst_mac"] = _mac(eth.dst)
        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            import socket

            out["src_ip"] = socket.inet_ntoa(ip.src)
            out["dst_ip"] = socket.inet_ntoa(ip.dst)
    except Exception:                                      # noqa: BLE001
        pass
    return out


def _mac(raw: bytes) -> Optional[str]:
    if not raw or len(raw) != 6:
        return None
    return ":".join("%02x" % b for b in raw)


class ScapyLiveSource(CaptureSource):
    """Live SPAN capture through scapy.

    scapy is imported inside `open()` rather than at module scope so the rest of
    this module — and every test of the capture loop — works on a machine with
    no scapy and no NIC.
    """

    name = "scapy-live"

    def __init__(self, interface: str, bpf: Optional[str] = None,
                 snaplen: int = 65535):
        self.interface = interface
        self.bpf = bpf
        self.snaplen = snaplen
        self._sock = None

    def open(self) -> None:
        from scapy.config import conf                      # noqa: PLC0415

        # L2listen: a listening socket. scapy's L2socket would be able to send;
        # this one is receive-only by construction (OTS-SEC-001).
        self._sock = conf.L2listen(iface=self.interface, filter=self.bpf)

    def read(self, max_frames: int = 256, timeout: float = 1.0) -> List[Frame]:
        if self._sock is None:
            self.open()
        out: List[Frame] = []
        deadline = time.time() + timeout
        while len(out) < max_frames and time.time() < deadline:
            pkt = self._sock.recv()                        # type: ignore[union-attr]
            if pkt is None:
                break
            raw = bytes(pkt)
            out.append(Frame(raw=raw, timestamp=float(getattr(pkt, "time", 0.0)),
                             **_addresses(raw)))
        return out

    def stats(self) -> DropSnapshot:
        from .counters import PcapStatsCounters

        handle = getattr(self._sock, "ins", None)
        return PcapStatsCounters(handle).read()

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None
