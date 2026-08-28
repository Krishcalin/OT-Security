"""
Durable store-and-forward spool (OTS-TRN-003, OTS-TRN-004).

OT links drop. A collector that loses its observations because the server was
unreachable for an afternoon is not a sensor, it is a live feed — so batches are
written to disk before any attempt to send, and survive a restart.

THE PART THAT IS EASY TO GET WRONG
──────────────────────────────────
A spool has a disk ceiling, so a long outage eventually forces a choice between
losing old batches and refusing new ones. Both are data loss. What must never
happen is losing them QUIETLY:

    A gap in delivery is a coverage gap.

If the server simply never receives a window, the absence looks exactly like a
quiet network — the same failure as an unreported dropped frame, one layer up.
So every eviction is counted, the interval it spans is recorded, and the loss is
reported to the server as an explicit record when the link returns. The server
then knows it is missing observations rather than inferring there were none.

WHY OLDEST-FIRST
────────────────
Newest-first would preserve continuity of history and discard the present, which
is the wrong way round for a security sensor: an operator asking "what is
happening now" is better served than one asking "what happened last Tuesday",
and Tuesday is also on the collector's rolling pcap. `OTS-TRN-003` specifies
oldest-first for that reason.

IDEMPOTENCY IS FREE HERE
────────────────────────
A batch carries a content-derived id (`ObservationBatch.batch_id`). A retry that
succeeded server-side but whose acknowledgement was lost re-sends the same id,
and the server recognises it. So the send path can be at-least-once without the
server double-counting an asset.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

SPOOL_SUFFIX = ".batch.json"
_NAME_RE = re.compile(r"^(?P<seq>\d{12})-(?P<bid>[0-9a-f]{8,40})\.batch\.json$")

#: A spool is small — records, not packets. 2 GiB is a long outage at the
#: observation volumes this system produces (~0.15-0.6 GB/day/collector).
DEFAULT_SPOOL_BYTES = 2 * 1024 ** 3


@dataclass
class SpoolLoss:
    """Observations discarded because the spool filled.

    Kept as a record rather than a counter so the server learns WHEN the gap
    was, not merely that one happened. A gap of unknown extent cannot be
    reasoned about; a gap with endpoints can.
    """

    batches: int = 0
    records: int = 0
    first_window: str = ""
    last_window: str = ""
    since_epoch: Optional[float] = None
    until_epoch: Optional[float] = None

    @property
    def any(self) -> bool:
        return self.batches > 0

    def absorb(self, window_id: str, records: int, epoch: Optional[float]) -> None:
        self.batches += 1
        self.records += records
        if not self.first_window:
            self.first_window = window_id
            self.since_epoch = epoch
        self.last_window = window_id
        self.until_epoch = epoch

    def to_record(self, collector_id: str) -> Dict:
        """The shape sent to the server so the gap is explicit.

        This is the transport-layer equivalent of a DEGRADED capture window: the
        server must be able to tell "we lost observations here" from "there were
        none", and only the collector knows which.
        """
        return {
            "kind": "delivery_gap",
            "collector_id": collector_id,
            "batches_lost": self.batches,
            "records_lost": self.records,
            "first_window": self.first_window,
            "last_window": self.last_window,
            "since_epoch": self.since_epoch,
            "until_epoch": self.until_epoch,
            "reason": "spool ceiling reached while the server was unreachable",
        }

    def clear(self) -> None:
        self.batches = 0
        self.records = 0
        self.first_window = ""
        self.last_window = ""
        self.since_epoch = None
        self.until_epoch = None


@dataclass
class SpoolStats:
    queued: int = 0
    bytes_used: int = 0
    sent: int = 0
    retries: int = 0
    loss: SpoolLoss = field(default_factory=SpoolLoss)

    def to_dict(self) -> Dict:
        return {
            "queued": self.queued,
            "bytes_used": self.bytes_used,
            "sent": self.sent,
            "retries": self.retries,
            "batches_lost": self.loss.batches,
            "records_lost": self.loss.records,
        }


class Spool:
    """Batches on disk, oldest-first, bounded, counted.

    Filesystem-backed rather than in-memory: an observation that exists only in
    a process is lost to a power cut, and a substation collector is exactly the
    thing that loses power.
    """

    def __init__(self, directory: str, max_bytes: int = DEFAULT_SPOOL_BYTES,
                 clock: Callable[[], float] = time.time):
        self.directory = directory
        self.max_bytes = max_bytes
        self.clock = clock
        self.loss = SpoolLoss()
        self.sent = 0
        self.retries = 0
        self._seq = 0
        os.makedirs(directory, exist_ok=True)
        self._recover_sequence()

    def _recover_sequence(self) -> None:
        """Continue the sequence across a restart, so ordering survives it."""
        highest = 0
        for name in self._names():
            m = _NAME_RE.match(name)
            if m:
                highest = max(highest, int(m.group("seq")))
        self._seq = highest

    def _names(self) -> List[str]:
        try:
            return sorted(n for n in os.listdir(self.directory)
                          if n.endswith(SPOOL_SUFFIX))
        except OSError:
            return []

    def _path(self, name: str) -> str:
        return os.path.join(self.directory, name)

    def _size(self, name: str) -> int:
        try:
            return os.path.getsize(self._path(name))
        except OSError:
            return 0

    @property
    def bytes_used(self) -> int:
        return sum(self._size(n) for n in self._names())

    @property
    def depth(self) -> int:
        return len(self._names())

    # ── writing ───────────────────────────────────────────────────────────
    def append(self, batch: Dict) -> str:
        """Persist a batch, evicting oldest-first if the ceiling requires it."""
        body = json.dumps(batch, separators=(",", ":")).encode("utf-8")
        self._make_room(len(body))
        self._seq += 1
        name = "%012d-%s%s" % (self._seq,
                               str(batch.get("batch_id", "nobatchid"))[:40],
                               SPOOL_SUFFIX)
        tmp = self._path(name + ".tmp")
        with open(tmp, "wb") as handle:
            handle.write(body)
        # Rename is atomic on POSIX, so a power cut mid-write leaves a .tmp
        # rather than a truncated batch the sender would ship as valid.
        os.replace(tmp, self._path(name))
        return name

    def _make_room(self, incoming: int) -> None:
        if incoming > self.max_bytes:
            raise ValueError("batch larger than the whole spool budget")
        names = self._names()
        used = sum(self._size(n) for n in names)
        for name in names:                       # oldest first
            if used + incoming <= self.max_bytes:
                return
            lost = self._read(name)
            used -= self._size(name)
            try:
                os.remove(self._path(name))
            except OSError:
                continue
            if lost is not None:
                self.loss.absorb(
                    str(lost.get("window_id", "")),
                    len(lost.get("records", []) or []),
                    self.clock())

    def _read(self, name: str) -> Optional[Dict]:
        try:
            with open(self._path(name), "rb") as handle:
                return json.loads(handle.read().decode("utf-8"))
        except (OSError, ValueError):
            return None

    # ── reading ───────────────────────────────────────────────────────────
    def peek(self) -> Optional[Tuple[str, Dict]]:
        """The oldest batch still awaiting delivery."""
        for name in self._names():
            body = self._read(name)
            if body is None:
                # Unreadable: a truncated write from a power cut. Drop it and
                # count it -- leaving it would block the queue head forever.
                self.loss.absorb("<corrupt:%s>" % name, 0, self.clock())
                try:
                    os.remove(self._path(name))
                except OSError:
                    pass
                continue
            return name, body
        return None

    def ack(self, name: str) -> None:
        """The server has it. Only now is it safe to forget."""
        try:
            os.remove(self._path(name))
            self.sent += 1
        except OSError:
            pass

    def note_retry(self) -> None:
        self.retries += 1

    def stats(self) -> SpoolStats:
        return SpoolStats(queued=self.depth, bytes_used=self.bytes_used,
                          sent=self.sent, retries=self.retries, loss=self.loss)

    # ── the gap record ────────────────────────────────────────────────────
    def take_loss_record(self, collector_id: str) -> Optional[Dict]:
        """Emit and reset the delivery-gap record, if there is one.

        Called when the link returns. Reporting it once and clearing means the
        server sees the gap exactly once; keeping it would re-report the same
        loss forever, and dropping it silently would leave the server unable to
        distinguish a gap from a quiet network.
        """
        if not self.loss.any:
            return None
        record = self.loss.to_record(collector_id)
        self.loss.clear()
        return record


def backoff_delay(attempt: int, base: float = 1.0, cap: float = 300.0) -> float:
    """Exponential backoff, capped.

    Capped because an OT link can be down for hours and an uncapped exponential
    reaches a retry interval longer than the outage — the collector would sit
    idle after the network returned. The cap bounds how stale a recovered link
    can be.
    """
    if attempt <= 0:
        return 0.0
    return min(cap, base * (2 ** (attempt - 1)))
