"""
Collector -> server transport (OTS-TRN-001, 002, 004, 005, 006).

OUTBOUND ONLY
─────────────
The collector dials out; it never listens. A device inside a plant network with
an open port is an attack surface installed on purpose, and the SPAN topology
means it is reachable from the OT side. There is no server here — only a client
— and `test_transport_opens_no_listening_socket` pins that by AST.

MUTUAL TLS, VERIFIED, WITH NO FALLBACK
──────────────────────────────────────
Both peers authenticate against a self-managed CA shipped with the server (Q4).
Verification is mandatory: a collector that silently accepted an unverified
certificate would be worse than one that failed, because it would keep reporting
and the operator would believe the channel was authenticated. `TransportConfig`
refuses to construct without a CA bundle and a client certificate.

DELIVERY IS AT-LEAST-ONCE, AND THAT IS SAFE
───────────────────────────────────────────
A batch carries a content-derived id. If an acknowledgement is lost the batch is
re-sent with the same id and the server recognises it (`OTS-TRN-004`), so the
collector never has to choose between possibly-losing and possibly-duplicating.

WHAT IS NOT SENT
────────────────
Raw pcap. It stays on the collector unless explicitly requested per incident
(`OTS-TRN-006`), and there is deliberately no code path here that would ship it.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from .spool import Spool, backoff_delay


class TransportError(RuntimeError):
    """Raised for configuration faults. A misconfigured collector must fail at
    start-up, not at the first outage."""


@dataclass
class TransportConfig:
    """Where to send, and what identity to send it with.

    Every field is required. There is no "insecure mode" flag: a switch that
    disables verification is a switch someone eventually leaves on, and the
    resulting deployment looks identical to a correct one from the console.
    """

    server_url: str
    ca_bundle: str
    client_cert: str
    client_key: str
    collector_id: str = "collector-01"
    timeout: float = 30.0
    verify: bool = True

    def __post_init__(self) -> None:
        if not self.server_url.lower().startswith("https://"):
            raise TransportError(
                "server_url must be https:// — the channel carries an "
                "operator's asset inventory and its own authentication")
        missing = [name for name in ("ca_bundle", "client_cert", "client_key")
                   if not getattr(self, name)]
        if missing:
            raise TransportError(
                "mutual TLS requires %s (OTS-TRN-002). A collector that reports "
                "without authenticating is indistinguishable from one that does."
                % ", ".join(missing))
        if not self.verify:
            raise TransportError(
                "certificate verification cannot be disabled: an unverified "
                "channel keeps reporting and looks authenticated on the console")

    @property
    def ingest_url(self) -> str:
        return self.server_url.rstrip("/") + "/api/v1/ingest"

    @property
    def heartbeat_url(self) -> str:
        return self.server_url.rstrip("/") + "/api/v1/heartbeat"

    def missing_files(self) -> Tuple[str, ...]:
        """Configured paths that do not exist. Checked at start-up, because a
        typo in a certificate path should not surface as a delivery failure an
        hour later."""
        return tuple(path for path in
                     (self.ca_bundle, self.client_cert, self.client_key)
                     if not os.path.isfile(path))


@dataclass
class SendResult:
    ok: bool
    status: int = 0
    detail: str = ""
    duplicate: bool = False          # server already had this batch_id


class HttpSender:
    """The one place an HTTPS request is made.

    `requests` is imported inside the call rather than at module scope so the
    spool, the retry policy and the whole transport loop can be tested on a
    machine with no HTTP stack — the same seam used for scapy in capture.py and
    for the same reason: a dependency in one layer must not make the layer above
    it untestable.
    """

    def __init__(self, config: TransportConfig):
        self.config = config

    def post(self, url: str, payload: Dict) -> SendResult:
        try:
            import requests
        except ImportError:
            return SendResult(False, 0, "requests is not installed")

        cfg = self.config
        try:
            response = requests.post(
                url, json=payload,
                cert=(cfg.client_cert, cfg.client_key),
                verify=cfg.ca_bundle,
                timeout=cfg.timeout,
                headers={"X-Collector-Id": cfg.collector_id})
        except Exception as exc:                           # noqa: BLE001
            # Never surface the driver's message verbatim: it can echo the
            # request, and the request is an operator's asset inventory.
            return SendResult(False, 0, type(exc).__name__)

        if response.status_code == 409:
            # The server already has this batch_id. At-least-once delivery
            # working as designed, not an error.
            return SendResult(True, 409, "duplicate", duplicate=True)
        if 200 <= response.status_code < 300:
            return SendResult(True, response.status_code, "ok")
        return SendResult(False, response.status_code,
                          "server rejected the batch")


class Transport:
    """Drains the spool to the server, with backoff and gap reporting."""

    def __init__(self, config: TransportConfig, spool: Spool,
                 sender: Optional[Any] = None,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep):
        self.config = config
        self.spool = spool
        self.sender = sender if sender is not None else HttpSender(config)
        self.clock = clock
        self.sleep = sleep
        self.consecutive_failures = 0
        self.last_success: Optional[float] = None

    # ── sending ───────────────────────────────────────────────────────────
    def enqueue(self, batch: Dict) -> str:
        return self.spool.append(batch)

    def flush(self, max_batches: int = 100) -> Dict[str, int]:
        """Send what is queued, oldest first. Stops on the first failure.

        Stopping rather than skipping ahead keeps delivery ordered, so the
        server sees windows in the order they happened. Skipping the head to
        deliver newer batches would make a partial outage produce an
        out-of-order history that is harder to reason about than a gap.
        """
        sent = duplicates = failed = 0

        gap = self.spool.take_loss_record(self.config.collector_id)
        if gap is not None:
            # Announce the gap BEFORE the batches that follow it, so the server
            # never sees the resumed stream as continuous.
            result = self.sender.post(self.config.ingest_url,
                                      {"gap": gap, "collector_id": gap["collector_id"]})
            if not result.ok:
                # Put it back: a gap that fails to send must not be forgotten.
                self.spool.loss.batches += gap["batches_lost"]
                self.spool.loss.records += gap["records_lost"]
                self.spool.loss.first_window = gap["first_window"]
                self.spool.loss.last_window = gap["last_window"]
                self.spool.loss.since_epoch = gap["since_epoch"]
                self.spool.loss.until_epoch = gap["until_epoch"]
                self._note_failure()
                return {"sent": 0, "duplicates": 0, "failed": 1}

        for _ in range(max_batches):
            head = self.spool.peek()
            if head is None:
                break
            name, batch = head
            result = self.sender.post(self.config.ingest_url, batch)
            if result.ok:
                self.spool.ack(name)
                sent += 1
                if result.duplicate:
                    duplicates += 1
                self._note_success()
            else:
                self.spool.note_retry()
                self._note_failure()
                failed += 1
                break
        return {"sent": sent, "duplicates": duplicates, "failed": failed}

    def heartbeat(self, capture_health: Optional[Dict] = None,
                  rulepack_version: str = "",
                  collector_version: str = "") -> SendResult:
        """OTS-TRN-005. Absence of a heartbeat is a fleet alarm, so it carries
        enough for the server to tell a healthy-but-quiet collector from a
        struggling one."""
        stats = self.spool.stats()
        payload = {
            "collector_id": self.config.collector_id,
            "epoch": self.clock(),
            "collector_version": collector_version,
            "rulepack_version": rulepack_version,
            "queue_depth": stats.queued,
            "queue_bytes": stats.bytes_used,
            "batches_sent": stats.sent,
            "batches_lost": stats.loss.batches,
            "records_lost": stats.loss.records,
            "consecutive_failures": self.consecutive_failures,
            "last_success_epoch": self.last_success,
            "capture_health": capture_health or {},
        }
        return self.sender.post(self.config.heartbeat_url, payload)

    # ── backoff ───────────────────────────────────────────────────────────
    def _note_success(self) -> None:
        self.consecutive_failures = 0
        self.last_success = self.clock()

    def _note_failure(self) -> None:
        self.consecutive_failures += 1

    @property
    def next_delay(self) -> float:
        return backoff_delay(self.consecutive_failures)

    def wait_before_retry(self) -> float:
        delay = self.next_delay
        if delay > 0:
            self.sleep(delay)
        return delay

    def status(self) -> Dict[str, Any]:
        stats = self.spool.stats()
        return {
            "collector_id": self.config.collector_id,
            "server": self.config.server_url,
            "queue_depth": stats.queued,
            "queue_bytes": stats.bytes_used,
            "batches_sent": stats.sent,
            "retries": stats.retries,
            "batches_lost": stats.loss.batches,
            "records_lost": stats.loss.records,
            "consecutive_failures": self.consecutive_failures,
            "next_retry_seconds": self.next_delay,
        }
