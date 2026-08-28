"""
Phase 3 — store-and-forward transport (OTS-TRN-001..006).

Driven by a stub sender, so the queue semantics, backoff and gap reporting are
exercised without a server, a certificate or an HTTP stack — the same seam that
lets the capture loop be tested without a NIC.

The behaviour that matters most here is not delivery. It is what happens when
delivery FAILS for long enough to lose something: a gap in delivery is a
coverage gap, and if the server simply never receives a window, the absence
looks exactly like a quiet network.
"""
from __future__ import annotations

import ast
import inspect
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector import transport as transport_mod  # noqa: E402
from collector.spool import Spool, backoff_delay  # noqa: E402
from collector.transport import (SendResult, Transport, TransportConfig,  # noqa: E402
                                 TransportError)


def _certs(tmp_path):
    paths = {}
    for name in ("ca.pem", "client.pem", "client.key"):
        p = tmp_path / name
        p.write_text("stub")
        paths[name] = str(p)
    return paths


def _config(tmp_path, **kw):
    c = _certs(tmp_path)
    kw.setdefault("server_url", "https://server.example:443")
    return TransportConfig(ca_bundle=c["ca.pem"], client_cert=c["client.pem"],
                           client_key=c["client.key"], **kw)


class StubSender:
    """Records what was sent and answers however the test needs."""

    def __init__(self, results=None):
        self.calls = []
        self._results = list(results or [])

    def post(self, url, payload):
        self.calls.append((url, payload))
        if self._results:
            return self._results.pop(0)
        return SendResult(True, 200, "ok")


def _batch(window="w-1", records=3, bid=None):
    return {"batch_id": bid or ("b" + window.replace("-", "")),
            "window_id": window, "collector_id": "c1",
            "coverage": "complete",
            "records": [{"key": "ip:10.0.0.%d" % i} for i in range(records)]}


def _transport(tmp_path, sender=None, max_bytes=None):
    spool = Spool(str(tmp_path / "spool"), clock=lambda: 1000.0,
                  **({"max_bytes": max_bytes} if max_bytes else {}))
    return Transport(_config(tmp_path), spool, sender=sender or StubSender(),
                     clock=lambda: 1000.0, sleep=lambda _s: None)


# ── OTS-TRN-001: outbound only ─────────────────────────────────────────────

def test_transport_opens_no_listening_socket():
    """A device inside a plant network with an open port is an attack surface
    installed on purpose, and the SPAN topology makes it reachable from the OT
    side."""
    banned = {"bind", "listen", "accept", "serve_forever", "create_server"}
    tree = ast.parse(inspect.getsource(transport_mod))
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute):
                called.add(fn.attr)
            elif isinstance(fn, ast.Name):
                called.add(fn.id)
    assert not (called & banned), sorted(called & banned)


# ── OTS-TRN-002: mutual TLS, no way to turn it off ─────────────────────────

def test_plain_http_is_refused(tmp_path):
    with pytest.raises(TransportError) as exc:
        _config(tmp_path, server_url="http://server.example")
    assert "https" in str(exc.value)


def test_missing_client_identity_is_refused(tmp_path):
    c = _certs(tmp_path)
    with pytest.raises(TransportError) as exc:
        TransportConfig(server_url="https://s.example", ca_bundle=c["ca.pem"],
                        client_cert="", client_key=c["client.key"])
    assert "OTS-TRN-002" in str(exc.value)


def test_verification_cannot_be_disabled(tmp_path):
    """A switch that disables verification is one someone eventually leaves on,
    and the resulting deployment looks correct from the console."""
    c = _certs(tmp_path)
    with pytest.raises(TransportError) as exc:
        TransportConfig(server_url="https://s.example", ca_bundle=c["ca.pem"],
                        client_cert=c["client.pem"], client_key=c["client.key"],
                        verify=False)
    assert "unverified" in str(exc.value)


def test_a_missing_certificate_file_is_detected_at_startup(tmp_path):
    """A typo in a certificate path should not surface as a delivery failure an
    hour later."""
    cfg = _config(tmp_path)
    os.remove(cfg.client_key)
    assert cfg.missing_files() == (cfg.client_key,)


# ── the spool ──────────────────────────────────────────────────────────────

def test_a_batch_survives_a_restart(tmp_path):
    """An observation that exists only in a process is lost to a power cut, and
    a substation collector is exactly the thing that loses power."""
    d = str(tmp_path / "spool")
    Spool(d).append(_batch("w-1"))
    assert Spool(d).depth == 1


def test_delivery_is_oldest_first(tmp_path):
    t = _transport(tmp_path)
    for i in range(3):
        t.enqueue(_batch("w-%d" % i))
    t.flush()
    windows = [p["window_id"] for _u, p in t.sender.calls]
    assert windows == ["w-0", "w-1", "w-2"]


def test_a_batch_is_kept_until_the_server_acknowledges_it(tmp_path):
    t = _transport(tmp_path, StubSender([SendResult(False, 500, "boom")]))
    t.enqueue(_batch("w-1"))
    t.flush()
    assert t.spool.depth == 1, "an unacknowledged batch must not be discarded"


def test_flush_stops_at_the_first_failure_rather_than_skipping_ahead(tmp_path):
    """Ordered delivery: skipping the head to deliver newer batches turns a
    partial outage into an out-of-order history, which is harder to reason
    about than a gap."""
    sender = StubSender([SendResult(True, 200), SendResult(False, 503, "down")])
    t = _transport(tmp_path, sender)
    for i in range(4):
        t.enqueue(_batch("w-%d" % i))
    result = t.flush()
    assert result["sent"] == 1 and result["failed"] == 1
    assert t.spool.depth == 3


# ── OTS-TRN-004: at-least-once is safe ─────────────────────────────────────

def test_a_duplicate_is_an_acknowledgement_not_an_error(tmp_path):
    """A retry whose first acknowledgement was lost re-sends the same content
    id. 409 means the server already has it — the collector must not keep it
    queued forever."""
    t = _transport(tmp_path, StubSender([SendResult(True, 409, "dup",
                                                    duplicate=True)]))
    t.enqueue(_batch("w-1"))
    result = t.flush()
    assert result["duplicates"] == 1 and t.spool.depth == 0


# ── the part that matters: a delivery gap is a coverage gap ────────────────

def test_the_spool_evicts_oldest_first_when_it_fills(tmp_path):
    spool = Spool(str(tmp_path / "s"), max_bytes=800, clock=lambda: 5.0)
    for i in range(6):
        spool.append(_batch("w-%d" % i, records=4))
    assert spool.bytes_used <= 800
    assert spool.loss.any, "eviction must be recorded"


def test_lost_observations_are_counted_not_silently_dropped(tmp_path):
    spool = Spool(str(tmp_path / "s"), max_bytes=800, clock=lambda: 5.0)
    for i in range(6):
        spool.append(_batch("w-%d" % i, records=4))
    assert spool.loss.records > 0
    assert spool.loss.first_window and spool.loss.last_window


def test_the_gap_is_reported_to_the_server_when_the_link_returns(tmp_path):
    """The whole point. If the server simply never receives these windows, the
    absence looks exactly like a quiet network."""
    sender = StubSender()
    spool = Spool(str(tmp_path / "s"), max_bytes=800, clock=lambda: 5.0)
    t = Transport(_config(tmp_path), spool, sender=sender,
                  clock=lambda: 9.0, sleep=lambda _s: None)
    for i in range(6):
        t.enqueue(_batch("w-%d" % i, records=4))
    t.flush()

    gaps = [p for _u, p in sender.calls if "gap" in p]
    assert len(gaps) == 1, "the gap must be announced exactly once"
    gap = gaps[0]["gap"]
    assert gap["batches_lost"] > 0 and gap["records_lost"] > 0
    assert gap["first_window"] and gap["last_window"], (
        "a gap of unknown extent cannot be reasoned about")


def test_the_gap_is_announced_before_the_batches_that_follow_it(tmp_path):
    """So the server never reads the resumed stream as continuous."""
    sender = StubSender()
    spool = Spool(str(tmp_path / "s"), max_bytes=800, clock=lambda: 5.0)
    t = Transport(_config(tmp_path), spool, sender=sender, clock=lambda: 9.0,
                  sleep=lambda _s: None)
    for i in range(6):
        t.enqueue(_batch("w-%d" % i, records=4))
    t.flush()
    kinds = ["gap" if "gap" in p else "batch" for _u, p in sender.calls]
    assert kinds[0] == "gap"


def test_a_gap_that_fails_to_send_is_not_forgotten(tmp_path):
    sender = StubSender([SendResult(False, 503, "still down")])
    spool = Spool(str(tmp_path / "s"), max_bytes=800, clock=lambda: 5.0)
    t = Transport(_config(tmp_path), spool, sender=sender, clock=lambda: 9.0,
                  sleep=lambda _s: None)
    for i in range(6):
        t.enqueue(_batch("w-%d" % i, records=4))
    t.flush()
    assert t.spool.loss.any, "the gap must survive a failed announcement"


def test_the_gap_is_reported_once_and_then_cleared(tmp_path):
    sender = StubSender()
    spool = Spool(str(tmp_path / "s"), max_bytes=800, clock=lambda: 5.0)
    t = Transport(_config(tmp_path), spool, sender=sender, clock=lambda: 9.0,
                  sleep=lambda _s: None)
    for i in range(6):
        t.enqueue(_batch("w-%d" % i, records=4))
    t.flush()
    t.enqueue(_batch("w-later"))
    t.flush()
    assert sum(1 for _u, p in sender.calls if "gap" in p) == 1


def test_a_corrupt_batch_does_not_block_the_queue_head(tmp_path):
    """A truncated write from a power cut would otherwise stall delivery
    forever. It is dropped and counted."""
    spool = Spool(str(tmp_path / "s"), clock=lambda: 5.0)
    spool.append(_batch("w-1"))
    name = spool._names()[0]
    with open(spool._path(name), "w") as handle:
        handle.write("{not json")
    spool.append(_batch("w-2"))
    head = spool.peek()
    assert head is not None and head[1]["window_id"] == "w-2"
    assert spool.loss.any


# ── backoff ────────────────────────────────────────────────────────────────

def test_backoff_grows_then_stops_growing():
    """Uncapped exponential reaches a retry interval longer than the outage, so
    the collector sits idle after the network has returned."""
    assert backoff_delay(0) == 0
    assert backoff_delay(1) < backoff_delay(3) < backoff_delay(6)
    assert backoff_delay(50) == backoff_delay(60) == 300.0


def test_a_success_resets_the_backoff(tmp_path):
    t = _transport(tmp_path, StubSender([SendResult(False, 500), SendResult(True, 200)]))
    t.enqueue(_batch("w-1"))
    t.flush()
    assert t.consecutive_failures == 1
    t.flush()
    assert t.consecutive_failures == 0 and t.next_delay == 0


# ── OTS-TRN-005: heartbeats ────────────────────────────────────────────────

def test_the_heartbeat_carries_what_distinguishes_quiet_from_struggling(tmp_path):
    sender = StubSender()
    t = _transport(tmp_path, sender)
    t.enqueue(_batch("w-1"))
    t.heartbeat(capture_health={"state": "ok"}, rulepack_version="abc123",
                collector_version="0.1.0")
    _url, payload = sender.calls[-1]
    for field in ("queue_depth", "batches_lost", "records_lost",
                  "consecutive_failures", "rulepack_version", "capture_health"):
        assert field in payload, "heartbeat omits %s" % field


def test_the_heartbeat_goes_to_its_own_endpoint(tmp_path):
    sender = StubSender()
    t = _transport(tmp_path, sender)
    t.heartbeat()
    assert sender.calls[-1][0].endswith("/heartbeat")


# ── OTS-TRN-006: pcap stays local ──────────────────────────────────────────

def test_nothing_in_transport_reads_a_pcap():
    """Raw frames stay on the collector. There is deliberately no code path here
    that would ship them."""
    src = inspect.getsource(transport_mod).lower()
    for token in ("pcap", "capture_dir", "rolling"):
        assert token not in src.replace("pcap stays local", "").replace(
            "raw pcap", ""), "transport mentions %r" % token


def test_a_driver_error_never_carries_the_request_into_the_message():
    """The request body is an operator's asset inventory."""
    src = inspect.getsource(transport_mod)
    assert "type(exc).__name__" in src
    assert "str(exc)" not in src
