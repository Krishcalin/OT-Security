"""
FastAPI ingest and read API (OTS-TRN-004/005, OTS-SRV-004/005/006).

TWO PLANES, TWO CREDENTIALS
───────────────────────────
`OTS-SRV-006`: ingest credentials do not grant console access. A collector holds
a client certificate so it can *report*; it has no business reading the estate
inventory, and if its certificate is lifted from a substation cabinet the holder
should not gain a map of the plant. So `/api/v1/ingest` and `/api/v1/heartbeat`
authenticate as a collector, and everything under `/api/v1/estate` requires an
operator role.

THE IDENTITY COMES FROM THE CERTIFICATE, NOT THE BODY
─────────────────────────────────────────────────────
`X-Collector-Id` is a hint for logging. The authoritative identity is the client
certificate's subject, supplied by the TLS terminator. A collector that could
name itself in the payload could impersonate another site and poison its
inventory — and the request would look perfectly ordinary.

WHAT 409 MEANS HERE
───────────────────
Success. A collector retrying after a lost acknowledgement resends the same
content-derived batch id; answering 409 lets it clear its queue instead of
resending forever (`OTS-TRN-004`). It is not an error condition and must not be
logged as one, or every healthy fleet will look like it is failing.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

from . import ingest
from .ingest import Decision, Verdict

COLLECTOR_ID_HEADER = "X-Collector-Id"
CLIENT_SUBJECT_HEADER = "X-Client-Subject"      # set by the TLS terminator


class AuthError(RuntimeError):
    pass


def collector_identity(headers: Dict[str, str],
                       trust_header: bool = True) -> str:
    """Which collector this request is from.

    Taken from the verified client certificate subject, not the payload. The
    body is data the caller controls; the certificate is what mTLS established.
    """
    subject = headers.get(CLIENT_SUBJECT_HEADER) or headers.get(
        CLIENT_SUBJECT_HEADER.lower())
    if not subject:
        raise AuthError(
            "no verified client identity — this endpoint is reachable only "
            "through the mTLS terminator (OTS-TRN-002)")
    # CN=pi-substation-01,O=... -> pi-substation-01
    for part in subject.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return subject


def create_app(store, require_operator: Optional[Callable] = None):
    """Build the ASGI app. `store` is injected so the routes can be tested
    against a double without Postgres running."""
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(title="OT Sensor Fleet", version="0.1.0")

    def _identity(request: Request) -> str:
        try:
            return collector_identity(dict(request.headers))
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

    def _operator(request: Request) -> str:
        if require_operator is None:
            raise HTTPException(
                status_code=503,
                detail="no operator authentication is configured; the estate "
                       "API is fail-closed until one is wired (OTS-SRV-006)")
        return require_operator(request)

    # ── ingest plane ──────────────────────────────────────────────────────
    @app.post("/api/v1/ingest")
    async def ingest_batch(request: Request):
        collector = _identity(request)
        payload = await request.json()

        # The payload cannot name a different collector than the certificate.
        claimed = payload.get("collector_id")
        if claimed and claimed != collector:
            raise HTTPException(
                status_code=403,
                detail="payload claims collector_id %r but the client "
                       "certificate is %r" % (claimed, collector))
        payload["collector_id"] = collector

        decision = ingest.decide(payload, _BatchLookup(store))
        if decision.verdict is Verdict.REJECT:
            raise HTTPException(status_code=400, detail=decision.reason)

        if decision.gap is not None:
            store.write_gap(collector, decision.gap)
            return JSONResponse(status_code=202,
                                content={"status": "gap recorded"})

        if decision.verdict is Verdict.DUPLICATE:
            # Success, not an error: the collector may clear its queue.
            return JSONResponse(
                status_code=409,
                content={"status": "duplicate", "batch_id": decision.batch_id})

        store.write_batch(decision, payload.get("window") or {})
        return JSONResponse(
            status_code=202,
            content={"status": "accepted", "batch_id": decision.batch_id,
                     "records": len(decision.records)})

    @app.post("/api/v1/heartbeat")
    async def heartbeat(request: Request):
        collector = _identity(request)
        payload = await request.json()
        payload["collector_id"] = collector
        store.record_heartbeat(payload)
        return {"status": "ok"}

    # ── estate plane (operator role required) ─────────────────────────────
    @app.get("/api/v1/estate/collectors/{collector_id}/coverage")
    def coverage(collector_id: str, request: Request):
        _operator(request)
        summary = ingest.summarise_coverage(
            collector_id, store.recent_windows(collector_id),
            store.recent_gaps(collector_id))
        return {
            "collector_id": collector_id,
            "windows": summary.windows,
            "complete": summary.complete,
            "degraded": summary.degraded,
            "unknown": summary.unknown,
            "delivery_gaps": summary.gaps,
            "records_lost": summary.records_lost,
            "trustworthy": summary.trustworthy,
            "explain": summary.explain(),
        }

    @app.get("/api/v1/estate/assets")
    def assets(request: Request, collector_id: Optional[str] = None):
        _operator(request)
        latest = store.latest_window(collector_id) if collector_id else ""
        rows = store.assets(collector_id)
        out = []
        for row in rows:
            state = ingest.asset_state(row.get("last_observed_window", ""),
                                       latest)
            row = dict(row)
            # OTS-SRV-005: absence is a STATE, never a deletion.
            row["state"] = state.value
            out.append(row)
        return {"assets": out, "latest_window": latest, "count": len(out)}

    return app


class _BatchLookup:
    """`in` against the store's uniqueness check, so ingest.decide stays pure."""

    def __init__(self, store):
        self.store = store

    def __contains__(self, batch_id: str) -> bool:
        return self.store.has_batch(batch_id)
