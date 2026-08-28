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
# NOTE: deliberately no `from __future__ import annotations` here.
#
# FastAPI resolves route annotations to decide what is a path/query parameter
# and what is injected. With postponed evaluation the annotations are strings,
# and `Request` is imported inside create_app() so it is not resolvable at
# module scope — FastAPI then treats `request: Request` as a QUERY PARAMETER and
# every route answers 422 Field required. It looks like a routing bug and is an
# annotation-resolution one.
#
# The lazy fastapi import is kept on purpose: collector_identity() and the
# module's constants stay importable, and testable, without the framework.

import os
from typing import Any, Callable, Dict, List, Optional

from . import estate as estate_merge
from . import ingest, vulnmatch
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


def create_app(store, require_operator: Optional[Callable] = None,
               console_dir: Optional[str] = None):
    """Build the ASGI app. `store` is injected so the routes can be tested
    against a double without Postgres running.

    `console_dir` overrides where the operator console is served from;
    None means the repository's `console/`, and a deployment without one
    simply serves no static files."""
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

    @app.get("/api/v1/estate/coverage")
    def estate_coverage(request: Request):
        """What the estate view as a whole is worth (OTS-SRV-004).

        The weakest link, not an average. Four healthy collectors and one blind
        one is not 80% trustworthy — it is an answer with a hole in it, and the
        hole is exactly where nobody is looking.
        """
        _operator(request)
        summaries = [
            ingest.summarise_coverage(cid, store.recent_windows(cid),
                                      store.recent_gaps(cid))
            for cid in store.collector_ids()]
        cov = estate_merge.estate_coverage(summaries)
        return {
            "collectors": cov.collectors,
            "trustworthy_collectors": cov.trustworthy_collectors,
            "blind_collectors": sorted(cov.blind_collectors),
            "degraded_collectors": sorted(cov.degraded_collectors),
            "collectors_with_gaps": sorted(cov.collectors_with_gaps),
            "trustworthy": cov.trustworthy,
            "explain": cov.explain(),
            "per_collector": [
                {"collector_id": s.collector_id, "windows": s.windows,
                 "complete": s.complete, "degraded": s.degraded,
                 "unknown": s.unknown, "delivery_gaps": s.gaps,
                 "records_lost": s.records_lost,
                 "trustworthy": s.trustworthy}
                for s in summaries],
        }

    @app.get("/api/v1/estate/inventory")
    def estate_inventory(request: Request):
        """The merged asset inventory (OTS-SRV-001).

        IP identities are scoped to a site and MAC identities are global, so the
        same private address at two plants stays two devices. See estate.py for
        why merging them would be unrecoverable.
        """
        _operator(request)
        assets = estate_merge.merge(store.all_assets(), store.collector_sites())
        summaries = [
            ingest.summarise_coverage(cid, store.recent_windows(cid),
                                      store.recent_gaps(cid))
            for cid in store.collector_ids()]
        cov = estate_merge.estate_coverage(summaries)
        return {
            "assets": [a.to_dict() for a in assets],
            "count": len(assets),
            # The count means nothing without this, so it is not a separate call.
            "coverage": {"trustworthy": cov.trustworthy,
                         "explain": cov.explain()},
        }

    @app.get("/api/v1/estate/vulnerabilities")
    def estate_vulnerabilities(request: Request):
        """CVE / KEV / EPSS matched server-side (OTS-SRV-002, decision D3).

        Computed from the CURRENT corpus over stored observations, so a KEV
        addition re-prioritises the estate without a collector being contacted.
        """
        _operator(request)
        corpus = vulnmatch.load_corpus()
        assets = estate_merge.merge(store.all_assets(), store.collector_sites())
        matches = vulnmatch.match_estate([a.to_dict() for a in assets], corpus)
        return {
            "corpus_version": corpus.version,
            "corpus_loaded": corpus.available,
            # Without a corpus every asset is UNKNOWN, never clean — a server
            # that has not looked has not established anything.
            "assessed": len(matches),
            "actionable": sum(1 for m in matches if m.actionable),
            "matches": [m.to_dict() for m in matches],
        }

    @app.get("/api/v1/estate/analysis")
    def estate_analysis(request: Request):
        """The five server-side engines over the merged estate (OTS-SRV-003).

        Every result names what it could not consider, and an engine without its
        required inputs is SKIPPED with a reason rather than run on nothing —
        drift without a baseline would answer *nothing changed*, which is the
        most confident wrong answer available.
        """
        _operator(request)
        from . import analysis as engines

        sites = store.collector_sites()
        assets = estate_merge.merge(store.all_assets(), sites)

        # Stored detections carry the COLLECTOR's asset key; the engines look
        # them up by estate_id. Handing them over unchanged attaches nothing and
        # every asset reads as detection-free — a clean estate, produced by a
        # wiring fault. See estate.reattach_detections.
        raw = store.all_detections()
        detections = estate_merge.reattach_detections(assets, raw)

        summaries = [
            ingest.summarise_coverage(cid, store.recent_windows(cid),
                                      store.recent_gaps(cid))
            for cid in store.collector_ids()]
        cov = estate_merge.estate_coverage(summaries)

        report = engines.run_all([a.to_dict() for a in assets], detections,
                                 store.all_flows(),
                                 coverage_explain=cov.explain(), sites=sites)
        body = report.to_dict()
        # A detection whose asset row never arrived is a hole in the inventory,
        # not a rounding error: the estate has findings for a device it cannot
        # show. Reported rather than quietly dropped.
        body["orphaned_detections"] = len(raw) - len(detections)
        return body

    @app.get("/api/v1/estate/zones")
    def estate_zones(request: Request):
        """Purdue zones, derived per site, with how each level was arrived at
        (decision D6, unblocks OTS-CON-005).

        `state` is the field that matters. "none" and "rejected" both leave the
        topology view empty, and they are not the same thing: one says the
        estate had nothing to derive from, the other says a derivation was made
        and was not trusted enough to draw. Collapsing them would let a guessed
        segmentation be read as an observed one.
        """
        _operator(request)
        from . import zones as zone_derivation

        sites = store.collector_sites()
        assets = estate_merge.merge(store.all_assets(), sites)
        topologies = zone_derivation.derive([a.to_dict() for a in assets],
                                            store.all_flows(), sites)
        confidence = zone_derivation.overall_confidence(topologies)
        return {
            "sites": [t.to_dict() for t in topologies],
            "zones": confidence.zones,
            "defaulted": confidence.defaulted,
            "usable": confidence.usable,
            "explain": confidence.explain(),
            "state": ("none" if confidence.zones == 0
                      else "derived" if confidence.usable else "rejected"),
        }

    _mount_console(app, console_dir)
    return app


def _mount_console(app, console_dir: Optional[str]) -> None:
    """Serve the operator console as static files from this same app.

    Same origin on purpose: the console client sends `credentials:
    "same-origin"` and takes no API base URL, so there is one deployable and no
    CORS relaxation of the estate plane to make a second one reachable.

    The shell is unauthenticated and that is deliberate — it contains no estate
    data. Every figure it shows comes from `/api/v1/estate/*`, which is
    fail-closed, so an unauthorised visitor gets the frame and a 503 in place of
    every number rather than an empty page that reads as an empty plant.

    Only `public/` and `dist/` are mounted. `src/` and `node_modules/` stay
    unreachable: serving the tree wholesale would publish the source and its
    dependencies to anyone who can reach the port.
    """
    if console_dir is None:
        console_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "console")
    public = os.path.join(console_dir, "public")
    dist = os.path.join(console_dir, "dist")
    if not os.path.isdir(public):
        return                     # server-only deployment; the API still runs

    from fastapi.staticfiles import StaticFiles

    if os.path.isdir(dist):
        app.mount("/dist", StaticFiles(directory=dist), name="console-dist")
    # Mounted last so every API route is matched first.
    app.mount("/", StaticFiles(directory=public, html=True), name="console")


class _BatchLookup:
    """`in` against the store's uniqueness check, so ingest.decide stays pure."""

    def __init__(self, store):
        self.store = store

    def __contains__(self, batch_id: str) -> bool:
        return self.store.has_batch(batch_id)
