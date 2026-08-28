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

AND, ONCE A CA IS CONFIGURED, FROM THE ISSUANCE RECORD
──────────────────────────────────────────────────────
A subject alone cannot be revoked. Nothing in `CN=pi-substation-01` changes when
an operator revokes that collector's certificate, so a server that authenticates
on the name keeps accepting the revoked holder — while the console shows the
certificate as revoked. Revocation that does not deny is worse than no
revocation at all, because it is believed.

So where a fleet CA is configured, the terminator must also pass the client
certificate's SHA-256 fingerprint (`X-Client-Fingerprint`), and the server looks
it up in `certificate`: unknown, revoked, expired, or naming a different
collector than the subject are each a refusal, each with its own reason. The
identity returned is the one on the issuance record, not the one parsed out of
the subject line.

Deployments with no CA configured fall back to the subject alone. That is the
pre-enrolment state, and it is a state in which revocation does not exist — the
enrolment endpoints say so with a 503 rather than pretending otherwise.

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

import json
import os
from typing import Any, Callable, Dict, List, Optional

from . import estate as estate_merge
from . import enrolment, ingest, vulnmatch
from .ingest import Decision, Verdict

COLLECTOR_ID_HEADER = "X-Collector-Id"
CLIENT_SUBJECT_HEADER = "X-Client-Subject"      # set by the TLS terminator
CLIENT_FINGERPRINT_HEADER = "X-Client-Fingerprint"   # likewise, sha256
#: The verified client certificate itself, PEM, URL-escaped.
#:
#: nginx has no SHA-256 fingerprint variable — `$ssl_client_fingerprint` is
#: SHA-1, and nothing in stock nginx will produce the digest this server
#: records. That was found by writing the config rather than by designing it.
#:
#: Passing the certificate instead is the better answer anyway: the server
#: computes the digest itself from the certificate the terminator actually
#: verified, so it depends on the terminator for one thing (that the
#: certificate was validated against the fleet CA) rather than two (that, plus
#: agreeing about which hash to use).
CLIENT_CERT_HEADER = "X-Client-Cert"


class AuthError(RuntimeError):
    pass


def header_values(headers, name: str) -> List[str]:
    """Every value for a header, not just the first.

    `Headers.get()` returns the FIRST occurrence, and a plain dict of headers
    keeps only one. Both hide the case this function exists for.
    """
    getlist = getattr(headers, "getlist", None)
    if getlist is not None:
        return [value for value in getlist(name) if value]
    value = headers.get(name) or headers.get(name.lower())
    return [value] if value else []


def single_header(headers, name: str) -> str:
    """One value for an identity header, or a refusal.

    A REPEATED identity header is a refusal, and this is the sharp edge of the
    whole terminator contract.

    The deployment rule is that the TLS terminator strips client-supplied
    identity headers before setting its own. That rule is one directive word
    away from being broken — HAProxy's `add-header` instead of `set-header`,
    a missing `proxy_set_header` in nginx — and when it breaks the request
    carries the header TWICE: the client's copy first, because it was already
    in the request, and the terminator's after it. `Headers.get()` then returns
    the client's, and the caller authenticates as whoever it said it was.

    Nothing downstream looks wrong. The certificate was real, the request was
    ordinary, and the inventory it poisons belongs to another plant.

    So the server does not rely on the terminator getting it right. Two values
    is not a value: it is a misconfiguration, and it fails loudly here instead
    of silently naming the caller.
    """
    values = header_values(headers, name)
    if len(values) > 1:
        raise AuthError(
            "%s appeared %d times in this request. The TLS terminator must "
            "STRIP a client-supplied copy before setting its own; appending "
            "leaves the caller's value in front of it, and the caller then "
            "names itself. Refusing rather than picking one."
            % (name, len(values)))
    return values[0] if values else ""


def collector_identity(headers, trust_header: bool = True) -> str:
    """Which collector this request is from.

    Taken from the verified client certificate subject, not the payload. The
    body is data the caller controls; the certificate is what mTLS established.
    """
    subject = single_header(headers, CLIENT_SUBJECT_HEADER)
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


def client_fingerprint(headers) -> str:
    """The presented certificate's fingerprint.

    Two ways in, because terminators differ:

    `X-Client-Cert` — the certificate itself, URL-escaped PEM. Preferred, and
    the only option on stock nginx, whose `$ssl_client_fingerprint` is SHA-1.
    The digest is computed here from the certificate the terminator verified.

    `X-Client-Fingerprint` — a SHA-256 the terminator computed (HAProxy's
    `ssl_c_der,sha2(256),hex`, Envoy's `%DOWNSTREAM_PEER_FINGERPRINT_256%`).
    Normalised, because they disagree about the shape: `SHA256:` prefixes,
    colons, case. A deployment whose format simply failed to match would look
    exactly like a fleet that had never enrolled, and would be debugged as one.

    The certificate wins when both are present. It is the stronger evidence,
    and a disagreement between them is a terminator wiring two different
    certificates into one request — which `authenticate_collector` refuses.
    """
    from . import ca as fleet_ca

    escaped = single_header(headers, CLIENT_CERT_HEADER)
    if escaped:
        try:
            return fleet_ca.fingerprint_of_escaped_pem(escaped)
        except Exception as exc:                           # noqa: BLE001
            raise AuthError(
                "the client certificate passed by the terminator could not be "
                "read (%s). It is not decodeable PEM." % type(exc).__name__)
    return fleet_ca.normalise_fingerprint(
        single_header(headers, CLIENT_FINGERPRINT_HEADER))


def authenticate_collector(store, headers,
                           enforce_certificate: bool) -> str:
    """Which collector this request is from, checked against what was issued.

    Every refusal names its own cause. "We do not know this certificate" and
    "we revoked this certificate" are different events for whoever reads the
    log, and collapsing them into one 401 loses the only signal that says
    somebody is still using a credential that was taken away.
    """
    subject_id = collector_identity(headers)
    if not enforce_certificate:
        return subject_id

    fingerprint = client_fingerprint(headers)
    if not fingerprint:
        raise AuthError(
            "a fleet CA is configured but this request identified no client "
            "certificate. The TLS terminator must pass %s (the verified "
            "certificate, URL-escaped PEM) or %s (its SHA-256); without one of "
            "them nothing can be checked against the issuance record and "
            "revocation would not deny anything."
            % (CLIENT_CERT_HEADER, CLIENT_FINGERPRINT_HEADER))

    record = store.certificate_by_fingerprint(fingerprint)
    if record is None:
        raise AuthError(
            "this client certificate was not issued by this server. It may be "
            "signed by a CA the terminator trusts, but it is not in the fleet "
            "issuance record, so there is nothing to revoke it by and no "
            "operator authorised it.")
    if record.get("revoked_at") is not None:
        raise AuthError(
            "this certificate was revoked (%s). It is still cryptographically "
            "valid, which is exactly why the check is against the issuance "
            "record rather than the signature."
            % (record.get("revocation_reason") or "no reason recorded"))

    not_after = record.get("not_after")
    if not_after is not None and not_after <= _utcnow():
        raise AuthError(
            "this certificate expired on %s; re-enrol rather than renewing, so "
            "a person sees a device nobody has heard from since then."
            % not_after.isoformat())

    if record["collector_id"] != subject_id:
        # The terminator is wiring two different certificates into one request,
        # or somebody is presenting one certificate and claiming another's name.
        raise AuthError(
            "the presented certificate was issued to %r but the subject header "
            "says %r" % (record["collector_id"], subject_id))
    return record["collector_id"]


def _utcnow():
    import datetime

    return datetime.datetime.now(datetime.timezone.utc)


def create_app(store, require_operator: Optional[Callable] = None,
               console_dir: Optional[str] = None, ca=None):
    """Build the ASGI app. `store` is injected so the routes can be tested
    against a double without Postgres running.

    `console_dir` overrides where the operator console is served from;
    None means the repository's `console/`, and a deployment without one
    simply serves no static files.

    `ca` is the fleet certificate authority. Passing one turns on certificate
    enforcement for the ingest plane and opens the enrolment endpoints; passing
    None leaves both off, and the enrolment routes answer 503 rather than
    accepting requests they cannot complete."""
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(title="OT Sensor Fleet", version="0.1.0")

    def _identity(request: Request) -> str:
        try:
            # request.headers, NOT dict(request.headers): building a dict
            # collapses a repeated header down to one value and throws away
            # the evidence that it was repeated.
            return authenticate_collector(store, request.headers,
                                          enforce_certificate=ca is not None)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

    async def _body(request: Request, allow_empty: bool = False) -> Dict:
        """The request body, or a 400.

        `await request.json()` raises on malformed input, which reaches the
        client as a 500 — and a 500 says the server is broken when the truth is
        that the request was. On `/api/v1/enrol`, the one route reachable
        without a client certificate, that is also the wrong thing to tell an
        unauthenticated caller about their own mistake.

        `allow_empty` is for routes whose fields are all optional. NO body and
        MALFORMED body are still different: swallowing a malformed one would
        hand an operator the defaults for a request they thought they had
        parameterised — a 24-hour token for someone who asked for one hour and
        mistyped the JSON around it.
        """
        raw = await request.body()
        if not raw.strip():
            if allow_empty:
                return {}
            raise HTTPException(status_code=400,
                                detail="this request needs a JSON body")
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:                                  # noqa: BLE001
            raise HTTPException(status_code=400,
                                detail="the request body is not valid JSON")
        if not isinstance(body, dict):
            raise HTTPException(
                status_code=400,
                detail="the request body must be a JSON object")
        return body

    def _ca():
        if ca is None:
            raise HTTPException(
                status_code=503,
                detail="no fleet CA is configured, so this server cannot issue "
                       "or revoke collector identities. Enrolment is "
                       "unavailable rather than approximated.")
        return ca

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
        payload = await _body(request)

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
        payload = await _body(request)
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

    # ── enrolment plane (Phase 6) ─────────────────────────────────────────
    #
    # `/api/v1/enrol` is the ONLY route in this server not behind mutual TLS,
    # and it cannot be otherwise: a collector arriving at a substation has no
    # certificate yet, which is the whole reason it is here. A one-time token
    # stands in front of it.
    @app.get("/api/v1/ca")
    def public_ca():
        """The fleet CA certificate, unauthenticated.

        A CA certificate is public by construction — it is the trust anchor
        every party needs before it can verify anything, and it travels in the
        clear in every TLS handshake. Serving it here is what lets a collector
        check the fingerprint an operator gave it BEFORE spending its one-time
        token.

        That ordering was not obvious until the flow was run end to end: with
        the check on the response instead, a mistyped fingerprint spent the
        token, left an issued certificate nobody holds, and blocked the next
        legitimate enrolment of that collector with "it already has one". The
        token is the scarce thing here, so it is offered last.
        """
        return {"ca_certificate": _ca().ca_pem}

    @app.post("/api/v1/enrol")
    async def enrol(request: Request):
        authority = _ca()
        payload = await _body(request)
        token = str(payload.get("token") or "")
        csr = str(payload.get("csr") or "")
        if not token or not csr:
            raise HTTPException(status_code=400,
                                detail="enrolment needs a token and a CSR")

        claim = store.redeem_enrolment_token(enrolment.hash_token(token))
        if claim is None:
            # One message for unknown, expired and already-redeemed. This is the
            # one place in this server that deliberately does NOT distinguish
            # its refusals: the caller is unauthenticated, and telling them
            # which tokens exist would turn this into an oracle.
            raise HTTPException(
                status_code=403,
                detail="this enrolment token is not valid. It may never have "
                       "existed, it may have expired, or it may already have "
                       "been redeemed — each is final.")

        # From here on the token is CLAIMED but not yet SPENT. Anything that
        # ends without a certificate releases it again: a one-time credential
        # consumed by a request that produced nothing sends the engineer at the
        # cabinet back to an operator for another one, and a malformed CSR is
        # the likeliest thing to go wrong in the field.
        token_hash = enrolment.hash_token(token)
        collector_id = claim["collector_id"]

        active = [c["serial"] for c in store.active_certificates(collector_id)]
        decision = enrolment.decide_issue(active, claim["allow_reissue"])
        if not decision.ok:
            store.release_enrolment_token(token_hash)
            raise HTTPException(status_code=409, detail=decision.reason)

        try:
            issued = authority.sign(csr, collector_id, claim["site"])
        except Exception as exc:                           # noqa: BLE001
            store.release_enrolment_token(token_hash)
            raise HTTPException(status_code=400, detail=str(exc))

        for serial in decision.supersede:
            store.revoke_certificate(
                serial, "superseded by %s at re-enrolment" % issued.serial)

        store.ensure_collector(collector_id)
        if claim["site"]:
            store.set_site(collector_id, claim["site"])
        store.record_certificate(issued)
        # Spent, now and permanently: `release_enrolment_token` refuses to
        # un-claim a token once this is set.
        store.record_token_serial(token_hash, issued.serial)

        return JSONResponse(status_code=201, content={
            "collector_id": collector_id,
            "site": claim["site"],
            "certificate": issued.pem,
            "ca_certificate": authority.ca_pem,
            "serial": issued.serial,
            "not_after": issued.not_after.isoformat(),
            "note": decision.reason,
        })

    @app.post("/api/v1/renew")
    async def renew(request: Request):
        """Exchange a valid certificate for a fresh one.

        Authenticated by the certificate being renewed, so no token is needed —
        the holder has already proven it is the collector. A renewal does NOT
        revoke the old certificate: if the response never reaches the Pi, a
        collector that had just invalidated its only identity would be
        unreachable in a substation, and recovering it means a site visit. The
        old one lapses on its own schedule instead.
        """
        authority = _ca()
        collector = _identity(request)
        payload = await _body(request)
        csr = str(payload.get("csr") or "")
        if not csr:
            raise HTTPException(status_code=400, detail="renewal needs a CSR")

        current = store.certificate_by_fingerprint(
            client_fingerprint(request.headers))
        if current is None:                                # pragma: no cover
            raise HTTPException(status_code=401,
                                detail="no issuance record for this certificate")
        decision = enrolment.decide_renewal(
            current["not_after"], current.get("revoked_at") is not None)
        if not decision.ok:
            raise HTTPException(status_code=409, detail=decision.reason)

        sites = store.collector_sites()
        try:
            issued = authority.sign(csr, collector, sites.get(collector, ""))
        except Exception as exc:                           # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc))
        store.record_certificate(issued)

        # The overlap is deliberate but must be BOUNDED. Renewing repeatedly
        # would otherwise leave a collector holding five, ten, twenty valid
        # identities, and "one identity, one holder" — the rule the enrolment
        # path refuses to break — would be undone one renewal at a time by the
        # path that does not go through it. Every active certificate except the
        # one just renewed from, and the one just issued, is retired here.
        retired = []
        for row in store.active_certificates(collector):
            if row["serial"] in (issued.serial, current["serial"]):
                continue
            if store.revoke_certificate(
                    row["serial"], "retired: superseded by two later renewals"):
                retired.append(row["serial"])

        return JSONResponse(status_code=201, content={
            "collector_id": collector,
            "certificate": issued.pem,
            "ca_certificate": authority.ca_pem,
            "serial": issued.serial,
            "not_after": issued.not_after.isoformat(),
            "superseded": current["serial"],
            "retired": retired,
            "note": "the previous certificate stays valid until it expires, so "
                    "a lost response does not strand a collector"
                    + (issued.note and "; " + issued.note),
        })

    # ── certificate lifecycle, operator side ──────────────────────────────

    @app.post("/api/v1/estate/collectors/{collector_id}/enrolment-token")
    async def mint_token(collector_id: str, request: Request):
        """Mint a one-time enrolment token.

        The plaintext is returned HERE AND NOWHERE ELSE. Only its hash is
        stored, so it cannot be recovered from the database or shown again on a
        later screen; a token an operator can look up twice is a token that
        lives in the system as a standing credential.
        """
        _operator(request)
        _ca()
        payload = await _body(request, allow_empty=True)
        # `payload.get("ttl_hours") or DEFAULT` would read an explicit 0 as
        # "not supplied" and quietly mint a 24-hour token for an operator who
        # asked for none. A refusal they can see beats a default they cannot.
        ttl = payload.get("ttl_hours")
        try:
            minted = enrolment.mint(
                collector_id,
                site=str(payload.get("site") or ""),
                ttl_hours=(int(ttl) if ttl is not None
                           else enrolment.DEFAULT_TOKEN_TTL_HOURS),
                allow_reissue=bool(payload.get("allow_reissue")))
        except (enrolment.EnrolmentError, ValueError, TypeError) as exc:
            # A rejected mint is the operator's mistake to see, not a server
            # fault: a 500 here reads as "the fleet server is broken" when the
            # actual problem is a ttl of "soon".
            raise HTTPException(status_code=400, detail=str(exc))
        store.create_enrolment_token(minted)
        return JSONResponse(status_code=201, content={
            "collector_id": minted.collector_id,
            "site": minted.site,
            "token": minted.token,
            "expires_at": minted.expires_at.isoformat(),
            "allow_reissue": minted.allow_reissue,
            "note": "this token is shown once and stored only as a hash",
        })

    @app.get("/api/v1/estate/certificates")
    def list_certificates(request: Request, collector_id: Optional[str] = None):
        """Every certificate ever issued, including revoked and expired ones.

        Not filtered to the valid ones: "no record" and "never issued" would
        otherwise be the same answer, and the question an operator asks after an
        incident is what this fleet has held, not what it holds now.
        """
        _operator(request)
        rows = store.certificates(collector_id)
        now = _utcnow()
        out = []
        for row in rows:
            expired = row["not_after"] <= now
            revoked = row.get("revoked_at") is not None
            out.append({
                "serial": row["serial"],
                "collector_id": row["collector_id"],
                "subject": row["subject"],
                "fingerprint": row["fingerprint"],
                "not_before": row["not_before"].isoformat(),
                "not_after": row["not_after"].isoformat(),
                "revoked": revoked,
                "revocation_reason": row["revocation_reason"],
                "state": ("revoked" if revoked
                          else "expired" if expired else "valid"),
                "expiring_soon": (not revoked and not expired
                                  and enrolment.expiring_within(
                                      row["not_after"], 14, now)),
            })
        return {"certificates": out, "count": len(out),
                "ca_configured": ca is not None}

    @app.post("/api/v1/estate/certificates/{serial}/revoke")
    async def revoke(serial: str, request: Request):
        _operator(request)
        _ca()
        payload = await _body(request, allow_empty=True)
        reason = str(payload.get("reason") or "revoked by operator")
        changed = store.revoke_certificate(serial, reason)
        if not changed:
            # Either it does not exist or it was already revoked. Both mean the
            # operator's intent already holds, so this is not an error — but it
            # must not report a revocation that did not happen here.
            raise HTTPException(
                status_code=409,
                detail="no unrevoked certificate with serial %r; it is either "
                       "unknown or already revoked" % serial)
        return {"serial": serial, "revoked": True, "reason": reason}

    @app.get("/api/v1/estate/ca")
    def ca_certificate(request: Request):
        """The CA certificate, for building a collector's trust bundle."""
        _operator(request)
        return {"ca_certificate": _ca().ca_pem}

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
