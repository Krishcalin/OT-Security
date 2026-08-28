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
from . import comms as comms_module
from . import lifecycle as lifecycle_module
from . import containment as contain_module
from . import severity as severity_module
from . import enrolment, health as fleet_health, ingest
from . import packs as pack_module
from . import vulnmatch
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


def _flow_endpoints(flow) -> dict:
    """A CommFlow as the plain endpoints containment reasons over.

    Containment does not need the whole flow model and should not depend on it;
    it needs who talked to whom, over what.
    """
    return {"src_ip": getattr(flow, "src_ip", ""),
            "dst_ip": getattr(flow, "dst_ip", ""),
            "protocol": getattr(flow, "protocol", ""),
            "port": getattr(flow, "port", 0)}


def _isoformat(value) -> str:
    """Timestamps arrive as datetimes from PostgreSQL and as strings from a
    double. Both have to render, and neither should crash a listing."""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _utcnow():
    import datetime

    return datetime.datetime.now(datetime.timezone.utc)


def create_app(store, require_operator: Optional[Callable] = None,
               console_dir: Optional[str] = None, ca=None,
               local_auth: bool = False, signer=None):
    """Build the ASGI app. `store` is injected so the routes can be tested
    against a double without Postgres running.

    `console_dir` overrides where the operator console is served from;
    None means the repository's `console/`, and a deployment without one
    simply serves no static files.

    `ca` is the fleet certificate authority. Passing one turns on certificate
    enforcement for the ingest plane and opens the enrolment endpoints; passing
    None leaves both off, and the enrolment routes answer 503 rather than
    accepting requests they cannot complete.

    `signer` is the content signing key. Passing one opens the pack routes;
    without it they answer 503, because a server that cannot sign content
    must not distribute any — an unsigned pack is content a collector
    should refuse, and offering it would only teach the fleet to accept
    what it cannot check.

    `local_auth` mounts the built-in operator sign-in (OTS-SRV-006) and, unless
    `require_operator` was supplied, makes it the hook the estate plane
    authenticates against. It is an OPT-IN: a deployment fronted by its own
    identity provider injects `require_operator` and never creates a local
    operator, and a deployment that asks for neither still answers 503 on every
    estate route. Nothing here relaxes the fail-closed default; it fills it."""
    from fastapi import (Depends, FastAPI, Header, HTTPException, Request,
                         Response)
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

    def _signer():
        if signer is None:
            raise HTTPException(
                status_code=503,
                detail="no content signing key is configured, so this server "
                       "cannot publish or serve content packs. Distribution is "
                       "unavailable rather than unsigned.")
        return signer

    def _ca():
        if ca is None:
            raise HTTPException(
                status_code=503,
                detail="no fleet CA is configured, so this server cannot issue "
                       "or revoke collector identities. Enrolment is "
                       "unavailable rather than approximated.")
        return ca

    operator_hook = require_operator
    if local_auth:
        from . import authn_api

        authn_api.add_auth_routes(app, store)
        authn_api.bootstrap(store)
        if operator_hook is None:
            operator_hook = authn_api.local_operator(store)

    def _operator(request: Request) -> str:
        if operator_hook is None:
            raise HTTPException(
                status_code=503,
                detail="no operator authentication is configured; the estate "
                       "API is fail-closed until one is wired (OTS-SRV-006)")
        return operator_hook(request)

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
    def _read(*pages):
        """Whether these query results are the whole of what was stored.

        Every estate route reads through `all_assets`, `all_flows` or
        `all_detections`, each of which carries a LIMIT. Measured on a
        100-collector fleet at 120 devices per ring: 12,000 assets in the
        database, 5,000 returned, and nothing in the response to say so.

        The ordering makes it worse rather than better. Rows come back
        `last_seen DESC`, so truncation discards the LEAST recently seen first
        — and on a distribution network the quietest device is an FRTU on a
        ring main unit that only transmits on a fault. The rows dropped first
        are the ones most worth having.

        Coverage already travels with every count, because a count without it
        is a lie about the network. This is the same lie about the QUERY, so it
        travels the same way: in the response, never as a separate call
        somebody has to know to make.

        The pages are bound at their call sites with `:=` so the route can name
        them here without re-running the query.
        """
        notes = [page.explain() for page in pages
                 if page is not None and not getattr(page, "complete", True)]
        return {"complete": not notes,
                "explain": " ".join(notes) or "the whole estate was read"}

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

        # The correction that matters. `summarise_coverage` reads stored
        # windows and never asks when they arrived, so a collector that stopped
        # reporting still summarises as trustworthy off history. Silence is
        # folded in here, and it makes the estate untrustworthy — because a
        # site nobody is watching is not a site with nothing wrong.
        silent = fleet_health.assess(store.collectors_health()).unbelievable

        return {
            "collectors": cov.collectors,
            "trustworthy_collectors": cov.trustworthy_collectors,
            "blind_collectors": sorted(cov.blind_collectors),
            "degraded_collectors": sorted(cov.degraded_collectors),
            "collectors_with_gaps": sorted(cov.collectors_with_gaps),
            "silent_collectors": sorted(silent),
            "trustworthy": cov.trustworthy and not silent,
            "explain": cov.explain() + (
                ("; %d collector(s) have stopped reporting (%s) and their "
                 "stored coverage is no longer counted — a switched-off sensor "
                 "reads as a clean plant"
                 % (len(silent), ", ".join(sorted(silent)))) if silent else ""),
            "per_collector": [
                {"collector_id": s.collector_id, "windows": s.windows,
                 "complete": s.complete, "degraded": s.degraded,
                 "unknown": s.unknown, "delivery_gaps": s.gaps,
                 "records_lost": s.records_lost,
                 "trustworthy": s.trustworthy}
                for s in summaries],
        }

    @app.get("/api/v1/estate/health")
    def estate_health(request: Request):
        """Which collectors need somebody to go and look at them.

        Coverage answers what the windows that ARRIVED were worth. It has no
        notion of when they arrived, so a collector that stopped a week ago
        still summarises as trustworthy off fifty stored windows. This is the
        half that notices.
        """
        _operator(request)
        latest = store.latest_pack_version(pack_module.KIND_RULES)
        behind = {}
        if latest:
            for collector_id, version in store.reported_pack_versions().items():
                if version and int(version) < latest:
                    behind[collector_id] = latest - int(version)
        return fleet_health.assess(store.collectors_health(),
                                   behind=behind).to_dict()

    @app.get("/api/v1/estate/inventory")
    def estate_inventory(request: Request):
        """The merged asset inventory (OTS-SRV-001).

        IP identities are scoped to a site and MAC identities are global, so the
        same private address at two plants stays two devices. See estate.py for
        why merging them would be unrecoverable.
        """
        _operator(request)
        _ap = store.all_assets()
        assets = estate_merge.merge(_ap, store.collector_sites())
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
            "read": _read(_ap),
        }

    @app.get("/api/v1/estate/lifecycle")
    def estate_lifecycle(request: Request):
        """Whether each device is still supported, or honestly unknown.

        No lifecycle data ships with this product: vendor end-of-support dates
        cannot be verified from here, and a plausible-looking table of them
        would drive real replacement decisions. Records arrive as a `lifecycle`
        content pack an operator publishes, and the source travels with every
        record so a person reading the screen knows whose claim it is.
        """
        _operator(request)
        pack = store.latest_pack(pack_module.KIND_LIFECYCLE)
        records = lifecycle_module.load_records(
            (pack or {}).get("payload") if pack else None)
        _ap = store.all_assets()
        assets = [a.to_dict()
                  for a in estate_merge.merge(_ap, store.collector_sites())]
        results = lifecycle_module.assess_estate(assets, records)
        return {
            "devices": [r.to_dict() for r in results.values()],
            "summary": lifecycle_module.summarise(results, len(records)),
            "pack_version": int((pack or {}).get("version") or 0),
        }

    @app.get("/api/v1/estate/communications")
    def estate_communications(request: Request):
        """Who talks to whom, with both endpoints resolved.

        The evidence under half this console's conclusions, finally visible: a
        containment rule says "denying this would cut control communication
        happening today", and until now there was no way to look at the
        communication in question.
        """
        _operator(request)
        from . import zones as zone_derivation

        sites = store.collector_sites()
        _ap = store.all_assets()
        assets = [a.to_dict() for a in estate_merge.merge(_ap, sites)]
        flows = (_fp := store.all_flows())
        topologies = {str(getattr(t, "site", "")): t
                      for t in zone_derivation.derive(assets, flows, sites)}

        def lookup_for(site):
            topology = topologies.get(site)
            return lambda ip: contain_module.zone_of(ip, topology)

        summaries = [
            ingest.summarise_coverage(cid, store.recent_windows(cid),
                                      store.recent_gaps(cid))
            for cid in store.collector_ids()]
        cov = estate_merge.estate_coverage(summaries)
        silent = fleet_health.assess(store.collectors_health()).unbelievable

        items = comms_module.conversations(flows, assets, sites, lookup_for)
        return {
            "conversations": [c.to_dict() for c in items],
            "summary": comms_module.summarise(
                items, cov.explain(), cov.trustworthy and not silent),
        }

    @app.get("/api/v1/estate/vulnerabilities")
    def estate_vulnerabilities(request: Request):
        """CVE / KEV / EPSS matched server-side (OTS-SRV-002, decision D3).

        Computed from the CURRENT corpus over stored observations, so a KEV
        addition re-prioritises the estate without a collector being contacted.
        """
        _operator(request)
        corpus = vulnmatch.load_corpus()
        sites = store.collector_sites()
        assets = estate_merge.merge((_ap := store.all_assets()), sites)
        asset_dicts = [a.to_dict() for a in assets]
        matches = vulnmatch.match_estate(asset_dicts, corpus,
                                         vulnmatch.load_matcher())

        # The join. "Patch it" is advice an operator has already discounted
        # before they finish reading it — the device is a relay and the fix
        # needs an outage. So each finding carries the segmentation change that
        # would contain it instead, built from that site's derived zones and
        # the traffic actually observed reaching the device.
        #
        # Both halves already existed and had never been introduced.
        from . import zones as zone_derivation

        flows = (_fp := store.all_flows())
        topologies = zone_derivation.derive(asset_dicts, flows, sites)
        flows_by_site = {}
        for flow in flows:
            site = sites.get(str(flow.get("collector_id") or ""), "") or ""
            flows_by_site.setdefault(site, []).append(
                _flow_endpoints(zone_derivation.rehydrate_flow(flow)))

        match_dicts = [m.to_dict() for m in matches]
        containments = contain_module.contain_estate(
            match_dicts, asset_dicts, topologies, flows_by_site)

        # And the same two inputs, asked the other question: not what it would
        # take to stop this traffic, but what the traffic means for how urgent
        # the finding is. A correction that would LOWER urgency is withheld
        # when the window behind it cannot carry the claim — see severity.py.
        by_site_topology = {str(getattr(t, "site", "")): t
                            for t in topologies}
        by_id = {str(a.get("estate_id") or ""): a for a in asset_dicts}
        corrections = []
        for match in match_dicts:
            found = containments.get(str(match.get("estate_id") or ""))
            match["containment"] = found.to_dict() if found else None

            asset = by_id.get(str(match.get("estate_id") or ""))
            if asset is None or not (match.get("hits") or []):
                continue
            topology = by_site_topology.get(str(asset.get("site") or ""))
            ip = str(asset.get("ip") or "")
            zone, basis = contain_module.zone_of(ip, topology)
            inbound = contain_module.inbound_for(
                ip, topology, flows_by_site.get(str(asset.get("site") or ""))
                or [])
            position = severity_module.position_from(asset, zone, basis,
                                                     inbound)
            for hit in match["hits"]:
                correction = severity_module.correct(hit, position)
                hit["corrected_priority"] = correction.corrected
                hit["correction"] = correction.to_dict()
                corrections.append(correction)

        return {
            "corpus_version": corpus.version,
            "corpus_loaded": corpus.available,
            # Without a corpus every asset is UNKNOWN, never clean — a server
            # that has not looked has not established anything.
            "assessed": len(matches),
            "actionable": sum(1 for m in matches if m.actionable),
            "matches": match_dicts,
            "containment": contain_module.summarise(containments),
            "correction": severity_module.summarise(corrections),
            "read": _read(_ap, _fp),
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
        assets = estate_merge.merge((_ap := store.all_assets()), sites)

        # Stored detections carry the COLLECTOR's asset key; the engines look
        # them up by estate_id. Handing them over unchanged attaches nothing and
        # every asset reads as detection-free — a clean estate, produced by a
        # wiring fault. See estate.reattach_detections.
        raw = (_dp := store.all_detections())
        detections = estate_merge.reattach_detections(assets, raw)

        summaries = [
            ingest.summarise_coverage(cid, store.recent_windows(cid),
                                      store.recent_gaps(cid))
            for cid in store.collector_ids()]
        cov = estate_merge.estate_coverage(summaries)

        report = engines.run_all([a.to_dict() for a in assets], detections,
                                 (_fp := store.all_flows()),
                                 coverage_explain=cov.explain(), sites=sites)
        body = report.to_dict()
        # A detection whose asset row never arrived is a hole in the inventory,
        # not a rounding error: the estate has findings for a device it cannot
        # show. Reported rather than quietly dropped.
        body["orphaned_detections"] = len(raw) - len(detections)
        body["read"] = _read(_ap, _fp, _dp)
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
        assets = estate_merge.merge((_ap := store.all_assets()), sites)
        topologies = zone_derivation.derive([a.to_dict() for a in assets],
                                            (_fp := store.all_flows()), sites)
        confidence = zone_derivation.overall_confidence(topologies)
        return {
            "sites": [t.to_dict() for t in topologies],
            "zones": confidence.zones,
            "defaulted": confidence.defaulted,
            "usable": confidence.usable,
            "explain": confidence.explain(),
            "state": ("none" if confidence.zones == 0
                      else "derived" if confidence.usable else "rejected"),
            "read": _read(_ap, _fp),
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
            # Both anchors in one exchange. The CA proves who the SERVER is;
            # this proves what the CONTENT is, and they are separate keys on
            # purpose. A collector that had to fetch the content key later would
            # be fetching it over a channel it could not yet verify content on.
            "content_key": signer.public_key_pem if signer is not None else "",
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

    # -- content packs (Phase 6) -------------------------------------------
    #
    # `rules` packs are the only kind that reach a collector. The CVE corpus
    # stays on the server under decision D3, which is why refreshing it needs no
    # fleet involvement at all -- half of the two-cadence split comes free.

    @app.get("/api/v1/packs/key")
    def content_key():
        """The public key packs are verified against.

        Unauthenticated for the same reason `/api/v1/ca` is: a verification key
        is useless to an attacker, and a collector needs it before it can check
        anything at all. It is written at enrolment; this route is how a
        collector recovers it without re-enrolling.
        """
        return {"public_key": _signer().public_key_pem, "algorithm": "Ed25519"}

    @app.get("/api/v1/packs/latest")
    def latest_pack(request: Request, kind: str = "rules", have: int = 0):
        """The newest pack, for a collector that already holds `have`.

        204 when there is nothing newer, so an up-to-date fleet costs one empty
        response per cycle rather than a full pack. 404 when nothing has been
        published at all, which is a different state and says so.
        """
        _identity(request)
        if kind != pack_module.KIND_RULES:
            # The corpus never leaves the server. A collector asking for it is
            # misconfigured or probing; either way the answer is no.
            raise HTTPException(
                status_code=403,
                detail="only 'rules' packs are distributed to collectors; the "
                       "vulnerability corpus stays on the server (D3)")
        _signer()
        pack = store.latest_pack(kind)
        if pack is None:
            raise HTTPException(status_code=404,
                                detail="no rules pack has been published")
        if int(pack["version"]) <= int(have or 0):
            return Response(status_code=204)
        return {"kind": pack["kind"], "version": int(pack["version"]),
                "created_at": _isoformat(pack["created_at"]),
                "payload": pack["payload"], "signature": pack["signature"],
                "digest": pack["digest"]}

    @app.post("/api/v1/estate/packs")
    async def publish_pack(request: Request):
        """Sign and publish a pack.

        The server signs it HERE rather than accepting a signature from the
        caller. A route that took a pre-signed pack would accept whatever the
        holder of any key produced, and the whole point of the key living on
        this server is that this server decides what the fleet runs.
        """
        operator = _operator(request)
        authority = _signer()
        body = await _body(request)

        kind = str(body.get("kind") or pack_module.KIND_RULES)
        payload = body.get("payload")
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400,
                                detail="a pack needs a payload object")

        # Monotonic, and chosen here rather than by the caller: a caller picking
        # its own version could publish one the fleet refuses as a rollback, or
        # collide with a version already issued and make "which content produced
        # this finding" unanswerable.
        version = store.latest_pack_version(kind) + 1
        try:
            pack = authority.sign(kind, version, payload)
        except pack_module.PackError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        store.publish_pack(pack, published_by=operator)
        return JSONResponse(status_code=201, content={
            "kind": pack.kind, "version": pack.version, "digest": pack.digest,
            "summary": pack_module.describe(pack),
            "detail": "collectors apply this on their next check; the fleet "
                      "view shows which are still behind"})

    @app.get("/api/v1/estate/packs")
    def list_packs(request: Request):
        """Published packs, and which collectors are still behind.

        Refusing a bad pack keeps a collector safe and leaves it running old
        content. Safe and stale has to be VISIBLE, or the fleet quietly stops
        detecting things nobody removed.
        """
        _operator(request)
        rows = store.packs()
        drift = pack_module.fleet_drift(
            store.latest_pack_version(pack_module.KIND_RULES),
            store.reported_pack_versions())
        return {
            "packs": [{"kind": row["kind"], "version": row["version"],
                       "created_at": _isoformat(row["created_at"]),
                       "digest": row["digest"],
                       "published_by": row["published_by"],
                       "summary": pack_module.describe(
                           pack_module.SignedPack(
                               kind=row["kind"], version=row["version"],
                               created_at="", payload=row["payload"]))}
                      for row in rows],
            "signing_configured": signer is not None,
            "drift": {"latest": drift.latest, "current": drift.current,
                      "behind": drift.behind, "unknown": drift.unknown,
                      "all_current": drift.all_current,
                      "explain": drift.explain()},
        }

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
    elif not console_dir:
        # An explicit empty string is "serve no console". Without this, None
        # meant the repository default and there was no way to ask for a
        # server-only deployment — and the catch-all static mount answered 405
        # to any POST that did not match a route, which reads as a routing bug.
        return
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
