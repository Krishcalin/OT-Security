"""
The operator sign-in routes (OTS-SRV-006).

`authn.py` owns the credential decisions and knows nothing about HTTP; this
turns them into routes and a cookie. Mounted only when a deployment asks for
local authentication — see `authn.py` for why that stays an explicit opt-in
rather than a default.

WHAT IS IN THE COOKIE
─────────────────────
A random token, and nothing else. Not the username, not a role, not an expiry
the browser could edit. Everything about the session is looked up server-side
from its SHA-256, so a session can be revoked by deleting one row — which is
what a password change does, and what disabling an account does.

A signed token carrying claims would save that lookup and would mean a revoked
operator keeps working until their token expires. In a console that fronts a
substation, "revoked but still working for another eleven hours" is not a
trade-off worth the round trip it saves.

WHY THE SECOND FACTOR CANNOT BE SKIPPED BY THE CLIENT
─────────────────────────────────────────────────────
`/auth/login` returns 401 with `second_factor_required` and NO cookie when a
code is needed. The browser cannot proceed by ignoring that, because there is
nothing to proceed with: the session does not exist until the code has been
verified. A design that issued a "half" session and asked the UI to finish the
job would be a complete login that merely looks unfinished.
"""
# NOTE: deliberately no `from __future__ import annotations`, for the same
# reason api.py says it there.
#
# FastAPI reads route annotations to decide what is a path parameter, a query
# parameter and what is injected. With postponed evaluation the annotations are
# strings, and `Request` is imported inside `add_auth_routes` so it is not
# resolvable at module scope — FastAPI then treats `request: Request` as a
# QUERY PARAMETER and every route here answers 422 Field required. It reads as
# a routing bug and is an annotation-resolution one, and it cost this file a
# round of confused test failures before the note in api.py was reread.

import time
from typing import Optional

from . import authn
from . import qr as qr_module
from . import totp as totp_module

COOKIE_NAME = "pnv_session"


def _cookie_secure(request) -> bool:
    """Whether to mark the cookie Secure.

    Behind the terminator this is always https and the answer is yes. On a
    developer machine over plain http, a Secure cookie is set by nothing and
    silently vanishes — the sign-in appears to succeed and the next request is
    anonymous, which is a confusing hour for whoever hits it. So it follows the
    scheme the request actually arrived on, including the terminator's
    X-Forwarded-Proto.
    """
    forwarded = (request.headers.get("x-forwarded-proto") or "").lower()
    if forwarded:
        return forwarded == "https"
    return request.url.scheme == "https"


def _session_token(request) -> str:
    return request.cookies.get(COOKIE_NAME) or ""


def local_operator(store):
    """A `require_operator` hook backed by the operator table.

    This is the built-in provider. A deployment fronted by its own identity
    provider injects a different one and never creates a local operator; the
    contract `create_app` documents is unchanged.
    """
    from fastapi import HTTPException

    def resolve(request) -> str:
        token = _session_token(request)
        if not token:
            raise HTTPException(status_code=401, detail="not signed in")
        session = store.session(authn.session_fingerprint(token))
        if session is None or session.get("status") != "active":
            raise HTTPException(status_code=401,
                                detail="this session is no longer valid")
        # Slide the idle timeout forward. Never past the absolute deadline —
        # the store clamps it, so an operator who never closes the tab still
        # signs in again eventually.
        store.touch_session(
            session["token_hash"],
            _stamp(time.time() + authn.SESSION_TTL_SECONDS))
        return session["username"]

    return resolve


def _stamp(value: float):
    import datetime

    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc)


def bootstrap(store) -> Optional[str]:
    """Create the first operator from the environment, once.

    Returns the username if one was created, None otherwise. Applied only
    against an EMPTY operator table: re-running with the variables still set
    cannot silently reset a password that has since been changed.
    """
    credentials = authn.bootstrap_credentials()
    if credentials is None:
        return None
    if store.operator_count() > 0:
        return None
    username, password = credentials
    store.create_operator(username, authn.hash_password(password),
                          display_name=username)
    return username


def add_auth_routes(app, store):
    """Mount `/api/v1/auth/*`."""
    from fastapi import Body, HTTPException, Request, Response
    from fastapi.responses import JSONResponse

    def _current(request: Request) -> Optional[dict]:
        token = _session_token(request)
        if not token:
            return None
        return store.session(authn.session_fingerprint(token))

    def _require(request: Request) -> dict:
        session = _current(request)
        if session is None or session.get("status") != "active":
            raise HTTPException(status_code=401, detail="not signed in")
        return session

    # ── sign in ───────────────────────────────────────────────────────────

    @app.post("/api/v1/auth/login")
    def login(request: Request, response: Response, body: dict = Body(...)):
        username = str(body.get("username") or "").strip().lower()
        password = str(body.get("password") or "")
        code = str(body.get("code") or "").strip()

        operator = store.operator(username) if username else None
        if operator is None:
            # Burn the same work an existing account would have cost. Returning
            # early makes "does this account exist" measurable on a stopwatch
            # even when the response is identical.
            authn.burn_verification_time()
            raise HTTPException(status_code=401,
                                detail="invalid username or password")

        state = store.totp_state(username) or {}
        outcome = authn.decide_login(
            operator["password_hash"], password, status=operator["status"],
            totp_secret=state.get("secret", ""),
            totp_enabled=bool(state.get("enabled")),
            totp_last_counter=int(state.get("last_counter", -1)),
            code=code,
            recovery_fingerprints=store.unused_recovery_fingerprints(username))

        if outcome.second_factor_required:
            # Safe to disclose: the password is already proven, so this tells
            # nothing to anyone who could not already sign in.
            return JSONResponse(
                status_code=401,
                content={"detail": "a second factor is required",
                         "second_factor_required": True})
        if not outcome.ok:
            raise HTTPException(status_code=401, detail=outcome.reason)

        if outcome.totp_counter >= 0:
            store.record_totp_counter(username, outcome.totp_counter)
        if outcome.recovery_used:
            if not store.spend_recovery_code(username, outcome.recovery_used):
                # Claimed by a concurrent request between the read and here.
                raise HTTPException(status_code=401,
                                    detail="invalid username or password")
        if outcome.rehash:
            # A free upgrade on a correct password. Without it, raising the
            # cost later would only protect accounts created after the change.
            store.set_operator_password(username,
                                        authn.hash_password(password))

        token = authn.new_session_token()
        window = authn.open_window()
        store.open_session(authn.session_fingerprint(token), username, window)
        store.note_operator_login(username)

        response = JSONResponse(status_code=200, content={
            "username": username,
            "display_name": operator.get("display_name") or username,
            "totp_enabled": bool(state.get("enabled")),
            "recovery_code_used": bool(outcome.recovery_used),
        })
        response.set_cookie(
            COOKIE_NAME, token, httponly=True, samesite="strict",
            secure=_cookie_secure(request),
            max_age=authn.SESSION_TTL_SECONDS, path="/")
        return response

    @app.post("/api/v1/auth/logout")
    def logout(request: Request):
        token = _session_token(request)
        if token:
            store.close_session(authn.session_fingerprint(token))
        response = JSONResponse(status_code=200, content={"signed_out": True})
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    @app.get("/api/v1/auth/me")
    def me(request: Request):
        """Who is signed in, or plainly nobody.

        200 with `authenticated: false` rather than 401: the console asks this
        to decide whether to show the estate or the sign-in page, and an error
        status for the ordinary not-signed-in case makes that decision look
        like a failure in every log and browser console.
        """
        session = _current(request)
        if session is None or session.get("status") != "active":
            return {"authenticated": False}
        state = store.totp_state(session["username"]) or {}
        return {
            "authenticated": True,
            "username": session["username"],
            "display_name": session.get("display_name") or session["username"],
            "totp_enabled": bool(state.get("enabled")),
            "expires_at": session["expires_at"].isoformat(),
        }

    # ── password ──────────────────────────────────────────────────────────

    @app.post("/api/v1/auth/password")
    def change_password(request: Request, body: dict = Body(...)):
        """Change a password by proving the current one.

        Deliberately NOT behind a session. The usual reason to change a
        password is that somebody handed you a temporary one, so requiring a
        session first would put the feature behind the door it exists to open.
        It is not weaker: the form proves the current password and the second
        factor, which is the whole check either way.
        """
        username = str(body.get("username") or "").strip().lower()
        current = str(body.get("current_password") or "")
        replacement = str(body.get("new_password") or "")
        code = str(body.get("code") or "").strip()

        operator = store.operator(username) if username else None
        if operator is None:
            authn.burn_verification_time()
            raise HTTPException(status_code=401,
                                detail="invalid username or password")

        state = store.totp_state(username) or {}
        outcome = authn.decide_login(
            operator["password_hash"], current, status=operator["status"],
            totp_secret=state.get("secret", ""),
            totp_enabled=bool(state.get("enabled")),
            totp_last_counter=int(state.get("last_counter", -1)),
            code=code,
            recovery_fingerprints=store.unused_recovery_fingerprints(username))
        if outcome.second_factor_required:
            return JSONResponse(
                status_code=401,
                content={"detail": "a second factor is required",
                         "second_factor_required": True})
        if not outcome.ok:
            raise HTTPException(status_code=401, detail=outcome.reason)

        try:
            new_hash = authn.hash_password(replacement)
        except authn.PasswordPolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        store.set_operator_password(username, new_hash)
        if outcome.totp_counter >= 0:
            store.record_totp_counter(username, outcome.totp_counter)
        # Every session, including any this operator is holding right now. A
        # password change that leaves the old sessions alive has changed
        # nothing for whoever already had one — which is the case where it
        # matters.
        closed = store.close_all_sessions(username)
        response = JSONResponse(status_code=200, content={
            "changed": True, "sessions_closed": closed,
            "detail": "sign in again with the new password"})
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    # ── second factor ─────────────────────────────────────────────────────

    @app.get("/api/v1/auth/totp")
    def totp_status(request: Request):
        session = _require(request)
        state = store.totp_state(session["username"]) or {}
        return {
            "enabled": bool(state.get("enabled")),
            "pending": bool(state) and not state.get("enabled"),
            "issuer": totp_module.ISSUER,
        }

    @app.post("/api/v1/auth/totp/begin")
    def totp_begin(request: Request):
        """Mint a secret and hand back what an authenticator needs. NOT active.

        Two-step on purpose: this stages a secret, and `confirm` only switches
        the factor on once a code it generates has been typed back. A one-step
        enable locks out anyone whose transcription was wrong or whose phone
        clock is skewed, and the person most likely to be hit is the first
        administrator, who has nobody to ask for a reset.
        """
        session = _require(request)
        username = session["username"]
        secret = totp_module.new_secret()
        store.stage_totp_secret(username, secret)
        uri = totp_module.provisioning_uri(secret, username)
        return {
            "secret": secret,
            "formatted_secret": totp_module.format_secret(secret),
            "provisioning_uri": uri,
            # Three ways in, and they are not redundant. The QR is for a phone
            # with a camera; the URI is a LINK, so tapping it on the phone
            # itself opens the authenticator with nothing to scan; the secret
            # is for "enter a setup key", which is what works when the camera
            # is unavailable or the screen is being shared.
            "qr_svg": qr_module.to_svg(uri, dark="#0f1115", light="#ffffff"),
            "issuer": totp_module.ISSUER,
            "digits": totp_module.DIGITS,
            "period": totp_module.PERIOD,
        }

    @app.post("/api/v1/auth/totp/confirm")
    def totp_confirm(request: Request, body: dict = Body(...)):
        """Prove the secret arrived intact, then switch the factor on.

        The recovery codes are returned HERE AND NOWHERE ELSE. They are stored
        only as SHA-256, so they cannot be shown again on a later screen — a
        list an operator can re-open is a standing credential rather than a
        break-glass one.
        """
        session = _require(request)
        username = session["username"]
        state = store.totp_state(username)
        if state is None:
            raise HTTPException(
                status_code=409,
                detail="no enrolment is in progress; start one first")
        if state.get("enabled"):
            raise HTTPException(status_code=409,
                                detail="a second factor is already enrolled")

        code = str(body.get("code") or "").strip()
        counter = totp_module.verify(state["secret"], code,
                                     after_counter=int(state["last_counter"]))
        if counter is None:
            raise HTTPException(
                status_code=400,
                detail="that code does not match. Check the clock on the "
                       "device, and that the whole secret was entered.")

        codes = totp_module.new_recovery_codes()
        store.store_recovery_codes(
            username, [totp_module.recovery_fingerprint(c) for c in codes])
        store.enable_totp(username, counter)
        return {"enabled": True, "recovery_codes": codes,
                "detail": "keep these somewhere a lost phone cannot reach. "
                          "They are shown once and stored only as hashes."}

    @app.post("/api/v1/auth/totp/disable")
    def totp_disable(request: Request, body: dict = Body(...)):
        """Remove the second factor, proving the password AND a current code.

        A session alone is not enough. The whole point of the factor is that a
        stolen session is not a complete credential, and letting one turn the
        factor off would make it exactly that.
        """
        session = _require(request)
        username = session["username"]
        operator = store.operator(username)
        state = store.totp_state(username) or {}
        if not state.get("enabled"):
            raise HTTPException(status_code=409,
                                detail="no second factor is enrolled")

        outcome = authn.decide_login(
            operator["password_hash"], str(body.get("password") or ""),
            status=operator["status"], totp_secret=state.get("secret", ""),
            totp_enabled=True,
            totp_last_counter=int(state.get("last_counter", -1)),
            code=str(body.get("code") or "").strip(),
            recovery_fingerprints=store.unused_recovery_fingerprints(username))
        if not outcome.ok:
            raise HTTPException(status_code=401,
                                detail="invalid password or code")

        store.disable_totp(username)
        return {"enabled": False,
                "detail": "second factor removed; enrol again to restore it"}
