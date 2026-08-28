"""
Operator sign-in and the second factor (OTS-SRV-006).

The load-bearing test here is `test_rfc6238_vectors`. A TOTP implementation that
agrees with itself proves nothing — a round trip passes just as happily when the
algorithm is subtly wrong, and the operator experiences that as "the
authenticator app is broken" at three in the morning. RFC 6238 Appendix B
publishes (time, expected code) for a known seed, and asserting against it is
proof of interoperability with every conforming app.

The other one that matters is `test_no_session_exists_until_the_code_verifies`.
A design that issues a session on a correct password and asks the UI to collect
the code afterwards has already logged the caller in; the second factor is then
a dialog, not a factor.
"""
from __future__ import annotations

import datetime
import os
import sys
import time

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ot_server import authn                                # noqa: E402
from ot_server import totp                                 # noqa: E402


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


# ── TOTP against the specification's own numbers ───────────────────────────

#: RFC 6238 Appendix B, SHA-1 rows. The seed is the ASCII "12345678901234567890"
#: base32-encoded, which is what the RFC's hex seed 3132...3930 spells.
_RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

_RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("when,expected", _RFC_VECTORS)
def test_rfc6238_vectors(when, expected):
    """Eight digits, because that is what the RFC's table publishes. The
    six-digit codes the console uses are the same computation truncated, so
    matching here is matching everywhere."""
    counter = totp.counter_at(when)
    assert totp.code_at(_RFC_SECRET, counter, digits=8) == expected


def test_the_six_digit_code_is_the_same_number_truncated():
    counter = totp.counter_at(59)
    assert totp.code_at(_RFC_SECRET, counter, digits=6) == "287082"


def test_a_secret_is_base32_a_human_can_type():
    secret = totp.new_secret()
    assert len(secret) == 32 and "=" not in secret
    assert secret.upper() == secret
    # And it survives being read off a screen onto a phone with spaces in it.
    assert totp.normalise_secret(totp.format_secret(secret).lower()) == \
        totp.normalise_secret(secret)


def test_the_provisioning_uri_names_this_product():
    uri = totp.provisioning_uri("ABCDEFGHIJKLMNOP", "operator")
    assert uri.startswith("otpauth://totp/")
    assert "Power%20NetView" in uri
    # Microsoft and Google Authenticator ignore `algorithm` and assume SHA-1;
    # advertising anything else produces codes that never match.
    assert "algorithm=SHA1" in uri and "digits=6" in uri and "period=30" in uri


def test_a_code_is_accepted_within_the_drift_window():
    secret = totp.new_secret()
    now = time.time()
    previous = totp.code_at(secret, totp.counter_at(now) - 1)
    assert totp.verify(secret, previous, when=now) is not None


def test_a_code_two_steps_old_is_not():
    """Two would be 2.5 minutes of replay surface for a code read over a
    shoulder."""
    secret = totp.new_secret()
    now = time.time()
    stale = totp.code_at(secret, totp.counter_at(now) - 2)
    assert totp.verify(secret, stale, when=now) is None


def test_the_same_code_cannot_be_used_twice():
    """A code stays valid for its whole step, so without the counter the same
    six digits replay for up to 90 seconds."""
    secret = totp.new_secret()
    now = time.time()
    counter = totp.verify(secret, totp.code_now(secret, when=now), when=now)
    assert counter is not None
    assert totp.verify(secret, totp.code_now(secret, when=now), when=now,
                       after_counter=counter) is None


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 34 56"])
def test_malformed_codes_are_rejected_without_reaching_the_comparison(bad):
    assert totp.verify(totp.new_secret(), bad) is None


def test_recovery_codes_are_stored_only_as_hashes():
    codes = totp.new_recovery_codes()
    assert len(codes) == totp.RECOVERY_CODE_COUNT
    for code in codes:
        fingerprint = totp.recovery_fingerprint(code)
        assert code not in fingerprint and len(fingerprint) == 64
    # Read aloud down a phone line and typed back with different case/spacing.
    first = codes[0]
    assert totp.recovery_fingerprint(first.upper().replace("-", " ")) == \
        totp.recovery_fingerprint(first)


def test_recovery_codes_avoid_the_characters_people_mishear():
    for code in totp.new_recovery_codes(3):
        assert not set(code) & set("l1o0")


# ── passwords ──────────────────────────────────────────────────────────────

def test_a_password_hash_describes_itself():
    """The algorithm and cost travel WITH the hash, so raising the cost later
    is not a migration."""
    stored = authn.hash_password("correct horse battery staple")
    algo, iterations, salt, derived = stored.split("$")
    assert algo == "pbkdf2_sha256"
    assert int(iterations) == authn.PBKDF2_ITERATIONS
    assert len(salt) == 32 and len(derived) == 64


def test_the_same_password_hashes_differently_every_time():
    a = authn.hash_password("correct horse battery staple")
    b = authn.hash_password("correct horse battery staple")
    assert a != b, "the salt is not being applied"


def test_a_corrupt_hash_reads_as_a_wrong_password_not_a_crash():
    """A 500 here would distinguish a real account from a broken one."""
    for stored in ("", "garbage", "bcrypt$1$2$3", "pbkdf2_sha256$notanint$a$b"):
        assert authn.verify_password("anything", stored) is False


def test_length_is_the_policy_and_symbols_are_not():
    """Character-class rules push people to `Password1!` — a shape a cracking
    rule set expands trivially — while rejecting a longer passphrase."""
    with pytest.raises(authn.PasswordPolicyError):
        authn.hash_password("short")
    authn.hash_password("a whole sentence typed out")     # no symbols, fine


def test_raising_the_cost_marks_old_hashes_for_upgrade():
    weak = authn.hash_password("correct horse battery staple", iterations=1000)
    assert authn.needs_rehash(weak) is True
    assert authn.needs_rehash(
        authn.hash_password("correct horse battery staple")) is False


# ── the login decision ─────────────────────────────────────────────────────

def _hash():
    return authn.hash_password("correct horse battery staple")


def test_no_session_exists_until_the_code_verifies():
    """THE test. A correct password with a factor enrolled and no code is not a
    login — it is a request for the second half of one."""
    outcome = authn.decide_login(
        _hash(), "correct horse battery staple", status="active",
        totp_secret=totp.new_secret(), totp_enabled=True, code="")
    assert outcome.ok is False
    assert outcome.second_factor_required is True


def test_a_wrong_code_reads_exactly_like_a_wrong_password():
    """Splitting them confirms a guessed password to somebody holding only half
    the credential."""
    stored, secret = _hash(), totp.new_secret()
    wrong_password = authn.decide_login(stored, "not it", status="active")
    wrong_code = authn.decide_login(
        stored, "correct horse battery staple", status="active",
        totp_secret=secret, totp_enabled=True, code="000000")
    assert wrong_password.reason == wrong_code.reason
    assert wrong_password.second_factor_required is False
    assert wrong_code.second_factor_required is False


def test_a_disabled_account_cannot_sign_in_with_the_right_password():
    outcome = authn.decide_login(_hash(), "correct horse battery staple",
                                 status="disabled")
    assert outcome.ok is False


def test_a_recovery_code_stands_in_for_the_app():
    code = totp.new_recovery_codes(1)[0]
    outcome = authn.decide_login(
        _hash(), "correct horse battery staple", status="active",
        totp_secret=totp.new_secret(), totp_enabled=True, code=code,
        recovery_fingerprints=[totp.recovery_fingerprint(code)])
    assert outcome.ok is True
    assert outcome.recovery_used == totp.recovery_fingerprint(code)


def test_a_recovery_code_that_was_never_issued_does_not():
    outcome = authn.decide_login(
        _hash(), "correct horse battery staple", status="active",
        totp_secret=totp.new_secret(), totp_enabled=True,
        code=totp.new_recovery_codes(1)[0], recovery_fingerprints=[])
    assert outcome.ok is False


def test_a_correct_password_with_no_factor_enrolled_is_a_login():
    outcome = authn.decide_login(_hash(), "correct horse battery staple",
                                 status="active")
    assert outcome.ok is True and outcome.second_factor_required is False


# ── sessions ───────────────────────────────────────────────────────────────

def test_a_session_token_is_stored_only_as_a_fingerprint():
    token = authn.new_session_token()
    assert token not in authn.session_fingerprint(token)


def test_a_session_slides_forward_but_not_past_its_deadline():
    """A continuously-active session still forces a fresh sign-in eventually."""
    window = authn.open_window(now=0.0)
    later = authn.extend(window, now=authn.SESSION_ABSOLUTE_MAX_SECONDS - 60)
    assert later.expires_at == window.absolute_deadline
    assert later.absolute_deadline == window.absolute_deadline


def test_a_session_past_its_absolute_deadline_is_not_valid():
    window = authn.open_window(now=0.0)
    assert window.valid_at(10.0) is True
    assert window.valid_at(authn.SESSION_ABSOLUTE_MAX_SECONDS + 1) is False


# ── bootstrap ──────────────────────────────────────────────────────────────

def test_no_environment_means_no_operator_rather_than_a_default(monkeypatch):
    """A well-known default is a published credential on every install that
    forgets to change it — and this one fronts a substation."""
    monkeypatch.delenv(authn.BOOTSTRAP_USER_ENV, raising=False)
    monkeypatch.delenv(authn.BOOTSTRAP_PASSWORD_ENV, raising=False)
    assert authn.bootstrap_credentials() is None


def test_a_bootstrap_password_must_still_meet_the_policy(monkeypatch):
    monkeypatch.setenv(authn.BOOTSTRAP_USER_ENV, "control-room")
    monkeypatch.setenv(authn.BOOTSTRAP_PASSWORD_ENV, "short")
    with pytest.raises(authn.PasswordPolicyError):
        authn.bootstrap_credentials()


def test_the_bootstrap_operator_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv(authn.BOOTSTRAP_USER_ENV, "Control-Room")
    monkeypatch.setenv(authn.BOOTSTRAP_PASSWORD_ENV, "a whole sentence typed out")
    username, password = authn.bootstrap_credentials()
    assert username == "control-room"          # normalised, so case cannot fork
    assert password == "a whole sentence typed out"


# ── the routes, end to end ─────────────────────────────────────────────────

class _AuthStore:
    """In-memory, faithful where it matters: a session lookup that has aged out
    returns nothing, and a recovery code can be spent exactly once."""

    def __init__(self):
        self.operators = {}
        self.sessions = {}
        self.totp = {}
        self.recovery = {}

    # operators
    def operator_count(self):
        return len(self.operators)

    def create_operator(self, username, password_hash, display_name=""):
        self.operators[username] = {
            "username": username, "display_name": display_name or username,
            "password_hash": password_hash, "status": "active",
            "last_login_at": None}

    def operator(self, username):
        row = self.operators.get((username or "").strip().lower())
        return dict(row) if row else None

    def set_operator_password(self, username, password_hash):
        self.operators[username]["password_hash"] = password_hash

    def note_operator_login(self, username):
        self.operators[username]["last_login_at"] = _utcnow()

    # sessions
    def open_session(self, token_hash, username, window):
        self.sessions[token_hash] = {
            "token_hash": token_hash, "username": username,
            "issued_at": _stamp(window.issued_at),
            "expires_at": _stamp(window.expires_at),
            "absolute_deadline": _stamp(window.absolute_deadline)}

    def session(self, token_hash):
        row = self.sessions.get(token_hash)
        if row is None:
            return None
        now = _utcnow()
        if row["expires_at"] <= now or row["absolute_deadline"] <= now:
            return None
        operator = self.operators[row["username"]]
        out = dict(row)
        out["status"] = operator["status"]
        out["display_name"] = operator["display_name"]
        return out

    def touch_session(self, token_hash, expires_at):
        row = self.sessions.get(token_hash)
        if row is not None:
            row["expires_at"] = min(expires_at, row["absolute_deadline"])

    def close_session(self, token_hash):
        self.sessions.pop(token_hash, None)

    def close_all_sessions(self, username):
        doomed = [k for k, v in self.sessions.items()
                  if v["username"] == username]
        for key in doomed:
            del self.sessions[key]
        return len(doomed)

    # second factor
    def totp_state(self, username):
        row = self.totp.get(username)
        return dict(row) if row else None

    def stage_totp_secret(self, username, secret):
        self.totp[username] = {"username": username, "secret": secret,
                               "enabled": False, "last_counter": -1,
                               "enrolled_at": None}

    def enable_totp(self, username, counter):
        self.totp[username].update(enabled=True, last_counter=counter,
                                   enrolled_at=_utcnow())

    def disable_totp(self, username):
        self.totp.pop(username, None)
        self.recovery.pop(username, None)

    def record_totp_counter(self, username, counter):
        row = self.totp[username]
        row["last_counter"] = max(row["last_counter"], counter)

    def store_recovery_codes(self, username, fingerprints):
        self.recovery[username] = {f: None for f in fingerprints}

    def unused_recovery_fingerprints(self, username):
        return [f for f, used in (self.recovery.get(username) or {}).items()
                if used is None]

    # Enough estate surface that "signed in, now read the estate" can actually
    # be exercised. A double that only answers ONE estate route makes the point
    # of the whole feature untestable past that route -- which showed up as a
    # 500 the first time this was run against a real server.
    def certificates(self, collector_id=None):
        return []

    def collector_ids(self):
        return []

    def collector_sites(self):
        return {}

    def all_assets(self, limit=5000):
        return []

    def assets(self, collector_id=None, limit=500):
        return []

    def all_flows(self, limit=20000):
        return []

    def all_detections(self, limit=20000):
        return []

    def recent_windows(self, collector_id):
        return []

    def recent_gaps(self, collector_id):
        return []

    def latest_window(self, collector_id):
        return ""

    def spend_recovery_code(self, username, fingerprint):
        codes = self.recovery.get(username) or {}
        if codes.get(fingerprint, "spent") is not None:
            return False
        codes[fingerprint] = _utcnow()
        return True


def _stamp(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc)


PASSWORD = "a whole sentence typed out"


def _next_code(secret, ahead=1):
    """A code from a later step.

    Confirming an enrolment consumes the counter of the code that was typed in,
    so the replay guard refuses that same code for the sign-in immediately
    afterwards. That is correct — a code is single use — and it means these
    tests must move on a step rather than reusing one, exactly as an operator's
    app does within 30 seconds.
    """
    return totp.code_at(secret, totp.counter_at() + ahead)


def _auth_client(store=None, operator="control-room"):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server import authn as authn_module
    from ot_server.api import create_app

    store = store or _AuthStore()
    if operator:
        store.create_operator(operator,
                              authn_module.hash_password(PASSWORD), operator)
    client = TestClient(create_app(store, console_dir="", local_auth=True))
    return client, store


def test_a_correct_password_opens_a_session():
    client, _store = _auth_client()
    response = client.post("/api/v1/auth/login",
                           json={"username": "control-room",
                                 "password": PASSWORD})
    assert response.status_code == 200, response.text
    assert response.json()["username"] == "control-room"
    assert client.cookies.get("pnv_session")


def test_the_session_cookie_is_not_readable_by_script():
    """A cookie a page's JavaScript can read is a cookie an injected script can
    exfiltrate."""
    client, _store = _auth_client()
    response = client.post("/api/v1/auth/login",
                           json={"username": "control-room",
                                 "password": PASSWORD})
    header = response.headers.get("set-cookie", "")
    assert "HttpOnly" in header
    assert "SameSite=strict" in header.replace("samesite", "SameSite")


def test_only_the_fingerprint_of_a_session_is_stored():
    client, store = _auth_client()
    client.post("/api/v1/auth/login",
                json={"username": "control-room", "password": PASSWORD})
    token = client.cookies.get("pnv_session")
    assert token not in store.sessions
    assert authn.session_fingerprint(token) in store.sessions


@pytest.mark.parametrize("body", [
    {"username": "control-room", "password": "wrong password entirely"},
    {"username": "nobody-here", "password": PASSWORD},
    {"username": "", "password": ""},
])
def test_every_failure_answers_the_same_way(body):
    """A distinct "no such operator" turns the form into a directory of who
    works at this utility."""
    client, _store = _auth_client()
    response = client.post("/api/v1/auth/login", json=body)
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid username or password"
    assert not client.cookies.get("pnv_session")


def test_the_estate_plane_is_reachable_once_signed_in():
    """The point of all of this: OTS-SRV-006 said fail-closed until operator
    authentication is wired, and this is it being wired."""
    client, _store = _auth_client()
    assert client.get("/api/v1/estate/certificates").status_code == 401
    client.post("/api/v1/auth/login",
                json={"username": "control-room", "password": PASSWORD})
    assert client.get("/api/v1/estate/certificates").status_code == 200
    # And a route that actually reads the estate, not only the one the double
    # was first written for.
    assert client.get("/api/v1/estate/inventory").status_code == 200


def test_without_local_auth_the_estate_plane_is_still_503():
    """Wiring the built-in provider is an OPT-IN. A deployment that asks for
    neither it nor its own hook gets the fail-closed default, unchanged."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    client = TestClient(create_app(_AuthStore(), console_dir=""))
    assert client.get("/api/v1/estate/certificates").status_code == 503
    # The auth routes are not mounted at all, so there is nothing to POST to.
    assert client.post("/api/v1/auth/login", json={}).status_code == 404


def test_signing_out_closes_the_session_on_the_server():
    """Not just in the browser. A console left open in a control room is a
    standing grant."""
    client, store = _auth_client()
    client.post("/api/v1/auth/login",
                json={"username": "control-room", "password": PASSWORD})
    assert client.post("/api/v1/auth/logout").status_code == 200
    assert store.sessions == {}
    assert client.get("/api/v1/estate/certificates").status_code == 401


def test_me_reports_nobody_without_erroring():
    """The console asks this to decide whether to show the estate or the form.
    An error status for the ordinary case makes that look like a failure."""
    client, _store = _auth_client()
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 200
    assert response.json() == {"authenticated": False}


# ── the second factor ──────────────────────────────────────────────────────

def _enrolled_client():
    client, store = _auth_client()
    client.post("/api/v1/auth/login",
                json={"username": "control-room", "password": PASSWORD})
    begin = client.post("/api/v1/auth/totp/begin").json()
    code = totp.code_now(begin["secret"])
    confirm = client.post("/api/v1/auth/totp/confirm", json={"code": code})
    assert confirm.status_code == 200, confirm.text
    client.post("/api/v1/auth/logout")
    return client, store, begin["secret"], confirm.json()["recovery_codes"]


def test_enrolment_offers_all_three_ways_in():
    """A QR for a phone with a camera, a link for the phone itself, and the
    secret for when the camera is unavailable or the screen is shared."""
    client, _store = _auth_client()
    client.post("/api/v1/auth/login",
                json={"username": "control-room", "password": PASSWORD})
    body = client.post("/api/v1/auth/totp/begin").json()
    assert body["provisioning_uri"].startswith("otpauth://totp/")
    assert body["qr_svg"].startswith("<svg")
    assert len(body["secret"]) == 32
    assert " " in body["formatted_secret"]


def test_a_staged_secret_is_not_in_force_until_a_code_verifies():
    """A one-step enable locks out anyone whose transcription was wrong — and
    the first administrator has nobody to ask for a reset."""
    client, store = _auth_client()
    client.post("/api/v1/auth/login",
                json={"username": "control-room", "password": PASSWORD})
    client.post("/api/v1/auth/totp/begin")
    assert store.totp["control-room"]["enabled"] is False
    assert client.post("/api/v1/auth/totp/confirm",
                       json={"code": "000000"}).status_code == 400
    assert store.totp["control-room"]["enabled"] is False


def test_no_session_is_issued_until_the_code_is_supplied():
    """THE one. A correct password against an enrolled account returns 401 and
    NO cookie — there is nothing for a careless client to proceed with."""
    client, _store, _secret, _codes = _enrolled_client()
    response = client.post("/api/v1/auth/login",
                           json={"username": "control-room",
                                 "password": PASSWORD})
    assert response.status_code == 401
    assert response.json()["second_factor_required"] is True
    assert not client.cookies.get("pnv_session")
    assert client.get("/api/v1/estate/certificates").status_code == 401


def test_the_password_and_a_current_code_together_sign_in():
    client, _store, secret, _codes = _enrolled_client()
    response = client.post("/api/v1/auth/login",
                           json={"username": "control-room",
                                 "password": PASSWORD,
                                 "code": _next_code(secret)})
    assert response.status_code == 200, response.text
    assert client.get("/api/v1/estate/certificates").status_code == 200


def test_the_same_code_cannot_sign_in_twice():
    """A code stays valid for its whole step. Without the stored counter, six
    digits read over a shoulder work for another 90 seconds."""
    client, _store, secret, _codes = _enrolled_client()
    code = _next_code(secret)
    assert client.post("/api/v1/auth/login",
                       json={"username": "control-room", "password": PASSWORD,
                             "code": code}).status_code == 200
    client.post("/api/v1/auth/logout")
    assert client.post("/api/v1/auth/login",
                       json={"username": "control-room", "password": PASSWORD,
                             "code": code}).status_code == 401


def test_a_recovery_code_works_once_and_then_never_again():
    client, _store, _secret, codes = _enrolled_client()
    first = codes[0]
    assert client.post("/api/v1/auth/login",
                       json={"username": "control-room", "password": PASSWORD,
                             "code": first}).status_code == 200
    client.post("/api/v1/auth/logout")
    assert client.post("/api/v1/auth/login",
                       json={"username": "control-room", "password": PASSWORD,
                             "code": first}).status_code == 401


def test_recovery_codes_are_shown_once_and_stored_as_hashes():
    client, store, _secret, codes = _enrolled_client()
    for code in codes:
        assert code not in str(store.recovery)
    assert len(store.recovery["control-room"]) == totp.RECOVERY_CODE_COUNT


def test_a_session_alone_cannot_remove_the_second_factor():
    """The whole point of the factor is that a stolen session is not a complete
    credential. Letting one turn it off would make it exactly that."""
    client, store, secret, _codes = _enrolled_client()
    client.post("/api/v1/auth/login",
                json={"username": "control-room", "password": PASSWORD,
                      "code": _next_code(secret)})
    assert client.post("/api/v1/auth/totp/disable",
                       json={}).status_code == 401
    assert store.totp["control-room"]["enabled"] is True


def test_the_password_and_a_code_together_remove_it():
    client, store, secret, codes = _enrolled_client()
    # Signed in with a RECOVERY code on purpose. A code two steps ahead is
    # outside the drift window, so after a sign-in that consumed the current
    # counter there is no app code left that this instant would accept — which
    # is correct, and is what an operator waiting 30 seconds resolves. A
    # recovery code does not move the counter, so the app code is still good.
    client.post("/api/v1/auth/login",
                json={"username": "control-room", "password": PASSWORD,
                      "code": codes[0]})
    response = client.post("/api/v1/auth/totp/disable",
                           json={"password": PASSWORD,
                                 "code": _next_code(secret)})
    assert response.status_code == 200, response.text
    assert "control-room" not in store.totp


# ── changing a password ────────────────────────────────────────────────────

def test_changing_a_password_closes_every_session():
    """One that leaves the old sessions alive has changed nothing for whoever
    already had one — which is the case where it matters."""
    client, store = _auth_client()
    client.post("/api/v1/auth/login",
                json={"username": "control-room", "password": PASSWORD})
    assert len(store.sessions) == 1
    response = client.post("/api/v1/auth/password", json={
        "username": "control-room", "current_password": PASSWORD,
        "new_password": "an entirely different sentence"})
    assert response.status_code == 200, response.text
    assert store.sessions == {}
    assert client.get("/api/v1/estate/certificates").status_code == 401


def test_a_new_password_must_meet_the_policy():
    client, _store = _auth_client()
    response = client.post("/api/v1/auth/password", json={
        "username": "control-room", "current_password": PASSWORD,
        "new_password": "short"})
    assert response.status_code == 400
    assert "at least" in response.json()["detail"]


def test_changing_a_password_needs_the_second_factor_too():
    client, _store, secret, _codes = _enrolled_client()
    without = client.post("/api/v1/auth/password", json={
        "username": "control-room", "current_password": PASSWORD,
        "new_password": "an entirely different sentence"})
    assert without.status_code == 401
    assert without.json()["second_factor_required"] is True

    with_code = client.post("/api/v1/auth/password", json={
        "username": "control-room", "current_password": PASSWORD,
        "new_password": "an entirely different sentence",
        "code": _next_code(secret)})
    assert with_code.status_code == 200, with_code.text


# ── bootstrap through the app ──────────────────────────────────────────────

def test_the_first_operator_is_created_once_and_never_again(monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    monkeypatch.setenv(authn.BOOTSTRAP_USER_ENV, "control-room")
    monkeypatch.setenv(authn.BOOTSTRAP_PASSWORD_ENV, PASSWORD)
    store = _AuthStore()

    TestClient(create_app(store, console_dir="", local_auth=True))
    assert store.operator_count() == 1
    original = store.operators["control-room"]["password_hash"]

    # Somebody changes the password, then the container restarts with the
    # variables still set. It must not be silently reset.
    store.set_operator_password("control-room",
                                authn.hash_password("something else entirely"))
    TestClient(create_app(store, console_dir="", local_auth=True))
    assert store.operator_count() == 1
    assert store.operators["control-room"]["password_hash"] != original
