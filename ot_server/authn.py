"""
Operator authentication — the credential half (OTS-SRV-006).

`totp.py` owns the second factor and knows nothing about storage. This module
owns password hashing, session tokens and the login decision, and knows nothing
about HTTP or SQL. `store.py` holds the rows; `api.py` turns a session cookie
into an operator.

WHY THIS IS A PROVIDER, NOT A REPLACEMENT FOR THE HOOK
──────────────────────────────────────────────────────
`create_app` takes `require_operator` and every estate route answers 503 without
one, with the instruction that a real deployment must inject a hook mapping the
authenticated caller to an operator. This module is one such hook — the built-in
one, for a plant with no identity provider in front of it. An operator who
fronts OTSec with their own SSO injects theirs instead and never creates
a local account.

So the fail-closed posture is unchanged. Local authentication is wired
explicitly by the deployment, never by default.

THE BOOTSTRAP PROBLEM, AND WHY THERE IS NO DEFAULT PASSWORD
───────────────────────────────────────────────────────────
A fresh database has no operators, and a console nobody can sign into is
useless. The two usual answers are both wrong:

  * A well-known default (`admin`/`admin`) is a published credential on every
    install that forgets to change it, which is most of them — and this one
    fronts a substation.
  * Auto-generating one and printing it to stdout puts a live credential in
    container logs, which are aggregated, shipped and retained.

So the first operator comes from `OTSEC_BOOTSTRAP_USER` and
`OTSEC_BOOTSTRAP_PASSWORD`, applied ONCE against an empty operator table
and ignored entirely afterwards. The deployment chooses the secret, it never
appears in a log line, and re-running with the variables still set cannot
silently reset a password that has since been changed.

EVERY FAILURE LOOKS THE SAME
────────────────────────────
Wrong password, unknown account, disabled account and wrong code all raise the
same `AuthError` with the same message. A distinct "no such operator" is a
username oracle: it turns a login form into a directory of who works at this
utility, which an attacker can enumerate before they start guessing passwords.

`SecondFactorRequired` is the one exception, and it is safe: by the time it is
raised the password has already been proven, so it tells nothing to anyone who
could not already sign in.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from typing import List, Optional

from . import totp as totp_module

#: PBKDF2-SHA256. Not the strongest option available — Argon2 is — but it is in
#: the standard library, and a dependency in the authentication path of a
#: console that fronts a plant is a dependency with a blast radius. The cost is
#: chosen instead: 600,000 iterations is roughly 0.3s on the server hardware
#: this runs on, which is invisible to a person signing in once a shift and
#: expensive against a stolen table.
PBKDF2_ITERATIONS = 600_000
_ALGO = "pbkdf2_sha256"
_SALT_BYTES = 16

#: 256 bits of urandom. Stored as a SHA-256, so a copy of the database yields no
#: usable session — the same reasoning as recovery codes, and for the same
#: reason stretching would buy nothing here.
SESSION_TOKEN_BYTES = 32

#: How long a session survives without being re-issued. A shift, not a season:
#: long enough not to interrupt an investigation, short enough that a browser
#: left open in a control room is not a standing grant.
SESSION_TTL_SECONDS = 12 * 3600

#: Sessions extend on use but never past this from first issue, so a
#: continuously-active session still forces a fresh sign-in eventually.
SESSION_ABSOLUTE_MAX_SECONDS = 7 * 24 * 3600

MIN_PASSWORD_LENGTH = 12


class AuthError(Exception):
    """Authentication failed. Deliberately carries no detail about why."""


class SecondFactorRequired(Exception):
    """The password was correct and a code is still needed."""


class PasswordPolicyError(ValueError):
    """A password that would not survive contact with a substation."""


# ── passwords ──────────────────────────────────────────────────────────────

def check_password_policy(password: str) -> None:
    """Length, and nothing else.

    No character-class rules. They push people towards `Password1!` — a
    predictable shape that a cracking rule set expands trivially — while
    rejecting a long passphrase that is genuinely stronger. Length is the term
    that actually matters in the search space.
    """
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            "a password must be at least %d characters. Length is what makes "
            "one hard to guess; a short password with a symbol in it is not a "
            "long one." % MIN_PASSWORD_LENGTH)


def hash_password(password: str, *,
                  iterations: int = PBKDF2_ITERATIONS) -> str:
    """`pbkdf2_sha256$<iterations>$<salt-hex>$<derived-hex>`.

    Self-describing on purpose: the algorithm and cost travel WITH the hash, so
    the verifier never guesses how an old row was produced, and raising the cost
    later is not a migration.
    """
    check_password_policy(password)
    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                  iterations)
    return "%s$%d$%s$%s" % (_ALGO, iterations, salt.hex(), derived.hex())


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify.

    Returns False for a malformed or unknown-algorithm row rather than raising:
    a corrupt hash must read as "wrong password", never as a 500 that
    distinguishes a real account from a broken one.
    """
    if not password or not stored:
        return False
    try:
        algo, iterations, salt_hex, want_hex = stored.split("$", 3)
        if algo != _ALGO:
            return False
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                      bytes.fromhex(salt_hex), int(iterations))
    except Exception:                                      # noqa: BLE001
        return False
    return hmac.compare_digest(derived.hex(), want_hex)


def needs_rehash(stored: str, *, iterations: int = PBKDF2_ITERATIONS) -> bool:
    """Whether a correct password should be re-hashed at a higher cost.

    Without this, raising `PBKDF2_ITERATIONS` would only ever protect accounts
    created after the change — the long-lived administrator account, the one
    worth attacking, would keep its original cost forever.
    """
    try:
        algo, current, _salt, _want = stored.split("$", 3)
    except Exception:                                      # noqa: BLE001
        return True
    return algo != _ALGO or int(current) < iterations


def burn_verification_time() -> None:
    """Do the work of a password check that was never going to succeed.

    Returning early for an unknown operator makes "does this account exist"
    measurable on a stopwatch even when the RESPONSE is identical. So an unknown
    account costs the same as a known one.
    """
    verify_password("x" * 24, hash_password("y" * 24))


# ── sessions ───────────────────────────────────────────────────────────────

def new_session_token() -> str:
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def session_fingerprint(token: str) -> str:
    """What the database stores. A cookie is a bearer credential; a database
    copy that yields working ones is a second, quieter way in."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


@dataclass
class SessionWindow:
    """When a session was opened, and when it must stop being honoured."""

    issued_at: float
    expires_at: float
    absolute_deadline: float

    def valid_at(self, now: float) -> bool:
        return now < self.expires_at and now < self.absolute_deadline


def open_window(now: Optional[float] = None) -> SessionWindow:
    now = time.time() if now is None else now
    return SessionWindow(
        issued_at=now,
        expires_at=now + SESSION_TTL_SECONDS,
        absolute_deadline=now + SESSION_ABSOLUTE_MAX_SECONDS)


def extend(window: SessionWindow, now: Optional[float] = None) -> SessionWindow:
    """Slide the idle timeout forward, never past the absolute deadline."""
    now = time.time() if now is None else now
    return SessionWindow(
        issued_at=window.issued_at,
        expires_at=min(now + SESSION_TTL_SECONDS, window.absolute_deadline),
        absolute_deadline=window.absolute_deadline)


# ── the login decision, as a pure function ─────────────────────────────────

@dataclass
class LoginOutcome:
    ok: bool
    reason: str = ""
    second_factor_required: bool = False
    #: The TOTP counter that was consumed, so the caller can persist it and
    #: refuse a replay of the same six digits.
    totp_counter: int = -1
    #: The recovery code that was spent, as its fingerprint.
    recovery_used: str = ""
    rehash: bool = False


def decide_login(stored_hash: str, password: str, *, status: str,
                 totp_secret: str = "", totp_enabled: bool = False,
                 totp_last_counter: int = -1, code: str = "",
                 recovery_fingerprints: Optional[List[str]] = None,
                 when: Optional[float] = None) -> LoginOutcome:
    """Everything the login path decides, with no I/O in it.

    Written as one function returning one outcome so the ORDER is inspectable:
    password first, then the second factor, and NO session until both are
    satisfied. An early session would be a complete login that merely looks
    unfinished to the browser.
    """
    if not verify_password(password, stored_hash) or status != "active":
        return LoginOutcome(ok=False, reason="invalid username or password")

    if not totp_enabled:
        return LoginOutcome(ok=True, rehash=needs_rehash(stored_hash))

    if not code:
        return LoginOutcome(ok=False, second_factor_required=True,
                            reason="a second factor is required")

    counter = totp_module.verify(totp_secret, code, when=when,
                                 after_counter=totp_last_counter)
    if counter is not None:
        return LoginOutcome(ok=True, totp_counter=counter,
                            rehash=needs_rehash(stored_hash))

    # A recovery code, which is single use and consumed by the caller.
    fingerprint = totp_module.recovery_fingerprint(code)
    for known in (recovery_fingerprints or []):
        if hmac.compare_digest(fingerprint, known):
            return LoginOutcome(ok=True, recovery_used=fingerprint,
                                rehash=needs_rehash(stored_hash))

    # Same message as a wrong password. "Password right, code wrong" confirms a
    # guessed password to somebody holding only half the credential.
    return LoginOutcome(ok=False, reason="invalid username or password")


# ── bootstrap ──────────────────────────────────────────────────────────────

BOOTSTRAP_USER_ENV = "OTSEC_BOOTSTRAP_USER"
BOOTSTRAP_PASSWORD_ENV = "OTSEC_BOOTSTRAP_PASSWORD"


def bootstrap_credentials() -> Optional[tuple]:
    """The first operator, from the environment, or None.

    Returns None rather than inventing anything. A deployment that sets neither
    variable gets a server with no operators, whose estate plane answers 503 —
    which is the honest state, and visibly different from a console with a
    default password on it.
    """
    username = (os.environ.get(BOOTSTRAP_USER_ENV) or "").strip().lower()
    password = os.environ.get(BOOTSTRAP_PASSWORD_ENV) or ""
    if not username or not password:
        return None
    check_password_policy(password)
    return username, password
