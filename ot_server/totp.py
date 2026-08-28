"""
Time-based one-time passwords (RFC 6238) — pure, stdlib-only.

Works with Microsoft Authenticator, Google Authenticator, Authy, 1Password and
anything else speaking the `otpauth://` URI scheme, because it implements the
specification rather than a lookalike.

CORRECTNESS IS TESTABLE, SO IT IS TESTED
────────────────────────────────────────
RFC 6238 Appendix B publishes a table of (time, expected code) for a known seed.
`tests/test_operator_auth.py` asserts against those vectors, which is proof of
interoperability with every conforming authenticator — as opposed to proof that
this file agrees with itself, which is all a round-trip test of a hand-rolled
scheme would give.

WHY SHA-1, WHICH LOOKS WRONG AT FIRST GLANCE
────────────────────────────────────────────
RFC 6238 allows SHA-1, SHA-256 and SHA-512, and the default is SHA-1. Microsoft
and Google Authenticator ignore the `algorithm=` parameter and assume SHA-1; an
enrolment advertising SHA-256 silently produces codes that never match, and the
operator experiences it as "the app is broken" — in a control room, at 3am.

It is also not the SHA-1 weakness that matters. The break is collision
resistance, and HMAC-SHA-1 does not rely on it; the secret is 160 bits of
urandom. Interoperability wins.

WHY STDLIB AND NOT `pyotp`
──────────────────────────
The server may carry dependencies — it already carries FastAPI, psycopg and
cryptography. This one is 80 lines of HMAC and a truncation, the specification
publishes its own test vectors, and a dependency here would be a dependency in
the authentication path of a console that fronts a plant.

WHAT THIS MODULE DELIBERATELY DOES NOT DO
─────────────────────────────────────────
It does not remember which codes have been used. A code stays valid for its
whole time step, so the same six digits replay happily for up to 90 seconds with
the drift window unless somebody records the last counter accepted per operator.
That is state, so it belongs in the store — `authn.verify_totp` does it — and
the omission is called out here because "verify returned True" reads like the
whole job and is not.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Optional
from urllib.parse import quote

#: RFC 6238 defaults, and what every mainstream authenticator assumes.
DIGITS = 6
PERIOD = 30
ALGORITHM = "SHA1"

#: 160 bits, the RFC 4226 recommendation, and a whole number of base32
#: characters (32) so the manual-entry string has no padding to mistype.
SECRET_BYTES = 20

#: Steps either side of "now" that are accepted. One step is +/-30s, which
#: covers an unsynchronised phone clock and a slow typist. Two would be 2.5
#: minutes of replay surface for a code read over a shoulder; zero fails honest
#: operators whose clock drifted by a few seconds.
DEFAULT_DRIFT_STEPS = 1

ISSUER = "Power NetView"


def new_secret() -> str:
    """A fresh base32 secret, unpadded and upper-case — the shape every
    authenticator's manual-entry field expects."""
    return base64.b32encode(
        secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def normalise_secret(secret: str) -> bytes:
    """Base32 text to key bytes, tolerating the spaces and lower case a human
    introduces when typing it in, and re-adding the padding b32decode wants."""
    cleaned = (secret or "").replace(" ", "").replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned, casefold=True)


def code_at(secret: str, counter: int, *, digits: int = DIGITS) -> str:
    """The HOTP value for an explicit counter (RFC 4226 section 5.3)."""
    mac = hmac.new(normalise_secret(secret), struct.pack(">Q", int(counter)),
                   hashlib.sha1).digest()
    offset = mac[-1] & 0x0F                        # dynamic truncation
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def counter_at(when: Optional[float] = None, *, period: int = PERIOD) -> int:
    return int((time.time() if when is None else when) // period)


def code_now(secret: str, *, when: Optional[float] = None) -> str:
    return code_at(secret, counter_at(when))


def verify(secret: str, code: str, *, when: Optional[float] = None,
           drift: int = DEFAULT_DRIFT_STEPS,
           after_counter: int = -1) -> Optional[int]:
    """Check a code. Returns the COUNTER it matched, or None.

    The counter rather than a bool, so the caller can persist it and refuse a
    replay. `after_counter` is the last one accepted for this operator, so a
    code cannot be used twice even inside its own still-valid window.

    Comparison is constant-time: six digits is a small space, and a timing side
    channel on the comparison would narrow it further.
    """
    cleaned = (code or "").strip().replace(" ", "")
    if not cleaned.isdigit() or len(cleaned) != DIGITS:
        return None
    now = counter_at(when)
    for step in range(-abs(drift), abs(drift) + 1):
        candidate = now + step
        if candidate <= after_counter:
            continue                      # already used: a replay, not a match
        if hmac.compare_digest(code_at(secret, candidate), cleaned):
            return candidate
    return None


def provisioning_uri(secret: str, account: str, *, issuer: str = ISSUER) -> str:
    """The `otpauth://` URI an authenticator app consumes.

    Offered three ways on the enrolment screen, and they are not redundant: as a
    QR to scan, as a LINK (tapping it on a phone opens the authenticator with
    nothing to scan) and as the bare secret for "enter a setup key", which is
    what works when the camera is unavailable or the screen is being shared.

    Enrolment is not active until a code generated from it has been typed back,
    so a failed scan or transcription cannot lock anyone out — it just does not
    enrol.
    """
    label = quote("%s:%s" % (issuer, account), safe="")
    return ("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d"
            "&period=%d" % (label, secret, quote(issuer, safe=""), ALGORITHM,
                            DIGITS, PERIOD))


def format_secret(secret: str, *, group: int = 4) -> str:
    """`ABCD EFGH ...` — grouped for a human reading it off a screen."""
    value = (secret or "").upper()
    return " ".join(value[i:i + group] for i in range(0, len(value), group))


# ── recovery codes ─────────────────────────────────────────────────────────
#: Without these a lost or wiped phone is a permanently locked account, and the
#: only way back is another administrator — which, for the FIRST one, is nobody.
RECOVERY_CODE_COUNT = 10

#: No l/1/o/0: these get read aloud down a phone line from a substation.
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> List[str]:
    """Single-use fallbacks, shown once at enrolment and stored only as hashes."""
    def one() -> str:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        return "%s-%s" % (raw[:5], raw[5:])
    return [one() for _ in range(count)]


def recovery_fingerprint(code: str) -> str:
    """What the database stores.

    SHA-256, not PBKDF2, and for the same reason as session tokens: these are 50
    bits of uniform randomness with no structure to guess at, so stretching buys
    nothing and would put a deliberate delay on a login path. What it does buy
    is that a leaked table yields no usable codes.
    """
    normalised = (code or "").strip().lower().replace(" ", "").replace("-", "")
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()
