"""
Enrolment tokens and the policy for issuing against them (Phase 6, decision Q4).

A collector arrives at a substation with no certificate, so the endpoint that
gives it one cannot be authenticated by a certificate. That single fact shapes
everything here: `/api/v1/enrol` is the only route in this server not behind
mutual TLS, and a bearer token is all that stands in front of it.

WHAT THE TOKEN IS, AND WHAT IT IS NOT
─────────────────────────────────────
It is a one-time credential that names a collector and a site *before* the
collector exists. It is minted by an operator through the estate plane, carried
to the plant by whatever means the operator already trusts for such things, and
redeemed exactly once.

It is NOT a password. It is not reusable, it is not memorable, and it is never
stored: the server keeps only its SHA-256, so a copy of the database does not
yield a working enrolment credential for a fleet that has not deployed yet.

THE TWO WAYS THIS GOES WRONG
────────────────────────────
**Redeeming twice.** Check-then-use is two statements, and between them a second
request can pass the same check. Two collectors then hold valid certificates
naming the same identity, both report, and the console shows one collector with
an inventory that does not match either plant. The redemption here is a single
conditional UPDATE, in the store, and the row it returns is the proof of
exclusive claim — see `Store.redeem_enrolment_token`.

**Re-enrolling a live collector.** A token stolen from an email thread, replayed
against a collector that has been running for a year, would mint a second valid
identity for it. Nothing breaks; both certificates work; the attacker reports
whatever it likes into that site's inventory alongside the real device.

So issuing to a collector that already holds a valid certificate is REFUSED
unless the operator said so when minting the token — and when they did, the
existing certificates are revoked as part of issuing rather than left alongside
the new one. A fleet identity is single-holder by construction: if two things
present certificates for the same collector, one of them is lying, and the
server should never have made that state reachable.
"""
from __future__ import annotations

import datetime
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import List, Optional

#: How long a minted token stays redeemable. A site visit, not a season: the
#: token is a bearer credential for a fleet identity, and every hour it stays
#: valid is an hour it can be replayed from a mailbox.
DEFAULT_TOKEN_TTL_HOURS = 24

#: Enough entropy that guessing is not a strategy, in a shape a person can paste
#: out of a ticket without transcription errors.
TOKEN_BYTES = 32

#: X.509 caps a CommonName at 64 characters (ub-common-name). A longer name is
#: rejected when the certificate is BUILT, which without this check happens in a
#: substation, minutes after the token was handed over, with the token spent.
#: Refusing at mint time puts the failure in front of the operator who caused it.
MAX_NAME = 64


class EnrolmentError(RuntimeError):
    pass


@dataclass
class MintedToken:
    """The plaintext exists only here, on the way out of `mint`."""

    token: str
    token_hash: str
    collector_id: str
    site: str
    expires_at: datetime.datetime
    allow_reissue: bool


def hash_token(token: str) -> str:
    """What the server stores. The plaintext is never written anywhere."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def mint(collector_id: str, site: str = "",
         ttl_hours: int = DEFAULT_TOKEN_TTL_HOURS,
         allow_reissue: bool = False,
         now: Optional[datetime.datetime] = None) -> MintedToken:
    """Create a token for one collector.

    `collector_id` and `site` are fixed at mint time and are what the issued
    certificate will name. They are deliberately not parameters of the enrolment
    request: a collector that could name itself could enrol into another plant's
    site scope, and every asset it reported afterwards would merge into that
    plant's inventory.
    """
    if not collector_id or not collector_id.strip():
        raise EnrolmentError("an enrolment token must name a collector")

    collector_id, site = collector_id.strip(), (site or "").strip()
    for label, value in (("collector id", collector_id), ("site", site)):
        if len(value) > MAX_NAME:
            raise EnrolmentError(
                "the %s is %d characters; X.509 caps a name at %d. This token "
                "would be redeemable right up to the moment the certificate is "
                "built, in a substation, and then fail."
                % (label, len(value), MAX_NAME))
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            raise EnrolmentError(
                "the %s contains a control character; it would not survive "
                "being written into a certificate subject" % label)

    if ttl_hours <= 0:
        raise EnrolmentError(
            "a token with no lifetime is a token that never expires or never "
            "works; neither is a useful thing to mint")

    now = now or datetime.datetime.now(datetime.timezone.utc)
    token = secrets.token_urlsafe(TOKEN_BYTES)
    return MintedToken(
        token=token,
        token_hash=hash_token(token),
        collector_id=collector_id,
        site=site,
        expires_at=now + datetime.timedelta(hours=ttl_hours),
        allow_reissue=bool(allow_reissue))


@dataclass
class IssueDecision:
    """Whether to issue, and what issuing implies for what is already out there."""

    ok: bool
    reason: str = ""
    #: Certificates to revoke as part of issuing. Never left alongside the new
    #: one: two valid certificates for one identity is a state the server should
    #: not be able to reach.
    supersede: List[str] = field(default_factory=list)


def decide_issue(active_serials: List[str], allow_reissue: bool) -> IssueDecision:
    """Whether a redeemed token may produce a certificate.

    `active_serials` is every unrevoked, unexpired certificate already held by
    this collector.
    """
    if not active_serials:
        return IssueDecision(ok=True, reason="first enrolment")
    if not allow_reissue:
        return IssueDecision(
            ok=False,
            reason=("this collector already holds %d valid certificate(s). "
                    "Issuing another would put two identities in the fleet that "
                    "the server cannot tell apart, so a replayed token cannot "
                    "quietly clone a running collector. Mint the token with "
                    "reissue allowed if you are deliberately replacing it."
                    % len(active_serials)))
    return IssueDecision(
        ok=True,
        reason="reissue permitted; %d existing certificate(s) revoked as "
               "superseded" % len(active_serials),
        supersede=list(active_serials))


@dataclass
class RenewalDecision:
    ok: bool
    reason: str = ""


def decide_renewal(not_after: datetime.datetime,
                   revoked: bool,
                   now: Optional[datetime.datetime] = None) -> RenewalDecision:
    """Whether a certificate may be exchanged for a fresh one.

    Renewal authenticates with the certificate being renewed, which means the
    holder has already proven it is the collector. The only questions left are
    whether that certificate is still one this server honours.

    A REVOKED certificate may not renew — that is the whole point of revoking
    it, and a renewal path that ignored revocation would hand the holder a fresh
    90 days.

    An EXPIRED one may not either, and this is the sharper edge: allowing it
    would mean a certificate never truly stops working, only pauses. A collector
    that has been off for longer than its certificate's life re-enrols with a
    token, which puts a person back in the loop for a device nobody has seen in
    three months.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if revoked:
        return RenewalDecision(
            ok=False,
            reason="this certificate is revoked; renewing it would hand its "
                   "holder a fresh certificate and undo the revocation")
    if not_after <= now:
        return RenewalDecision(
            ok=False,
            reason="this certificate has expired. Re-enrol with a token rather "
                   "than renewing: a certificate that can always be renewed "
                   "never really expires, it only pauses")
    return RenewalDecision(ok=True, reason="renewed from a valid certificate")


def expiring_within(not_after: datetime.datetime, days: int,
                    now: Optional[datetime.datetime] = None) -> bool:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return not_after <= now + datetime.timedelta(days=days)
