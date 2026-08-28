"""
Content packs — signed detection content, distributed to the fleet.

`rulepack.py` on the collector already answers "which logic produced this
finding" by content-hashing the rule sources it was built with. What it cannot
do is change them: updating a rule today means rebuilding the collector wheel
and driving to the substation. This is the channel that fixes that.

TWO LANES, AND ONLY ONE OF THEM TOUCHES A COLLECTOR
───────────────────────────────────────────────────
Dragos split their Knowledge Packs into a weekly lane carrying only indicators
and vulnerabilities and a quarterly lane carrying everything else, because a
single monolithic pack was delaying the fast-moving half. The same split applies
here, and decision **D3 already gives us the better version of it**: the CVE,
KEV and EPSS corpus lives on the server and never ships to a Pi, so refreshing
it re-prioritises the whole estate without contacting a single collector.

So:

  `corpus` packs stay on the server. No fleet involvement at all.
  `rules`  packs go to collectors, signed, and are the only lane that does.

A PACK CARRIES DATA, NEVER CODE
───────────────────────────────
This is the load-bearing decision, and it is a deliberate departure from what
Dragos ships — their packs carry protocol dissection engines, which is to say
executable code.

A channel that delivers code to every collector in every substation and runs it
is a remote code execution path into the plant, by design, with the signing key
as the only thing standing in the way. That key sits on the server this same
codebase runs. The blast radius of one compromise becomes every controller
network the fleet can see.

So a pack carries declarative content — indicators, signature definitions,
advisory metadata — that a fixed interpreter on the collector applies. New
protocol *dissectors* still require a release, and that is the intended cost:
shipping a parser is shipping code, and it should require the same review and
the same deliberate act as any other release.

If that ever changes, it must change as its own decision with its own reasoning,
not by widening this one.

THE SIGNING KEY IS NOT THE CA KEY
─────────────────────────────────
The CA signs identities; this signs content. One key doing both means anyone who
can publish a detection update can also mint a collector identity, and anyone
who can mint an identity can publish content the fleet will run. They are
separate keys with separate blast radii, generated separately, and the
collector learns the content key at enrolment alongside the CA certificate.

Ed25519 rather than RSA or ECDSA-with-choices: one curve, one hash, no
parameters to get wrong, small signatures, and no way to configure it weakly.

A REPLAYED OLD PACK IS AN ATTACK
────────────────────────────────
Every pack this server has ever issued is correctly signed forever. An attacker
who can answer the collector's fetch — or simply replay a recorded response —
can therefore serve a genuine, valid, *old* pack, and the collector would apply
it happily and silently lose every detection added since.

So the version is monotonic and a collector refuses anything that is not
strictly newer than what it holds. Refusing is not enough on its own to be
useful, which is why the refusal is reported through the heartbeat: a fleet
stuck three versions behind is visible on the console rather than merely safe.
"""
# NOTE: no `from __future__ import annotations` — this module is imported by
# api.py's route factory, and the same annotation-resolution trap that turns
# `request: Request` into a query parameter applies to anything it touches.

import copy
import datetime
import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SIGNING_KEY_NAME = "content-key.pem"
PUBLIC_KEY_NAME = "content-key.pub"

#: The kinds of pack that exist. `corpus` never leaves the server (D3); `rules`
#: is the only kind a collector ever fetches.
KIND_RULES = "rules"
KIND_CORPUS = "corpus"
KINDS = (KIND_RULES, KIND_CORPUS)

#: What a rules pack is allowed to contain. A pack carrying anything else is
#: refused rather than partially applied — an unknown section is either a newer
#: format this collector cannot honour, or content somebody is trying to smuggle
#: past the interpreter, and both should stop here.
RULES_SECTIONS = ("indicators", "signatures", "advisories")


class PackError(RuntimeError):
    """A pack that cannot be built, signed, or trusted."""


@dataclass
class Verdict:
    """Whether a pack may be applied, and why not when it may not."""

    ok: bool
    reason: str = ""


@dataclass
class SignedPack:
    kind: str
    version: int
    created_at: str
    payload: Dict[str, Any]
    signature: str = ""
    #: SHA-256 of the canonical body. Recorded on every finding the pack
    #: produces, so a result can always be traced to the content behind it.
    digest: str = ""

    def body(self) -> Dict[str, Any]:
        return {"kind": self.kind, "version": self.version,
                "created_at": self.created_at, "payload": self.payload}

    def canonical(self) -> bytes:
        """The exact bytes that are signed and hashed.

        Sorted keys and no incidental whitespace, because a signature over
        "whatever json.dumps did today" is a signature that stops verifying when
        a library changes its default separators.
        """
        return json.dumps(self.body(), sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        out = self.body()
        out["signature"] = self.signature
        out["digest"] = self.digest
        return out

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "SignedPack":
        try:
            return cls(kind=str(raw["kind"]), version=int(raw["version"]),
                       created_at=str(raw["created_at"]),
                       payload=dict(raw["payload"]),
                       signature=str(raw.get("signature") or ""),
                       digest=str(raw.get("digest") or ""))
        except Exception as exc:                           # noqa: BLE001
            raise PackError("this is not a pack: %s" % type(exc).__name__)


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:                             # pragma: no cover
        raise PackError(
            "content signing needs `cryptography` (see "
            "ot_server/requirements.txt). Publishing is unavailable without "
            "it, which is why the routes answer 503 rather than distributing "
            "content nobody signed.") from exc
    return serialization, ed25519


def _utcnow_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest_of(pack: SignedPack) -> str:
    return hashlib.sha256(pack.canonical()).hexdigest()


class ContentSigner:
    """The key that signs content. Deliberately not the CA."""

    def __init__(self, private_key, directory: str):
        self._key = private_key
        self.directory = directory

    # ── lifecycle ─────────────────────────────────────────────────────────

    @classmethod
    def create(cls, directory: str) -> "ContentSigner":
        serialization, ed25519 = _crypto()

        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, SIGNING_KEY_NAME)
        if os.path.exists(path):
            raise PackError(
                "a content signing key already exists at %s. Replacing it "
                "would strand every collector holding the old public key: they "
                "would refuse each new pack as unsigned and keep running the "
                "content they have, silently, until somebody noticed." % path)

        key = ed25519.Ed25519PrivateKey.generate()
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(handle, "wb") as fh:
            fh.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
        with open(os.path.join(directory, PUBLIC_KEY_NAME), "wb") as fh:
            fh.write(key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
        return cls(key, directory)

    @classmethod
    def load(cls, directory: str) -> "ContentSigner":
        serialization, _ed25519 = _crypto()

        path = os.path.join(directory, SIGNING_KEY_NAME)
        if not os.path.isfile(path):
            raise PackError("no content signing key at %s" % directory)
        _refuse_readable_key(path)
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        return cls(key, directory)

    @classmethod
    def load_or_create(cls, directory: str) -> "ContentSigner":
        try:
            return cls.load(directory)
        except PackError:
            if os.path.isfile(os.path.join(directory, SIGNING_KEY_NAME)):
                raise           # it exists and is unusable; do not paper over it
            return cls.create(directory)

    # ── signing ───────────────────────────────────────────────────────────

    @property
    def public_key_pem(self) -> str:
        serialization, _ed25519 = _crypto()
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def sign(self, kind: str, version: int, payload: Dict[str, Any],
             created_at: Optional[str] = None) -> SignedPack:
        if kind not in KINDS:
            raise PackError("unknown pack kind %r; expected one of %s"
                            % (kind, ", ".join(KINDS)))
        if kind == KIND_RULES:
            check_rules_payload(payload)
        if int(version) < 1:
            raise PackError("a pack version starts at 1 and only goes up")

        # A DEEP copy. `dict(payload)` shares every nested list and object with
        # the caller, so a pack could be edited after it was signed and its
        # signature would no longer cover what it carries. For an artifact whose
        # whole job is to be tamper-evident, that is the wrong default — and it
        # surfaced first as one test's tampering leaking into the next.
        pack = SignedPack(kind=kind, version=int(version),
                          created_at=created_at or _utcnow_iso(),
                          payload=copy.deepcopy(payload))
        pack.signature = self._key.sign(pack.canonical()).hex()
        pack.digest = digest_of(pack)
        return pack


def check_rules_payload(payload: Dict[str, Any]) -> None:
    """A rules pack carries data, and only the data this collector understands.

    An unrecognised section is either a newer format than the interpreter on the
    far end, or content somebody is trying to smuggle past it. Neither should be
    applied in part.
    """
    if not isinstance(payload, dict):
        raise PackError("a rules payload is an object of named sections")
    unknown = sorted(set(payload) - set(RULES_SECTIONS))
    if unknown:
        raise PackError(
            "a rules pack may carry %s and nothing else; found %s. A pack "
            "carries DATA, never code — see the module docstring."
            % (", ".join(RULES_SECTIONS), ", ".join(unknown)))
    for section, entries in payload.items():
        if not isinstance(entries, list):
            raise PackError("section %r must be a list" % section)
        for entry in entries:
            if not isinstance(entry, dict):
                raise PackError("every entry in %r must be an object" % section)


def verify(public_key_pem: str, raw: Dict[str, Any], *,
           current_version: int = 0,
           expect_kind: str = KIND_RULES) -> Verdict:
    """Whether this pack may be applied. Every refusal names its own cause.

    `current_version` is what the caller already holds. A pack that is not
    strictly newer is refused even when its signature is perfect, because every
    pack this server ever issued stays correctly signed forever — so a recorded
    old one, replayed, would silently roll the fleet back past every detection
    added since.
    """
    serialization, ed25519 = _crypto()

    try:
        pack = SignedPack.from_dict(raw)
    except PackError as exc:
        return Verdict(False, str(exc))

    if pack.kind != expect_kind:
        return Verdict(False, "this is a %r pack; expected %r"
                              % (pack.kind, expect_kind))
    if not pack.signature:
        return Verdict(False, "this pack is unsigned")

    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, ed25519.Ed25519PublicKey):
            return Verdict(False, "the verification key is not an Ed25519 key")
        key.verify(bytes.fromhex(pack.signature), pack.canonical())
    except Exception:                                      # noqa: BLE001
        # Deliberately undifferentiated: a bad signature, a tampered payload and
        # a malformed key are the same event to a collector — content it must
        # not run — and telling an attacker which one they achieved is telling
        # them how close they are.
        return Verdict(False, "this pack is not signed by the key this "
                              "collector was enrolled with")

    if pack.digest and pack.digest != digest_of(pack):
        return Verdict(False, "the pack digest does not match its content")

    if pack.version <= int(current_version):
        return Verdict(
            False,
            "this pack is version %d and version %d is already held. A "
            "correctly signed OLD pack is what a replay looks like, so it is "
            "refused rather than applied." % (pack.version, current_version))

    if pack.kind == KIND_RULES:
        try:
            check_rules_payload(pack.payload)
        except PackError as exc:
            return Verdict(False, str(exc))

    return Verdict(True, "version %d, %s" % (pack.version, describe(pack)))


def describe(pack: SignedPack) -> str:
    counts = ["%d %s" % (len(pack.payload.get(section) or []), section)
              for section in RULES_SECTIONS
              if pack.payload.get(section)]
    return ", ".join(counts) or "empty"


@dataclass
class FleetDrift:
    """Which collectors are behind, and by how much.

    Refusing a bad pack keeps a collector safe and leaves it running old
    content. Safe and stale is a state somebody has to be able to SEE, or the
    fleet quietly stops detecting things nobody removed.
    """

    latest: int = 0
    current: List[str] = field(default_factory=list)
    behind: List[Dict[str, Any]] = field(default_factory=list)
    unknown: List[str] = field(default_factory=list)

    @property
    def all_current(self) -> bool:
        return not self.behind and not self.unknown

    def explain(self) -> str:
        if self.latest == 0:
            return "no rules pack has been published"
        if self.all_current:
            return ("every collector is on version %d" % self.latest)
        parts = []
        if self.behind:
            parts.append("%d behind" % len(self.behind))
        if self.unknown:
            parts.append("%d have not reported a version" % len(self.unknown))
        return ("version %d published; %s — a collector left behind keeps "
                "running old content and will not report what the new pack "
                "would have found" % (self.latest, ", ".join(parts)))


def fleet_drift(latest_version: int,
                reported: Dict[str, Any]) -> FleetDrift:
    """`reported` maps collector_id -> the pack version it last announced."""
    drift = FleetDrift(latest=int(latest_version or 0))
    for collector_id, version in sorted(reported.items()):
        if version in (None, "", 0):
            drift.unknown.append(collector_id)
        elif int(version) >= drift.latest:
            drift.current.append(collector_id)
        else:
            drift.behind.append({"collector_id": collector_id,
                                 "version": int(version),
                                 "behind_by": drift.latest - int(version)})
    return drift


def _refuse_readable_key(path: str) -> None:
    """A signing key readable beyond its owner is a disclosed signing key, and
    a disclosed content key is the fleet running whatever its holder writes."""
    try:
        mode = os.stat(path).st_mode
    except OSError:                                        # pragma: no cover
        return
    if os.name == "nt":
        # Windows permissions are not POSIX mode bits. Refusing on them would
        # fail every developer machine, and pretending to have checked would be
        # worse than not checking.
        return
    if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
        raise PackError(
            "the content signing key at %s is readable or writable beyond its "
            "owner (mode %o). Treat it as disclosed: every collector will run "
            "content signed with it." % (path, mode & 0o777))
