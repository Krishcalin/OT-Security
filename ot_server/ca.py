"""
The fleet certificate authority (decision Q4, OTS-TRN-002).

Enrolment and revocation stay inside the product rather than depending on an
external PKI process at each site. The CA private key is generated on the server
at install and never leaves it.

THE SUBJECT COMES FROM THE ENROLMENT RECORD, NEVER FROM THE CSR
──────────────────────────────────────────────────────────────
A certificate signing request carries a subject, and the obvious implementation
signs it. That would be the same mistake `api.collector_identity` exists to
avoid, made one layer lower and with worse consequences: the CSR is data the
caller controls, so a collector could request `CN=pi-substation-01` and receive
a certificate that authenticates it as another site's collector. It would then
report assets into that site's inventory, and every request afterwards would
look perfectly ordinary — the identity really was issued by this CA.

So the CSR is used for exactly one thing: its public key, and the proof that the
requester holds the matching private key. The name is ours.

WHAT ELSE IS REFUSED, AND WHY EACH ONE MATTERS
──────────────────────────────────────────────
A CA that signs whatever it is handed is a CA that has delegated its policy to
whoever is asking.

- **A CSR whose self-signature does not verify.** Without that check the
  requester need not hold the private key, and a certificate can be issued for
  somebody else's public key — the holder of which can then authenticate as this
  collector without ever having spoken to us.
- **Weak keys.** RSA below 2048 bits and curves other than P-256/P-384. A key
  size is chosen once and lives as long as the fleet.
- **serverAuth.** These certificates are `clientAuth` only. A collector
  certificate that can also authenticate a server is one that can terminate TLS
  for the ingest endpoint, and the fleet would report to it happily.
- **CA:TRUE.** A collector that could sign is a collector that could enrol the
  rest of the fleet.

SHORT LIVED ON PURPOSE
──────────────────────
Certificates are issued for 90 days. Revocation in this product is enforced by
the server checking every request against its own issuance record, so it is
immediate — but a short lifetime means a collector that is decommissioned,
stolen, or simply forgotten stops being able to report on a timescale someone
will notice, without anyone having to remember to revoke it.
"""
from __future__ import annotations

import datetime
import os
import stat
from dataclasses import dataclass
from typing import Optional

CA_KEY_NAME = "ca-key.pem"
CA_CERT_NAME = "ca-cert.pem"

#: How long an issued collector certificate is valid. See the module docstring.
DEFAULT_CERT_DAYS = 90

#: How long the CA itself is valid. Long, because rotating it means re-enrolling
#: every collector in every substation.
DEFAULT_CA_DAYS = 3650

MIN_RSA_BITS = 2048
ALLOWED_CURVES = ("secp256r1", "secp384r1")


class CaError(RuntimeError):
    """A refusal to issue, or a CA that cannot be trusted to issue."""


@dataclass
class IssuedCertificate:
    """What was issued, in the terms the server records and checks later."""

    pem: str
    serial: str
    subject: str
    collector_id: str
    fingerprint: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    #: Anything the issuer had to decide that the caller should know. Empty in
    #: the ordinary case; set when the lifetime was shortened to the CA's own.
    note: str = ""


def _crypto():
    """Import lazily so the module, its constants and its errors stay importable
    on a machine without the dependency — the same reason `api.py` imports
    FastAPI inside `create_app`."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as exc:                             # pragma: no cover
        raise CaError(
            "the fleet CA needs `cryptography` (see ot_server/requirements.txt). "
            "Enrolment is unavailable without it, which is why the enrolment "
            "endpoints answer 503 rather than accepting a request they cannot "
            "complete.") from exc
    return x509, hashes, serialization, ec, rsa, ExtendedKeyUsageOID, NameOID


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class CertificateAuthority:
    """The fleet CA. Constructed through `create`, `load` or `load_or_create`."""

    def __init__(self, key, certificate, directory: str):
        self._key = key
        self._certificate = certificate
        self.directory = directory

    # ── lifecycle ─────────────────────────────────────────────────────────

    @classmethod
    def create(cls, directory: str, common_name: str = "OT Sensor Fleet CA",
               days: int = DEFAULT_CA_DAYS) -> "CertificateAuthority":
        x509, hashes, serialization, ec, _rsa, _eku, NameOID = _crypto()

        os.makedirs(directory, exist_ok=True)
        key_path = os.path.join(directory, CA_KEY_NAME)
        if os.path.exists(key_path):
            raise CaError(
                "a CA key already exists at %s. Overwriting it would orphan "
                "every certificate in the fleet: the collectors would keep "
                "presenting certificates this server can no longer verify, and "
                "the fleet would go silent one site at a time." % key_path)

        key = ec.generate_private_key(ec.SECP384R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = _utcnow()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                           critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA384()))

        # 0600 before anything is written into it. A CA key that spends even a
        # moment world-readable on a shared host has to be treated as disclosed,
        # and nothing afterwards would show that it had been.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        handle = os.open(key_path, flags, 0o600)
        with os.fdopen(handle, "wb") as fh:
            fh.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
        with open(os.path.join(directory, CA_CERT_NAME), "wb") as fh:
            fh.write(certificate.public_bytes(serialization.Encoding.PEM))
        return cls(key, certificate, directory)

    @classmethod
    def load(cls, directory: str) -> "CertificateAuthority":
        x509, _hashes, serialization, _ec, _rsa, _eku, _name = _crypto()

        key_path = os.path.join(directory, CA_KEY_NAME)
        cert_path = os.path.join(directory, CA_CERT_NAME)
        for path in (key_path, cert_path):
            if not os.path.isfile(path):
                raise CaError("no fleet CA at %s" % directory)

        _refuse_readable_key(key_path)
        with open(key_path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        with open(cert_path, "rb") as fh:
            certificate = x509.load_pem_x509_certificate(fh.read())
        return cls(key, certificate, directory)

    @classmethod
    def load_or_create(cls, directory: str) -> "CertificateAuthority":
        try:
            return cls.load(directory)
        except CaError:
            if os.path.isfile(os.path.join(directory, CA_KEY_NAME)):
                raise            # it exists and is unusable; do not paper over it
            return cls.create(directory)

    # ── issuing ───────────────────────────────────────────────────────────

    @property
    def ca_pem(self) -> str:
        _x509, _hashes, serialization, _ec, _rsa, _eku, _name = _crypto()
        return self._certificate.public_bytes(
            serialization.Encoding.PEM).decode("ascii")

    def sign(self, csr_pem: str, collector_id: str, site: str = "",
             days: int = DEFAULT_CERT_DAYS) -> IssuedCertificate:
        """Issue a client certificate for `collector_id`.

        `collector_id` comes from the redeemed enrolment token or from the
        certificate being renewed — never from the request body, and never from
        the CSR's own subject. See the module docstring.
        """
        x509, hashes, serialization, ec, rsa, ExtendedKeyUsageOID, NameOID = \
            _crypto()

        if not collector_id or not collector_id.strip():
            raise CaError("refusing to issue a certificate with no identity")

        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        except Exception as exc:                           # noqa: BLE001
            raise CaError("the certificate request could not be parsed") from exc

        # Proof of possession. Without it a certificate can be issued over
        # somebody else's public key, and its holder authenticates as this
        # collector without ever having contacted us.
        if not csr.is_signature_valid:
            raise CaError(
                "the certificate request is not signed by the key it presents, "
                "so the requester has not shown it holds the private key")

        _refuse_weak_key(csr.public_key(), ec, rsa)

        now = _utcnow()

        # A certificate cannot usefully outlive its issuer: it verifies against
        # nothing once the CA has expired, and the failure surfaces as a TLS
        # handshake error in a substation with no clue pointing back here.
        ca_expiry = self._certificate.not_valid_after_utc
        if ca_expiry <= now:
            raise CaError(
                "this CA expired on %s and cannot issue. Every certificate it "
                "signed now is unverifiable from the moment it is written. "
                "Create a new CA and re-enrol the fleet." % ca_expiry.isoformat())

        note = ""
        wanted = now + datetime.timedelta(days=days)
        if wanted > ca_expiry:
            # Shortened rather than refused: refusing would stop enrolment dead
            # for the last 90 days of a CA's life, which is exactly when a
            # replacement collector is most likely to be installed. Shortened
            # AND SAID, because a silently short certificate is a renewal
            # deadline nobody was told about.
            note = ("lifetime shortened to the CA's own expiry (%s); plan a CA "
                    "rotation before then" % ca_expiry.isoformat())
            wanted = ca_expiry
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, collector_id),
        ] + ([x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, site)]
             if site else []))

        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            # Backdated slightly: a collector whose clock is a minute fast would
            # otherwise reject the certificate it just enrolled for, and the
            # failure would look like a signing fault.
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(wanted)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            # clientAuth ONLY. A collector certificate that could also
            # authenticate a server could terminate TLS for the ingest endpoint,
            # and the rest of the fleet would report to it without complaint.
            .add_extension(x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
            .sign(self._key, hashes.SHA384()))

        return IssuedCertificate(
            pem=certificate.public_bytes(
                serialization.Encoding.PEM).decode("ascii"),
            serial=format(certificate.serial_number, "x"),
            subject=certificate.subject.rfc4514_string(),
            collector_id=collector_id,
            fingerprint=fingerprint_of(certificate),
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            note=note)


def fingerprint_of(certificate) -> str:
    """The SHA-256 fingerprint, lowercase hex, no colons.

    This is the identity the server checks on every request. The subject is a
    name and names can be reissued; the fingerprint identifies one certificate,
    which is what revocation actually revokes.
    """
    _x509, hashes, _serialization, _ec, _rsa, _eku, _name = _crypto()
    return certificate.fingerprint(hashes.SHA256()).hex()


def fingerprint_of_pem(pem: str) -> str:
    x509, _hashes, _serialization, _ec, _rsa, _eku, _name = _crypto()
    return fingerprint_of(x509.load_pem_x509_certificate(pem.encode("ascii")))


def fingerprint_of_escaped_pem(value: str) -> str:
    """The digest of a certificate a terminator passed in a header.

    nginx's `$ssl_client_escaped_cert` is the PEM with newlines
    percent-encoded, because a raw PEM cannot travel in an HTTP header at
    all. Some deployments also flatten it to one line or wrap it in quotes;
    both are tolerated, because the alternative is a deployment that looks
    exactly like a fleet which never enrolled.
    """
    import urllib.parse

    text = urllib.parse.unquote(value.strip().strip(chr(34)))
    if "BEGIN CERTIFICATE" not in text:
        raise CaError("this is not a PEM certificate")

    newline = chr(10)
    if newline not in text:
        # Flattened somewhere in the chain. Rebuild the block.
        body = (text.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .strip().replace(" ", ""))
        wrapped = [body[i:i + 64] for i in range(0, len(body), 64)]
        text = (("-----BEGIN CERTIFICATE-----" + newline)
                + newline.join(wrapped)
                + (newline + "-----END CERTIFICATE-----" + newline))
    return fingerprint_of_pem(text)


def normalise_fingerprint(value: str) -> str:
    """Accept the shapes a TLS terminator might send.

    nginx writes `SHA256:...` base64, HAProxy writes hex, and people paste
    colon-separated hex out of `openssl x509`. Normalising here means a
    deployment does not silently fail to match every certificate it holds, which
    would look exactly like a fleet that had not enrolled.
    """
    value = (value or "").strip()
    if value.upper().startswith("SHA256:"):
        value = value[7:]
    return value.replace(":", "").replace(" ", "").lower()


def _refuse_weak_key(public_key, ec, rsa) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < MIN_RSA_BITS:
            raise CaError(
                "refusing a %d-bit RSA key; the floor is %d. A key size is "
                "chosen once and lives as long as the fleet."
                % (public_key.key_size, MIN_RSA_BITS))
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name not in ALLOWED_CURVES:
            raise CaError(
                "refusing curve %s; this CA issues over %s"
                % (public_key.curve.name, " or ".join(ALLOWED_CURVES)))
        return
    raise CaError(
        "refusing an unsupported key type (%s). Signing a key whose properties "
        "this CA cannot state is signing a key it cannot vouch for."
        % type(public_key).__name__)


def _refuse_readable_key(path: str) -> None:
    """A CA key readable by anyone but its owner is a disclosed CA key.

    Loading it anyway would mean the server keeps issuing certificates from a
    key it has no reason to believe is still private, and nothing downstream
    would show that anything was wrong.
    """
    try:
        mode = os.stat(path).st_mode
    except OSError:                                        # pragma: no cover
        return
    if os.name == "nt":
        # Windows permissions are not POSIX mode bits; st_mode says nothing
        # useful here. Refusing on it would fail every developer machine, and
        # pretending to have checked would be worse than not checking.
        return
    if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
        raise CaError(
            "the CA private key at %s is readable or writable beyond its owner "
            "(mode %o). Treat it as disclosed: issue a new CA and re-enrol the "
            "fleet rather than continuing to sign with it." % (path, mode & 0o777))


def available() -> bool:
    """Whether a CA can be built at all on this machine."""
    try:
        _crypto()
    except CaError:
        return False
    return True


def load_configured(directory: Optional[str]) -> Optional["CertificateAuthority"]:
    """The CA for a deployment, or None if enrolment is not configured.

    None is not a degraded mode that quietly issues nothing: the enrolment
    endpoints answer 503 and say so, exactly as the estate plane does without
    operator authentication.
    """
    if not directory:
        return None
    return CertificateAuthority.load_or_create(directory)
