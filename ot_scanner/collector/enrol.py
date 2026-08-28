"""
Collector enrolment (Phase 6, decision Q4).

    python -m collector.enrol --server https://fleet.example \\
        --collector-id pi-substation-01 --token <one-time token> \\
        --dest /etc/ot-collector/pki --ca-fingerprint <sha256 of the fleet CA>

Produces the three files `TransportConfig` already refuses to start without:
a private key, a certificate signed by the fleet CA, and the CA bundle to verify
the server with. Until this existed, that configuration named files nothing in
the product could produce.

WHY openssl AND NOT `cryptography`
──────────────────────────────────
`manifest.RUNTIME_REQUIRES` is `("dpkt>=1.9.8",)` and a test asserts that exact
tuple. The minimality argument behind it is not decoration: every dependency
here is a dependency on a fleet of Raspberry Pis in substations, updated by
people who have to drive there. openssl already ships with Raspberry Pi OS, so
key generation and CSR creation shell out to it and the ratchet holds.

The cost is real and worth stating: subprocess output has to be parsed, and a
missing binary is a failure at enrolment rather than at import. So openssl is
checked for first, and the check names what is missing.

THE PRIVATE KEY IS GENERATED HERE AND NEVER LEAVES
──────────────────────────────────────────────────
The server signs a public key; it never sees the private one. A design where the
server generated the pair and sent it back would be simpler — no openssl on the
Pi at all — and would put every collector's private key on the network and in
the server's memory, which is the thing "the CA private key never leaves the
server" was written to prevent, applied to the wrong key.

THE BOOTSTRAP PROBLEM, STATED PLAINLY
─────────────────────────────────────
This is the one moment a collector talks to the server without already trusting
it: the CA bundle is what it came here to fetch. Something must anchor that
first connection, so this refuses to run without one of two things:

  --server-ca PATH        verify the TLS connection against a bundle the
                          operator brought with them. The strongest option: an
                          interceptor cannot complete the connection at all.

  --ca-fingerprint HEX    verify the CA certificate against a fingerprint
                          the operator brought with them. The channel may be
                          intercepted, but the interceptor cannot produce a CA
                          certificate matching the fingerprint, so the enrolment
                          fails LOUDLY rather than succeeding against the wrong
                          server.

Both may be given. Neither may be omitted: trust on first use, here, means a
substation collector that reports a plant's inventory to whoever answered.

THE TOKEN IS OFFERED LAST
─────────────────────────
The fingerprint is checked against `GET /api/v1/ca` BEFORE the token is sent and
before a key is generated. The first version checked it against the enrolment
response instead, and running the flow end to end showed what that costs: a
mistyped fingerprint spent the token, left the server holding an issued
certificate nobody had, and blocked the next legitimate enrolment of that
collector with "it already holds a valid certificate". Three problems from one
typo, all needing an operator to unpick.

The token is the scarce thing in this exchange. Everything that can be checked
without it is checked first.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional

KEY_NAME = "collector-key.pem"
CERT_NAME = "collector-cert.pem"
CA_NAME = "ca-cert.pem"
#: The content verification key, written beside the CA bundle. `content.py`
#: reads it by this name and applies nothing without it.
CONTENT_KEY_NAME = "content-key.pub"

#: P-256. Small keys, fast handshakes on a Pi, and universally supported.
CURVE = "prime256v1"

TIMEOUT = 30.0


class EnrolmentError(RuntimeError):
    """Anything that stops a collector obtaining a usable identity."""


# ── openssl ────────────────────────────────────────────────────────────────

def openssl_path() -> str:
    path = shutil.which("openssl") or shutil.which("openssl.exe")
    if path is None:
        raise EnrolmentError(
            "openssl is not on PATH. The collector generates its own key with "
            "it rather than carrying a crypto library (see the module "
            "docstring); install it with `apt-get install openssl`.")
    return path


def _run(args: List[str], stdin: Optional[bytes] = None) -> bytes:
    proc = subprocess.run([openssl_path()] + args, input=stdin,
                          capture_output=True, timeout=120)
    if proc.returncode != 0:
        raise EnrolmentError(
            "openssl %s failed: %s"
            % (args[0], proc.stderr.decode("utf-8", "replace").strip()[:400]))
    return proc.stdout


def generate_key(dest: str) -> str:
    """Write a new EC private key, readable only by its owner — or reuse the
    one already there if no certificate accompanies it.

    Generated to stdout and written here rather than with `-out`, so the file
    never exists with permissions from the ambient umask. A key that is
    world-readable for even a moment has to be treated as disclosed, and nothing
    afterwards would show that it had been.
    """
    os.makedirs(dest, exist_ok=True)
    path = os.path.join(dest, KEY_NAME)
    if os.path.exists(path):
        # A key with a certificate beside it is a live identity, and generating
        # over it would orphan that certificate — the collector would keep the
        # cert it can no longer use and stop being able to report.
        #
        # A key with NO certificate is the debris of an enrolment that failed
        # partway, which is a thing that happens in a substation with a laptop
        # balanced on a cabinet. Refusing there would make the retry harder than
        # the original attempt, so the key is reused: it is a key, not an
        # identity, and nothing has been issued over it.
        if os.path.exists(os.path.join(dest, CERT_NAME)):
            raise EnrolmentError(
                "a key and certificate already exist in %s. Enrolling over them "
                "would orphan that certificate and this collector would stop "
                "being able to report. Move them aside deliberately if you are "
                "replacing this identity." % dest)
        return path

    pem = _run(["genpkey", "-algorithm", "EC",
                "-pkeyopt", "ec_paramgen_curve:%s" % CURVE,
                "-pkeyopt", "ec_param_enc:named_curve"])
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(handle, "wb") as fh:
        fh.write(pem)
    return path


def create_csr(key_path: str, collector_id: str) -> str:
    """A certificate signing request over the collector's key.

    The subject here is DECORATIVE. openssl requires one, but the server
    replaces it with the identity from the redeemed enrolment token — a CSR that
    could name itself could ask to be issued as another site's collector. It is
    set to the expected id anyway, so a mismatch is visible when someone reads
    the request rather than silently discarded.
    """
    pem = _run(["req", "-new", "-key", key_path, "-sha256",
                "-subj", "/CN=%s" % collector_id])
    return pem.decode("ascii")


def public_key_of_key(key_path: str) -> str:
    return _run(["pkey", "-in", key_path, "-pubout"]).decode("ascii").strip()


def public_key_of_cert(cert_pem: str) -> str:
    return _run(["x509", "-pubkey", "-noout"],
                stdin=cert_pem.encode("ascii")).decode("ascii").strip()


def fingerprint_of_cert(cert_pem: str) -> str:
    """SHA-256, lowercase hex, no colons — the shape the server records."""
    out = _run(["x509", "-noout", "-fingerprint", "-sha256"],
               stdin=cert_pem.encode("ascii")).decode("ascii")
    _, _, value = out.partition("=")
    return value.strip().replace(":", "").lower()


def normalise_fingerprint(value: str) -> str:
    return (value or "").strip().replace(":", "").replace(" ", "").lower()


# ── the enrolment request ──────────────────────────────────────────────────

@dataclass
class EnrolmentResult:
    collector_id: str
    site: str
    serial: str
    not_after: str
    key_path: str
    cert_path: str
    ca_path: str
    #: Empty when the server has no content signing key, which means this
    #: collector cannot be updated remotely and will say so when asked to.
    content_key_path: str = ""


def _context(server_ca: Optional[str]):
    if server_ca:
        return ssl.create_default_context(cafile=server_ca)
    # Only reachable when --ca-fingerprint was supplied; `enrol` refuses
    # otherwise. The channel is unverified and the ARTIFACT is checked instead —
    # an interceptor cannot produce a CA certificate matching the fingerprint,
    # so enrolment fails visibly rather than completing against the wrong server.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _get(url: str, server_ca: Optional[str]) -> Dict:
    request = urllib.request.Request(url, method="GET",
                                     headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT,
                                    context=_context(server_ca)) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise EnrolmentError("the server would not publish its CA (%d): %s"
                             % (exc.code, detail))
    except Exception as exc:                               # noqa: BLE001
        raise EnrolmentError("could not reach %s: %s"
                             % (url, type(exc).__name__))


def _post(url: str, payload: Dict, server_ca: Optional[str]) -> Dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"})

    context = _context(server_ca)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT,
                                    context=context) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise EnrolmentError("the server refused enrolment (%d): %s"
                             % (exc.code, detail))
    except Exception as exc:                               # noqa: BLE001
        raise EnrolmentError("could not reach %s: %s"
                             % (url, type(exc).__name__))


def fetch_ca(server_url: str, server_ca: Optional[str] = None) -> str:
    """The fleet CA certificate, before authenticating anything.

    Unauthenticated on both sides on purpose: a CA certificate is the trust
    anchor everyone needs in order to verify anything at all, and it travels in
    the clear in every TLS handshake already.
    """
    url = server_url.rstrip("/") + "/api/v1/ca"
    body = _get(url, server_ca)
    pem = str(body.get("ca_certificate") or "")
    if not pem:
        raise EnrolmentError("the server returned no CA certificate")
    return pem


def enrol(server_url: str, token: str, collector_id: str, dest: str,
          server_ca: Optional[str] = None,
          ca_fingerprint: Optional[str] = None) -> EnrolmentResult:
    """Obtain a fleet identity. See the module docstring for the trust rules."""
    if not server_url.lower().startswith("https://"):
        raise EnrolmentError(
            "the enrolment server must be https:// — this exchange carries a "
            "one-time credential and returns this collector's identity")
    if not server_ca and not ca_fingerprint:
        raise EnrolmentError(
            "enrolment needs an anchor: --server-ca to verify the connection, "
            "or --ca-fingerprint to verify the CA certificate it returns. "
            "Without either, this collector would report a plant's inventory "
            "to whoever answered.")

    openssl_path()                     # fail here, not after the token is spent

    # Everything checkable without the token, first. See the module docstring.
    anchor_pem = ""
    if ca_fingerprint:
        anchor_pem = fetch_ca(server_url, server_ca)
        expected = normalise_fingerprint(ca_fingerprint)
        actual = fingerprint_of_cert(anchor_pem)
        if expected != actual:
            raise EnrolmentError(
                "this server's CA certificate does not match the fingerprint "
                "you supplied (%s, expected %s). The token has NOT been sent, "
                "so it is still good: check the fingerprint and the server "
                "address." % (actual, expected))

    key_path = generate_key(dest)
    csr = create_csr(key_path, collector_id)

    url = server_url.rstrip("/") + "/api/v1/enrol"
    body = _post(url, {"token": token, "csr": csr}, server_ca)

    certificate = str(body.get("certificate") or "")
    ca_certificate = str(body.get("ca_certificate") or "")
    if not certificate or not ca_certificate:
        raise EnrolmentError("the server returned no certificate")

    # The CA that signed must be the CA that was verified. Without this a server
    # could serve one anchor and issue under another, and the fingerprint check
    # above would be satisfied by a certificate nobody uses.
    if anchor_pem and fingerprint_of_cert(ca_certificate) != \
            fingerprint_of_cert(anchor_pem):
        raise EnrolmentError(
            "the CA returned with the certificate is not the one this server "
            "published; the token has been spent, so mint a new one")

    # The certificate must be over OUR key. A server that issued over somebody
    # else's public key would leave this collector holding a certificate it
    # cannot use, and the failure would surface much later as a TLS handshake
    # error with no obvious cause.
    if public_key_of_cert(certificate) != public_key_of_key(key_path):
        raise EnrolmentError(
            "the issued certificate is not over this collector's key")

    cert_path = os.path.join(dest, CERT_NAME)
    ca_path = os.path.join(dest, CA_NAME)
    written = [(cert_path, certificate), (ca_path, ca_certificate)]

    # The content verification key, when the server has one. A server without a
    # signing key distributes no content, so its absence here is not a failure —
    # it is a fleet that will not be updated remotely, and `content.py` says so
    # plainly rather than applying anything unverified.
    content_key = str(body.get("content_key") or "")
    content_key_path = os.path.join(dest, CONTENT_KEY_NAME)
    if content_key:
        written.append((content_key_path, content_key))

    for path, content in written:
        with open(path, "w", encoding="ascii") as fh:
            fh.write(content if content.endswith("\n") else content + "\n")

    return EnrolmentResult(
        collector_id=str(body.get("collector_id") or collector_id),
        site=str(body.get("site") or ""),
        serial=str(body.get("serial") or ""),
        not_after=str(body.get("not_after") or ""),
        key_path=key_path, cert_path=cert_path, ca_path=ca_path,
        content_key_path=content_key_path if content_key else "")


# ── CLI ────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="collector.enrol",
        description="Obtain this collector's fleet identity (Phase 6, Q4).")
    ap.add_argument("--server", required=True, help="https://fleet.example")
    ap.add_argument("--collector-id", required=True)
    ap.add_argument("--token", required=True,
                    help="one-time enrolment token, minted by an operator")
    ap.add_argument("--dest", required=True,
                    help="directory for the key, certificate and CA bundle")
    ap.add_argument("--server-ca",
                    help="CA bundle to verify the enrolment server with")
    ap.add_argument("--ca-fingerprint",
                    help="SHA-256 of the fleet CA certificate, checked against "
                         "what the server returns")
    args = ap.parse_args(argv)

    try:
        result = enrol(args.server, args.token, args.collector_id, args.dest,
                       server_ca=args.server_ca,
                       ca_fingerprint=args.ca_fingerprint)
    except EnrolmentError as exc:
        print("enrolment failed: %s" % exc, file=sys.stderr)
        return 1

    print("enrolled as %s%s" % (result.collector_id,
                                (" at %s" % result.site) if result.site else ""))
    print("  serial      %s" % result.serial)
    print("  valid until %s" % result.not_after)
    print("  key         %s" % result.key_path)
    print("  certificate %s" % result.cert_path)
    print("  ca bundle   %s" % result.ca_path)
    if result.content_key_path:
        print("  content key %s" % result.content_key_path)
    else:
        print("  content key NOT ISSUED - this server signs no content, so "
              "this collector cannot be updated remotely")
    print("\nThe token is now spent. Renew before the expiry above with "
          "`/api/v1/renew`; a certificate that has expired must be enrolled "
          "again, which puts a person back in the loop.")
    return 0


if __name__ == "__main__":                                 # pragma: no cover
    raise SystemExit(main())
