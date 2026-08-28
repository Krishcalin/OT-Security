"""
Fetching and applying signed content packs, on the collector.

`rulepack.py` answers which logic produced a finding. This is how that logic
changes without somebody driving to the substation.

WHAT THIS REFUSES, AND WHAT IT DOES INSTEAD OF FAILING
──────────────────────────────────────────────────────
Every refusal here leaves the collector running the content it already has.
There is no path where a bad pack, an unreachable server, or a signature that
does not verify results in a collector with NO detection content — a sensor that
silently stops detecting is worse than one running last month's rules, because
the first looks exactly like a quiet plant.

So: verify, then stage, then swap. A pack that fails any check never reaches the
staging path, and a swap that fails leaves the previous file untouched.

WHY THE VERIFICATION KEY IS NOT THE CA BUNDLE
─────────────────────────────────────────────
The CA proves who the server is; this proves what the content is. Keeping them
separate means compromising the transport does not let anybody publish rules,
and compromising the content key does not let anybody impersonate the server.
The key arrives at enrolment, beside the CA certificate, and is pinned from then
on: a server that starts serving content signed by a different key is either a
key rotation somebody must perform deliberately, or an attack.

WHY openssl IS NOT USED HERE
────────────────────────────
`enrol.py` shells out to openssl because key generation needs it and
`manifest.RUNTIME_REQUIRES` is `("dpkt>=1.9.8",)`. Ed25519 verification is one
`openssl pkeyutl -verify` away, so the same trick works and the ratchet holds.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

PACK_NAME = "rules-pack.json"
KEY_NAME = "content-key.pub"
TIMEOUT = 30.0


class ContentError(RuntimeError):
    """A pack that must not be applied. The collector keeps what it has."""


@dataclass
class Applied:
    version: int
    digest: str
    path: str
    note: str = ""


def current_pack(directory: str) -> Optional[Dict[str, Any]]:
    """Whatever this collector is running, or None before the first fetch."""
    path = os.path.join(directory, PACK_NAME)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:                                      # noqa: BLE001
        # A corrupt file on disk is not a reason to run nothing; it is a reason
        # to accept the next valid pack as if this were the first.
        return None


def current_version(directory: str) -> int:
    pack = current_pack(directory)
    try:
        return int((pack or {}).get("version") or 0)
    except Exception:                                      # noqa: BLE001
        return 0


def verify_signature(public_key_path: str, canonical: bytes,
                     signature_hex: str) -> bool:
    """Ed25519 verify, through openssl, so the dependency ratchet holds.

    Returns False rather than raising for every failure mode — a bad signature,
    a malformed key and a missing binary are all "do not apply this", and the
    caller says so once in its own words.
    """
    openssl = shutil.which("openssl") or shutil.which("openssl.exe")
    if openssl is None:
        return False
    try:
        signature = bytes.fromhex(signature_hex or "")
    except ValueError:
        return False
    if not signature:
        return False

    sig_file = data_file = None
    try:
        handle, sig_file = tempfile.mkstemp(prefix="pnv-sig-")
        with os.fdopen(handle, "wb") as fh:
            fh.write(signature)
        handle, data_file = tempfile.mkstemp(prefix="pnv-body-")
        with os.fdopen(handle, "wb") as fh:
            fh.write(canonical)
        proc = subprocess.run(
            [openssl, "pkeyutl", "-verify", "-pubin",
             "-inkey", public_key_path, "-rawin", "-in", data_file,
             "-sigfile", sig_file],
            capture_output=True, timeout=60)
        return proc.returncode == 0
    except Exception:                                      # noqa: BLE001
        return False
    finally:
        for path in (sig_file, data_file):
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:                            # pragma: no cover
                    pass


def canonical_bytes(pack: Dict[str, Any]) -> bytes:
    """The bytes the server signed. Must match `packs.SignedPack.canonical`
    exactly — sorted keys, no incidental whitespace — or nothing verifies."""
    body = {"kind": pack.get("kind"), "version": pack.get("version"),
            "created_at": pack.get("created_at"),
            "payload": pack.get("payload")}
    return json.dumps(body, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def check(pack: Dict[str, Any], public_key_path: str,
          held_version: int) -> None:
    """Raise `ContentError` unless this pack may replace what is held."""
    if str(pack.get("kind") or "") != "rules":
        raise ContentError("this is a %r pack; a collector applies only rules"
                           % pack.get("kind"))
    try:
        version = int(pack.get("version") or 0)
    except (TypeError, ValueError):
        raise ContentError("this pack has no usable version")

    if not verify_signature(public_key_path, canonical_bytes(pack),
                            str(pack.get("signature") or "")):
        raise ContentError(
            "this pack is not signed by the key this collector was enrolled "
            "with, so it is not applied and the current content stays in place")

    # AFTER the signature, on purpose. A correctly signed old pack is exactly
    # what a replay looks like, and every pack this server ever issued stays
    # correctly signed forever.
    if version <= held_version:
        raise ContentError(
            "this pack is version %d and version %d is already held; a signed "
            "older pack is a rollback, not an update" % (version, held_version))


def apply_pack(directory: str, pack: Dict[str, Any],
               public_key_path: str) -> Applied:
    """Verify, stage, then swap.

    Written to a temporary file in the SAME directory and renamed over the
    target, so a collector that loses power midway keeps the pack it had rather
    than half of the one it was fetching.
    """
    held = current_version(directory)
    check(pack, public_key_path, held)

    os.makedirs(directory, exist_ok=True)
    target = os.path.join(directory, PACK_NAME)
    handle, staged = tempfile.mkstemp(prefix="pnv-pack-", dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            json.dump(pack, fh, sort_keys=True)
        os.replace(staged, target)
    except Exception:
        if os.path.exists(staged):
            try:
                os.unlink(staged)
            except OSError:                                # pragma: no cover
                pass
        raise

    return Applied(version=int(pack["version"]),
                   digest=str(pack.get("digest") or ""), path=target,
                   note="replaced version %d" % held if held else "first pack")


def fetch(server_url: str, ca_bundle: str, client_cert: str, client_key: str,
          held_version: int) -> Optional[Dict[str, Any]]:
    """Ask the server for anything newer. None means nothing newer exists.

    The transport is the collector's existing mTLS identity — the content key
    proves the PACK, the client certificate proves the COLLECTOR, and both are
    required. A pack served over an authenticated channel is still verified, and
    a pack with a good signature is still only accepted over one.
    """
    url = ("%s/api/v1/packs/latest?kind=rules&have=%d"
           % (server_url.rstrip("/"), int(held_version)))
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    context = _mtls_context(ca_bundle, client_cert, client_key)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT,
                                    context=context) as response:
            if response.status == 204:
                return None                    # up to date; nothing to apply
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None                        # no pack published yet
        raise ContentError("the server refused the pack request (%d)" % exc.code)
    except Exception as exc:                               # noqa: BLE001
        # Never the driver's message verbatim: it can echo the request, and the
        # request carries this collector's identity.
        raise ContentError("could not reach the content endpoint: %s"
                           % type(exc).__name__)


def _mtls_context(ca_bundle: str, client_cert: str, client_key: str):
    import ssl

    context = ssl.create_default_context(cafile=ca_bundle)
    context.load_cert_chain(client_cert, client_key)
    return context


def update(directory: str, server_url: str, ca_bundle: str, client_cert: str,
           client_key: str) -> Optional[Applied]:
    """One update cycle. Returns what was applied, or None if nothing was.

    Every failure raises `ContentError` and leaves the collector on the content
    it already has. There is deliberately no branch that ends with no content.
    """
    public_key_path = os.path.join(directory, KEY_NAME)
    if not os.path.isfile(public_key_path):
        raise ContentError(
            "no content verification key at %s. It is written at enrolment "
            "beside the CA bundle; without it nothing can be checked and "
            "nothing is applied." % public_key_path)

    held = current_version(directory)
    pack = fetch(server_url, ca_bundle, client_cert, client_key, held)
    if pack is None:
        return None
    return apply_pack(directory, pack, public_key_path)
