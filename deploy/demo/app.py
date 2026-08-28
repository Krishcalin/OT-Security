"""
A preview of the Power NetView console.

    docker build -f deploy/demo/Dockerfile -t power-netview-demo .
    docker run --rm -p 8080:8080 \
      -e POWERNETVIEW_BOOTSTRAP_USER=operator \
      -e POWERNETVIEW_BOOTSTRAP_PASSWORD='<something you choose>' \
      power-netview-demo

Then open http://localhost:8080/.

WHAT THIS IS FOR, AND WHAT IT IS NOT
────────────────────────────────────
It is for looking at the screens. It runs the real server, the real console
bundle and the real sign-in — but over an in-memory estate (`demo_store.py`) and
with no TLS terminator in front of it.

That last part matters and is why this is not a deployment:

  * There is no mutual TLS, so the ingest plane has no collector identity to
    check. Nothing is ingesting here anyway; the estate is fabricated.
  * The session cookie is not marked `Secure`, because the request arrived over
    plain http. That is correct behaviour for http and wrong for a plant — see
    `deploy/README.md`, which is how the console is actually fronted.
  * The password comes from the environment at `docker run`, and there is still
    no default. A preview image with a baked-in credential is a published
    credential the moment anyone runs it on a routable address.

The estate is deliberately untidy: a collector dropping frames, two substations
sharing 10.0.0.x, an asset that went quiet, a revoked certificate, and no CVE
corpus. A demo where everything is clean would show none of the behaviour this
console exists for.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
for path in (_ROOT, _HERE, os.path.join(_ROOT, "ot_scanner")):
    if path not in sys.path:
        sys.path.insert(0, path)

from demo_store import DemoStore                           # noqa: E402
from ot_server import ca as fleet_ca                       # noqa: E402
from ot_server.api import create_app                       # noqa: E402


def _seed_certificates(store: DemoStore, authority) -> None:
    """One certificate per collector, and one of them revoked.

    Real keys and real signatures through the real CA, because the fleet screen
    reads an issuance record and a hand-written dictionary would drift from what
    `ca.sign` actually produces.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    for collector, site in sorted(store.collector_sites().items()):
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([
                   x509.NameAttribute(NameOID.COMMON_NAME, "ignored")]))
               .sign(key, hashes.SHA256()))
        issued = authority.sign(
            csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            collector, site)
        store.record_certificate(issued)
        if collector == "pi-alderley-02":
            store.revoke_certificate(
                issued.serial, "cabinet found open during an inspection")


def build_app():
    store = DemoStore()
    authority = fleet_ca.CertificateAuthority.load_or_create(
        os.environ.get("POWERNETVIEW_CA_DIR", "/var/lib/power-netview/ca"))
    _seed_certificates(store, authority)

    if not os.environ.get("POWERNETVIEW_BOOTSTRAP_USER"):
        raise SystemExit(
            "Set POWERNETVIEW_BOOTSTRAP_USER and "
            "POWERNETVIEW_BOOTSTRAP_PASSWORD on `docker run`.\n"
            "There is no default: a preview image with a baked-in credential "
            "is a published credential the moment somebody runs it on a "
            "routable address.")

    return create_app(store,
                      console_dir=os.path.join(_ROOT, "console"),
                      ca=authority, local_auth=True)


app = build_app()


if __name__ == "__main__":                                 # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="0.0.0.0",
                port=int(os.environ.get("PORT", "8080")), log_level="info")
