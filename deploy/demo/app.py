"""
A preview of the OTSec console.

    docker build -f deploy/demo/Dockerfile -t otsec-demo .
    docker run --rm -p 8080:8080 \
      -e OTSEC_BOOTSTRAP_USER=operator \
      -e OTSEC_BOOTSTRAP_PASSWORD='<something you choose>' \
      otsec-demo

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
from ot_server import packs as fleet_packs                 # noqa: E402
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


def _seed_packs(store: DemoStore, signer) -> None:
    """Two published packs, signed by the real signer.

    Signed rather than fabricated, so the fleet view is reading the same
    issuance record a deployment would and the digests on screen are the
    digests of the content beside them.
    """
    store.publish_pack(signer.sign(fleet_packs.KIND_RULES, 1, {
        "indicators": [
            {"kind": "ip", "value": "203.0.113.9", "why": "staging host"},
        ],
        "signatures": [
            {"rule_id": "iec104-unauthorised-command", "protocol": "iec104",
             "severity": "high", "title": "Command from an unexpected source"},
        ],
    }), published_by="control-room")
    store.publish_pack(signer.sign(fleet_packs.KIND_RULES, 2, {
        "indicators": [
            {"kind": "ip", "value": "203.0.113.9", "why": "staging host"},
            {"kind": "domain", "value": "updates.example.invalid",
             "why": "observed beaconing"},
        ],
        "signatures": [
            {"rule_id": "iec104-unauthorised-command", "protocol": "iec104",
             "severity": "high", "title": "Command from an unexpected source"},
            {"rule_id": "modbus-write-from-workstation", "protocol": "modbus",
             "severity": "high", "title": "Write coil from an engineering host"},
        ],
        "advisories": [{"id": "ICSA-26-001", "title": "Vendor advisory"}],
    }), published_by="control-room")


#: DEMO DATA. Every `source` says so, and that is not decoration: the whole
#: point of ot_server/lifecycle.py is that this product ships no lifecycle
#: dates, because a plausible-looking table of them drives real replacement
#: decisions. These exist so the screen has something to draw in a preview, and
#: an operator reading them is told immediately whose claim they are.
_DEMO_LIFECYCLE = {
    "lifecycle": [
        {"vendor": "Siemens", "product_pattern": r"S7-1200",
         "status": "end_of_sale", "end_of_sale": "2024-10-01",
         "end_of_support": "2031-10-01",
         "source": "FABRICATED demo data - not a vendor statement"},
        {"vendor": "ABB", "product_pattern": r"RTU560",
         "status": "supported", "end_of_support": "2032-01-01",
         "source": "FABRICATED demo data - not a vendor statement"},
        {"vendor": "Schneider", "product_pattern": r"Modicon\s*M580",
         "status": "end_of_support", "end_of_support": "2025-06-30",
         "source": "FABRICATED demo data - not a vendor statement",
         "note": "a device past end of support: no fix is coming for the "
                 "CVEs matched against it, so containment is the only option"},
    ],
}


def _seed_lifecycle(store: DemoStore, signer) -> None:
    store.publish_pack(
        signer.sign(fleet_packs.KIND_LIFECYCLE, 1, _DEMO_LIFECYCLE),
        published_by="control-room")


def build_app():
    store = DemoStore()
    authority = fleet_ca.CertificateAuthority.load_or_create(
        os.environ.get("OTSEC_CA_DIR", "/var/lib/otsec/ca"))
    _seed_certificates(store, authority)

    signer = fleet_packs.ContentSigner.load_or_create(
        os.environ.get("OTSEC_CA_DIR", "/var/lib/otsec/ca"))
    _seed_packs(store, signer)
    _seed_lifecycle(store, signer)

    if not os.environ.get("OTSEC_BOOTSTRAP_USER"):
        raise SystemExit(
            "Set OTSEC_BOOTSTRAP_USER and "
            "OTSEC_BOOTSTRAP_PASSWORD on `docker run`.\n"
            "There is no default: a preview image with a baked-in credential "
            "is a published credential the moment somebody runs it on a "
            "routable address.")

    return create_app(store,
                      console_dir=os.path.join(_ROOT, "console"),
                      ca=authority, signer=signer, local_auth=True)


app = build_app()


if __name__ == "__main__":                                 # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="0.0.0.0",
                port=int(os.environ.get("PORT", "8080")), log_level="info")
