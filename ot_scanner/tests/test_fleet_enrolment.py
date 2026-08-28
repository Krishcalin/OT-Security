"""
Phase 6 — enrolment and certificate lifecycle (decision Q4, OTS-TRN-002).

Two tests in this file carry the design, and both are about an identity being
something the SERVER decides rather than something the requester asks for.

`test_the_subject_comes_from_the_token_not_from_the_csr` — a certificate signing
request carries a subject, and the obvious implementation signs it. Then a
collector requests `CN=pi-substation-01`, receives a certificate that
authenticates it as another site's collector, and reports assets into that
site's inventory. Every request afterwards looks perfectly ordinary, because the
identity really was issued by this CA.

`test_a_revoked_certificate_is_refused` — revocation that does not deny is worse
than no revocation, because the console shows it as revoked and somebody stops
looking. Nothing in a subject line changes when a certificate is revoked, so
authenticating on the name alone leaves the revoked holder working.
"""
from __future__ import annotations

import datetime
import os
import shutil
import stat
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _ROOT)

from ot_server import ca as fleet_ca                       # noqa: E402
from ot_server import enrolment                            # noqa: E402

cryptography = pytest.importorskip("cryptography")

from cryptography import x509                              # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa     # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID    # noqa: E402


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _csr(common_name="whatever-it-likes", key=None):
    """A CSR that names itself. What the server does with that name is the
    whole point of half this file."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii"), key


@pytest.fixture()
def authority(tmp_path):
    return fleet_ca.CertificateAuthority.create(str(tmp_path / "ca"))


# ── the CA ─────────────────────────────────────────────────────────────────

def test_the_subject_comes_from_the_token_not_from_the_csr(authority):
    """THE test in this file. A CSR is data the caller controls; signing its
    subject would let a collector be issued as another site's collector, after
    which everything it reported would merge into that plant's inventory."""
    csr, _key = _csr(common_name="pi-substation-99")
    issued = authority.sign(csr, "pi-substation-01", site="Substation A")

    certificate = x509.load_pem_x509_certificate(issued.pem.encode("ascii"))
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert [n.value for n in names] == ["pi-substation-01"]
    assert "pi-substation-99" not in issued.subject
    assert issued.collector_id == "pi-substation-01"


def test_the_site_travels_into_the_certificate(authority):
    csr, _key = _csr()
    issued = authority.sign(csr, "pi-a", site="Substation A")
    certificate = x509.load_pem_x509_certificate(issued.pem.encode("ascii"))
    units = certificate.subject.get_attributes_for_oid(
        NameOID.ORGANIZATIONAL_UNIT_NAME)
    assert [u.value for u in units] == ["Substation A"]


def test_a_request_the_caller_cannot_prove_it_holds_is_refused(authority):
    """Without proof of possession a certificate can be issued over somebody
    else's public key, and its holder authenticates as this collector without
    ever having contacted us."""
    csr, _key = _csr()
    # Corrupt the signature while leaving the structure parseable.
    lines = csr.strip().splitlines()
    body = list(lines[1:-1])
    body[-2] = ("A" * len(body[-2])) if body[-2][0] != "A" else ("B" * len(body[-2]))
    tampered = "\n".join([lines[0]] + body + [lines[-1]]) + "\n"

    with pytest.raises(fleet_ca.CaError):
        authority.sign(tampered, "pi-a")


def test_a_weak_rsa_key_is_refused(authority):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, "pi-a")]))
           .sign(key, hashes.SHA256()))
    pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")
    with pytest.raises(fleet_ca.CaError) as exc:
        authority.sign(pem, "pi-a")
    assert "1024" in str(exc.value)


def test_an_unlisted_curve_is_refused(authority):
    """A whitelist, not a strength test: P-521 is stronger than P-256 and is
    still refused. A CA that accepts whatever it recognises has delegated its
    key policy to whoever is asking."""
    _pem, _key = _csr(key=ec.generate_private_key(ec.SECP521R1()))
    with pytest.raises(fleet_ca.CaError):
        authority.sign(_pem, "pi-a")


def test_an_issued_certificate_cannot_authenticate_a_server(authority):
    """A collector certificate that could also be a server certificate could
    terminate TLS for the ingest endpoint, and the fleet would report to it."""
    csr, _key = _csr()
    issued = authority.sign(csr, "pi-a")
    certificate = x509.load_pem_x509_certificate(issued.pem.encode("ascii"))

    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert list(eku.value) == [ExtendedKeyUsageOID.CLIENT_AUTH]

    basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.value.ca is False, "a collector could enrol the rest of the fleet"


def test_creating_a_ca_over_an_existing_one_is_refused(tmp_path):
    """Overwriting it orphans every certificate in the fleet: the collectors
    keep presenting certificates this server can no longer verify, and the fleet
    goes silent one site at a time."""
    directory = str(tmp_path / "ca")
    fleet_ca.CertificateAuthority.create(directory)
    with pytest.raises(fleet_ca.CaError):
        fleet_ca.CertificateAuthority.create(directory)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_the_ca_key_is_written_unreadable_to_anyone_else(tmp_path):
    directory = str(tmp_path / "ca")
    fleet_ca.CertificateAuthority.create(directory)
    mode = os.stat(os.path.join(directory, fleet_ca.CA_KEY_NAME)).st_mode
    assert not mode & (stat.S_IRGRP | stat.S_IROTH)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_a_readable_ca_key_is_refused_rather_than_used(tmp_path):
    """Loading it anyway means signing with a key there is no reason to believe
    is still private, and nothing downstream would show that."""
    directory = str(tmp_path / "ca")
    fleet_ca.CertificateAuthority.create(directory)
    os.chmod(os.path.join(directory, fleet_ca.CA_KEY_NAME), 0o644)
    with pytest.raises(fleet_ca.CaError) as exc:
        fleet_ca.CertificateAuthority.load(directory)
    assert "disclosed" in str(exc.value)


@pytest.mark.parametrize("value,expected", [
    ("AA:BB:CC", "aabbcc"),
    ("SHA256:aabbcc", "aabbcc"),
    ("  AaBbCc  ", "aabbcc"),
])
def test_fingerprints_from_different_terminators_normalise(value, expected):
    """nginx, HAProxy and a pasted `openssl x509` line all disagree about the
    shape. A deployment whose format simply failed to match would look exactly
    like a fleet that had never enrolled."""
    assert fleet_ca.normalise_fingerprint(value) == expected


# ── token policy ───────────────────────────────────────────────────────────

def test_only_the_hash_of_a_token_is_ever_stored():
    minted = enrolment.mint("pi-a", site="Substation A")
    assert minted.token_hash == enrolment.hash_token(minted.token)
    assert minted.token not in minted.token_hash


def test_a_token_must_name_a_collector():
    with pytest.raises(enrolment.EnrolmentError):
        enrolment.mint("   ")


def test_issuing_to_a_collector_that_already_has_one_is_refused():
    """A token stolen from a mailbox and replayed would otherwise mint a second
    valid identity for a collector that has been running for a year. Both
    certificates work; the server cannot tell them apart."""
    decision = enrolment.decide_issue(["aa11"], allow_reissue=False)
    assert not decision.ok
    assert "clone" in decision.reason


def test_a_deliberate_reissue_revokes_what_it_replaces():
    """Never left alongside: two valid certificates for one identity is a state
    the server should not be able to reach."""
    decision = enrolment.decide_issue(["aa11", "bb22"], allow_reissue=True)
    assert decision.ok
    assert decision.supersede == ["aa11", "bb22"]


def test_a_revoked_certificate_cannot_be_renewed():
    """Renewing it would hand its holder a fresh 90 days and undo the
    revocation."""
    decision = enrolment.decide_renewal(
        _utcnow() + datetime.timedelta(days=30), revoked=True)
    assert not decision.ok


def test_an_expired_certificate_cannot_be_renewed():
    """Otherwise a certificate never really expires, it only pauses."""
    decision = enrolment.decide_renewal(
        _utcnow() - datetime.timedelta(days=1), revoked=False)
    assert not decision.ok
    assert "re-enrol" in decision.reason.lower()


def test_a_valid_certificate_renews():
    decision = enrolment.decide_renewal(
        _utcnow() + datetime.timedelta(days=30), revoked=False)
    assert decision.ok


# ── the API, wired end to end ──────────────────────────────────────────────

class _FleetStore:
    """In-memory, with the one behaviour that matters kept faithful: redeeming
    a token is a single exclusive claim."""

    def __init__(self):
        self.tokens = {}
        self.certs = {}
        self.collectors = {}
        self.heartbeats = []

    # enrolment
    def create_enrolment_token(self, minted):
        self.tokens[minted.token_hash] = {
            "collector_id": minted.collector_id, "site": minted.site,
            "expires_at": minted.expires_at, "used_at": None,
            "allow_reissue": minted.allow_reissue, "used_serial": ""}

    def redeem_enrolment_token(self, token_hash):
        row = self.tokens.get(token_hash)
        if row is None or row["used_at"] is not None:
            return None
        if row["expires_at"] <= _utcnow():
            return None
        row["used_at"] = _utcnow()
        return {"collector_id": row["collector_id"], "site": row["site"],
                "allow_reissue": row["allow_reissue"]}

    def release_enrolment_token(self, token_hash):
        row = self.tokens.get(token_hash)
        if row is None or row["used_serial"]:
            return False
        row["used_at"] = None
        return True

    def record_token_serial(self, token_hash, serial):
        self.tokens[token_hash]["used_serial"] = serial

    # certificates
    def record_certificate(self, issued):
        self.certs[issued.serial] = {
            "serial": issued.serial, "collector_id": issued.collector_id,
            "subject": issued.subject, "fingerprint": issued.fingerprint,
            "not_before": issued.not_before, "not_after": issued.not_after,
            "revoked_at": None, "revocation_reason": ""}

    def certificate_by_fingerprint(self, fingerprint):
        for row in self.certs.values():
            if row["fingerprint"] == fingerprint:
                return dict(row)
        return None

    def active_certificates(self, collector_id):
        now = _utcnow()
        return [dict(r) for r in self.certs.values()
                if r["collector_id"] == collector_id
                and r["revoked_at"] is None and r["not_after"] > now]

    def certificates(self, collector_id=None):
        return [dict(r) for r in self.certs.values()
                if collector_id in (None, r["collector_id"])]

    def revoke_certificate(self, serial, reason):
        row = self.certs.get(serial)
        if row is None or row["revoked_at"] is not None:
            return False
        row["revoked_at"] = _utcnow()
        row["revocation_reason"] = reason
        return True

    # collectors
    def ensure_collector(self, collector_id):
        self.collectors.setdefault(collector_id, "")

    def set_site(self, collector_id, site):
        self.collectors[collector_id] = site

    def collector_sites(self):
        return dict(self.collectors)

    def record_heartbeat(self, payload):
        self.heartbeats.append(payload)


def _client(store, ca=None, operator=True):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    return TestClient(create_app(
        store, require_operator=(lambda r: "op") if operator else None,
        console_dir=os.path.join(_ROOT, "console"), ca=ca))


def _headers(collector_id, fingerprint=None):
    headers = {"X-Client-Subject": "CN=%s,O=Fleet" % collector_id}
    if fingerprint:
        headers["X-Client-Fingerprint"] = fingerprint
    return headers


def _enrol(client, token, common_name="anything"):
    csr, key = _csr(common_name)
    return client.post("/api/v1/enrol", json={"token": token, "csr": csr}), key


def test_enrolment_is_unavailable_rather_than_approximated_without_a_ca():
    client = _client(_FleetStore(), ca=None)
    response = client.post("/api/v1/enrol", json={"token": "x", "csr": "y"})
    assert response.status_code == 503
    assert "cannot issue" in response.json()["detail"]


def test_a_minted_token_enrols_once(authority):
    store = _FleetStore()
    client = _client(store, ca=authority)

    minted = client.post(
        "/api/v1/estate/collectors/pi-a/enrolment-token",
        json={"site": "Substation A"})
    assert minted.status_code == 201
    token = minted.json()["token"]

    first, _key = _enrol(client, token)
    assert first.status_code == 201, first.text
    assert first.json()["collector_id"] == "pi-a"
    assert first.json()["site"] == "Substation A"

    second, _key2 = _enrol(client, token)
    assert second.status_code == 403, "a spent token enrolled a second collector"


def test_the_refusal_to_enrol_does_not_say_which_token_exists(authority):
    """The caller is unauthenticated. Distinguishing unknown from expired from
    already-redeemed would make this an oracle."""
    client = _client(_FleetStore(), ca=authority)
    response, _key = _enrol(client, "not-a-real-token")
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert "may never have existed" in detail


def test_the_plaintext_token_is_returned_once_and_stored_only_as_a_hash(authority):
    store = _FleetStore()
    client = _client(store, ca=authority)
    token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={}).json()["token"]
    assert token not in str(store.tokens)
    assert enrolment.hash_token(token) in store.tokens


def test_a_second_enrolment_of_a_live_collector_is_refused(authority):
    store = _FleetStore()
    client = _client(store, ca=authority)

    first_token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                              json={}).json()["token"]
    assert _enrol(client, first_token)[0].status_code == 201

    second_token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                               json={}).json()["token"]
    response, _key = _enrol(client, second_token)
    assert response.status_code == 409
    assert "clone" in response.json()["detail"]


def test_a_deliberate_reissue_revokes_the_previous_certificate(authority):
    store = _FleetStore()
    client = _client(store, ca=authority)

    token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={}).json()["token"]
    first = _enrol(client, token)[0].json()

    reissue = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                          json={"allow_reissue": True}).json()["token"]
    second = _enrol(client, reissue)[0]
    assert second.status_code == 201

    assert store.certs[first["serial"]]["revoked_at"] is not None
    assert "superseded" in store.certs[first["serial"]]["revocation_reason"]


# ── enforcement: the point of having issued anything ───────────────────────

def _enrolled(authority):
    store = _FleetStore()
    client = _client(store, ca=authority)
    token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={"site": "Substation A"}).json()["token"]
    body = _enrol(client, token)[0].json()
    fingerprint = store.certs[body["serial"]]["fingerprint"]
    return store, client, body, fingerprint


def test_an_enrolled_collector_is_accepted(authority):
    _store, client, _body, fingerprint = _enrolled(authority)
    response = client.post("/api/v1/heartbeat", json={},
                           headers=_headers("pi-a", fingerprint))
    assert response.status_code == 200


def test_a_revoked_certificate_is_refused(authority):
    """THE other test in this file. Revocation that does not deny is worse than
    no revocation, because the console shows it as revoked."""
    store, client, body, fingerprint = _enrolled(authority)
    assert client.post("/api/v1/estate/certificates/%s/revoke" % body["serial"],
                       json={"reason": "cabinet opened"}).status_code == 200

    response = client.post("/api/v1/heartbeat", json={},
                           headers=_headers("pi-a", fingerprint))
    assert response.status_code == 401
    assert "revoked" in response.json()["detail"]
    assert "cabinet opened" in response.json()["detail"]


def test_a_certificate_this_server_did_not_issue_is_refused(authority):
    _store, client, _body, _fp = _enrolled(authority)
    response = client.post("/api/v1/heartbeat", json={},
                           headers=_headers("pi-a", "00" * 32))
    assert response.status_code == 401
    assert "not in the fleet issuance record" in response.json()["detail"]


def test_a_missing_fingerprint_is_refused_when_a_ca_is_configured(authority):
    """Otherwise revocation would not deny anything, and the deployment would
    look identical to a working one."""
    _store, client, _body, _fp = _enrolled(authority)
    response = client.post("/api/v1/heartbeat", json={},
                           headers=_headers("pi-a"))
    assert response.status_code == 401
    assert "X-Client-Fingerprint" in response.json()["detail"]


def test_a_certificate_presented_under_another_name_is_refused(authority):
    _store, client, _body, fingerprint = _enrolled(authority)
    response = client.post("/api/v1/heartbeat", json={},
                           headers=_headers("pi-b", fingerprint))
    assert response.status_code == 401
    assert "issued to" in response.json()["detail"]


def test_an_expired_certificate_is_refused(authority):
    store, client, body, fingerprint = _enrolled(authority)
    store.certs[body["serial"]]["not_after"] = (
        _utcnow() - datetime.timedelta(days=1))
    response = client.post("/api/v1/heartbeat", json={},
                           headers=_headers("pi-a", fingerprint))
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]


def test_without_a_ca_the_subject_alone_still_authenticates():
    """The pre-enrolment state. It is a state in which revocation does not
    exist, which is why the enrolment routes answer 503 rather than pretending
    otherwise."""
    store = _FleetStore()
    client = _client(store, ca=None)
    response = client.post("/api/v1/heartbeat", json={},
                           headers=_headers("pi-a"))
    assert response.status_code == 200


# ── lifecycle, operator side ───────────────────────────────────────────────

def test_the_certificate_list_keeps_revoked_and_expired_entries(authority):
    """"No record" and "never issued" must not be the same answer: the question
    after an incident is what this fleet has held, not what it holds now."""
    store, client, body, _fp = _enrolled(authority)
    client.post("/api/v1/estate/certificates/%s/revoke" % body["serial"],
                json={"reason": "decommissioned"})

    listing = client.get("/api/v1/estate/certificates").json()
    assert listing["count"] == 1
    row = listing["certificates"][0]
    assert row["state"] == "revoked"
    assert row["revocation_reason"] == "decommissioned"


def test_revoking_twice_does_not_report_a_revocation_that_did_not_happen(authority):
    _store, client, body, _fp = _enrolled(authority)
    path = "/api/v1/estate/certificates/%s/revoke" % body["serial"]
    assert client.post(path, json={"reason": "first"}).status_code == 200
    assert client.post(path, json={"reason": "second"}).status_code == 409


def test_a_certificate_near_expiry_is_flagged(authority):
    store, client, body, _fp = _enrolled(authority)
    store.certs[body["serial"]]["not_after"] = (
        _utcnow() + datetime.timedelta(days=3))
    row = client.get("/api/v1/estate/certificates").json()["certificates"][0]
    assert row["expiring_soon"] is True
    assert row["state"] == "valid"


@pytest.mark.parametrize("path,method", [
    ("/api/v1/estate/certificates", "get"),
    ("/api/v1/estate/ca", "get"),
    ("/api/v1/estate/collectors/pi-a/enrolment-token", "post"),
])
def test_the_lifecycle_endpoints_are_fail_closed(path, method, authority):
    client = _client(_FleetStore(), ca=authority, operator=False)
    call = getattr(client, method)
    response = call(path) if method == "get" else call(path, json={})
    assert response.status_code == 503


# ── renewal ────────────────────────────────────────────────────────────────

def test_renewal_leaves_the_old_certificate_valid(authority):
    """If the response never reaches the Pi, a collector that had just
    invalidated its only identity would be unreachable in a substation."""
    store, client, body, fingerprint = _enrolled(authority)
    csr, _key = _csr()
    response = client.post("/api/v1/renew", json={"csr": csr},
                           headers=_headers("pi-a", fingerprint))
    assert response.status_code == 201, response.text
    assert response.json()["superseded"] == body["serial"]
    assert store.certs[body["serial"]]["revoked_at"] is None


def test_a_revoked_certificate_cannot_renew_itself(authority):
    store, client, body, fingerprint = _enrolled(authority)
    client.post("/api/v1/estate/certificates/%s/revoke" % body["serial"],
                json={"reason": "stolen"})
    csr, _key = _csr()
    response = client.post("/api/v1/renew", json={"csr": csr},
                           headers=_headers("pi-a", fingerprint))
    # Refused at authentication, before renewal policy is even consulted.
    assert response.status_code == 401


# ── the collector side ─────────────────────────────────────────────────────

from collector import enrol as collector_enrol  # noqa: E402


def test_enrolment_refuses_without_a_trust_anchor(tmp_path):
    """Trust on first use here means a substation collector reporting a plant's
    inventory to whoever answered."""
    with pytest.raises(collector_enrol.EnrolmentError) as exc:
        collector_enrol.enrol("https://fleet.example", "token", "pi-a",
                              str(tmp_path))
    assert "anchor" in str(exc.value)


def test_enrolment_refuses_plain_http(tmp_path):
    with pytest.raises(collector_enrol.EnrolmentError):
        collector_enrol.enrol("http://fleet.example", "token", "pi-a",
                              str(tmp_path), ca_fingerprint="aa")


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_the_collector_generates_its_own_key_and_never_sends_it(tmp_path):
    dest = str(tmp_path / "pki")
    key_path = collector_enrol.generate_key(dest)
    csr = collector_enrol.create_csr(key_path, "pi-a")

    assert "BEGIN CERTIFICATE REQUEST" in csr
    # The private key is not in the thing that goes over the wire.
    assert "PRIVATE KEY" not in csr
    if os.name != "nt":
        mode = os.stat(key_path).st_mode
        assert not mode & (stat.S_IRGRP | stat.S_IROTH)


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_a_real_openssl_csr_is_signed_under_the_servers_name(tmp_path, authority):
    """The two halves meeting: a CSR made by the collector's openssl, naming
    itself, signed by the server under the identity the operator authorised."""
    dest = str(tmp_path / "pki")
    key_path = collector_enrol.generate_key(dest)
    csr = collector_enrol.create_csr(key_path, "pi-imposter")

    issued = authority.sign(csr, "pi-substation-01", site="Substation A")
    certificate = x509.load_pem_x509_certificate(issued.pem.encode("ascii"))
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert [n.value for n in names] == ["pi-substation-01"]

    # And the certificate really is over the collector's key.
    assert (collector_enrol.public_key_of_cert(issued.pem)
            == collector_enrol.public_key_of_key(key_path))


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_the_two_sides_compute_the_same_fingerprint(tmp_path, authority):
    """The collector checks the returned CA against a fingerprint the operator
    carried; the server records certificates by the same digest. A mismatch in
    format would make every deployment look like one that never enrolled."""
    collector_view = collector_enrol.fingerprint_of_cert(authority.ca_pem)
    server_view = fleet_ca.fingerprint_of_pem(authority.ca_pem)
    assert collector_view == server_view


# ── the two halves, wired together ─────────────────────────────────────────
#
# `_get` and `_post` are the collector's only two exits to the network, so
# routing them into a TestClient runs the real enrolment logic — the anchor
# check, the ordering, the key handling — against the real server.

def _wire(monkeypatch, client):
    def _get(url, server_ca):
        response = client.get("/api/v1" + url.split("/api/v1", 1)[1])
        if response.status_code >= 400:
            raise collector_enrol.EnrolmentError(
                "the server would not publish its CA (%d)" % response.status_code)
        return response.json()

    def _post(url, payload, server_ca):
        response = client.post("/api/v1" + url.split("/api/v1", 1)[1],
                               json=payload)
        if response.status_code >= 400:
            raise collector_enrol.EnrolmentError(
                "the server refused enrolment (%d): %s"
                % (response.status_code, response.text))
        return response.json()

    monkeypatch.setattr(collector_enrol, "_get", _get)
    monkeypatch.setattr(collector_enrol, "_post", _post)


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_a_collector_enrols_end_to_end(tmp_path, authority, monkeypatch):
    store = _FleetStore()
    client = _client(store, ca=authority)
    _wire(monkeypatch, client)
    token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={"site": "Substation A"}).json()["token"]

    result = collector_enrol.enrol(
        "https://fleet.example", token, "pi-a", str(tmp_path / "pki"),
        ca_fingerprint=fleet_ca.fingerprint_of_pem(authority.ca_pem))

    assert result.collector_id == "pi-a"
    assert result.site == "Substation A"
    for path in (result.key_path, result.cert_path, result.ca_path):
        assert os.path.isfile(path)

    # And the identity it just obtained authenticates.
    fingerprint = store.certs[result.serial]["fingerprint"]
    assert client.post("/api/v1/heartbeat", json={},
                       headers=_headers("pi-a", fingerprint)).status_code == 200


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_a_fingerprint_mismatch_does_not_spend_the_token(tmp_path, authority,
                                                         monkeypatch):
    """Found by running the flow end to end rather than by reading it.

    With the check on the enrolment RESPONSE, one mistyped fingerprint spent the
    token, left the server holding a certificate nobody had, and blocked the
    next legitimate enrolment of that collector with "it already holds a valid
    certificate" — three problems from one typo. The anchor is checked against
    `GET /api/v1/ca` first, so the token is never offered to a server that fails
    it.
    """
    store = _FleetStore()
    client = _client(store, ca=authority)
    _wire(monkeypatch, client)
    token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={}).json()["token"]

    with pytest.raises(collector_enrol.EnrolmentError) as exc:
        collector_enrol.enrol("https://fleet.example", token, "pi-a",
                              str(tmp_path / "pki"), ca_fingerprint="00" * 32)
    assert "has NOT been sent" in str(exc.value)

    assert store.certs == {}, "a certificate was issued to nobody"
    assert store.tokens[enrolment.hash_token(token)]["used_at"] is None

    # The proof that it is still good: it enrols.
    result = collector_enrol.enrol(
        "https://fleet.example", token, "pi-a", str(tmp_path / "pki"),
        ca_fingerprint=fleet_ca.fingerprint_of_pem(authority.ca_pem))
    assert result.serial in store.certs


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_a_retry_after_a_failed_enrolment_reuses_the_orphan_key(tmp_path):
    """A key with no certificate is the debris of an enrolment that failed
    partway — a laptop balanced on a cabinet, a network that dropped. Refusing
    there would make the retry harder than the first attempt."""
    dest = str(tmp_path / "pki")
    first = collector_enrol.generate_key(dest)
    with open(first, "rb") as fh:
        original = fh.read()

    again = collector_enrol.generate_key(dest)
    with open(again, "rb") as fh:
        assert fh.read() == original, "the retry replaced a usable key"


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_a_key_with_a_certificate_beside_it_is_a_live_identity(tmp_path):
    dest = str(tmp_path / "pki")
    collector_enrol.generate_key(dest)
    with open(os.path.join(dest, collector_enrol.CERT_NAME), "w") as fh:
        fh.write("-----BEGIN CERTIFICATE-----\n")
    with pytest.raises(collector_enrol.EnrolmentError) as exc:
        collector_enrol.generate_key(dest)
    assert "orphan" in str(exc.value)


def test_the_ca_is_published_without_authentication(authority):
    """A CA certificate is the trust anchor everyone needs before verifying
    anything, and it travels in the clear in every TLS handshake already.
    Publishing it is what lets the fingerprint be checked before the token is
    spent."""
    client = _client(_FleetStore(), ca=authority, operator=False)
    response = client.get("/api/v1/ca")
    assert response.status_code == 200
    assert "BEGIN CERTIFICATE" in response.json()["ca_certificate"]


def test_publishing_the_ca_is_still_refused_when_there_is_none():
    client = _client(_FleetStore(), ca=None)
    assert client.get("/api/v1/ca").status_code == 503


# ── defects found by auditing the slice, each with the test that catches it ─

def test_a_malformed_csr_does_not_spend_the_token(authority):
    """The likeliest field failure there is. The token was claimed before the
    CSR was parsed, so a typo in a `--dest` path or a truncated file left the
    engineer at the cabinet with a spent credential and a trip back to an
    operator."""
    store = _FleetStore()
    client = _client(store, ca=authority)
    token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={}).json()["token"]

    bad = client.post("/api/v1/enrol",
                      json={"token": token, "csr": "-----BEGIN NONSENSE-----"})
    assert bad.status_code == 400
    assert store.tokens[enrolment.hash_token(token)]["used_at"] is None

    # Still good: it enrols.
    assert _enrol(client, token)[0].status_code == 201


def test_a_refused_reissue_does_not_spend_the_token(authority):
    store = _FleetStore()
    client = _client(store, ca=authority)
    first = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={}).json()["token"]
    _enrol(client, first)

    second = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                         json={}).json()["token"]
    assert _enrol(client, second)[0].status_code == 409
    assert store.tokens[enrolment.hash_token(second)]["used_at"] is None


def test_a_token_that_produced_a_certificate_stays_spent(authority):
    """The release path must never reopen a token that actually worked."""
    store = _FleetStore()
    client = _client(store, ca=authority)
    token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={}).json()["token"]
    _enrol(client, token)
    assert store.release_enrolment_token(enrolment.hash_token(token)) is False


@pytest.mark.parametrize("body", [
    {"ttl_hours": "soon"},
    {"ttl_hours": 0},
    {"ttl_hours": -5},
])
def test_a_rejected_mint_is_the_operators_mistake_not_a_server_fault(body,
                                                                    authority):
    """A 500 reads as "the fleet server is broken" when the actual problem is a
    ttl of "soon"."""
    client = _client(_FleetStore(), ca=authority)
    response = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                           json=body)
    assert response.status_code == 400


def test_a_name_too_long_for_a_certificate_is_refused_at_mint_time():
    """Without this the token is redeemable right up to the moment the
    certificate is built — in a substation, minutes after it was handed over,
    with the token spent."""
    with pytest.raises(enrolment.EnrolmentError) as exc:
        enrolment.mint("pi-" + "x" * 100)
    assert "64" in str(exc.value)

    with pytest.raises(enrolment.EnrolmentError):
        enrolment.mint("pi-a", site="Substation " + "A" * 100)


def test_a_control_character_in_a_name_is_refused():
    with pytest.raises(enrolment.EnrolmentError):
        enrolment.mint("pi-a\x00rogue")


def test_renewal_does_not_accumulate_identities_without_limit(authority):
    """The enrolment path refuses to let one collector hold two identities. The
    renewal path would have undone that rule one renewal at a time: the overlap
    that protects against a lost response is deliberate, and unbounded it means
    a collector holding five, ten, twenty valid certificates."""
    store, client, first, fingerprint = _enrolled(authority)

    current = fingerprint
    for _ in range(3):
        csr, _key = _csr()
        response = client.post("/api/v1/renew", json={"csr": csr},
                               headers=_headers("pi-a", current))
        assert response.status_code == 201, response.text
        current = store.certs[response.json()["serial"]]["fingerprint"]

    active = store.active_certificates("pi-a")
    assert len(active) == 2, (
        "a collector accumulated %d valid identities" % len(active))


def test_a_certificate_cannot_outlive_the_ca_that_signed_it(tmp_path):
    """It verifies against nothing once the CA has expired, and the failure
    surfaces as a TLS handshake error in a substation with nothing pointing
    back here."""
    authority = fleet_ca.CertificateAuthority.create(
        str(tmp_path / "short-ca"), days=1)
    csr, _key = _csr()
    issued = authority.sign(csr, "pi-a", days=90)

    assert issued.not_after <= _utcnow() + datetime.timedelta(days=1, hours=1)
    assert "shortened" in issued.note, "the lifetime was cut without saying so"


def test_an_expired_ca_refuses_to_issue(tmp_path):
    authority = fleet_ca.CertificateAuthority.create(
        str(tmp_path / "dead-ca"), days=0)
    csr, _key = _csr()
    with pytest.raises(fleet_ca.CaError) as exc:
        authority.sign(csr, "pi-a")
    assert "re-enrol the fleet" in str(exc.value)


def test_the_test_double_implements_everything_the_api_calls():
    """The seventh defect, and the one that would have hidden the others.

    `_FleetStore` stands in for `Store`. When the API grew a call the double did
    not have, the double raised AttributeError — which surfaced here only
    because a test happened to exercise that branch. On a branch no test
    reached, the double would have stayed silent and production would have
    answered 500.

    So the double is checked against the API's actual calls, and the real Store
    is checked against them too: a method the API calls and the Store lacks is
    the same bug with the roles reversed.
    """
    import re

    from ot_server.store import Store

    with open(os.path.join(_ROOT, "ot_server", "api.py"), encoding="utf-8") as fh:
        called = set(re.findall(r"\bstore\.([a-z_]+)\(", fh.read()))
    assert called, "the scan found no store calls at all"

    missing_real = sorted(n for n in called if not hasattr(Store, n))
    assert not missing_real, "the API calls Store.%s, which does not exist" % (
        ", Store.".join(missing_real))

    # The double is deliberately PARTIAL — it serves the enrolment routes and
    # not the estate ones. What it must not be is DIVERGENT: every method it
    # does implement has to exist on the real Store under the same name, or a
    # rename leaves the double answering happily for a method production no
    # longer has.
    double = _FleetStore()
    invented = sorted(
        name for name in dir(double)
        if not name.startswith("_") and callable(getattr(double, name))
        and not hasattr(Store, name))
    assert not invented, (
        "_FleetStore implements %s, which Store does not. The double has "
        "drifted from the thing it stands in for." % ", ".join(invented))


def test_a_limit_over_a_meaningless_order_is_not_reintroduced():
    """`severity` is TEXT, so ORDER BY severity is alphabetical: 'medium'
    before 'low' before 'high'. With a LIMIT on top, the query drops the
    high-severity detections first while looking like it kept the important
    ones."""
    with open(os.path.join(_ROOT, "ot_server", "store.py"), encoding="utf-8") as fh:
        source = fh.read()
    assert "severity DESC LIMIT" not in source


def test_a_malformed_body_is_the_callers_mistake_not_a_server_fault(authority):
    """A 500 says the server is broken when the truth is that the request was —
    and `/api/v1/enrol` is the one route reachable without a client
    certificate, so it is the worst place to say it."""
    client = _client(_FleetStore(), ca=authority)
    response = client.post("/api/v1/enrol", content=b"{not json",
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 400, response.text


def test_an_unauthenticated_caller_is_told_nothing_about_its_body(authority):
    """Authentication runs before the body is even parsed. A caller with no
    valid certificate learns that it has no valid certificate, and nothing
    about what the server thought of what it sent."""
    client = _client(_FleetStore(), ca=authority)
    response = client.post("/api/v1/heartbeat", content=b"{not json",
                           headers={**_headers("pi-a"),
                                    "Content-Type": "application/json"})
    assert response.status_code == 401


def test_an_enrolled_collector_sending_rubbish_gets_a_400(authority):
    _store, client, _body, fingerprint = _enrolled(authority)
    response = client.post("/api/v1/heartbeat", content=b"{not json",
                           headers={**_headers("pi-a", fingerprint),
                                    "Content-Type": "application/json"})
    assert response.status_code == 400


def test_a_json_body_that_is_not_an_object_is_refused(authority):
    client = _client(_FleetStore(), ca=authority)
    response = client.post("/api/v1/enrol", json=["token", "csr"])
    assert response.status_code == 400


def test_a_malformed_body_does_not_become_the_defaults(authority):
    """Swallowing it would hand an operator the defaults for a request they
    thought they had parameterised — a 24-hour token for someone who asked for
    one hour and mistyped the JSON around it."""
    client = _client(_FleetStore(), ca=authority)
    response = client.post(
        "/api/v1/estate/collectors/pi-a/enrolment-token",
        content=b'{"ttl_hours": 1,,}',
        headers={"Content-Type": "application/json"})
    assert response.status_code == 400


def test_an_absent_body_is_still_the_defaults(authority):
    """No body and a broken body are different requests. All of this route's
    fields are optional, so sending none of them is a real thing to do."""
    client = _client(_FleetStore(), ca=authority)
    response = client.post("/api/v1/estate/collectors/pi-a/enrolment-token")
    assert response.status_code == 201
    assert response.json()["allow_reissue"] is False
