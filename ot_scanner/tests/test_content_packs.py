"""
Signed content packs, server and collector (Phase 6).

Three tests carry this file.

`test_both_sides_agree_on_the_bytes_that_are_signed` — the server builds the
canonical body in Python with `cryptography`, and the collector rebuilds it
independently to hand to openssl. Two implementations of "what exactly was
signed" is precisely where a signing scheme breaks, and it breaks silently: the
signature simply stops verifying and every collector refuses every pack, which
looks like a fleet that will not update rather than a serialisation
disagreement.

`test_a_correctly_signed_older_pack_is_refused` — every pack this server ever
issued stays correctly signed forever. An attacker who can answer a collector's
fetch, or simply replay a recorded response, serves a genuine old pack and rolls
the fleet back past every detection added since. The signature is not the
control here; the version is.

`test_a_pack_may_not_carry_anything_but_data` — the deliberate departure from
what Dragos ships. Their packs carry protocol dissection engines, which is
executable code delivered to every sensor in every plant. That is a remote code
execution path by design, with one key in the way.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import stat
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ot_server import packs                                # noqa: E402

pytest.importorskip("cryptography")

from collector import content as collector_content         # noqa: E402


def payload():
    """A fresh payload per test.

    Shared module-level test data plus any copy that is not deep is how one
    test's tampering becomes the next test's starting state — which is exactly
    what happened here, and it made a refusal look like an acceptance.
    """
    return copy.deepcopy(_BASE_PAYLOAD)


_BASE_PAYLOAD = {
    "indicators": [
        {"kind": "ip", "value": "203.0.113.9", "why": "PIPEDREAM staging",
         "severity": "high"},
    ],
    "signatures": [
        {"rule_id": "iec104-unauthorised-c-sc-na-1", "protocol": "iec104",
         "severity": "high", "title": "Single command from an unexpected source",
         "remediation": "Confirm the originating address is a known master."},
    ],
}


@pytest.fixture()
def signer(tmp_path):
    return packs.ContentSigner.create(str(tmp_path / "content"))


# ── the key ────────────────────────────────────────────────────────────────

def test_the_content_key_is_not_the_ca_key(tmp_path):
    """One key doing both means anyone who can publish a detection update can
    also mint a collector identity, and anyone who can mint an identity can
    publish content the fleet will run."""
    from ot_server import ca as fleet_ca

    directory = str(tmp_path / "pki")
    authority = fleet_ca.CertificateAuthority.create(directory)
    content = packs.ContentSigner.create(directory)

    assert os.path.isfile(os.path.join(directory, fleet_ca.CA_KEY_NAME))
    assert os.path.isfile(os.path.join(directory, packs.SIGNING_KEY_NAME))
    assert authority.ca_pem != content.public_key_pem


def test_replacing_the_signing_key_is_refused(tmp_path):
    """Every collector holds the old public key. A new one strands all of them:
    they refuse each new pack as unsigned and keep running what they have,
    silently, until somebody notices."""
    directory = str(tmp_path / "content")
    packs.ContentSigner.create(directory)
    with pytest.raises(packs.PackError) as exc:
        packs.ContentSigner.create(directory)
    assert "strand" in str(exc.value)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_a_readable_signing_key_is_refused_rather_than_used(tmp_path):
    directory = str(tmp_path / "content")
    packs.ContentSigner.create(directory)
    os.chmod(os.path.join(directory, packs.SIGNING_KEY_NAME), 0o644)
    with pytest.raises(packs.PackError) as exc:
        packs.ContentSigner.load(directory)
    assert "disclosed" in str(exc.value)


# ── signing and verifying ──────────────────────────────────────────────────

def test_a_signed_pack_verifies(signer):
    pack = signer.sign(packs.KIND_RULES, 1, payload())
    verdict = packs.verify(signer.public_key_pem, pack.to_dict())
    assert verdict.ok, verdict.reason
    assert "1 indicators" in verdict.reason and "1 signatures" in verdict.reason


def test_a_tampered_payload_does_not_verify(signer):
    pack = signer.sign(packs.KIND_RULES, 1, payload()).to_dict()
    pack["payload"]["indicators"][0]["value"] = "198.51.100.7"
    verdict = packs.verify(signer.public_key_pem, pack)
    assert not verdict.ok
    assert "not signed by the key" in verdict.reason


def test_a_pack_signed_by_another_key_does_not_verify(signer, tmp_path):
    other = packs.ContentSigner.create(str(tmp_path / "other"))
    pack = other.sign(packs.KIND_RULES, 1, payload())
    assert not packs.verify(signer.public_key_pem, pack.to_dict()).ok


def test_an_unsigned_pack_is_refused(signer):
    pack = signer.sign(packs.KIND_RULES, 1, payload()).to_dict()
    pack["signature"] = ""
    verdict = packs.verify(signer.public_key_pem, pack)
    assert not verdict.ok and "unsigned" in verdict.reason


def test_every_signature_failure_reads_the_same(signer, tmp_path):
    """A bad signature, a tampered payload and a malformed key are one event to
    a collector — content it must not run. Telling an attacker which one they
    achieved tells them how close they are."""
    other = packs.ContentSigner.create(str(tmp_path / "other"))
    tampered = signer.sign(packs.KIND_RULES, 1, payload()).to_dict()
    tampered["payload"]["indicators"] = []
    wrong_key = other.sign(packs.KIND_RULES, 1, payload()).to_dict()
    reasons = {packs.verify(signer.public_key_pem, tampered).reason,
               packs.verify(signer.public_key_pem, wrong_key).reason}
    assert len(reasons) == 1


# ── the rollback ───────────────────────────────────────────────────────────

def test_a_correctly_signed_older_pack_is_refused(signer):
    """THE one. The signature is not the control; the version is."""
    old = signer.sign(packs.KIND_RULES, 4, payload())
    assert packs.verify(signer.public_key_pem, old.to_dict(),
                        current_version=0).ok

    verdict = packs.verify(signer.public_key_pem, old.to_dict(),
                           current_version=7)
    assert not verdict.ok
    assert "rollback" in verdict.reason or "already held" in verdict.reason


def test_the_same_version_again_is_refused(signer):
    pack = signer.sign(packs.KIND_RULES, 3, payload())
    assert not packs.verify(signer.public_key_pem, pack.to_dict(),
                            current_version=3).ok


# ── data, never code ───────────────────────────────────────────────────────

@pytest.mark.parametrize("payload", [
    {"dissectors": [{"protocol": "profinet", "code": "import os"}]},
    {"indicators": [], "hooks": [{"on": "start", "run": "curl | sh"}]},
    {"plugins": []},
])
def test_a_pack_may_not_carry_anything_but_data(signer, payload):
    """A channel that delivers code to every collector in every substation and
    runs it is a remote code execution path into the plant, by design, with the
    signing key as the only thing in the way."""
    with pytest.raises(packs.PackError) as exc:
        signer.sign(packs.KIND_RULES, 1, payload)
    assert "DATA, never code" in str(exc.value)


def test_a_section_that_is_not_a_list_is_refused(signer):
    with pytest.raises(packs.PackError):
        signer.sign(packs.KIND_RULES, 1, {"indicators": {"not": "a list"}})


def test_an_unknown_pack_kind_is_refused(signer):
    with pytest.raises(packs.PackError):
        signer.sign("firmware", 1, {})


def test_a_version_below_one_is_refused(signer):
    with pytest.raises(packs.PackError):
        signer.sign(packs.KIND_RULES, 0, payload())


# ── the two implementations must agree ─────────────────────────────────────

def test_both_sides_agree_on_the_bytes_that_are_signed(signer):
    """THE interop test.

    The server builds the canonical body one way and the collector rebuilds it
    another. A disagreement here breaks silently: signatures stop verifying, the
    whole fleet refuses every pack, and it looks like a distribution problem
    rather than a serialisation one.
    """
    pack = signer.sign(packs.KIND_RULES, 9, payload())
    assert collector_content.canonical_bytes(pack.to_dict()) == pack.canonical()


def test_key_order_and_whitespace_cannot_drift(signer):
    """The canonical form is sorted and separator-pinned, so a pack that has
    been round-tripped through any JSON library still verifies."""
    pack = signer.sign(packs.KIND_RULES, 2, payload())
    reordered = json.loads(json.dumps(pack.to_dict()))
    assert collector_content.canonical_bytes(reordered) == pack.canonical()
    assert packs.verify(signer.public_key_pem, reordered).ok


# ── the collector side ─────────────────────────────────────────────────────

@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_the_collector_verifies_a_real_signature(tmp_path, signer):
    directory = str(tmp_path / "collector-pki")
    os.makedirs(directory)
    key_path = os.path.join(directory, collector_content.KEY_NAME)
    with open(key_path, "w", encoding="ascii") as fh:
        fh.write(signer.public_key_pem)

    pack = signer.sign(packs.KIND_RULES, 1, payload()).to_dict()
    applied = collector_content.apply_pack(directory, pack, key_path)
    assert applied.version == 1
    assert collector_content.current_version(directory) == 1


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_the_collector_refuses_a_tampered_pack_and_keeps_what_it_has(
        tmp_path, signer):
    """No path here ends with a collector running NO content. A sensor that
    silently stops detecting looks exactly like a quiet plant."""
    directory = str(tmp_path / "collector-pki")
    os.makedirs(directory)
    key_path = os.path.join(directory, collector_content.KEY_NAME)
    with open(key_path, "w", encoding="ascii") as fh:
        fh.write(signer.public_key_pem)

    good = signer.sign(packs.KIND_RULES, 1, payload()).to_dict()
    collector_content.apply_pack(directory, good, key_path)

    bad = signer.sign(packs.KIND_RULES, 2, payload()).to_dict()
    bad["payload"]["indicators"][0]["value"] = "198.51.100.7"
    with pytest.raises(collector_content.ContentError):
        collector_content.apply_pack(directory, bad, key_path)

    assert collector_content.current_version(directory) == 1
    held = collector_content.current_pack(directory)
    assert held["payload"]["indicators"][0]["value"] == "203.0.113.9"


@pytest.mark.skipif(shutil.which("openssl") is None,
                    reason="openssl is not on PATH")
def test_the_collector_refuses_a_rollback(tmp_path, signer):
    directory = str(tmp_path / "collector-pki")
    os.makedirs(directory)
    key_path = os.path.join(directory, collector_content.KEY_NAME)
    with open(key_path, "w", encoding="ascii") as fh:
        fh.write(signer.public_key_pem)

    collector_content.apply_pack(
        directory, signer.sign(packs.KIND_RULES, 5, payload()).to_dict(), key_path)
    with pytest.raises(collector_content.ContentError) as exc:
        collector_content.apply_pack(
            directory, signer.sign(packs.KIND_RULES, 4, payload()).to_dict(),
            key_path)
    assert "rollback" in str(exc.value)
    assert collector_content.current_version(directory) == 5


def test_without_a_verification_key_nothing_is_applied(tmp_path):
    with pytest.raises(collector_content.ContentError) as exc:
        collector_content.update(str(tmp_path / "empty"), "https://fleet",
                                 "ca.pem", "cert.pem", "key.pem")
    assert "verification key" in str(exc.value)


def test_a_corrupt_pack_on_disk_reads_as_no_pack(tmp_path):
    """Not as a reason to run nothing — as a reason to accept the next valid
    pack as if this were the first."""
    directory = str(tmp_path / "collector-pki")
    os.makedirs(directory)
    with open(os.path.join(directory, collector_content.PACK_NAME), "w") as fh:
        fh.write("{ this is not json")
    assert collector_content.current_pack(directory) is None
    assert collector_content.current_version(directory) == 0


# ── fleet drift ────────────────────────────────────────────────────────────

def test_drift_separates_behind_from_never_reported():
    """"Has not told us" and "is running version 0" are different states, and
    only one of them is a collector to go and look at."""
    drift = packs.fleet_drift(7, {"pi-a": 7, "pi-b": 5, "pi-c": None})
    assert drift.current == ["pi-a"]
    assert drift.behind == [{"collector_id": "pi-b", "version": 5,
                             "behind_by": 2}]
    assert drift.unknown == ["pi-c"]
    assert drift.all_current is False
    assert "behind" in drift.explain()


def test_drift_says_so_plainly_when_the_fleet_is_current():
    drift = packs.fleet_drift(3, {"pi-a": 3, "pi-b": 4})
    assert drift.all_current is True
    assert "every collector" in drift.explain()


def test_drift_before_anything_is_published():
    drift = packs.fleet_drift(0, {"pi-a": None})
    assert "no rules pack has been published" in drift.explain()


# ── the routes ─────────────────────────────────────────────────────────────

class _PackStore:
    """In-memory, with the one behaviour that matters kept faithful: two packs
    cannot share a version, because "which content produced this finding" has to
    stay answerable."""

    def __init__(self):
        self.rows = {}
        self.reported = {}

    def publish_pack(self, pack, published_by=""):
        key = (pack.kind, pack.version)
        if key in self.rows:
            raise AssertionError("duplicate version %d" % pack.version)
        self.rows[key] = {"kind": pack.kind, "version": pack.version,
                          "created_at": pack.created_at, "digest": pack.digest,
                          "signature": pack.signature, "payload": pack.payload,
                          "published_by": published_by}

    def latest_pack(self, kind):
        matching = [r for r in self.rows.values() if r["kind"] == kind]
        if not matching:
            return None
        return dict(max(matching, key=lambda r: r["version"]))

    def latest_pack_version(self, kind):
        return max([r["version"] for r in self.rows.values()
                    if r["kind"] == kind] or [0])

    def packs(self, kind=None):
        return [dict(r) for r in sorted(self.rows.values(),
                                        key=lambda r: -r["version"])
                if kind in (None, r["kind"])]

    def reported_pack_versions(self):
        return dict(self.reported)


def _pack_client(store=None, with_signer=True, operator=True, tmp_path=None):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    signer = None
    if with_signer:
        signer = packs.ContentSigner.create(str(tmp_path / "signing"))
    return TestClient(create_app(
        store if store is not None else _PackStore(),
        require_operator=(lambda r: "operator") if operator else None,
        console_dir="", signer=signer)), signer


def _collector_headers():
    return {"X-Client-Subject": "CN=pi-alderley-01,O=Fleet"}


def test_without_a_signing_key_distribution_is_unavailable_not_unsigned(tmp_path):
    """Offering an unsigned pack would only teach the fleet to accept content it
    cannot check."""
    client, _ = _pack_client(with_signer=False, tmp_path=tmp_path)
    assert client.get("/api/v1/packs/key").status_code == 503
    assert client.post("/api/v1/estate/packs",
                       json={"payload": {}}).status_code == 503


def test_the_verification_key_is_published_without_authentication(tmp_path):
    """A verification key is useless to an attacker, and a collector needs it
    before it can check anything at all — the same reason /api/v1/ca is open."""
    client, signer = _pack_client(operator=False, tmp_path=tmp_path)
    response = client.get("/api/v1/packs/key")
    assert response.status_code == 200
    assert response.json()["public_key"] == signer.public_key_pem
    assert response.json()["algorithm"] == "Ed25519"


def test_nothing_published_yet_is_a_404_not_an_empty_pack(tmp_path):
    client, _ = _pack_client(tmp_path=tmp_path)
    response = client.get("/api/v1/packs/latest", headers=_collector_headers())
    assert response.status_code == 404
    assert "no rules pack has been published" in response.json()["detail"]


def test_publishing_assigns_the_version_and_the_caller_does_not(tmp_path):
    """A caller picking its own version could publish one the fleet refuses as a
    rollback, or collide with a version already issued."""
    store = _PackStore()
    client, _ = _pack_client(store, tmp_path=tmp_path)

    first = client.post("/api/v1/estate/packs",
                        json={"payload": payload(), "version": 99})
    assert first.status_code == 201, first.text
    assert first.json()["version"] == 1

    second = client.post("/api/v1/estate/packs", json={"payload": payload()})
    assert second.json()["version"] == 2


def test_a_collector_gets_the_newest_pack_and_it_verifies(tmp_path):
    store = _PackStore()
    client, signer = _pack_client(store, tmp_path=tmp_path)
    client.post("/api/v1/estate/packs", json={"payload": payload()})

    response = client.get("/api/v1/packs/latest", headers=_collector_headers())
    assert response.status_code == 200
    verdict = packs.verify(signer.public_key_pem, response.json())
    assert verdict.ok, verdict.reason


def test_an_up_to_date_collector_gets_no_body(tmp_path):
    """One empty response per cycle rather than a full pack the collector
    already holds."""
    store = _PackStore()
    client, _ = _pack_client(store, tmp_path=tmp_path)
    client.post("/api/v1/estate/packs", json={"payload": payload()})

    response = client.get("/api/v1/packs/latest?have=1",
                          headers=_collector_headers())
    assert response.status_code == 204
    assert not response.content


def test_a_collector_may_not_fetch_the_corpus(tmp_path):
    """The CVE corpus stays on the server under D3. A collector asking for it is
    misconfigured or probing; either way the answer is no."""
    client, _ = _pack_client(tmp_path=tmp_path)
    response = client.get("/api/v1/packs/latest?kind=corpus",
                          headers=_collector_headers())
    assert response.status_code == 403
    assert "stays on the server" in response.json()["detail"]


def test_a_pack_carrying_code_is_refused_at_the_route(tmp_path):
    client, _ = _pack_client(tmp_path=tmp_path)
    response = client.post(
        "/api/v1/estate/packs",
        json={"payload": {"dissectors": [{"protocol": "profinet"}]}})
    assert response.status_code == 400
    assert "DATA, never code" in response.json()["detail"]


def test_a_payload_that_is_not_an_object_is_refused(tmp_path):
    client, _ = _pack_client(tmp_path=tmp_path)
    assert client.post("/api/v1/estate/packs",
                       json={"payload": []}).status_code == 400


@pytest.mark.parametrize("path,method", [
    ("/api/v1/estate/packs", "get"),
    ("/api/v1/estate/packs", "post"),
])
def test_the_publishing_routes_are_fail_closed(path, method, tmp_path):
    client, _ = _pack_client(operator=False, tmp_path=tmp_path)
    call = getattr(client, method)
    response = call(path) if method == "get" else call(path, json={})
    assert response.status_code == 503


def test_the_listing_shows_which_collectors_are_behind(tmp_path):
    """Refusing a bad pack keeps a collector safe and leaves it on old content.
    Safe and stale has to be visible, or the fleet quietly stops detecting
    things nobody removed."""
    store = _PackStore()
    client, _ = _pack_client(store, tmp_path=tmp_path)
    client.post("/api/v1/estate/packs", json={"payload": payload()})
    client.post("/api/v1/estate/packs", json={"payload": payload()})
    store.reported = {"pi-a": 2, "pi-b": 1, "pi-c": None}

    body = client.get("/api/v1/estate/packs").json()
    assert body["signing_configured"] is True
    assert len(body["packs"]) == 2
    drift = body["drift"]
    assert drift["latest"] == 2
    assert drift["current"] == ["pi-a"]
    assert drift["behind"][0]["collector_id"] == "pi-b"
    assert drift["unknown"] == ["pi-c"]
    assert drift["all_current"] is False
    assert "will not report what the new pack would have found" in drift["explain"]


def test_the_published_pack_records_who_published_it(tmp_path):
    store = _PackStore()
    client, _ = _pack_client(store, tmp_path=tmp_path)
    client.post("/api/v1/estate/packs", json={"payload": payload()})
    assert store.packs()[0]["published_by"] == "operator"


def test_enrolment_hands_over_both_anchors_at_once(tmp_path):
    """The CA proves who the SERVER is; the content key proves what the CONTENT
    is. A collector that had to fetch the second one later would be fetching it
    over a channel it could not yet verify content on."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server import ca as fleet_ca
    from ot_server.api import create_app

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_fleet_enrolment import _FleetStore, _csr

    store = _FleetStore()
    authority = fleet_ca.CertificateAuthority.create(str(tmp_path / "ca"))
    signer = packs.ContentSigner.create(str(tmp_path / "signing"))
    client = TestClient(create_app(store, require_operator=lambda r: "op",
                                   console_dir="", ca=authority, signer=signer))

    token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={}).json()["token"]
    csr, _key = _csr()
    body = client.post("/api/v1/enrol",
                       json={"token": token, "csr": csr}).json()

    assert body["ca_certificate"].startswith("-----BEGIN CERTIFICATE")
    assert body["content_key"] == signer.public_key_pem
    assert body["content_key"] != body["ca_certificate"]


def test_a_server_that_signs_nothing_issues_no_content_key(tmp_path):
    """Not a failure — a fleet that will not be updated remotely, which
    `content.py` says plainly rather than applying anything unverified."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from ot_server import ca as fleet_ca
    from ot_server.api import create_app

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from test_fleet_enrolment import _FleetStore, _csr

    store = _FleetStore()
    authority = fleet_ca.CertificateAuthority.create(str(tmp_path / "ca"))
    client = TestClient(create_app(store, require_operator=lambda r: "op",
                                   console_dir="", ca=authority))

    token = client.post("/api/v1/estate/collectors/pi-a/enrolment-token",
                        json={}).json()["token"]
    csr, _key = _csr()
    body = client.post("/api/v1/enrol",
                       json={"token": token, "csr": csr}).json()
    assert body["content_key"] == ""
