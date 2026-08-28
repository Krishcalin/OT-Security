"""
The TLS terminator contract, proved against a real nginx (DECISIONS D8).

Everything this server knows about who is calling comes from two headers a
terminator sets. `deploy/nginx/ot-fleet.conf` is the config that must set them
correctly, and a config nobody executes is a document, not a control.

So this starts the fleet server, puts the REPO'S OWN nginx config in front of it
in a container with mutual TLS, and attacks it from outside: an anonymous
caller, a revoked certificate, and a caller supplying its own identity headers
alongside a certificate it legitimately holds.

WHAT WRITING THE CONFIG CHANGED
───────────────────────────────
Two things, neither of which was visible from the design:

nginx has no SHA-256 fingerprint variable. `$ssl_client_fingerprint` is SHA-1,
and nothing in stock nginx produces the digest the server records. The server
now accepts the verified certificate itself (`$ssl_client_escaped_cert`) and
computes the digest — which is the better division anyway, since nginx is then
trusted for one thing rather than two.

And `/api/v1/enrol` and `/api/v1/ca` must work WITHOUT a client certificate: a
collector arriving at a substation has none, and obtaining one is what it is
there for. So verification is `optional` at the server level and enforced per
location, which is a very different config from the obvious one.

RUNNING IT
──────────
Needs Docker. Skipped without it, and REFUSED as a skip when
OT_TERMINATOR_REQUIRED is set — which the CI test job does, because GitHub's
ubuntu runners have Docker, and a skipped test on a summary page is
indistinguishable from a passing one.
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

NGINX_IMAGE = "nginx:1.27-alpine"
CONTAINER = "ot-terminator-test"


def _docker_works() -> bool:
    if shutil.which("docker") is None and shutil.which("docker.exe") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=60).returncode == 0
    except Exception:                                      # noqa: BLE001
        return False


_REQUIRED = os.environ.get("OT_TERMINATOR_REQUIRED", "").lower() in (
    "1", "true", "yes")
_AVAILABLE = _docker_works()

if _REQUIRED and not _AVAILABLE:
    raise RuntimeError(
        "OT_TERMINATOR_REQUIRED is set but Docker is not usable. The terminator "
        "contract would go unchecked, and a skipped test on a summary page is "
        "indistinguishable from a passing one.")

pytestmark = pytest.mark.skipif(
    not _AVAILABLE, reason="Docker is not available for the terminator test")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _openssl(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True)


class _Fleet:
    """A server, a terminator in front of it, and the certificates for both."""

    def __init__(self, work):
        self.work = str(work)
        self.tls = os.path.join(self.work, "tls")
        os.makedirs(self.tls, exist_ok=True)
        self.app_port = _free_port()
        self.tls_port = _free_port()
        self.server = None

    # ── set-up ────────────────────────────────────────────────────────────

    def start(self):
        from ot_server import ca as fleet_ca
        from ot_server.api import create_app

        from test_fleet_enrolment import _FleetStore

        self.ca = fleet_ca.CertificateAuthority.create(
            os.path.join(self.work, "ca"))
        with open(os.path.join(self.tls, "fleet-ca.pem"), "w") as fh:
            fh.write(self.ca.ca_pem)

        _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=localhost",
                 "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                 "-keyout", os.path.join(self.tls, "server-key.pem"),
                 "-out", os.path.join(self.tls, "server-cert.pem"))

        self.store = _FleetStore()
        self.good = self.issue("pi-substation-01", "Substation A")
        self.revoked = self.issue("pi-substation-02", "Substation B")
        self.store.revoke_certificate(self.revoked[2].serial,
                                      "cabinet found open")

        app = create_app(self.store, require_operator=lambda r: "op",
                         console_dir=os.path.join(_ROOT, "console"),
                         ca=self.ca)
        import uvicorn

        config = uvicorn.Config(app, host="0.0.0.0", port=self.app_port,
                                log_level="error")
        self.server = uvicorn.Server(config)
        threading.Thread(target=self.server.run, daemon=True).start()
        for _ in range(200):
            if self.server.started:
                break
            time.sleep(0.1)
        assert self.server.started, "the fleet server did not start"

        self._start_nginx()

    def issue(self, collector_id, site):
        key = os.path.join(self.work, "%s-key.pem" % collector_id)
        _openssl("genpkey", "-algorithm", "EC",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", key)
        csr = _openssl("req", "-new", "-key", key, "-sha256",
                       "-subj", "/CN=%s" % collector_id).stdout.decode()
        issued = self.ca.sign(csr, collector_id, site)
        self.store.ensure_collector(collector_id)
        self.store.record_certificate(issued)
        cert = os.path.join(self.work, "%s-cert.pem" % collector_id)
        with open(cert, "w") as fh:
            fh.write(issued.pem)
        return cert, key, issued

    def _start_nginx(self):
        source = os.path.join(_ROOT, "deploy", "nginx", "ot-fleet.conf")
        with open(source, encoding="utf-8") as fh:
            conf = fh.read()
        # Only what the container cannot know: where the app is, and the port.
        # The directives under test are used exactly as they ship.
        conf = conf.replace("server 127.0.0.1:8001;",
                            "server host.docker.internal:%d;" % self.app_port)
        conf = conf.replace("listen 443 ssl;", "listen 8443 ssl;")
        conf = conf.replace("http2 on;", "")
        path = os.path.join(self.work, "ot-fleet.conf")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(conf)

        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
        run = subprocess.run(
            ["docker", "run", "-d", "--name", CONTAINER,
             "--add-host", "host.docker.internal:host-gateway",
             "-p", "%d:8443" % self.tls_port,
             "-v", "%s:/etc/nginx/conf.d/default.conf:ro" % path,
             "-v", "%s:/etc/nginx/tls:ro" % self.tls,
             NGINX_IMAGE], capture_output=True, text=True)
        assert run.returncode == 0, run.stderr

        for _ in range(120):
            probe = subprocess.run(["docker", "exec", CONTAINER, "nginx", "-t"],
                                   capture_output=True, text=True)
            if "successful" in probe.stderr:
                return
            time.sleep(0.5)
        raise AssertionError("nginx never accepted deploy/nginx/ot-fleet.conf")

    def stop(self):
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
        if self.server is not None:
            self.server.should_exit = True

    # ── talking to it ─────────────────────────────────────────────────────

    def call(self, path, cert=None, key=None, headers=None, method="GET",
             body=None, repeat=None, direct=False):
        """One request, with full control over the headers.

        Not `requests` or curl: curl on some platforms is built against
        Schannel, which will not load a PEM client certificate, and putheader()
        is what lets a header be sent TWICE.
        """
        if direct:
            conn = http.client.HTTPConnection("127.0.0.1", self.app_port,
                                              timeout=30)
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            if cert:
                context.load_cert_chain(cert, key)
            conn = http.client.HTTPSConnection("localhost", self.tls_port,
                                               context=context, timeout=30)
        payload = json.dumps(body).encode() if body is not None else b""
        try:
            conn.putrequest(method, path, skip_accept_encoding=True)
            if payload:
                conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(payload)))
            for name, value in (headers or {}).items():
                conn.putheader(name, value)
            for name, value in (repeat or []):
                conn.putheader(name, value)
            conn.endheaders()
            if payload:
                conn.send(payload)
            response = conn.getresponse()
            return response.status, response.read().decode("utf-8", "replace")
        finally:
            conn.close()


@pytest.fixture(scope="module")
def fleet(tmp_path_factory):
    pytest.importorskip("fastapi")
    pytest.importorskip("uvicorn")
    pytest.importorskip("cryptography")
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not on PATH")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    fleet = _Fleet(tmp_path_factory.mktemp("terminator"))
    fleet.start()
    try:
        yield fleet
    finally:
        fleet.stop()


# ── the config the repository ships actually loads ─────────────────────────

def test_the_shipped_nginx_config_is_valid(fleet):
    """`nginx -t` inside the container, against deploy/nginx/ot-fleet.conf.
    The fixture refuses to come up otherwise, so reaching here proves it."""
    probe = subprocess.run(["docker", "exec", CONTAINER, "nginx", "-t"],
                           capture_output=True, text=True)
    assert "successful" in probe.stderr


# ── the two planes ─────────────────────────────────────────────────────────

def test_the_ca_is_published_without_a_client_certificate(fleet):
    """A collector arriving at a substation has no certificate, and checking
    the fingerprint before spending its token is what this route is for."""
    status, body = fleet.call("/api/v1/ca")
    assert status == 200
    assert "BEGIN CERTIFICATE" in body


def test_the_estate_plane_refuses_an_anonymous_caller_at_the_proxy(fleet):
    """Refused by nginx, before the request reaches the server at all."""
    status, _ = fleet.call("/api/v1/estate/certificates")
    assert status == 403


def test_a_valid_collector_certificate_is_accepted(fleet):
    cert, key, _issued = fleet.good
    status, body = fleet.call("/api/v1/heartbeat", cert, key, method="POST",
                              body={"collector_version": "0.1.0"})
    assert status == 200, body


def test_a_revoked_certificate_is_refused_end_to_end(fleet):
    """It is still cryptographically valid — nginx accepts it happily, because
    the fleet CA signed it. The refusal comes from the issuance record."""
    cert, key, _issued = fleet.revoked
    status, body = fleet.call("/api/v1/heartbeat", cert, key, method="POST",
                              body={})
    assert status == 401
    assert "revoked" in body and "cabinet found open" in body


# ── forging identity through the proxy ─────────────────────────────────────

def test_a_forged_subject_header_does_not_become_the_identity(fleet):
    """The attack the contract exists to stop: a caller supplying its own
    identity alongside a certificate it legitimately holds. `proxy_set_header`
    replaces it, so the revoked certificate is what the server sees."""
    cert, key, _issued = fleet.revoked
    status, body = fleet.call(
        "/api/v1/heartbeat", cert, key, method="POST", body={},
        headers={"X-Client-Subject": "CN=pi-substation-01,O=Fleet"})
    assert status == 401
    assert "pi-substation-01" not in body or "revoked" in body


def test_a_forged_fingerprint_header_is_not_honoured(fleet):
    """What defeats this is the CERTIFICATE, not the clearing directive.

    The first version of this test claimed the opposite, and deleting
    `proxy_set_header X-Client-Fingerprint ""` from the shipped config did not
    fail it — because nginx also sets `X-Client-Cert`, and the certificate wins
    when both arrive. The claim was wrong and the test was passing for a
    different reason than it stated.

    Deleting the CERTIFICATE directive instead fails this test, and that is the
    finding worth keeping: with no certificate passed, the caller's forged
    fingerprint IS believed, and the clearing directive becomes the only thing
    in the way. Which is the shape HAProxy deployments run in — see
    `test_both_shipped_configs_clear_every_identity_header`.
    """
    cert, key, _issued = fleet.revoked
    good_fingerprint = fleet.good[2].fingerprint
    status, body = fleet.call(
        "/api/v1/heartbeat", cert, key, method="POST", body={},
        headers={"X-Client-Fingerprint": good_fingerprint})
    assert status == 401
    assert "revoked" in body


def test_a_forged_certificate_header_is_replaced_by_the_verified_one(fleet):
    cert, key, _issued = fleet.revoked
    status, body = fleet.call(
        "/api/v1/heartbeat", cert, key, method="POST", body={},
        headers={"X-Client-Cert": "-----BEGIN CERTIFICATE-----rubbish"})
    assert status == 401
    assert "revoked" in body, "the caller's certificate header was believed"


def test_an_anonymous_caller_cannot_name_itself_on_the_enrolment_route(fleet):
    """The one route without mutual TLS. The identity headers are cleared there
    too — a route that does not need an identity must still not accept one."""
    status, body = fleet.call(
        "/api/v1/enrol", method="POST", body={"token": "x", "csr": "y"},
        headers={"X-Client-Subject": "CN=pi-substation-01,O=Fleet"})
    assert status == 403
    assert "token" in body


# ── and when a terminator gets it wrong anyway ─────────────────────────────

def test_a_repeated_identity_header_is_refused(fleet):
    """nginx REPLACES, so this cannot be produced through it — which is why it
    goes straight at the server. HAProxy's `add-header` would produce exactly
    this, and the caller's value comes first."""
    status, body = fleet.call(
        "/api/v1/heartbeat", method="POST", body={}, direct=True,
        repeat=[("X-Client-Subject", "CN=attacker,O=Fleet"),
                ("X-Client-Subject", "CN=pi-substation-01,O=Fleet")])
    assert status == 401
    assert "STRIP" in body


def test_both_shipped_configs_clear_every_identity_header():
    """Read from the files, because this cannot be proved by running nginx.

    Under the shipped nginx config the certificate decides, so clearing
    `X-Client-Fingerprint` is redundant — deleting it fails nothing. Under a
    terminator that sends a fingerprint and no certificate, which is the shape
    the HAProxy config runs in, it is the only protection there is: remove the
    certificate directive from the nginx config and the forged fingerprint is
    believed, which is what
    `test_a_forged_fingerprint_header_is_not_honoured` demonstrates.

    A directive that is redundant in one deployment and load-bearing in another
    is one to assert the presence of rather than reason about each time.
    """
    deploy = os.path.join(_ROOT, "deploy")
    with open(os.path.join(deploy, "nginx", "ot-fleet.conf"),
              encoding="utf-8") as fh:
        nginx = fh.read()
    for header in ("X-Client-Subject", "X-Client-Cert", "X-Client-Fingerprint"):
        assert nginx.count("proxy_set_header %s" % header) >= 3, (
            "%s is not set on every location in the nginx config; a header "
            "this config leaves alone is a header the caller supplies" % header)

    with open(os.path.join(deploy, "haproxy", "ot-fleet.cfg"),
              encoding="utf-8") as fh:
        haproxy = fh.read()
    for header in ("X-Client-Subject", "X-Client-Cert", "X-Client-Fingerprint"):
        assert "del-header %s" % header in haproxy, (
            "%s is not deleted before HAProxy sets its own" % header)
    assert "add-header X-Client" not in haproxy, (
        "add-header APPENDS, leaving the caller's value in front of HAProxy's")
