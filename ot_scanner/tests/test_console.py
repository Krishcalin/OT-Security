"""
Phase 5 — the console (OTS-CON-001..006).

The interesting requirement is OTS-CON-004: every screen presenting counts or
clean states must display the coverage those numbers rest on, and a degraded
window must be visibly marked rather than footnoted.

A rule like that, enforced by review, survives about three sprints. Someone adds
a summary tile in a hurry, the number renders alone, and it looks exactly like
every other number on the page — the failure the collector, the spool and the
estate merge have all been built to prevent, arriving at the last step where a
person actually reads it.

So it is enforced by the TYPE CHECKER, and this file is what proves the
enforcement still bites. `src/con004.expect-errors.ts` contains code that MUST
NOT compile; if it ever does, OTS-CON-004 has quietly become a convention again.
"""
from __future__ import annotations

import datetime
import os
import re
import shutil
import subprocess
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONSOLE = os.path.join(_ROOT, "console")
SRC = os.path.join(CONSOLE, "src")

_INSTALLED = os.path.isdir(os.path.join(CONSOLE, "node_modules"))

# The same reasoning as OT_TEST_DSN in test_server_store.py. These tests skip
# silently without Node, and a skipped test on a CI summary page is
# indistinguishable from a passing one — so the job that exists to run them sets
# OT_CONSOLE_REQUIRED and gets a red build instead of a quiet green one in which
# OTS-CON-004 was never checked at all. Every other job may still skip.
if os.environ.get("OT_CONSOLE_REQUIRED", "").lower() in ("1", "true", "yes"):
    if not _INSTALLED:
        raise RuntimeError(
            "OT_CONSOLE_REQUIRED is set but console/node_modules is absent. "
            "The console tests would skip, and OTS-CON-004 would be enforced by "
            "nothing. Run `npm ci` in console/.")
    if shutil.which("npx") is None and shutil.which("npx.cmd") is None:
        raise RuntimeError(
            "OT_CONSOLE_REQUIRED is set but npx is not on PATH; the type "
            "checker is what enforces OTS-CON-004 and it would not run.")

pytestmark = pytest.mark.skipif(
    not _INSTALLED,
    reason="console dependencies not installed (npm install in console/)")


def _tsc(*args, cwd=CONSOLE):
    npx = shutil.which("npx") or shutil.which("npx.cmd")
    if npx is None:
        pytest.skip("npx not on PATH")
    return subprocess.run([npx, "tsc", *args], cwd=cwd, capture_output=True,
                          text=True, timeout=600)


# ── the console builds ─────────────────────────────────────────────────────

def test_the_console_type_checks():
    proc = _tsc("--noEmit")
    assert proc.returncode == 0, proc.stdout[-2000:]


def test_strictness_is_actually_on():
    """noUncheckedIndexedAccess caught a real bug here — a lookup returning
    undefined would have written the literal text "undefined" into the page. The
    settings are load-bearing, not decorative."""
    import json

    with open(os.path.join(CONSOLE, "tsconfig.json"), encoding="utf-8") as fh:
        cfg = json.load(fh)
    options = cfg["compilerOptions"]
    for flag in ("strict", "noUncheckedIndexedAccess",
                 "exactOptionalPropertyTypes"):
        assert options.get(flag) is True, "%s is off" % flag


# ── OTS-CON-004 is structural ──────────────────────────────────────────────

def test_every_expected_error_actually_errors():
    """The proof. Each EXPECT-ERROR line must produce a compiler error, and the
    counts must match — a file that fails for one reason while three other
    violations slipped through would still pass a naive check."""
    path = os.path.join(SRC, "con004.expect-errors.ts")
    with open(path, encoding="utf-8") as fh:
        expected = len(re.findall(r"^// EXPECT-ERROR", fh.read(), re.M))
    assert expected >= 4, "the harness lost its cases"

    proc = _tsc("--noEmit", "--strict", "--target", "ES2022",
                "--module", "ES2022", "--moduleResolution", "bundler",
                "--lib", "ES2022,DOM", "src/con004.expect-errors.ts")
    assert proc.returncode != 0, (
        "code that must not compile now compiles — OTS-CON-004 has stopped "
        "being structural and is a convention again")
    errors = len(re.findall(r"error TS", proc.stdout))
    assert errors == expected, (
        "expected %d compiler errors, got %d:\n%s"
        % (expected, errors, proc.stdout[-1500:]))


def test_the_harness_is_excluded_from_the_real_build():
    """Otherwise the console could never build."""
    import json

    with open(os.path.join(CONSOLE, "tsconfig.json"), encoding="utf-8") as fh:
        cfg = json.load(fh)
    assert any("expect-errors" in pattern for pattern in cfg.get("exclude", []))


# ── the rendering rules, read from source ──────────────────────────────────

def _read(name):
    with open(os.path.join(SRC, name), encoding="utf-8") as fh:
        return fh.read()


def test_nothing_renders_a_bare_number():
    """`metric` is the only headline-number path and it takes Measured<number>.
    An overload accepting a plain number would reopen the hole."""
    src = _read("render.ts")
    assert "m: Measured<number>" in src
    assert "value: number)" not in src


def test_unknown_coverage_is_an_alarm_not_a_neutral_grey():
    """'We could not tell' is the state most likely to be mistaken for 'fine'.
    Rendering it quietly restores the ambiguity the three-state model removes."""
    src = _read("coverage.ts")
    assert 'tone: "alarm"' in src
    unknown = src[src.index('case "unknown"'):]
    assert '"alarm"' in unknown[:400]


def test_a_zero_is_qualified_when_coverage_is_not_complete():
    """'0 findings' and 'no findings were observable' are different claims, and
    on a substation network the difference is the whole product."""
    src = _read("coverage.ts")
    assert "not evidence of absence" in src


def test_a_measured_value_cannot_be_built_without_a_basis():
    """A blank basis satisfies the type and defeats the point: the operator sees
    a coverage badge with nothing behind it."""
    src = _read("coverage.ts")
    assert "needs a basis" in src


def test_combining_measured_values_takes_the_weakest_coverage():
    """There is deliberately no way to combine and keep the better coverage."""
    src = _read("coverage.ts")
    assert "weakest(parts.map" in src


def test_a_fail_closed_api_is_surfaced_not_rendered_as_empty():
    """A 503 from the fail-closed estate plane must not become an empty, clean
    looking estate."""
    src = _read("api.ts")
    assert "503" in src and "fail-closed" in src


def test_an_unassessed_estate_is_unknown_not_zero_actionable():
    """With no corpus loaded, 'actionable: 0' would be a confident claim built
    on no assessment at all."""
    src = _read("api.ts")
    assert "has established nothing" in src or "nothing has been assessed" in src


def test_an_absent_asset_renders_as_a_state_not_a_deletion():
    src = _read("render.ts")
    assert "not observed" in src
    assert "did not speak" in src


def test_engine_limitations_are_rendered_not_hidden():
    """OTS-SRV-003 results carry what they could not consider; the console must
    show it rather than collapsing everything to a status chip."""
    src = _read("render.ts")
    assert "limitations" in src and "limits" in src


# ── the shell and the screens (OTS-CON-001..006) ───────────────────────────

SCREENS = ("estate", "assets", "findings", "topology", "change",
           "fleet", "account")
PUBLIC = os.path.join(CONSOLE, "public")


def _screen(name):
    with open(os.path.join(SRC, "screens", "%s.ts" % name),
              encoding="utf-8") as fh:
        return fh.read()


def test_every_screen_exists_and_is_routed():
    main = _read("main.ts")
    for name in SCREENS:
        assert os.path.isfile(os.path.join(SRC, "screens", "%s.ts" % name))
        assert 'id: "%s"' % name in main, "%s is built but unreachable" % name


def test_relative_imports_carry_their_extension():
    """`moduleResolution: bundler` accepts `./coverage`, and the browser does
    not. There is no bundler here — tsc's output is loaded as native ESM — so an
    extensionless import type-checks perfectly and then 404s at runtime, which
    renders as a screen that never appears rather than as an error."""
    import glob

    bad = []
    for path in glob.glob(os.path.join(SRC, "**", "*.ts"), recursive=True):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                match = re.search(r'from\s+"(\.[^"]+)"', line)
                if match and not match.group(1).endswith(".js"):
                    bad.append("%s: %s" % (os.path.basename(path),
                                           match.group(1)))
    assert not bad, "these imports would 404 in the browser: %s" % bad


def test_no_screen_writes_a_raw_value_into_markup():
    """OTS-CON-004 holds for headline numbers by construction: `metric` takes a
    Measured and nothing else. This closes the way around it — a screen building
    its own markup and interpolating a value straight into it, which the type
    checker cannot object to because the result is only a string.

    The rule is deliberately shaped so it needs no allowlist to maintain: an
    interpolation inside markup must be a call to a NAMED function. A list of
    approved helpers would have to grow every time a screen adds a composer, and
    a guard that asks to be edited to keep passing is one that eventually gets
    edited without being read.

    `${row.ip}`, `${vulns.count}` and `${a ? b : c}` are all rejected; `esc(x)`,
    `metric(...)`, `cls(...)` and a screen's own `priorityChip(m)` are accepted.
    Numbers inside a coverage BASIS are untouched by this — the basis is the
    explanation, and "3 windows degraded" belongs in it.
    """
    import glob

    call = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*\(")
    offenders = []
    targets = glob.glob(os.path.join(SRC, "screens", "*.ts"))
    targets.append(os.path.join(SRC, "router.ts"))
    for path in targets:
        with open(path, encoding="utf-8") as fh:
            for number, line in enumerate(fh, 1):
                if "<" not in line:
                    continue
                for expression in re.findall(r"\$\{([^}]*)\}", line):
                    if not call.match(expression.strip()):
                        offenders.append("%s:%d %s" % (
                            os.path.basename(path), number, expression.strip()))
    assert not offenders, (
        "values interpolated into markup without going through a render "
        "helper: %s" % offenders)


def test_the_guard_above_would_actually_catch_a_bare_value():
    """A guard nobody has seen fail is a guard nobody knows works."""
    call = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*\(")
    for bad in ("row.ip", "vulns.count", "a ? b : c", 'items.join("")', "tone"):
        assert not call.match(bad), "%s would have slipped through" % bad
    for good in ("esc(row.ip)", "metric(x, m)", 'cls("chip")'):
        assert call.match(good), "%s would be a false positive" % good


def test_the_shell_starts_as_a_failure_message_not_a_blank_page():
    """If the bundle never loads, whatever index.html holds is what the operator
    reads. A spinner suggests work in progress and an empty page reads as a
    plant with nothing in it; both are the failure this system is built to
    prevent, arriving at the last step."""
    with open(os.path.join(PUBLIC, "index.html"), encoding="utf-8") as fh:
        shell = fh.read()
    assert "The console did not start" in shell
    assert "not an empty estate" in shell


def test_a_failed_screen_clears_the_previous_one():
    """Leaving the last screen's figures up under a failed refresh presents
    stale numbers as current ones, and they look exactly as they did when they
    were true."""
    src = _read("router.ts")
    assert "cleared rather than left in place" in src


def test_a_fail_closed_estate_is_a_panel_not_an_empty_page():
    src = _read("router.ts")
    assert "503" in src and "this is not an empty estate" in src.lower()


def test_the_banner_belongs_to_the_shell_not_to_each_screen():
    """A rule every screen must remember to apply is one that the sixth screen,
    written in a hurry a year from now, will not."""
    main = _read("main.ts")
    assert "estateBanner(" in main
    for name in SCREENS:
        assert "estateBanner(" not in _screen(name), (
            "%s renders its own banner; the shell already renders one, and two "
            "answers to the same question is worse than either" % name)


def test_the_topology_screen_separates_no_zones_from_rejected_zones():
    """Both draw nothing. Only one of them means somebody holds a segmentation
    model that should not be trusted."""
    src = _screen("topology")
    assert "No zones could be derived" in src
    assert "derived and then rejected" in src


def test_a_defaulted_purdue_level_is_not_presented_as_an_observed_one():
    src = _screen("topology")
    assert '"role"' in src and '"protocol"' in src
    assert "fallback, not an observation" in src


def test_the_change_screen_reports_absence_as_a_state():
    """OTS-SRV-005. A passive sensor cannot tell a decommissioned device from
    one that did not speak, so nothing here may read as a deletion."""
    src = _screen("change")
    assert "not_observed" in src
    assert "not a deletion" in src


def test_drift_without_a_baseline_is_shown_rather_than_read_as_no_change():
    src = _screen("change")
    assert "SKIPPED" in src
    assert "most confident wrong answer" in src


def test_the_per_draw_cache_does_not_outlive_the_draw():
    """Two reads of estate coverage on one page can disagree — the banner
    saying whole while the tile below carries a degraded badge. A cache that
    survived the draw would show yesterday's estate as today's."""
    src = _read("main.ts")
    assert "reset()" in src and "per draw" in src


# ── the console is served without opening the estate plane ─────────────────

class _EmptyStore:
    """A server with nothing in it. Enough for the mounting tests, which are
    about what is reachable rather than about what is in the database."""

    def collector_ids(self):
        return []

    def collector_sites(self):
        return {}

    def all_assets(self, limit=5000):
        return []

    def assets(self, collector_id=None, limit=500):
        return []

    def all_flows(self, limit=20000):
        return []

    def all_detections(self, limit=20000):
        return []

    def recent_windows(self, cid):
        return []

    def recent_gaps(self, cid):
        return []

    def latest_window(self, cid):
        return ""

    def collectors_health(self):
        return []

    def latest_pack_version(self, kind):
        return 0

    def reported_pack_versions(self):
        return {}


def _app():
    pytest.importorskip("fastapi")
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    return TestClient(create_app(_EmptyStore(), require_operator=None,
                                 console_dir=CONSOLE))


def test_the_shell_is_served_from_the_same_origin_as_the_api():
    """The client sends `credentials: "same-origin"` and takes no API base URL.
    A second origin would mean relaxing CORS on the fail-closed estate plane
    just to make it reachable."""
    response = _app().get("/")
    assert response.status_code == 200
    assert "Power NetView" in response.text


def test_serving_the_console_does_not_open_the_estate_plane():
    """The shell is unauthenticated because it holds no estate data. Every
    figure on it still comes from an endpoint that is fail-closed."""
    client = _app()
    for path in ("/api/v1/estate/inventory", "/api/v1/estate/analysis",
                 "/api/v1/estate/zones"):
        assert client.get(path).status_code == 503


@pytest.mark.parametrize("path", [
    "/src/api.ts",
    "/node_modules/typescript/package.json",
    "/package.json",
    "/tsconfig.json",
])
def test_only_the_built_console_is_reachable(path):
    """Mounting the console tree wholesale would publish the source and every
    dependency to anyone who can reach the port."""
    assert _app().get(path).status_code == 404


def test_the_unknown_label_does_not_assert_a_cause_either():
    """The second time this mistake was made, and more quietly than the first.

    The TITLE was fixed to stop naming a mechanism. The LABEL kept doing it:
    "not measured" reads correctly over a capture window and wrongly over
    everything else `unknown` now covers — a revoked certificate was measured
    perfectly well and is simply not valid; a skipped engine never ran; an
    unassessed vulnerability had no corpus. The chip asserted a cause the basis
    beside it contradicted, on a table row where the label is read and the
    tooltip is not.

    Every `unknown` means one thing regardless of how it arose: this has not
    been established as clean.
    """
    src = _read("coverage.ts")
    labels = re.findall(r'label:\s*"([^"]+)"', src)
    assert labels, "the badge labels could not be found"
    for label in labels:
        for mechanism in ("measured", "frames", "capture", "packet", "lost"):
            assert mechanism not in label.lower(), (
                "the %r label names %r as a cause, which is wrong for every "
                "coverage state that did not arise that way" % (label, mechanism))


def test_unknown_is_still_the_loudest_state_on_the_page():
    """Cause-free must not become restful. It is the state most likely to be
    mistaken for fine."""
    src = _read("coverage.ts")
    unknown = src[src.index('case "unknown"'):]
    assert '"alarm"' in unknown[:400]


def test_a_coverage_badge_does_not_assert_a_cause_it_cannot_know():
    """The badge titles used to name a mechanism — "frames were lost", "capture
    loss could not be measured". That was true while every coverage state came
    from a capture window and false the moment they did not: an unassessed
    vulnerability count is `unknown` because no corpus is loaded, and a skipped
    engine is `unknown` because it never ran. Both rendered a tooltip blaming
    packet capture, contradicting the basis printed beside it.

    The title states the consequence; the cause belongs to the basis."""
    src = _read("coverage.ts")
    titles = src[src.index("export function badge("):]
    titles = titles[:titles.index("\n}")]
    for mechanism in ("frames", "capture", "packet"):
        assert mechanism not in titles, (
            "badge() names %r as the cause, which is wrong for every coverage "
            "state that did not come from a capture window" % mechanism)


# ── the screens actually render (OTS-CON-001..006) ─────────────────────────

def _payloads(directory, client=None):
    """Real API responses, dumped from the real app.

    Hand-written fixtures would drift from the server and keep passing while the
    console broke against it; these cannot.
    """
    import json

    client = client or _app_with_operator()
    for name in ("coverage", "inventory", "vulnerabilities", "assets",
                 "analysis", "zones", "certificates", "packs"):
        body = client.get("/api/v1/estate/%s" % name).json()
        with open(os.path.join(directory, "%s.json" % name), "w",
                  encoding="utf-8") as fh:
            json.dump(body, fh)


def _app_with_operator(store=None, ca=None):
    pytest.importorskip("fastapi")
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)
    from fastapi.testclient import TestClient

    from ot_server.api import create_app

    return TestClient(create_app(store or _PopulatedStore(),
                                 require_operator=lambda request: "operator",
                                 console_dir=CONSOLE, ca=ca))


class _PopulatedStore:
    """An estate with something in it, and something wrong with it: two sites
    sharing 10.0.0.1, one collector dropping frames, an asset that stopped being
    observed, and a detection whose asset row never arrived."""

    @staticmethod
    def _row(collector, key="ip:10.0.0.1", ip="10.0.0.1", window="w-1", **attrs):
        attributes = {"ip": ip}
        attributes.update(attrs)
        return {"collector_id": collector, "asset_key": key,
                "first_seen": 100.0, "last_seen": 200.0,
                "observation_count": 5, "last_observed_window": window,
                "last_coverage": "complete", "attributes": attributes}

    def collector_ids(self):
        return ["pi-a", "pi-b"]

    def collector_sites(self):
        return {"pi-a": "Substation A", "pi-b": "Substation B"}

    def all_assets(self, limit=5000):
        return [self._row("pi-a", vendor="Siemens", role="plc"),
                self._row("pi-a", key="ip:10.0.0.2", ip="10.0.0.2",
                          window="w-0", role="hmi"),
                self._row("pi-b")]

    def assets(self, collector_id=None, limit=500):
        return self.all_assets()

    def all_flows(self, limit=20000):
        return [{"flow_key": "f1", "collector_id": "pi-a",
                 "attributes": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                                "protocol": "modbus", "dst_port": "502",
                                "packet_count": 10, "byte_count": 900}}]

    def all_detections(self, limit=20000):
        return [{"detection_key": "d1", "collector_id": "pi-a",
                 "asset_key": "ip:10.0.0.1", "rule_id": "telnet",
                 "severity": "high", "last_coverage": "complete",
                 "rulepack_version": "1", "attributes": {"rule_id": "telnet"}},
                {"detection_key": "d2", "collector_id": "pi-a",
                 "asset_key": "ip:10.9.9.9", "rule_id": "ghost",
                 "severity": "low", "last_coverage": "complete",
                 "rulepack_version": "1", "attributes": {}}]

    def recent_windows(self, collector_id):
        if collector_id == "pi-b":
            return [{"coverage": "degraded"}]
        return [{"coverage": "complete"}]

    def recent_gaps(self, collector_id):
        return []

    def latest_window(self, collector_id):
        return "w-1"

    # A collector row is what fleet health reasons over. `last_heartbeat`
    # is the column the coverage model never looked at, and the reason a
    # switched-off collector could report a clean plant indefinitely.
    def collectors_health(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        return [
            {"collector_id": "pi-a", "site": "Substation A",
             "last_heartbeat": now, "capture_state": "complete",
             "queue_depth": 0, "enabled": True, "rulepack_version": "1"},
            {"collector_id": "pi-b", "site": "Substation B",
             "last_heartbeat": now, "capture_state": "degraded",
             "queue_depth": 0, "enabled": True, "rulepack_version": "1"},
        ]

    # ── fleet identities (Phase 6) ────────────────────────────────────────
    def __init__(self):
        self.certs = []

    def ensure_collector(self, collector_id):
        pass

    def set_site(self, collector_id, site):
        pass

    def certificates(self, collector_id=None):
        return [dict(c) for c in self.certs
                if collector_id in (None, c["collector_id"])]

    # Content packs: none published, which is a state the fleet screen must
    # draw rather than fail on.
    def packs(self, kind=None):
        return []

    def latest_pack_version(self, kind):
        return 0

    def reported_pack_versions(self):
        return {"pi-a": None}

    def active_certificates(self, collector_id):
        return []

    def record_certificate(self, issued):
        self.certs.append({
            "serial": issued.serial, "collector_id": issued.collector_id,
            "subject": issued.subject, "fingerprint": issued.fingerprint,
            "not_before": issued.not_before, "not_after": issued.not_after,
            "revoked_at": None, "revocation_reason": ""})


def _with_a_fleet_identity(tmp_path):
    """A store holding one real issued certificate, so the fleet screen renders
    its lifecycle rather than its no-CA explanation.

    Falls back to no CA when `cryptography` is absent — which exercises the
    other half of that screen, and is why render-check accepts an explanation in
    place of a chip.
    """
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)
    try:
        from ot_server import ca as fleet_ca
    except Exception:                                      # noqa: BLE001
        return _PopulatedStore(), None
    if not fleet_ca.available():
        return _PopulatedStore(), None

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    authority = fleet_ca.CertificateAuthority.create(
        os.path.join(str(tmp_path), "ca"))
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, "ignored")]))
           .sign(key, hashes.SHA256()))
    issued = authority.sign(
        csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "pi-a", site="Substation A")
    store = _PopulatedStore()
    store.record_certificate(issued)
    return store, authority


def test_every_screen_renders_against_real_api_responses(tmp_path):
    """The type checker proves a screen cannot render a number without its
    coverage. It does not prove the screen renders at all — a field read off a
    response shape that drifted type-checks against `api.ts` and then throws in
    the browser, where the operator sees a failure panel instead of an estate.

    So the compiled console is executed here, against payloads taken from the
    real app, with only `fetch` standing in."""
    node = shutil.which("node") or shutil.which("node.exe")
    if node is None:
        pytest.skip("node not on PATH")

    # Built rather than assumed: a stale dist/ would let this pass while the
    # source it claims to exercise no longer compiles into it.
    build = _tsc()
    assert build.returncode == 0, build.stdout[-2000:]

    store, authority = _with_a_fleet_identity(tmp_path)
    _payloads(str(tmp_path), _app_with_operator(store, authority))
    proc = subprocess.run([node, "render-check.mjs", str(tmp_path)],
                          cwd=CONSOLE, capture_output=True, text=True,
                          timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_render_check_would_notice_a_screen_that_drew_nothing():
    """A harness nobody has seen fail is a harness nobody knows works."""
    with open(os.path.join(CONSOLE, "render-check.mjs"), encoding="utf-8") as fh:
        src = fh.read()
    assert "rendered nothing" in src
    assert "rendered no coverage chip and no explanation" in src
    assert "[object Object]" in src


# ── the sign-in page (OTS-SRV-006) ─────────────────────────────────────────

def test_the_sign_in_page_is_served():
    response = _app().get("/login.html")
    assert response.status_code == 200
    assert "Power NetView" in response.text


def test_the_sign_in_page_starts_as_a_refusal_not_an_inert_form():
    """If the bundle never loads, whatever this holds is what an operator
    reads. A username box that looks like it works, and does not, is the shape
    a phishing page has."""
    with open(os.path.join(PUBLIC, "login.html"), encoding="utf-8") as fh:
        page = fh.read()
    assert "The sign-in page did not start" in page
    assert "Do not enter credentials" in page


def test_the_product_is_identified_before_a_password_is_asked_for():
    """On a narrow viewport the brand comes first. A bare username box with no
    branding above it is exactly what a phishing page looks like."""
    with open(os.path.join(PUBLIC, "login.html"), encoding="utf-8") as fh:
        page = fh.read()
    assert "login-brand-side" in page and "logo.svg" in page
    with open(os.path.join(PUBLIC, "console.css"), encoding="utf-8") as fh:
        css = fh.read()
    assert "order: -1" in css, "the brand does not come first on a small screen"


def test_the_logo_is_served():
    response = _app().get("/logo.svg")
    assert response.status_code == 200
    assert "svg" in response.headers.get("content-type", "")


def test_the_sign_in_page_does_not_split_its_error_messages():
    """A friendlier "no such operator" is a directory of who works at this
    utility; a friendlier "code wrong" confirms a guessed password."""
    src = _read("login.ts")
    assert "oracle" in src
    assert "no self-service reset" in src or "no \"forgot password\"" in src


def test_the_console_sends_an_expired_session_to_the_form():
    """Not a panel explaining that the operator should go and find it."""
    src = _read("router.ts")
    assert "/login.html" in src and "401" in src


def test_the_sign_in_form_sends_what_was_typed_into_it(tmp_path):
    """The test that was missing, and the reason it was missing.

    Every test of the sign-in path drove `/api/v1/auth/login` directly. They all
    passed while the page was incapable of signing anyone in: `submit()` called
    `draw()` first, which replaces innerHTML and destroys the inputs, and THEN
    read their values — so it posted an empty username and password every time.
    The server answered "invalid username or password", correctly, and the page
    told the operator their password was wrong when it had never sent it.

    A person found that in about four seconds. `form-check.mjs` types into the
    form the way a person does and asserts on what reaches the network; putting
    the read back after the redraw fails four of its checks.
    """
    node = shutil.which("node") or shutil.which("node.exe")
    if node is None:
        pytest.skip("node not on PATH")

    build = _tsc()
    assert build.returncode == 0, build.stdout[-2000:]

    proc = subprocess.run([node, "form-check.mjs"], cwd=CONSOLE,
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_form_check_would_notice_an_empty_submission():
    """A harness nobody has seen fail is a harness nobody knows works."""
    with open(os.path.join(CONSOLE, "form-check.mjs"), encoding="utf-8") as fh:
        src = fh.read()
    assert "EMPTY — the bug" in src
    assert "it carried the password that was typed" in src
