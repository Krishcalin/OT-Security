"""
The product is OTSec, and every surface says so.

Two things are checked here, and the second is the load-bearing one.

**The retired name is gone from every shipping surface.** A rename that lands
in the page title and misses the cookie, the environment variable or the
authenticator entry leaves an operator reading two product names for one
product, and the one they see at the moment of doubt — the sign-in page, the
phone — is the one that decides whether they trust it.

Documentation is deliberately NOT scanned. `docs/DECISIONS.md` and
`docs/BUILD_ORDER.md` are a record of what was decided and when, and a history
that cannot name what it changed from is a worse history. The rule is about
what ships and what runs, not about what is remembered.

**Every asset a page references exists.** The console's PNGs are DERIVED from `docs/brand/otsec-master.png` by
`tools/build_brand_assets.py` and committed, so a deployment needs nothing but
the repository. That means three things can silently go wrong, and each has a
test below: a page can point at a file that is not there; the committed assets
can drift from the master; and the panel painted behind the lockup can stop
matching the field baked into the lockup itself.

The last one is the interesting failure. MonitorRisk keyed a cream field out
from under a white wordmark and rendered its product name as half a word — with
a valid RGBA PNG, correct dimensions and a green suite, because the only
assertion checked the file's colour type. `test_the_brand_panel_matches_the_
field_baked_into_the_lockup` is the assertion that would have caught it.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PUBLIC = os.path.join(_ROOT, "console", "public")

PRODUCT = "OTSec"

#: Assembled rather than written out, so this file does not itself trip the
#: scan it performs.
RETIRED = (
    "Power" + " NetView",
    "Power" + "NetView",
    "POWER" + "NETVIEW",
    "pnv" + "_session",
    "power" + "-netview",
)

#: What ships and what runs. Not docs — see the module docstring.
SCANNED_DIRS = ("ot_server", "ot_scanner", "console/public", "console/src",
                "deploy", "plc_passive_scanner", "rtu_passive_scanner")
SCANNED_SUFFIXES = (".py", ".ts", ".mjs", ".html", ".css", ".svg", ".yaml",
                    ".yml", ".json", ".cfg", ".conf")
SKIP_DIRS = {"__pycache__", "node_modules", "dist", ".git", ".mypy_cache"}


def _shipping_files():
    for rel in SCANNED_DIRS:
        base = os.path.join(_ROOT, rel)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(SCANNED_SUFFIXES) or name == "Dockerfile":
                    yield os.path.join(dirpath, name)


# ── the name ───────────────────────────────────────────────────────────────

def test_no_shipping_surface_still_carries_the_retired_name():
    """A half-done rename leaves an operator reading two product names for one
    product."""
    offenders = []
    for path in _shipping_files():
        if os.path.abspath(path) == os.path.abspath(__file__):
            continue
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        for token in RETIRED:
            if token in text:
                offenders.append("%s: %s"
                                 % (os.path.relpath(path, _ROOT), token))
    assert not offenders, "retired brand name still ships:\n  " + \
        "\n  ".join(offenders)


@pytest.mark.parametrize("page", ["index.html", "login.html"])
def test_every_page_names_the_product_in_its_title(page):
    """The tab is the one place the brand is visible on every screen."""
    text = open(os.path.join(PUBLIC, page), encoding="utf-8").read()
    title = re.search(r"<title>(.*?)</title>", text, re.S)
    assert title and PRODUCT in title.group(1), \
        "%s has no product name in its <title>" % page


def test_the_authenticator_entry_names_the_same_product_as_the_console():
    """An operator scanning the QR gets a permanent entry on their phone. If it
    says something other than what the console says, the entry they find six
    months later belongs to a product they do not recognise."""
    from ot_server import totp
    assert totp.ISSUER == PRODUCT
    assert PRODUCT in totp.provisioning_uri("ABCDEFGHIJKLMNOP", "operator")


def test_the_session_cookie_and_bootstrap_variables_carry_the_product_name():
    """These are the two places a rename is quietly skipped, because nothing
    renders them and no screenshot shows them wrong."""
    from ot_server import authn, authn_api
    assert authn_api.COOKIE_NAME.startswith("otsec")
    assert authn.BOOTSTRAP_USER_ENV.startswith("OTSEC_")
    assert authn.BOOTSTRAP_PASSWORD_ENV.startswith("OTSEC_")


# ── the artwork ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("page", ["index.html", "login.html"])
def test_every_asset_a_page_references_exists(page):
    """A missing logo on the sign-in page reads as a phishing site. The real
    artwork has not landed yet (docs/brand/README.md), so the swap that brings
    it in must fail here rather than in front of an operator."""
    text = open(os.path.join(PUBLIC, page), encoding="utf-8").read()
    refs = set(re.findall(r'(?:src|href)="(/[^"]+)"', text))
    missing = []
    for ref in sorted(refs):
        # `/dist/*` is built by the console job, not committed.
        if ref.startswith("/dist/"):
            continue
        if not os.path.isfile(os.path.join(PUBLIC, ref.lstrip("/"))):
            missing.append(ref)
    assert not missing, "%s references files that do not exist: %s" % (
        page, ", ".join(missing))


def test_the_committed_assets_match_the_master_artwork():
    """`--check` rebuilds from the master and compares the pictures. Without this, an
    edited PNG and an edited master drift apart and the repository stops being
    the thing a deployment can be built from."""
    pillow = pytest.importorskip("PIL", reason="Pillow is a build-time dependency")
    del pillow
    sys.path.insert(0, os.path.join(_ROOT, "tools"))
    try:
        import build_brand_assets
    finally:
        sys.path.pop(0)
    fresh, _field = build_brand_assets.build()
    for path, image in fresh.items():
        rel = os.path.relpath(path, _ROOT)
        assert os.path.isfile(path), "%s was never built" % rel
        # Pixels, not bytes: the CI matrix spans four Python legs that do not
        # resolve to the same Pillow, and PNG encoder output differs between
        # versions. A byte check would go red on a runner upgrade, which is how
        # a real signal gets trained away.
        assert not build_brand_assets.differs(path, image), (
            "%s differs from a fresh build of the master. Run "
            "`python tools/build_brand_assets.py` and commit the result." % rel)


def test_the_brand_panel_matches_the_field_baked_into_the_lockup():
    """The lockup keeps its own coloured field rather than being keyed
    transparent, so the panel behind it is painted the same value. If the two
    drift, the sign-in page shows a rectangle seam around the logo.

    This is the assertion MonitorRisk did not have."""
    pytest.importorskip("PIL", reason="Pillow is a build-time dependency")
    from PIL import Image

    logo = Image.open(os.path.join(PUBLIC, "otsec-logo.png")).convert("RGB")
    corner = logo.load()[3, 3]
    baked = "#%02x%02x%02x" % corner

    css = open(os.path.join(PUBLIC, "console.css"), encoding="utf-8").read()
    declared = re.search(r"--brand-field:\s*(#[0-9a-fA-F]{6})", css)
    assert declared, "console.css declares no --brand-field"
    assert declared.group(1).lower() == baked, (
        "the panel is painted %s but the lockup's own field is %s — the "
        "sign-in page will show a seam around the logo"
        % (declared.group(1), baked))


def test_text_on_the_brand_panel_is_legible_against_it():
    """--ink-dim is 1.31:1 on this field. Reusing the console's own text colour
    would put invisible text on the one page that has to inspire trust."""
    css = open(os.path.join(PUBLIC, "console.css"), encoding="utf-8").read()
    field = re.search(r"--brand-field:\s*#([0-9a-fA-F]{6})", css).group(1)
    ink = re.search(r"--brand-ink:\s*#([0-9a-fA-F]{6})", css)
    assert ink, "console.css declares no --brand-ink"

    def luminance(hexcolour):
        parts = [int(hexcolour[i:i + 2], 16) / 255.0 for i in (0, 2, 4)]
        parts = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
                 for c in parts]
        return 0.2126 * parts[0] + 0.7152 * parts[1] + 0.0722 * parts[2]

    high, low = sorted((luminance(field), luminance(ink.group(1))), reverse=True)
    ratio = (high + 0.05) / (low + 0.05)
    assert ratio >= 4.5, ("--brand-ink on --brand-field is %.2f:1; WCAG AA "
                          "body text needs 4.5:1" % ratio)


def test_the_sign_in_page_shows_the_full_lockup_and_the_shell_shows_the_mark():
    """Different sizes want different artwork. The header slot is 26px, where a
    wordmark is a smudge; the sign-in panel is 22rem, where the mark alone
    would not name the product."""
    login = open(os.path.join(PUBLIC, "login.html"), encoding="utf-8").read()
    shell = open(os.path.join(PUBLIC, "index.html"), encoding="utf-8").read()
    assert 'class="login-logo" src="/otsec-logo.png"' in login
    assert 'class="brand-mark" src="/otsec-mark.png"' in shell


def test_the_page_does_not_repeat_the_tagline_the_artwork_already_carries():
    """The lockup has "OT SECURITY. TOTAL VISIBILITY." baked into it. A second
    copy underneath says it twice."""
    login = open(os.path.join(PUBLIC, "login.html"), encoding="utf-8").read()
    assert "login-tagline" not in login


def test_the_logo_carries_a_text_alternative_and_the_mark_does_not():
    """The lockup names the product, so it needs alt text. The mark sits beside
    a visible wordmark in the header, so alt text on it would make a screen
    reader say the name twice."""
    login = open(os.path.join(PUBLIC, "login.html"), encoding="utf-8").read()
    shell = open(os.path.join(PUBLIC, "index.html"), encoding="utf-8").read()
    logo = re.search(r'<img class="login-logo".*?/>', login, re.S)
    assert logo and re.search(r'alt="[^"]+"', logo.group(0)), \
        "the sign-in lockup has no alt text"
    assert 'class="brand-mark" src="/otsec-mark.png" alt=""' in shell
