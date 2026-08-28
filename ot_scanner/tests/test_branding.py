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

**Every asset a page references exists.** This is here because the artwork in
`console/public/` is a drawn stand-in for supplied logo files that have not
landed yet (see `docs/brand/README.md`). Whoever drops the real ones in will
edit an `src` attribute, and a typo there produces a sign-in page with a broken
image where the brand should be — which is precisely the page on which a
missing logo reads as a phishing site. A broken reference fails here instead.
"""
from __future__ import annotations

import os
import re

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


def test_the_sign_in_page_shows_the_full_lockup_and_the_shell_shows_the_mark():
    """Different sizes want different artwork. The header slot is 26px, where a
    wordmark is a smudge; the sign-in panel is 22rem, where the mark alone
    would not name the product."""
    login = open(os.path.join(PUBLIC, "login.html"), encoding="utf-8").read()
    shell = open(os.path.join(PUBLIC, "index.html"), encoding="utf-8").read()
    assert 'class="login-logo" src="/otsec-logo' in login
    assert 'class="brand-mark" src="/otsec-mark' in shell


def test_the_logo_carries_a_text_alternative_and_the_mark_does_not():
    """The lockup names the product, so it needs alt text. The mark sits beside
    a visible wordmark in the header, so alt text on it would make a screen
    reader say the name twice."""
    login = open(os.path.join(PUBLIC, "login.html"), encoding="utf-8").read()
    shell = open(os.path.join(PUBLIC, "index.html"), encoding="utf-8").read()
    logo = re.search(r'<img class="login-logo".*?/>', login, re.S)
    assert logo and re.search(r'alt="[^"]+"', logo.group(0)), \
        "the sign-in lockup has no alt text"
    assert 'class="brand-mark" src="/otsec-mark.svg" alt=""' in shell
