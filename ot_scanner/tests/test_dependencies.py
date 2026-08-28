"""
The declared test dependencies must actually be sufficient.

WHY THIS FILE EXISTS
────────────────────
Three commits landed on main with a red build and nobody noticed. The cause was
one undeclared package: `starlette.testclient` imports `httpx`, neither FastAPI
nor Starlette depends on it, and `requirements-dev.txt` did not name it. On a
developer machine it was installed for some other reason and everything passed;
on a clean runner every API test raised at import and all three Python legs
failed at "Run tests".

`requirements-dev.txt` opens by claiming exactly the property it did not have —
"without them the server tests do not fail, they ERROR at import, which reads as
a broken checkout rather than a missing install". The claim was right and
nothing checked it.

These tests check it. They are cheap, they run everywhere, and each one names
the failure it exists to prevent rather than asserting a version number for its
own sake.
"""
from __future__ import annotations

import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_DEV_REQUIREMENTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "requirements-dev.txt")


def _declared():
    with open(_DEV_REQUIREMENTS, encoding="utf-8") as fh:
        lines = [line.strip() for line in fh]
    return [line for line in lines if line and not line.startswith("#")]


def _names():
    out = set()
    for line in _declared():
        name = line.split(";")[0]
        for separator in (">=", "==", "<=", "~=", ">", "<", "["):
            name = name.split(separator)[0]
        out.add(name.strip().lower())
    return out


# ── the seam that broke ────────────────────────────────────────────────────

def test_the_http_client_the_test_client_needs_is_declared():
    """`starlette.testclient` imports httpx and nothing in the dependency tree
    requires it. Undeclared, the API tests do not skip — they raise, which on a
    CI summary page reads as a broken checkout rather than a missing install."""
    declared = _names()
    assert declared & {"httpx", "httpx2"}, (
        "requirements-dev.txt does not name an HTTP client for "
        "starlette.testclient; every API test will raise at import on a clean "
        "runner while passing on any machine that happens to have one")


def test_the_test_client_actually_imports_where_fastapi_does():
    """The end the declaration exists to serve. If FastAPI is installed, the
    harness the API tests are built on has to work — a skip here would be
    honest, but an exception is what actually happened."""
    pytest.importorskip("fastapi")
    try:
        from fastapi.testclient import TestClient           # noqa: F401
    except Exception as exc:                                # noqa: BLE001
        pytest.fail(
            "fastapi is installed but its TestClient will not import (%s: %s). "
            "This is the failure that turned three commits red: install the "
            "HTTP client named in requirements-dev.txt."
            % (type(exc).__name__, exc))


def test_every_server_dependency_the_suite_needs_is_declared():
    """The suite in this directory covers scanner, collector AND server, so the
    server's own runtime requirements have to be installable from this one
    file. Referencing them with `-r` was rejected deliberately; that makes
    duplication the thing to check."""
    declared = _names()
    for package in ("pytest", "fastapi", "psycopg", "cryptography"):
        assert package in declared, (
            "%s is needed by tests in this directory and is not declared in "
            "requirements-dev.txt" % package)


# ── the CA's version floor is load-bearing, not decorative ─────────────────

def test_cryptography_exposes_the_timezone_aware_accessors():
    """`ot_server/ca.py` reads `not_valid_before_utc` / `not_valid_after_utc`,
    which arrive in cryptography 42.0. The accessors they replace return NAIVE
    datetimes, which compare wrongly — and raise — against the timezone-aware
    timestamps PostgreSQL hands back.

    Without this test a wrong resolution surfaces as an AttributeError deep
    inside `sign()`, which reads as a bug in the CA rather than as an
    environment that resolved an old package.
    """
    pytest.importorskip("cryptography")
    from cryptography import x509

    for accessor in ("not_valid_before_utc", "not_valid_after_utc"):
        assert hasattr(x509.Certificate, accessor), (
            "the installed cryptography has no Certificate.%s. The floor in "
            "requirements is >=42.0 for exactly this reason; something "
            "resolved an older release." % accessor)


def test_the_ca_floor_is_still_declared():
    """A floor nobody states is a floor somebody removes."""
    text = "\n".join(_declared())
    assert "cryptography>=42.0" in text.replace(" ", ""), (
        "the cryptography floor is no longer pinned at 42.0, where the "
        "timezone-aware certificate accessors ot_server/ca.py depends on "
        "were introduced")
