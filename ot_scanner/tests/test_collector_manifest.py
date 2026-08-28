"""
Phase 2 — the collector distribution (OTS-SRS-001 §5).

The partition is a manifest over one tree, not a file move, because moving files
would mean two copies of the protocol analysers and copies diverge silently — a
rule fixed on the desk and not in the field, or the reverse.

That makes the manifest load-bearing, so it is proved rather than reviewed. The
decisive test assembles the distribution into a temp directory, runs it in a
SUBPROCESS with only that tree importable, and compares its findings with the
full tree's. A missing module fails at import there instead of in a substation.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector import manifest  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(BASE)
SAMPLE = os.path.join(ROOT, "test_data", "ot_test_traffic.pcap")

dpkt = pytest.importorskip("dpkt")


@pytest.fixture(scope="module")
def distribution(tmp_path_factory):
    dest = tmp_path_factory.mktemp("collector-dist")
    manifest.assemble(BASE, str(dest))
    return str(dest)


# ── the manifest describes something real ──────────────────────────────────

def test_every_manifest_entry_exists_on_disk():
    """A manifest naming a renamed file builds a wheel with a hole in it, and
    the hole is found when a collector fails to start in a substation."""
    assert manifest.missing_from(BASE) == []


def test_the_distribution_is_a_fraction_of_the_tree():
    s = manifest.summary(BASE)
    assert s["files"] > 40, "suspiciously small — did a package stop resolving?"
    assert s["lines"] < 20000, "the collector should not be carrying the server"


# ── minimality: server-side code must not reach the Pi ─────────────────────

@pytest.mark.parametrize("package", sorted(manifest.EXCLUDED))
def test_an_excluded_package_is_absent_from_the_distribution(package, distribution):
    assert not os.path.exists(os.path.join(distribution, "scanner", package)), (
        "%s reached the collector: %s" % (package, manifest.EXCLUDED[package]))


def test_the_vulnerability_corpus_is_not_shipped(distribution):
    """D3, and the most consequential exclusion. cvedb/ is ~3,170 lines of CVE,
    KEV and EPSS data that changes daily; inside a fleet of Pis every refresh
    becomes a firmware push and each collector's answer depends on when it was
    last updated."""
    assert not os.path.exists(os.path.join(distribution, "scanner", "cvedb"))
    assert "cvedb" in manifest.EXCLUDED


def test_every_exclusion_states_a_reason():
    """An exclusion without a reason is one nobody can safely reverse."""
    for name, why in manifest.EXCLUDED.items():
        assert len(why) > 25, "%s is excluded without a real reason" % name


# ── completeness: it actually runs, alone ──────────────────────────────────

def _run_isolated(distribution, *argv):
    """Run the entry point with ONLY the distribution importable.

    A subprocess with a cleaned PYTHONPATH, so the parent's sys.path cannot
    silently supply a module the manifest forgot. Running it in-process would
    prove nothing: the full tree is already imported here.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = distribution
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, os.path.join(distribution, "ot_collector.py")] + list(argv),
        cwd=distribution, env=env, capture_output=True, text=True, timeout=300)


def test_the_distribution_runs_on_its_own(distribution):
    """The completeness proof. If a protocol analyser, a rule file or a package
    __init__ is missing, this is where it surfaces."""
    proc = _run_isolated(distribution, "--replay", SAMPLE, "--quiet")
    assert proc.returncode == 0, proc.stderr[-1500:]
    assert "ModuleNotFoundError" not in proc.stderr
    assert "ImportError" not in proc.stderr


def test_package_initialisers_are_shipped(distribution):
    """Nothing imports `scanner.vuln` by name — the imports are all
    `from .vuln.engine import ...`. A manifest computed from import statements
    alone omits these, and the wheel fails at import on the Pi."""
    for package in manifest.COLLECTOR_PACKAGES:
        init = os.path.join(distribution, "scanner", package, "__init__.py")
        assert os.path.isfile(init), "%s/__init__.py did not ship" % package


def test_the_isolated_distribution_finds_what_the_full_tree_finds(distribution,
                                                                  tmp_path):
    """Parity, again — this time across the partition rather than across the
    file/live boundary. The collector must not be a different product from the
    scanner it was projected from."""
    out = tmp_path / "iso.jsonl"
    proc = _run_isolated(distribution, "--replay", SAMPLE, "--quiet",
                         "--out", str(out))
    assert proc.returncode == 0, proc.stderr[-1500:]

    records = []
    for line in out.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records += json.loads(line)["records"]
    isolated = sorted(r["attributes"]["rule_id"]
                      for r in records if r["kind"] == "detection")
    assets = sorted(r["attributes"]["ip"]
                    for r in records if r["kind"] == "asset")

    from scanner.core import PCAPAnalyzer

    devices = PCAPAnalyzer(verbose=False).analyze(SAMPLE)[0]
    full = sorted(getattr(v, "title", "")
                  for d in devices for v in (d.vulnerabilities or []))
    full_assets = sorted(d.ip for d in devices if getattr(d, "ip", None))

    assert assets == full_assets, "the distribution and the tree disagree on assets"
    assert isolated == full, "the distribution and the tree disagree on findings"


def test_the_rulepack_version_survives_the_partition(distribution):
    """If the rule sources are shipped byte-identically the hash matches. A
    mismatch means the collector is running rules the scanner does not have."""
    sys.path.insert(0, distribution)
    try:
        from collector import rulepack

        here = rulepack.compute(os.path.join(BASE, "scanner"))
        there = rulepack.compute(os.path.join(distribution, "scanner"))
    finally:
        sys.path.remove(distribution)
    assert there.complete, there.describe()
    assert here.version == there.version


def test_assembly_is_deterministic():
    """Two builds of the same tree must list the same files in the same order,
    or the manifest depends on filesystem enumeration and differs between the
    build host and CI."""
    assert manifest.collector_files(BASE) == manifest.collector_files(BASE)


# ── packaging ──────────────────────────────────────────────────────────────

def test_the_distribution_is_installable(distribution, tmp_path):
    """A tree without a pyproject is a directory, not a package."""
    import re

    manifest.write_packaging(str(tmp_path))
    body = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "ot-collector"' in body
    assert "ot-collector = \"ot_collector:main\"" in body
    for package in manifest.COLLECTOR_PACKAGES:
        assert "scanner.%s" % package in body, (
            "%s is in the manifest but not in the wheel's package list, so its "
            "files ship and its imports still fail" % package)


def test_the_runtime_dependency_is_minimal():
    """A sensor appliance should carry as little as it can. scapy is optional:
    without it the collector still runs in replay mode, which is how it is
    developed and tested off a Pi."""
    assert manifest.RUNTIME_REQUIRES == ("dpkt>=1.9.8",)


def test_the_build_refuses_a_manifest_with_holes(tmp_path, monkeypatch):
    """Better to fail on the build host than to ship a wheel that cannot start."""
    from collector import build

    monkeypatch.setattr(manifest, "missing_from", lambda base: ["scanner/gone.py"])
    code = build.main(["--dest", str(tmp_path / "out"), "--base", BASE])
    assert code == 1
    assert not (tmp_path / "out").exists()
