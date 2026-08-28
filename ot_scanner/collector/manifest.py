"""
What ships to a collector (OTS-SRS-001 §5).

THE PARTITION IS A MANIFEST, NOT A FILE MOVE
────────────────────────────────────────────
The obvious way to split a codebase is to move files. Here that would mean two
copies of the protocol analysers — one in the scanner, one in the collector —
and the copies would diverge. They always do, and the divergence is silent: a
rule fixed on the desk and not in the field, or the reverse.

So there is one tree, and this declares the subset a collector wheel is built
from. The existing scanner keeps working untouched; the collector is a
projection of it. `assemble()` produces the distribution and
`tests/test_collector_manifest.py` proves the projection is both complete
(everything it needs is there) and minimal (nothing server-side leaks in).

WHY MINIMALITY MATTERS AS MUCH AS COMPLETENESS
──────────────────────────────────────────────
The vulnerability corpus is the case in point. `cvedb/` is 3,170 lines of CVE,
KEV and EPSS data that changes daily (decision D3). Shipping it inside a fleet
of Pis makes every CVE refresh a firmware push to every substation, and worse,
makes each collector's answer depend on when it was last updated. It is
excluded deliberately, and a test fails if it reappears.

`__init__.py` FILES ARE PART OF THE MANIFEST
────────────────────────────────────────────
Nothing imports `scanner.vuln` by name — the imports are all
`from .vuln.engine import ...`. A manifest computed from import statements alone
therefore omits the package initialisers, and the wheel fails at import on the
Pi rather than on the desk. They are listed explicitly for that reason.
"""
from __future__ import annotations

import os
import shutil
from typing import Dict, List, Tuple

#: Whole packages the collector needs. Every .py beneath them ships.
COLLECTOR_PACKAGES: Tuple[str, ...] = (
    "protocols",        # 22 modules — the frames are here
    "vuln",             # ~30 detection rules, evaluated on the collector
    "threat",           # 10 ICS malware behavioural signatures
    "fingerprint",      # vendor identification at asset-extraction time
)

#: Individual modules at the root of scanner/.
COLLECTOR_MODULES: Tuple[str, ...] = (
    "__init__.py",
    "core.py",          # the packet handlers and _finalise
    "models.py",        # the shared vocabulary, also used server-side
)

#: Server-side. Named rather than merely absent, with the reason, so removing
#: one from this list is a visible decision.
EXCLUDED: Dict[str, str] = {
    "cvedb": "volatile — CVE/KEV/EPSS change daily (D3). Shipping it makes every "
             "refresh a fleet firmware push and makes a collector's answer depend "
             "on when it was last updated.",
    "compliance": "35 controls assessed per site but reported per estate.",
    "report": "reporting spans collectors.",
    "export": "SIEM/STIX/ServiceNow/Splunk/Elastic — one integration point, "
              "server-side, not one per substation.",
    "policy": "firewall rule generation needs the whole topology.",
    "topology": "zones only mean anything across collectors.",
    "delta": "needs history; a collector holds only its own window.",
    "attack": "paths cross collector boundaries.",
    "config": "baselines are long-lived state.",
    "risk": "scoring consumes CVE and topology, both server-side.",
    "access": "secure-access audit is an estate-level question.",
    "project_files": "engineering project files are imported at the server.",
}

#: The collector's own package, shipped whole.
COLLECTOR_OWN = "collector"

#: Entry point module at the ot_scanner root.
COLLECTOR_ENTRY = "ot_collector.py"


def scanner_root(base: str) -> str:
    return os.path.join(base, "scanner")


def collector_files(base: str) -> List[str]:
    """Every path a collector distribution contains, relative to `base`.

    Deterministic order so two builds of the same tree produce the same list —
    a manifest that depends on filesystem enumeration order is one that differs
    between the build host and CI.
    """
    out: List[str] = []
    for name in COLLECTOR_MODULES:
        out.append(os.path.join("scanner", name))
    for package in COLLECTOR_PACKAGES:
        root = os.path.join(scanner_root(base), package)
        for dirpath, _dirs, files in os.walk(root):
            for filename in sorted(files):
                if not filename.endswith(".py"):
                    continue
                full = os.path.join(dirpath, filename)
                out.append(os.path.relpath(full, base))
    own = os.path.join(base, COLLECTOR_OWN)
    for filename in sorted(os.listdir(own)):
        if filename.endswith(".py"):
            out.append(os.path.join(COLLECTOR_OWN, filename))
    out.append(COLLECTOR_ENTRY)
    return sorted(set(out))


def missing_from(base: str) -> List[str]:
    """Manifest entries that do not exist on disk.

    A manifest naming a file that was renamed builds a wheel with a hole in it,
    and the hole is only found when a collector fails to start in a substation.
    """
    return [rel for rel in collector_files(base)
            if not os.path.isfile(os.path.join(base, rel))]


def assemble(base: str, dest: str) -> List[str]:
    """Copy the collector distribution into `dest`. Returns what was written."""
    written: List[str] = []
    for rel in collector_files(base):
        src = os.path.join(base, rel)
        if not os.path.isfile(src):
            continue
        target = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(src, target)
        written.append(rel)
    return written


def summary(base: str) -> Dict[str, int]:
    files = collector_files(base)
    lines = 0
    for rel in files:
        path = os.path.join(base, rel)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines += sum(1 for _ in handle)
        except OSError:
            continue
    return {"files": len(files), "lines": lines,
            "packages": len(COLLECTOR_PACKAGES), "excluded": len(EXCLUDED)}


# ── packaging ──────────────────────────────────────────────────────────────

#: The collector's entire runtime dependency. dpkt is pure-Python, ~1 MB, and
#: parses the frames; scapy is supported by the live source but not required to
#: install, because a sensor appliance should carry as little as it can.
RUNTIME_REQUIRES: Tuple[str, ...] = ("dpkt>=1.9.8",)

_PYPROJECT = '''# Generated by ot_scanner.collector.manifest — do not edit by hand.
#
# The collector is a PROJECTION of the OT-Security tree, not a fork of it. Build
# it with `python -m ot_scanner.collector.build`; the manifest decides what is
# inside and tests/test_collector_manifest.py proves that projection is both
# complete and minimal.
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "ot-collector"
version = "%(version)s"
description = "Passive OT/ICS capture collector with coverage accounting"
requires-python = ">=3.8"
dependencies = [%(deps)s]

[project.optional-dependencies]
# Live SPAN capture. Absent, the collector still runs in replay mode, which is
# how it is developed and tested off a Raspberry Pi.
live = ["scapy>=2.5.0"]

[project.scripts]
ot-collector = "ot_collector:main"

[tool.setuptools]
packages = ["collector", "scanner", "scanner.protocols", "scanner.vuln",
            "scanner.threat", "scanner.fingerprint"]
py-modules = ["ot_collector"]
'''


def write_packaging(dest: str, version: str = "0.1.0") -> str:
    """Write the pyproject that turns an assembled tree into a wheel."""
    deps = ", ".join('"%s"' % d for d in RUNTIME_REQUIRES)
    body = _PYPROJECT % {"version": version, "deps": deps}
    path = os.path.join(dest, "pyproject.toml")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    return path


def build(base: str, dest: str, version: str = "0.1.0") -> Dict[str, int]:
    """Assemble the distribution and make it installable."""
    written = assemble(base, dest)
    write_packaging(dest, version)
    return {"files": len(written), "version": version}
