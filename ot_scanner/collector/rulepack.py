"""
Rule-pack versioning (OTS-ANL-005).

Every detection names the logic that produced it. Without that, a finding is
untraceable the moment the rules change: an operator asking "why did this start
firing on Tuesday" has no way to tell a new rule from a changed network, and
those demand opposite responses.

WHY A CONTENT HASH RATHER THAN A HAND-EDITED VERSION
────────────────────────────────────────────────────
A version string someone must remember to bump is a version string that is
wrong. It is wrong precisely when it matters most — the hotfix, the quick tweak
to a threshold — because that is when nobody edits the constant. Hashing the
rule sources means the version cannot disagree with the rules.

The trade is that the hash changes on a comment edit too. That is the right
direction to be wrong in: a spurious version change costs a re-review, a missed
one costs a wrong answer to "which rules produced this".
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

#: Rule and signature sources. Ordered, because the digest must not depend on
#: filesystem enumeration order.
RULE_SOURCES: Tuple[str, ...] = (
    "vuln/dnp3_checks.py",
    "vuln/general_checks.py",
    "vuln/iec104_checks.py",
    "vuln/iec61850_checks.py",
    "vuln/engine.py",
    "threat/signatures.py",
    "threat/engine.py",
)


@dataclass
class RulePack:
    version: str
    files: int
    missing: List[str]
    scanner_root: str = ""

    @property
    def complete(self) -> bool:
        return not self.missing

    def describe(self) -> str:
        if self.complete:
            return "rulepack %s (%d sources)" % (self.version, self.files)
        return ("rulepack %s (%d of %d sources — MISSING %s; detections will be "
                "attributed to an incomplete pack)"
                % (self.version, self.files, self.files + len(self.missing),
                   ", ".join(self.missing)))


def compute(scanner_root: Optional[str] = None) -> RulePack:
    """Hash the rule sources into a version.

    A missing source is recorded rather than skipped. Silently hashing six files
    when seven were expected produces a version that looks fine and describes a
    different pack — the failure this whole module exists to prevent.
    """
    root = scanner_root or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanner")

    digest = hashlib.sha256()
    present = 0
    missing: List[str] = []
    for rel in RULE_SOURCES:
        path = os.path.join(root, *rel.split("/"))
        try:
            with open(path, "rb") as handle:
                body = handle.read()
        except OSError:
            missing.append(rel)
            continue
        digest.update(rel.encode())
        # Normalise line endings so a checkout on Windows and one on the Pi
        # produce the same version for identical rules.
        digest.update(body.replace(b"\r\n", b"\n"))
        present += 1

    version = digest.hexdigest()[:12]
    if missing:
        version = "partial-" + version
    return RulePack(version=version, files=present, missing=missing,
                    scanner_root=root)
