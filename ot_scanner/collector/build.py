"""
Build the collector distribution.

    python -m collector.build --dest ./dist/collector [--version 0.2.0]

Produces an installable tree containing exactly the subset a Raspberry Pi needs
— see manifest.py for what that is and, more importantly, what it is not.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="collector.build")
    ap.add_argument("--dest", required=True, help="output directory")
    ap.add_argument("--version", default="0.1.0")
    ap.add_argument("--base", default=os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))),
        help="ot_scanner root to project from")
    args = ap.parse_args(argv)

    missing = manifest.missing_from(args.base)
    if missing:
        # A manifest naming files that are not there builds a wheel with a hole
        # in it, and the hole shows up when a collector fails to start in a
        # substation. Refuse here instead.
        print("manifest names %d file(s) that do not exist:" % len(missing))
        for rel in missing:
            print("   ", rel)
        return 1

    result = manifest.build(args.base, args.dest, args.version)
    summary = manifest.summary(args.base)
    print("built ot-collector %s -> %s" % (result["version"], args.dest))
    print("  %d files, %d lines" % (summary["files"], summary["lines"]))
    print("  %d package(s) shipped, %d excluded server-side"
          % (summary["packages"], summary["excluded"]))
    print("\ninstall on the Pi:  pip install %s" % args.dest)
    print("with live capture:  pip install '%s[live]'" % args.dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
