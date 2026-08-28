#!/usr/bin/env python3
"""
ot_collector — the Phase 1 collector entry point (OTS-SRS-001).

Runs the capture loop, accounts for what it actually saw, and reports coverage.
Three modes, all through the same loop so what is measured is what will run:

    --interface eth0        live capture from a SPAN port      (Linux)
    --replay file.pcap      offline analysis of an existing capture
    --preflight-only        check the interface and stop

WHAT THIS PRINTS AND WHY
────────────────────────
Coverage, first and loudest. Everything else this collector reports is
conditional on it: a finding from a window that dropped frames is a different
claim from one taken on a window known to be complete, and a window whose
counters could not be read supports neither.

    OTS-NFR-001 target: a Raspberry Pi 5 with capture on attached USB SSD
    sustaining 50 Mbps of mirrored OT traffic with ZERO measured loss.

`--measure` reports the achieved rate against that target. It will not certify a
rate it could not verify: if drop counters were unreadable the verdict is
UNVERIFIED rather than a pass, because "we processed 50 Mbps" and "we processed
all 50 Mbps that arrived" are different statements and only the second is a
capacity claim.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from collector.analysis import IncrementalAnalyzer            # noqa: E402
from collector.capture import ReplaySource, ScapyLiveSource   # noqa: E402
from collector.coverage import Coverage                        # noqa: E402
from collector.health import AlarmState                        # noqa: E402
from collector.preflight import check_capture_interface        # noqa: E402
from collector.rotation import (DEFAULT_MAX_BYTES, RollingPcapStore,  # noqa: E402
                                warn_if_on_boot_media)
from collector.self_exclusion import (ExclusionMode, SelfExclusion,     # noqa: E402
                                      SelfIdentity)
from collector.service import (CaptureRefused, CaptureService,  # noqa: E402
                               CollectorConfig)

#: OTS-NFR-001, set from SRS Q2/Q3: Pi 5 + USB SSD, sites under 50 Mbps.
NFR_TARGET_MBPS = 50.0

BANNER = r"""
  ot_collector  |  OT Sensor Fleet collector  |  Phase 1
  passive capture | coverage accounting | no transmit
"""


def _make_output_safe() -> None:
    """Never let an encoding fault replace the coverage report.

    A Windows console defaults to cp1252 and raises on anything outside it. This
    tool exists to report honestly about capture; dying with a UnicodeEncodeError
    instead of printing coverage is the worst failure it could have, and it would
    happen only on the machine an engineer is using to check a capture by hand.
    Output here is ASCII anyway -- this is the belt to that braces.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                  # noqa: BLE001
            pass


def _fmt_mbps(bits: float, seconds: float) -> Optional[float]:
    if seconds <= 0:
        return None
    return bits / seconds / 1_000_000.0


def _print_preflight(interface: str) -> bool:
    pf = check_capture_interface(interface)
    print(pf.report())
    return pf.may_start


def _build_exclusion(args) -> SelfExclusion:
    identity = SelfIdentity(mgmt_mac=args.mgmt_mac, mgmt_ipv4=args.mgmt_ip,
                            server_ipv4=args.server_ip)
    mode = ExclusionMode(args.exclusion_mode)
    return SelfExclusion(identity=identity, mode=mode)


def _report_window(report, seen_warnings: set) -> None:
    w = report.window
    mark = {"complete": "  ok  ", "degraded": " DROP ", "unknown": "  ??  "}
    print("%s %-12s %6d frames  %s"
          % (mark[w.coverage.value], w.window_id, report.frames_analysed,
             w.explain()))
    # Configuration warnings are the same every window; repeating them once a
    # minute is how an operator learns to stop reading warnings. Health alarms
    # DO repeat, because those describe this window.
    for warning in report.warnings:
        if warning in seen_warnings:
            continue
        seen_warnings.add(warning)
        print("        ! %s" % warning)


def _summarise(svc: CaptureService, analyzer: Optional[IncrementalAnalyzer],
               elapsed: float, measure: bool) -> int:
    reports = svc.reports
    print("\n" + "-" * 72)
    print("COVERAGE")
    summary = svc.coverage_summary()
    total = summary["windows_accounted"] or 0
    print("  windows            %d  (complete %d, degraded %d, unknown %d)"
          % (total,
             total - summary["windows_degraded"] - summary["windows_unknown"],
             summary["windows_degraded"], summary["windows_unknown"]))
    print("  frames analysed    %d" % summary["frames_analysed"])
    print("  capture health     %s - %s" % (summary["state"], summary["detail"]))

    if getattr(svc, "store", None) is not None:
        # The budget is what was promised; the window is what it bought. Only
        # the second answers "do we still have Tuesday".
        print("  pcap retention     %s" % svc.store.state().describe())

    excl = summary["self_exclusion"]
    if excl["configured"]:
        count = excl["excluded_frames"]
        print("  self-exclusion     %s, excluded %s"
              % (excl["mode"], "unknown (kernel filtered)" if count is None else count))
    else:
        print("  self-exclusion     NOT CONFIGURED (OTS-CAP-006)")

    if analyzer is not None:
        a = analyzer.summary()
        print("\nANALYSIS")
        print("  rulepack           %s%s"
              % (a["rulepack"], "" if a["rulepack_complete"] else "  (INCOMPLETE)"))
        print("  frames decoded     %d of %d  (%d undecodable)"
              % (a["frames_decoded"], a["frames_seen"], a["decode_failures"]))

    exit_code = 0
    if measure:
        exit_code = _report_measurement(reports, elapsed)

    alarm = svc.health.evaluate()
    if alarm.state is AlarmState.BLIND:
        print("\n  Nothing from this run may be reported as clean: capture loss "
              "could not be measured.")
        exit_code = max(exit_code, 2)
    elif alarm.state is AlarmState.LOSS:
        exit_code = max(exit_code, 2)
    return exit_code


def _report_measurement(reports: List, elapsed: float) -> int:
    """OTS-NFR-001. Refuses to certify a rate it could not verify."""
    print("\nTHROUGHPUT (OTS-NFR-001, target %.0f Mbps with zero loss)"
          % NFR_TARGET_MBPS)
    total_bytes = sum(r.bytes_analysed for r in reports)
    rate = _fmt_mbps(total_bytes * 8, elapsed)
    if rate is None:
        print("  no elapsed time to measure over")
        return 1
    print("  sustained          %.2f Mbps over %.1f s" % (rate, elapsed))

    measurable = [r for r in reports if r.window.coverage is not Coverage.UNKNOWN]
    if not measurable:
        print("  verdict            UNVERIFIED - drop counters were unreadable, so")
        print("                     this is a processing rate, not a capacity claim.")
        print("                     Run on Linux with the capture interface to certify.")
        return 2

    lost = sum((r.window.lost or 0) for r in measurable)
    if lost == 0 and rate >= NFR_TARGET_MBPS:
        print("  verdict            PASS - %.2f Mbps with zero measured loss" % rate)
        print("  headroom           %.2f Mbps above target" % (rate - NFR_TARGET_MBPS))
        return 0
    if lost == 0:
        print("  verdict            zero loss, but %.2f Mbps is below the %.0f Mbps "
              "target." % (rate, NFR_TARGET_MBPS))
        print("                     Offer more traffic before concluding the Pi "
              "cannot sustain it.")
        return 1
    print("  verdict            FAIL - %d frames lost at %.2f Mbps" % (lost, rate))
    return 2


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="ot_collector",
        description="Passive OT capture collector with coverage accounting.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--interface", help="capture interface (SPAN port)")
    src.add_argument("--replay", help="analyse an existing pcap instead")

    ap.add_argument("--collector-id", default="collector-01")
    ap.add_argument("--window-seconds", type=float, default=60.0)
    ap.add_argument("--duration", type=float, default=0.0,
                    help="stop after N seconds (0 = run until interrupted)")
    ap.add_argument("--preflight-only", action="store_true")
    ap.add_argument("--no-preflight", action="store_true",
                    help="start even if the interface is unsafe (NOT for production)")
    ap.add_argument("--no-analysis", action="store_true",
                    help="capture and account only; skip protocol analysis")

    ap.add_argument("--mgmt-mac", help="management NIC MAC, excluded from analysis")
    ap.add_argument("--mgmt-ip", help="management NIC IPv4, excluded")
    ap.add_argument("--server-ip", help="server IPv4, excluded")
    ap.add_argument("--exclusion-mode", default="bpf",
                    choices=[m.value for m in ExclusionMode])

    ap.add_argument("--capture-dir", help="rolling pcap directory (attached storage)")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                    help="rolling pcap budget in bytes (default 512 GiB, Q5a)")
    ap.add_argument("--out", help="write observation batches as JSONL")
    ap.add_argument("--measure", action="store_true",
                    help="report sustained throughput against OTS-NFR-001")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    _make_output_safe()
    if not args.quiet:
        print(BANNER)

    if args.interface:
        safe = _print_preflight(args.interface)
        if args.preflight_only:
            return 0 if safe else 1
        if not safe and not args.no_preflight:
            print("\nRefusing to start. Fix the interface, or pass --no-preflight "
                  "if you accept the risk (it is not a passive tap).")
            return 1
    elif args.preflight_only:
        print("--preflight-only needs --interface")
        return 1

    if args.capture_dir:
        warning = warn_if_on_boot_media(args.capture_dir)
        if warning:
            print("  ! %s\n" % warning)

    exclusion = _build_exclusion(args)
    for warning in exclusion.warnings():
        print("  ! %s" % warning)

    if args.replay:
        source = ReplaySource(args.replay)
    else:
        source = ScapyLiveSource(args.interface, bpf=exclusion.bpf)

    analyzer = None if args.no_analysis else IncrementalAnalyzer(
        collector_id=args.collector_id)

    store = None
    if args.capture_dir:
        store = RollingPcapStore(args.capture_dir, max_bytes=args.max_bytes)

    config = CollectorConfig(collector_id=args.collector_id,
                             capture_interface=args.interface or "replay",
                             window_seconds=args.window_seconds,
                             enforce_preflight=False)
    svc = CaptureService(source, config, exclusion=exclusion, store=store,
                         on_frames=(analyzer.feed if analyzer else None),
                         read_decode_counters=(
                             analyzer.take_decode_counters if analyzer
                             else None))

    sink = open(args.out, "w", encoding="utf-8") if args.out else None
    seen: set = set(exclusion.warnings())      # already printed above
    started = time.time()
    try:
        svc.start()
        if args.replay:
            for report in svc.run_until_exhausted():
                if not args.quiet:
                    _report_window(report, seen)
                _emit(sink, analyzer, report)
        else:
            deadline = started + args.duration if args.duration else None
            while deadline is None or time.time() < deadline:
                report = svc.poll()
                if report is not None:
                    if not args.quiet:
                        _report_window(report, seen)
                    _emit(sink, analyzer, report)
    except KeyboardInterrupt:
        print("\n[interrupted]")
    except CaptureRefused as exc:
        print("\n%s" % exc)
        return 1
    finally:
        # run_until_exhausted() already closed the last window; stopping again
        # would open and close an empty one, inflating the window count and
        # adding a phantom UNKNOWN to the coverage summary.
        final = svc.stop() if not args.replay else None
        if args.replay:
            svc.source.close()
        if final is not None and not args.quiet:
            _report_window(final, seen)
        if final is not None:
            _emit(sink, analyzer, final)
        if sink is not None:
            sink.close()

    elapsed = max(time.time() - started, 1e-9)
    return _summarise(svc, analyzer, elapsed, args.measure)


def _emit(sink, analyzer: Optional[IncrementalAnalyzer], report) -> None:
    if sink is None or analyzer is None:
        return
    batch = analyzer.build_batch(report.window.window_id,
                                 report.window.coverage.value,
                                 report.to_dict())
    sink.write(json.dumps(batch.to_dict()) + "\n")


if __name__ == "__main__":
    sys.exit(main())
