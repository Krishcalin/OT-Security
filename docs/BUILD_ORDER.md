# Build order — OT Sensor Fleet

The phase-by-phase plan for re-architecting the OT/ICS passive scanner into a
fleet of Raspberry Pi collectors reporting to a central server and console.

Specification: **OTS-SRS-001**. This document is the *order of work* and the
record of what is actually built — the SRS says what the system must do, this
says what exists.

> **Status at 2026-08-28** — Phases 1 and 2 complete (`dd6d7b5`).
> 188 tests passing. One requirement, `OTS-NFR-001`, is **unverified** and can
> only be closed on real hardware — see [Open on hardware](#open-on-hardware).

---

## Why this order

Two rules decided the sequence, and both are about finding out early rather than
comfortably:

1. **The riskiest unknown goes first.** Everything in this system rests on a
   Raspberry Pi sustaining continuous capture without silently losing frames. If
   that assumption is wrong, it is cheaper to learn it in week one than after a
   server, an API and a console have been built on top of it. So Phase 1 is
   capture and drop accounting, not the parts that demo well.

2. **Each phase leaves something that runs.** No phase is only scaffolding. At
   the end of Phase 1 you can point the collector at a capture and get an honest
   coverage report; at the end of Phase 2 you can install it on a Pi.

---

## The governing idea

A passive sensor that drops frames still produces a report, and that report is
indistinguishable from one taken on a network that is genuinely clean. On a
substation network that is the worst failure available to this system: an
operator reads *no findings* and cannot tell it apart from *we did not see the
traffic*.

So coverage is not a diagnostic printed at the end of a run. It is a property of
every window, it travels with every finding derived from that window, and it has
**three** states rather than two:

| state | meaning |
|---|---|
| `COMPLETE` | counters read at both ends, no loss measured |
| `DEGRADED` | loss was measured |
| `UNKNOWN` | the counters could not be read |

`UNKNOWN` is the one usually missing and the one that matters. A collector that
cannot measure loss has not established there was none, so it says so — and
anything downstream treats an unmeasurable window as not-clean.

---

## Phases

### Phase 1 — Capture core and drop accounting · **COMPLETE**

Commits `94e1a03`, `1e8059f`, `a74a9cd`.

| § | requirement | where |
|---|---|---|
| 6.1 | `OTS-CAP-001` refuse to start on an interface carrying an IP | `collector/preflight.py` |
| 6.1 | `OTS-CAP-002` continuous capture, bounded rolling pcap | `collector/rotation.py` |
| 6.1 | `OTS-CAP-003` drop counters read every window | `collector/counters.py` |
| 6.1 | `OTS-CAP-004` degraded windows marked, coverage travels | `collector/coverage.py` |
| 6.1 | `OTS-CAP-005` sustained-loss and blind alarms | `collector/health.py` |
| 6.1 | `OTS-CAP-006` self-traffic excluded and counted | `collector/self_exclusion.py` |
| 6.2 | `OTS-ANL-001` existing analysers driven from the live stream | `collector/analysis.py` |
| 6.2 | `OTS-ANL-002` normalised records, no payloads | `collector/observations.py` |
| 6.2 | `OTS-ANL-003` vuln and threat engines run on the collector | `collector/analysis.py` |
| 6.2 | `OTS-ANL-004` provenance on every record | `collector/observations.py` |
| 6.2 | `OTS-ANL-005` content-hashed rule pack | `collector/rulepack.py` |
| — | the loop, and the CLI that reports coverage | `collector/service.py`, `ot_collector.py` |

**Decisions taken inside this phase that are easy to get backwards.** Each is
pinned by a test, because each fails quietly:

- A drop counter going **backwards is a reset**, not zero loss. An interface
  bounce resets the kernel counters; clamping the negative to zero manufactures
  a clean window out of an interval nobody measured.
- **Interface loss and capture loss are counted separately.** A NIC ring overrun
  needs a bigger ring; a capture-buffer drop means analysis is too slow.
  Summing them into one number hides which.
- **One counter reading closes a window and opens the next.** Reading twice
  leaves a gap between them where loss is invisible — small, constant, and
  always in the direction of looking clean.
- **An IP on the capture port is a refusal to start**, not a warning. With an
  address the kernel owns the interface and will emit ARP, DHCP and mDNS onto
  the OT segment; nothing in a capture tells you your own NIC is talking.
- **A replayed pcap reports `UNKNOWN`**, never `COMPLETE`. A file cannot tell
  you what the tap missed while it was recording.
- Under BPF, `excluded_frames` is **`None`, not `0`** — the kernel does not
  report what it filtered on our behalf, and zero would claim the collector saw
  no self-traffic when it merely could not count.

### Phase 2 — Collector package · **COMPLETE**

Commit `dd6d7b5`. Builds `ot-collector 0.1.0`: 52 files, 14,093 lines, 4
packages shipped, 12 excluded.

```
python -m collector.build --dest ./dist/collector
pip install ./dist/collector           # replay mode
pip install './dist/collector[live]'   # + scapy for live SPAN capture
```

**The partition is a manifest over one tree, not a file move.** Moving files
would mean two copies of the protocol analysers, and copies diverge — a rule
fixed on the desk and not in the field, or the reverse, silently either way. The
scanner is untouched; the collector is a projection of it, declared in
`collector/manifest.py`.

It needed **no changes to existing code**: every engine import in
`scanner/core.py` is already guarded with a `_HAS_*` flag, so a collector
shipped without `topology/` and `cvedb/` resolves those to `False`.

That same property is the trap. Dropping `vuln/` from the manifest does **not**
crash the distribution — the guarded import degrades to zero findings, and the
collector starts cleanly and reports nothing. So completeness is proved by
**parity in a subprocess** with only the assembled tree importable, not by
"does it import":

```
assemble -> run isolated -> compare assets and findings with the full tree
```

### Phase 3 — Transport and ingest · **NEXT**

The first phase with a server in it, and the first that needs a database.

- `OTS-TRN-001` outbound-only; no listening port on the collector
- `OTS-TRN-002` mutual TLS against a **self-managed CA shipped with the server**
  (Q4); the CA private key is generated at install and never leaves it
- `OTS-TRN-003` durable store-and-forward queue with backoff, a disk ceiling,
  oldest-first eviction and an explicit loss counter
- `OTS-TRN-004` idempotency keys — a replayed batch must not duplicate anything
- `OTS-TRN-005` heartbeats carrying version, rule-pack version, capture health
  and queue depth
- `OTS-TRN-006` raw pcap stays local unless explicitly requested per incident
- FastAPI ingest endpoints and the **PostgreSQL** schema (Q1)

**Suggested order within the phase:** the collector's transport half first. It
can be proved end to end against a stub server without Postgres running, the
same way the capture loop was proved without a NIC.

### Phase 4 — Server analysis

- Estate asset merge — the same device seen by two collectors is one asset
- Server-side CVE / KEV / EPSS matching, so a corpus refresh re-prioritises the
  estate without re-ingest (decision D3)
- Compliance, risk, attack-path, drift and policy engines over merged data
- `OTS-SRV-004` coverage accounting surfaced through the API
- `OTS-SRV-005` an asset absent from the latest window is **not observed**,
  never silently removed — a passive sensor cannot distinguish a decommissioned
  device from an unseen one

### Phase 5 — Console

TypeScript front end: estate, assets, findings, topology, change view.

`OTS-CON-004` is the one that constrains the design: every screen presenting
counts or clean states must display the coverage those numbers rest on, and a
degraded window must be **visibly marked, not footnoted**.

### Phase 6 — Fleet operations

Enrolment, certificate lifecycle, signed updates, rule-pack distribution, health
alarms. Once the fleet is stable, two borrowed capabilities become candidates:
learned communication zones (Claroty's virtual zones, extending the existing
`topology/`) and process-variable baselining (Nozomi — the protocol parsers
already decode the point values it needs).

---

## Decisions in force

| | decision | consequence |
|---|---|---|
| **D1** | the management NIC must not bridge the OT L2 domain | capture NIC has no IP and TX disabled; management NIC on a dedicated VLAN, ACL to the server only |
| **D2** | continuous capture, and drops are reported | packet-drop accounting is mandatory, not diagnostic |
| **D3** | volatile facts live on the server | `cvedb/` never ships to a collector; a KEV addition re-prioritises the estate without touching a Pi |
| **Q1** | PostgreSQL only | one dialect, one set of migrations |
| **Q2** | under 50 Mbps per site, fewer than 10 collectors | `COMPLETE` coverage is the expected normal state, so `DEGRADED` is a real signal |
| **Q3** | Raspberry Pi 5, rolling pcap on attached USB SSD | SD card stays boot-only |
| **Q4** | self-managed CA shipped with the server | enrolment and revocation stay inside the product |
| **Q5** | 512 GiB pcap ceiling; 13 months of observations | see below |

**On retention (`OTS-OPS-003`).** pcap is configured in **bytes** and reported
in **days**. A retention promise expressed in days is broken silently by a busy
afternoon: the same 512 GiB budget holds roughly nine days at 5 Mbps and under
one during a sustained 50 Mbps burst. Bytes are a promise the collector can
keep; days are a measurement it must publish.

---

## Out of scope

- **Active polling of OT devices.** Nozomi and Claroty both offer it, carefully
  rate-limited, and it genuinely improves inventory depth. It also sends packets
  to production PLCs. This tool's entire safety claim is that it never
  transmits, and that is worth more than the extra inventory. If it is ever
  built it must be a separate, explicitly-enabled component — never a collector
  default.
- Any write path to OT equipment.
- Anomaly-only detection. Known-bad behaviour first; an anomaly alert an
  operator cannot action is noise.
- Cloud-hosted analysis. The server is deployed inside the operator's boundary.
- Automatic remediation. Policy engines propose; a human applies.

---

## Open on hardware

**`OTS-NFR-001` is unverified.** The target — a Pi 5 with capture on attached
USB SSD sustaining **50 Mbps with zero measured loss** — cannot be measured on a
development machine, because there are no drop counters to read. The CLI refuses
to certify what it could not measure:

```
$ ot_collector --interface eth0 --measure
  sustained          <rate> Mbps over <n> s
  verdict            UNVERIFIED - drop counters were unreadable, so
                     this is a processing rate, not a capacity claim.
```

Run that on the Pi against a live SPAN port to close it. Until then the figure
is an intention, not a measurement, and the SRS says it must be measured and
published rather than asserted.

---

## Testing

```
python -m pytest ot_scanner/tests -q          # 188 tests
python ot_scanner/ot_collector.py --replay test_data/ot_test_traffic.pcap --measure
```

Everything in `collector/` is testable **without a capture NIC, without root and
on any OS** — driven by a synthetic source and by replaying the repository's own
sample capture. That is a design property, not a convenience: the logic under
test decides what the collector may claim to have seen, and if it could only be
exercised on a Raspberry Pi it would never be exercised at all. Only the counter
sources and the live scapy backend require Linux.

CI runs Python 3.8, 3.10 and 3.12; the collector is written to the 3.8 grammar.
