# Build order — OT Sensor Fleet

The phase-by-phase plan for re-architecting the OT/ICS passive scanner into a
fleet of Raspberry Pi collectors reporting to a central server and console.

Specification: **OTS-SRS-001**. This document is the *order of work* and the
record of what is actually built — the SRS says what the system must do, this
says what exists.

> **Status at 2026-08-28** — Phases 1–4 complete. 273 tests passing (263
> without a database). `OTS-NFR-001` is **deferred to live commissioning** on
> the Pi — see [Live commissioning](#live-commissioning).

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

### Phase 3 — Transport and ingest · **COMPLETE**

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

Built collector-half first (`85fbaf7`), then the server (`5d9b505`).

**A delivery gap is a coverage gap.** A spool has a disk ceiling, so a long
outage eventually forces data loss — and losing observations *quietly* is the
failure, not losing them. The collector counts every eviction with the interval
it spans and announces the gap **before** the batches that follow, so the server
never reads a resumed stream as continuous. The server then counts that gap
against trustworthiness: a collector whose windows were all complete but which
lost data in transit is **not** reported clean.

mTLS has no off switch — `TransportConfig` refuses `http://`, missing
certificates, and `verify=False`. The SQL is tested against a real PostgreSQL
rather than an in-memory double, because a double is a second implementation
that passes while production fails.

### Phase 4 — Server analysis · **MOSTLY COMPLETE**

Estate merge, server-side CVE matching and coverage through the API are built.
The five analysis engines (`OTS-SRV-003`) remain — see below.

**The merge had a trap in it.** Collectors emit `ip:10.0.0.1`, and private
ranges overlap across plants: a PLC at Substation A and an unrelated one at
Substation B are both very likely 10.0.0.1. Merging on that key fuses two
devices into one, after which one plant's findings appear against the other's
asset, the count silently drops, and nothing in the output looks wrong — and it
is unrecoverable, because un-merging needs provenance that has already been
averaged away.

So **IP identities are scoped to a site; MAC identities are global.**

| | |
|---|---|
| same IP, two sites | 2 assets, always |
| same IP, one site | 1 asset (overlapping SPANs) |
| same MAC, two sites | 1 asset **+ a warning** — moved device, or spoofing |

Related decisions: a merged asset takes the **weakest** coverage of its
contributions, never an average, or a healthy collector launders a blind one's
silence. Estate coverage is likewise not a percentage — four healthy collectors
and one blind one is not 80% trustworthy, it is an answer with a hole in it.
Conflicting attributes are reported rather than overwritten.

**CVE matching is the payoff for keeping `cvedb` off the Pi** (D3).
`reprioritise()` re-runs against a new corpus over stored observations and
reports what moved: *"corpus 2026-08-27 → 2026-08-28: 1 escalated, 0
de-escalated, with no collector contacted."* `NOW` means known-exploited only —
high EPSS alone is `NEXT`, because EPSS is a probability rather than an
observation, and a priority that fires on everything is one an operator stops
reading. No corpus loaded yields `UNKNOWN`, never "clean".

**Still to build — `OTS-SRV-003`.** Compliance, risk, attack-path, drift and
policy engines exist in `scanner/` and are server-side by the partition, but are
not yet wired to merged estate data. Each needs an adapter from `EstateAsset` to
the shape it expects; they were left rather than half-wired.

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

## Live commissioning

One requirement cannot be closed on a development machine, and is **scheduled
for live testing** rather than left open.

### `OTS-NFR-001` — sustained throughput

**Target.** A Raspberry Pi 5 with capture on attached USB SSD sustaining
**50 Mbps** of mirrored OT traffic with **zero measured loss**, per Q2/Q3.

**Why it cannot be done here.** There are no drop counters to read without a
capture interface, so the collector reports `UNKNOWN` coverage and the benchmark
refuses to certify:

```
$ ot_collector --interface eth0 --measure
  sustained          <rate> Mbps over <n> s
  verdict            UNVERIFIED - drop counters were unreadable, so
                     this is a processing rate, not a capacity claim.
```

"We processed 50 Mbps" and "we processed *all* 50 Mbps that arrived" are
different statements, and only the second is a capacity claim.

### On the day

Before anything else, confirm the interface is safe to capture on. This should
pass with no `FAIL` lines; an IP address on the capture port is a refusal to
start, not a warning:

```
ot_collector --preflight-only --interface eth0
```

Then run against the live SPAN port, with self-exclusion configured so the
collector does not inventory itself:

```
ot_collector --interface eth0 \
  --collector-id <site>-01 \
  --mgmt-mac <eth1 MAC> --server-ip <server> \
  --capture-dir /mnt/ssd/capture \
  --duration 3600 --measure
```

**What to record**, because these are the numbers `OTS-NFR-001` is written
against and the ones that size the next site:

| | |
|---|---|
| verdict | `PASS` / `FAIL` / below-target, and the headroom figure |
| sustained rate | Mbps, and the offered rate from the switch's own counters |
| loss | interface-dropped and capture-dropped, **separately** — different failures, different fixes |
| coverage mix | how many windows were `COMPLETE` vs `DEGRADED` vs `UNKNOWN` |
| retention | the `holding N days` line, which converts the 512 GiB budget into a real forensic window at this site's actual traffic |
| self-exclusion | whether the filter matched anything — if it matched nothing, either the SPAN does not mirror the management VLAN, or the identity is wrong |

**A below-target result is not automatically a failure of the Pi.** If loss is
zero and the rate is under 50 Mbps, the site simply may not be offering 50 Mbps
— the collector says so rather than concluding the hardware is inadequate. Offer
more traffic before drawing that conclusion.

If loss is non-zero, the two counters say which fix applies: interface drops
point at the NIC ring or the link, capture drops at analysis speed or buffer
size.

### Also worth doing on the day

- **Confirm the SPAN actually mirrors what you think it does.** Compare the
  collector's asset list against the site's own inventory; a mirror configured
  on the wrong VLAN produces a confident, quiet, partial answer.
- **Check the pcap landed on the SSD**, not the boot card — the collector warns
  at start-up if the path looks like boot media (`OTS-OPS-002`).

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
