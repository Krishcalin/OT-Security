# Build order — OT Sensor Fleet

The phase-by-phase plan for re-architecting the OT/ICS passive scanner into a
fleet of Raspberry Pi collectors reporting to a central server and console.

Specification: **OTS-SRS-001**. This document is the *order of work* and the
record of what is actually built — the SRS says what the system must do, this
says what exists.

> **Status at 2026-08-28** — Phases 1–5 complete; Phase 6 in progress
> (enrolment and certificate lifecycle done); the console signs operators
> in with a second factor (D9). 516 tests passing without a
> database; 22 more require one and are skipped without it (CI refuses that
> skip). `OTS-NFR-001` is **deferred to live commissioning** on the Pi — see
> [Live commissioning](#live-commissioning).

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

### Phase 4 — Server analysis · **COMPLETE**

Estate merge, server-side CVE matching, coverage through the API, the five
analysis engines (`OTS-SRV-003`) and the Purdue zone derivation they needed.

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

**`OTS-SRV-003` — five engines, each declaring what it could not see.**
Compliance, risk, attack-path, drift and policy run on merged estate data
through `ot_server/analysis.py`. `rehydrate()` rebuilds an `OTDevice` from the
wire format, and because 10 of its 49 fields survive that trip, **every result
names the fields it could not consider** — a compliance pass computed without
`communication_profile` is not the same claim as one computed with it.

An engine without its required inputs is `SKIPPED` with a reason, never run on
nothing: drift without a baseline would answer *nothing changed*, which is the
most confident wrong answer available.

**Purdue zones are derived server-side (D6).** They were the missing input that
kept attack-path and policy skipped. Derivation is **per site** — deriving across
the estate would fuse two plants that share `10.10.1.0/24` — and each zone
records whether its level came from a role, from the protocol mix, or from the
topology engine's fallback. A derivation that is mostly fallback is **refused**,
because a firewall ruleset built on guessed segmentation may be applied to a live
plant network.

The same work exposed a silent bug worth recording: stored flow dicts were passed
straight to the engines. Policy raised, which surfaced; attack-path iterated
records it could not read, found nothing, and reported `RAN` — indistinguishable
from a network with no attack paths, and that is the answer an operator believes.
Flows are now rehydrated once, and an engine handed the wrong type says so.

### Phase 5 — Console · **COMPLETE**

TypeScript front end: estate, assets, findings, topology, change view, served
from the analysis server (D7).

`OTS-CON-004` is the one that constrains the design: every screen presenting
counts or clean states must display the coverage those numbers rest on, and a
degraded window must be **visibly marked, not footnoted**.

**It is enforced by the type checker rather than by review.** A branded
`Measured<T>` carries its coverage, and `metric()` accepts nothing else — so a
bare number is unrenderable and forgetting coverage is a build failure, not a
missed review comment. `src/con004.expect-errors.ts` holds the four cases that
must not compile.

**Two endpoints had to exist first.** Three of the five screens had no data
source: the five analysis engines and the zone derivation were reachable only
from Python. `/api/v1/estate/analysis` and `/api/v1/estate/zones` expose them,
and wiring the first one surfaced a bug that would have been invisible in
production. The engines look detections up by `estate_id`; the store holds them
under the **collector's** asset key. Passed through unchanged they attach to
nothing, every asset reads as detection-free, and the console draws a clean
estate produced by a wiring fault. `estate.reattach_detections` re-keys them on
`(collector_id, asset_key)` — never on the key alone, because both plants have a
10.0.0.1 and matching on it would hang Substation B's finding on Substation A's
device. Detections whose asset row never arrived are **counted and reported**
rather than dropped.

**What the type checker cannot see, three guards do.**

- A screen can build its own markup and interpolate a value straight into it;
  the result is only a string, so `tsc` has no objection. Every interpolation
  inside markup must therefore be a **call to a named function** — a rule with
  no allowlist to maintain, because a guard that must be edited to keep passing
  eventually gets edited without being read.
- `moduleResolution: bundler` accepts `./coverage`, and the browser does not.
  There is no bundler here — tsc's output is loaded as native ESM — so an
  extensionless import type-checks perfectly and 404s at runtime, rendering as a
  screen that never appears.
- The compiled console is **executed** against payloads dumped from the real
  app, with only `fetch` standing in. Sabotaging one screen with those first two
  defects leaves `tsc --noEmit` completely clean and fails all three guards.

**The shell owns what no screen is trusted to remember.** The estate banner is
rendered above every screen by the shell, because a rule each screen must apply
for itself is one the sixth screen, written in a hurry a year from now, will
not. A failed load clears the page rather than leaving the previous screen's
figures under a new heading — a stale count is indistinguishable from a current
one. And the per-draw request cache never outlives the draw, so the banner and
the tile beneath it cannot give two different answers to the same question.

**A defect the rendered output found.** The coverage badge named a mechanism —
"frames were lost", "capture loss could not be measured". True while every
coverage state came from a capture window; false as soon as they did not. An
unassessed vulnerability count is `unknown` because no corpus is loaded, and a
skipped engine is `unknown` because it never ran; both rendered a tooltip
blaming packet capture, contradicting the basis printed beside it. The title now
states the consequence and leaves the cause to the basis.

**CI has a Node job.** `test_console.py` skipped silently without it, and a
skipped test on a summary page reads exactly like a passing one — which would
have left `OTS-CON-004` enforced by nothing behind a green badge.
`OT_CONSOLE_REQUIRED` turns that skip into a hard error in the job that exists
to run it.

### Phase 6 — Fleet operations · **ENROLMENT AND LIFECYCLE DONE**

Enrolment, certificate lifecycle, signed updates, rule-pack distribution, health
alarms.

**Enrolment came first because nothing could be deployed without it.**
`TransportConfig` has always refused to start without a key, a certificate and a
CA bundle, and no part of the product could produce them. The fleet CA (Q4) now
does: `ot_server/ca.py` signs, `ot_server/enrolment.py` holds the token policy,
`collector/enrol.py` is the collector side, and `POST /api/v1/enrol` is the one
route in this server not behind mutual TLS — obtaining a certificate is what the
caller is there for.

The design is **D8**: the server names the collector and the collector proves it
holds a key. The CSR's own subject is discarded, because signing it would let a
collector be issued as another site's collector and report into that plant's
inventory with a certificate this CA really did issue.

**Revocation has to deny.** Nothing in a subject line changes when a certificate
is revoked, so a server authenticating on the name keeps accepting the revoked
holder while the console shows it as revoked — worse than not revoking, because
somebody stops looking. Where a CA is configured, every request is checked
against the issuance record by fingerprint, and unknown / revoked / expired /
name-mismatch are four refusals with four reasons rather than one 401.

**Two defects surfaced by running it rather than reading it.**

A mistyped CA fingerprint spent the token, left the server holding a certificate
nobody had, and blocked that collector's next legitimate enrolment with "it
already holds a valid certificate" — three problems from one typo. The anchor is
now checked against `GET /api/v1/ca` before the token is offered; the token is
the scarce thing in the exchange, so everything checkable without it is checked
first.

And refusing to enrol over any existing key made a retry harder than the first
attempt. A key with a certificate beside it is a live identity and is protected;
a key on its own is the debris of an enrolment that failed partway — a laptop
balanced on a cabinet — and is reused.

**The console shows the lifecycle**, because a revocation nobody can see is one
nobody can audit. With no CA configured the counts are `unknown` rather than
zero: a deployment without one has no issuance record, so "0 revoked" would be a
confident statement about identities nobody is tracking.

**An audit of the slice found nine more, and they had a shape.** Six of
them are the same mistake as the two above: a failure that costs more than
it should, because the expensive thing was consumed before the cheap check ran.

| | the defect | what it cost |
|---|---|---|
| 1 | the token was claimed before the CSR was parsed | a malformed CSR — the likeliest field failure — spent a one-time credential and sent the engineer back to an operator |
| 2 | the same, for a policy refusal | enrolling a collector that already held a certificate spent the token to be told no |
| 3 | `payload.get("ttl_hours") or DEFAULT` | an operator asking for a 0-hour token silently got 24 |
| 4 | a rejected mint raised | 500, which reads as "the fleet server is broken" when the problem was a ttl of `"soon"` |
| 5 | no length check at mint time | a name over X.509's 64-character cap minted fine and failed in a substation, with the token spent |
| 6 | renewal never retired anything | the overlap that protects against a lost response, unbounded, let one collector accumulate five, ten, twenty valid identities — undoing "one identity, one holder" one renewal at a time |
| 7 | the CA could sign past its own expiry | certificates that verify against nothing, failing as a TLS handshake error in a substation with nothing pointing back here |
| 8 | `ORDER BY severity` on a TEXT column, under a `LIMIT` | alphabetical: `medium`, `low`, `high` — so the limit dropped the high-severity detections first while looking like it kept the important ones |
| 9 | a malformed JSON body | a 500 from the one route reachable without a client certificate; and on the mint route, silently the defaults for a request the operator thought they had parameterised |

A token is now released whenever enrolment ends without a certificate, and
spent for good the moment one is issued: `release_enrolment_token` refuses to un-claim a
token once `used_serial` is set. Renewal retires every active certificate except
the one renewed from and the one just issued, so the overlap stays at two. The
CA refuses to sign once expired, and shortens — visibly, in a `note` the
response carries — rather than issuing past its own expiry.

**And one defect about the tests themselves.** `_FleetStore` stands in for
`Store`, and when the API grew a call the double did not have, the double raised
`AttributeError` — which surfaced only because a test happened to reach that
branch. On a branch no test reached, the double would have stayed quiet while
production answered 500. Two guards now: every `store.<method>` the API calls
must exist on the real `Store`, and every method the double implements must
exist there too, so a rename cannot leave the double answering for something
that is gone.

**A postscript, from checking rather than assuming.** The console job added in
Phase 5 was reported here as unproven on a runner. It was not: it has passed on
both pushes since. What the check did find is that CI had been RED for the three
commits before it — every Python leg failing at "Run tests" — because
`starlette.testclient` imports `httpx`, nothing in the dependency tree requires
it, and `requirements-dev.txt` did not name it. On a developer machine it was
present for some other reason; on a clean runner every API test raised at
import. The Phase 5 commit fixed that as a side effect of declaring `httpx`.

Two things were wrong, and only one of them was the dependency.

`requirements-dev.txt` opens by claiming exactly the property it lacked —
"without them the server tests do not fail, they ERROR at import, which reads as
a broken checkout rather than a missing install". Nothing checked the claim, so
`tests/test_dependencies.py` now does: an HTTP client must be named, and
`fastapi.testclient` must really import wherever fastapi does.

And nobody saw the red. The README carries a **CI badge** now, which is the
cheaper half of the fix.

The `cryptography` floor was checked the same way rather than reasoned about:
48.0 raised requires-python to `>=3.9`, so pip on the 3.8 leg resolves to
47.0.0 and stays there — a `cp38-abi3` wheel, no Rust toolchain on the runner,
and both `not_valid_before_utc` and `not_valid_after_utc` present. A test now
asserts those accessors exist, so a wrong resolution fails with that sentence
instead of an `AttributeError` inside `ca.sign()`.

**The terminator contract is now executed, not documented.** Everything this
server knows about who is calling comes from headers a TLS terminator sets, and
no config in this repository had ever been run against it. `deploy/` carries
reference nginx and HAProxy configs, and `tests/test_terminator.py` starts the
server, puts the nginx one in front of it in a container with mutual TLS, and
attacks it from outside.

Writing the config changed the design twice, and running it changed a test.

**nginx cannot produce the digest this server records.**
`$ssl_client_fingerprint` is SHA-1, and nothing in stock nginx computes
SHA-256 — so a contract that asked for one was not implementable on the most
likely terminator. The server now accepts the verified certificate itself and
computes the digest, which is the better division anyway: nginx is trusted for
one thing rather than two.

**The enrolment plane cannot sit behind `ssl_verify_client on`.** A collector
arriving at a substation has no certificate, and obtaining one is what it is
there for, so verification is `optional` at the server level and enforced per
location. That would have been found by a failed deployment.

**And a repeated identity header was a total bypass.** `Headers.get()` returns
the FIRST of a repeated header. A terminator that appends rather than replaces —
HAProxy's `add-header`, or a missing `proxy_set_header` — leaves the caller's
value in front of its own, and the server authenticates whoever asked to be
authenticated. Nothing downstream looks wrong: the certificate was real, the
request was ordinary. The server now refuses a repeated identity header rather
than resolving it, so a misconfiguration fails loudly. The config is the floor;
this is the net.

**One test claimed more than it proved.** `test_a_forged_fingerprint_header_is
_not_honoured` was written as though the clearing directive defeated the attack.
Deleting that directive failed nothing — the certificate wins when both arrive.
Deleting the CERTIFICATE directive fails four tests, and makes the forged
fingerprint succeed. So the clearing directive is redundant under the shipped
nginx config and load-bearing under the fingerprint-only shape HAProxy runs in;
the test now says that, and a separate check asserts both configs carry it.

### `OTS-SRV-006` — the console has a front door · **DONE**

Every estate route answered 503 with the instruction that a deployment must
inject an operator hook, and nothing in the product was one — so the console
could not be used at all. `ot_server/authn.py`, `authn_api.py`, `totp.py` and
`qr.py` are that hook, and `console/public/login.html` is its front door.

Password plus TOTP, with **no session issued until both are satisfied**, and no
default password anywhere. The reasoning is decision **D9**; the two things
worth repeating here are that the TOTP and the QR encoder are both checked
against external oracles (RFC 6238 Appendix B, ISO/IEC 18004's worked example)
rather than against themselves, and that wiring this is an opt-in that leaves
the fail-closed posture exactly as it was.

The product is branded **Power NetView** on the console and the sign-in page.

**Two things this cost, both worth recording.** `authn_api.py` was written with
`from __future__ import annotations`, which is the trap the top of `api.py`
documents: FastAPI then sees the route annotations as strings, cannot resolve
`Request`, treats it as a query parameter, and every route answers 422. The note
was there and had to be rediscovered.

And the in-memory store double answered exactly one estate route, so "signed in,
now read the estate" passed in the unit tests and returned 500 the first time it
ran against a real server. The double is complete now — the same lesson as the
one in Phase 6, arriving from the other direction.

**Still to do in this phase.** Signed updates, rule-pack distribution and
server-side health alarms. Once the fleet is stable, two borrowed capabilities
become candidates: learned communication zones (Claroty's virtual zones,
extending the existing `topology/`) and process-variable baselining (Nozomi —
the protocol parsers already decode the point values it needs).

---

## Decisions in force

| | decision | consequence |
|---|---|---|
| **D1** | the management NIC must not bridge the OT L2 domain | capture NIC has no IP and TX disabled; management NIC on a dedicated VLAN, ACL to the server only |
| **D2** | continuous capture, and drops are reported | packet-drop accounting is mandatory, not diagnostic |
| **D3** | volatile facts live on the server | `cvedb/` never ships to a collector; a KEV addition re-prioritises the estate without touching a Pi |
| **D6** | zones are derived per site | a mostly-defaulted derivation is refused; the engines stay `SKIPPED` and say which of the two empty states applies |
| **D7** | the console is served by the server | one origin, so no CORS relaxation of the fail-closed estate plane; only `public/` and `dist/` are mounted |
| **D8** | an identity is issued, not requested | the CSR's subject is discarded; every request is checked against the issuance record, so revocation denies |
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
