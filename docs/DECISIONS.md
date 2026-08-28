# OT Sensor Fleet — decisions

The decisions taken while re-architecting the scanner into a collector fleet,
recorded with their reasoning and — where one exists — the test that keeps the
answer true.

**Why this file exists.** A decision that lives only in a conversation gets
re-litigated, and worse, gets contradicted by code nobody checked against it.
Several of these are also answers a customer's security review will ask for
directly: *"can this sensor reach our PLCs?"* is a question where *"we decided
that deliberately, here is the test that enforces it"* is a materially different
answer from *"we haven't done that yet."*

---

## Status at a glance

| | Decision | Answer | Enforced by |
|---|---|---|---|
| **D1** | May the management NIC share the OT L2 domain? | **No** — dedicated management VLAN | deployment; `OTS-CAP-001` preflight |
| **D2** | Are dropped frames reported, or absorbed? | **Reported** — coverage is a property of every window | `tests/test_collector_coverage.py` |
| **D3** | Where do CVE / KEV / EPSS live? | **Server only** — never on a collector | `tests/test_collector_manifest.py` |
| **D4** | Does the collector ever transmit? | **No** — no send path exists | `tests/test_collector_capture.py` |
| **D5** | Do packet payloads leave the plant? | **No** — records carry conclusions, not bytes | `tests/test_collector_analysis.py` |
| **D6** | Are Purdue zones derived across the estate? | **No** — per site, and a mostly-guessed derivation is refused | `tests/test_server_zones.py` |
| **D7** | Where does the operator console live? | **In the server** — one origin, one deployable | `tests/test_console.py` |
| **D8** | What decides a collector's identity? | **The server** — the CSR's own subject is discarded, and every request is checked against the issuance record | `tests/test_fleet_enrolment.py` |
| **Q1** | Server datastore | **PostgreSQL only** | Phase 3 |
| **Q2** | Scale | **<50 Mbps per site, <10 collectors** | `OTS-NFR-001` |
| **Q3** | Hardware | **Pi 5, rolling pcap on USB SSD** | `OTS-OPS-002` |
| **Q4** | CA for collector mTLS | **Self-managed, shipped with the server** | Phase 3 |
| **Q5** | Retention | **512 GiB pcap; 13 months observations** | `OTS-OPS-003/004` |

---

## D1 — The management NIC must not bridge the OT L2 domain

**Asked because** the original design put both Pi NICs on the same OT switch.

**Answer.** The capture NIC sits on the SPAN port with **no IP address and
transmit disabled**. The management NIC sits on a **dedicated management VLAN**
whose ACL permits exactly one thing: outbound to the server on 443. The physical
switch may be shared; the L2/L3 domain may not.

**Reasoning.** If both NICs share the OT L2 domain, the collector becomes a
route from the plant network to wherever the server lives — a pivot path
installed, by design, in every substation. Nozomi, Claroty and Dragos sensor
deployments all separate the management plane for this reason.

**What enforces it.** Deployment configuration, plus `OTS-CAP-001`: an IP
address on the capture interface is a **refusal to start**, not a warning. With
an address the kernel owns the interface and will emit ARP, DHCP, mDNS and IPv6
router solicitations onto the OT segment — and nothing in a packet capture tells
you your own NIC is talking. A warning would be scrolled past and the collector
would run for a year.

---

## D2 — Dropped frames are reported, never absorbed

**Answer.** Coverage is a property of every window, travels with every finding
derived from it, and has **three** states: `COMPLETE`, `DEGRADED`, `UNKNOWN`.

**Reasoning.** A passive sensor that drops frames under load still produces a
report, and that report is indistinguishable from one taken on a network that is
genuinely clean. On a substation network that is the worst failure this system
can have.

`UNKNOWN` is the state usually missing, and it is the load-bearing one. A
collector that cannot measure loss has not established there was none — so
`observed_fraction` returns `None` rather than a confident 1.0, `degraded` is
true, and sustained unmeasurable windows raise their own **BLIND** alarm,
separate from the loss alarm because the fix differs (a missing counter source,
not an undersized buffer).

**Consequences that follow from it, each pinned by a test:**

- A counter going **backwards is a reset**, not zero loss.
- Interface loss and capture loss are **counted separately** — different
  failures, different fixes.
- **One** counter reading closes a window and opens the next; reading twice
  leaves a gap where loss is invisible.
- A replayed pcap reports `UNKNOWN`, never `COMPLETE`.
- The throughput benchmark refuses to certify a rate it could not verify.

**What enforces it.** `tests/test_collector_coverage.py`. Mutation-tested:
injecting the classic bug — treating an unreadable counter as zero loss — fails
six tests.

---

## D3 — Volatile facts live on the server

**Answer.** Collectors ship observations. The server holds the vulnerability
corpus and matches against it.

**Reasoning.** CVE records, CISA KEV status and EPSS scores change daily.
`cvedb/` is 3,170 lines today. Shipping it inside a fleet of collectors makes
every CVE refresh a firmware push to every substation, and makes each
collector's answer depend on when it was last updated. Server-side matching
means a KEV addition re-prioritises the whole estate without touching a single
collector.

**What enforces it.** `tests/test_collector_manifest.py` — `cvedb/` is in the
excluded set, tested per package, and every exclusion must carry a stated
reason so removing one is a visible decision rather than quiet drift.

---

## D4 — The collector never transmits

**Answer.** No capture source has a send path.

**Reasoning.** The capture interface is the one place a bug could put a frame
onto a live plant network, where it can reach a protection relay. "We are
passive" has to be a checked property of the running system rather than a claim
in a README.

**What enforces it.** `tests/test_collector_capture.py` walks the **AST** of
`capture.py` for calls to `send`, `sendp`, `sendto`, `sr`, `sr1`, `srp`,
`L2socket`, `L3socket`. The live source uses scapy's `L2listen`, a listening
socket, rather than `L2socket`, which can send.

This guard began as a substring scan of the source text and fired on a *comment*
explaining why `L2socket` is not used — brittle in both directions, false
positives on prose and false negatives on a call split across lines. A companion
test proves the guard fires on a real `sock.sendp(...)`, because a guard that
cannot fail is decoration.

---

## D5 — Packet payloads do not leave the plant

**Answer.** Observation records carry what was *concluded*, never the bytes it
was concluded from. Raw pcap stays on the collector unless explicitly requested
per incident (`OTS-TRN-006`).

**Reasoning.** A collector sits inside an operator's process network, and the
bytes on that network are the plant's business — setpoints, tag names, sometimes
credentials in cleartext protocols that predate authentication. Shipping them to
a central server by default would make this system a data-exfiltration path with
a security label on it, and at many sites the capture legally cannot leave.

**What enforces it.** `tests/test_collector_analysis.py`. `scrub()` drops
payload-named fields *and* any binary value, as belt and braces against a future
analyser attaching one. Bytes are **dropped rather than encoded** — base64 of a
payload is still the payload.

---

## D6 — Zones are derived per site, and a guessed derivation is refused

**Asked because** three things were blocked on zones — attack-path analysis,
firewall policy generation and the topology view — and nothing derived them from
estate data.

**Answer.** Zones are derived **per site**, never across the estate. Each zone
records the **basis** of its Purdue level — `role`, `protocol` or `defaulted` —
and a derivation where more than half the levels came from the fallback is
**refused**: the engines that need segmentation stay `SKIPPED`, with the reason
naming which of the two states applies.

**Reasoning — the site scope.** The same trap as the asset merge, one level up.
`TopologyEngine` groups devices into /24 subnets, and `10.10.1.0/24` exists at
almost every plant. Deriving across the estate fuses two substations into one
zone, and then a cross-plant flow reads as a segmentation breach inside one site
while a real breach inside a site is hidden by the merge — wrong in both
directions at once.

**Reasoning — the refusal.** `_assign_purdue_levels` always returns a level; its
documented fallback is *default to Level 1*. A recognised role and a fall-through
are indistinguishable in its output, and both are then consumed by a firewall
rule generator whose output someone may apply to a live plant network. Refusing
is the conservative direction: **"we had no zones" is visibly absent, "we had bad
zones" is confidently wrong**, and only the second gets deployed.

The classification does not reimplement the level assignment — it re-runs the
engine's own predicates afterwards, so it cannot drift from the assignment it
describes.

**What enforces it.** `tests/test_server_zones.py`. Deriving estate-wide instead
of per site fails 5 tests; letting a mostly-defaulted derivation count as usable
fails 2.

---

## D7 — The console is served by the analysis server

**Asked because** the console had to be delivered somehow, and the obvious
alternative — a static bundle on whatever web server the plant already runs — is
how most front ends ship.

**Answer.** The server serves it, from the same origin as the API.

**Why.** A second origin means the browser sends no credentials to the estate
API unless CORS is opened for it. The estate plane is the half of this system
that is fail-closed on purpose: ingest credentials do not grant console access
(`OTS-SRV-006`), because a certificate lifted from a substation cabinet must not
yield a map of the plant. Relaxing its cross-origin policy to make a separate
bundle reachable would widen exactly the surface that requirement narrows, and
it would widen it in a configuration file rather than in code anyone reviews.

One origin also means one deployable. The console client takes no API base URL
and sends `credentials: "same-origin"`; there is no environment where those are
configured wrongly, because there is no configuration.

**What that costs, and what is done about it.** A static mount is a way to serve
files that were never meant to be served.

- Only `console/public/` and `console/dist/` are mounted. Mounting the console
  directory would publish `src/` and `node_modules/` to anyone who can reach the
  port; four tests assert those paths 404.
- The shell is **unauthenticated and empty**. It contains no estate data — every
  figure on it is fetched from `/api/v1/estate/*`, which still answers 503
  without an operator. An unauthorised visitor gets the frame and an explicit
  refusal in place of every number, which is deliberately not the same as a page
  of empty tables.
- If the console was never built, `index.html` says so. Its untouched content is
  a failure message rather than a spinner or a blank page: a blank page reads as
  a plant with nothing in it, which is the failure this system exists to
  prevent, arriving at the last step where a person actually reads it.

---

## D8 — An identity is issued, not requested

**Asked because** `TransportConfig` has always refused to start without a
private key, a certificate and a CA bundle, and nothing in the product could
produce any of them. The fleet could not be deployed.

**Answer.** The server names the collector; the collector proves it holds a key.

### The CSR's subject is discarded

A certificate signing request carries a subject, and the obvious implementation
signs it. Then a collector requests `CN=pi-substation-01`, receives a
certificate that authenticates it as another site's collector, and reports
assets into that site's inventory. Every request afterwards looks perfectly
ordinary, because the identity really was issued by this CA.

So the CSR is used for exactly one thing — its public key, and the proof that
the requester holds the matching private key. The name comes from the enrolment
token an operator minted. This is the same rule as `api.collector_identity`
("the identity comes from the certificate, not the body"), one layer lower.

The CA also refuses: a CSR whose self-signature does not verify (otherwise a
certificate can be issued over somebody else's public key), RSA below 2048 bits
and curves outside P-256/P-384, `serverAuth` (a collector certificate that could
authenticate a server could terminate TLS for the ingest endpoint and the fleet
would report to it), and `CA:TRUE`.

### Revocation has to deny, or it is theatre

Nothing in `CN=pi-substation-01` changes when that certificate is revoked. A
server that authenticates on the subject keeps accepting the revoked holder
while the console shows the certificate as revoked — which is worse than not
revoking at all, because somebody stops looking.

So where a CA is configured, the TLS terminator must also pass the client
certificate's SHA-256 fingerprint, and the server checks it against
`certificate`. Unknown, revoked, expired, or naming a different collector than
the subject are each refused, each with its own reason: "we do not know this
certificate" and "we revoked this certificate" are different events for whoever
reads the log.

### One identity, one holder

Enrolling a collector that already holds a valid certificate is **refused**
unless the operator allowed reissue when minting the token — and when they did,
the previous certificates are revoked as part of issuing rather than left
alongside. Otherwise a token stolen from a mailbox and replayed mints a second
valid identity for a collector that has been running for a year: both
certificates work, and the server cannot tell which of the two is the plant.

### What the deployment must do

**The TLS terminator must strip client-supplied `X-Client-Subject` and
`X-Client-Fingerprint` before setting its own.** Every identity claim in this
server rests on those two headers being the terminator's words rather than the
caller's. A terminator that merely adds them lets anyone who can reach the port
name themselves, and the requests look ordinary.

### A token is spent only when a certificate exists

The redemption is atomic so a replay cannot pass a check a concurrent request
has already passed. But claiming a token and then refusing to issue — a
malformed CSR, a collector that already holds a certificate — consumes a
one-time credential on a request that produced nothing, and the engineer at the
cabinet goes back to an operator for another one. Enrolment releases the claim
on every path that does not end in a certificate, and `used_serial` makes the
release one-way: a token that worked stays spent forever.

The same rule shapes the renewal overlap. A renewal does not revoke the
certificate it renews, because a response lost on the way to a substation would
otherwise strand a collector that had just invalidated its only identity. Left
unbounded, that would undo "one identity, one holder" one renewal at a time, so
each renewal retires every active certificate except the one it renewed from and
the one it issued. Two, never more.

### The one endpoint without mutual TLS

`/api/v1/enrol` cannot require a client certificate: obtaining one is what the
caller is there for. A single-use token stands in front of it, stored only as a
SHA-256, redeemed by one conditional UPDATE so a replay cannot pass a check that
a concurrent request has already passed.

`/api/v1/ca` is also unauthenticated, and deliberately so — a CA certificate is
the trust anchor everyone needs before verifying anything, and it travels in the
clear in every TLS handshake. Publishing it is what lets a collector check the
fingerprint an operator gave it **before** spending its token. That ordering was
not obvious until the flow was run end to end: checking the enrolment response
instead meant one mistyped fingerprint spent the token, left the server holding
a certificate nobody had, and blocked the next legitimate enrolment of that
collector with "it already holds a valid certificate".

### And the collector still carries only dpkt

Key generation and CSR creation shell out to `openssl`, which ships with
Raspberry Pi OS. `manifest.RUNTIME_REQUIRES` stays `("dpkt>=1.9.8",)` and the
test asserting that exact tuple still passes. The private key is generated on
the Pi and never leaves it: a server that generated the pair and sent it back
would be simpler and would put every collector's private key on the network,
which is what "the CA private key never leaves the server" was written to
prevent, applied to the wrong key.

---

## Q1–Q5 — deployment questions

Answered 2026-08-28. Recorded in the SRS as requirements; summarised here.

**Q1 · PostgreSQL only.** One dialect, one set of migrations, and it matches the
multi-collector concurrency model. No SQLite variant to keep in step — OverWatch
carries exactly that dual-dialect tax and it is a real ongoing cost.

**Q2 · Under 50 Mbps per site, fewer than 10 collectors.** Comfortable for a
Pi 5, which has a consequence worth stating: `COMPLETE` coverage is the expected
normal state, so a `DEGRADED` window is a genuine signal rather than background
noise. That is what makes the drop alarm worth acting on instead of worth
muting.

**Q3 · Raspberry Pi 5, rolling pcap on attached USB SSD.** The SD card stays
boot-only; continuous pcap writing to SD is a predictable failure measured in
weeks (`OTS-OPS-002`, and the collector warns at start-up).

**Q4 · Self-managed CA shipped with the server.** Enrolment and revocation stay
inside the product rather than depending on an external PKI process at each
site. The CA private key is generated on the server at install and never leaves
it.

**Q5 · 512 GiB pcap ceiling; 13 months of observations.**

The two sides have completely different economics, so they are expressed
differently:

| | at 50 Mbps peak | at 2–5 Mbps typical |
|---|---|---|
| pcap | 540 GB/day — 1 TB lasts 1.9 days | 22–54 GB/day — 18–46 days |
| observations | ~0.15–0.6 GB/day/collector | years are cheap |

**pcap retention is configured in bytes and reported in days.** A promise
expressed in days is broken silently by a busy afternoon: the same budget holds
roughly nine days at 5 Mbps and under one during a sustained burst. Bytes are a
promise the collector can keep; days are a measurement it must publish —
`300.0 GiB across 2 file(s); holding 9.3 days`. An unmeasurable window says *not
yet measurable* rather than reporting zero days, because those are different and
only one should send an operator looking for the capture.

**13 months** of observations covers a full year of seasonal plant behaviour
plus one month, so a year-on-year comparison always has both endpoints.

---

## Deliberately not done

**Active polling of OT devices.** Nozomi and Claroty both offer it, carefully
rate-limited, and it materially improves inventory depth. It also sends packets
to production PLCs. This tool's entire safety claim is that it never transmits,
and that claim is worth more than the extra inventory. If it is ever built it
must be a separate, explicitly-enabled component — never a default of the
collector. See D4.

**Anomaly-only detection.** Known-bad behaviour first. Dragos are explicit about
favouring codified adversary behaviour over unsupervised anomaly detection, and
the reason is operational: an anomaly alert an operator cannot action is noise,
and noise trains people to close the console.
