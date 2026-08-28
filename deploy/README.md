# Deploying the fleet server

The server behind these configs trusts two request headers absolutely.
Everything it knows about who is calling comes from them, which makes the
terminator config part of the security design rather than scaffolding around
it — see [DECISIONS D8](../docs/DECISIONS.md).

| | |
|---|---|
| [`nginx/ot-fleet.conf`](nginx/ot-fleet.conf) | reference nginx terminator |
| [`haproxy/ot-fleet.cfg`](haproxy/ot-fleet.cfg) | the same for HAProxy |

Both are executed, not merely documented:
[`tests/test_terminator.py`](../ot_scanner/tests/test_terminator.py) starts the
server, puts the nginx config in front of it in a container with mutual TLS, and
attacks it from outside. A config nobody runs is a document, not a control.

---

## The three rules

### 1. Strip the caller's copy before setting your own

`proxy_set_header` (nginx) and `http-request set-header` (HAProxy) **replace**.
`http-request add-header` **appends** — and an appended header leaves the
caller's value *in front of* the terminator's, because the caller's was already
in the request. A server reading the first value then authenticates whoever
asked to be authenticated, and nothing downstream looks wrong: the certificate
was real, the request was ordinary, and the inventory it poisons belongs to
another plant.

The server refuses a repeated identity header for exactly this reason. Do not
rely on that: it is the net, not the floor.

Set **every** identity header, including ones the config does not use. A header
left alone is a header the caller supplies.

### 2. The enrolment plane cannot require a client certificate

`/api/v1/enrol` and `/api/v1/ca` must be reachable without one. A collector
arriving at a substation has no certificate; obtaining one is what it is there
for. So verification is `optional` at the server level and enforced per
location — not `on` globally, which is the config most people would write.

### 3. Pass the certificate, or a SHA-256 — not a SHA-1

The server checks every request against its own issuance record, by digest.

**nginx cannot produce that digest.** `$ssl_client_fingerprint` is SHA-1, and
nothing in stock nginx computes SHA-256. So the nginx config passes the verified
certificate itself, in `X-Client-Cert` (`$ssl_client_escaped_cert`), and the
server computes the digest. That is the better division anyway: nginx is trusted
for one thing — that the certificate validated against the fleet CA — rather
than that plus agreeing about which hash to use.

**HAProxy can**, via `ssl_c_der,sha2(256),hex`, so it may send
`X-Client-Fingerprint` instead. If both arrive the certificate wins.

---

## Headers the terminator owns

| header | who sets it | what it carries |
|---|---|---|
| `X-Client-Subject` | terminator | the verified certificate's subject DN |
| `X-Client-Cert` | terminator | the verified certificate, URL-escaped PEM |
| `X-Client-Fingerprint` | terminator | its SHA-256, lowercase hex |

A request carrying any of these from the client must never reach the server with
that value intact.

---

## The operator session (D9)

The console signs operators in with a password and a TOTP code, and carries the
session in an `HttpOnly`, `SameSite=strict` cookie. Two things the terminator
must get right:

**Pass `X-Forwarded-Proto`.** The cookie is marked `Secure` when the request
arrived over https, and the server reads that header to find out. Without it, a
terminator doing TLS in front of a plain-http upstream produces a cookie the
browser then refuses to send back — the sign-in appears to succeed and the next
request is anonymous. Both configs here set it.

**Do not strip or rewrite `Cookie` / `Set-Cookie`.** Nothing in these configs
touches them, and nothing should: the session is the cookie.

`/login.html`, `/logo.svg` and the bundle are static and unauthenticated, which
they must be — the sign-in page cannot require a session. They carry no estate
data; every figure still comes from `/api/v1/estate/*`.

---

## Siting a collector

### Which port to mirror

Prefer an **access / UNI port facing the RTUs**. You get the device's own MAC,
its IP, and no ambiguity.

An **NNI or trunk carrying MPLS-TP pseudowires** also works — the collector
opens the label stack and the pseudowire control word — but two things change:

* The outer MACs are the provider edge routers'. An Ethernet pseudowire yields
  the RTU's real MAC; a *routed* pseudowire carries no inner MAC at all, and
  the collector reports the router's rather than inventing one.
* A pseudowire that omits the control word is inherently ambiguous. Those
  frames are counted as unreadable rather than guessed at, and the window is
  degraded accordingly.

**If the estate comes up empty, read the window before the network.** A tap on
the wrong side of a pseudowire produces a perfectly quiet, entirely empty
estate, and the window says so in as many words: *"an empty estate here means
the tap, not the network."*

### Two NICs, and why the second one matters

| NIC | Role |
|---|---|
| **tap** | promiscuous, **no IP address**, never transmits |
| **mgmt** | reaches the server over mTLS; carries heartbeats and batches |

The management NIC's own traffic must never be analysed as estate traffic, or
the collector inventories itself and its conversation with the server becomes a
flow in the plant's topology. Configure the exclusion explicitly:

```
--mgmt-mac   AA:BB:CC:DD:EE:FF     # the management NIC
--mgmt-ip    10.20.0.51            # its address
--server-ip  10.20.0.10            # the server it dials
```

The number of excluded frames is **recorded**, not assumed. Under a BPF filter
the kernel does not report it, and the collector says so rather than reporting
zero.

### What a mirror must carry

Beyond the industrial protocols, three things are worth ensuring reach the
span port, because each unlocks identification nothing else provides:

* **LLDP** — the only passive source that names the ring switches at all, and
  the source of their management IP. Note the cadence: the default transmit
  interval is 30s against a 60s window, so a switch emits *two* advertisements
  per window.
* **SNMP** (v1/v2c) — `sysDescr` is the only route to an OS version for a
  device whose industrial protocol carries no identification service, which
  includes every IEC 60870-5-104 RTU and FRTU. v3 is encrypted and yields
  nothing; the device is still recorded as seen.
* **R-APS / BPDUs** — ring protection. Without them a protection switch is
  invisible, and a device that moved out of earshot looks like a device that
  stopped talking.

---

## Sizing the server

The fleet is built and tested for **~100 collectors against one server**.

Measured on PostgreSQL 16 with 100 collectors:

| devices per ring | asset rows | flows | estate query |
|---:|---:|---:|---|
| 20 | 2,000 | 6,000 | 0.02s |
| 50 | 5,000 | 20,000 | 0.05s |
| 120 | 12,000 | 40,000 | 0.05s |

Query time is not the constraint. **Row limits are**: the estate reads return
at most 5,000 assets and 20,000 flows, and above that the console is told
plainly that it is seeing part of the estate rather than the whole of it
(`read.complete` on every estate route). If your fleet exceeds those, raise the
limits deliberately — the truncation will be visible either way, which is the
point.

Retention is 13 months (Q5b), applied by a scheduled prune.

---

## What is not covered here

**TLS for the server certificate itself.** These configs assume you already have
one for the name collectors dial. The fleet CA is for *client* certificates and
is deliberately not used for the server's own — a collector verifies the server
against whatever bundle it was enrolled with.

**Rate limiting on `/api/v1/enrol`.** It is the one unauthenticated route, and
its token has 256 bits of entropy, so guessing is not a strategy. A
`limit_req_zone` there is still cheap insurance against a caller hammering it,
and is left to the deployment rather than baked in.

**Where the server listens.** Both configs proxy to `127.0.0.1:8001`. The
uvicorn process must not be reachable from anywhere else — every identity check
in this system assumes the request came through the terminator.
