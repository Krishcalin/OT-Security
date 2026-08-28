# Architecture — collector and server

The scanner was a command-line tool: point it at a `.pcap`, get a report. That
model cannot answer the question an OT security team actually has — *what is on
my network right now, and what changed since yesterday* — because it only sees
what someone remembered to capture.

This is the distributed form: passive collectors at each plant network, a
central server that correlates across them, and a console that presents one
asset inventory for the estate.

```
Plant network (Purdue L2/L3)
  OT switch SPAN port
        |  mirrored frames
        v
  Raspberry Pi collector
    eth0  no IP, TX disabled          <- capture
    eth1  management VLAN             -> outbound HTTPS 443 only
        |
        v
  Analysis server            FastAPI ingest (mTLS) -> PostgreSQL -> engines
        |
        v
  Web console (TypeScript)
```

Collectors never accept inbound connections. Every session is dialled out by the
collector, so no listening port exists on a device sitting inside the plant
network.

---

## The partition is a projection, not a fork

The obvious way to split a codebase is to move files. Here that would mean two
copies of the protocol analysers — one in the scanner, one in the collector —
and copies diverge. They always do, and the divergence is silent: a rule fixed
on the desk and not in the field, or the reverse.

So there is **one tree**. `ot_scanner/collector/manifest.py` declares the subset
a collector wheel is built from, and the existing scanner keeps working
untouched.

```
python -m collector.build --dest ./dist/collector
```

### What ships to a collector

| package | lines | why it must be where the frames are |
|---|---:|---|
| `scanner/protocols/` | 5,397 | parses frames — 18 analysers |
| `scanner/core.py` + `models.py` | 2,030 | packet handlers, device registry, shared vocabulary |
| `scanner/vuln/` | 1,802 | ~30 rules over parsed events; must fire in real time |
| `scanner/threat/` | 1,088 | behavioural ICS malware signatures; latency matters |
| `scanner/fingerprint/` | 971 | vendor identification at asset-extraction time |
| `collector/` | ~2,000 | capture, coverage, transport |

### What stays on the server

`cvedb` · `report` · `export` · `policy` · `topology` · `compliance` · `delta` ·
`attack` · `config` · `risk` · `access` · `project_files`

Each carries a stated reason in `manifest.EXCLUDED`, and a test fails if one
reappears in a distribution. `cvedb` is the one that matters most — see D3 in
[DECISIONS.md](DECISIONS.md).

### Why the partition needed no code changes

Every engine import in `scanner/core.py` is already guarded:

```python
try:
    from .topology.engine import TopologyEngine
    _HAS_TOPOLOGY = True
except ImportError:
    _HAS_TOPOLOGY = False
```

So a collector shipped without `topology/` and `cvedb/` simply resolves those to
`False`.

**That same property is the trap.** Dropping `vuln/` from the manifest does
*not* crash the distribution — the guarded import degrades to zero findings, and
the collector starts cleanly and reports nothing. So manifest completeness is
proved by **parity in a subprocess** with only the assembled tree importable,
never by "does it import":

```
assemble -> run isolated -> compare assets and findings against the full tree
```

---

## The collector

```
collector/
  preflight.py       refuses to start on an unsafe interface   (OTS-CAP-001)
  capture.py         frame sources: live SPAN, replay, synthetic
  counters.py        drop counters: sysfs, AF_PACKET, libpcap
  coverage.py        the accounting core — three states        (OTS-CAP-003/004)
  health.py          sustained-loss and blind alarms           (OTS-CAP-005)
  self_exclusion.py  the collector's own traffic               (OTS-CAP-006)
  rotation.py        bounded rolling pcap                      (OTS-CAP-002)
  decap.py           MPLS / pseudowire decapsulation          (D14)
  analysis.py        drives the existing analysers             (OTS-ANL-001/003)
  observations.py    the wire record                           (OTS-ANL-002/004)
  rulepack.py        content-hashed rule version               (OTS-ANL-005)
  service.py         the loop
  manifest.py        what ships                                (§5)
```

### Three things reach the window, not one

Coverage began as packet loss and is now three independent blindnesses, because
they fail differently and an operator fixes them differently:

| What | Means | Fix |
|---|---|---|
| **frames lost** | the NIC or capture buffer dropped them | a faster Pi, a smaller BPF |
| **frames unreadable** | they arrived intact on a transport we could not open | tap elsewhere, or teach `decap.py` |
| **ring protected** | traffic moved; some of it may have left earshot | nothing — but a silent device is now explained |

Collapsing them into one number would send somebody to the wrong place. A
window that lost nothing, read nothing and protected once is three different
sentences, and the estate needs all three.

### Coverage is the spine

Everything the collector reports is conditional on it. A finding from a window
that dropped frames is a different claim from one taken on a complete window,
and a window whose counters could not be read supports neither. The three states
— `COMPLETE`, `DEGRADED`, `UNKNOWN` — are described in
[DECISIONS.md](DECISIONS.md#d2--dropped-frames-are-reported-never-absorbed).

### Identification, and what cannot be identified

The estate is only as good as what it can name. Four passive sources answer
that, in descending order of how much they give:

| Source | Gives | For |
|---|---|---|
| **IEC 61850 MMS Identify** | vendorName, modelName, revision | relays and IEDs |
| **LLDP** (802.1AB) | make, model, OS version, **management IP**, hostname | ring switches — the ONLY thing that sees them |
| **SNMP `sysDescr`** | the same string by a different road | anything the NMS polls |
| **Modbus FC43/MEI** | vendor, product code, revision | Modbus devices |

LLDP earns its place for a reason the others do not need: a ring switch speaks
no industrial protocol and its management traffic may never cross the mirror.
Its Management Address TLV is why a switch can be inventoried **by IP** at all.

`lldp.identify()` is shared with SNMP because LLDP's System Description TLV *is*
the `sysDescr` MIB object — two tables would drift, and one switch would be two
models depending on which road its identity arrived by. The BER reader is shared
with MMS for the same reason.

**What no source can supply**: IEC 60870-5-104 has no identification service, so
a 104-only FRTU can never report a model or firmware passively. The console
renders that as a stated limit, not as an empty cell (D16).

### The analysers are the same analysers

`PCAPAnalyzer._handle_ip_packet` and `._handle_l2_frame` were already the
per-packet entry points; `analyze()` is only a file reader wrapped around them.
The collector feeds those same handlers from a live stream.

Writing a second decoder would have been easier and wrong — two decoders drift,
silently. The parity test is what makes the reuse verifiable rather than
hoped-for.

**A window is an accounting boundary, not an analysis one.** One analyser
instance lives for the life of the collector, so a DNP3 session opened at 10:59
and exploited at 11:01 is still one session. `_finalise()` is safe to run per
window because it *assigns* `device.vulnerabilities` rather than appending —
checked before relying on it, and pinned by test, because an append would
inflate every count on a long-running collector and nothing else would notice.

---

## Testability

Everything in `collector/` runs **without a capture NIC, without root, on any
OS** — driven by a synthetic source and by replaying the repository's own sample
capture.

That is a design property, not a convenience. The logic under test decides what
the collector may claim to have seen; if it could only be exercised on a
Raspberry Pi it would never be exercised at all. Only the counter sources and
the live scapy backend require Linux, and both sit behind a seam.

The same reasoning put `requests` behind a lazy import in the triage harness and
`scapy` behind `open()` here: a platform constraint in one layer must not make
the layer above it untestable.

---

## See also

- [BUILD_ORDER.md](BUILD_ORDER.md) — the phase plan and what is built
- [DECISIONS.md](DECISIONS.md) — decisions with the tests that keep them true
- **OTS-SRS-001** — the specification
