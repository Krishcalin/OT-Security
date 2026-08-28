/**
 * OTS-CON-004, proved by the compiler refusing to build.
 *
 * This file is EXCLUDED from the build and compiled on purpose by
 * `tests/test_console.py`, which asserts that each marked line produces an
 * error. A rule enforced by review survives about three sprints; a rule
 * enforced by the type checker fails the build.
 *
 * If any of these ever compiles, OTS-CON-004 has stopped being structural and
 * has quietly become a convention again.
 */

import { measured } from "./coverage.js";
import { metric, table } from "./render.js";

// EXPECT-ERROR: a bare number cannot be rendered as a metric. This is the whole
// requirement: someone adds a summary tile in a hurry and the count appears with
// nothing saying what it rests on.
metric("assets", 42);

// EXPECT-ERROR: an object that merely looks like a Measured is not one. The
// brand makes it unforgeable, so measured() — which demands a basis — is the
// only way in.
metric("assets", { value: 42, coverage: "complete", basis: "made up" });

// EXPECT-ERROR: coverage is a closed set. "probably fine" is not a state, and
// admitting free-form strings would let an unrecognised value be coerced to
// something reassuring.
measured(42, "probably fine", "a basis");

// EXPECT-ERROR: a table row must carry its own coverage. Per-row, because one
// collector may be blind while another is healthy.
table([{ header: "ip", cell: (r: { ip: string }) => r.ip }], [
  { row: { ip: "10.0.0.1" } },
]);

// This one is fine, and is here so the file cannot pass by failing to import
// anything real.
const ok = metric("assets", measured(42, "degraded", "1 window dropped frames"));
void ok;
