/**
 * Coverage as a type, not a convention (OTS-CON-004).
 *
 * The requirement says every screen presenting counts or clean states must
 * display the coverage those numbers rest on, and that a degraded window must be
 * visibly marked rather than footnoted.
 *
 * A rule like that, enforced by review, survives about three sprints. Someone
 * adds a summary tile in a hurry, the number renders alone, and it looks exactly
 * like every other number on the page — which is the failure the collector, the
 * spool and the estate merge have all been built to prevent, arriving at the
 * last step where a person actually reads it.
 *
 * So it is enforced by the compiler instead. A bare `number` cannot be rendered.
 * Only a `Measured<T>` can, and a `Measured<T>` cannot be constructed without
 * saying what it was derived from. Forgetting is a build failure, not a
 * discrepancy someone might notice in review.
 */

/** What the collector said about the window a number came from. */
export type Coverage = "complete" | "degraded" | "unknown";

/**
 * A value together with the coverage it rests on.
 *
 * The brand makes this genuinely unforgeable: an object literal that happens to
 * have `value` and `coverage` is not a `Measured`, so the only way to obtain one
 * is `measured()`, which is where the accompanying explanation is demanded.
 */
export type Measured<T> = {
  readonly value: T;
  readonly coverage: Coverage;
  /** Why this coverage — shown to the operator, never elided. */
  readonly basis: string;
  readonly __measured: unique symbol;
};

/** The only way to make a Measured. */
export function measured<T>(
  value: T,
  coverage: Coverage,
  basis: string,
): Measured<T> {
  if (!basis.trim()) {
    // A blank basis would satisfy the type and defeat the point: the operator
    // would see a coverage badge with nothing behind it.
    throw new Error(
      "a measured value needs a basis — the badge is meaningless without one",
    );
  }
  return { value, coverage, basis } as Measured<T>;
}

/**
 * Only `complete` may be presented as a clean result.
 *
 * `unknown` is deliberately grouped with `degraded` rather than with
 * `complete`: a collector that could not measure its own packet loss has not
 * established that there was none.
 */
export function isTrustworthy(coverage: Coverage): boolean {
  return coverage === "complete";
}

export interface CoverageBadge {
  readonly label: string;
  readonly tone: "ok" | "warn" | "alarm";
  readonly title: string;
}

/**
 * How a coverage state appears. `unknown` is an ALARM, not a neutral grey:
 * "we could not tell" is the state most likely to be mistaken for "fine", and
 * making it quiet on screen would restore exactly the ambiguity the three-state
 * model exists to remove.
 *
 * The LABEL and the TITLE both state the consequence and leave the cause to
 * `basis`. That took two goes to get right, and both mistakes were the same
 * mistake.
 *
 * The title used to name a mechanism — "frames were lost", "capture loss could
 * not be measured" — which was true when every coverage state came from a
 * capture window and became false the moment they did not.
 *
 * The label then did it again, more quietly. "not measured" reads correctly
 * over a capture window and wrongly over everything else `unknown` now covers:
 * a revoked certificate was measured perfectly well and is simply not valid; a
 * skipped engine never ran; an unassessed vulnerability had no corpus to assess
 * against; a silent collector's reading is stale rather than absent. The chip
 * asserted a cause the basis beside it contradicted — on a table row, where the
 * label is read and the tooltip is not.
 *
 * So the label is now cause-free. Every `unknown` means one thing regardless of
 * how it arose: this has not been established as clean. The basis says why, and
 * `measured()` refuses to build a value without one.
 *
 * It stays an ALARM tone. "Unconfirmed" must not look restful — that is the
 * state most likely to be mistaken for fine, and making it quiet on screen
 * would restore exactly the ambiguity the three-state model removes.
 */
export function badge(coverage: Coverage, basis: string): CoverageBadge {
  switch (coverage) {
    case "complete":
      return { label: "complete", tone: "ok", title: basis };
    case "degraded":
      return {
        label: "degraded",
        tone: "warn",
        title: `${basis} — something in this chain was incomplete, so treat this as a floor rather than a total`,
      };
    case "unknown":
      return {
        label: "unconfirmed",
        tone: "alarm",
        title: `${basis} — this has not been established as clean`,
      };
  }
}

/**
 * The weakest coverage across several inputs.
 *
 * An estate figure built from four healthy collectors and one blind one is not
 * mostly-trustworthy; it is an answer with a hole in it. Averaging would let a
 * healthy collector launder a blind one's silence.
 */
export function weakest(states: readonly Coverage[]): Coverage {
  if (states.length === 0 || states.includes("unknown")) return "unknown";
  if (states.includes("degraded")) return "degraded";
  return "complete";
}

/**
 * Combine measured values, carrying the weakest coverage and both bases.
 * There is deliberately no way to combine them and keep the better coverage.
 */
export function combine<T>(
  parts: readonly Measured<unknown>[],
  value: T,
): Measured<T> {
  const coverage = weakest(parts.map((p) => p.coverage));
  const bases = Array.from(new Set(parts.map((p) => p.basis)));
  return measured(value, coverage, bases.join("; ") || "no inputs");
}

/**
 * The phrase used wherever a zero is shown.
 *
 * "0 findings" and "no findings were observable" are different claims, and on a
 * substation network the difference is the whole product.
 */
export function describeZero(coverage: Coverage): string {
  return isTrustworthy(coverage)
    ? "none found"
    : "none found — but coverage was incomplete, so this is not evidence of absence";
}
