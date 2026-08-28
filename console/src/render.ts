/**
 * Rendering primitives (OTS-CON-001..006).
 *
 * Every function that puts a number on screen takes a `Measured<T>`. There is no
 * overload that accepts a bare number, which is what makes OTS-CON-004
 * structural: a developer who forgets the coverage gets a type error at build
 * time rather than a plausible-looking tile in production.
 */

import {
  Coverage,
  Measured,
  badge,
  describeZero,
  isTrustworthy,
} from "./coverage.js";

const escapes: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/**
 * Escape before interpolation. Asset names, vendor strings and rule titles all
 * originate on a scanned network, so none of them are ours to trust.
 *
 * The `?? c` is not defensive noise: with noUncheckedIndexedAccess the lookup is
 * `string | undefined`, and returning undefined would put the literal text
 * "undefined" where a character belonged.
 */
export function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (c) => escapes[c] ?? c);
}

export function coverageChip(coverage: Coverage, basis: string): string {
  const b = badge(coverage, basis);
  return (
    `<span class="chip chip-${b.tone}" title="${esc(b.title)}">` +
    `${esc(b.label)}</span>`
  );
}

/**
 * A headline number with its coverage beside it — never beneath it, never in a
 * tooltip alone. The requirement says visibly marked, not footnoted.
 */
export function metric(label: string, m: Measured<number>): string {
  const zero = m.value === 0 ? `<div class="zero">${esc(describeZero(m.coverage))}</div>` : "";
  return [
    `<div class="metric${isTrustworthy(m.coverage) ? "" : " metric-qualified"}">`,
    `  <div class="metric-label">${esc(label)}</div>`,
    `  <div class="metric-value">${esc(m.value)}</div>`,
    `  <div class="metric-cov">${coverageChip(m.coverage, m.basis)}</div>`,
    zero,
    `</div>`,
  ].join("\n");
}

export interface Column<R> {
  readonly header: string;
  readonly cell: (row: R) => string;
  readonly numeric?: boolean;
}

/**
 * A table whose rows each carry their own coverage.
 *
 * Per-row rather than per-table on purpose: one collector may be blind while
 * another is healthy, and a single banner over the whole table would either
 * overstate the good rows or understate the bad ones.
 */
export function table<R>(
  columns: readonly Column<R>[],
  rows: readonly { row: R; coverage: Coverage; basis: string }[],
): string {
  const head = columns
    .map((c) => `<th${c.numeric ? ' class="num"' : ""}>${esc(c.header)}</th>`)
    .join("");
  const body = rows
    .map(({ row, coverage, basis }) => {
      const cells = columns
        .map((c) => `<td${c.numeric ? ' class="num"' : ""}>${c.cell(row)}</td>`)
        .join("");
      return (
        `<tr class="${isTrustworthy(coverage) ? "" : "row-qualified"}">` +
        `${cells}<td>${coverageChip(coverage, basis)}</td></tr>`
      );
    })
    .join("\n");
  return `<table><thead><tr>${head}<th>coverage</th></tr></thead><tbody>${body}</tbody></table>`;
}

/**
 * The banner an estate view carries when any collector is not reporting cleanly.
 * Rendered above the content, not below it.
 */
export function estateBanner(explain: string, trustworthy: boolean): string {
  if (trustworthy) {
    return `<div class="banner banner-ok">${esc(explain)}</div>`;
  }
  return (
    `<div class="banner banner-alarm">` +
    `<strong>This view is incomplete.</strong> ${esc(explain)}</div>`
  );
}

/**
 * An asset that stopped appearing (OTS-SRV-005).
 *
 * Rendered as a state, never omitted from the list. A passive sensor cannot tell
 * a decommissioned device from one that did not speak, and dropping the row
 * would silently answer a question nobody can answer.
 */
export function assetState(state: "observed" | "not_observed"): string {
  return state === "observed"
    ? `<span class="chip chip-ok">observed</span>`
    : `<span class="chip chip-warn" title="absent from the latest window. A passive sensor cannot distinguish a decommissioned device from one that did not speak.">not observed</span>`;
}

/** Engine results from OTS-SRV-003, each showing what it could not consider. */
export function engineRow(engine: {
  engine: string;
  status: string;
  reason: string;
  limitations: string[];
}): string {
  const tone =
    engine.status === "ran"
      ? "ok"
      : engine.status === "skipped" || engine.status === "error"
        ? "alarm"
        : "warn";
  const limits = engine.limitations.length
    ? `<ul class="limits">${engine.limitations
        .map((l) => `<li>${esc(l)}</li>`)
        .join("")}</ul>`
    : "";
  return [
    `<div class="engine">`,
    `  <div class="engine-head">`,
    `    <span class="engine-name">${esc(engine.engine)}</span>`,
    `    <span class="chip chip-${tone}">${esc(engine.status)}</span>`,
    `  </div>`,
    `  <div class="engine-reason">${esc(engine.reason)}</div>`,
    `  ${limits}`,
    `</div>`,
  ].join("\n");
}
