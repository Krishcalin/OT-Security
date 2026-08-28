/**
 * Merged asset inventory (OTS-CON-002, OTS-SRV-001).
 *
 * One row per device the estate believes exists. The merge behind it is
 * site-scoped for IPs and warns rather than fuses on a shared MAC, and both of
 * those decisions are only legible if the evidence travels with the row — which
 * collectors saw it, at which sites, and what they disagreed about.
 */

import { EstateApi, EstateAssetRow, rowCoverage } from "../api.js";
import { measured } from "../coverage.js";
import { esc, metric, table } from "../render.js";

function when(seconds: number | null): string {
  if (seconds === null || Number.isNaN(seconds)) return "—";
  return new Date(seconds * 1000).toISOString().replace("T", " ").slice(0, 19);
}

/**
 * Warnings are rendered in the row, not collapsed into a count.
 *
 * "This MAC appears at two sites and was NOT merged" is the sentence that
 * explains why two rows look like one device, and a badge saying `1 warning`
 * carries none of it.
 */
function warnings(row: EstateAssetRow): string {
  if (!row.warnings.length) return "";
  return `<ul class="warn-list">${row.warnings
    .map((w) => `<li>${esc(w)}</li>`)
    .join("")}</ul>`;
}

export async function render(api: EstateApi): Promise<string> {
  const [inventory, coverage] = await Promise.all([
    api.inventory(),
    api.coverage(),
  ]);

  const total = measured(
    inventory.count,
    coverage.trustworthy
      ? "complete"
      : coverage.blind_collectors.length
        ? "unknown"
        : "degraded",
    inventory.coverage.explain,
  );

  const rows = table<EstateAssetRow>(
    [
      { header: "site", cell: (r) => esc(r.site) },
      { header: "ip", cell: (r) => esc(r.ip || "—") },
      { header: "mac", cell: (r) => esc(r.mac || "—") },
      { header: "seen by", cell: (r) => esc(r.seen_by), numeric: true },
      { header: "collectors", cell: (r) => esc(r.collectors.join(", ")) },
      { header: "observations", cell: (r) => esc(r.observation_count), numeric: true },
      { header: "last seen", cell: (r) => esc(when(r.last_seen)) },
      { header: "notes", cell: (r) => warnings(r) },
    ],
    inventory.assets.map((row) => ({ row, ...rowCoverage(row) })),
  );

  return [
    `<h1>Assets</h1>`,
    `<div class="metrics">`,
    metric("merged assets", total),
    `</div>`,
    `<p class="note">IP identities are scoped to a site and MAC identities are`,
    ` reported rather than merged across sites. The same private address at two`,
    ` plants stays two devices, because fusing them is invisible afterwards and`,
    ` cannot be undone.</p>`,
    rows,
  ].join("\n");
}
