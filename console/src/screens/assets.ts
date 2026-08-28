/**
 * Merged asset inventory (OTS-CON-002, OTS-SRV-001).
 *
 * One row per device the estate believes exists. The merge behind it is
 * site-scoped for IPs and warns rather than fuses on a shared MAC, and both of
 * those decisions are only legible if the evidence travels with the row — which
 * collectors saw it, at which sites, and what they disagreed about.
 */

import {
  DeviceLifecycle,
  EstateApi,
  EstateAssetRow,
  LifecycleResponse,
  VulnMatch,
  VulnerabilitiesResponse,
  identityOf,
  rowCoverage,
} from "../api.js";
import { measured } from "../coverage.js";
import { cls, esc, metric, table } from "../render.js";

/**
 * Whether this device is still supported, or honestly not known to be.
 *
 * `unknown` wears the loudest badge on the row, and that is deliberate: a
 * device with no lifecycle record has not been assessed, and rendering that
 * quietly — or worse, as supported — is the same failure as an unassessed
 * asset reported clean.
 */
function lifecycleChip(item: DeviceLifecycle | undefined): string {
  if (item === undefined) return "&mdash;";
  const tone =
    item.status === "supported" ? "ok"
      : item.status === "end_of_sale" ? "warn"
        : item.status === "unidentified" ? "warn" : "alarm";
  const label = item.status.replace(/_/g, " ");
  const title = item.reason
    + (item.bearing_on_findings ? " — " + item.bearing_on_findings : "");
  return `<span class="${cls("chip", "chip-" + tone)}" title="${esc(title)}">`
    + `${esc(label)}</span>`;
}

/**
 * What the device says it is.
 *
 * An empty cell is NOT the same as an unidentified device, and the title says
 * which it is. An FRTU speaking only IEC 60870-5-104 can never report a model
 * or a firmware version — that protocol carries no identification service — so
 * a blank there is a limit of what is knowable passively, not a gap in the
 * scan. Rendering both as "—" with no explanation would put the two on the
 * same footing.
 */
function identity(row: EstateAssetRow): string {
  const id = identityOf(row);
  const parts = [id.make, id.model].filter((x) => x).join(" ");
  if (!parts) {
    return `<span class="${cls("chip", "chip-warn")}" title="No passive source`
      + ` named this device. IEC 60870-5-104 carries no identification service,`
      + ` so a 104-only RTU cannot report a make or model however long it is`
      + ` watched. LLDP, SNMP sysDescr or MMS Identify would answer it.">`
      + `unidentified</span>`;
  }
  // Built per branch rather than by interpolating a prepared fragment: a
  // markup string spliced into markup is unsafe by inspection even when its
  // contents were escaped, and the console's own guard refuses it.
  if (!id.identifiedBy) return `<span>${esc(parts)}</span>`;
  return `<span title="identified by ${esc(id.identifiedBy)}">`
    + `${esc(parts)}</span>`;
}

/**
 * The OS and its version, with the evidence attached.
 *
 * A version with no provenance is a claim. The title names the source, so an
 * operator deciding whether to act on a CVE match can tell a parsed
 * advertisement from an inference.
 */
function osCell(row: EstateAssetRow): string {
  const id = identityOf(row);
  if (!id.osVersion) return "&mdash;";
  const label = id.osName ? `${id.osName} ${id.osVersion}` : id.osVersion;
  const via = id.identifiedBy ? ` (${id.identifiedBy})` : "";
  return `<span title="${esc(label + via)}">${esc(label)}</span>`;
}

/**
 * Vulnerabilities on this device, in the three states the matcher has.
 *
 * `unknown` is not zero and must not look like it. A device with no corpus
 * entry, or one the estate could not identify well enough to look up, has not
 * been assessed — and an unassessed device rendered as clean is the mistake
 * this system has already made once, in code that had tests.
 */
function vulnCell(match: VulnMatch | undefined): string {
  if (match === undefined) {
    return `<span class="${cls("chip", "chip-warn")}" title="This device was`
      + ` not assessed against the CVE corpus.">unknown</span>`;
  }
  if (match.state === "unknown") {
    return `<span class="${cls("chip", "chip-warn")}" `
      + `title="${esc(match.note)}">unknown</span>`;
  }
  if (match.state === "clean" || !match.hits.length) {
    return `<span class="${cls("chip", "chip-ok")}" `
      + `title="${esc(match.note)}">none</span>`;
  }
  const kev = match.hits.filter((h) => h.kev).length;
  const tone = match.priority === "now" ? "alarm"
    : match.priority === "next" ? "warn" : "ok";
  const label = `${match.hits.length}${kev ? ` (${kev} KEV)` : ""}`;
  return `<span class="${cls("chip", "chip-" + tone)}" `
    + `title="${esc(match.hits.map((h) => h.cve).join(", "))}">`
    + `${esc(label)}</span>`;
}

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
  const [inventory, coverage, lifecycle, vulns]:
    [Awaited<ReturnType<EstateApi["inventory"]>>,
     Awaited<ReturnType<EstateApi["coverage"]>>,
     LifecycleResponse,
     VulnerabilitiesResponse] = await Promise.all([
       api.inventory(),
       api.coverage(),
       api.lifecycle(),
       api.vulnerabilities(),
     ]);

  const byId = new Map(lifecycle.devices.map((d) => [d.estate_id, d]));
  const vulnById = new Map(vulns.matches.map((m) => [m.estate_id, m]));

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
      { header: "make / model", cell: (r) => identity(r) },
      { header: "os version", cell: (r) => osCell(r) },
      // The station address, not the IP: an FRTU keeps its IEC 104 common
      // address across a re-addressing, and that is what appears on the SCADA
      // mimic an operator is looking at while they read this screen.
      { header: "asset id", cell: (r) => esc(identityOf(r).assetIdentifier || "—") },
      { header: "vulns", cell: (r) => vulnCell(vulnById.get(r.estate_id)) },
      { header: "lifecycle", cell: (r) => lifecycleChip(byId.get(r.estate_id)) },
      { header: "seen by", cell: (r) => esc(r.seen_by), numeric: true },
      { header: "last seen", cell: (r) => esc(when(r.last_seen)) },
      { header: "notes", cell: (r) => warnings(r) },
    ],
    inventory.assets.map((row) => ({ row, ...rowCoverage(row) })),
  );

  // A truncated inventory must not render as an inventory. This is the
  // QUERY's completeness, which `coverage` cannot speak to: at 100 collectors
  // every collector can be healthy while the console is handed a fraction of
  // the estate.
  const truncated = inventory.read && !inventory.read.complete
    ? `<div class="${cls("panel", "panel-alarm")}">`
      + `<h2>This is not the whole inventory</h2>`
      + `<p>${esc(inventory.read.explain)}</p></div>`
    : "";

  return [
    `<h1>Assets</h1>`,
    truncated,
    `<div class="metrics">`,
    metric("merged assets", total),
    metric("past end of support",
      measured(lifecycle.summary.unsupported.length,
        lifecycle.summary.records_loaded ? "complete" : "unknown",
        lifecycle.summary.explain)),
    `</div>`,
    `<p class="note">${esc(lifecycle.summary.explain)}</p>`,
    `<p class="note">IP identities are scoped to a site and MAC identities are`,
    ` reported rather than merged across sites. The same private address at two`,
    ` plants stays two devices, because fusing them is invisible afterwards and`,
    ` cannot be undone.</p>`,
    rows,
  ].join("\n");
}
