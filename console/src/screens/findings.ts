/**
 * Findings — vulnerability matches and the analysis engines
 * (OTS-CON-003, OTS-SRV-002, OTS-SRV-003).
 *
 * Two kinds of claim share this screen, and both fail in the same direction if
 * rendered carelessly: a match list that is empty because nothing matched looks
 * identical to one that is empty because no corpus was loaded, and an engine
 * that ran on partial inputs looks identical to one that ran on complete ones.
 * Neither is allowed to be silent here.
 */

import {
  AnalysisResponse,
  EngineResultRow,
  EstateApi,
  VulnMatch,
  engineCoverage,
} from "../api.js";
import { Coverage, Measured, measured, weakest } from "../coverage.js";
import { cls, engineRow, esc, fragments, metric, table } from "../render.js";

/** Engines that answer "what is wrong now". Drift belongs to the change view. */
const HERE = ["compliance", "risk", "attack_paths", "policy"];

/**
 * A match's coverage is the OBSERVATION's coverage, not the corpus's.
 *
 * A device seen through a degraded window may be running software nobody saw,
 * so `clean` against it is a statement about what was observed rather than
 * about the device.
 */
function matchCoverage(m: VulnMatch): { coverage: Coverage; basis: string } {
  if (m.state === "unknown") {
    return { coverage: "unknown", basis: m.note || "not assessed" };
  }
  return {
    coverage: m.observation_coverage,
    basis: m.note || `corpus ${m.corpus_version}`,
  };
}

function priorityChip(m: VulnMatch): string {
  const tone =
    m.priority === "now" ? "alarm" : m.priority === "next" ? "warn" : "ok";
  const title =
    m.priority === "now"
      ? "known exploited — an observation, not a forecast"
      : m.priority === "next"
        ? "elevated probability, but a probability rather than an observation"
        : m.priority === "unknown"
          ? "nothing has been assessed against this asset"
          : "no action indicated by the current corpus";
  return `<span class="${cls("chip", "chip-" + tone)}" title="${esc(title)}">${esc(m.priority)}</span>`;
}

function hits(m: VulnMatch): string {
  if (!m.hits.length) return "—";
  const items = m.hits.map(
    (h) =>
      `<li><code>${esc(h.cve)}</code>` +
      (h.kev ? ` <span class="chip chip-alarm">KEV</span>` : "") +
      ` <span class="hit-why">${esc(h.why)}</span></li>`,
  );
  return `<ul class="hit-list">${fragments(items)}</ul>`;
}

function engines(analysis: AnalysisResponse): string {
  const shown = analysis.engines.filter((e) => HERE.includes(e.engine));
  if (!shown.length) {
    return `<p class="note">No analysis engine reported.</p>`;
  }
  return shown.map((e: EngineResultRow) => engineRow(e)).join("");
}

/**
 * How many engines answered without qualification — and what that count rests
 * on.
 *
 * The weakest engine's coverage, never an average: three clean engines beside
 * one that was skipped do not make the picture three-quarters trustworthy, and
 * a bare "3 of 4" is exactly the tile OTS-CON-004 exists to make impossible.
 */
function enginesClean(analysis: AnalysisResponse): Measured<number> {
  const shown = analysis.engines.filter((e) => HERE.includes(e.engine));
  const states = shown.map((e) => engineCoverage(e));
  const bases = states.map((s) => s.basis).filter((b) => b.length > 0);
  return measured(
    shown.filter((e) => e.trustworthy).length,
    weakest(states.map((s) => s.coverage)),
    bases.join("; ") || "no engine reported",
  );
}

export async function render(api: EstateApi): Promise<string> {
  const [vulns, analysis] = await Promise.all([
    api.vulnerabilities(),
    api.analysis(),
  ]);

  // Without a corpus this is not zero, it is unknown: a server that has not
  // looked has established nothing.
  const assessedState: Coverage = vulns.corpus_loaded ? "complete" : "unknown";
  const assessedBasis = vulns.corpus_loaded
    ? `corpus ${vulns.corpus_version}`
    : "no vulnerability corpus is loaded, so nothing has been assessed";

  const rows = table<VulnMatch>(
    [
      { header: "asset", cell: (r) => esc(r.estate_id) },
      { header: "state", cell: (r) => esc(r.state) },
      { header: "priority", cell: (r) => priorityChip(r) },
      { header: "matches", cell: (r) => hits(r) },
    ],
    vulns.matches.map((row) => ({ row, ...matchCoverage(row) })),
  );

  // A detection whose asset row never arrived means the estate holds findings
  // for a device it cannot show. Louder than a footnote, because the asset
  // count below is then missing at least one device.
  const orphans = analysis.orphaned_detections
    ? `<div class="panel panel-alarm"><strong>${esc(analysis.orphaned_detections)}` +
      ` detection(s) name an asset the inventory does not hold.</strong>` +
      ` The estate has findings for a device it cannot show.</div>`
    : "";

  return [
    `<h1>Findings</h1>`,
    orphans,
    `<div class="metrics">`,
    metric("assets assessed", measured(vulns.assessed, assessedState, assessedBasis)),
    metric("actionable", measured(vulns.actionable, assessedState, assessedBasis)),
    `</div>`,
    `<p class="note">Priority <code>now</code> means known-exploited. High EPSS`,
    ` alone is <code>next</code>, because EPSS is a probability rather than an`,
    ` observation and a priority that fires on everything is one an operator`,
    ` stops reading.</p>`,
    rows,
    `<h2>Analysis engines</h2>`,
    `<div class="metrics">`,
    metric("engines answering without qualification", enginesClean(analysis)),
    `</div>`,
    `<p class="note">${esc(analysis.fidelity.explain)}</p>`,
    engines(analysis),
  ].join("");
}
