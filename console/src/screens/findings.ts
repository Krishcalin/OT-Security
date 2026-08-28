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
  ContainmentPlan,
  Correction,
  EngineResultRow,
  EstateApi,
  VulnMatch,
  engineCoverage,
} from "../api.js";
import { Coverage, Measured, measured, weakest } from "../coverage.js";
import { cls, engineRow, esc, fragments, metric, table } from "../render.js";

/**
 * What to do about a finding nobody is going to patch.
 *
 * "Patch it" is advice an operator has already discounted before they finish
 * reading it — the device is a relay and the fix needs an outage. So each
 * finding carries the segmentation change that would contain it instead.
 *
 * The two refusals are rendered as loudly as the rule, because they are the
 * more important half: a rule built on a guessed boundary might be applied to
 * a live plant, and an allow-list for a device nothing has been observed
 * talking to is a list somebody invented.
 */
function containment(plan: ContainmentPlan | null): string {
  if (plan === null) return "";

  if (plan.state === "refused") {
    return [
      '<div class="panel panel-alarm">',
      "  <h3>No containment offered</h3>",
      '  <p class="note">' + esc(plan.reason) + "</p>",
      "</div>",
    ].join("");
  }
  if (plan.state === "unknown") {
    return [
      '<div class="panel panel-warn">',
      "  <h3>Nothing to build a rule from</h3>",
      '  <p class="note">' + esc(plan.reason) + "</p>",
      "</div>",
    ].join("");
  }

  const rules = plan.rules.map((rule) => [
    "<li>",
    '<span class="' + cls("chip", rule.action === "deny" ? "chip-alarm" : "chip-ok")
      + '">' + esc(rule.action) + "</span> ",
    "<code>" + esc(rule.src_ip) + " &rarr; " + esc(rule.dst_ip),
    rule.port ? esc(" " + rule.protocol + "/" + rule.port) : esc(" any"),
    "</code>",
    '<div class="hit-why">' + esc(rule.rationale) + "</div>",
    "</li>",
  ].join(""));

  return [
    '<div class="panel">',
    "  <h3>Containment &mdash; zone " + esc(plan.zone_id)
      + " (Purdue " + esc(plan.purdue_level) + ", level from "
      + esc(plan.zone_basis) + ")</h3>",
    '  <p class="note">' + esc(plan.reason) + "</p>",
    '  <ol class="recovery-list">' + fragments(rules) + "</ol>",
    '  <p class="note"><strong>Before you apply this:</strong> '
      + esc(plan.caveat) + "</p>",
    "</div>",
  ].join("");
}

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

function containmentChip(m: VulnMatch): string {
  const plan = m.containment;
  if (plan === null) return "&mdash;";
  const tone = plan.state === "proposed" ? "ok"
    : plan.state === "refused" ? "alarm" : "warn";
  return '<span class="' + cls("chip", "chip-" + tone) + '" title="'
    + esc(plan.reason) + '">' + esc(plan.state) + "</span>";
}

/**
 * How a correction reads on the row.
 *
 * A WITHHELD correction is rendered as loudly as an applied one and never as
 * nothing. It means a lowering was justified by what was observed and refused
 * by the coverage behind it — which is a statement about this estate's
 * monitoring, and the operator should see that the tool declined rather than
 * that it had nothing to say.
 */
function correctionNote(correction: Correction | undefined): string {
  if (!correction) return "";
  if (correction.state === "withheld") {
    return ` <span class="${cls("chip", "chip-warn")}" title="${esc(correction.reason)}">`
      + `withheld</span>`;
  }
  if (correction.state === "applied") {
    const tone = correction.direction === "raised" ? "alarm" : "ok";
    return ` <span class="${cls("chip", "chip-" + tone)}" title="${esc(correction.reason)}">`
      + `${esc(correction.original)} &rarr; ${esc(correction.corrected)}</span>`;
  }
  if (correction.state === "refused") {
    return ` <span class="${cls("chip", "chip-alarm")}" title="${esc(correction.reason)}">`
      + `not corrected</span>`;
  }
  return "";
}

function hits(m: VulnMatch): string {
  if (!m.hits.length) return "—";
  const items = m.hits.map(
    (h) =>
      `<li><code>${esc(h.cve)}</code>` +
      (h.kev ? ` <span class="chip chip-alarm">KEV</span>` : "") +
      correctionNote(h.correction) +
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
      { header: "containment", cell: (r) => containmentChip(r) },
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
    `<h2>Corrected for where each device sits</h2>`,
    `<p class="note">${esc(vulns.correction.explain)}</p>`,
    `<p class="note">A correction that would <em>lower</em> urgency needs a`,
    ` complete window behind it: not seeing a path into a device is not`,
    ` evidence there is none, and lowering on a degraded window would`,
    ` de-escalate a genuinely exposed relay because a collector dropped`,
    ` frames. One that <em>raises</em> urgency does not wait \u2014 being wrong`,
    ` upward costs attention, being wrong downward costs the finding.</p>`,
    `<h2>What to do about the ones you cannot patch</h2>`,
    `<p class="note">${esc(vulns.containment.explain)}</p>`,
    fragments(vulns.matches
      .filter((m) => m.containment !== null)
      .slice(0, 8)
      .map((m) => `<h3>${esc(m.estate_id)}</h3>` + containment(m.containment))),
    `<h2>Analysis engines</h2>`,
    `<div class="metrics">`,
    metric("engines answering without qualification", enginesClean(analysis)),
    `</div>`,
    `<p class="note">${esc(analysis.fidelity.explain)}</p>`,
    engines(analysis),
  ].join("");
}
