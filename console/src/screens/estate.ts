/**
 * Estate overview (OTS-CON-001, OTS-CON-004).
 *
 * The screen an operator looks at first, which makes it the one where an
 * unqualified number does the most damage: three headline figures and a glance
 * is how "the plant is fine" gets decided. Every figure here is a `Measured`,
 * so none of them can appear without what it rests on.
 */

import {
  CollectorCoverage,
  EstateApi,
  EstateCoverageResponse,
  estateMetrics,
} from "../api.js";
import { Coverage, measured } from "../coverage.js";
import { esc, metric, table } from "../render.js";

/**
 * One collector's coverage, on its own terms.
 *
 * Per collector rather than per estate: a healthy collector's row must not
 * inherit a blind one's badge, and a blind one's row must not be softened by
 * the four healthy ones beside it.
 */
function collectorCoverage(c: CollectorCoverage): {
  coverage: Coverage;
  basis: string;
} {
  const parts: string[] = [`${c.windows} window(s)`];
  if (c.degraded) parts.push(`${c.degraded} degraded`);
  if (c.unknown) parts.push(`${c.unknown} unmeasurable`);
  if (c.delivery_gaps) {
    parts.push(`${c.delivery_gaps} delivery gap(s), ${c.records_lost} record(s) lost`);
  }
  const basis = parts.join(", ");
  if (c.unknown > 0 || c.windows === 0) return { coverage: "unknown", basis };
  if (c.degraded > 0 || c.delivery_gaps > 0) return { coverage: "degraded", basis };
  return { coverage: "complete", basis };
}

function collectorTable(coverage: EstateCoverageResponse): string {
  return table<CollectorCoverage>(
    [
      { header: "collector", cell: (r) => esc(r.collector_id) },
      { header: "windows", cell: (r) => esc(r.windows), numeric: true },
      { header: "degraded", cell: (r) => esc(r.degraded), numeric: true },
      { header: "unmeasurable", cell: (r) => esc(r.unknown), numeric: true },
      { header: "delivery gaps", cell: (r) => esc(r.delivery_gaps), numeric: true },
      { header: "records lost", cell: (r) => esc(r.records_lost), numeric: true },
    ],
    coverage.per_collector.map((c) => ({ row: c, ...collectorCoverage(c) })),
  );
}

export async function render(api: EstateApi): Promise<string> {
  const [coverage, inventory, vulns] = await Promise.all([
    api.coverage(),
    api.inventory(),
    api.vulnerabilities(),
  ]);
  const m = estateMetrics(inventory, coverage, vulns);

  // Not `coverage.collectors - trustworthy_collectors` rendered as a bare
  // figure: the count of collectors that are NOT reporting cleanly is itself
  // only as good as the coverage data behind it.
  const notClean = measured(
    coverage.collectors - coverage.trustworthy_collectors,
    coverage.trustworthy ? "complete" : "degraded",
    coverage.explain,
  );

  return [
    `<h1>Estate</h1>`,
    `<div class="metrics">`,
    metric("assets", m.assets),
    metric("actionable findings", m.actionable),
    metric("collectors", m.collectors),
    metric("collectors not reporting cleanly", notClean),
    `</div>`,
    `<h2>Per collector</h2>`,
    `<p class="note">Estate coverage is the weakest link, never an average:`,
    ` four healthy collectors and one blind one is not 80% trustworthy, it is`,
    ` an answer with a hole in it.</p>`,
    collectorTable(coverage),
  ].join("\n");
}
