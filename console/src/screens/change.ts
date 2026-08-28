/**
 * Change view — drift, and what stopped being observed
 * (OTS-CON-006, OTS-SRV-005).
 *
 * A passive sensor cannot tell a decommissioned device from one that did not
 * speak, so this screen never says a device was removed. It says the device was
 * not observed and leaves the row in place: dropping it would make a quiet PLC
 * vanish from the inventory, which is the inverse of what an operator needs and
 * is unrecoverable once done.
 */

import {
  AnalysisResponse,
  AssetsResponse,
  CollectorAssetRow,
  EstateApi,
  engineCoverage,
} from "../api.js";
import { Coverage, Measured, measured } from "../coverage.js";
import { assetState, engineRow, esc, metric, table } from "../render.js";

function rowCoverage(row: CollectorAssetRow): {
  coverage: Coverage;
  basis: string;
} {
  return {
    coverage: row.last_coverage,
    basis:
      row.collector_id +
      ", last observed in window " +
      (row.last_observed_window || "—"),
  };
}

/**
 * Drift is reported through its engine result rather than as a number.
 *
 * Without a baseline the engine is SKIPPED, and the screen shows that instead
 * of an empty change list: "nothing changed" computed against no baseline is
 * the most confident wrong answer available here.
 */
function drift(analysis: AnalysisResponse): string {
  const engine = analysis.engines.find((e) => e.engine === "drift");
  if (!engine) {
    return '<p class="note">The drift engine did not report at all.</p>';
  }
  return engineRow(engine);
}

function driftMetric(analysis: AnalysisResponse): Measured<number> {
  const engine = analysis.engines.find((e) => e.engine === "drift");
  if (!engine) {
    return measured(0, "unknown", "the drift engine did not report");
  }
  const { coverage, basis } = engineCoverage(engine);
  return measured(engine.status === "ran" ? 1 : 0, coverage, basis);
}

export async function render(api: EstateApi): Promise<string> {
  const [assets, analysis]: [AssetsResponse, AnalysisResponse] =
    await Promise.all([api.assets(), api.analysis()]);

  const absent = assets.assets.filter((a) => a.state === "not_observed");

  // What this count rests on is the latest window having been measured at all.
  // If the newest window's coverage is unknown, "3 went quiet" may be "3 we
  // failed to hear", and those are not the same report.
  const worst: Coverage = assets.assets.some(
    (a) => a.last_coverage === "unknown",
  )
    ? "unknown"
    : assets.assets.some((a) => a.last_coverage === "degraded")
      ? "degraded"
      : "complete";
  const basis = "compared against window " + (assets.latest_window || "—");

  const rows = table<CollectorAssetRow>(
    [
      { header: "asset", cell: (r) => esc(r.asset_key) },
      { header: "collector", cell: (r) => esc(r.collector_id) },
      { header: "state", cell: (r) => assetState(r.state) },
      { header: "last window", cell: (r) => esc(r.last_observed_window || "—") },
      {
        header: "observations",
        cell: (r) => esc(r.observation_count),
        numeric: true,
      },
    ],
    absent.map((row) => ({ row, ...rowCoverage(row) })),
  );

  return [
    "<h1>Change</h1>",
    '<div class="metrics">',
    metric(
      "assets not observed in the latest window",
      measured(absent.length, worst, basis),
    ),
    metric("drift baselines available", driftMetric(analysis)),
    "</div>",
    "<h2>Configuration drift</h2>",
    drift(analysis),
    "<h2>Stopped being observed</h2>",
    '<p class="note">Absent from the latest window is a state, not a deletion.',
    " A passive sensor cannot distinguish a decommissioned device from one that",
    " did not speak, so these rows stay in the inventory.</p>",
    rows,
  ].join("");
}
