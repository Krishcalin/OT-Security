/**
 * Estate API client (OTS-CON-001..006).
 *
 * Every count the server returns is converted into a `Measured` at the boundary,
 * with the basis taken from the server's own coverage explanation. That is the
 * one place a raw number is allowed to exist: past this module nothing can put a
 * figure on screen without saying what it rests on.
 */

import { Coverage, Measured, measured, weakest } from "./coverage.js";

export interface CollectorCoverage {
  collector_id: string;
  windows: number;
  complete: number;
  degraded: number;
  unknown: number;
  delivery_gaps: number;
  records_lost: number;
  trustworthy: boolean;
}

export interface EstateCoverageResponse {
  collectors: number;
  trustworthy_collectors: number;
  blind_collectors: string[];
  degraded_collectors: string[];
  collectors_with_gaps: string[];
  trustworthy: boolean;
  explain: string;
  per_collector: CollectorCoverage[];
}

export interface EstateAssetRow {
  estate_id: string;
  site: string;
  ip: string;
  mac: string;
  first_seen: number | null;
  last_seen: number | null;
  observation_count: number;
  collectors: string[];
  sites: string[];
  seen_by: number;
  coverage: Coverage;
  attributes: Record<string, unknown>;
  warnings: string[];
}

export interface InventoryResponse {
  assets: EstateAssetRow[];
  count: number;
  coverage: { trustworthy: boolean; explain: string };
}

export interface VulnMatch {
  estate_id: string;
  state: "matched" | "clean" | "unknown";
  priority: "now" | "next" | "never" | "unknown";
  corpus_version: string;
  observation_coverage: Coverage;
  note: string;
  hits: { cve: string; kev: boolean; priority: string; why: string }[];
}

export interface VulnerabilitiesResponse {
  corpus_version: string;
  corpus_loaded: boolean;
  assessed: number;
  actionable: number;
  matches: VulnMatch[];
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export class EstateApi {
  constructor(private readonly base: string = "") {}

  private async get<T>(path: string): Promise<T> {
    const response = await fetch(`${this.base}${path}`, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    });
    if (response.status === 503) {
      // The estate plane is fail-closed until operator auth is wired
      // (OTS-SRV-006). Surfaced as itself rather than as an empty result, which
      // would render as a clean, empty estate.
      throw new ApiError(
        "the estate API is not yet configured for operator access",
        503,
      );
    }
    if (!response.ok) {
      throw new ApiError(`request failed`, response.status);
    }
    return (await response.json()) as T;
  }

  coverage(): Promise<EstateCoverageResponse> {
    return this.get("/api/v1/estate/coverage");
  }

  inventory(): Promise<InventoryResponse> {
    return this.get("/api/v1/estate/inventory");
  }

  vulnerabilities(): Promise<VulnerabilitiesResponse> {
    return this.get("/api/v1/estate/vulnerabilities");
  }
}

/**
 * The boundary where raw server numbers become measurable ones.
 *
 * Beyond this function the console cannot render a figure without its coverage,
 * because nothing else can construct a `Measured`.
 */
export function estateMetrics(
  inventory: InventoryResponse,
  coverage: EstateCoverageResponse,
  vulns: VulnerabilitiesResponse,
): {
  assets: Measured<number>;
  actionable: Measured<number>;
  collectors: Measured<number>;
} {
  const state: Coverage = coverage.trustworthy
    ? "complete"
    : coverage.blind_collectors.length
      ? "unknown"
      : "degraded";
  const basis = coverage.explain;

  return {
    assets: measured(inventory.count, state, basis),
    // If no corpus is loaded the actionable count is not zero, it is unknown —
    // a server that has not looked has established nothing.
    actionable: measured(
      vulns.actionable,
      vulns.corpus_loaded ? state : "unknown",
      vulns.corpus_loaded
        ? `${basis}; corpus ${vulns.corpus_version}`
        : "no vulnerability corpus is loaded, so nothing has been assessed",
    ),
    collectors: measured(coverage.collectors, state, basis),
  };
}

/** Coverage for one merged asset row: its own, never the estate's. */
export function rowCoverage(row: EstateAssetRow): {
  coverage: Coverage;
  basis: string;
} {
  const basis =
    row.seen_by > 1
      ? `seen by ${row.seen_by} collectors (${row.collectors.join(", ")})`
      : `seen by ${row.collectors[0] ?? "no collector"}`;
  return { coverage: weakest([row.coverage]), basis };
}
