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

/** One collector's own view of an asset, before the estate merge (OTS-SRV-005). */
export interface CollectorAssetRow {
  asset_key: string;
  collector_id: string;
  first_seen: number | null;
  last_seen: number | null;
  observation_count: number;
  last_observed_window: string;
  last_coverage: Coverage;
  attributes: Record<string, unknown>;
  /** Absence is a state, never a deletion. */
  state: "observed" | "not_observed";
}

export interface AssetsResponse {
  assets: CollectorAssetRow[];
  latest_window: string;
  count: number;
}

/** One engine's result from OTS-SRV-003, carrying what it could not consider. */
export interface EngineResultRow {
  engine: string;
  status: "ran" | "degraded" | "skipped" | "error";
  reason: string;
  limitations: string[];
  trustworthy: boolean;
}

export interface AnalysisResponse {
  fidelity: { shipped: number; total: number; explain: string };
  /** The estate coverage these engine results were computed over. */
  coverage: string;
  /** How the Purdue levels underneath them were arrived at — or were not. */
  zones: string;
  engines: EngineResultRow[];
  skipped: string[];
  /** Detections whose asset row never arrived: a hole, not a rounding error. */
  orphaned_detections: number;
}

export interface ZoneRow {
  zone_id: string;
  subnet: string;
  purdue_level: number;
  purdue_label: string;
  device_count: number;
  dominant_role: string;
  /** role | protocol | defaulted — a guessed level must not read as an observed one. */
  level_basis: string;
}

export interface SiteTopologyRow {
  site: string;
  zones: ZoneRow[];
  violations: number;
  edges: number;
  confidence: {
    zones: number;
    defaulted: number;
    usable: boolean;
    explain: string;
  };
}

export interface ZonesResponse {
  sites: SiteTopologyRow[];
  zones: number;
  defaulted: number;
  usable: boolean;
  explain: string;
  /**
   * `none` and `rejected` both draw an empty topology and are NOT the same
   * claim: one had nothing to derive from, the other derived something and did
   * not trust it. The screen must say which.
   */
  state: "none" | "derived" | "rejected";
}

/** One issued certificate, as the lifecycle endpoint reports it. */
export interface CertificateRow {
  serial: string;
  collector_id: string;
  subject: string;
  fingerprint: string;
  not_before: string;
  not_after: string;
  revoked: boolean;
  revocation_reason: string;
  state: "valid" | "revoked" | "expired";
  expiring_soon: boolean;
}

export interface CertificatesResponse {
  certificates: CertificateRow[];
  count: number;
  /**
   * Without a CA there is no issuance record, so no identity is verifiable and
   * revocation does not exist. An empty list then means "we cannot tell you",
   * not "this fleet holds nothing".
   */
  ca_configured: boolean;
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

  /** Per-collector asset rows, which carry observed / not-observed. */
  assets(): Promise<AssetsResponse> {
    return this.get("/api/v1/estate/assets");
  }

  analysis(): Promise<AnalysisResponse> {
    return this.get("/api/v1/estate/analysis");
  }

  zones(): Promise<ZonesResponse> {
    return this.get("/api/v1/estate/zones");
  }

  certificates(): Promise<CertificatesResponse> {
    return this.get("/api/v1/estate/certificates");
  }
}

/**
 * The coverage an engine result rests on.
 *
 * An engine is only `complete` when it RAN with nothing missing. `degraded` and
 * `skipped` are not the same failure, but both mean the answer is qualified —
 * and `skipped` is `unknown` rather than `degraded`, because an engine that did
 * not run has established nothing at all.
 */
export function engineCoverage(engine: EngineResultRow): {
  coverage: Coverage;
  basis: string;
} {
  if (engine.status === "ran" && engine.trustworthy) {
    return { coverage: "complete", basis: engine.reason || "ran with every input it wanted" };
  }
  if (engine.status === "skipped" || engine.status === "error") {
    return { coverage: "unknown", basis: engine.reason || "did not run" };
  }
  return {
    coverage: "degraded",
    basis: engine.limitations.join("; ") || engine.reason || "ran without some inputs",
  };
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
