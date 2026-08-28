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
  /**
   * Collectors that have stopped reporting. Their stored windows still read as
   * complete, which is why they are named here rather than counted.
   */
  silent_collectors?: string[];
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
  hits: {
    cve: string;
    kev: boolean;
    priority: string;
    why: string;
    corrected_priority?: string;
    correction?: Correction;
  }[];
  /** Null when nothing matched — there is nothing to contain. */
  containment: ContainmentPlan | null;
}

/** One rule in a proposed containment. */
export interface ContainmentRule {
  order: number;
  action: "allow" | "deny";
  src_ip: string;
  dst_ip: string;
  protocol: string;
  port: number;
  rationale: string;
}

/**
 * The segmentation change that would contain a finding nobody can patch.
 *
 * `state` is the field to read first. `refused` and `unknown` both mean no
 * rule, and they are not the same: one is a boundary we derived and do not
 * trust, the other is a device nothing has been observed talking to.
 */
export interface ContainmentPlan {
  estate_id: string;
  site: string;
  zone_id: string;
  purdue_level: number;
  zone_basis: string;
  state: "proposed" | "refused" | "unknown";
  reason: string;
  allow: {
    src_ip: string;
    src_zone: string;
    protocol: string;
    port: number;
    crosses_zone: boolean;
  }[];
  rules: ContainmentRule[];
  /** What the allow-list rests on, and what it cannot see. Always present. */
  caveat: string;
}

/**
 * One CVE's priority, corrected for where the device sits.
 *
 * `state` matters more than `corrected`. A `withheld` correction did not move
 * the priority and is not the same as one that had nothing to say: it means a
 * lowering was justified by the observations and refused by the coverage.
 */
export interface Correction {
  cve: string;
  original: string;
  corrected: string;
  state: "applied" | "refused" | "withheld" | "unchanged";
  direction: "raised" | "lowered" | "unchanged";
  basis: string[];
  reason: string;
}

export interface CorrectionSummary {
  raised: number;
  lowered: number;
  withheld: number;
  refused: number;
  explain: string;
}

export interface ContainmentSummary {
  proposed: number;
  refused: number;
  unknown: number;
  explain: string;
}

export interface VulnerabilitiesResponse {
  corpus_version: string;
  corpus_loaded: boolean;
  assessed: number;
  actionable: number;
  matches: VulnMatch[];
  containment: ContainmentSummary;
  correction: CorrectionSummary;
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

/** Who is signed in, from `/api/v1/auth/me`. */
export interface MeResponse {
  authenticated: boolean;
  username?: string;
  display_name?: string;
  totp_enabled?: boolean;
  expires_at?: string;
}

export interface TotpStatus {
  enabled: boolean;
  pending: boolean;
  issuer: string;
}

export interface TotpEnrolment {
  secret: string;
  formatted_secret: string;
  provisioning_uri: string;
  /** An SVG produced by this server's own encoder from the URI above. */
  qr_svg: string;
  issuer: string;
  digits: number;
  period: number;
}

export interface TotpConfirmed {
  enabled: boolean;
  /** Shown once. Stored only as hashes, so there is no second chance. */
  recovery_codes: string[];
  detail: string;
}

/** One published content pack. */
export interface PackRow {
  kind: string;
  version: number;
  created_at: string;
  digest: string;
  published_by: string;
  summary: string;
}

/**
 * Which collectors are running which pack.
 *
 * `unknown` is separate from `behind` on purpose: "has not told us" and "is
 * running an old version" are different states, and only one of them is a
 * collector to go and look at.
 */
export interface PackDrift {
  latest: number;
  current: string[];
  behind: { collector_id: string; version: number; behind_by: number }[];
  unknown: string[];
  all_current: boolean;
  explain: string;
}

export interface PacksResponse {
  packs: PackRow[];
  signing_configured: boolean;
  drift: PackDrift;
}

/** Something a person can go and do about one collector. */
export interface FleetAlarm {
  collector_id: string;
  kind: string;
  severity: "info" | "warning" | "critical";
  detail: string;
  action: string;
}

export interface CollectorHealthRow {
  collector_id: string;
  site: string;
  state: "reporting" | "late" | "silent" | "never_reported" | "disabled";
  seconds_since_heartbeat: number | null;
  capture_state: string;
  queue_depth: number;
  /**
   * False when this collector's STORED coverage must not be counted. A silent
   * collector's fifty complete windows describe last week.
   */
  coverage_believable: boolean;
  alarms: FleetAlarm[];
}

export interface FleetHealthResponse {
  collectors: CollectorHealthRow[];
  alarms: FleetAlarm[];
  silent: string[];
  never_reported: string[];
  coverage_not_believable: string[];
  healthy: boolean;
  explain: string;
}

/** One end of an observed conversation, resolved to a device where possible. */
export interface CommsEndpoint {
  ip: string;
  estate_id: string;
  label: string;
  zone_id: string;
  purdue_level: number;
  zone_basis: string;
  /** True when this address talked and the inventory holds no device for it. */
  unknown_device: boolean;
}

export interface Conversation {
  site: string;
  protocol: string;
  port: number;
  packets: number;
  src: CommsEndpoint;
  dst: CommsEndpoint;
  /**
   * `undetermined` is not `lateral`. One says the two Purdue levels are equal,
   * the other says at least one of them was never derived.
   */
  direction: "downstream" | "upstream" | "lateral" | "undetermined";
  crosses_zone: boolean;
  note: string;
}

export interface CommsResponse {
  conversations: Conversation[];
  summary: {
    observed: number;
    downstream: number;
    crossing_zones: number;
    undetermined: number;
    unknown_endpoints: string[];
    coverage_explain: string;
    trustworthy: boolean;
    explain: string;
  };
}

/**
 * One device's lifecycle position.
 *
 * `fixes_are_coming` is three-valued on purpose: "we do not know whether a fix
 * is coming" is not "no fix is coming", and a bare boolean cannot hold the
 * difference.
 */
export interface DeviceLifecycle {
  estate_id: string;
  vendor: string;
  model: string;
  status: "supported" | "end_of_sale" | "end_of_support" | "end_of_life"
    | "unknown" | "unidentified";
  end_of_sale: string;
  end_of_support: string;
  /** Whose claim this is. An operator should know before acting on it. */
  source: string;
  reason: string;
  fixes_are_coming: boolean | null;
  bearing_on_findings: string;
}

export interface LifecycleResponse {
  devices: DeviceLifecycle[];
  summary: {
    records_loaded: number;
    assessed: number;
    counts: Record<string, number>;
    unsupported: string[];
    explain: string;
  };
  pack_version: number;
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

  packs(): Promise<PacksResponse> {
    return this.get("/api/v1/estate/packs");
  }

  health(): Promise<FleetHealthResponse> {
    return this.get("/api/v1/estate/health");
  }

  communications(): Promise<CommsResponse> {
    return this.get("/api/v1/estate/communications");
  }

  lifecycle(): Promise<LifecycleResponse> {
    return this.get("/api/v1/estate/lifecycle");
  }

  // ── operator session (OTS-SRV-006) ──────────────────────────────────────
  //
  // `me` is deliberately not routed through `get`: it answers 200 with
  // `authenticated: false` for the ordinary not-signed-in case, and turning
  // that into an ApiError would make "nobody is signed in" look like a fault.

  async me(): Promise<MeResponse> {
    const response = await fetch(`${this.base}/api/v1/auth/me`, {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    });
    if (!response.ok) return { authenticated: false };
    return (await response.json()) as MeResponse;
  }

  private async send<T>(path: string, body: unknown): Promise<T> {
    const response = await fetch(`${this.base}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body ?? {}),
    });
    if (!response.ok) {
      let detail = `request failed (${response.status})`;
      try {
        const parsed = (await response.json()) as { detail?: string };
        if (parsed.detail) detail = parsed.detail;
      } catch {
        // Keep the status-only message.
      }
      throw new ApiError(detail, response.status);
    }
    return (await response.json()) as T;
  }

  signOut(): Promise<{ signed_out: boolean }> {
    return this.send("/api/v1/auth/logout", {});
  }

  totpStatus(): Promise<TotpStatus> {
    return this.get("/api/v1/auth/totp");
  }

  totpBegin(): Promise<TotpEnrolment> {
    return this.send("/api/v1/auth/totp/begin", {});
  }

  totpConfirm(code: string): Promise<TotpConfirmed> {
    return this.send("/api/v1/auth/totp/confirm", { code });
  }

  totpDisable(password: string, code: string): Promise<{ enabled: boolean }> {
    return this.send("/api/v1/auth/totp/disable", { password, code });
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
