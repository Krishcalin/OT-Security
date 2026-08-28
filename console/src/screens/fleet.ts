/**
 * Fleet identities — the certificate lifecycle (Phase 6, decision Q4).
 *
 * The screen that makes revocation real. A revocation an operator cannot see is
 * one they cannot audit, and this system's whole claim about revoked
 * certificates is that the server refuses them — which is worth nothing if
 * nobody can tell which certificates those are.
 *
 * The counts here are `unknown` when no CA is configured, not zero. A
 * deployment without one has no issuance record at all, so "0 revoked" would be
 * a confident statement about a fleet whose identities are not being tracked.
 */

import {
  CertificateRow,
  CertificatesResponse,
  EstateApi,
  CollectorHealthRow,
  FleetAlarm,
  FleetHealthResponse,
  PackDrift,
  PackRow,
  PacksResponse,
} from "../api.js";
import { Coverage, measured } from "../coverage.js";
import { cls, esc, fragments, metric, table } from "../render.js";

/**
 * What a fleet running mixed content is worth.
 *
 * `complete` only when every collector is on the newest pack. A collector
 * left behind is not a smaller number — it is a sensor that will not report
 * what the new pack would have found, and nothing in its own output says so.
 * A collector that has never announced a version is `unknown` rather than
 * `degraded`, because we do not know what it is running at all.
 */
function driftCoverage(drift: PackDrift): { coverage: Coverage; basis: string } {
  if (drift.latest === 0) {
    return {
      coverage: "unknown",
      basis: "no rules pack has been published, so no collector has been "
        + "told anything and none of them are behind",
    };
  }
  if (drift.unknown.length) {
    return { coverage: "unknown", basis: drift.explain };
  }
  if (drift.behind.length) {
    return { coverage: "degraded", basis: drift.explain };
  }
  return { coverage: "complete", basis: drift.explain };
}

/**
 * How much of the fleet is actually reporting.
 *
 * `unknown` when anyone is silent, and that is the whole point: their stored
 * coverage still reads as complete, so a count that included them would be a
 * confident number about sites nobody is watching.
 */
function healthCoverage(fleet: FleetHealthResponse): {
  coverage: Coverage;
  basis: string;
} {
  if (fleet.coverage_not_believable.length) {
    return { coverage: "unknown", basis: fleet.explain };
  }
  if (fleet.alarms.length) {
    return { coverage: "degraded", basis: fleet.explain };
  }
  return { coverage: "complete", basis: fleet.explain };
}

function alarmRow(alarm: FleetAlarm): string {
  const tone = alarm.severity === "critical" ? "alarm"
    : alarm.severity === "warning" ? "warn" : "ok";
  return [
    '<div class="engine">',
    '  <div class="engine-head">',
    '    <span class="engine-name">' + esc(alarm.collector_id) + "</span>",
    '    <span class="' + cls("chip", "chip-" + tone) + '">'
      + esc(alarm.kind.replace(/_/g, " ")) + "</span>",
    "  </div>",
    '  <div class="engine-reason">' + esc(alarm.detail) + "</div>",
    '  <ul class="limits"><li>' + esc(alarm.action) + "</li></ul>",
    "</div>",
  ].join("");
}

function healthPanel(fleet: FleetHealthResponse): string {
  const { coverage, basis } = healthCoverage(fleet);
  const reporting = fleet.collectors.filter(
    (c) => c.state === "reporting").length;

  const rows = table<CollectorHealthRow>(
    [
      { header: "collector", cell: (c) => esc(c.collector_id) },
      { header: "site", cell: (c) => esc(c.site || "—") },
      { header: "state", cell: (c) => stateChipFor(c) },
      {
        header: "last heard",
        cell: (c) => esc(c.seconds_since_heartbeat === null
          ? "never"
          : Math.round(c.seconds_since_heartbeat / 60) + " min ago"),
      },
      { header: "capture", cell: (c) => esc(c.capture_state) },
      { header: "queued", cell: (c) => esc(c.queue_depth), numeric: true },
    ],
    fleet.collectors.map((row) => ({
      row,
      coverage: row.state === "reporting"
        ? ("complete" as Coverage)
        : row.state === "late"
          ? ("degraded" as Coverage)
          : ("unknown" as Coverage),
      basis: row.coverage_believable
        ? "reporting; its coverage is counted"
        : "its stored coverage still reads as complete and is not counted",
    })),
  );

  return [
    "<h2>Collector health</h2>",
    '<p class="note">Coverage says what the windows that ARRIVED were worth.',
    " It has no notion of when they arrived, so a collector switched off last",
    " week still summarises as trustworthy off fifty stored windows. This is",
    " the half that notices.</p>",
    '<div class="metrics">',
    metric("collectors reporting", measured(reporting, coverage, basis)),
    metric("open alarms",
      measured(fleet.alarms.length,
        fleet.alarms.length ? ("degraded" as Coverage) : coverage, basis)),
    "</div>",
    fleet.alarms.length
      ? fragments(fleet.alarms.map((alarm) => alarmRow(alarm)))
      : '<p class="note">Nothing needs looking at.</p>',
    rows,
  ].join("");
}

function stateChipFor(row: CollectorHealthRow): string {
  const tone = row.state === "reporting" ? "ok"
    : row.state === "late" ? "warn"
      : row.state === "disabled" ? "ok" : "alarm";
  return '<span class="' + cls("chip", "chip-" + tone) + '">'
    + esc(row.state.replace(/_/g, " ")) + "</span>";
}

function packPanel(packs: PacksResponse): string {
  if (!packs.signing_configured) {
    return [
      '<div class="panel panel-warn">',
      "  <h2>No content signing key is configured</h2>",
      '  <p class="note">This server cannot publish detection content, so',
      "   the fleet runs whatever it was built with and can only be updated",
      "   by replacing the collector. Distribution is unavailable rather",
      "   than unsigned — an unsigned pack is content a collector should",
      "   refuse.</p>",
      "</div>",
    ].join("");
  }

  const { coverage, basis } = driftCoverage(packs.drift);
  const rows = table<PackRow>(
    [
      { header: "version", cell: (p) => esc(p.version), numeric: true },
      { header: "contents", cell: (p) => esc(p.summary) },
      { header: "published", cell: (p) => esc(p.created_at.slice(0, 10)) },
      { header: "by", cell: (p) => esc(p.published_by || "—") },
      { header: "digest", cell: (p) => esc(p.digest.slice(0, 16)) },
    ],
    packs.packs.map((row) => ({
      row,
      coverage: row.version === packs.drift.latest
        ? ("complete" as Coverage)
        : ("degraded" as Coverage),
      basis: row.version === packs.drift.latest
        ? "the current pack"
        : "superseded by version " + packs.drift.latest,
    })),
  );

  const behind = packs.drift.behind.map(
    (row) => "<li>" + esc(row.collector_id) + " on version "
      + esc(row.version) + ", " + esc(row.behind_by) + " behind</li>",
  );
  const silent = packs.drift.unknown.map(
    (id) => "<li>" + esc(id) + " has not reported a version</li>",
  );

  return [
    "<h2>Detection content</h2>",
    '<div class="metrics">',
    metric("collectors on the current pack",
      measured(packs.drift.current.length, coverage, basis)),
    metric("published version",
      measured(packs.drift.latest, coverage, basis)),
    "</div>",
    behind.length || silent.length
      ? ['<div class="panel panel-warn">',
         "  <h2>Not every collector is on the current pack</h2>",
         '  <p class="note">A collector that refused or missed a pack keeps',
         "   running the content it has. It stays safe and goes quiet about",
         "   everything the new pack would have found, so the gap shows",
         "   here rather than in its own output.</p>",
         '  <ul class="warn-list">',
         behind.join(""), silent.join(""),
         "  </ul>",
         "</div>"].join("")
      : "",
    rows,
  ].join("");
}

/**
 * What a certificate's row is worth.
 *
 * `expiring_soon` is `degraded` rather than fine: a certificate that lapses in
 * a substation takes a site visit to replace, and the window in which that is
 * still avoidable is the thing this screen exists to show.
 */
function rowCoverage(row: CertificateRow): { coverage: Coverage; basis: string } {
  if (row.state === "revoked") {
    return {
      coverage: "unknown",
      basis:
        "revoked" +
        (row.revocation_reason ? ": " + row.revocation_reason : "") +
        " — the server refuses it, though it is still cryptographically valid",
    };
  }
  if (row.state === "expired") {
    return {
      coverage: "unknown",
      basis: "expired on " + row.not_after + "; this collector must re-enrol",
    };
  }
  if (row.expiring_soon) {
    return {
      coverage: "degraded",
      basis: "expires " + row.not_after + " — renew before it lapses, or the "
        + "replacement is a site visit",
    };
  }
  return { coverage: "complete", basis: "valid until " + row.not_after };
}

function stateChip(row: CertificateRow): string {
  const tone =
    row.state === "valid" ? (row.expiring_soon ? "warn" : "ok") : "alarm";
  return `<span class="${cls("chip", "chip-" + tone)}">${esc(row.state)}</span>`;
}

function noCa(): string {
  return [
    '<div class="panel panel-alarm">',
    "  <h2>No fleet CA is configured</h2>",
    "  <p>This server cannot issue or revoke collector identities, so there is",
    "     no issuance record to show. Collectors are authenticated by the name",
    "     in their certificate alone, and <strong>revocation does not exist in",
    "     this state</strong> — nothing in a subject line changes when a",
    "     certificate is withdrawn.</p>",
    "  <p>This is the pre-enrolment state, and it is reported rather than drawn",
    "     as an empty fleet.</p>",
    "</div>",
  ].join("");
}

export async function render(api: EstateApi): Promise<string> {
  const certificates: CertificatesResponse = await api.certificates();

  if (!certificates.ca_configured) {
    const [packs, fleet] = await Promise.all([api.packs(), api.health()]);
    return ["<h1>Fleet</h1>", healthPanel(fleet), noCa(),
            packPanel(packs)].join("");
  }

  const rows = certificates.certificates;
  const state: Coverage = "complete";
  const basis = "from this server's own issuance record";

  const valid = rows.filter((r) => r.state === "valid");
  const expiring = valid.filter((r) => r.expiring_soon);
  const revoked = rows.filter((r) => r.state === "revoked");

  const listing = table<CertificateRow>(
    [
      { header: "collector", cell: (r) => esc(r.collector_id) },
      { header: "state", cell: (r) => stateChip(r) },
      { header: "serial", cell: (r) => esc(r.serial.slice(0, 16)) },
      { header: "issued", cell: (r) => esc(r.not_before.slice(0, 10)) },
      { header: "expires", cell: (r) => esc(r.not_after.slice(0, 10)) },
      { header: "why revoked", cell: (r) => esc(r.revocation_reason || "—") },
    ],
    rows.map((row) => ({ row, ...rowCoverage(row) })),
  );

  const [packs, fleet] = await Promise.all([api.packs(), api.health()]);

  return [
    "<h1>Fleet</h1>",
    healthPanel(fleet),
    '<div class="metrics">',
    metric("valid certificates", measured(valid.length, state, basis)),
    metric(
      "expiring within 14 days",
      measured(
        expiring.length,
        expiring.length ? "degraded" : state,
        expiring.length
          ? "a certificate that lapses in a substation is replaced by a site visit"
          : basis,
      ),
    ),
    metric("revoked", measured(revoked.length, state, basis)),
    "</div>",
    '<p class="note">Revoked and expired certificates stay in this list.',
    ' "No record" and "never issued" would otherwise be the same answer, and',
    " the question after an incident is what this fleet has held rather than",
    " what it holds now.</p>",
    listing,
    packPanel(packs),
  ].join("");
}
