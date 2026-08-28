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

import { CertificateRow, CertificatesResponse, EstateApi } from "../api.js";
import { Coverage, measured } from "../coverage.js";
import { cls, esc, metric, table } from "../render.js";

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
    return ["<h1>Fleet identities</h1>", noCa()].join("");
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

  return [
    "<h1>Fleet identities</h1>",
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
  ].join("");
}
