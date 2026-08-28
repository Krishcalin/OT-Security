/**
 * Who talks to whom (OTS-CON-007).
 *
 * Flows have fed the zone derivation, the attack paths, the policy engine and —
 * since containment — every firewall rule this console proposes. Until now
 * nothing showed them. A containment rule could say "denying this would cut
 * control communication happening today" with no way for the operator to look
 * at the communication in question.
 *
 * DIRECTION IS THE ANALYTIC, NOT VOLUME
 * A table sorted by packet count is a network graph, and a substation operator
 * already has one. What they do not have is the answer to "is anything reaching
 * down into the control layer from above" — so downstream conversations sort
 * first and are marked, whatever their size.
 *
 * AND `undetermined` IS NOT `lateral`
 * They would look alike on a screen and mean opposite things: one says the two
 * levels are equal, the other says at least one of them was never derived. A
 * conversation whose direction cannot be stated is rendered as its own state,
 * because the honest answer to "is this a segmentation problem" is sometimes
 * "we cannot tell you, and here is why".
 */

import {
  CommsResponse,
  Conversation,
  EstateApi,
} from "../api.js";
import { Coverage, measured } from "../coverage.js";
import { cls, esc, fragments, metric, table } from "../render.js";

function directionChip(conversation: Conversation): string {
  const tone =
    conversation.direction === "downstream" ? "alarm"
      : conversation.direction === "undetermined" ? "warn" : "ok";
  const title =
    conversation.direction === "downstream"
      ? "a higher Purdue level reaching toward the process — the direction "
        + "segmentation exists to control"
      : conversation.direction === "undetermined"
        ? "at least one endpoint's Purdue level was not derived, so the "
          + "direction cannot be stated. This is not the same as lateral."
        : conversation.direction === "upstream"
          ? "a controller reporting upward, which is ordinary"
          : "within one Purdue level";
  return `<span class="${cls("chip", "chip-" + tone)}" title="${esc(title)}">`
    + `${esc(conversation.direction)}</span>`;
}

function endpoint(side: Conversation["src"]): string {
  const zone = side.zone_id
    ? esc(side.zone_id) + (side.purdue_level >= 0
      ? esc(" · L" + side.purdue_level) : " · level not derived")
    : "no derived zone";
  const label = side.unknown_device
    ? `<span class="${cls("chip", "chip-warn")}" title="this address talked `
      + `and the inventory holds no device for it">unknown</span> `
      + `<code>${esc(side.ip)}</code>`
    : esc(side.label);
  // `zone` is already-escaped markup, and `fragments` is how that is said
  // out loud — the guard in test_console.py requires every interpolation
  // inside markup to be a named call, with no exceptions to remember.
  return label + `<div class="hit-why">${esc(side.ip)} &middot; `
    + `${fragments([zone])}</div>`;
}

/**
 * What the conversation counts rest on.
 *
 * Never `complete`, even on a perfect estate: a conversation that did not
 * happen during the observed windows does not appear here, so every count is a
 * floor. The estate's own coverage decides how much of a floor.
 */
function commsCoverage(body: CommsResponse): { coverage: Coverage; basis: string } {
  return {
    coverage: body.summary.trustworthy ? "degraded" : "unknown",
    basis: body.summary.trustworthy
      ? "every collector reporting cleanly — but this is still only what was "
        + "observed during the windows, so it is a floor rather than a total"
      : body.summary.coverage_explain,
  };
}

export async function render(api: EstateApi): Promise<string> {
  const body = await api.communications();
  const { coverage, basis } = commsCoverage(body);
  const summary = body.summary;

  const rows = table<Conversation>(
    [
      { header: "direction", cell: (c) => directionChip(c) },
      { header: "from", cell: (c) => endpoint(c.src) },
      { header: "to", cell: (c) => endpoint(c.dst) },
      { header: "protocol", cell: (c) => esc(c.protocol || "unknown") },
      { header: "port", cell: (c) => esc(c.port || "—"), numeric: true },
      { header: "packets", cell: (c) => esc(c.packets), numeric: true },
      { header: "site", cell: (c) => esc(c.site || "—") },
    ],
    body.conversations.map((row) => ({
      row,
      coverage: row.direction === "undetermined"
        ? ("unknown" as Coverage)
        : coverage,
      basis: row.direction === "undetermined"
        ? "a Purdue level behind this conversation was not derived, so its "
          + "direction is not established"
        : basis,
    })),
  );

  const unknownPanel = summary.unknown_endpoints.length
    ? [
      '<div class="panel panel-warn">',
      "  <h2>Addresses talking that the inventory does not hold</h2>",
      '  <p class="note">These spoke on the wire and no merged asset matches',
      "   them. The estate has evidence of a device it cannot show, which is",
      "   the same gap as a detection whose asset row never arrived.</p>",
      '  <ul class="warn-list">',
      summary.unknown_endpoints.map((ip) => "<li>" + esc(ip) + "</li>").join(""),
      "  </ul>",
      "</div>",
    ].join("")
    : "";

  return [
    "<h1>Communications</h1>",
    '<p class="note">Every conversation observed on the wire, with both ends',
    " resolved to devices. This is the evidence under the containment rules on",
    " the Findings screen &mdash; a rule that says denying a source would cut",
    " control traffic happening today is talking about a row in this table.</p>",
    '<div class="metrics">',
    metric("conversations observed",
      measured(summary.observed, coverage, basis)),
    metric("reaching down toward the process",
      measured(summary.downstream,
        summary.downstream ? ("degraded" as Coverage) : coverage,
        summary.downstream
          ? "a higher Purdue level reaching a lower one is the direction "
            + "segmentation exists to control"
          : basis)),
    metric("direction not established",
      measured(summary.undetermined,
        summary.undetermined ? ("unknown" as Coverage) : coverage,
        summary.undetermined
          ? "a Purdue level behind these was not derived; this is not the "
            + "same as saying they are fine"
          : basis)),
    "</div>",
    '<p class="note">' + esc(summary.explain) + "</p>",
    unknownPanel,
    rows,
  ].join("");
}
