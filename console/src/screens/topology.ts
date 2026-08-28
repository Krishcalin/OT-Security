/**
 * Purdue zones and segmentation (OTS-CON-005, decision D6).
 *
 * The screen where a guess is most dangerous. A zone diagram is read as a
 * statement about how the plant is actually segmented, and the firewall rules
 * someone writes from it may be applied to a live network — so a level that came
 * from the topology engine's fallback must never look like one that came from an
 * observed device role.
 *
 * An empty topology therefore has to say WHICH empty it is. "No zones could be
 * derived" and "zones were derived and rejected" both draw nothing, and only the
 * second means somebody holds a segmentation model that should not be trusted.
 */

import { EstateApi, SiteTopologyRow, ZoneRow, ZonesResponse } from "../api.js";
import { Coverage, measured } from "../coverage.js";
import { esc, metric, table } from "../render.js";

/**
 * What a zone's Purdue level is worth.
 *
 * `role` came from a recognised device role — an observation. `protocol` was
 * inferred from the protocol mix, which is evidence but not identification.
 * `defaulted` is the engine's fall-through, and is `unknown` rather than
 * `degraded` because nothing about the plant produced it.
 */
function zoneCoverage(zone: ZoneRow): { coverage: Coverage; basis: string } {
  switch (zone.level_basis) {
    case "role":
      return {
        coverage: "complete",
        basis: "level from the dominant device role (" +
          (zone.dominant_role || "unnamed") + ")",
      };
    case "protocol":
      return {
        coverage: "degraded",
        basis: "level inferred from the protocol mix, not from a device role",
      };
    default:
      return {
        coverage: "unknown",
        basis:
          "no role and no OT protocol evidence — this level is the engine's " +
          "fallback, not an observation about the plant",
      };
  }
}

function site(topology: SiteTopologyRow): string {
  const rows = table<ZoneRow>(
    [
      { header: "zone", cell: (z) => esc(z.zone_id) },
      { header: "subnet", cell: (z) => esc(z.subnet) },
      { header: "purdue", cell: (z) => esc(z.purdue_label) },
      { header: "level", cell: (z) => esc(z.purdue_level), numeric: true },
      { header: "dominant role", cell: (z) => esc(z.dominant_role || "—") },
      { header: "devices", cell: (z) => esc(z.device_count), numeric: true },
      { header: "level from", cell: (z) => esc(z.level_basis) },
    ],
    topology.zones.map((z) => ({ row: z, ...zoneCoverage(z) })),
  );

  const state: Coverage = topology.confidence.usable
    ? topology.confidence.defaulted > 0
      ? "degraded"
      : "complete"
    : "unknown";

  return [
    "<h2>" + esc(topology.site) + "</h2>",
    '<div class="metrics">',
    metric(
      "zones",
      measured(topology.confidence.zones, state, topology.confidence.explain),
    ),
    metric(
      "segmentation violations",
      measured(topology.violations, state, topology.confidence.explain),
    ),
    "</div>",
    rows,
  ].join("");
}

/**
 * Why the topology is empty, in the operator's terms.
 *
 * Deliberately two messages rather than one with the reason in a tooltip: the
 * difference between these states is the difference between "we cannot tell
 * you" and "we can, and you should not believe it".
 */
function emptyExplanation(zones: ZonesResponse): string {
  if (zones.state === "rejected") {
    return [
      '<div class="panel panel-alarm">',
      "  <h2>Zones were derived and then rejected</h2>",
      "  <p>" + esc(zones.explain) + "</p>",
      "  <p>More than half of the Purdue levels came from the fallback rather",
      "     than from an observed role or protocol, which makes this a subnet",
      "     listing with numbers attached rather than a segmentation model.",
      "     Drawing it would dress a guess as a control, and the rules someone",
      "     writes from it may reach a live plant network.</p>",
      "</div>",
    ].join("");
  }
  return [
    '<div class="panel panel-warn">',
    "  <h2>No zones could be derived</h2>",
    "  <p>" + esc(zones.explain) + "</p>",
    "  <p>This is an absence of input, not a flat network. Zones are derived",
    "     from assets that carry addresses; without them there is nothing to",
    "     segment, and nothing here should be read as segmentation.</p>",
  ].join("") + "</div>";
}

export async function render(api: EstateApi): Promise<string> {
  const zones = await api.zones();

  if (zones.state !== "derived") {
    return ["<h1>Topology</h1>", emptyExplanation(zones)].join("");
  }

  return [
    "<h1>Topology</h1>",
    '<p class="note">Zones are derived per site, never across the estate:',
    " <code>10.10.1.0/24</code> exists at almost every plant, and one",
    " estate-wide derivation would fuse two substations into a single zone —",
    " after which a cross-plant flow reads as a breach inside one site while a",
    " real breach inside a site is hidden by the merge.</p>",
    '<p class="note">' + esc(zones.explain) + "</p>",
    zones.sites.map((t) => site(t)).join(""),
  ].join("");
}
