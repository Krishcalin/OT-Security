/**
 * Render every screen against real API responses, in Node.
 *
 * The type checker proves a screen cannot render a number without its coverage.
 * It does not prove the screen renders at all: a field read off a response shape
 * that drifted, an undefined row, a helper called with the wrong argument — all
 * of that type-checks against the interfaces in `api.ts` and then throws in the
 * browser, where the operator sees the router's failure panel and no estate.
 *
 * So the payloads here are not hand-written fixtures. `tests/test_console.py`
 * dumps them out of the real FastAPI app and points this script at them, which
 * means a response the server actually changed cannot keep passing here.
 *
 * Usage: node render-check.mjs <dir-of-endpoint-json>
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: node render-check.mjs <dir-of-endpoint-json>");
  process.exit(2);
}

const FILES = {
  "/api/v1/estate/coverage": "coverage.json",
  "/api/v1/estate/inventory": "inventory.json",
  "/api/v1/estate/vulnerabilities": "vulnerabilities.json",
  "/api/v1/estate/assets": "assets.json",
  "/api/v1/estate/analysis": "analysis.json",
  "/api/v1/estate/zones": "zones.json",
  "/api/v1/estate/certificates": "certificates.json",
  "/api/v1/estate/packs": "packs.json",
};

// The console talks to the network and nothing else, so the network is the only
// thing that needs standing in for. Everything below this line is the real
// compiled console.
globalThis.fetch = async (url) => {
  const name = FILES[String(url)];
  if (!name || !existsSync(join(dir, name))) {
    return { ok: false, status: 404, json: async () => ({}) };
  }
  const body = JSON.parse(readFileSync(join(dir, name), "utf8"));
  return { ok: true, status: 200, json: async () => body };
};

const { EstateApi } = await import("./dist/api.js");
const api = new EstateApi();

const screens = ["estate", "assets", "findings", "topology", "change"];
const failures = [];

for (const name of screens) {
  const module = await import(`./dist/screens/${name}.js`);
  let html;
  try {
    html = await module.render(api);
  } catch (error) {
    failures.push(`${name}: threw ${error && error.stack ? error.stack : error}`);
    continue;
  }
  if (typeof html !== "string" || html.length === 0) {
    failures.push(`${name}: rendered nothing`);
    continue;
  }
  // Every screen presents counts or clean states, so every screen must show
  // the coverage they rest on. A screen that rendered without a single chip has
  // found a way around OTS-CON-004 that the type checker cannot see.
  //
  // Unless it is presenting NOTHING — no zones could be derived, no CA is
  // configured — in which case it must say why instead. Those two are the only
  // acceptable states: a figure with its coverage, or an explanation of why
  // there is no figure. Silence is neither.
  const explains = html.includes("panel-alarm") || html.includes("panel-warn");
  if (!html.includes("chip-") && !explains) {
    failures.push(`${name}: rendered no coverage chip and no explanation`);
  }
  if (html.includes("undefined") || html.includes("[object Object]")) {
    failures.push(`${name}: rendered a placeholder value into the page`);
  }
  console.log(`${name.padEnd(9)} ${String(html.length).padStart(6)} bytes`);
}

if (failures.length) {
  console.error("\nFAILED:\n" + failures.join("\n"));
  process.exit(1);
}
console.log("\nevery screen rendered");
