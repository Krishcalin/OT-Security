/**
 * Console entry point (OTS-CON-001..006).
 *
 * The shell owns two things no screen is trusted to remember:
 *
 * The estate banner is rendered here, above whatever screen is showing. A rule
 * that every screen must apply for itself is one that the sixth screen,
 * written in a hurry a year from now, will not — and the screen that forgets it
 * is the one presenting counts as though the estate were whole.
 *
 * A failed load clears the page rather than leaving the last screen's numbers
 * under a new heading. See `router.failurePanel`.
 */

import { EstateApi } from "./api.js";
import { estateBanner } from "./render.js";
import { Screen, RouterHost, start } from "./router.js";
import * as assets from "./screens/assets.js";
import * as change from "./screens/change.js";
import * as estate from "./screens/estate.js";
import * as findings from "./screens/findings.js";
import * as fleet from "./screens/fleet.js";
import * as topology from "./screens/topology.js";

/**
 * One draw, one set of reads.
 *
 * Both the banner and the screen beneath it need estate coverage, and fetching
 * it twice would let them disagree: the banner could say the estate is whole
 * while the tile below it carries a degraded badge from a second, later read.
 * Two different answers to the same question on one page is worse than either
 * answer alone, so the cache is per draw — reset by `chrome()`, which the
 * router runs first every time — and never outlives it. A cache that survived
 * the draw would show yesterday's estate as today's.
 */
class PerDrawApi extends EstateApi {
  private cache = new Map<string, Promise<unknown>>();

  reset(): void {
    this.cache = new Map();
  }

  private once<T>(key: string, load: () => Promise<T>): Promise<T> {
    const existing = this.cache.get(key);
    if (existing) return existing as Promise<T>;
    const started = load();
    this.cache.set(key, started);
    return started;
  }

  override coverage() {
    return this.once("coverage", () => super.coverage());
  }

  override inventory() {
    return this.once("inventory", () => super.inventory());
  }

  override vulnerabilities() {
    return this.once("vulnerabilities", () => super.vulnerabilities());
  }

  override assets() {
    return this.once("assets", () => super.assets());
  }

  override analysis() {
    return this.once("analysis", () => super.analysis());
  }

  override zones() {
    return this.once("zones", () => super.zones());
  }

  override certificates() {
    return this.once("certificates", () => super.certificates());
  }
}

const api = new PerDrawApi();

const SCREENS: readonly Screen[] = [
  {
    id: "estate",
    label: "Estate",
    question: "What is out there, and how much of it did we actually see?",
    render: () => estate.render(api),
  },
  {
    id: "assets",
    label: "Assets",
    question: "One row per device the estate believes exists.",
    render: () => assets.render(api),
  },
  {
    id: "findings",
    label: "Findings",
    question: "What is wrong now, and what could not be assessed.",
    render: () => findings.render(api),
  },
  {
    id: "topology",
    label: "Topology",
    question: "How the plant is segmented — and how much of that was inferred.",
    render: () => topology.render(api),
  },
  {
    id: "change",
    label: "Change",
    question: "What changed, and what stopped being observed.",
    render: () => change.render(api),
  },
  {
    id: "fleet",
    label: "Fleet",
    question: "Which collectors hold which identities, and which were revoked.",
    render: () => fleet.render(api),
  },
];

async function chrome(): Promise<string> {
  api.reset();
  const coverage = await api.coverage();
  return estateBanner(coverage.explain, coverage.trustworthy);
}

function host(): RouterHost {
  const nav = document.getElementById("nav");
  const main = document.getElementById("app");
  const banner = document.getElementById("banner");
  if (!nav || !main || !banner) {
    throw new Error("the console shell is missing its mount points");
  }
  return { nav, main, banner };
}

start(host(), SCREENS, chrome);
