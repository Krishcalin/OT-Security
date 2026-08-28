/**
 * Hash routing for the console shell (OTS-CON-001).
 *
 * Hash rather than history routing on purpose: the console is served as static
 * files beside the API (`_mount_console`), and a path-routed SPA would need a
 * catch-all rewrite on the server. A rewrite that answers every unmatched path
 * with the shell also answers a mistyped `/api/v1/estate/inventroy` with HTML,
 * and a client that parsed it would show an empty estate rather than an error.
 * Hashes never reach the server, so that whole class of confusion is absent.
 */

import { ApiError } from "./api.js";
import { cls, esc, fragments } from "./render.js";

export interface Screen {
  /** The hash fragment, without the leading `#/`. */
  readonly id: string;
  readonly label: string;
  /** What this screen answers, shown in the nav title attribute. */
  readonly question: string;
  readonly render: () => Promise<string>;
  /**
   * Called after the markup is mounted, for a screen with controls.
   *
   * The router replaces `innerHTML`, so a screen cannot attach listeners while
   * rendering — the elements do not exist yet. `redraw` re-runs the current
   * screen, which is how a form reflects what it just did.
   */
  readonly attach?: (redraw: () => void) => void;
}

/**
 * The panel shown when a screen could not be drawn.
 *
 * Two rules, both the same rule as everywhere else in this system:
 *
 * It replaces the content rather than overlaying it. Leaving the previous
 * screen's figures on the page under a failed refresh would present stale
 * numbers as current ones — the operator has no way to tell, and the numbers
 * look exactly as they did when they were true.
 *
 * A fail-closed 503 is reported as itself. `api.ts` refuses to let it become an
 * empty result; this refuses to let it become an empty page, which would read
 * as a plant with nothing in it.
 */
export function failurePanel(error: unknown): string {
  if (error instanceof ApiError && error.status === 503) {
    return [
      `<div class="panel panel-alarm">`,
      `  <h2>This console is not authorised to read the estate</h2>`,
      `  <p>The estate API is fail-closed until operator authentication is`,
      `     wired (OTS-SRV-006). Nothing is shown here because nothing was`,
      `     read — <strong>this is not an empty estate</strong>.</p>`,
      `</div>`,
    ].join("\n");
  }
  const detail = error instanceof Error ? error.message : String(error);
  return [
    `<div class="panel panel-alarm">`,
    `  <h2>This screen could not be drawn</h2>`,
    `  <p>${esc(detail)}</p>`,
    `  <p>No figures are shown because none were retrieved. The previous`,
    `     screen's numbers have been cleared rather than left in place, since`,
    `     a stale count is indistinguishable from a current one.</p>`,
    `</div>`,
  ].join("\n");
}

export function currentId(hash: string, fallback: string): string {
  const id = hash.replace(/^#\/?/, "").split("?")[0] ?? "";
  return id || fallback;
}

export function nav(screens: readonly Screen[], active: string): string {
  const links = screens.map(
    (s) =>
      `<a class="${cls("nav-link", s.id === active && "nav-active")}"` +
      ` href="#/${esc(s.id)}" title="${esc(s.question)}">${esc(s.label)}</a>`,
  );
  return fragments(links);
}

export interface RouterHost {
  readonly nav: HTMLElement;
  readonly main: HTMLElement;
  /** Rendered above every screen, so no screen can omit it. */
  readonly banner: HTMLElement;
}

/**
 * Start routing. `chrome` runs before every screen and returns the estate-wide
 * banner: it is the shell's job, not each screen's, because a rule that every
 * screen must remember to apply is one that a new screen eventually will not.
 */
export function start(
  host: RouterHost,
  screens: readonly Screen[],
  chrome: () => Promise<string>,
): void {
  const first = screens[0];
  if (!first) throw new Error("the console has no screens");
  const fallback = first.id;
  let generation = 0;

  const draw = async (): Promise<void> => {
    const mine = ++generation;
    const id = currentId(window.location.hash, fallback);
    const screen = screens.find((s) => s.id === id) ?? first;
    host.nav.innerHTML = nav(screens, screen.id);
    host.main.innerHTML = `<div class="loading">reading the estate…</div>`;
    host.banner.innerHTML = "";

    let banner = "";
    let body: string;
    try {
      banner = await chrome();
      body = await screen.render();
    } catch (error) {
      // A session that has expired or been revoked is not a screen that failed
      // to draw; it is a console that is no longer signed in. Sending the
      // operator to the form beats a panel explaining that they should find
      // it themselves.
      if (error instanceof ApiError && error.status === 401) {
        window.location.assign("/login.html");
        return;
      }
      body = failurePanel(error);
    }
    // A slower earlier navigation must not overwrite a later one, or the
    // operator reads one screen's numbers under another screen's heading.
    if (mine !== generation) return;
    host.banner.innerHTML = banner;
    host.main.innerHTML = body;
    if (screen.attach) screen.attach(() => void draw());
  };

  window.addEventListener("hashchange", () => void draw());
  void draw();
}
