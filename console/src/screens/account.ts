/**
 * Account and second factor (OTS-SRV-006).
 *
 * The screen where an operator enrols a TOTP factor, and the only place the
 * recovery codes are ever shown. They are stored as SHA-256, so this page
 * cannot re-display them and does not pretend it can: a list an operator can
 * re-open is a standing credential rather than a break-glass one.
 *
 * ENROLMENT IS TWO STEPS AND THAT IS THE POINT
 * `Begin` stages a secret; the factor is not in force until a code it
 * generated has been typed back. A one-step enable locks out anyone whose
 * transcription was wrong or whose phone clock is skewed — and the person most
 * likely to be hit is the first administrator, who has nobody to ask for a
 * reset.
 */

import {
  ApiError,
  EstateApi,
  TotpConfirmed,
  TotpEnrolment,
  TotpStatus,
} from "../api.js";
import { esc, fragments } from "../render.js";

/** Kept between draws so the QR is not re-minted on every keystroke. */
let pending: TotpEnrolment | null = null;
let confirmed: TotpConfirmed | null = null;
let message = "";

function enrolmentPanel(enrolment: TotpEnrolment): string {
  return [
    '<div class="panel">',
    "  <h2>Enrol an authenticator</h2>",
    '  <div class="enrol-grid">',
    // The SVG is markup this server generated from its own provisioning URI,
    // not a value that arrived from a scanned network. `fragments` says so.
    '    <div class="enrol-qr">' + fragments([enrolment.qr_svg]) + "</div>",
    '    <div style="flex:1;min-width:16rem">',
    '      <p class="note">Scan this with Microsoft Authenticator, Google',
    "       Authenticator, Authy or 1Password. On the phone itself, open",
    '       <a href="' + esc(enrolment.provisioning_uri) + '">this link</a>',
    "       instead — there is nothing to scan. If the camera is unavailable or",
    "       the screen is being shared, use setup-key entry:</p>",
    '      <div class="secret-box">' + esc(enrolment.formatted_secret) + "</div>",
    '      <p class="note">Then type the current 6-digit code below. Nothing is',
    "       switched on until that code verifies, so a mistyped secret cannot",
    "       lock you out — it just does not enrol.</p>",
    '      <label class="login-label" for="enrol-code">Authentication code</label>',
    '      <input class="login-input" id="enrol-code" inputmode="numeric"',
    '             autocomplete="one-time-code" placeholder="123456">',
    '      <button class="login-btn" id="enrol-confirm">Verify and enable</button>',
    "    </div>",
    "  </div>",
    "</div>",
  ].join("");
}

function recoveryPanel(result: TotpConfirmed): string {
  const items = result.recovery_codes.map((code) => "<li>" + esc(code) + "</li>");
  return [
    '<div class="panel panel-warn">',
    "  <h2>Recovery codes — shown once</h2>",
    '  <p class="note">' + esc(result.detail) + "</p>",
    '  <ul class="recovery-list">' + fragments(items) + "</ul>",
    '  <p class="note">Each works once, in place of a code from the app. Without',
    "   them a lost or wiped phone is a locked account, and for the first",
    "   administrator there is nobody to ask for a reset.</p>",
    "</div>",
  ].join("");
}

function enabledPanel(): string {
  return [
    '<div class="panel">',
    "  <h2>Second factor is enrolled</h2>",
    '  <p class="note">Sign-in asks for a code from your authenticator. To',
    "   remove it you must prove the password AND a current code — a session on",
    "   its own is not enough, because the whole point of the factor is that a",
    "   stolen session is not a complete credential.</p>",
    '  <label class="login-label" for="off-password">Password</label>',
    '  <input class="login-input" id="off-password" type="password"',
    '         autocomplete="current-password">',
    '  <label class="login-label" for="off-code">Authentication code</label>',
    '  <input class="login-input" id="off-code" inputmode="numeric"',
    '         autocomplete="one-time-code">',
    '  <button class="login-btn" id="totp-disable">Remove second factor</button>',
    "</div>",
  ].join("");
}

function offerPanel(): string {
  return [
    '<div class="panel panel-warn">',
    "  <h2>No second factor is enrolled</h2>",
    '  <p class="note">A password alone protects this estate. Anyone who learns',
    "   it — reused elsewhere, phished, read off a note in a control room — has",
    "   the plant inventory and the segmentation map.</p>",
    '  <button class="login-btn" id="totp-begin">Set up an authenticator</button>',
    "</div>",
  ].join("");
}

export async function render(api: EstateApi): Promise<string> {
  const me = await api.me();
  if (!me.authenticated) {
    return [
      "<h1>Account</h1>",
      '<div class="panel panel-alarm"><h2>Not signed in</h2>',
      "<p>This console has no session. Nothing here describes your plant.</p>",
      "</div>",
    ].join("");
  }

  let status: TotpStatus;
  try {
    status = await api.totpStatus();
  } catch (error) {
    status = {
      enabled: false,
      pending: false,
      issuer: error instanceof ApiError ? "unavailable" : "unavailable",
    };
  }

  const body = confirmed
    ? recoveryPanel(confirmed) + enabledPanel()
    : status.enabled
      ? enabledPanel()
      : pending
        ? enrolmentPanel(pending)
        : offerPanel();

  return [
    "<h1>Account</h1>",
    '<p class="note">Signed in as <strong>' + esc(me.display_name || me.username || "") +
      "</strong>. This session expires at " + esc((me.expires_at || "").slice(0, 19)) +
      " and slides forward while you use it, but never past seven days from" +
      " sign-in.</p>",
    message ? '<p class="login-notice">' + esc(message) + "</p>" : "",
    body,
    '<div class="panel">',
    "  <h2>Sign out</h2>",
    '  <p class="note">Closes this session on the server, not just in the',
    "   browser. A console left open in a control room is a standing grant.</p>",
    '  <button class="login-btn" id="sign-out">Sign out</button>',
    "</div>",
  ].join("");
}

/**
 * Wire the buttons after the screen is in the DOM.
 *
 * The router replaces `innerHTML`, so listeners cannot be attached during
 * render — this is called by the shell once the markup is mounted.
 */
export function attach(api: EstateApi, redraw: () => void): void {
  document.getElementById("totp-begin")?.addEventListener("click", () => {
    void (async () => {
      message = "";
      try {
        pending = await api.totpBegin();
      } catch (error) {
        message = error instanceof Error ? error.message : "could not start";
      }
      redraw();
    })();
  });

  document.getElementById("enrol-confirm")?.addEventListener("click", () => {
    void (async () => {
      const input = document.getElementById("enrol-code");
      const code = input instanceof HTMLInputElement ? input.value.trim() : "";
      try {
        confirmed = await api.totpConfirm(code);
        pending = null;
        message = "";
      } catch (error) {
        message = error instanceof Error ? error.message : "that code did not verify";
      }
      redraw();
    })();
  });

  document.getElementById("totp-disable")?.addEventListener("click", () => {
    void (async () => {
      const passwordInput = document.getElementById("off-password");
      const codeInput = document.getElementById("off-code");
      const password =
        passwordInput instanceof HTMLInputElement ? passwordInput.value : "";
      const code = codeInput instanceof HTMLInputElement ? codeInput.value.trim() : "";
      try {
        await api.totpDisable(password, code);
        confirmed = null;
        pending = null;
        message = "Second factor removed.";
      } catch (error) {
        message = error instanceof Error ? error.message : "could not remove it";
      }
      redraw();
    })();
  });

  document.getElementById("sign-out")?.addEventListener("click", () => {
    void (async () => {
      try {
        await api.signOut();
      } finally {
        window.location.assign("/login.html");
      }
    })();
  });
}
