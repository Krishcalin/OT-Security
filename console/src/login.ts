/**
 * The sign-in page (OTS-SRV-006).
 *
 * Three modes on one page, because they are the same conversation: prove who
 * you are, prove it again with a second factor, or replace the password you
 * were just handed.
 *
 * WHY CHANGE-PASSWORD LIVES HERE AND NOT BEHIND A SESSION
 * The usual reason to change a password is that somebody issued you a
 * temporary one, so requiring a session first would put the feature behind the
 * door it exists to open. It is not weaker: the form proves the current
 * password and the second factor, which is the whole check either way.
 *
 * THE ERROR MESSAGE IS DELIBERATELY VAGUE
 * The server returns the same "invalid username or password" for a wrong
 * password, an unknown account AND a wrong six-digit code, and this renders it
 * verbatim. Splitting them would be friendlier and would turn the form into an
 * oracle: the account-exists version is a directory of who works at this
 * utility, and the "password right, code wrong" version confirms a guessed
 * password to somebody holding only half the credential.
 *
 * There is no "forgot password" link, because there is no self-service reset.
 * An unauthenticated reset path is a way in.
 */

import { esc } from "./render.js";

type Mode = "signin" | "totp" | "change";

interface State {
  mode: Mode;
  username: string;
  /** Kept across the password -> code step so nobody retypes it. */
  password: string;
  error: string;
  notice: string;
  busy: boolean;
}

const state: State = {
  mode: "signin",
  username: "",
  password: "",
  error: "",
  notice: "",
  busy: false,
};

async function post(path: string, body: unknown): Promise<Response> {
  return fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
}

function root(): HTMLElement {
  const element = document.getElementById("login-root");
  if (!element) throw new Error("the sign-in page is missing its mount point");
  return element;
}

function field(id: string, label: string, type: string, extra = ""): string {
  return [
    `<label class="login-label" for="${esc(id)}">${esc(label)}</label>`,
    `<input class="login-input" id="${esc(id)}" type="${esc(type)}" ${extra}>`,
  ].join("");
}

function messages(): string {
  const parts: string[] = [];
  if (state.notice) {
    parts.push(`<p class="login-notice">${esc(state.notice)}</p>`);
  }
  if (state.error) {
    parts.push(`<p class="login-error" role="alert">${esc(state.error)}</p>`);
  }
  return parts.join("");
}

function title(): string {
  if (state.mode === "change") return "Change password";
  if (state.mode === "totp") return "Two-factor authentication";
  return "Sign in";
}

function subtitle(): string {
  if (state.mode === "totp") {
    return "Open your authenticator app and enter the current 6-digit code. " +
      "A recovery code works here too.";
  }
  if (state.mode === "change") {
    return "Prove the current password, then choose a new one. Every open " +
      "session is closed, including this one.";
  }
  return "Passive OT visibility across the estate. Sign in to continue.";
}

function form(): string {
  const busy = state.busy ? "disabled" : "";

  if (state.mode === "totp") {
    return [
      `<form class="login-card" id="login-form">`,
      field("code", "Authentication code", "text",
        'inputmode="numeric" autocomplete="one-time-code" autofocus ' +
        'placeholder="123456"'),
      messages(),
      `<button class="login-btn" type="submit" ${busy}>`,
      esc(state.busy ? "Verifying…" : "Verify"),
      `</button>`,
      `<button class="login-link" type="button" id="to-signin">Back</button>`,
      `</form>`,
    ].join("");
  }

  if (state.mode === "change") {
    return [
      `<form class="login-card" id="login-form">`,
      field("username", "Operator", "text",
        `autocomplete="username" value="${esc(state.username)}"`),
      field("password", "Current password", "password",
        'autocomplete="current-password"'),
      field("new-password", "New password", "password",
        'autocomplete="new-password"'),
      field("confirm-password", "Confirm new password", "password",
        'autocomplete="new-password"'),
      field("code", "Authentication code (if enrolled)", "text",
        'inputmode="numeric" autocomplete="one-time-code"'),
      messages(),
      `<button class="login-btn" type="submit" ${busy}>`,
      esc(state.busy ? "Changing…" : "Change password"),
      `</button>`,
      `<button class="login-link" type="button" id="to-signin">Back to sign in</button>`,
      `</form>`,
    ].join("");
  }

  return [
    `<form class="login-card" id="login-form">`,
    field("username", "Operator", "text",
      `autocomplete="username" autofocus value="${esc(state.username)}"`),
    field("password", "Password", "password",
      'autocomplete="current-password"'),
    messages(),
    `<button class="login-btn" type="submit" ${busy}>`,
    esc(state.busy ? "Signing in…" : "Sign in"),
    `</button>`,
    `<button class="login-link" type="button" id="to-change">`,
    `Change my password</button>`,
    `</form>`,
  ].join("");
}

function value(id: string): string {
  const element = document.getElementById(id);
  return element instanceof HTMLInputElement ? element.value : "";
}

function draw(): void {
  root().innerHTML = [
    `<h1 class="login-title">${esc(title())}</h1>`,
    `<p class="login-sub">${esc(subtitle())}</p>`,
    form(),
    `<p class="login-help">`,
    `Access is logged. This console shows an operator's plant inventory, so `,
    `a session left open on a shared machine is a standing grant — sign out `,
    `when you are done.`,
    `</p>`,
  ].join("");

  const element = document.getElementById("login-form");
  if (element instanceof HTMLFormElement) {
    element.addEventListener("submit", (event) => {
      event.preventDefault();
      void submit();
    });
  }
  document.getElementById("to-signin")?.addEventListener("click", () => {
    go("signin");
  });
  document.getElementById("to-change")?.addEventListener("click", () => {
    go("change");
  });
}

function go(mode: Mode): void {
  state.mode = mode;
  state.error = "";
  state.notice = "";
  if (mode !== "totp") state.password = "";
  draw();
}

async function detail(response: Response): Promise<{
  detail: string;
  second: boolean;
}> {
  try {
    const body = (await response.json()) as {
      detail?: string;
      second_factor_required?: boolean;
    };
    return {
      detail: body.detail ?? "Sign-in failed",
      second: body.second_factor_required === true,
    };
  } catch {
    return { detail: "Sign-in failed", second: false };
  }
}

interface Entered {
  username: string;
  password: string;
  code: string;
  newPassword: string;
  confirm: string;
}

/**
 * Everything the operator typed, read in one go.
 *
 * BEFORE any `draw()`. `draw()` replaces the container's innerHTML, which
 * destroys the inputs and builds fresh empty ones — so reading a field after
 * drawing reads the new empty box, and the request goes out with an empty
 * username. The server answers "invalid username or password", correctly, and
 * the page tells the operator their password is wrong when it never sent it.
 *
 * That is exactly what happened the first time a person tried to sign in. Every
 * test drove the API directly and none of them typed into the form.
 */
function entered(): Entered {
  return {
    username: value("username").trim(),
    password: value("password"),
    code: value("code").trim(),
    newPassword: value("new-password"),
    confirm: value("confirm-password"),
  };
}

async function submit(): Promise<void> {
  const typed = entered();

  state.error = "";
  state.notice = "";
  state.busy = true;
  draw();

  if (state.mode === "change") {
    await submitChange(typed);
    return;
  }

  if (state.mode === "signin") {
    state.username = typed.username;
    state.password = typed.password;
  }
  const code = state.mode === "totp" ? typed.code : "";

  const response = await post("/api/v1/auth/login", {
    username: state.username,
    password: state.password,
    code,
  });

  if (response.ok) {
    // A hard load, not a client-side navigate: every screen fetches on mount,
    // and this guarantees they all start from the authenticated state rather
    // than reusing anything a pre-sign-in render cached.
    window.location.assign("/");
    return;
  }

  const { detail: message, second } = await detail(response);
  state.busy = false;
  if (second) {
    // The password is already proven. Ask for the code and keep the password
    // in memory so it is not retyped.
    state.mode = "totp";
    state.notice = message;
  } else {
    state.error = message;
    if (state.mode !== "totp") state.password = "";
  }
  draw();
}

async function submitChange(typed: Entered): Promise<void> {
  const username = typed.username;
  const current = typed.password;
  const replacement = typed.newPassword;
  const confirm = typed.confirm;
  const code = typed.code;

  if (replacement !== confirm) {
    state.busy = false;
    state.error = "The two new passwords do not match.";
    draw();
    return;
  }

  const response = await post("/api/v1/auth/password", {
    username,
    current_password: current,
    new_password: replacement,
    code,
  });

  state.busy = false;
  if (response.ok) {
    state.mode = "signin";
    state.username = username;
    state.password = "";
    state.notice = "Password changed. Every session was closed — sign in with " +
      "the new one.";
    draw();
    return;
  }

  const { detail: message, second } = await detail(response);
  if (second) state.notice = message;
  else state.error = message;
  draw();
}

/**
 * If a session is already live, do not show a sign-in form at all.
 *
 * Presenting one to somebody who is already signed in invites them to type a
 * password they did not need to, which is the habit a phishing page relies on.
 */
async function boot(): Promise<void> {
  try {
    const response = await fetch("/api/v1/auth/me", {
      credentials: "same-origin",
    });
    if (response.ok) {
      const body = (await response.json()) as { authenticated?: boolean };
      if (body.authenticated) {
        window.location.assign("/");
        return;
      }
    }
  } catch {
    // Offline or the API is unreachable. Draw the form; the attempt will say so.
  }
  draw();
}

void boot();
