/**
 * Drive the sign-in FORM, not the API behind it.
 *
 * WHY THIS EXISTS
 * Every test of the sign-in path drove `/api/v1/auth/login` directly, and they
 * all passed while the page was incapable of signing anyone in. `submit()`
 * called `draw()` first, which replaces innerHTML and destroys the inputs, and
 * then read their values — so it posted an empty username and password every
 * time. The server answered "invalid username or password", correctly, and the
 * page told the operator their password was wrong when it had never sent it.
 *
 * A person found that in about four seconds. So this types into the form the
 * way a person does, and asserts on what actually reaches the network.
 *
 * The DOM here is a stub, not jsdom: the page needs `getElementById`,
 * `innerHTML` and `addEventListener`, and a dependency-free stub that provides
 * exactly those keeps this runnable anywhere `node` is, which is what makes it
 * cheap enough to keep.
 *
 * Usage: node form-check.mjs
 */

const failures = [];

function check(name, ok, detail = "") {
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${name.padEnd(52)} ${detail}`);
  if (!ok) failures.push(name);
}

// ── the smallest DOM the page uses ──────────────────────────────────────────

class Element {
  constructor(tag = "div", id = "") {
    this.tagName = tag.toUpperCase();
    this.id = id;
    this.value = "";
    this.listeners = {};
    this.children = [];
    this._html = "";
  }

  get innerHTML() {
    return this._html;
  }

  /**
   * Parsing is deliberately crude: the page only ever needs to find elements by
   * id and read a value off them, so ids and input tags are all this extracts.
   * A real parser would be a dependency, and the thing under test is the ORDER
   * of reads and redraws, not HTML parsing.
   */
  set innerHTML(html) {
    this._html = html;
    this.children = [];
    const pattern = /<(input|button|form|a)\b[^>]*\bid="([^"]+)"[^>]*>/g;
    let match;
    while ((match = pattern.exec(html)) !== null) {
      // A fresh element every time, exactly as a browser does — which is the
      // whole point: whatever was typed into the old one is gone.
      this.children.push(new Element(match[1], match[2]));
    }
  }

  addEventListener(name, handler) {
    (this.listeners[name] ??= []).push(handler);
  }

  dispatch(name, event = {}) {
    for (const handler of this.listeners[name] ?? []) handler(event);
  }
}

const root = new Element("div", "login-root");

function byId(id) {
  if (id === "login-root") return root;
  return root.children.find((child) => child.id === id) ?? null;
}

const requests = [];
let nextResponse = { ok: true, status: 200, body: {} };

globalThis.document = { getElementById: byId };
globalThis.window = { location: { assign(url) { globalThis.__assigned = url; } } };
globalThis.HTMLInputElement = Element;
globalThis.HTMLFormElement = Element;
globalThis.fetch = async (url, init = {}) => {
  requests.push({
    url: String(url),
    body: init.body ? JSON.parse(init.body) : null,
  });
  return {
    ok: nextResponse.ok,
    status: nextResponse.status,
    json: async () => nextResponse.body,
  };
};

// `boot()` calls /auth/me first and draws the form when nobody is signed in.
nextResponse = { ok: true, status: 200, body: { authenticated: false } };
await import("./dist/login.js");
await new Promise((resolve) => setTimeout(resolve, 20));

console.log("-- the form draws ----------------------------------------------");
check("the sign-in form is rendered", root.innerHTML.includes("login-form"),
  `${root.innerHTML.length} bytes`);
check("it has a username and a password field",
  byId("username") !== null && byId("password") !== null);

console.log("\n-- what a person types is what gets sent -----------------------");
byId("username").value = "  Operator  ";
byId("password").value = "alder-lantern-alder-anchor";

requests.length = 0;
nextResponse = { ok: false, status: 401, body: { detail: "invalid username or password" } };
byId("login-form").dispatch("submit", { preventDefault() {} });
await new Promise((resolve) => setTimeout(resolve, 20));

const sent = requests.find((r) => r.url.includes("/auth/login"));
check("a login request was made", sent !== undefined,
  requests.map((r) => r.url).join(", "));
check("it carried the username that was typed",
  sent?.body?.username === "Operator",
  JSON.stringify(sent?.body?.username));
check("it carried the password that was typed",
  sent?.body?.password === "alder-lantern-alder-anchor",
  sent?.body?.password ? "(present)" : "(EMPTY — the bug)");

console.log("\n-- the second factor step keeps the password -------------------");
byId("username").value = "operator";
byId("password").value = "alder-lantern-alder-anchor";
requests.length = 0;
nextResponse = {
  ok: false, status: 401,
  body: { detail: "a second factor is required", second_factor_required: true },
};
byId("login-form").dispatch("submit", { preventDefault() {} });
await new Promise((resolve) => setTimeout(resolve, 20));

check("the page moved to the code step",
  root.innerHTML.includes("Authentication code"));
check("and did not ask for the password again",
  byId("password") === null);

byId("code").value = "123456";
requests.length = 0;
nextResponse = { ok: true, status: 200, body: {} };
byId("login-form").dispatch("submit", { preventDefault() {} });
await new Promise((resolve) => setTimeout(resolve, 20));

const second = requests.find((r) => r.url.includes("/auth/login"));
check("the code request still carried the password",
  second?.body?.password === "alder-lantern-alder-anchor",
  second?.body?.password ? "(present)" : "(EMPTY — retyping required)");
check("and the code", second?.body?.code === "123456",
  JSON.stringify(second?.body?.code));
check("a successful sign-in leaves for the console",
  globalThis.__assigned === "/", globalThis.__assigned);

console.log("\n----------------------------------------------------------------");
if (failures.length) {
  console.error(`FAILED: ${failures.join("; ")}`);
  process.exit(1);
}
console.log("the form sends what was typed into it");
