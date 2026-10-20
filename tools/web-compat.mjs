#!/usr/bin/env node
// Independently authored real-browser test; no upstream implementation is copied.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createReadStream } from "node:fs";
import http from "node:http";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { seedAccount } from "./seed-account.mjs";

// Start a quiet process before any request or credential is created. Node's HTTP
// debug setting is cached during startup; unsetting it later cannot silence it.
const verboseEnvironment = ["DEBUG", "DEBUG_FILE", "PWDEBUG", "NODE_DEBUG", "NODE_DEBUG_NATIVE"];
if (verboseEnvironment.some((name) => process.env[name])) {
  const environment = { ...process.env };
  for (const name of verboseEnvironment) delete environment[name];
  const child = spawnSync(process.execPath, [process.argv[1]], { env: environment, stdio: "inherit" });
  process.exit(child.status ?? 1);
}

const CLIENT = {
  distribution: "Vaultwarden Web",
  version: "2026.7.0",
  layerSha256: "d7b6e37be08b53480724fb772207fdfc1d75a2d150580c41348a82e7fa52403b",
  scripts: {
    "/app/main.a46e2355765814789865.js": "fdabe9950b6d9b3c3b2f0ed3fda84d70958e109575c7f2d12a98328790296719",
    "/app/vendor.33eb90af298c6fbb7f03.js": "8df26dcae9aaf64086165d0488be95fa68eb0d7ccce5e8e6c84a66663194079e",
    "/app/polyfills.17d66214ebf3b773befe.js": "ee9e6d5320fbfce55055d9ef4482acdead6ca455064684d5bea722925744fc7e",
  },
};
const ROUTES = new Set([
  "/api/config", "/identity/accounts/prelogin/password", "/api/devices/knowndevice",
  "/identity/connect/token", "/api/sync", "/api/accounts/profile",
  "/api/accounts/revision-date", "/api/auth-requests/pending",
  "/api/ciphers", "/api/ciphers/{id}", "/api/ciphers/{id}/delete",
]);
let stage = "configuration";
const proxies = [];
let browser;
let directory;

function endpoint(name, fallback, protocol) {
  const value = new URL(process.env[name] ?? fallback);
  assert.equal(value.protocol, protocol);
  assert.equal(value.hostname, "127.0.0.1", "Only disposable loopback servers are supported");
  assert.equal(value.username + value.password + value.search + value.hash, "");
  assert.equal(value.pathname, "/");
  return value;
}
function apiPath(path) {
  return /^\/(api|identity|notifications|events|icons)(\/|$)/.test(path);
}
function observedPath(path) {
  if (/^\/api\/ciphers\/[0-9a-f-]{36}$/i.test(path)) return "/api/ciphers/{id}";
  if (/^\/api\/ciphers\/[0-9a-f-]{36}\/delete$/i.test(path)) return "/api/ciphers/{id}/delete";
  return path;
}
async function artifact(reference) {
  const version = await fetch(new URL("/vw-version.json", reference), {
    signal: AbortSignal.timeout(15_000),
  });
  assert.equal(version.status, 200);
  assert.equal((await version.json()).version, CLIENT.version);
  for (const [path, digest] of Object.entries(CLIENT.scripts)) {
    const response = await fetch(new URL(path, reference), { signal: AbortSignal.timeout(15_000) });
    assert.equal(response.status, 200);
    assert.equal(createHash("sha256").update(Buffer.from(await response.arrayBuffer())).digest("hex"), digest);
  }
}
async function proxy(origin, backend, reference, tls) {
  const server = https.createServer(tls, (request, response) => {
    const target = apiPath(request.url) ? backend : reference;
    const upstream = http.request({
      hostname: target.hostname,
      port: target.port,
      path: request.url,
      method: request.method,
      headers: { ...request.headers, host: origin.host },
    }, (incoming) => {
      response.writeHead(incoming.statusCode, incoming.headers);
      incoming.pipe(response);
    });
    upstream.on("error", () => { response.writeHead(502); response.end(); });
    request.pipe(upstream);
  });
  // Notification WebSockets are deliberately outside this login/sync smoke.
  server.on("upgrade", (_request, socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(Number(origin.port || "443"), "127.0.0.1", resolve);
  });
  proxies.push(server);
}
function responseFor(page, method, path) {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === method && observedPath(url.pathname) === path && response.status() === 200;
  }, { timeout: 30_000 });
}
async function run(label, backend, origin, strictVault) {
  stage = `${label}: register disposable account`;
  const email = `web-${randomBytes(12).toString("hex")}@example.test`;
  const password = randomBytes(32).toString("base64");
  // The registration helper's detailed errors can contain server bodies. The
  // top-level error handler below intentionally emits only the fixed stage.
  await seedAccount(backend.origin, email, password);
  const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" });
  const page = await context.newPage();
  const observations = new Map();
  // Never subscribe to browser console, pageerror, requestfailed, or tracing:
  // their error messages and WebSocket URLs may contain tokens or vault data.
  page.on("response", (response) => {
    const url = new URL(response.url());
    const path = observedPath(url.pathname);
    if (url.origin !== origin.origin || !ROUTES.has(path)) return;
    const key = `${response.request().method()} ${path} ${response.status()}`;
    observations.set(key, (observations.get(key) ?? 0) + 1);
  });
  await context.route("**/*", (route) => {
    const url = new URL(route.request().url());
    return url.origin === origin.origin || ["data:", "blob:"].includes(url.protocol)
      ? route.continue() : route.abort();
  });
  try {
    stage = `${label}: real browser login and initial sync`;
    await page.goto(origin.origin);
    await page.getByTestId("login-email-input").fill(email);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.locator("input[type=password]:visible").fill(password);
    await Promise.all([
      responseFor(page, "POST", "/identity/connect/token"),
      responseFor(page, "GET", "/api/sync"),
      responseFor(page, "GET", "/api/accounts/profile"),
      page.getByRole("button", { name: "Log in", exact: true }).click(),
    ]);
    await page.waitForURL((url) => ["#/vault", "#/setup-extension"].includes(url.hash));
    for (const operation of [
      "GET /api/config 200", "POST /identity/accounts/prelogin/password 200",
      "GET /api/devices/knowndevice 200", "POST /identity/connect/token 200",
      "GET /api/sync 200", "GET /api/accounts/profile 200",
    ]) assert.ok(observations.get(operation) > 0);
    const onboarding = new URL(page.url()).hash === "#/setup-extension";
    if (strictVault) {
      stage = `${label}: vault onboarding`;
      if (onboarding) {
        await page.getByRole("button", { name: "Add it later", exact: true }).click();
        await page.getByRole("dialog").getByRole("link", { name: "Skip to web app", exact: true }).click();
      }
      await page.waitForURL((url) => url.hash === "#/vault", { timeout: 15_000 });
      if (onboarding) await page.getByRole("dialog").getByRole("button", { name: "Skip", exact: true }).click();
      stage = `${label}: create encrypted login through UI`;
      const itemName = `web-ui-${randomBytes(8).toString("hex")}`;
      const username = randomBytes(12).toString("hex"), itemPassword = randomBytes(24).toString("base64");
      const editedUsername = randomBytes(12).toString("hex"), editedPassword = randomBytes(24).toString("base64");
      await page.locator("#newItemDropdown").click();
      await page.getByRole("menuitem", { name: "Login", exact: true }).click();
      const dialog = page.getByRole("dialog");
      await dialog.locator("input[formcontrolname=name]").fill(itemName);
      await dialog.locator("input[formcontrolname=username]").fill(username);
      await dialog.locator("input[formcontrolname=password]").fill(itemPassword);
      await Promise.all([
        responseFor(page, "POST", "/api/ciphers"),
        dialog.getByRole("button", { name: "Save", exact: true }).click(),
      ]);
      stage = `${label}: read and edit encrypted login through UI`;
      await dialog.getByTestId("login-username").waitFor({ state: "visible" });
      assert.equal(await dialog.getByTestId("login-username").inputValue(), username);
      assert.equal(await dialog.getByTestId("login-password").inputValue(), itemPassword);
      await dialog.getByRole("button", { name: "Edit", exact: true }).click();
      await dialog.locator("input[formcontrolname=username]").fill(editedUsername);
      await dialog.locator("input[formcontrolname=password]").fill(editedPassword);
      await Promise.all([
        responseFor(page, "PUT", "/api/ciphers/{id}"),
        dialog.getByRole("button", { name: "Save", exact: true }).click(),
      ]);
      await dialog.getByTestId("login-username").waitFor({ state: "visible" });
      assert.equal(await dialog.getByTestId("login-username").inputValue(), editedUsername);
      await dialog.getByRole("button", { name: "Close", exact: true }).click();
      await dialog.waitFor({ state: "hidden" });
      stage = `${label}: lock and master-password unlock`;
      await page.getByRole("button").filter({ has: page.locator("dynamic-avatar") }).first().click();
      await page.getByRole("menuitem", { name: "Lock now", exact: true }).click();
      await page.waitForURL((url) => url.hash.startsWith("#/lock"));
      await page.locator("input[type=password]:visible").fill(password);
      await Promise.all([
        responseFor(page, "GET", "/api/sync"),
        page.getByRole("button", { name: "Unlock", exact: true }).click(),
      ]);
      await page.waitForURL((url) => url.hash === "#/vault");
      stage = `${label}: decrypt persisted edit after unlock`;
      await page.getByRole("button", { name: itemName, exact: true }).click();
      await dialog.getByTestId("login-username").waitFor({ state: "visible" });
      assert.equal(await dialog.getByTestId("login-username").inputValue(), editedUsername);
      assert.equal(await dialog.getByTestId("login-password").inputValue(), editedPassword);
      stage = `${label}: move login to trash through UI`;
      await dialog.getByTestId("delete-cipher-btn").click();
      await Promise.all([
        responseFor(page, "PUT", "/api/ciphers/{id}/delete"),
        page.getByRole("button", { name: "Yes", exact: true }).click(),
      ]);
      await dialog.waitFor({ state: "hidden" });
      await page.getByRole("button", { name: itemName, exact: true }).waitFor({ state: "hidden" });
      stage = `${label}: refreshed vault is locked`;
      await page.reload();
      await page.waitForURL((url) => url.hash.startsWith("#/lock"));
    }
    return {
      server: label,
      result: strictVault ? "login-sync-lock-unlock-reload" : "login-initial-sync",
      postLoginView: onboarding ? "extension-onboarding" : "vault",
      checks: {
        passwordLogin: "passed", initialSync: "passed", authenticatedProfile: "passed",
        vaultNavigation: strictVault ? "passed" : "not-requested",
        lock: strictVault ? "passed" : "not-requested",
        passwordUnlockAndSync: strictVault ? "passed" : "not-requested",
        reloadLocksVault: strictVault ? "passed" : "not-requested",
        itemRoundtrip: strictVault ? "passed" : "not-requested", notifications: "not-tested",
      },
      http: [...observations].sort().map(([operation, count]) => ({ operation, count })),
    };
  } finally { await context.close(); }
}

try {
  const reference = endpoint("BW_WEB_REFERENCE_BASE", "http://127.0.0.1:18181", "http:");
  const target = endpoint("BW_WEB_TARGET_BASE", "http://127.0.0.1:18182", "http:");
  const referenceOrigin = endpoint("BW_WEB_REFERENCE_ORIGIN", "https://127.0.0.1:18184", "https:");
  const targetOrigin = endpoint("BW_WEB_TARGET_ORIGIN", "https://127.0.0.1:18185", "https:");
  assert.notEqual(referenceOrigin.port, targetOrigin.port);
  assert.ok(process.env.BW_WEB_CHROMIUM, "Set BW_WEB_CHROMIUM to the pinned Chromium executable");
  stage = "pinned web-client artifact verification";
  await artifact(reference);
  directory = await mkdtemp(join(tmpdir(), "no-warden-web-compat-tls-"));
  const key = join(directory, "key.pem"), cert = join(directory, "cert.pem");
  stage = "ephemeral HTTPS certificate";
  assert.equal(spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "1"], { stdio: "ignore" }).status, 0);
  const tls = { key: await readFile(key), cert: await readFile(cert) };
  await proxy(referenceOrigin, reference, reference, tls);
  await proxy(targetOrigin, target, reference, tls);
  stage = "pinned Chromium artifact verification";
  const chromiumDigest = createHash("sha256");
  for await (const chunk of createReadStream(process.env.BW_WEB_CHROMIUM)) chromiumDigest.update(chunk);
  assert.equal(chromiumDigest.digest("hex"), "2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801");
  stage = "pinned Chromium launch";
  const module = process.env.BW_WEB_PLAYWRIGHT_MODULE
    ? pathToFileURL(process.env.BW_WEB_PLAYWRIGHT_MODULE).href
    : new URL("./web-compat/node_modules/playwright-core/index.mjs", import.meta.url).href;
  const driver = JSON.parse(await readFile(new URL("./package.json", module), "utf8"));
  assert.equal(driver.version, "1.64.1");
  const { chromium } = await import(module);
  browser = await chromium.launch({ executablePath: process.env.BW_WEB_CHROMIUM, headless: true });
  assert.equal(browser.version(), "149.0.7827.55");
  // Catch broken host fontconfig before it makes the client's input appear empty.
  const readiness = await browser.newPage();
  await readiness.goto("data:text/html,<p>font and input readiness</p><input>");
  await readiness.locator("input").fill("test-input");
  assert.equal(await readiness.locator("input").inputValue(), "test-input");
  assert.match(await readiness.locator("body").innerText(), /font and input readiness/);
  await readiness.close();
  const results = [];
  for (const [label, backend, origin] of [["vaultwarden", reference, referenceOrigin], ["no-warden", target, targetOrigin]]) {
    const mode = process.env.BW_WEB_VAULT_MODE ?? "both";
    assert.ok(["login", "target", "both"].includes(mode));
    results.push(await run(label, backend, origin, mode === "both" || (mode === "target" && label === "no-warden")));
  }
  console.log(JSON.stringify({ client: CLIENT, chromium: browser.version(), playwright: driver.version, results }, null, 2));
} catch {
  // Do not print exception messages/stacks, URLs, browser diagnostics, or bodies.
  console.error(`FAIL web compatibility at ${stage}`);
  process.exitCode = 1;
} finally {
  if (browser) await browser.close().catch(() => {});
  await Promise.all(proxies.map((server) => new Promise((resolve) => {
    server.closeAllConnections(); server.close(resolve);
  })));
  if (directory) await rm(directory, { recursive: true, force: true });
}
