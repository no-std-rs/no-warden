#!/usr/bin/env node
/** Exercise the real, pinned Bitwarden CLI against any compatible test server. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fork, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { seedAccount } from "./seed-account.mjs";

const toolsDir = dirname(fileURLToPath(import.meta.url));
const localBw = join(toolsDir, "node_modules/.bin/bw");
const bw = process.env.BW_BIN ?? (existsSync(localBw) ? localBw : "bw");
const server = (process.env.BW_E2E_SERVER ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const email = process.env.BW_E2E_EMAIL ?? `no-warden-${Date.now()}-${randomBytes(4).toString("hex")}@example.test`;
const password = process.env.BW_E2E_PASSWORD ?? randomBytes(32).toString("base64url");
const appdata = mkdtempSync(join(tmpdir(), "no-warden-bw-"));
const tlsDirectory = mkdtempSync(join(tmpdir(), "no-warden-tls-"));
const env = {
  ...process.env,
  BITWARDENCLI_APPDATA_DIR: appdata,
  BW_E2E_PASSWORD: password,
  // This is a disposable test account and the CLI must never prompt in CI.
  BW_NOINTERACTION: "true",
};
delete env.BW_SESSION;
let commands = 0;
let proxy;

async function cliServer() {
  if (!server.startsWith("http:")) return server;
  proxy = fork(join(toolsDir, "tls-proxy.mjs"), [server, tlsDirectory], {
    stdio: ["ignore", "ignore", "pipe", "ipc"],
  });
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Test TLS proxy startup timed out")), 15_000);
    proxy.once("message", ({ url, cert }) => {
      clearTimeout(timeout);
      env.NODE_EXTRA_CA_CERTS = cert;
      resolve(url);
    });
    proxy.once("exit", code => {
      clearTimeout(timeout);
      reject(new Error(`Test TLS proxy exited during startup (${code}); openssl and a loopback server are required.`));
    });
  });
}

function run(args, options = {}) {
  commands += 1;
  if (process.env.BW_E2E_VERBOSE) console.log(`    bw ${args.slice(0, 2).join(" ")}`);
  const result = spawnSync(bw, [...args, "--nointeraction"], {
    env: { ...env, ...options.env }, encoding: "utf8", timeout: 90_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (options.failure) {
    assert(!result.error && result.status !== null, `bw ${args.slice(0, 2).join(" ")} could not complete`);
    assert.notEqual(result.status, 0, `bw ${args.slice(0, 2).join(" ")} unexpectedly succeeded`);
    return;
  }
  if (result.error || result.status !== 0) {
    // Arguments may contain encrypted or plaintext vault items; never print them.
    throw new Error(`bw ${args.slice(0, 2).join(" ")} failed (${result.status}): ${result.error?.message ?? result.stderr.trim()}`);
  }
  return result.stdout.trim();
}

function json(args) { return JSON.parse(run(args)); }
function encode(value) { return Buffer.from(JSON.stringify(value)).toString("base64"); }
function stage(name) { console.log(`  ${name}`); }
function login() {
  env.BW_SESSION = run(["login", email, "--passwordenv", "BW_E2E_PASSWORD", "--raw"]);
  assert(env.BW_SESSION.length > 20, "CLI did not return an unlock session");
}

try {
  const clientServer = await cliServer();
  const version = run(["--version"]);
  console.log(`Bitwarden CLI ${version}: ${server}`);
  await seedAccount(server, email, password);
  run(["config", "server", clientServer]);
  stage("Reject incorrect password, then authenticate and decrypt the user key");
  run(["login", email, "--passwordenv", "BW_E2E_PASSWORD", "--raw"], {
    failure: true, env: { BW_E2E_PASSWORD: `${password}-incorrect` },
  });
  login();
  assert.equal(json(["status"]).status, "unlocked");
  run(["sync"]);
  assert.deepEqual(json(["list", "items"]), []);

  stage("Create, read, and rename an encrypted folder");
  const folder = json(["create", "folder", encode({ name: "Compatibility folder" })]);
  assert(folder.id);
  assert.equal(folder.name, "Compatibility folder");
  assert.equal(json(["get", "folder", folder.id]).name, folder.name);
  const renamedFolder = json(["edit", "folder", folder.id, encode({ ...folder, name: "Renamed folder" })]);
  assert.equal(renamedFolder.name, "Renamed folder");

  stage("Create and decrypt a login item with URI, notes, custom field, and folder");
  const item = json(["create", "item", encode({
    type: 1, name: "Compatibility login", notes: "Encrypted note: café 🔐", favorite: true,
    folderId: folder.id, reprompt: 0,
    login: {
      username: "test-user", password: "test-item-password",
      totp: "JBSWY3DPEHPK3PXP", uris: [{ uri: "https://example.test/login", match: null }],
    },
    fields: [{ name: "Test field", value: "Private field value", type: 0 }],
  })]);
  assert(item.id);
  assert.equal(item.name, "Compatibility login");
  const fetched = json(["get", "item", item.id]);
  assert.equal(fetched.login.password, "test-item-password");
  assert.equal(fetched.notes, "Encrypted note: café 🔐");
  assert.equal(fetched.fields[0].value, "Private field value");
  assert.equal(fetched.folderId, folder.id);
  assert.equal(json(["list", "items", "--search", "Compatibility login"]).length, 1);

  stage("Edit encrypted fields, sync, lock, and unlock");
  const edited = json(["edit", "item", item.id, encode({
    ...fetched, name: "Edited compatibility login", notes: "Updated encrypted note",
    login: { ...fetched.login, password: "changed-item-password" },
  })]);
  assert.equal(edited.login.password, "changed-item-password");
  run(["sync"]);
  run(["lock"]);
  delete env.BW_SESSION;
  assert.equal(json(["status"]).status, "locked");
  env.BW_SESSION = run(["unlock", "--passwordenv", "BW_E2E_PASSWORD", "--raw"]);
  assert.equal(json(["get", "item", item.id]).login.password, "changed-item-password");

  stage("Logout/login and verify server persistence with a fresh client cache");
  run(["logout"]);
  delete env.BW_SESSION;
  rmSync(appdata, { recursive: true, force: true });
  run(["config", "server", clientServer]);
  login();
  const persisted = json(["get", "item", item.id]);
  assert.equal(persisted.name, "Edited compatibility login");
  assert.equal(persisted.login.password, "changed-item-password");
  assert.equal(json(["get", "folder", folder.id]).name, "Renamed folder");

  stage("Trash, restore, permanently delete the cipher, and delete its folder");
  run(["delete", "item", item.id]);
  assert.equal(json(["list", "items"]).length, 0);
  assert.equal(json(["list", "items", "--trash"]).length, 1);
  run(["restore", "item", item.id]);
  assert.equal(json(["get", "item", item.id]).login.password, "changed-item-password");
  run(["delete", "item", item.id]);
  run(["delete", "item", item.id, "--permanent"]);
  run(["delete", "folder", folder.id]);
  run(["sync"]);
  assert.deepEqual(json(["list", "items"]), []);
  assert.deepEqual(json(["list", "items", "--trash"]), []);
  // The official CLI appends a synthetic "No Folder" entry with id: "".
  assert.equal(json(["list", "folders"]).filter(f => f.id).length, 0);
  run(["logout"]);
  console.log(`PASS: ${commands} real CLI commands; encrypted login/folder lifecycle and fresh-cache persistence verified.`);
} finally {
  proxy?.kill();
  rmSync(appdata, { recursive: true, force: true });
  rmSync(tlsDirectory, { recursive: true, force: true });
}
