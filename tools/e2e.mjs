#!/usr/bin/env node
/** Exercise the real, pinned Bitwarden CLI against any compatible test server. */
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fork } from "node:child_process";
import { fileURLToPath } from "node:url";
import { registration, seedAccount } from "./seed-account.mjs";
import { runCliProcess } from "./cli-process.mjs";

const toolsDir = dirname(fileURLToPath(import.meta.url));
const localBw = join(toolsDir, "node_modules/.bin/bw");
const bw = process.env.BW_BIN ?? (existsSync(localBw) ? localBw : "bw");
const server = (process.env.BW_E2E_SERVER ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const email = process.env.BW_E2E_EMAIL ?? `no-warden-${Date.now()}-${randomBytes(4).toString("hex")}@example.test`;
const password = process.env.BW_E2E_PASSWORD ?? randomBytes(32).toString("base64url");
const appdata = mkdtempSync(join(tmpdir(), "no-warden-bw-"));
const tlsDirectory = mkdtempSync(join(tmpdir(), "no-warden-tls-"));
const outputDirectory = mkdtempSync(join(tmpdir(), "no-warden-cli-"));
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
let lastRunMetadata;

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
  const result = runCliProcess(bw, [...args, "--nointeraction"], {
    env: { ...env, ...options.env }, cacheDirectory: outputDirectory,
  });
  lastRunMetadata = {
    status: result.status, signal: result.signal, errorCode: result.error?.code ?? null,
    stdoutBytes: result.stdoutBytes, stderrBytes: result.stderrBytes,
  };
  if (options.failure) {
    assert(!result.error && result.status !== null, `bw ${args.slice(0, 2).join(" ")} could not complete`);
    assert.notEqual(result.status, 0, `bw ${args.slice(0, 2).join(" ")} unexpectedly succeeded`);
    return;
  }
  if (result.error || result.status !== 0) {
    // Arguments may contain encrypted or plaintext vault items; never print them.
    throw new Error(`bw ${args.slice(0, 2).join(" ")} failed: ${JSON.stringify(lastRunMetadata)}`);
  }
  return result.stdout.trim();
}

function json(args) { return JSON.parse(run(args)); }
function encode(value) { return Buffer.from(JSON.stringify(value)).toString("base64"); }
function stage(name) { console.log(`  ${name}`); }
function login() {
  const session = run(["login", email, "--passwordenv", "BW_E2E_PASSWORD", "--raw"]);
  if (session.length <= 20) {
    const metadata = lastRunMetadata;
    let authStatus = "unavailable";
    try {
      const status = json(["status"]).status;
      if (["unauthenticated", "locked", "unlocked"].includes(status)) authStatus = status;
    } catch { /* Keep the original failure, without exposing any CLI output. */ }
    assert.fail(`CLI did not return an unlock session: ${JSON.stringify({ ...metadata, authStatus })}`);
  }
  env.BW_SESSION = session;
}

async function apiRequest(path, { method = "POST", token, body, form } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers["content-type"] = "application/json";
  if (form) headers["content-type"] = "application/x-www-form-urlencoded";
  const response = await fetch(`${server}${path}`, {
    method, headers, signal: AbortSignal.timeout(15_000),
    body: form ? new URLSearchParams(form) : body ? JSON.stringify(body) : undefined,
  });
  assert.equal(response.status, 200, `${method} ${path}: HTTP ${response.status}`);
  return response.json();
}

function apiUnlock() {
  env.BW_SESSION = run(["unlock", "--passwordenv", "BW_E2E_PASSWORD", "--raw"]);
  assert(env.BW_SESSION.length > 20, "API-key login must unlock with the master password before decrypting");
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
  assert.equal(commands, 37, "The original CLI lifecycle must retain all 37 commands");

  stage("Import JSON and CSV vaults with escaped folders and multiple encrypted item types");
  login();
  const jsonFolders = [
    { id: randomUUID(), name: 'JSON import "quoted" \\ café 🔐' },
    { id: randomUUID(), name: "JSON import/第二 folder" },
  ];
  const importItems = [
    {
      id: randomUUID(), type: 1, name: 'Imported JSON login "quoted"', folderId: jsonFolders[0].id,
      organizationId: null, favorite: true, reprompt: 0, notes: "Imported café 🔐\nsecond line",
      fields: [{ name: "Imported custom field", value: "preserved field value", type: 0 }],
      login: { username: "json-user", password: "json-import-password", uris: [{ uri: "https://example.test/import", match: null }] },
    },
    {
      id: randomUUID(), type: 2, name: "Imported JSON secure note", folderId: jsonFolders[1].id,
      organizationId: null, favorite: false, reprompt: 0, notes: 'Private note "quoted" \\ 雪', secureNote: { type: 0 },
    },
    {
      id: randomUUID(), type: 3, name: "Imported JSON card", folderId: jsonFolders[0].id,
      organizationId: null, favorite: false, reprompt: 0, notes: null,
      card: { cardholderName: "Test Cardholder", brand: "Visa", number: "4111111111111111", expMonth: "12", expYear: "2035", code: "123" },
    },
    {
      id: randomUUID(), type: 4, name: "Imported JSON identity", folderId: null,
      organizationId: null, favorite: false, reprompt: 0, notes: null,
      identity: { firstName: "Test", lastName: "Identity", email: "identity@example.test", city: "Montréal" },
    },
  ];
  const jsonPath = join(outputDirectory, "import.json");
  writeFileSync(jsonPath, JSON.stringify({ encrypted: false, folders: jsonFolders, items: importItems }), { mode: 0o600 });
  const csvFolderName = 'CSV import "quoted", \\ café 🔑';
  // The pinned CSV importer normalizes path separators and creates ancestors.
  const normalizedCsvFolder = csvFolderName.replaceAll("\\", "/");
  const csvParentFolder = normalizedCsvFolder.slice(0, normalizedCsvFolder.lastIndexOf("/"));
  const csvLoginName = "Imported CSV login";
  const csvNoteName = "Imported CSV secure note";
  const csvColumns = ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"];
  const csvCell = value => `"${String(value).replaceAll('"', '""')}"`;
  const csvRows = [
    [csvFolderName, "1", "login", csvLoginName, 'CSV note "quoted"\nsecond line', "CSV field: preserved CSV value", "0", "https://example.test/csv", "csv-user", "csv-import-password", ""],
    [csvFolderName, "0", "note", csvNoteName, "CSV secure note café 🔐", "", "0", "", "", "", ""],
  ];
  const csvPath = join(outputDirectory, "import.csv");
  writeFileSync(csvPath, [csvColumns, ...csvRows].map(row => row.map(csvCell).join(",")).join("\r\n"), { mode: 0o600 });
  run(["import", "bitwardenjson", jsonPath]);
  run(["import", "bitwardencsv", csvPath]);
  run(["sync"]);

  function verifyImports(items, folders) {
    assert.equal(items.length, 6, "Both imports must preserve all six items");
    const realFolders = folders.filter(candidate => candidate.id);
    assert.equal(realFolders.length, 4, "JSON and CSV imports must preserve their folders and CSV ancestor");
    const folderIds = new Map(realFolders.map(candidate => [candidate.name, candidate.id]));
    for (const expectedFolder of [...jsonFolders.map(folder => folder.name), normalizedCsvFolder, csvParentFolder]) {
      assert(folderIds.has(expectedFolder), "An escaped imported folder name did not decrypt correctly");
    }
    const byName = new Map(items.map(candidate => [candidate.name, candidate]));
    for (const expected of importItems) {
      const actual = byName.get(expected.name);
      assert(actual && actual.type === expected.type, "An imported JSON item did not decrypt correctly");
      assert.notEqual(actual.id, expected.id, "Import must allocate fresh item IDs");
      const expectedFolder = jsonFolders.find(folder => folder.id === expected.folderId)?.name;
      assert.equal(actual.folderId ?? null, expectedFolder ? folderIds.get(expectedFolder) : null);
      assert.equal(actual.organizationId ?? null, null);
    }
    const loginItem = byName.get(importItems[0].name);
    assert(loginItem.login.password === importItems[0].login.password, "JSON login password did not decrypt correctly");
    assert(loginItem.notes === importItems[0].notes, "JSON notes did not survive import");
    assert(loginItem.fields[0].value === importItems[0].fields[0].value, "JSON custom field did not survive import");
    assert(byName.get(importItems[1].name).notes === importItems[1].notes, "Secure-note content did not decrypt correctly");
    assert(byName.get(importItems[2].name).card.number === importItems[2].card.number, "Card content did not decrypt correctly");
    assert(byName.get(importItems[3].name).identity.city === importItems[3].identity.city, "Identity content did not decrypt correctly");
    const csvLogin = byName.get(csvLoginName);
    const csvNote = byName.get(csvNoteName);
    assert(csvLogin?.type === 1 && csvNote?.type === 2, "CSV item types did not survive import");
    assert(csvLogin.login.password === "csv-import-password", "CSV login password did not decrypt correctly");
    assert(csvLogin.notes === csvRows[0][4], "Multiline CSV notes did not survive import");
    assert(csvLogin.fields[0].value === "preserved CSV value", "CSV custom field did not survive import");
    assert(csvNote.notes === csvRows[1][4], "CSV secure-note content did not decrypt correctly");
    assert.equal(csvLogin.folderId, folderIds.get(normalizedCsvFolder));
    assert.equal(csvNote.folderId, folderIds.get(normalizedCsvFolder));
    return byName;
  }
  const imported = verifyImports(json(["list", "items"]), json(["list", "folders"]));
  stage("Discard the client cache, log in again, and decrypt every imported item and folder link");
  run(["logout"]);
  delete env.BW_SESSION;
  rmSync(appdata, { recursive: true, force: true });
  run(["config", "server", clientServer]);
  login();
  const freshImports = verifyImports(json(["list", "items"]), json(["list", "folders"]));
  for (const name of [importItems[0].name, csvLoginName]) {
    const fetchedImport = json(["get", "item", imported.get(name).id]);
    assert(fetchedImport.login.password === freshImports.get(name).login.password, "Fresh-cache get did not decrypt the imported password");
  }
  run(["logout"]);
  assert.equal(commands, 51, "The existing lifecycle and import suite must retain all 51 commands");

  stage("Archive an encrypted item, discard the cache, and restore it from the archive");
  login();
  const archiveItem = imported.get(importItems[0].name);
  run(["archive", "item", archiveItem.id]);
  run(["sync"]);
  const archived = json(["list", "items", "--archived"]);
  assert.equal(archived.length, 1);
  assert.equal(archived[0].id, archiveItem.id);
  assert(archived[0].login.password === importItems[0].login.password, "Archived password must decrypt");
  assert.equal(json(["list", "items"]).length, 5);
  run(["logout"]);
  delete env.BW_SESSION;
  rmSync(appdata, { recursive: true, force: true });
  run(["config", "server", clientServer]);
  login();
  const freshArchived = json(["list", "items", "--archived"]);
  assert.equal(freshArchived.length, 1);
  assert.equal(freshArchived[0].id, archiveItem.id);
  assert(freshArchived[0].login.password === importItems[0].login.password, "Fresh-cache archived password must decrypt");
  const freshArchiveItem = json(["get", "item", archiveItem.id]);
  assert.equal(typeof freshArchiveItem.archivedDate, "string");
  assert(freshArchiveItem.notes === importItems[0].notes, "Fresh-cache archived notes must decrypt");
  run(["restore", "item", archiveItem.id]);
  run(["sync"]);
  assert.deepEqual(json(["list", "items", "--archived"]), []);
  const unarchived = json(["get", "item", archiveItem.id]);
  assert.equal(unarchived.archivedDate ?? null, null);
  assert(unarchived.login.password === importItems[0].login.password, "Unarchived password must decrypt");
  assert.equal(unarchived.folderId, archiveItem.folderId);
  run(["logout"]);
  assert.equal(commands, 66, "The archive extension must exercise all 66 CLI commands");

  stage("Authenticate with a personal API key, then unlock and decrypt with the master password");
  delete env.BW_SESSION;
  const masterPasswordHash = registration(email, password).masterPasswordHash;
  const passwordBearer = await apiRequest("/identity/connect/token", {
    form: {
      grant_type: "password", username: email, password: masterPasswordHash,
      scope: "api offline_access", client_id: "cli", deviceType: "8",
      deviceIdentifier: randomUUID(), deviceName: "CLI API-key fixture",
    },
  });
  const profile = await apiRequest("/api/accounts/profile", { method: "GET", token: passwordBearer.access_token });
  const key = await apiRequest("/api/accounts/api-key", {
    token: passwordBearer.access_token, body: { masterPasswordHash },
  });
  assert(typeof key.apiKey === "string" && /^[A-Za-z0-9]{30}$/.test(key.apiKey), "API key response must contain a valid secret");
  env.BW_CLIENTID = `user.${profile.id}`;
  env.BW_CLIENTSECRET = key.apiKey;
  run(["login", "--apikey"], { failure: true, env: { BW_CLIENTSECRET: `${key.apiKey}-incorrect` } });
  run(["login", "--apikey"]);
  assert.equal(json(["status"]).status, "locked");
  apiUnlock();
  assert.equal(json(["status"]).status, "unlocked");
  run(["sync"]);
  const apiItem = json(["get", "item", archiveItem.id]);
  assert(apiItem.login.password === importItems[0].login.password, "API-key login and password unlock must decrypt the item");
  run(["logout"]);
  delete env.BW_SESSION;
  rmSync(appdata, { recursive: true, force: true });
  run(["config", "server", clientServer]);
  run(["login", "--apikey"]);
  assert.equal(json(["status"]).status, "locked");
  apiUnlock();
  run(["sync"]);
  verifyImports(json(["list", "items"]), json(["list", "folders"]));
  const apiFresh = json(["get", "item", archiveItem.id]);
  assert(apiFresh.notes === importItems[0].notes, "Fresh-cache API login must decrypt encrypted notes");
  run(["logout"]);
  delete env.BW_SESSION;

  stage("Rotate the personal API key, reject the old secret, and decrypt after login with the new key");
  const rotated = await apiRequest("/api/accounts/rotate-api-key", {
    token: passwordBearer.access_token, body: { masterPasswordHash },
  });
  assert(typeof rotated.apiKey === "string" && rotated.apiKey !== key.apiKey, "Rotation must replace the API secret");
  run(["login", "--apikey"], { failure: true });
  env.BW_CLIENTSECRET = rotated.apiKey;
  run(["login", "--apikey"]);
  assert.equal(json(["status"]).status, "locked");
  apiUnlock();
  run(["sync"]);
  const rotatedItem = json(["get", "item", archiveItem.id]);
  assert(rotatedItem.login.password === importItems[0].login.password, "Rotated API-key login must preserve decryptability");
  run(["logout"]);
  assert.equal(commands, 90, "API-key authentication must retain the original 66 and exercise all 90 CLI commands");
  console.log(`PASS: ${commands} real CLI commands; original 66 plus API-key login, password unlock, fresh-cache decryption, and key rotation verified.`);
} finally {
  proxy?.kill();
  rmSync(appdata, { recursive: true, force: true });
  rmSync(tlsDirectory, { recursive: true, force: true });
  rmSync(outputDirectory, { recursive: true, force: true });
}
