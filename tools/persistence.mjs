#!/usr/bin/env node
/** Verify SQLite durability by stopping and restarting a real server process. */
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { registration } from "./seed-account.mjs";

const binary = process.env.NO_WARDEN_BIN
  ? resolve(process.env.NO_WARDEN_BIN)
  : fileURLToPath(new URL("../target/debug/no-warden-server", import.meta.url));
const directory = mkdtempSync(join(tmpdir(), "no-warden-persistence-"));
const database = join(directory, "vault.db");
const children = new Set();
let server;

async function freePort() {
  const listener = createServer();
  await new Promise((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", resolve);
  });
  const port = listener.address().port;
  await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
  return port;
}

async function startServer(port) {
  const child = spawn(binary, [], {
    env: {
      ...process.env,
      NO_WARDEN_DB: database,
      NO_WARDEN_BIND: `127.0.0.1:${port}`,
      NO_WARDEN_URL: `http://127.0.0.1:${port}`,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  const record = { child, completed: false, stderr: "", error: null, code: null, signal: null };
  children.add(record);
  child.stderr.on("data", chunk => { record.stderr = `${record.stderr}${chunk}`.slice(-4096); });
  child.on("error", error => { record.error = error; });
  record.closed = new Promise(resolve => child.once("close", (code, signal) => {
    Object.assign(record, { completed: true, code, signal });
    resolve();
  }));
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (record.error || record.completed) {
      throw new Error(`Standalone server could not start: ${record.error?.message ?? record.stderr.trim()}`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(200) });
      if (response.ok && (await response.json()).status === "ok") return record;
    } catch { /* The child may still be opening its database and listener. */ }
    await delay(50);
  }
  throw new Error("Standalone server did not become healthy within the startup deadline.");
}

async function stopServer(record, strict = true) {
  if (record.completed) {
    if (strict) assert.equal(record.code, 0, "Standalone server exited unexpectedly");
    return;
  }
  record.child.kill("SIGINT");
  let timer;
  const graceful = await Promise.race([
    record.closed.then(() => true),
    new Promise(resolve => { timer = setTimeout(() => resolve(false), 5000); }),
  ]);
  clearTimeout(timer);
  if (!graceful) {
    record.child.kill("SIGKILL");
    await record.closed;
  }
  if (strict) {
    assert(graceful, "Standalone server did not stop gracefully");
    assert.equal(record.code, 0, "Standalone server failed during graceful shutdown");
  }
}

async function request(path, { method = "GET", token, body, form } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  if (form) headers["content-type"] = "application/x-www-form-urlencoded";
  const response = await fetch(`${server}${path}`, {
    method, headers, signal: AbortSignal.timeout(15_000),
    body: form ? new URLSearchParams(form) : body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  assert(response.ok, `${method} ${path}: HTTP ${response.status}`);
  return text ? JSON.parse(text) : null;
}

try {
  const port = await freePort();
  server = `http://127.0.0.1:${port}`;
  let child = await startServer(port);
  const account = registration(`restart-${randomUUID()}@example.test`, randomBytes(32).toString("base64url"));
  account.name = 'Restart "quoted" \\ café 🔐';
  await request("/api/accounts/register", { method: "POST", body: account });
  const session = await request("/identity/connect/token", {
    method: "POST",
    form: {
      grant_type: "password", username: account.email, password: account.masterPasswordHash,
      scope: "api offline_access", client_id: "cli", deviceType: "8",
      deviceIdentifier: randomUUID(), deviceName: "restart durability test",
    },
  });
  assert.equal(session.Key, account.key);
  const token = session.access_token;
  const folder = await request("/api/folders", { method: "POST", token, body: { name: account.key } });
  const body = {
    type: 1, name: account.key, notes: account.key, favorite: false, reprompt: 0,
    folderId: folder.id, organizationId: null, fields: [],
    login: { username: account.key, password: account.key, uris: [] },
    futureProtocolExtension: { encryptedValue: account.key, label: '"quoted" café 🔐' },
  };
  const initial = await request("/api/ciphers", { method: "POST", token, body });
  const active = await request(`/api/ciphers/${initial.id}`, {
    method: "PUT", token,
    body: { ...initial, favorite: true, lastKnownRevisionDate: initial.revisionDate },
  });
  assert(Date.parse(active.revisionDate) > Date.parse(initial.revisionDate));
  const deleted = await request("/api/ciphers", { method: "POST", token, body });
  await request(`/api/ciphers/${deleted.id}/delete`, { method: "PUT", token });
  const trashed = await request(`/api/ciphers/${deleted.id}`, { token });
  assert.equal(typeof trashed.deletedDate, "string");
  const preImport = await request("/api/sync", { token });
  await request("/api/ciphers/import", {
    method: "POST", token,
    body: {
      folders: [{ id: folder.id, name: account.keys.encryptedPrivateKey }, { name: account.key }],
      ciphers: [
        { ...body, encryptedFor: preImport.profile.id, futureProtocolExtension: { imported: true, opaque: '"quoted" \\ café 🔐' } },
        { type: 2, encryptedFor: preImport.profile.id, name: account.key, notes: account.key, secureNote: { type: 0 } },
      ],
      folderRelationships: [{ key: 0, value: 1 }, { key: 1, value: 0 }],
    },
  });
  const postImport = await request("/api/sync", { token });
  const imported = postImport.ciphers.filter(item => !preImport.ciphers.some(old => old.id === item.id));
  assert.equal(imported.length, 2, "Both imported items must be present before restart");
  const importedFolder = postImport.folders.find(candidate => candidate.id !== folder.id);
  assert(importedFolder, "Import must create its additional folder");
  assert.equal(imported.find(item => item.type === 1).folderId, importedFolder.id);
  assert.equal(imported.find(item => item.type === 2).folderId, folder.id);
  assert.equal(postImport.folders.find(candidate => candidate.id === folder.id).name, folder.name);
  const createBulk = () => request("/api/ciphers", { method: "POST", token, body });
  const bulkTrash = await createBulk();
  const bulkRestored = await createBulk();
  const bulkDeleted = await createBulk();
  const bulkArchived = await createBulk();
  const bulkUnarchived = await createBulk();
  await request("/api/ciphers/delete", {
    method: "PUT", token, body: { ids: [bulkTrash.id, bulkRestored.id, bulkRestored.id] },
  });
  await request("/api/ciphers/restore", { method: "PUT", token, body: { ids: [bulkRestored.id, bulkRestored.id] } });
  await request("/api/ciphers", { method: "DELETE", token, body: { ids: [bulkDeleted.id, bulkDeleted.id] } });
  await request("/api/ciphers/archive", {
    method: "PUT", token, body: { ids: [bulkArchived.id, bulkUnarchived.id, bulkArchived.id] },
  });
  await request("/api/ciphers/unarchive", { method: "PUT", token, body: { ids: [bulkUnarchived.id] } });
  const userKeyId = randomBytes(32).toString("base64");
  await request("/api/accounts/key-management/user-key-id", { method: "POST", token, body: { userKeyId } });
  const before = await request("/api/sync", { token });
  const revision = await request("/api/accounts/revision-date", { token });
  assert.equal(before.profile.name, account.name);
  assert.equal(before.profile.key, account.key);
  assert.equal(before.userDecryption.userKeyId, userKeyId);
  assert.equal(typeof before.ciphers.find(item => item.id === bulkTrash.id).deletedDate, "string");
  assert.equal(before.ciphers.find(item => item.id === bulkRestored.id).deletedDate ?? null, null);
  assert(!before.ciphers.some(item => item.id === bulkDeleted.id));
  assert.equal(typeof before.ciphers.find(item => item.id === bulkArchived.id).archivedDate, "string");
  assert.equal(before.ciphers.find(item => item.id === bulkArchived.id).revisionDate, bulkArchived.revisionDate);
  assert.equal(before.ciphers.find(item => item.id === bulkUnarchived.id).archivedDate ?? null, null);

  await stopServer(child);
  child = await startServer(port);

  // Reuse the exact pre-restart bearer: session storage must survive too.
  const after = await request("/api/sync", { token });
  assert.deepEqual(after.profile, before.profile);
  assert.deepEqual(after.userDecryption, before.userDecryption);
  assert.deepEqual(after.folders, before.folders);
  const sortedCiphers = values => [...values].sort((a, b) => a.id.localeCompare(b.id));
  assert.deepEqual(sortedCiphers(after.ciphers), sortedCiphers(before.ciphers));
  assert.deepEqual(await request(`/api/ciphers/${active.id}`, { token }), active);
  assert.deepEqual(await request(`/api/ciphers/${trashed.id}`, { token }), trashed);
  assert.deepEqual(await request(`/api/folders/${folder.id}`, { token }), folder);
  assert.deepEqual(await request(`/api/folders/${importedFolder.id}`, { token }), importedFolder);
  for (const item of imported) assert.deepEqual(await request(`/api/ciphers/${item.id}`, { token }), item);
  assert.equal(await request("/api/accounts/revision-date", { token }), revision);
  assert.equal(after.profile.privateKey, account.keys.encryptedPrivateKey);
  assert.equal(after.profile.accountKeys.publicKeyEncryptionKeyPair.publicKey, account.keys.publicKey);
  const refreshed = await request("/identity/connect/token", {
    method: "POST",
    form: { grant_type: "refresh_token", refresh_token: session.refresh_token, client_id: "cli" },
  });
  assert.notEqual(refreshed.refresh_token, session.refresh_token);
  assert.equal(refreshed.Key, account.key);
  assert.equal(refreshed.UserDecryptionOptions.UserKeyId, userKeyId);
  assert.deepEqual((await request("/api/sync", { token: refreshed.access_token })).profile, before.profile);
  const unarchived = await request(`/api/ciphers/${bulkArchived.id}/unarchive`, { method: "PUT", token });
  assert.equal(unarchived.archivedDate ?? null, null);
  assert.equal(unarchived.revisionDate, bulkArchived.revisionDate);
  const clearedRevision = await request("/api/accounts/revision-date", { token });
  await stopServer(child);
  child = await startServer(port);
  const cleared = await request(`/api/ciphers/${bulkArchived.id}`, { token: refreshed.access_token });
  assert.equal(cleared.archivedDate ?? null, null, "Removing an archive annotation must survive a second restart");
  assert.equal(cleared.revisionDate, bulkArchived.revisionDate);
  assert.equal(await request("/api/accounts/revision-date", { token }), clearedRevision);
  await stopServer(child);
  console.log("PASS: graceful restarts preserve SQLite keys, owner data, imported folder links, bulk trash/restore/deletion, archive annotations and their removal, revisions, and authentication sessions.");
} finally {
  await Promise.allSettled([...children].map(record => stopServer(record, false)));
  rmSync(directory, { recursive: true, force: true });
}
