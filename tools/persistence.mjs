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

async function request(path, { method = "GET", token, body, form, multipart, binary = false, expectedStatus } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  if (form) headers["content-type"] = "application/x-www-form-urlencoded";
  const target = new URL(path, `${server}/`);
  assert.equal(target.origin, new URL(server).origin, "Durability fixtures only fetch their own server");
  const response = await fetch(target, {
    method, headers, signal: AbortSignal.timeout(15_000),
    body: form ? new URLSearchParams(form) : multipart ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  // Signed query values are capabilities and must never enter failure messages.
  if (expectedStatus !== undefined) assert.equal(response.status, expectedStatus, `${method} ${target.pathname}: unexpected HTTP status`);
  else assert(response.ok, `${method} ${target.pathname}: HTTP ${response.status}`);
  if (binary) return Buffer.from(await response.arrayBuffer());
  const text = await response.text();
  return text ? JSON.parse(text) : null;
}

function stableCipher(item) {
  return Array.isArray(item.attachments)
    ? { ...item, attachments: item.attachments.map(({ url, ...metadata }) => metadata) }
    : item;
}

function apiGrantForm(clientId, clientSecret) {
  return {
    grant_type: "client_credentials", scope: "api", client_id: clientId, client_secret: clientSecret,
    deviceIdentifier: randomUUID(), deviceName: "API-key restart fixture", deviceType: "8",
  };
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
  const proof = { masterPasswordHash: account.masterPasswordHash };
  const apiKey = await request("/api/accounts/api-key", { method: "POST", token, body: proof });
  assert(typeof apiKey.apiKey === "string" && apiKey.apiKey.length === 30, "Restart fixture must create an API key");
  const ownerId = (await request("/api/accounts/profile", { token })).id;
  const clientId = `user.${ownerId}`;
  const apiSession = await request("/identity/connect/token", {
    method: "POST", form: apiGrantForm(clientId, apiKey.apiKey),
  });
  assert.equal(Object.hasOwn(apiSession, "refresh_token"), false);
  const attachmentBytes = randomBytes(257 * 1024 + 13);
  async function attach(cipherId) {
    const reserved = await request(`/api/ciphers/${cipherId}/attachment/v2`, {
      method: "POST", token,
      body: { key: account.key, fileName: account.keys.encryptedPrivateKey, fileSize: attachmentBytes.length },
    });
    const multipart = new FormData();
    multipart.append("data", new Blob([attachmentBytes]), "ignored-v2-name");
    await request(`/api/ciphers/${cipherId}/attachment/${reserved.attachmentId}`, { method: "POST", token, multipart });
    return request(`/api/ciphers/${cipherId}/attachment/${reserved.attachmentId}`, { token });
  }
  const attachmentCipher = await createBulk();
  const attachment = await attach(attachmentCipher.id);
  assert((await request(attachment.url, { binary: true })).equals(attachmentBytes), "Attachment bytes must match before restart");
  const doomedCipher = await createBulk();
  const doomedAttachment = await attach(doomedCipher.id);
  await request(`/api/ciphers/${doomedCipher.id}`, { method: "DELETE", token });
  await request(doomedAttachment.url, { binary: true, expectedStatus: 404 });
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
  const sortedCiphers = values => values.map(stableCipher).sort((a, b) => a.id.localeCompare(b.id));
  assert(JSON.stringify(sortedCiphers(after.ciphers)) === JSON.stringify(sortedCiphers(before.ciphers)),
    "All stored cipher and attachment metadata must survive restart; signed URLs may change");
  const restartedAttachment = await request(`/api/ciphers/${attachmentCipher.id}/attachment/${attachment.id}`, { token });
  const { url: oldUrl, ...oldMetadata } = attachment;
  const { url: freshUrl, ...freshMetadata } = restartedAttachment;
  assert(JSON.stringify(oldMetadata) === JSON.stringify(freshMetadata), "All encrypted attachment metadata must survive restart");
  assert((await request(oldUrl, { binary: true })).equals(attachmentBytes), "An unexpired original download capability must survive restart");
  assert((await request(freshUrl, { binary: true })).equals(attachmentBytes), "Attachment bytes must survive restart");
  await request(doomedAttachment.url, { binary: true, expectedStatus: 404 });
  const persistedKey = await request("/api/accounts/api-key", { method: "POST", token, body: proof });
  assert(persistedKey.apiKey === apiKey.apiKey, "The personal API key must survive restart");
  const apiAfterRestart = await request("/api/sync", { token: apiSession.access_token });
  assert.equal(apiAfterRestart.profile.id, before.profile.id, "The original API bearer must survive restart");
  assert(JSON.stringify(sortedCiphers(apiAfterRestart.ciphers)) === JSON.stringify(sortedCiphers(before.ciphers)),
    "Persisted API access must retrieve the same stored cipher and attachment metadata");
  for (const item of [active, trashed, ...imported]) {
    const actual = await request(`/api/ciphers/${item.id}`, { token });
    assert(JSON.stringify(stableCipher(actual)) === JSON.stringify(stableCipher(item)),
      "Existing active, trashed, and imported cipher data must survive restart");
  }
  assert.deepEqual(await request(`/api/folders/${folder.id}`, { token }), folder);
  assert.deepEqual(await request(`/api/folders/${importedFolder.id}`, { token }), importedFolder);
  assert.equal(await request("/api/accounts/revision-date", { token }), revision);
  assert.equal(after.profile.privateKey, account.keys.encryptedPrivateKey);
  assert.equal(after.profile.accountKeys.publicKeyEncryptionKeyPair.publicKey, account.keys.publicKey);
  const refreshed = await request("/identity/connect/token", {
    method: "POST",
    form: { grant_type: "refresh_token", refresh_token: session.refresh_token, client_id: "cli" },
  });
  assert.deepEqual(Object.keys(refreshed).sort(), ["access_token", "expires_in", "refresh_token", "scope", "token_type"]);
  const refreshedSync = await request("/api/sync", { token: refreshed.access_token });
  assert.deepEqual(refreshedSync.profile, before.profile);
  assert.equal(refreshedSync.userDecryption.userKeyId, userKeyId);
  const replayed = await request("/identity/connect/token", {
    method: "POST",
    form: { grant_type: "refresh_token", refresh_token: session.refresh_token, client_id: "cli" },
  });
  assert.deepEqual((await request("/api/sync", { token: replayed.access_token })).profile, before.profile);
  const unarchived = await request(`/api/ciphers/${bulkArchived.id}/unarchive`, { method: "PUT", token });
  assert.equal(unarchived.archivedDate ?? null, null);
  assert.equal(unarchived.revisionDate, bulkArchived.revisionDate);
  const rotatedKey = await request("/api/accounts/rotate-api-key", { method: "POST", token, body: proof });
  assert(rotatedKey.apiKey !== apiKey.apiKey, "Restart fixture must rotate the personal API key");
  await request("/identity/connect/token", {
    method: "POST", form: apiGrantForm(clientId, apiKey.apiKey), expectedStatus: 400,
  });
  await request(`/api/ciphers/${attachmentCipher.id}/attachment/${attachment.id}`, { method: "DELETE", token });
  await request(freshUrl, { binary: true, expectedStatus: 404 });
  const clearedRevision = await request("/api/accounts/revision-date", { token });
  await stopServer(child);
  child = await startServer(port);
  const cleared = await request(`/api/ciphers/${bulkArchived.id}`, { token: refreshed.access_token });
  assert.equal(cleared.archivedDate ?? null, null, "Removing an archive annotation must survive a second restart");
  assert.equal(cleared.revisionDate, bulkArchived.revisionDate);
  assert.equal(await request("/api/accounts/revision-date", { token }), clearedRevision);
  await request(`/api/ciphers/${attachmentCipher.id}/attachment/${attachment.id}`, { token, expectedStatus: 400 });
  await request(freshUrl, { binary: true, expectedStatus: 404 });
  await request(doomedAttachment.url, { binary: true, expectedStatus: 404 });
  const persistedRotation = await request("/api/accounts/api-key", { method: "POST", token, body: proof });
  assert(persistedRotation.apiKey === rotatedKey.apiKey, "The rotated API key must survive a second restart");
  await request("/identity/connect/token", {
    method: "POST", form: apiGrantForm(clientId, apiKey.apiKey), expectedStatus: 400,
  });
  const newApiSession = await request("/identity/connect/token", {
    method: "POST", form: apiGrantForm(clientId, rotatedKey.apiKey),
  });
  assert.equal(Object.hasOwn(newApiSession, "refresh_token"), false);
  assert(newApiSession.Key === account.key, "The rotated API key must retain password-unlock metadata after restart");
  assert.equal((await request("/api/sync", { token: newApiSession.access_token })).profile.id, ownerId);
  assert.equal((await request("/api/sync", { token: apiSession.access_token })).profile.id, ownerId,
    "Previously issued API access must survive rotation and both restarts");
  await stopServer(child);
  console.log("PASS: graceful restarts preserve vault data, encrypted attachment metadata and bytes, scoped download capabilities, deletion cleanup, API keys and rotation, and authentication sessions.");
} finally {
  await Promise.allSettled([...children].map(record => stopServer(record, false)));
  rmSync(directory, { recursive: true, force: true });
}
