#!/usr/bin/env node
/** HTTP security and forward-compatibility checks for the standalone adapter. */
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { registration } from "./seed-account.mjs";

const server = (process.env.BW_E2E_SERVER ?? "http://127.0.0.1:8000").replace(/\/$/, "");

async function request(path, { method = "GET", token, body, form, multipart, binary = false } = {}) {
  const headers = { accept: "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  if (form) headers["content-type"] = "application/x-www-form-urlencoded";
  const target = new URL(path, `${server}/`);
  assert.equal(target.origin, new URL(server).origin, "HTTP fixtures only fetch the configured test server");
  let payload = form ? new URLSearchParams(form) : multipart ?? (body !== undefined ? JSON.stringify(body) : undefined);
  if (multipart) {
    // Send one bounded body, including rejection probes whose server can close
    // the connection before a streamed FormData writer finishes. Never retry.
    const encoded = new Request(target, { method, body: multipart });
    headers["content-type"] = encoded.headers.get("content-type");
    payload = Buffer.from(await encoded.arrayBuffer());
  }
  const response = await fetch(target, {
    method, headers, signal: AbortSignal.timeout(15_000),
    body: payload,
  });
  if (binary) return { status: response.status, bytes: Buffer.from(await response.arrayBuffer()) };
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: response.status, data, bodyBytes: Buffer.byteLength(text) };
}

function ok(response, context) {
  assert(response.status >= 200 && response.status < 300, `${context}: HTTP ${response.status}`);
  return response.data;
}

function denied(response, context, statuses = [400, 401, 403, 404]) {
  assert(statuses.includes(response.status), `${context}: expected rejection, received HTTP ${response.status}`);
}

async function account(name = "no-warden HTTP tests") {
  const email = `http-test-${randomUUID()}@example.test`;
  const password = randomBytes(32).toString("base64url");
  const registrationBody = registration(email, password);
  registrationBody.name = name;
  let response = await request("/api/accounts/register", { method: "POST", body: registrationBody });
  if (response.status === 404) {
    // The portable lifecycle checks also run against disposable upstream servers.
    const verification = ok(await request("/identity/accounts/register/send-verification-email", {
      method: "POST", body: { email, name },
    }), "registration verification");
    assert.equal(typeof verification, "string", "Upstream comparison requires SMTP-disabled registration");
    response = await request("/identity/accounts/register/finish", {
      method: "POST", body: { ...registrationBody, emailVerificationToken: verification },
    });
  }
  ok(response, "registration");
  const token = ok(await passwordLogin(registrationBody), "password login");
  assert.equal(typeof token.access_token, "string");
  assert.equal(typeof token.refresh_token, "string");
  return { registration: registrationBody, token };
}

function passwordLogin(registrationBody, password = registrationBody.masterPasswordHash) {
  return request("/identity/connect/token", {
    method: "POST",
    form: {
      grant_type: "password", username: registrationBody.email, password,
      scope: "api offline_access", client_id: "cli", deviceType: "8",
      deviceIdentifier: randomUUID(), deviceName: "no-warden HTTP tests",
    },
  });
}

function cipher(user, overrides = {}) {
  return {
    type: 1, name: user.registration.key, notes: null, favorite: false,
    folderId: null, organizationId: null, reprompt: 0,
    login: { username: user.registration.key, password: user.registration.key, uris: [] },
    fields: [], ...overrides,
  };
}

const bulkActions = [
  ["DELETE", "/api/ciphers", "hard"], ["POST", "/api/ciphers/delete", "hard"],
  ["DELETE", "/api/ciphers/admin", "hard"], ["POST", "/api/ciphers/delete-admin", "hard"],
  ["PUT", "/api/ciphers/delete", "soft"], ["PUT", "/api/ciphers/delete-admin", "soft"],
  ["PUT", "/api/ciphers/restore", "restore"], ["PUT", "/api/ciphers/restore-admin", "restore"],
].map(([method, path, kind]) => ({ method, path, kind }));
const archiveActions = [
  { method: "PUT", path: "/api/ciphers/archive", kind: "archive" },
  { method: "PUT", path: "/api/ciphers/unarchive", kind: "unarchive" },
];
async function vaultState(token) {
  const sync = ok(await request("/api/sync", { token }), "lifecycle sync");
  const sorted = values => [...values].sort((a, b) => a.id.localeCompare(b.id));
  return {
    ciphers: sorted(sync.ciphers.map(stableCipher)), folders: sorted(sync.folders),
    revision: ok(await request("/api/accounts/revision-date", { token }), "lifecycle account revision"),
  };
}
function stableCipher(item) {
  // Every metadata read may mint a new signed download URL. Keep all stored fields.
  return Array.isArray(item.attachments)
    ? { ...item, attachments: item.attachments.map(({ url, ...metadata }) => metadata) }
    : item;
}
function attachmentForm(bytes, fileName, key) {
  const form = new FormData();
  if (key !== undefined) form.append("key", key);
  if (bytes !== undefined) form.append("data", new Blob([bytes], { type: "application/octet-stream" }), fileName);
  return form;
}
function unchanged(actual, expected, context) {
  // Failure messages must not serialize encrypted vault contents.
  assert(JSON.stringify(actual) === JSON.stringify(expected), context);
}
function lifecycleList(response, ids, context) {
  assert.equal(response.status, 200, context);
  assert.equal(response.data.object, "list", context);
  assert.equal(response.data.continuationToken, null, context);
  assert.deepEqual(response.data.data.map(item => item.id).sort(), [...new Set(ids)].sort(), context);
  return response.data.data;
}
function emptyLifecycle(response, context) {
  assert.equal(response.status, 200, context);
  assert.equal(response.bodyBytes, 0, `${context}: response must be empty`);
}
async function lifecycleFixture(user, overrides = {}) {
  const token = user.token.access_token;
  const profile = ok(await request("/api/accounts/profile", { token }), "lifecycle owner profile");
  return ok(await request("/api/ciphers", {
    method: "POST", token,
    body: cipher(user, { encryptedFor: profile.id, notes: user.registration.key, ...overrides }),
  }), "lifecycle fixture create");
}

function apiGrantForm(clientId, clientSecret, overrides = {}) {
  return {
    grant_type: "client_credentials", scope: "api", client_id: clientId, client_secret: clientSecret,
    deviceIdentifier: randomUUID(), deviceName: "HTTP API-key tests", deviceType: "8", ...overrides,
  };
}
function apiKeyResponse(response) {
  assert.equal(response.status, 200, "Personal API-key request must succeed");
  const data = response.data;
  assert.equal(data.object, "apiKey");
  assert(typeof data.apiKey === "string" && /^[A-Za-z0-9]{30}$/.test(data.apiKey), "API secret must be 30 ASCII alphanumeric characters");
  assert(Number.isFinite(Date.parse(data.revisionDate)), "API-key revision must be a timestamp");
  return data;
}
async function apiKeyFixture(user) {
  const token = user.token.access_token;
  const profile = ok(await request("/api/accounts/profile", { token }), "API-key owner profile");
  const key = apiKeyResponse(await request("/api/accounts/api-key", {
    method: "POST", token, body: { masterPasswordHash: user.registration.masterPasswordHash },
  }));
  return { ...key, clientId: `user.${profile.id}`, userId: profile.id };
}
function apiTokenResponse(response, user, clientId) {
  assert.equal(response.status, 200, "Personal client_credentials request must succeed");
  const token = response.data;
  assert.equal(token.scope, "api");
  assert.equal(token.token_type, "Bearer");
  assert(Number.isInteger(token.expires_in) && token.expires_in >= 7195 && token.expires_in <= 7200,
    "API-key access must advertise the remaining two-hour lifetime");
  assert.equal(Object.hasOwn(token, "refresh_token"), false, "API-key tokens must not issue a refresh token");
  assert(typeof token.access_token === "string" && token.access_token.length > 20, "API-key access token must be present");
  assert(token.Key === user.registration.key, "API token must retain the master-password-wrapped user key");
  assert(token.PrivateKey === user.registration.keys.encryptedPrivateKey, "API token must retain the wrapped private key");
  assert.equal(token.Kdf, user.registration.kdf);
  assert.equal(token.KdfIterations, user.registration.kdfIterations);
  assert.equal(token.UserDecryptionOptions.HasMasterPassword, true);
  assert.equal(token.UserDecryptionOptions.MasterPasswordUnlock.Salt, user.registration.email);
  const claims = JSON.parse(Buffer.from(token.access_token.split(".")[1], "base64url").toString("utf8"));
  assert.equal(claims.client_id, clientId);
  assert.deepEqual(claims.scope, ["api"]);
  assert.equal(claims.exp - claims.nbf, 7200);
  return token;
}

await test("standalone adapter enforces authentication, isolation, and JSON preservation", async (t) => {
  const alice = await account('Alice "quoted" \\ café 🔐');
  const bob = await account();
  const aliceToken = alice.token.access_token;
  const bobToken = bob.token.access_token;

  await t.test("escaped registration names decode and round-trip through the profile", async () => {
    const profile = ok(await request("/api/accounts/profile", { token: aliceToken }), "escaped-name profile");
    assert.equal(profile.name, alice.registration.name);
    assert.equal(profile.email, alice.registration.email);
  });

  await t.test("unauthenticated requests and forged bearer tokens are rejected", async () => {
    for (const path of ["/api/sync", "/api/accounts/profile", "/api/ciphers", "/api/folders"]) {
      denied(await request(path), path, [401, 403]);
      denied(await request(path, { token: "not-a-valid-bearer-token" }), `forged token ${path}`, [401, 403]);
    }
    denied(await request("/api/ciphers", { method: "POST", body: cipher(alice) }), "anonymous create", [401, 403]);
  });

  await t.test("incorrect password hash cannot authenticate", async () => {
    denied(await passwordLogin(alice.registration, randomBytes(32).toString("base64")), "wrong password", [400, 401]);
  });

  const created = ok(await request("/api/ciphers", {
    method: "POST", token: aliceToken, body: cipher(alice),
  }), "create Alice item");
  assert.equal(typeof created.id, "string");

  await t.test("another user cannot read, edit, trash, restore, or delete the cipher", async () => {
    for (const operation of [
      { method: "GET", suffix: "" },
      { method: "PUT", suffix: "", body: cipher(bob) },
      { method: "PUT", suffix: "/delete" },
      { method: "PUT", suffix: "/restore" },
      { method: "DELETE", suffix: "" },
    ]) {
      denied(await request(`/api/ciphers/${created.id}${operation.suffix}`, {
        method: operation.method, token: bobToken, body: operation.body,
      }), `cross-user ${operation.method} ${operation.suffix}`, operation.method === "GET" ? [400] : [403, 404]);
    }
    const own = ok(await request(`/api/ciphers/${created.id}`, { token: aliceToken }), "owner read");
    assert.equal(own.name, alice.registration.key);
    assert.equal(own.deletedDate ?? null, null);
    const bobSync = ok(await request("/api/sync", { token: bobToken }), "Bob sync");
    assert.equal(bobSync.ciphers.some(item => item.id === created.id), false);
  });

  await t.test("folder ownership is enforced and unknown organization/folder IDs are rejected", async () => {
    const bobFolder = ok(await request("/api/folders", {
      method: "POST", token: bobToken, body: { name: bob.registration.key },
    }), "Bob folder");
    denied(await request(`/api/folders/${bobFolder.id}`, { token: aliceToken }), "cross-user folder read", [400]);
    denied(await request(`/api/folders/${bobFolder.id}`, {
      method: "PUT", token: aliceToken, body: { name: alice.registration.key },
    }), "cross-user folder edit", [400]);
    denied(await request(`/api/folders/${bobFolder.id}`, { method: "DELETE", token: aliceToken }), "cross-user folder delete", [400]);
    for (const overrides of [
      { folderId: randomUUID() }, { folderId: bobFolder.id }, { organizationId: randomUUID() },
    ]) {
      denied(await request("/api/ciphers", {
        method: "POST", token: aliceToken, body: cipher(alice, overrides),
      }), "invalid cipher owner references", [400, 403, 404]);
    }
  });

  await t.test("malformed cipher types and missing encrypted names are rejected", async () => {
    for (const body of [
      {}, cipher(alice, { type: 0 }), cipher(alice, { type: 999 }),
      cipher(alice, { name: null }), cipher(alice, { name: "plaintext is not encrypted" }),
      cipher(alice, { type: "1" }),
    ]) {
      denied(await request("/api/ciphers", { method: "POST", token: aliceToken, body }), "malformed cipher", [400, 422]);
    }
  });

  await t.test("unknown future JSON fields survive create, update, and sync", async () => {
    const future = { encryptedMetadata: alice.registration.key, nested: [null, 42, { enabled: true }], version: 17 };
    const body = cipher(alice, { futureProtocolExtension: future });
    const item = ok(await request("/api/ciphers", { method: "POST", token: aliceToken, body }), "future cipher create");
    assert.deepEqual(item.futureProtocolExtension, future);
    const updated = ok(await request(`/api/ciphers/${item.id}`, {
      method: "PUT", token: aliceToken,
      body: { ...item, futureProtocolExtension: { ...future, version: 18 } },
    }), "future cipher update");
    assert.equal(updated.futureProtocolExtension.version, 18);
    const sync = ok(await request("/api/sync", { token: aliceToken }), "sync future cipher");
    assert.deepEqual(sync.ciphers.find(candidate => candidate.id === item.id).futureProtocolExtension, { ...future, version: 18 });
  });

  await t.test("persisted user-key IDs reject mismatched encryption metadata before mutation", async () => {
    const user = await account();
    const token = user.token.access_token;
    const userKeyId = randomBytes(32).toString("base64");
    ok(await request("/api/accounts/key-management/user-key-id", {
      method: "POST", token, body: { userKeyId },
    }), "key-matching fixture migration");
    const before = ok(await request("/api/sync", { token }), "key-matching fixture sync");
    assert.equal(before.userDecryption.userKeyId, userKeyId);
    const revision = ok(await request("/api/accounts/revision-date", { token }), "pre-rejection revision");
    denied(await request("/api/ciphers", {
      method: "POST", token,
      body: cipher(user, { encryptedFor: before.profile.id, encryptedByKeyId: `${userKeyId}-incorrect` }),
    }), "mismatched encryptedByKeyId", [400, 422]);
    assert.deepEqual(ok(await request("/api/sync", { token }), "post-rejection sync").ciphers, []);
    assert.equal(ok(await request("/api/accounts/revision-date", { token }), "post-rejection revision"), revision);
    const matched = ok(await request("/api/ciphers", {
      method: "POST", token,
      body: cipher(user, { encryptedFor: before.profile.id, encryptedByKeyId: userKeyId }),
    }), "matching encryptedByKeyId");
    // Vaultwarden 1.37.4 omits request encryption metadata on every public
    // projection, including a matching non-null key ID. Raw persistence is
    // checked separately by the Store service regression.
    const single = ok(await request(`/api/ciphers/${matched.id}`, { token }), "matching key-ID read");
    const listed = ok(await request("/api/ciphers", { token }), "matching key-ID list").data.find(item => item.id === matched.id);
    const synced = ok(await request("/api/sync", { token }), "matching key-ID sync").ciphers.find(item => item.id === matched.id);
    for (const projected of [matched, single, listed, synced]) {
      assert(projected, "matching key-ID cipher must remain visible");
      assert.equal(Object.hasOwn(projected, "encryptedByKeyId"), false);
      assert.equal(Object.hasOwn(projected, "encryptedFor"), false);
      assert.equal(projected.id, matched.id);
      assert(projected.name === matched.name, "matching key-ID projection must retain ciphertext");
    }
    const legacy = ok(await request("/api/ciphers", { method: "POST", token, body: cipher(user) }), "legacy omitted key ID");
    assert(legacy.id);
    assert.notEqual(legacy.id, matched.id);
  });

  await t.test("opaque cipher blobs preserve escaped JSON strings through create, get, edit, and sync", async () => {
    const blob = JSON.stringify({
      format_version: 1, wrapped_cek: 'opaque "quoted" \\ café 🔐',
      envelope: "sealed-ciphertext", unknownExtension: { enabled: true },
    });
    const item = ok(await request("/api/ciphers", {
      method: "POST", token: aliceToken,
      body: { type: 1, data: blob, name: null, key: alice.registration.key, organizationId: null },
    }), "blob create");
    assert.equal(item.data, blob);
    assert.equal(item.name, null);
    assert.equal(item.key, alice.registration.key);
    assert.equal(ok(await request(`/api/ciphers/${item.id}`, { token: aliceToken }), "blob get").data, blob);
    const changedBlob = JSON.stringify({ ...JSON.parse(blob), envelope: 'updated "sealed" \\ 🔑' });
    const updated = ok(await request(`/api/ciphers/${item.id}`, {
      method: "PUT", token: aliceToken,
      body: { ...item, data: changedBlob, lastKnownRevisionDate: item.revisionDate },
    }), "blob edit");
    assert.equal(updated.data, changedBlob);
    assert.equal(updated.key, alice.registration.key);
    const sync = ok(await request("/api/sync", { token: aliceToken }), "blob sync");
    assert.equal(sync.ciphers.find(candidate => candidate.id === item.id).data, changedBlob);
  });

  await t.test("decoded field boundaries allow JSON overhead and retain request limits", async () => {
    const fieldLimit = 1024 * 1024;
    for (const data of ["x".repeat(fieldLimit), "\u0001".repeat(fieldLimit)]) {
      const body = { type: 1, data, name: null };
      assert(Buffer.byteLength(JSON.stringify(body)) > fieldLimit);
      const item = ok(await request("/api/ciphers", { method: "POST", token: aliceToken, body }), "maximum decoded blob");
      assert.equal(item.data, data);
      assert.equal(ok(await request(`/api/ciphers/${item.id}`, { token: aliceToken }), "maximum blob get").data, data);
      const deleted = await request(`/api/ciphers/${item.id}`, { method: "DELETE", token: aliceToken });
      assert.equal(deleted.status, 200, "Single cipher permanent deletion returns 200");
      assert.equal(deleted.bodyBytes, 0, "Single cipher permanent deletion has an empty body");
    }
    const before = ok(await request("/api/sync", { token: aliceToken }), "size limit baseline");
    const beforeRevision = ok(await request("/api/accounts/revision-date", { token: aliceToken }), "size limit baseline revision");
    denied(await request("/api/ciphers", {
      method: "POST", token: aliceToken, body: { type: 1, data: "x".repeat(fieldLimit + 1) },
    }), "oversized decoded field", [400]);
    denied(await request("/api/ciphers", {
      method: "POST", token: aliceToken, body: { type: 1, data: "x", extension: "x".repeat(16 * fieldLimit) },
    }), "oversized encoded request", [413]);
    const after = ok(await request("/api/sync", { token: aliceToken }), "size limit rejection state");
    assert.equal(after.ciphers.length, before.ciphers.length);
    assert.equal(after.profile.id, before.profile.id);
    assert.equal(ok(await request("/api/accounts/revision-date", { token: aliceToken }), "size limit revision"), beforeRevision);
  });

  await t.test("encrypted FIDO2 records preserve every stored field through create, update, and sync", async () => {
    const credential = {
      credentialId: alice.registration.key,
      keyType: alice.registration.key,
      keyAlgorithm: alice.registration.key,
      keyCurve: alice.registration.key,
      keyValue: alice.registration.key,
      rpId: alice.registration.key,
      rpName: alice.registration.key,
      counter: alice.registration.key,
      userHandle: alice.registration.key,
      userName: alice.registration.key,
      userDisplayName: alice.registration.key,
      discoverable: alice.registration.key,
      creationDate: "2026-01-01T00:00:00.000Z",
      futureEncryptedExtension: alice.registration.keys.encryptedPrivateKey,
    };
    const body = cipher(alice);
    body.login.fido2Credentials = [credential];
    const item = ok(await request("/api/ciphers", { method: "POST", token: aliceToken, body }), "FIDO2 create");
    assert.deepEqual(item.login.fido2Credentials, [credential]);
    assert.deepEqual(ok(await request(`/api/ciphers/${item.id}`, { token: aliceToken }), "FIDO2 get").login.fido2Credentials, [credential]);
    const changed = { ...credential, counter: alice.registration.keys.encryptedPrivateKey, creationDate: "2026-02-01T00:00:00.000Z" };
    const records = [changed, { ...credential, userName: alice.registration.keys.encryptedPrivateKey }];
    const updated = ok(await request(`/api/ciphers/${item.id}`, {
      method: "PUT", token: aliceToken,
      body: { ...item, login: { ...item.login, fido2Credentials: records }, lastKnownRevisionDate: item.revisionDate },
    }), "FIDO2 update");
    assert.deepEqual(updated.login.fido2Credentials, records);
    const sync = ok(await request("/api/sync", { token: aliceToken }), "FIDO2 sync");
    assert.deepEqual(sync.ciphers.find(candidate => candidate.id === item.id).login.fido2Credentials, records);
  });

  await t.test("wrapped clone creation allocates a fresh ID and rejects unsupported ownership", async () => {
    const source = ok(await request("/api/ciphers", { method: "POST", token: aliceToken, body: cipher(alice) }), "clone source");
    const body = { cipher: { ...source, lastKnownRevisionDate: "2000-01-01T00:00:00.000Z" }, collectionIds: [] };
    denied(await request("/api/ciphers/create", { method: "POST", body }), "anonymous wrapped clone", [401, 403]);
    const clone = ok(await request("/api/ciphers/create", { method: "POST", token: aliceToken, body }), "wrapped clone");
    assert(clone.id);
    assert.notEqual(clone.id, source.id);
    assert.equal(clone.name, source.name);
    assert.equal(clone.lastKnownRevisionDate ?? null, null);
    assert.equal(clone.cipher, undefined);
    assert.deepEqual(ok(await request(`/api/ciphers/${source.id}`, { token: aliceToken }), "unchanged clone source"), source);
    const alias = ok(await request("/api/ciphers/create", {
      method: "POST", token: aliceToken, body: { Cipher: body.cipher, CollectionIds: [] },
    }), "PascalCase wrapped clone");
    assert.notEqual(alias.id, source.id);
    assert.notEqual(alias.id, clone.id);
    assert.equal(alias.lastKnownRevisionDate ?? null, null);
    denied(await request("/api/ciphers/create", { token: aliceToken }), "reserved create path fails the read UUID guard", [422]);
    const before = ok(await request("/api/sync", { token: aliceToken }), "pre-rejection clone sync");
    const revision = ok(await request("/api/accounts/revision-date", { token: aliceToken }), "pre-rejection clone revision");
    for (const invalid of [
      source,
      { ...body, collectionIds: [randomUUID()] },
      { ...body, cipher: { ...body.cipher, organizationId: randomUUID() } },
    ]) {
      denied(await request("/api/ciphers/create", {
        method: "POST", token: aliceToken, body: invalid,
      }), "invalid cloned cipher request", [400, 403, 404, 422]);
    }
    assert.deepEqual(ok(await request("/api/sync", { token: aliceToken }), "post-rejection clone sync").ciphers, before.ciphers);
    assert.equal(ok(await request("/api/accounts/revision-date", { token: aliceToken }), "post-rejection clone revision"), revision);
  });

  await t.test("legacy POST folder update and delete aliases enforce owner isolation", async () => {
    const folder = ok(await request("/api/folders", {
      method: "POST", token: bobToken, body: { name: bob.registration.key },
    }), "folder alias fixture");
    denied(await request(`/api/folders/${folder.id}`, {
      method: "POST", token: aliceToken, body: { name: alice.registration.key },
    }), "cross-user POST folder update", [400]);
    denied(await request(`/api/folders/${folder.id}/delete`, {
      method: "POST", token: aliceToken,
    }), "cross-user POST folder delete", [400]);
    assert.deepEqual(ok(await request(`/api/folders/${folder.id}`, { token: bobToken }), "folder after rejected aliases"), folder);
    const updated = ok(await request(`/api/folders/${folder.id}`, {
      method: "POST", token: bobToken, body: { name: bob.registration.keys.encryptedPrivateKey },
    }), "owner POST folder update");
    assert.equal(updated.name, bob.registration.keys.encryptedPrivateKey);
    ok(await request(`/api/folders/${folder.id}/delete`, { method: "POST", token: bobToken }), "owner POST folder delete");
    denied(await request(`/api/folders/${folder.id}`, { token: bobToken }), "deleted aliased folder", [400]);
    const sync = ok(await request("/api/sync", { token: bobToken }), "folder alias sync");
    assert.equal(sync.folders.some(candidate => candidate.id === folder.id), false);
  });

  await t.test("archivedDate survives cipher creation, update, and sync", async () => {
    const archivedDate = "2026-01-01T00:00:00.123456Z";
    const item = ok(await request("/api/ciphers", {
      method: "POST", token: aliceToken, body: cipher(alice, { archivedDate }),
    }), "archived cipher create");
    assert.equal(item.archivedDate, archivedDate);
    const changed = "2026-02-01T00:00:00.123456Z";
    const updated = ok(await request(`/api/ciphers/${item.id}`, {
      method: "PUT", token: aliceToken, body: { ...item, archivedDate: changed, lastKnownRevisionDate: item.revisionDate },
    }), "archived cipher update");
    assert.equal(updated.archivedDate, changed);
    const sync = ok(await request("/api/sync", { token: aliceToken }), "archived cipher sync");
    assert.equal(sync.ciphers.find(candidate => candidate.id === item.id).archivedDate, changed);
  });

  await t.test("organizationID alias cannot bypass personal-vault ownership validation", async () => {
    const body = cipher(alice, { organizationID: randomUUID() });
    delete body.organizationId;
    const before = ok(await request("/api/sync", { token: aliceToken }), "pre-alias-rejection sync");
    for (const path of ["/api/ciphers", `/api/ciphers/${created.id}`]) {
      denied(await request(path, {
        method: path === "/api/ciphers" ? "POST" : "PUT", token: aliceToken, body,
      }), "organizationID owner bypass", [400, 403, 422]);
    }
    denied(await request("/api/ciphers/create", {
      method: "POST", token: aliceToken, body: { cipher: body, collectionIds: [] },
    }), "wrapped organizationID owner bypass", [400, 403, 422]);
    assert.deepEqual(ok(await request("/api/sync", { token: aliceToken }), "post-alias-rejection sync").ciphers, before.ciphers);
  });

  await t.test("concurrent edits with the same revision allow only one update", async () => {
    const item = ok(await request("/api/ciphers", {
      method: "POST", token: aliceToken, body: cipher(alice),
    }), "revision fixture");
    assert.equal(typeof item.revisionDate, "string");
    const edit = () => request(`/api/ciphers/${item.id}`, {
      method: "PUT", token: aliceToken,
      body: { ...item, lastKnownRevisionDate: item.revisionDate },
    });
    const results = await Promise.all([edit(), edit()]);
    assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
    const latest = ok(await request(`/api/ciphers/${item.id}`, { token: aliceToken }), "latest revision");
    assert(Date.parse(latest.revisionDate) > Date.parse(item.revisionDate));
  });

  await t.test("POST delete alias permanently removes the cipher", async () => {
    const item = ok(await request("/api/ciphers", {
      method: "POST", token: aliceToken, body: cipher(alice),
    }), "delete alias fixture");
    ok(await request(`/api/ciphers/${item.id}/delete`, { method: "POST", token: aliceToken }), "POST delete");
    denied(await request(`/api/ciphers/${item.id}`, { token: aliceToken }), "deleted item read", [400]);
    const sync = ok(await request("/api/sync", { token: aliceToken }), "sync after POST delete");
    assert.equal(sync.ciphers.some(candidate => candidate.id === item.id), false);
  });

  await t.test("SDK user-key migration persists once and cannot overwrite the key ID", async () => {
    const path = "/api/accounts/key-management/user-key-id";
    const userKeyId = randomBytes(32).toString("base64");
    denied(await request(path, { method: "POST", body: { userKeyId } }), "unauthenticated migration", [401, 403]);
    const before = ok(await request("/api/sync", { token: aliceToken }), "pre-migration sync");
    assert.equal(before.userDecryption.userKeyId, null);
    ok(await request(path, { method: "POST", token: aliceToken, body: { userKeyId } }), "key-ID migration");
    denied(await request(path, {
      method: "POST", token: aliceToken, body: { userKeyId: randomBytes(32).toString("base64") },
    }), "key-ID overwrite", [409, 422]);
    const after = ok(await request("/api/sync", { token: aliceToken }), "post-migration sync");
    assert.equal(after.userDecryption.userKeyId, userKeyId);
    const refreshed = ok(await request("/identity/connect/token", {
      method: "POST",
      form: { grant_type: "refresh_token", refresh_token: alice.token.refresh_token, client_id: "cli" },
    }), "post-migration refresh");
    assert.equal(Object.hasOwn(refreshed, "UserDecryptionOptions"), false, "refresh returns token fields only");
    const refreshedSync = ok(await request("/api/sync", { token: refreshed.access_token }), "post-refresh sync");
    assert.equal(refreshedSync.userDecryption.userKeyId, userKeyId);
    const relogin = ok(await passwordLogin(alice.registration), "post-migration password login");
    assert.equal(relogin.UserDecryptionOptions.UserKeyId, userKeyId);
  });

  await t.test("refresh reuse keeps original proofs and unexpired access valid", async () => {
    const form = { grant_type: "refresh_token", refresh_token: bob.token.refresh_token, client_id: "cli" };
    const refreshed = ok(await request("/identity/connect/token", { method: "POST", form }), "refresh token");
    assert.equal(typeof refreshed.access_token, "string");
    assert.equal(typeof refreshed.refresh_token, "string");
    ok(await request("/identity/connect/token", { method: "POST", form }), "reuse original refresh token");
    ok(await request("/api/sync", { token: bobToken }), "original unexpired access token after refresh");
    ok(await request("/api/sync", { token: refreshed.access_token }), "refreshed access token");
    const nextForm = { grant_type: "refresh_token", refresh_token: refreshed.refresh_token, client_id: "cli" };
    const concurrent = await Promise.all([0, 1].map(() => request("/identity/connect/token", { method: "POST", form: nextForm })));
    assert.deepEqual(concurrent.map(result => result.status).sort(), [200, 200]);
    ok(await request("/api/sync", { token: bobToken }), "original access after concurrent refresh");
    ok(await request("/api/sync", { token: refreshed.access_token }), "previous access after concurrent refresh");
    ok(await request("/api/sync", { token: concurrent.find(result => result.status === 200).data.access_token }), "latest access token");
  });
});

await test("personal cipher imports preserve relationships and isolate atomic batches", async (t) => {
  const owner = await account("Import owner");
  const other = await account("Import foreign owner");
  const token = owner.token.access_token;
  const otherToken = other.token.access_token;
  const path = "/api/ciphers/import";
  const ownerId = ok(await request("/api/accounts/profile", { token }), "import owner profile").id;
  const batch = (overrides = {}) => {
    const body = { ciphers: [cipher(owner)], folders: [], folderRelationships: [], ...overrides };
    if (Array.isArray(body.ciphers)) body.ciphers = body.ciphers.map(item => ({ encryptedFor: ownerId, ...item }));
    return body;
  };
  async function state(userToken = token) {
    const sync = ok(await request("/api/sync", { token: userToken }), "import state");
    const byId = rows => [...rows].sort((left, right) => left.id.localeCompare(right.id));
    return {
      ciphers: byId(sync.ciphers), folders: byId(sync.folders),
      revision: ok(await request("/api/accounts/revision-date", { token: userToken }), "import revision"),
    };
  }
  async function imported(body) {
    const response = await request(path, { method: "POST", token, body });
    assert.equal(response.status, 200, "Successful personal import must return HTTP 200");
    assert.equal(response.data, null, "Personal import response must have an empty body");
  }

  await t.test("empty imports are accepted and unauthenticated imports cannot mutate storage", async () => {
    await imported({ ciphers: [], folders: [], folderRelationships: [] });
    const empty = await state();
    assert.deepEqual(empty.ciphers, []);
    assert.deepEqual(empty.folders, []);
    const before = await state();
    for (const forged of [undefined, "forged-import-token"]) {
      denied(await request(path, { method: "POST", token: forged, body: batch() }), "unauthenticated import", [401, 403]);
    }
    assert.deepEqual(await state(), before);
  });

  await t.test("owned folders are reused, foreign or unknown IDs create fresh folders, and relationship rules match upstream", async () => {
    const ownFolder = ok(await request("/api/folders", { method: "POST", token, body: { name: owner.registration.key } }), "owned import folder");
    const foreignFolder = ok(await request("/api/folders", {
      method: "POST", token: otherToken, body: { name: other.registration.key },
    }), "foreign import folder");
    const foreignBefore = await state(otherToken);
    const unknownId = randomUUID();
    const requestedIds = Array.from({ length: 4 }, () => randomUUID());
    const ciphers = [
      cipher(owner, { id: requestedIds[0], folderId: foreignFolder.id }),
      { type: 2, id: requestedIds[1], name: owner.registration.key, notes: owner.registration.key, secureNote: { type: 0 } },
      { type: 3, id: requestedIds[2], name: owner.registration.key, folderId: foreignFolder.id, card: { number: owner.registration.key } },
      { type: 4, id: requestedIds[3], name: owner.registration.key, identity: { firstName: owner.registration.key } },
    ];
    await imported(batch({
      ciphers,
      folders: [
        { id: ownFolder.id, name: owner.registration.keys.encryptedPrivateKey },
        {
          id: foreignFolder.id, name: owner.registration.key,
          creationDate: "2000-01-01T00:00:00.000Z", deletedDate: "2001-01-01T00:00:00.000Z",
        },
        { id: unknownId, name: owner.registration.keys.encryptedPrivateKey },
        { id: unknownId, name: owner.registration.keys.encryptedPrivateKey },
      ],
      folderRelationships: [
        { key: 0, value: 0 }, { key: 1, value: 0 }, { key: 1, value: 1 },
        { key: 2, value: 999 }, { key: 3, value: 3 }, { key: 999, value: 0 },
      ],
    }));
    const after = await state();
    assert.equal(after.ciphers.length, 4);
    assert.equal(after.folders.length, 4);
    assert.equal(after.folders.find(folder => folder.id === ownFolder.id).name, ownFolder.name, "Reusing a folder ID must preserve its existing name");
    const addedFolders = after.folders.filter(folder => folder.id !== ownFolder.id);
    assert.equal(new Set(addedFolders.map(folder => folder.id)).size, 3);
    assert(addedFolders.every(folder => folder.id !== foreignFolder.id && folder.id !== unknownId));
    for (const folder of addedFolders) {
      assert.equal(Object.hasOwn(folder, "creationDate"), false, "Import must discard client-supplied folder creation metadata");
      assert.equal(Object.hasOwn(folder, "deletedDate"), false, "Import must discard client-supplied folder deletion metadata");
    }
    const byType = new Map(after.ciphers.map(item => [item.type, item]));
    assert.equal(byType.get(1).folderId, ownFolder.id);
    assert(addedFolders.some(folder => folder.id === byType.get(2).folderId && folder.name === owner.registration.key), "The last duplicate relationship must win");
    assert.equal(byType.get(3).folderId ?? null, null, "An unknown relationship target must clear the folder mapping");
    assert(addedFolders.some(folder => folder.id === byType.get(4).folderId));
    assert(after.ciphers.every(item => !requestedIds.includes(item.id)), "Imported ciphers must receive fresh IDs");
    assert(after.ciphers.every(item => (item.organizationId ?? null) === null));
    assert.deepEqual(await state(otherToken), foreignBefore, "Import must not modify a foreign account or folder");
  });

  await t.test("omitted relationships discard incoming folder IDs and import appends to existing items", async () => {
    const before = await state();
    const foreignFolder = (await state(otherToken)).folders[0];
    await imported(batch({ ciphers: [cipher(owner, { folderId: foreignFolder.id })] }));
    const after = await state();
    const added = after.ciphers.filter(item => !before.ciphers.some(old => old.id === item.id));
    assert.equal(added.length, 1);
    assert.equal(added[0].folderId ?? null, null);
    for (const old of before.ciphers) assert.deepEqual(after.ciphers.find(item => item.id === old.id), old);
  });

  await t.test("import preserves escaped opaque extensions under the adapter's existing JSON contract", async () => {
    const extension = { sealed: owner.registration.key, opaque: '{"quoted":"\\\\ café 🔐","future":[true,null,7]}' };
    const before = await state();
    await imported(batch({ ciphers: [cipher(owner, { futureProtocolExtension: extension })] }));
    const added = (await state()).ciphers.filter(item => !before.ciphers.some(old => old.id === item.id));
    assert.equal(added.length, 1);
    assert.deepEqual(added[0].futureProtocolExtension, extension);
    assert.deepEqual(ok(await request(`/api/ciphers/${added[0].id}`, { token }), "imported opaque item").futureProtocolExtension, extension);
  });

  await t.test("malformed arrays and relationship index types are rejected without partial writes (local provider guarantee)", async () => {
    const before = await state();
    const valid = batch({ folders: [{ name: owner.registration.key }] });
    for (const body of [
      {}, { ...valid, ciphers: null }, { ...valid, folders: {} }, { ...valid, folderRelationships: null },
      ...[-1, 0.5, "0", null].map(key => ({ ...valid, folderRelationships: [{ key, value: 0 }] })),
      ...[-1, 0.5, "0", null].map(value => ({ ...valid, folderRelationships: [{ key: 0, value }] })),
      { ...valid, folderRelationships: [{ key: 0 }] },
    ]) {
      denied(await request(path, { method: "POST", token, body }), "malformed import", [400, 422]);
      assert.deepEqual(await state(), before, "A rejected local import must leave its entire batch unchanged");
    }
  });

  await t.test("organization injection and a malformed encrypted item roll back the entire batch (local provider guarantee)", async () => {
    const before = await state();
    for (const invalid of [
      cipher(owner, { organizationId: randomUUID() }),
      cipher(owner, { organizationId: undefined, organizationID: randomUUID() }),
      cipher(owner, { key: "not-an-encrypted-key" }),
      cipher(owner, { name: "not-an-encrypted-name" }),
      cipher(owner, { type: 999 }),
    ]) {
      const response = await request(path, {
        method: "POST", token,
        body: batch({
          folders: [{ name: owner.registration.key }], ciphers: [cipher(owner), invalid],
          folderRelationships: [{ key: 0, value: 0 }, { key: 1, value: 0 }],
        }),
      });
      denied(response, "invalid import batch", [400, 403, 404, 422]);
      assert.deepEqual(await state(), before, "A rejected local batch must preserve items, folders, and revision");
    }
  });
});

await test("bulk cipher lifecycle matches the pinned delete and restore contracts", async (t) => {
  const owner = await account("Bulk owner");
  const other = await account("Bulk foreign owner");
  const token = owner.token.access_token;
  const otherToken = other.token.access_token;
  const folder = ok(await request("/api/folders", { method: "POST", token, body: { name: owner.registration.key } }), "bulk owner folder");
  const foreign = await lifecycleFixture(other);
  const foreignBefore = await vaultState(otherToken);

  await t.test("all eight aliases accept empty sets without changing the account revision", async () => {
    const before = await vaultState(token);
    for (const action of bulkActions) {
      const response = await request(action.path, { method: action.method, token, body: { ids: [] } });
      if (action.kind === "restore") lifecycleList(response, [], action.path);
      else emptyLifecycle(response, action.path);
      unchanged(await vaultState(token), before, "An empty bulk set must not change vault data or revision");
    }
  });

  await t.test("both soft-delete and restore aliases deduplicate IDs and refresh repeated state transitions", async () => {
    const soft = bulkActions.filter(action => action.kind === "soft");
    const restore = bulkActions.filter(action => action.kind === "restore");
    for (let index = 0; index < soft.length; index += 1) {
      const items = [await lifecycleFixture(owner, { folderId: folder.id }), await lifecycleFixture(owner, { folderId: folder.id })];
      const ids = [items[1].id, items[0].id, items[1].id];
      const apply = action => request(action.path, { method: action.method, token, body: { ids } });
      let revision = (await vaultState(token)).revision;
      await delay(5);
      emptyLifecycle(await apply(soft[index]), "bulk soft delete");
      let state = await vaultState(token);
      assert(state.revision > revision, "Bulk trash must advance account revision");
      revision = state.revision;
      const trashed = state.ciphers.filter(item => ids.includes(item.id));
      assert.equal(trashed.length, 2);
      assert(trashed.every(item => typeof item.deletedDate === "string"));
      await delay(5);
      emptyLifecycle(await apply(soft[index]), "repeat bulk soft delete");
      state = await vaultState(token);
      assert(state.revision > revision, "Repeated bulk trash must advance account revision");
      revision = state.revision;
      const repeated = state.ciphers.filter(item => ids.includes(item.id));
      for (const item of repeated) {
        const previous = trashed.find(candidate => candidate.id === item.id);
        assert(Date.parse(item.deletedDate) > Date.parse(previous.deletedDate), "Repeated bulk trash must refresh deletion time");
        assert(Date.parse(item.revisionDate) > Date.parse(previous.revisionDate), "Repeated bulk trash must advance cipher revision");
      }
      await delay(5);
      const restored = lifecycleList(await apply(restore[index]), ids, "bulk restore");
      state = await vaultState(token);
      assert(state.revision > revision, "Bulk restore must advance account revision");
      revision = state.revision;
      assert(restored.every(item => (item.deletedDate ?? null) === null));
      for (const item of restored) {
        const original = items.find(candidate => candidate.id === item.id);
        for (const field of ["name", "notes", "login", "fields", "folderId"]) {
          unchanged(item[field], original[field], "Bulk transitions must preserve encrypted fields and folder links");
        }
      }
      await delay(5);
      const activeAgain = lifecycleList(await apply(restore[index]), ids, "repeat bulk restore");
      assert((await vaultState(token)).revision > revision, "Repeated bulk restore must advance account revision");
      for (const item of activeAgain) {
        assert(Date.parse(item.revisionDate) > Date.parse(restored.find(old => old.id === item.id).revisionDate),
          "Restoring an already active item must still advance its cipher revision");
      }
    }
  });

  await t.test("all four permanent-delete aliases remove active and trashed items with duplicate IDs", async () => {
    for (const action of bulkActions.filter(action => action.kind === "hard")) {
      const active = await lifecycleFixture(owner);
      const trash = await lifecycleFixture(owner);
      ok(await request(`/api/ciphers/${trash.id}/delete`, { method: "PUT", token }), "prepare trash");
      const beforeRevision = (await vaultState(token)).revision;
      await delay(5);
      emptyLifecycle(await request(action.path, {
        method: action.method, token, body: { ids: [trash.id, active.id, trash.id] },
      }), "bulk permanent delete");
      const after = await vaultState(token);
      assert(after.revision > beforeRevision, "Permanent bulk deletion must advance account revision");
      assert(!after.ciphers.some(item => [active.id, trash.id].includes(item.id)));
      for (const id of [active.id, trash.id]) {
        denied(await request(`/api/ciphers/${id}`, { token }), "permanently deleted item", [400, 404]);
        assert.equal((await request("/api/ciphers/restore", { method: "PUT", token, body: { ids: [id] } })).status, 400);
      }
    }
  });

  await t.test("all aliases reject anonymous, foreign, unknown, case-altered, and malformed selections", async () => {
    const own = await lifecycleFixture(owner);
    const before = await vaultState(token);
    for (const action of bulkActions) {
      for (const bearer of [undefined, "forged-bulk-bearer"]) {
        denied(await request(action.path, { method: action.method, token: bearer, body: { ids: [own.id] } }),
          "bulk authentication", [401, 403]);
      }
      const changedCase = own.id.toUpperCase();
      for (const id of [foreign.id, randomUUID(), "not-a-uuid", ...(changedCase === own.id ? [] : [changedCase])]) {
        assert.equal((await request(action.path, { method: action.method, token, body: { ids: [id] } })).status, 400,
          "Missing and foreign bulk IDs must return HTTP 400");
      }
      for (const body of [{}, [], { ids: null }, { ids: "not-an-array" }, { ids: [null] }, { ids: [1] }, { ids: [{}] }]) {
        denied(await request(action.path, { method: action.method, token, body }), "malformed bulk selection", [400, 422]);
      }
    }
    unchanged(await vaultState(token), before, "Rejected selections must preserve owned data and revision");
    unchanged(await vaultState(otherToken), foreignBefore, "Bulk aliases must never modify another account");
  });
});

await test("cipher archive lifecycle preserves per-owner metadata and encrypted content", async (t) => {
  const owner = await account("Archive owner");
  const other = await account("Archive foreign owner");
  const token = owner.token.access_token;
  const otherToken = other.token.access_token;
  const ownerId = ok(await request("/api/accounts/profile", { token }), "archive owner profile").id;
  const folder = ok(await request("/api/folders", { method: "POST", token, body: { name: owner.registration.key } }), "archive owner folder");
  const foreign = await lifecycleFixture(other);
  const foreignBefore = await vaultState(otherToken);

  await t.test("empty bulk archive and unarchive return empty lists without changing account revision", async () => {
    const before = await vaultState(token);
    for (const action of archiveActions) {
      lifecycleList(await request(action.path, { method: "PUT", token, body: { ids: [] } }), [], action.path);
      unchanged(await vaultState(token), before, "Empty archive selections must preserve data and revision");
    }
  });

  await t.test("single archive and unarchive retain cipher revision, trash state, and encrypted fields", async () => {
    const item = await lifecycleFixture(owner, { folderId: folder.id });
    ok(await request(`/api/ciphers/${item.id}/delete`, { method: "PUT", token }), "trash before archive");
    const trashed = ok(await request(`/api/ciphers/${item.id}`, { token }), "trashed archive fixture");
    for (const action of ["archive", "unarchive", "unarchive"]) {
      const before = await vaultState(token);
      await delay(5);
      const response = await request(`/api/ciphers/${item.id}/${action}`, { method: "PUT", token });
      assert.equal(response.status, 200, `single ${action}`);
      assert.equal(response.data.id, item.id);
      const archived = action === "archive";
      assert.equal(typeof response.data.archivedDate === "string", archived);
      if (!archived) assert.equal(response.data.archivedDate ?? null, null);
      assert.equal(response.data.revisionDate, trashed.revisionDate, "Archive metadata must not change cipher revision");
      assert.equal(response.data.deletedDate, trashed.deletedDate, "Archive must preserve trash state");
      for (const field of ["name", "notes", "login", "fields", "folderId"]) {
        unchanged(response.data[field], trashed[field], "Archive actions must preserve encrypted fields");
      }
      assert((await vaultState(token)).revision > before.revision, "Archive actions must advance account revision");
    }
  });

  await t.test("bulk archive deduplicates IDs, refreshes archive time, and follows ordinary-edit archive metadata rules", async () => {
    const items = [await lifecycleFixture(owner, { folderId: folder.id }), await lifecycleFixture(owner, { folderId: folder.id })];
    const ids = [items[1].id, items[0].id, items[1].id];
    const apply = action => request(`/api/ciphers/${action}`, { method: "PUT", token, body: { ids } });
    let revision = (await vaultState(token)).revision;
    await delay(5);
    const archived = lifecycleList(await apply("archive"), ids, "bulk archive");
    assert(archived.every(item => typeof item.archivedDate === "string"));
    let state = await vaultState(token);
    assert(state.revision > revision, "Bulk archive must advance account revision");
    revision = state.revision;
    await delay(5);
    const repeated = lifecycleList(await apply("archive"), ids, "repeat bulk archive");
    state = await vaultState(token);
    assert(state.revision > revision, "Repeated bulk archive must advance account revision");
    for (const item of repeated) {
      assert.equal(item.revisionDate, items.find(old => old.id === item.id).revisionDate);
      assert(Date.parse(item.archivedDate) > Date.parse(archived.find(old => old.id === item.id).archivedDate));
    }
    const exactDate = "2026-02-01T00:00:00.123456Z";
    const editBody = {
      ...repeated[0], encryptedFor: ownerId, favorite: true, archivedDate: exactDate,
      lastKnownRevisionDate: repeated[0].revisionDate,
    };
    const edited = ok(await request(`/api/ciphers/${editBody.id}`, { method: "PUT", token, body: editBody }), "ordinary archived-item edit");
    assert.equal(edited.archivedDate, exactDate, "An explicit valid archive date must retain all six fractional digits");
    assert.equal((await vaultState(token)).ciphers.find(item => item.id === edited.id).archivedDate, exactDate);
    assert(Date.parse(edited.revisionDate) > Date.parse(repeated[0].revisionDate));
    const invalidDate = ok(await request(`/api/ciphers/${edited.id}`, {
      method: "PUT", token,
      body: { ...edited, encryptedFor: ownerId, archivedDate: "not-a-date", lastKnownRevisionDate: edited.revisionDate },
    }), "invalid archive-date edit");
    assert.equal(invalidDate.archivedDate, edited.archivedDate, "Invalid archive dates must leave the prior annotation intact");
    const omittedBody = { ...invalidDate, encryptedFor: ownerId, lastKnownRevisionDate: invalidDate.revisionDate };
    delete omittedBody.archivedDate;
    const omitted = ok(await request(`/api/ciphers/${edited.id}`, { method: "PUT", token, body: omittedBody }), "omitted archive-date edit");
    assert.equal(omitted.archivedDate ?? null, null, "An omitted archive date must remove the owner's archive annotation");
    assert(Date.parse(omitted.revisionDate) > Date.parse(edited.revisionDate));
    assert.equal((await vaultState(token)).ciphers.find(item => item.id === edited.id).archivedDate ?? null, null);
    const explicitNull = ok(await request(`/api/ciphers/${repeated[1].id}`, {
      method: "PUT", token,
      body: { ...repeated[1], encryptedFor: ownerId, archivedDate: null, lastKnownRevisionDate: repeated[1].revisionDate },
    }), "null archive-date edit");
    assert.equal(explicitNull.archivedDate ?? null, null, "An explicit null date must remove the owner's archive annotation");
    revision = (await vaultState(token)).revision;
    await delay(5);
    const unarchived = lifecycleList(await apply("unarchive"), ids, "bulk unarchive");
    assert(unarchived.every(item => (item.archivedDate ?? null) === null));
    assert((await vaultState(token)).revision > revision, "Bulk unarchive must advance account revision");
    for (const item of unarchived) {
      assert.equal(item.revisionDate, item.id === edited.id ? omitted.revisionDate : explicitNull.revisionDate);
    }
  });

  await t.test("single and bulk archive aliases enforce authentication and owner isolation", async () => {
    const item = await lifecycleFixture(owner);
    const before = await vaultState(token);
    for (const action of ["archive", "unarchive"]) {
      for (const path of [`/api/ciphers/${action}`, `/api/ciphers/${item.id}/${action}`]) {
        denied(await request(path, { method: "PUT", body: { ids: [item.id] } }), "anonymous archive", [401, 403]);
      }
      for (const id of [foreign.id, randomUUID()]) {
        assert.equal((await request(`/api/ciphers/${action}`, { method: "PUT", token, body: { ids: [id] } })).status, 400);
        assert.equal((await request(`/api/ciphers/${id}/${action}`, { method: "PUT", token })).status, 400);
      }
      for (const body of [{}, { ids: null }, { ids: [1] }]) {
        denied(await request(`/api/ciphers/${action}`, { method: "PUT", token, body }), "malformed archive selection", [400, 422]);
      }
    }
    unchanged(await vaultState(token), before, "Rejected archive actions must preserve owned data and revision");
    unchanged(await vaultState(otherToken), foreignBefore, "Archive actions must preserve foreign data and revision");
  });
});

await test("standalone bulk transactions preserve opaque JSON and roll back mixed invalid selections (local provider guarantee)", async () => {
  const owner = await account("Atomic bulk owner");
  const other = await account("Atomic bulk foreign owner");
  const token = owner.token.access_token;
  const otherToken = other.token.access_token;
  const extension = { opaque: '{"quoted":"\\\\ café 🔐","nested":[true,null,7]}', sealed: owner.registration.key };
  const own = await lifecycleFixture(owner, { futureProtocolExtension: extension });
  const foreign = await lifecycleFixture(other);
  for (const path of ["delete", "restore", "archive", "unarchive"]) {
    ok(await request(`/api/ciphers/${path}`, { method: "PUT", token, body: { ids: [own.id, own.id] } }), "opaque bulk transition");
    const fetched = ok(await request(`/api/ciphers/${own.id}`, { token }), "opaque bulk read");
    unchanged(fetched.futureProtocolExtension, extension, "Bulk actions must preserve the adapter's opaque JSON contract");
    unchanged((await vaultState(token)).ciphers.find(item => item.id === own.id).futureProtocolExtension, extension,
      "Sync must retain opaque JSON after a bulk action");
  }
  const before = await vaultState(token);
  const foreignBefore = await vaultState(otherToken);
  for (const action of bulkActions) {
    for (const invalid of [foreign.id, randomUUID()]) {
      for (const ids of [[own.id, invalid], [invalid, own.id]]) {
        assert.equal((await request(action.path, { method: action.method, token, body: { ids } })).status, 400);
        unchanged(await vaultState(token), before, "A rejected local bulk transaction must leave every owned cipher and revision unchanged");
        unchanged(await vaultState(otherToken), foreignBefore, "A rejected local bulk transaction must preserve foreign data");
      }
    }
  }
});

await test("selected archive errors retain only eligible actor archive steps (local provider guarantee)", async () => {
  const owner = await account("Selected archive owner");
  const other = await account("Selected archive foreign owner");
  const token = owner.token.access_token;
  const otherToken = other.token.access_token;
  const folder = ok(await request("/api/folders", {
    method: "POST", token, body: { name: owner.registration.key },
  }), "selected archive private folder");
  const foreignFolder = ok(await request("/api/folders", {
    method: "POST", token: otherToken, body: { name: other.registration.key },
  }), "selected archive foreign folder");
  const foreign = await lifecycleFixture(other, { folderId: foreignFolder.id, favorite: true });
  await lifecycleFixture(owner, { folderId: folder.id, favorite: false });
  const protectedAccount = async bearer => {
    const profile = ok(await request("/api/accounts/profile", { token: bearer }), "selected archive profile");
    delete profile.revisionDate;
    return { profile, keys: ok(await request("/api/accounts/keys", { token: bearer }), "selected archive keys") };
  };
  const foreignBefore = await vaultState(otherToken);
  const foreignAccount = await protectedAccount(otherToken);
  const ownerAccount = await protectedAccount(token);
  const extension = { future: [null, { opaque: "quoted \" café 🔐" }], sealed: owner.registration.key };
  for (const action of archiveActions) {
    for (const priorArchived of [false, true]) {
      for (const foreignTarget of [false, true]) {
        for (const reverse of [false, true]) {
          // Fresh source per trial: no rejected operation's partial effects become
          // another trial's assumed baseline. Request order is not process order.
          const own = await lifecycleFixture(owner, {
            folderId: folder.id, favorite: true, key: owner.registration.key,
            futureProtocolExtension: extension,
          });
          unchanged(own.futureProtocolExtension, extension, "The fixture must preserve its unknown opaque JSON before archive operations");
          if (priorArchived) {
            lifecycleList(await request("/api/ciphers/archive", {
              method: "PUT", token, body: { ids: [own.id] },
            }), [own.id], "selected archive prior state");
          }
          const invalid = foreignTarget ? foreign.id : randomUUID();
          assert.equal((await request(`/api/ciphers/${invalid}`, { token })).status, 400,
            "The invalid selection must remain unreadable to the acting account");
          const before = await vaultState(token);
          const prior = before.ciphers.find(item => item.id === own.id);
          assert(prior, "The eligible source must exist before the request");
          const priorDate = prior.archivedDate ?? null;
          assert.equal(typeof priorDate === "string", priorArchived);
          await delay(5);
          const ids = reverse ? [invalid, own.id] : [own.id, invalid];
          assert.equal((await request(action.path, { method: action.method, token, body: { ids } })).status, 400);
          const after = await vaultState(token);
          const current = after.ciphers.find(item => item.id === own.id);
          assert(current, "A rejected archive selection must never delete its eligible source");
          const currentDate = current.archivedDate ?? null;
          const changedDate = currentDate !== priorDate;
          const advanced = after.revision !== before.revision;
          assert(Number.isSafeInteger(before.revision) && Number.isSafeInteger(after.revision) && after.revision >= before.revision,
            "A rejected archive selection must never regress the acting revision");
          if (action.kind === "archive") {
            assert(currentDate === priorDate || typeof currentDate === "string",
              "An eligible Archive step may only retain or set its private archive date");
            if (advanced) {
              assert(changedDate && typeof currentDate === "string" && Number.isFinite(Date.parse(currentDate)),
                "A completed Archive step must set a fresh selected archive date");
              if (priorDate !== null) assert(Date.parse(currentDate) > Date.parse(priorDate),
                "A completed Archive step must refresh its previous archive date");
            }
          } else {
            assert(currentDate === priorDate || currentDate === null,
              "An eligible Unarchive step may only retain or clear its private archive date");
            if (advanced && !changedDate) assert.equal(priorDate, null,
              "Only an already-unarchived eligible no-op may advance without a date change");
          }
          if (changedDate) assert(advanced, "A durable eligible archive change must advance the actor revision");
          if (!advanced) assert.equal(currentDate, priorDate, "An uncommitted eligible step must preserve its archive date");
          unchanged(after, {
            ...before, revision: after.revision,
            ciphers: before.ciphers.map(item => item.id === own.id ? { ...item, archivedDate: current.archivedDate } : item),
          }, "Only the selected actor archive date and account revision may change after a mixed archive error");
          const fetched = ok(await request(`/api/ciphers/${own.id}`, { token }), "selected archive opaque GET");
          unchanged(fetched, current, "GET and sync must agree on every selected cipher field");
          unchanged(fetched.futureProtocolExtension, prior.futureProtocolExtension, "Selected archive errors must preserve unknown opaque JSON");
          assert.equal(fetched.revisionDate, prior.revisionDate, "Archive steps must preserve the source cipher revision");
          assert.equal((await request(`/api/ciphers/${invalid}`, { token })).status, 400,
            "The invalid target must remain unreadable after a partial eligible step");
          unchanged(await protectedAccount(token), ownerAccount, "Archive errors must preserve account keys and nonrevision profile data");
          unchanged(await vaultState(otherToken), foreignBefore, "Archive errors must preserve the entire foreign vault and revision");
          unchanged(await protectedAccount(otherToken), foreignAccount, "Archive errors must preserve the foreign account and keys");
        }
      }
    }
  }
});

// Run each API-key parent against a fresh upstream process: its default login
// limiter allows ten requests per IP burst. Every group below stays under ten.
await test("personal API-key management requires reauthentication and keeps secrets private", async (t) => {
  const owner = await account("API-key owner");
  const other = await account("API-key foreign owner");
  const token = owner.token.access_token;
  const proof = { masterPasswordHash: owner.registration.masterPasswordHash };
  let first;

  await t.test("first retrieval creates a key and repeated retrieval preserves its key and revision", async () => {
    const before = await vaultState(token);
    await delay(5);
    first = await apiKeyFixture(owner);
    assert((await vaultState(token)).revision > before.revision, "Lazy API-key creation must advance account revision");
    const revision = (await vaultState(token)).revision;
    const repeated = apiKeyResponse(await request("/api/accounts/api-key", {
      method: "POST", token, body: { MasterPasswordHash: owner.registration.masterPasswordHash },
    }));
    assert(repeated.apiKey === first.apiKey, "Retrieval must reuse the existing API key");
    assert.equal(repeated.revisionDate, first.revisionDate);
    assert.equal((await vaultState(token)).revision, revision, "Repeated API-key retrieval must not change account revision");
  });

  await t.test("both management routes require a bearer and exactly one valid owner proof", async () => {
    const before = await vaultState(token);
    for (const path of ["/api/accounts/api-key", "/api/accounts/rotate-api-key"]) {
      for (const bearer of [undefined, "forged-api-key-bearer"]) {
        denied(await request(path, { method: "POST", token: bearer, body: proof }), "API-key management authentication", [401, 403]);
      }
      for (const body of [
        {}, { masterPasswordHash: null }, { masterPasswordHash: "incorrect-proof" },
        { masterPasswordHash: other.registration.masterPasswordHash },
        { ...proof, otp: "123456" }, { otp: "123456" },
      ]) {
        assert.equal((await request(path, { method: "POST", token, body })).status, 400,
          "Management requires exactly one valid owner proof; protected OTP is unavailable in this fixture");
      }
    }
    unchanged(await vaultState(token), before, "Rejected API-key management must preserve vault data and revision");
    const after = await apiKeyFixture(owner);
    assert(after.apiKey === first.apiKey, "Rejected rotation must preserve the existing API secret");
  });

  await t.test("profile and sync never expose a recoverable API secret", async () => {
    const profile = ok(await request("/api/accounts/profile", { token }), "private API-key profile");
    const sync = ok(await request("/api/sync", { token }), "private API-key sync");
    assert(!JSON.stringify({ profile, sync }).includes(first.apiKey), "API secrets must never be present in profile or sync JSON");
  });
});

await test("personal API-key credentials require the correct owner and exact scope", async (t) => {
  const owner = await account("API-grant owner");
  const other = await account("API-grant foreign owner");
  const key = await apiKeyFixture(owner);
  const otherKey = await apiKeyFixture(other);

  await t.test("API grants return owner-bound two-hour access tokens and password-unlock metadata without refresh tokens", async () => {
    const token = apiTokenResponse(await request("/identity/connect/token", {
      method: "POST", form: apiGrantForm(key.clientId, key.apiKey),
    }), owner, key.clientId);
    const profile = ok(await request("/api/accounts/profile", { token: token.access_token }), "API-grant owner profile");
    assert.equal(profile.id, key.userId);
  });

  await t.test("wrong secrets, swapped owner keys, malformed or unknown clients, and wrong or missing scopes are rejected", async () => {
    const before = await vaultState(owner.token.access_token);
    for (const overrides of [
      { client_secret: `${key.apiKey}-incorrect` }, { client_secret: otherKey.apiKey },
      { client_id: key.userId }, { client_id: `user.${randomUUID()}` },
      { scope: "api offline_access" }, { scope: undefined },
    ]) {
      const form = apiGrantForm(key.clientId, key.apiKey, overrides);
      for (const field of Object.keys(form)) if (form[field] === undefined) delete form[field];
      assert.equal((await request("/identity/connect/token", { method: "POST", form })).status, 400,
        "Invalid personal API credentials or scope must be rejected");
    }
    unchanged(await vaultState(owner.token.access_token), before, "Rejected API grants must preserve vault data and revision");
  });
});

await test("personal API-key device fields require presence and accept upstream form aliases", async (t) => {
  const owner = await account("API-device owner");
  const key = await apiKeyFixture(owner);

  await t.test("missing client credentials or any required device field are rejected", async () => {
    for (const field of ["client_id", "client_secret", "deviceIdentifier", "deviceName", "deviceType"]) {
      const form = apiGrantForm(key.clientId, key.apiKey);
      delete form[field];
      assert.equal((await request("/identity/connect/token", { method: "POST", form })).status, 400,
        "Missing API-grant credentials or device fields must be rejected");
    }
  });

  await t.test("present empty device strings and a nonnumeric device type follow upstream permissive parsing", async () => {
    apiTokenResponse(await request("/identity/connect/token", {
      method: "POST", form: apiGrantForm(key.clientId, key.apiKey, {
        deviceIdentifier: "", deviceName: "", deviceType: "not-a-number",
      }),
    }), owner, key.clientId);
  });

  await t.test("case-insensitive compact and underscored form aliases authenticate", async () => {
    apiTokenResponse(await request("/identity/connect/token", {
      method: "POST", form: {
        GRANTTYPE: "client_credentials", CLIENTID: key.clientId, CLIENTSECRET: key.apiKey, SCOPE: "api",
        DEVICE_IDENTIFIER: randomUUID(), DEVICE_NAME: "API-key alias fixture", DEVICE_TYPE: "8",
      },
    }), owner, key.clientId);
  });
});

await test("personal API-key rotation replaces login credentials while preserving issued sessions", async (t) => {
  const owner = await account("API-rotation owner");
  const token = owner.token.access_token;
  const first = await apiKeyFixture(owner);
  const apiBearer = apiTokenResponse(await request("/identity/connect/token", {
    method: "POST", form: apiGrantForm(first.clientId, first.apiKey),
  }), owner, first.clientId);
  let rotated;

  await t.test("rotation changes key and revision but preserves API/password access and password refresh authority", async () => {
    const revision = (await vaultState(token)).revision;
    await delay(5);
    rotated = apiKeyResponse(await request("/api/accounts/rotate-api-key", {
      method: "POST", token, body: { masterPasswordHash: owner.registration.masterPasswordHash },
    }));
    assert(rotated.apiKey !== first.apiKey, "Rotation must produce a different API secret");
    assert(Date.parse(rotated.revisionDate) > Date.parse(first.revisionDate));
    assert((await vaultState(token)).revision > revision);
    ok(await request("/api/sync", { token: apiBearer.access_token }), "API bearer remains authorized after key rotation");
    const refreshed = ok(await request("/identity/connect/token", {
      method: "POST", form: { grant_type: "refresh_token", refresh_token: owner.token.refresh_token, client_id: "cli" },
    }), "password refresh remains authorized after API-key rotation");
    ok(await request("/api/sync", { token }), "original password bearer remains authorized after API-key rotation");
    ok(await request("/api/sync", { token: refreshed.access_token }), "refreshed password bearer after API-key rotation");
    const retrieved = await apiKeyFixture(owner);
    assert(retrieved.apiKey === rotated.apiKey, "Retrieval after rotation must return the new key");
  });

  await t.test("the old secret cannot log in again and the new secret supports repeated client-credentials authentication", async () => {
    assert.equal((await request("/identity/connect/token", {
      method: "POST", form: apiGrantForm(first.clientId, first.apiKey),
    })).status, 400, "The replaced API secret must not grant another access token");
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const granted = apiTokenResponse(await request("/identity/connect/token", {
        method: "POST", form: apiGrantForm(first.clientId, rotated.apiKey),
      }), owner, first.clientId);
      ok(await request("/api/sync", { token: granted.access_token }), "new API-key access");
    }
    ok(await request("/api/sync", { token: apiBearer.access_token }), "old issued API bearer after old-secret rejection");
  });
});

await test("personal attachments preserve opaque bytes and enforce the pinned lifecycle contracts", async (t) => {
  const owner = await account("Attachment owner");
  const other = await account("Attachment foreign owner");
  const token = owner.token.access_token;
  const otherToken = other.token.access_token;
  const item = await lifecycleFixture(owner);
  const second = await lifecycleFixture(owner);
  const foreign = await lifecycleFixture(other);
  const ownerId = ok(await request("/api/accounts/profile", { token }), "attachment owner profile").id;
  const base = id => `/api/ciphers/${id}/attachment`;
  const deletionAliases = [
    { method: "DELETE", suffix: "" }, { method: "DELETE", suffix: "/admin" },
    { method: "POST", suffix: "/delete" }, { method: "POST", suffix: "/delete-admin" },
  ];
  const payload = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
  async function metadata(cipherId, attachmentId) {
    const data = ok(await request(`${base(cipherId)}/${attachmentId}`, { token }), "attachment metadata");
    assert.equal(data.id, attachmentId);
    assert.equal(data.object, "attachment");
    assert.equal(typeof data.size, "string");
    assert.equal(typeof data.sizeName, "string");
    assert(new URL(data.url).searchParams.get("token"), "Direct download must have a scoped capability token");
    return data;
  }
  async function download(url, bytes, status = 200) {
    const response = await request(url, { binary: true });
    assert.equal(response.status, status, "Attachment download status");
    if (status === 200) assert(response.bytes.equals(bytes), "Every opaque attachment byte must survive transport");
  }
  async function reserve(cipherId, size, overrides = {}) {
    const response = await request(`${base(cipherId)}/v2`, {
      method: "POST", token,
      body: { key: owner.registration.key, fileName: owner.registration.key, fileSize: size, ...overrides },
    });
    assert.equal(response.status, 200, "Attachment reservation");
    const data = response.data;
    assert.equal(data.object, "attachment-fileUpload");
    assert.equal(data.fileUploadType, 0);
    assert(data.url === `/ciphers/${cipherId}/attachment/${data.attachmentId}`, "Reservation must return the relative direct-upload path");
    assert.equal((overrides.adminRequest ? data.cipherMiniResponse : data.cipherResponse).id, cipherId);
    return data.attachmentId;
  }
  async function upload(cipherId, attachmentId, bytes) {
    emptyLifecycle(await request(`${base(cipherId)}/${attachmentId}`, {
      method: "POST", token, multipart: attachmentForm(bytes, "ignored-v2-name", "ignored-v2-key"),
    }), "V2 upload");
  }
  async function attached(cipherId, bytes = payload) {
    const id = await reserve(cipherId, bytes.length);
    await upload(cipherId, id, bytes);
    return metadata(cipherId, id);
  }

  await t.test("v2 pending slots, numeric/string sizes, admin responses, empty and large bytes match upstream", async () => {
    for (const [index, bytes] of [Buffer.alloc(0), payload, Buffer.alloc(1024 * 1024 + 37, 0xa5)].entries()) {
      const before = await vaultState(token);
      const id = await reserve(item.id, index === 1 ? String(bytes.length) : bytes.length, {
        adminRequest: index === 2, lastKnownRevisionDate: "2000-01-01T00:00:00.000Z",
      });
      assert.equal((await vaultState(token)).revision, before.revision, "Reservation must not advance account revision");
      const pending = await metadata(item.id, id);
      assert.equal(pending.size, String(bytes.length));
      await download(pending.url, bytes, 404);
      await delay(5);
      await upload(item.id, id, bytes);
      const saved = await metadata(item.id, id);
      assert(saved.key === owner.registration.key && saved.fileName === owner.registration.key,
        "V2 multipart key and filename must not replace reserved encrypted metadata");
      assert.equal(saved.size, String(bytes.length));
      await download(saved.url, bytes);
      const after = await vaultState(token);
      assert(after.revision > before.revision, "Successful upload must advance account revision");
      assert.equal(after.ciphers.find(candidate => candidate.id === item.id).revisionDate, item.revisionDate,
        "Attachment writes must preserve cipher revision");
    }
  });

  await t.test("all four deletion aliases return the updated cipher and remove metadata and stored bytes", async () => {
    for (const action of deletionAliases) {
      const saved = await attached(item.id);
      const before = await vaultState(token);
      await delay(5);
      const response = await request(`${base(item.id)}/${saved.id}${action.suffix}`, { method: action.method, token });
      assert.equal(response.status, 200);
      assert.equal(response.data.cipher.id, item.id);
      assert(!(response.data.cipher.attachments ?? []).some(candidate => candidate.id === saved.id));
      assert.equal(response.data.cipher.revisionDate, item.revisionDate);
      assert((await vaultState(token)).revision > before.revision);
      assert.equal((await request(`${base(item.id)}/${saved.id}`, { token })).status, 400);
      await download(saved.url, payload, 404);
    }
  });

  await t.test("legacy upload aliases and share replacement preserve encrypted metadata with a fresh replacement ID", async () => {
    for (const suffix of ["", "-admin"]) {
      const before = ok(await request(`/api/ciphers/${item.id}`, { token }), "legacy upload baseline");
      const oldIds = new Set((before.attachments ?? []).map(candidate => candidate.id));
      const response = await request(`${base(item.id)}${suffix}`, {
        method: "POST", token, multipart: attachmentForm(payload, owner.registration.key, owner.registration.key),
      });
      assert.equal(response.status, 200);
      assert.equal(response.data.id, item.id);
      assert.equal(response.data.revisionDate, item.revisionDate);
      const saved = response.data.attachments.find(candidate => !oldIds.has(candidate.id));
      assert(saved, "Legacy upload must add a distinct attachment ID");
      assert(saved.key === owner.registration.key && saved.fileName === owner.registration.key);
      await download(saved.url, payload);
      const existingIds = new Set(response.data.attachments.map(candidate => candidate.id));
      const shared = ok(await request(`${base(item.id)}/${saved.id}/share`, {
        method: "POST", token,
        multipart: attachmentForm(Buffer.from([0, 255, 42]), other.registration.key, other.registration.key),
      }), "share attachment replacement");
      const replacement = shared.attachments.find(candidate => !existingIds.has(candidate.id));
      assert(replacement && replacement.id !== saved.id, "Share must replace the attachment with a fresh ID");
      assert(replacement.key === other.registration.key && replacement.fileName === other.registration.key);
      await download(replacement.url, Buffer.from([0, 255, 42]));
      await download(saved.url, payload, 404);
    }
  });

  await t.test("all attachment APIs enforce authentication, owner isolation, and cipher-to-attachment binding", async () => {
    const saved = await attached(item.id);
    const before = await vaultState(token);
    const otherBefore = await vaultState(otherToken);
    const operations = [
      { path: `${base(item.id)}/v2`, method: "POST", body: { key: owner.registration.key, fileName: owner.registration.key, fileSize: 3 } },
      { path: `${base(item.id)}/${saved.id}`, method: "GET" },
      { path: `${base(item.id)}/${saved.id}`, method: "POST", file: true },
      { path: base(item.id), method: "POST", file: true },
      { path: `${base(item.id)}-admin`, method: "POST", file: true },
      { path: `${base(item.id)}/${saved.id}/share`, method: "POST", file: true },
      ...deletionAliases.map(action => ({ path: `${base(item.id)}/${saved.id}${action.suffix}`, method: action.method })),
    ];
    for (const operation of operations) {
      for (const bearer of [undefined, otherToken]) {
        const response = await request(operation.path, {
          method: operation.method, token: bearer, body: operation.body,
          multipart: operation.file ? attachmentForm(payload, owner.registration.key, owner.registration.key) : undefined,
        });
        denied(response, "attachment authorization", bearer ? [400] : [401, 403]);
      }
    }
    for (const method of ["GET", "POST", "DELETE"]) {
      assert.equal((await request(`${base(second.id)}/${saved.id}`, {
        method, token, multipart: method === "POST" ? attachmentForm(payload, "ignored") : undefined,
      })).status, 400, "An attachment ID must not be usable with another owned cipher");
    }
    const capability = new URL(saved.url);
    const missing = new URL(capability); missing.search = "";
    await download(missing, payload, 422);
    const forged = new URL(capability); forged.searchParams.set("token", "forged-download-token");
    await download(forged, payload, 404);
    const wrongPath = new URL(capability); wrongPath.pathname = `/attachments/${second.id}/${saved.id}`;
    await download(wrongPath, payload, 404);
    await download(capability, payload); // A valid capability intentionally needs no bearer.
    unchanged(await vaultState(token), before, "Rejected attachment operations must preserve owner data and revision");
    unchanged(await vaultState(otherToken), otherBefore, "Attachment operations must preserve foreign data and revision");
  });

  await t.test("inclusive one-MiB size leeway adjusts metadata and an out-of-range overwrite deletes its slot and blob", async () => {
    const mib = 1024 * 1024;
    for (const [declared, bytes] of [[mib + 3, Buffer.alloc(3)], ["3", Buffer.alloc(mib + 3)]]) {
      const id = await reserve(item.id, declared);
      await upload(item.id, id, bytes);
      const saved = await metadata(item.id, id);
      assert.equal(saved.size, String(bytes.length));
      await download(saved.url, bytes);
    }
    const saved = await attached(item.id, Buffer.alloc(3));
    const revision = (await vaultState(token)).revision;
    assert.equal((await request(`${base(item.id)}/${saved.id}`, {
      method: "POST", token, multipart: attachmentForm(Buffer.alloc(mib + 4), "ignored"),
    })).status, 400);
    assert.equal((await request(`${base(item.id)}/${saved.id}`, { token })).status, 400);
    await download(saved.url, payload, 404);
    assert.equal((await vaultState(token)).revision, revision, "Size-mismatch cleanup must not advance account revision");
    const limit = await reserve(item.id, 525 * mib);
    ok(await request(`${base(item.id)}/${limit}`, { method: "DELETE", token }), "delete maximum-size pending slot");
  });

  await t.test("malformed reservations and incomplete legacy multipart requests are rejected", async () => {
    const before = await vaultState(token);
    for (const body of [
      {}, { key: owner.registration.key, fileName: owner.registration.key },
      ...[-1, "-1", 525 * 1024 * 1024 + 1, "not-a-number", 1.5, true].map(fileSize => ({ key: owner.registration.key, fileName: owner.registration.key, fileSize })),
    ]) {
      denied(await request(`${base(item.id)}/v2`, { method: "POST", token, body }), "invalid attachment reservation", [400, 422]);
    }
    for (const multipart of [attachmentForm(payload, owner.registration.key), attachmentForm(undefined, undefined, owner.registration.key)]) {
      denied(await request(base(item.id), { method: "POST", token, multipart }), "incomplete legacy upload", [400, 422]);
    }
    unchanged(await vaultState(token), before, "Malformed attachment requests must preserve stored data and revision");
  });

  await t.test("ordinary cipher attachments2 updates metadata, ignores missing IDs, and cannot modify foreign attachments", async () => {
    const saved = await attached(item.id);
    const foreignAttachment = await attachedForForeign();
    async function edit(attachments2) {
      const current = ok(await request(`/api/ciphers/${item.id}`, { token }), "attachment rotation cipher");
      return ok(await request(`/api/ciphers/${item.id}`, {
        method: "PUT", token,
        body: { ...current, encryptedFor: ownerId, attachments2, lastKnownRevisionDate: current.revisionDate },
      }), "attachment metadata rotation");
    }
    async function attachedForForeign() {
      const response = ok(await request(`${base(foreign.id)}/v2`, {
        method: "POST", token: otherToken,
        body: { key: other.registration.key, fileName: other.registration.key, fileSize: 0 },
      }), "foreign attachment slot");
      return response.attachmentId;
    }
    const changed = { key: other.registration.key, fileName: other.registration.keys.encryptedPrivateKey };
    await edit({ [saved.id]: changed });
    const rotated = await metadata(item.id, saved.id);
    assert(rotated.key === changed.key && rotated.fileName === changed.fileName, "Attachment key and name metadata must update exactly");
    await download(rotated.url, payload);
    await edit({ [randomUUID()]: changed });
    const foreignBefore = await vaultState(otherToken);
    await edit({ [foreignAttachment]: changed });
    unchanged(await vaultState(otherToken), foreignBefore, "An attachments2 map must not update a foreign cipher's metadata");
  });

  await t.test("trash/restore keeps attachment data and single/bulk permanent cipher deletion removes every attachment", async () => {
    for (const bulk of [false, true]) {
      const doomed = await lifecycleFixture(owner);
      const saved = [await attached(doomed.id), await attached(doomed.id, Buffer.from([42]))];
      ok(await request(`/api/ciphers/${doomed.id}/delete`, { method: "PUT", token }), "trash attached cipher");
      await download(saved[0].url, payload);
      ok(await request(`/api/ciphers/${doomed.id}/restore`, { method: "PUT", token }), "restore attached cipher");
      assert.equal(ok(await request(`/api/ciphers/${doomed.id}`, { token }), "restored attachment metadata").attachments.length, 2);
      ok(await request(bulk ? "/api/ciphers" : `/api/ciphers/${doomed.id}`, {
        method: "DELETE", token, body: bulk ? { ids: [doomed.id] } : undefined,
      }), "permanently delete attached cipher");
      for (const attachment of saved) await download(attachment.url, payload, 404);
    }
  });
});
