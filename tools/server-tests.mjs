#!/usr/bin/env node
/** HTTP security and forward-compatibility checks for the standalone adapter. */
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import test from "node:test";
import { registration } from "./seed-account.mjs";

const server = (process.env.BW_E2E_SERVER ?? "http://127.0.0.1:8000").replace(/\/$/, "");

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
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: response.status, data };
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
  ok(await request("/api/accounts/register", { method: "POST", body: registrationBody }), "registration");
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
      }), `cross-user ${operation.method} ${operation.suffix}`, [403, 404]);
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
    denied(await request(`/api/folders/${bobFolder.id}`, { token: aliceToken }), "cross-user folder read", [403, 404]);
    denied(await request(`/api/folders/${bobFolder.id}`, {
      method: "PUT", token: aliceToken, body: { name: alice.registration.key },
    }), "cross-user folder edit", [403, 404]);
    denied(await request(`/api/folders/${bobFolder.id}`, { method: "DELETE", token: aliceToken }), "cross-user folder delete", [403, 404]);
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
    assert.equal(matched.encryptedByKeyId, userKeyId);
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
      ok(await request(`/api/ciphers/${item.id}`, { method: "DELETE", token: aliceToken }), "maximum blob cleanup");
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
    denied(await request("/api/ciphers/create", { token: aliceToken }), "reserved create path is not an item ID", [404]);
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
    }), "cross-user POST folder update", [403, 404]);
    denied(await request(`/api/folders/${folder.id}/delete`, {
      method: "POST", token: aliceToken,
    }), "cross-user POST folder delete", [403, 404]);
    assert.deepEqual(ok(await request(`/api/folders/${folder.id}`, { token: bobToken }), "folder after rejected aliases"), folder);
    const updated = ok(await request(`/api/folders/${folder.id}`, {
      method: "POST", token: bobToken, body: { name: bob.registration.keys.encryptedPrivateKey },
    }), "owner POST folder update");
    assert.equal(updated.name, bob.registration.keys.encryptedPrivateKey);
    ok(await request(`/api/folders/${folder.id}/delete`, { method: "POST", token: bobToken }), "owner POST folder delete");
    denied(await request(`/api/folders/${folder.id}`, { token: bobToken }), "deleted aliased folder", [404]);
    const sync = ok(await request("/api/sync", { token: bobToken }), "folder alias sync");
    assert.equal(sync.folders.some(candidate => candidate.id === folder.id), false);
  });

  await t.test("archivedDate survives cipher creation, update, and sync", async () => {
    const archivedDate = "2026-01-01T00:00:00.000Z";
    const item = ok(await request("/api/ciphers", {
      method: "POST", token: aliceToken, body: cipher(alice, { archivedDate }),
    }), "archived cipher create");
    assert.equal(item.archivedDate, archivedDate);
    const changed = "2026-02-01T00:00:00.000Z";
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
    denied(await request(`/api/ciphers/${item.id}`, { token: aliceToken }), "deleted item read", [404]);
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
    assert.equal(refreshed.UserDecryptionOptions.UserKeyId, userKeyId);
    const relogin = ok(await passwordLogin(alice.registration), "post-migration password login");
    assert.equal(relogin.UserDecryptionOptions.UserKeyId, userKeyId);
  });

  await t.test("refresh rotation keeps unexpired access valid and rejects refresh replay", async () => {
    const form = { grant_type: "refresh_token", refresh_token: bob.token.refresh_token, client_id: "cli" };
    const refreshed = ok(await request("/identity/connect/token", { method: "POST", form }), "refresh token");
    assert.equal(typeof refreshed.access_token, "string");
    assert.equal(typeof refreshed.refresh_token, "string");
    assert.notEqual(refreshed.refresh_token, bob.token.refresh_token);
    denied(await request("/identity/connect/token", { method: "POST", form }), "replay refresh token", [400, 401]);
    ok(await request("/api/sync", { token: bobToken }), "original unexpired access token after refresh");
    ok(await request("/api/sync", { token: refreshed.access_token }), "refreshed access token");
    const nextForm = { grant_type: "refresh_token", refresh_token: refreshed.refresh_token, client_id: "cli" };
    const concurrent = await Promise.all([0, 1].map(() => request("/identity/connect/token", { method: "POST", form: nextForm })));
    assert.deepEqual(concurrent.map(result => result.status).sort(), [200, 400]);
    ok(await request("/api/sync", { token: bobToken }), "original access after concurrent refresh");
    ok(await request("/api/sync", { token: refreshed.access_token }), "previous access after concurrent refresh");
    ok(await request("/api/sync", { token: concurrent.find(result => result.status === 200).data.access_token }), "latest access token");
  });
});
