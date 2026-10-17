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

  await t.test("refresh tokens rotate and an already-used refresh token is rejected", async () => {
    const form = { grant_type: "refresh_token", refresh_token: bob.token.refresh_token, client_id: "cli" };
    const refreshed = ok(await request("/identity/connect/token", { method: "POST", form }), "refresh token");
    assert.equal(typeof refreshed.access_token, "string");
    assert.equal(typeof refreshed.refresh_token, "string");
    assert.notEqual(refreshed.refresh_token, bob.token.refresh_token);
    denied(await request("/identity/connect/token", { method: "POST", form }), "replay refresh token", [400, 401]);
    ok(await request("/api/sync", { token: refreshed.access_token }), "refreshed access token");
  });
});
