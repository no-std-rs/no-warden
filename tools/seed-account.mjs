#!/usr/bin/env node
/** Generate an ordinary Bitwarden password registration, with no login bypass. */
import {
  createCipheriv, createHmac, generateKeyPairSync, pbkdf2Sync, randomBytes,
} from "node:crypto";
import { pathToFileURL } from "node:url";

// Bitwarden stretches its 256-bit PBKDF2 master key with HKDF-Expand only:
// the master key is already a pseudorandom key, so there is no extract step.
function expand(masterKey, label) {
  return createHmac("sha256", masterKey)
    .update(Buffer.from(label)).update(Buffer.from([1])).digest();
}

function encrypt(plaintext, key) {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", key.subarray(0, 32), iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const mac = createHmac("sha256", key.subarray(32, 64))
    .update(iv).update(ciphertext).digest();
  return `2.${iv.toString("base64")}|${ciphertext.toString("base64")}|${mac.toString("base64")}`;
}

export function registration(email, password, iterations = 600_000) {
  const normalizedEmail = email.trim().toLowerCase();
  const masterKey = pbkdf2Sync(password, normalizedEmail, iterations, 32, "sha256");
  const masterPasswordHash = pbkdf2Sync(masterKey, password, 1, 32, "sha256").toString("base64");
  const stretchedKey = Buffer.concat([expand(masterKey, "enc"), expand(masterKey, "mac")]);
  const userKey = randomBytes(64);
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  return {
    email: normalizedEmail,
    name: "no-warden compatibility test",
    masterPasswordHash,
    masterPasswordHint: null,
    key: encrypt(userKey, stretchedKey),
    keys: {
      publicKey: publicKey.toString("base64"),
      encryptedPrivateKey: encrypt(privateKey, userKey),
    },
    kdf: 0,
    kdfIterations: iterations,
    kdfMemory: null,
    kdfParallelism: null,
    organizationUserId: null,
    referenceData: null,
  };
}

export async function seedAccount(server, email, password) {
  const base = server.replace(/\/$/, "");
  const body = registration(email, password);
  let response = await fetch(`${base}/api/accounts/register`, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  // Recent upstream Vaultwarden follows Bitwarden's two-step registration.
  // A disposable instance without SMTP returns the verification token directly.
  if (response.status === 404) {
    const verification = await fetch(`${base}/identity/accounts/register/send-verification-email`, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ email: body.email, name: body.name, receiveMarketingEmails: false }),
    });
    if (!verification.ok || verification.status === 204) {
      throw new Error(`Registration verification requires a test server with email verification disabled (HTTP ${verification.status}).`);
    }
    const emailVerificationToken = await verification.json();
    if (typeof emailVerificationToken !== "string") {
      throw new Error("Registration verification did not return a token.");
    }
    response = await fetch(`${base}/identity/accounts/register/finish`, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...body, emailVerificationToken }),
    });
  }
  if (!response.ok) {
    throw new Error(`Account registration failed with HTTP ${response.status}: ${await response.text()}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { BW_E2E_EMAIL: email, BW_E2E_PASSWORD: password } = process.env;
  if (!email || !password) {
    console.error("Set BW_E2E_EMAIL and BW_E2E_PASSWORD to register a test account.");
    process.exit(1);
  }
  await seedAccount(process.env.BW_E2E_SERVER ?? "http://127.0.0.1:8000", email, password);
  console.log("Registered compatibility test account.");
}
