# Bitwarden protocol notes

Research date: 2026-10-19. These notes describe upstream wire contracts relevant
to the supported API slices. They are a research target, **not a claim that
every endpoint below is implemented or verified**. The README and real CLI
integration results define the demonstrated compatibility of no-warden.

## Upstream references

| Project | Reference examined |
| --- | --- |
| Vaultwarden | [`58a980f850464f7d9cdc99a765df36f0a3308b91`](https://github.com/dani-garcia/vaultwarden/tree/58a980f850464f7d9cdc99a765df36f0a3308b91) |
| Bitwarden CLI | [`cli-v2026.10.0`, `b449ac1d255784380d75ef026343198891286be7`](https://github.com/bitwarden/clients/tree/b449ac1d255784380d75ef026343198891286be7) |
| Bundled Bitwarden SDK | [`c5e53d3e82ab80fdc9fd79ebd74058399a6444b6`](https://github.com/bitwarden/sdk-internal/tree/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6) |

This document independently describes observable contracts. It does not import
upstream implementation code. Upstream projects retain their respective
licenses.

## Transport and opaque data

For a self-hosted URL such as `http://127.0.0.1:8222`, API paths normally begin
with `/api`, and identity paths with `/identity`. The token endpoint takes
`application/x-www-form-urlencoded`; vault endpoints take JSON. Authenticated
API requests carry `Authorization: Bearer <access_token>`.

The HTTP URL describes the local adapter. The real CLI suite uses a temporary
trusted loopback TLS proxy because CLI 2026.10.0 requires HTTPS; certificate
validation remains enabled.

The server stores client ciphertext. A folder name, cipher name, login username,
password, notes, and many nested fields are encrypted strings, not plaintext.
The client performs decryption with the recovered user key or an individual
cipher key. Preserve opaque nested fields and unknown fields across storage
and synchronization. The independent Rust library must not decrypt vault data
as part of ordinary CRUD.

## Discovery and prelogin

`GET /api/config` returns a config object containing a protocol `version`, server
identity, and an `environment` with `vault`, `api`, `identity`, `notifications`,
`sso`, and `cloudRegion`. Feature flags and the advertised protocol version affect
client behavior. Advertise only behavior that the adapter supports. Vaultwarden
at the reference above advertises `2026.6.0`.

Both of these identity routes accept `{"email":"person@example.test"}`:

- `POST /identity/accounts/prelogin`
- `POST /identity/accounts/prelogin/password`

The newer route is used by CLI `2026.10.0`. Both routes return the same exact
six-field response, including legacy and nested settings and `salt:null`. A
PBKDF2 account with 600,000 iterations returns:

```json
{
  "kdf": 0,
  "kdfIterations": 600000,
  "kdfMemory": null,
  "kdfParallelism": null,
  "kdfSettings": {
    "kdfType": 0,
    "iterations": 600000,
    "memory": null,
    "parallelism": null
  },
  "salt": null
}
```

The required canonical `email` is an opaque string, including empty, control and
Unicode values. A one-string positional array is accepted. Missing/null/wrong
types and duplicate known fields return 422; malformed/surplus positional JSON
and raw invalid UTF-8 anywhere in the body return 400. Unknown fields and bearer
credentials are ignored. The route has no Content-Type restriction. Successful
requests return JSON 200 without changing account, vault, device or revision
state. `/api/accounts/prelogin` is an additional local alias, not a registered
Vaultwarden handler or part of the portable comparison.

Lookup trims Unicode whitespace and lowercases the email. Known accounts return
their stored signed i32 KDF settings verbatim, without registration-policy
filtering. KDF type `0` is PBKDF2-SHA256; `1` is Argon2id. Unknown accounts select
from this ordered catalog; memory and parallelism remain explicit nulls when
absent:

| Slot | KDF | Iterations | Memory | Parallelism |
| --- | --- | --- | --- | --- |
| 0, 1 | PBKDF2 | 600000 | null | null |
| 2 | PBKDF2 | 100000 | null | null |
| 3 | PBKDF2 | 5000 | null | null |
| 4 | Argon2id | 3 | 64 | 4 |
| 5 | Argon2id | 6 | 32 | 4 |

Upstream derives a selection key using HMAC-SHA256 over `prelogin-kdf`, keyed by
its persisted RSA PEM bytes. A second HMAC over normalized email UTF-8 supplies
a big-endian two-byte value modulo six. Identical email and key remain stable
across requests/restarts; independent installations need not choose the same
slot. The adapter uses an independent persisted random 32-byte key rather than
RSA-derived key material. It also returns backend errors instead of upstream's
lookup-error fallback, lacks the shared public limiter, and retains its 16-MiB
body cap versus upstream's decimal 20,000,000-byte JSON cap. These differences
remain partial-parity limits.

`PreloginStorage` owns normalization, known lookup, configured policy and secret
selection outside the allocation-free core. `CompletePreloginResponse` keeps
legacy/nested settings identical and salt null; the prior unsigned four-field
`PreloginResponse` remains available. Client password salt for legacy accounts
is normalized email. The default CLI TS branch uses `kdfSettings` and derives
from email; the feature-gated SDK branch calls the same endpoint and substitutes
normalized email when server salt is null. Argon2 memory and parallelism must
agree at registration, prelogin, token issuance and sync.

The [pinned handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1392-L1439)
and [release 1.37.4](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/accounts.rs#L1377-L1424)
match, including unknown selection. Key lifecycle is specified by
[auth initialization](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L74-L120).
The shipped CLI [password strategy](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/auth/src/common/login-strategies/password-login.strategy.ts#L162-L183)
uses the [prelogin API](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/auth/password-prelogin/password-prelogin-api.service.ts#L15-L25).
The [SDK response conversion](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-auth/src/login/login_via_password/password_prelogin_response.rs#L27-L55)
defines the null-salt fallback. Static callers are distinct from captured route
traces, which remain absent.

## Fixture cryptography and registration

For a legacy PBKDF2 account, a fixture producer can derive:

```text
salt = UTF8(trim(lowercase(email)))
master_key = PBKDF2-HMAC-SHA256(UTF8(password), salt, iterations, 32)
authentication_hash = Base64(PBKDF2-HMAC-SHA256(master_key, UTF8(password), 1, 32))
encryption_key = HKDF-Expand-SHA256(master_key, UTF8("enc"), 32)
mac_key = HKDF-Expand-SHA256(master_key, UTF8("mac"), 32)
user_key = 64 random bytes
wrapped_user_key = EncString2(user_key, encryption_key || mac_key)
```

HKDF here is **expand only** with `master_key` as the pseudorandom key. There is
no additional extract operation. `EncString2` uses AES-256-CBC with PKCS#7 padding
and a fresh 16-byte random IV. Its HMAC-SHA256 authenticates `IV || ciphertext`,
using the second half of its 64-byte composite key. Its text representation is
`2.<Base64(IV)>|<Base64(ciphertext)>|<Base64(HMAC)>`.

A complete account fixture also supplies an RSA encryption key pair. The public
key is base64 DER SubjectPublicKeyInfo; the private key is DER PKCS#8 encrypted
with the user key as an EncString. Supplying a real pair avoids client key
generation and migration paths. These are disposable test account secrets,
never a template for production credentials.

For ordinary password login, the token password is `authentication_hash`; it is
not the plaintext master password. The approved-auth-request variant below uses
its access code instead. Servers should hash that authentication secret again for
storage using an appropriate password verifier.

Sources: [CLI authentication hash](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/key-management/master-password/services/master-password.service.ts),
[CLI key stretching](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/legacy-crypto/src/services/default-key-generation.service.ts),
[SDK encryption](https://github.com/bitwarden/sdk-internal/blob/c159ee882654e65dd885014001c7f3253d1a170e/crates/bitwarden-crypto/src/hazmat/symmetric_encryption/aes256_cbc_hmac_sha256_ae.rs).

Upstream includes a [public PBKDF2 account test vector](https://github.com/bitwarden/sdk-internal/blob/c159ee882654e65dd885014001c7f3253d1a170e/test-vectors/users/v1-pbkdf2-password.json)
with a known password, wrapped user key, RSA keys, and encrypted sample vault.
Its legacy `userKeyId` is initially null. The server must not invent a
cryptographic key identifier; current clients can generate and backfill one.

Current Vaultwarden registration is a two-step identity flow:

1. `POST /identity/accounts/register/send-verification-email` with `email` and
   optionally `name`. When email verification is disabled, the response contains
   a verification token directly; `Accept: application/json` selects a JSON
   string. With email verification, the response is 204 and email delivers it.
2. `POST /identity/accounts/register/finish` with that `emailVerificationToken`
   and the account cryptographic material. The response is
   `{"object":"registerFinish"}`.

The historical account-material shape is:

```json
{
  "email": "person@example.test",
  "emailVerificationToken": "<verification token>",
  "masterPasswordHash": "<base64 authentication hash>",
  "key": "<wrapped user key>",
  "kdf": 0,
  "kdfIterations": 600000,
  "kdfMemory": null,
  "kdfParallelism": null,
  "keys": {
    "publicKey": "<base64 DER SPKI>",
    "encryptedPrivateKey": "<encrypted DER PKCS8>"
  }
}
```

Newer registration may instead provide `masterPasswordAuthentication` and
`masterPasswordUnlock`, each with the same `kdf` settings and normalized `salt`.
The former carries `hash` / `masterPasswordAuthenticationHash`; the latter
carries `key` / `masterKeyWrappedUserKey`. Vaultwarden accepts `userAsymmetricKeys`
as an alias for `keys`, and `userSymmetricKey` as an alias for the old `key`.
The adapter now implements this ordinary two-step flow with SMTP disabled.
The historical `/api/accounts/register` fixture path and strict embedding API
remain separate; their client baseline does not establish modern-flow parity.

Source: [Vaultwarden identity registration](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs).

## Modern ordinary registration contract

The adapter's new ordinary no-SMTP flow follows the
[verification handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L1031-L1103)
and [finish normalization](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L88-L478).
These sections are also unchanged in the examined Vaultwarden `1.37.4` release.
The corrected HTTP comparison below verifies this focused flow separately from
the legacy registration fixture. It establishes no CLI registration-command or
request-trace claim.

Verification requires string `email` and accepts optional/null string `name`.
It does not apply email-format or 50-byte name validation at this stage. With
SMTP disabled it returns the signed token directly: a JSON string only when
the preferred `Accept` media type is exactly `application/json`, otherwise plain
text. Media-type comparison ignores case and parameters; wildcard and `+json`
types alone do not select JSON. Rocket's ordered weighting/specificity behavior,
including `q=0` and ties, is part of the comparison matrix. The
[pinned parameter grammar](https://github.com/rwf2/Rocket/blob/v0.5.1/core/http/src/parse/media_type.rs#L15-L35)
preserves quoted comma/semicolon content and escaped quotes. Only the
[first parameter named `q`, with value length at most five](https://github.com/rwf2/Rocket/blob/v0.5.1/core/http/src/parse/accept.rs#L12-L29),
supplies a weight; a later/longer `q` is unweighted. Quoted quality text is not
escape-decoded before numeric parsing. Malformed input falls back to plain text.
Neither endpoint has
a `format=json` route filter; valid JSON is decoded even with missing, plain-text
or `application/problem+json` content types. Syntax errors return 400 and known
schema/duplicate-field errors return 422.

The token's [claims](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L451-L478)
are `nbf`, `exp`, `iss`, raw-email `sub`, optional `name` and `verified:false`.
The issuer is canonical configured origin plus `|register_verify`; the URL path
is excluded. Lifetime is thirty minutes. Signature, exact issuer, expiry and
not-before validation use the pinned decoder's 30-second leeway and removal of
Unicode whitespace. The adapter signs HS256 with a separate persistent private
key; upstream signs RS256. Cross-server token portability and complete JWT
equivalence are not claimed. A client treats the token as an opaque finish proof.

Finish requires raw string `email`, valid `emailVerificationToken`, and one
credential shape. The owned decoder tries the flat old shape first, even when
both complete shapes are supplied:

| Shape | Required credential fields and aliases |
| --- | --- |
| Old | Signed `kdf`/`kdfType`, `kdfIterations`/`iterations`; `key`/`userSymmetricKey`; `master_password_hash`/`masterPasswordHash` |
| Current | `masterPasswordAuthentication`/`MasterPasswordAuthentication` and `masterPasswordUnlock`/`MasterPasswordUnlock` |
| Authentication | `kdf`/`Kdf`, `salt`/`Salt`, and `hash`/`masterPasswordAuthenticationHash`/`MasterPasswordAuthenticationHash` |
| Unlock | `kdf`, `salt`, and `key`/`masterKeyWrappedUserKey` |
| Optional key pair | `keys`/`userAsymmetricKeys`, containing required string `encryptedPrivateKey` and `publicKey` |

Each KDF also accepts optional signed `kdfMemory`/`memory` and
`kdfParallelism`/`parallelism`. The optional key pair may be omitted or null.
Credential strings remain opaque, including empty/NUL/Unicode values. This
provider does not reuse legacy base64, EncString, email or key-size validation.

For current credentials, both complete KDF structs must be equal and both salts
must equal `email.trim().to_lowercase()`. A mismatch returns 422 before token or
unsupported invitation-proof rejection. The token subject must equal the exact
raw email, including case/whitespace; its name alone may set the account name.
That optional name is limited to 50 UTF-8 bytes at finish, and an absent claim
defaults a new account's name to the storage email. Root finish `name`, ID,
verification flags and other unknown fields grant no authority. Storage email
is Unicode-lowercased without trimming. Password hints trim whitespace and turn
blank values into null; the adapter's fixed policy permits hints.

The [KDF setter](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L690-L725)
requires PBKDF2 iterations at least 100,000, with no new maximum. Argon2 requires
iterations at least one, memory 15–1024 and parallelism 1–16. Other signed KDF IDs
are accepted; non-Argon2 memory/parallelism store null. Signed metadata is retained
in prelogin and token/decryption projections. Finish then applies the upstream
[account-save email validation](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/util.rs#L533-L541):
`email_address` 0.2.9 parsing followed by a URL with a domain, path `/` and no
query. This preserves supported Unicode/display mailbox forms while rejecting
invalid, space-wrapped, IP-only and malformed domain/path inputs. The provider
reports validity to the core, which rejects with 400 after earlier proof/policy/
KDF checks and before account storage. Verification remains permissive.

Successful finish returns exactly `{"object":"registerFinish"}` with status 200.
An existing host account rejects with 400. Unsupported or mixed organization and
emergency-access proof slots reject instead of being treated as ordinary signup.
The provider atomically stores canonical account fields, an Argon2 verifier and
private verification metadata; it excludes the raw token/hash, nested proof
objects and unknown extras. No-SMTP profile/JWT verification remains true under
upstream policy, independently of the false token claim. A failed commit leaves
existing account/vault state unchanged and permits retry; tokens survive restart.

`RegistrationStorage`, owned verified-claims handles, borrowed semantic finish
data and explicit response serializers keep JWTs, Unicode normalization, JSON
compatibility parsing, hashing, clocks and persistence outside the no-allocation
core. The full finish view has no flattened/untagged decoder in the core. The
strict legacy registration API remains available unchanged.
SMTP delivery, invite-JWT/emergency enrollment, domain
restrictions/configuration, rate controls, notifications, complete header grammar,
detailed errors and
transport-limit parity remain open. The adapter's 16-MiB request cap differs
from upstream's 20-MB JSON limit. All eight corrected modern HTTP cases pass
against both the adapter and actual Vaultwarden `1.37.4`: 541 counted requests
per server, including 69 verification requests, 64 finish requests, ten prelogins
and nine successful password logins. Public attempts stay at most 44 per peer
under unchanged reference limits. A fresh official CLI `2026.10.0` regression
also passes all 120 commands against both servers. That unchanged client flow
uses legacy fixture registration; it adds no CLI registration-command trace
or full-parity flag.

## Password login and refresh

`POST /identity/connect/token` form fields:

| Field | Personal password login |
| --- | --- |
| `grant_type` | `password` |
| `client_id` | `cli` |
| `scope` | `api offline_access` |
| `username` | Account email |
| `password` | Base64 authentication hash derived above |
| `deviceIdentifier` | Stable client device identifier |
| `deviceName` | Client device name |
| `deviceType` | Numeric device type as a string |

Vaultwarden also accepts underscore variants of the device fields. A successful
response contains OAuth `access_token`, `expires_in`, `token_type` (`Bearer`),
`refresh_token`, and `scope`. Decryption fields include `Key`, `PrivateKey`,
`Kdf`, `KdfIterations`, `KdfMemory`, `KdfParallelism`, `ForcePasswordReset`,
`MasterPasswordPolicy`, `AccountKeys`, and `UserDecryptionOptions`. Identity
decryption fields historically use PascalCase.

For a personal PBKDF2 account, the unlock part is:

```json
{
  "UserDecryptionOptions": {
    "HasMasterPassword": true,
    "MasterPasswordUnlock": {
      "Kdf": {
        "KdfType": 0,
        "Iterations": 600000,
        "Memory": null,
        "Parallelism": null
      },
      "Salt": "person@example.test",
      "MasterKeyEncryptedUserKey": "<wrapped user key>",
      "MasterKeyWrappedUserKey": "<same wrapped user key>"
    },
    "Object": "userDecryptionOptions"
  }
}
```

The access token must be a JWT because the CLI reads its payload. Relevant claims
are string `sub` (user UUID), `email`, `name`, boolean `email_verified`, `premium`,
numeric `exp`, `nbf`, and server-side `sstamp`, `device`, `devicetype`, `client_id`, `scope`,
and `amr`. NumericDate claims use seconds. Vaultwarden uses a two-hour access
lifetime and issuer `<server origin>|login`. The server must validate its own
tokens; a client decoding a JWT is not a substitute for signature validation.

Refresh uses the same endpoint with `grant_type=refresh_token`, `refresh_token`,
and `client_id`. Success returns the OAuth fields and new tokens. An invalid
refresh must return HTTP 400 with at least `{"error":"invalid_grant"}`; clients
use this to discard unusable login state. Enforce expiry and user/device binding.

Sources: [Vaultwarden identity](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs),
[CLI token parsing](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/auth/models/response/identity-token.response.ts),
[JWT claims](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs).

## Device discovery

The [pinned discovery handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1504-L1580)
expose three read routes:

| Method and route | Authentication and result |
| --- | --- |
| `GET /api/devices/knowndevice` | Public header guard; bare JSON boolean |
| `GET /api/devices` | Bearer required; owner-only list wrapper |
| `GET /api/devices/identifier/<id>` | Bearer required; one owned device, or 400 when absent/foreign |

Known-device discovery requires both `X-Request-Email` and
`X-Device-Identifier` headers. The email guard removes every trailing `=`,
strictly decodes unpadded base64url, and requires valid UTF-8. Missing or invalid
headers return 400. Account lookup lowercases the decoded email without trimming
it. The identifier is an exact opaque UTF-8 string; an empty or non-UUID value is
allowed. Unknown accounts or identifiers return false without authentication.

The identifier path has a different guard. Rocket percent-decodes the path
segment, then the [upstream `IdFromParam` macro](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/macros/src/lib.rs#L40-L58)
accepts only ASCII letters, digits and hyphens, keeping their spelling and case.
There is no UUID requirement. Percent-encoded letters and hyphens work.
Decoded identifiers containing `+`, underscore, slash or Unicode reject with
422; a literal `+` keeps its value rather than being form-decoded.
Authentication precedes this path guard: a missing/invalid bearer returns 401
before an invalid identifier is parsed.

The [single-device model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/device.rs#L67-L78)
projects exactly `id`, `name`, `type`, `identifier`, `creationDate`, `isTrusted`,
and `object: "device"`; `isTrusted` is false. The list wrapper has `data`,
`continuationToken: null`, and `object: "list"`. Each list entry adds
`devicePendingAuthRequest`, `encryptedPublicKey`, and `encryptedUserKey`, giving
ten fields. The encrypted-key fields are null. The pending model has only
[`id` and `creationDate`](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/auth_request.rs#L76-L82),
or null without a request. The standalone adapter selects the latest pending
request by creation date for the exact owner/requesting device. Approval and
login remain separate from this discovery projection.

Successful password and personal API-key logins register the authenticated
owner's device. The three device form fields require presence; their identifier
and name remain opaque, including empty strings. The
[pinned login helper](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L776-L797)
parses device type as `i32`, falling back to 14 when parsing fails. Reusing an
owner/identifier retains its initial name, type and creation time. Different
owners may use the same identifier. Activity updates do not advance account
revision or change vault data. Refresh retains the existing device identity,
regardless of device metadata supplied in the refresh form.

The allocation-free core exposes `DeviceStorage`, borrowed header input, and
explicit boolean/list/single response projections. The standalone adapter owns
the persistent registry, session binding and `device` JWT claim. Legacy sessions
without bindings remain valid and are not backfilled. Device removal,
notification behavior and broader device management remain unimplemented. The direct HTTP comparison establishes only
this discovery/login-binding contract, with no CLI device-route trace claim.

## Device push tokens

The [pinned token handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1577-L1641)
provide four aliases, all returning a genuinely empty 200 response, not JSON null:

| Method and route | Target and authentication |
| --- | --- |
| `POST` / `PUT /api/devices/identifier/<id>/token` | Verified session's device; bearer and JSON body required |
| `POST` / `PUT /api/devices/identifier/<id>/clear-token` | Public path identifier; disabled push returns without clearing |

The write path ID must pass `IdFromParam` syntax but does not select the target.
The verified [request guard](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L637-L710)
resolves the device from its authenticated session. A syntactically valid path
can name a missing device or any other device; its value does not redirect or
reject the write. Request device headers and owner fields have no authority. Guard order is
session/device authentication, path validation, then JSON decoding; anonymous or
unbound sessions return 401 before malformed paths or bodies are parsed.

The required `pushToken` field is an opaque string: empty, control and Unicode
values are accepted without normalization. Positional `["value"]` is also valid.
Missing, null, wrong-typed or duplicate known fields return 422. Malformed JSON
and surplus positional elements return 400. Unknown fields are ignored.
An identical present token returns before persistence, activity or relay hooks.
A changed token saves with device activity before
[registration](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/push.rs#L87-L151).
Registration failure leaves that save in place; repeating the same token does
not retry registration. Account revision, original device metadata and vault data
remain unchanged.

Clear applies its path guard even without a valid bearer and ignores body data.
With push disabled it returns an empty 200 without clearing or looking up devices.
With push enabled the provider clears every owner's token for that exact
identifier, then unregisters only the first selected matching record's push ID
when present. A first record without a push ID does not use another owner's ID.
Unregister failure retains the cleared state. The core exposes this ordering
through `DevicePushStorage`; enabled-provider tests establish those hooks, not
interoperability with a real relay.

The standalone adapter has push disabled. Its token writes and no-op clears do
not send network requests. Its legacy unbound access sessions remain valid for
existing routes but cannot choose a push-write target. Upstream clear has an
unauthenticated rate limiter; the local adapter does not implement it. Real relay
registration, unregistration, push delivery, abuse controls and notification APIs
remain open. All eight focused HTTP cases pass against the adapter and official
Vaultwarden `1.37.4`: 383 counted requests and three password logins per server.
A separate private Rust/read-only SQLite probe also passes against both servers:
16 HTTP requests and 13 read-only checks per server, using three password logins
and one refresh. It confirms target selection, retained activity on an identical
token, disabled-clear retention and refresh binding. Literal zero SQL writes is
a stronger property covered by host trigger tests. No CLI device-token route
attribution or live enabled-relay behavior is claimed.

## Auth-request creation and discovery

The [pinned creation and lookup handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1650-L1743)
and [pending-list aliases](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1863-L1900)
provide this discovery slice:

| Method and route | Contract |
| --- | --- |
| `POST /api/auth-requests` | Public creation for an existing account and matching registered device |
| `GET /api/auth-requests/<id>` | Authenticated owner-only lookup, including stored approval states |
| `GET /api/auth-requests` | Authenticated pending list alias |
| `GET /api/auth-requests/pending` | Authenticated pending list; only records whose approval is null |

Creation requires four string fields, in positional order `accessCode`,
`deviceIdentifier`, `email`, `publicKey`. Escapes, blank/control/NUL/Unicode values
and opaque non-UUID device identifiers are accepted as strings; account/device
verification still applies. Unknown fields are ignored. Missing, null,
wrong-typed or duplicate known fields return 422; malformed JSON and surplus
positional elements return 400. A four-element positional array is accepted.
Email lookup lowercases Unicode without trimming whitespace. The existing device
must match the resolved owner, exact identifier and raw header type.

[ClientHeaders](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L610-L636)
parses optional `device-type` as `i32` without trimming, using 14 for absence or
parse failure. Unknown numeric types retain their value for equality checks;
only response labels map them to `Unknown Browser`. Creation ignores bearer
credentials. Lookup/list require the verified session device; authentication
precedes the single-request UUID guard. Percent decoding occurs once and retains
the accepted UUID spelling, including case, braces and URN forms. Malformed UUIDs
return 422; valid missing or foreign requests return 400.

Each auth-request response has exactly `id`, `publicKey`, `requestDeviceType`,
`requestIpAddress`, `key`, `masterPasswordHash`, `creationDate`, `responseDate`,
`requestApproved`, `origin`, and `object: "auth-request"`. Creation returns false
for `requestApproved`, with null key/hash/response date; its stored approval is
null, which GET and pending list return. The list wrapper has `data`,
`continuationToken: null`, and `object: "list"`. Access codes, owner identifiers
and requesting-device identifiers are never projected. Internal models and
responses redact Debug output.

The [pending-device model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/auth_request.rs#L145-L163)
selects the latest creation date for the owner/requesting device with null
approval. Device lists project only that request's `id` and `creationDate`, or
null; single-device responses remain seven fields. Creation does not update
account revision, device activity, vault state or credentials. The standalone
adapter records the direct socket peer and ignores forwarding headers. Upstream
[ClientIp](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L1092-L1162)
can honor the configured IP header from trusted proxies; its
[defaults](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/config.rs#L667-L680)
use `X-Real-IP` and trust local peers. Forwarded-IP parity remains unimplemented.
The adapter's peer-address unit test verifies its own policy, not equivalence to
that upstream proxy behavior. Canonical origin from the configured URL, without
its path, does match upstream.

All eight focused Rust HTTP cases pass against the adapter and official
Vaultwarden `1.37.4`: 273 requests and five successful logins per server, with 33
decoded creation attempts below the unchanged upstream public burst of 50. The
suite includes a NUL/Unicode/non-UUID device identifier. Host tests separately
verify hidden activity/state preservation, rollback, durable private storage and
peer metadata; response projections alone do not establish those properties.
Notifications/events, expiry cleanup, trusted proxy policy
and local rate controls remain open. No
CLI auth-request route claim or complete authentication parity is established.

## Auth-request approval and response polling

The [pinned decision and polling handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1745-L1861)
add two routes; neither route itself grants a login:

| Method and route | Contract |
| --- | --- |
| `PUT /api/auth-requests/<id>` | Authenticated owner decision; JSON device must match the verified session device |
| `GET /api/auth-requests/<id>/response?code=...` | Public code/type/IP-protected read; bearer ignored |

The PUT body requires string `deviceIdentifier`, string `key`, boolean
`requestApproved`, and optional nullable string `masterPasswordHash`. Positional
order is device, key, hash, decision; `["device","key",null,true]` is valid.
Strings stay opaque, including empty/control/Unicode values. Missing/wrong-typed
known fields and duplicate known fields return 422; syntax and surplus positional
elements return 400. Unknown fields are ignored. Authentication/session binding
precedes UUID validation, which precedes JSON decoding. A foreign/missing request,
a mismatched body device or an already-answered request rejects before mutation.

True decisions save `approved: true`, the supplied key/hash, the response device
and fresh response time. False decisions delete the pending record. Their
response still contains its old key/hash and null approval, with a fresh
`responseDate`; the rejected body's key/hash are ignored. Responses retain the
same eleven-field projection. Pending-list and device metadata remove a decided
request, exposing an older pending request when one exists. Both actions preserve
account revision, device activity, sessions, vault and unrelated requests.

Public polling first applies UUID and required `code` query guards. A missing
query field returns 422; empty and bare `code` reach verification. The first
matching case-sensitive `code` root wins, including dotted/bracketed scalar forms.
Form decoding changes literal `+` to space, `%2B` to plus, and percent-decodes once
with lossy UTF-8 handling. A wrong code, original raw `device-type`, recorded IP,
or missing record returns the same opaque 400 error. Code verification belongs
to the provider and uses constant-time fixed-size HMAC tag verification in the
host. Pending and approved records can be polled repeatedly, with no consumption
or implicit expiry. Rejected records are gone and return 400.

The optional device-type fallback and direct-peer/forwarding-header limitation
are unchanged. Canonical configured origin remains the response origin. The
no-allocation core exposes `AuthRequestResponseStorage` and borrowed update data;
clocks, code verification, storage and HTTP/query guards remain adapter duties.
Host tests cover rejection snapshots, constant-time primitive usage, wrong proofs,
rollback and reopen. All eight selected HTTP cases pass against the adapter and
official Vaultwarden `1.37.4`: 322 counted requests and four successful logins
per server. Eleven creates and 33 guard-valid polls produce 44 admitted public
attempts; six additional query/path guard rejections do not reach the handler
rate limiter. The reference retains its public burst of 50. The combined local
HTTP milestone passes 72 cases and 3038 requests, including the login group.
Current client and login
comparison results are recorded in [verified compatibility](compatibility.md).
Notifications/events, expiry cleanup, trusted proxy policy and local rate controls
remain open; this is not full authentication parity.

## Login with an approved authentication request

The [pinned password handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L370-L498)
selects an access-code proof when the password grant includes `authRequest`.
The [form declaration](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L1108-L1157)
accepts this compact root case-insensitively, including `authRequest.x`,
`authRequest[root]`, `[authRequest]` and `.authRequest` scalar names;
`auth_request` is an ignored unknown field. The value is an opaque string, rather than a UUID-guarded path parameter.
A present empty, unknown or foreign ID selects this variant and fails proof;
it cannot fall back to ordinary password verification.

`grant_type=password` requires present client ID, password, scope, username,
device identifier, name and type. The scope is exactly `api offline_access`.
Missing required `grant_type` is a form-guard 422; absent optional grant fields
are handler errors with status 400. Present empty strings reach validation;
an empty code works when it is the stored code, and blank device type falls back
to 14. The password field contains the original creation access code, never the
encrypted `masterPasswordHash` supplied by approval. Username is trimmed before
Unicode-lowercase account lookup. Compact/underscore client and device aliases
follow the existing case-insensitive form adapter.

Login requires the exact owner, constant-time code verification, `approved=true`,
no prior authentication timestamp, an enabled account, the same IP and
`now < creation + five minutes`. Expiry starts at creation, not approval, and
equality with the deadline rejects. Neither the requested login device ID nor
its raw type must equal the request's original device. A successful login can
create a different registered device. The adapter uses the direct socket peer
and ignores forwarding headers; upstream trusted-proxy handling remains open.

The [upstream consumption model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/auth_request.rs)
records an authentication timestamp. The adapter adds an owner-scoped
approved/unused compare-and-set and wraps it together with device activity,
session issuance and binding in a savepoint. Late failures, including deferred
commit errors, restore all of them. Replay cannot issue another session.
Approval/key/hash/response fields remain unchanged, and public polling can still
read an approved request after login or beyond the login deadline. No polling
consumption or implicit polling expiry is added. All eight focused login HTTP
cases pass against both the adapter and actual Vaultwarden `1.37.4`: 444 counted
requests, including 43 identity requests, twelve creations and twelve public
polls per server. Identity requests include two ordinary logins, seven successful
auth-request logins and two refreshes. The real 301-second fixture confirms
expired login with readable polling, separately from unit-clock boundary tests.

`AuthRequestLoginStorage` and borrowed `AuthRequestLoginRequest` keep proof
verification and clocks outside the no-allocation core. Its private record and
unforgeable owned-account grant redact Debug output and cannot serialize secrets.
The host parses creation dates into full-width nanoseconds, reuses fixed-size
HMAC verification, and reads enabled state from a private account-policy table.
Missing policy rows mean enabled; registration or profile extras cannot override
that state. This table does not provide an administrative account API.

The [password-method token source](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L239-L313)
uses a two-hour access lifetime. The adapter now uses 7200 seconds for ordinary
and auth-request password grants and refresh. Password login retains encrypted
account-decryption fields; refresh returns only its five OAuth fields.
JWT `client_id` is the supplied value, including empty, or `undefined` when
absent. Refresh uses the optional
client ID on the refresh request. Bound tokens project `device` and the retained
registry type label as `devicetype`; repeated login/refresh does not replace the
stored name/type. Personal API-key authority is unchanged. Legacy unbound
sessions retain existing access behavior but cannot refresh without current
device authority.

The password-method refresh contract below preserves source proof reuse. Full
JWT/refresh-token representation and `nbf` equivalence, two-factor/mail/SSO policy,
administrative controls, notifications, expiry cleanup, rate controls and proxy
policy remain open. Required CI reruns the HTTP comparison and the verified
unchanged 120-command CLI baseline. That client regression does not
exercise auth-request login or establish broader authentication parity.

## Profile, account keys, and synchronization

`GET /api/accounts/profile` returns a profile containing the account `id`, `name`,
`email`, `emailVerified`, encrypted `key` and `privateKey`, `securityStamp`,
`creationDate`, empty organization/provider lists for an individual account,
and `object: "profile"`. Its `accountKeys` carries:

```json
{
  "publicKeyEncryptionKeyPair": {
    "wrappedPrivateKey": "<encrypted private key>",
    "publicKey": "<base64 DER SPKI>",
    "signedPublicKey": null,
    "object": "publicKeyEncryptionKeyPair"
  },
  "securityState": null,
  "signatureKeyPair": null,
  "object": "privateKeys"
}
```

`GET /api/accounts/keys` returns `key`, `publicKey`, `privateKey`, `accountKeys`,
and `object: "keys"`. Upstream returns 404 when the account has no key pair.
`POST /api/accounts/keys` accepts `publicKey` and `encryptedPrivateKey` to
initialize a missing pair; it must not overwrite an existing pair.

Current clients backfill a legacy user-key identifier through authenticated
`POST /api/accounts/key-management/user-key-id`. The required canonical
`userKeyId` is an opaque string: empty, long, Unicode and escaped NUL values are
accepted, with no core UUID/hex/size policy. A one-string positional array is
also accepted. Unknown fields cannot select another account. Current device and
security-stamp authorization precede JSON decoding. Missing/null/wrong-type or
duplicate known fields return 422; syntax, surplus positional data and raw
invalid UTF-8 anywhere in the body return 400. This route does not require a
JSON Content-Type. Successful initialization returns empty **200**, advances
account revision, and preserves keys, sessions, devices and cipher revisions.
Any existing ID, including empty, rejects every repeat with **422** and the
nine-field API error message `Unexpected data`.

The authoritative observation is `sync.userDecryption.userKeyId`. Upstream
profile and password/API-key token options omit it; the adapter's inherited
extra `UserDecryptionOptions.UserKeyId` is not a full-projection parity claim.
The core `AccountKeyIdStorage` provider and SQLite transaction compare-and-set
an absent ID with its revision atomically, a stronger guarantee than upstream's
separate check/save. This identifies existing key material without rotating it.
The adapter's 16 MiB body cap is 16,777,216 bytes; upstream's JSON cap is
20 MB (20,000,000 bytes).

The [pinned handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1067-L1081)
and [release 1.37.4 handler](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/accounts.rs#L1052-L1066)
agree. Its [KeyId model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs#L555-L573)
wraps a String; the SDK's stricter 32-hex ID representation is a client contract.
CLI [login](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/auth/commands/login.command.ts#L402-L424)
and [unlock](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/key-management/commands/unlock.command.ts#L96)
invoke the unflagged backfill migration. The
[SDK](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-user-crypto-management/src/key_id_backfill.rs#L40-L90)
records the local ID only after API acceptance. The client migration syncs and
rechecks server state before posting;
API failures trigger a client cooldown. No captured request trace is claimed.

`GET /api/accounts/revision-date` returns a JSON integer timestamp in
**milliseconds**. Successful account or vault mutations advance this revision.

`GET /api/sync?excludeDomains=true` returns a complete personal snapshot with
`profile`, `folders`, `ciphers`, `collections`, `policies`, `policiesNew`,
`sends`, `domains`, `userDecryption`, and `object: "sync"`. Empty lists are
arrays. `domains` is null when excluded. For a legacy password account,
`userDecryption.masterPasswordUnlock` has the same content as the identity
unlock data but **camelCase** keys, and `userDecryption.userKeyId` can initially
be null until a client backfills it.
Include trashed ciphers in sync so clients can show and restore them.

Sources: [Vaultwarden profile](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs),
[Vaultwarden sync](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs),
[CLI sync response](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/platform/sync/sync.response.ts).

## Folders

| Method and API path | Behavior |
| --- | --- |
| `GET /api/folders` | List response |
| `GET /api/folders/{id}` | One owned folder |
| `POST /api/folders` | Create from opaque string `name` |
| `PUT /api/folders/{id}` | Replace opaque string `name` |
| `POST /api/folders/{id}` | Update alias |
| `DELETE /api/folders/{id}` | Delete folder, retain its ciphers |
| `POST /api/folders/{id}/delete` | Delete alias |

A folder response has exactly `id`, `name`, `revisionDate`, and
`object: "folder"`. Clients normally encrypt `name`; upstream accepts any string,
including empty strings. The optional body `id` accepts a string or null and is
ignored during CRUD: creation generates an ID, and updates use the route ID.
Unknown request fields do not enter responses.

Malformed JSON returns 400; semantic decoding errors, including missing names,
wrong field types, and duplicate known fields, return 422. Folder UUID path
syntax is validated without normalizing its spelling. A malformed path ID
returns 422; a valid but absent or foreign folder ID returns 400. Both delete
aliases return an empty 200 response.
A list response is `{"data":[...],"object":"list","continuationToken":null}`.
Deleting a folder clears its association and advances the account revision
without deleting vault items or changing their cipher revisions, archive state,
encrypted fields, or attachment bytes. IDs belonging to another account must not be usable by the caller. The
core classifies both legacy POST aliases in the table, as well as PUT updates
and DELETE removal.

Source: [Vaultwarden folders](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/folders.rs).

## Ciphers

| Method and API path | Behavior |
| --- | --- |
| `GET /api/ciphers` | List response |
| `GET /api/ciphers/{id}` | One accessible cipher |
| `GET /api/ciphers/{id}/details` | Same accessible-cipher read |
| `GET /api/ciphers/{id}/admin` | Same accessible-cipher read; upstream admin TODO |
| `POST /api/ciphers` | Create encrypted cipher |
| `POST /api/ciphers/create` | Create/clone from the wrapped request below |
| `PUT /api/ciphers/{id}` | Replace encrypted cipher |
| `POST /api/ciphers/{id}` | Update alias |
| `PUT /api/ciphers/{id}/delete` | Move to trash |
| `PUT /api/ciphers/{id}/restore` | Restore and return cipher |
| `DELETE /api/ciphers/{id}` | Permanent deletion |
| `POST /api/ciphers/{id}/delete` | Permanent deletion alias |

Legacy field-level write requests carry `type`, encrypted `name`, `notes`,
`folderId`, `organizationId`, `favorite`, `reprompt`, `fields`, `passwordHistory`,
optional individual encrypted `key`, and one type-specific object. Modern
requests also carry `encryptedFor` (the user UUID) and optionally the opaque
`encryptedByKeyId`. The core retains both and checks `encryptedFor` against the
authenticated owner. On creation, `Storage::user_key_id` supplies the account's
current key ID when available; different supplied IDs are rejected. Embeddings
that support key-ID backfill must override the default provider returning None.

Existing-item writes may contain `lastKnownRevisionDate`; reject stale writes
before mutating storage. A provider can override `Storage::map_error` to map a
known conditional-write conflict to `ErrorKind::Conflict` (HTTP 409), while
keeping unknown failures generic. The revision check and write must share the
same lock or transaction. Fresh creates discard a source item's revision.

The clone endpoint accepts `{"cipher":{...},"collectionIds":[]}`. The core's
borrowed `CipherCreateRequest` uses a bounded collection and delegates personal
creates to the same validation and ownership rules. Nonempty collection IDs
are rejected by the personal-vault service.

For an initial personal vault, reject non-null organization IDs until the
organization authorization model is implemented. Both `organizationId` and the
upstream alias `organizationID` are recognized; the standalone HTTP suite
verifies rejection through direct and wrapped writes.

Type-specific object names are `login` (1), `secureNote` (2), `card` (3),
`identity` (4), `sshKey` (5), `bankAccount` (6), `driversLicense` (7), and
`passport` (8). The CLI release under test knows all eight request shapes.
The core currently models field-level types 1–5. Its opaque blob path permits
type metadata 1–8 without interpreting the encrypted contents. Opaque storage
alone does not establish end-to-end support for each type.

A login can include encrypted `username`, `password`, `totp`, URI records, and
`fido2Credentials`, plus plaintext metadata `passwordRevisionDate` and
`autofillOnPageLoad`. A URI contains encrypted `uri`, numeric/null `match`, and
encrypted `uriChecksum`. Keep this nested JSON intact even when the core does
not interpret it.

Stored FIDO2 credential fields `credentialId`, `keyType`, `keyAlgorithm`,
`keyCurve`, `keyValue`, `rpId`, `rpName`, `counter`, `userHandle`, `userName`,
`userDisplayName`, and `discoverable` contain encrypted strings, including the
fields whose names suggest counters or booleans. `creationDate` is plaintext
ISO date metadata and can be null. The borrowed core model preserves these
optional fields in a list capped at 16 credentials. This cap is a project
resource policy, not an upstream protocol limit. Stored credential support
does not implement WebAuthn/passkey login or demonstrate authenticator use.
HTTP tests verify that all these fields, including unknown nested extensions,
survive create/get/update/sync unchanged.

Sources: [CLI encrypted credential writes](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/vault/models/request/cipher.request.ts),
[CLI credential domain model](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/vault/models/domain/fido2-credential.ts).

Blob-encryption clients put sensitive content into optional `data` and omit
legacy `name` and type-specific objects. The SDK's blob value is an **opaque JSON
string** containing `format_version`, `wrapped_cek`, and `envelope`; it is not
itself an EncString. The core preserves nonempty blob data up to its
1,048,576-byte field-size bound and conditionally requires legacy fields only when data is
absent. It does not parse or authenticate the inner blob. Escaped inner JSON
requires an application-owned decoding buffer when the transport decoder
cannot borrow the decoded string. The standalone host first decodes owned JSON,
then borrows from those decoded strings for core validation.

Separately, an encrypted wrapped key can use `7.<Base64(COSE_Encrypt0 bytes)>`.
The core checks the nonempty base64 envelope and keeps the bytes opaque;
it does not validate CBOR structure or implement COSE encryption. SDK schema
support is not a claim that the pinned Vaultwarden version supports blob
ciphers, or that a real-client blob round trip has passed here.

Sources: [SDK blob encryption](https://github.com/bitwarden/sdk-internal/blob/c159ee882654e65dd885014001c7f3253d1a170e/crates/bitwarden-vault/src/cipher/blob/encryption.rs),
[SDK sealed blob string](https://github.com/bitwarden/sdk-internal/blob/c159ee882654e65dd885014001c7f3253d1a170e/crates/bitwarden-vault/src/cipher/blob/sealed.rs),
[SDK EncString formats](https://github.com/bitwarden/sdk-internal/blob/c159ee882654e65dd885014001c7f3253d1a170e/crates/bitwarden-crypto/src/enc_string/symmetric.rs).

Personal cipher responses add server `id`, UTC `creationDate`, `revisionDate`,
`deletedDate` (null or trash time), `archivedDate`, `attachments`,
`collectionIds`, `edit`, `viewPassword`, and `permissions: {"delete":true,
"restore":true}`. Upstream's detailed object discriminator is `cipherDetails`.
Type-specific objects other than the selected type may be null. A trash request
sets `deletedDate`; it does not destroy encrypted contents. A restore clears
that date. Permanent deletion removes the stored object.

The API response metadata is authoritative: never accept client-supplied IDs,
ownership, creation time, revision time, or permission booleans as authority.
Mutations must enforce account ownership, folder ownership, and revision checks
before committing a change.

`archivedDate` is client-supplied metadata retained by the adapter. HTTP tests
cover its preservation across create/update/sync; the dedicated archive and
unarchive action endpoints are outside the current route set.

Sources: [Vaultwarden cipher routes](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs),
[Vaultwarden response shape](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/cipher.rs),
[CLI cipher writes](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/vault/models/request/cipher.request.ts).

## Compatibility evidence still needed

The baseline personal-vault CLI result and its scope are recorded in
[verified compatibility](compatibility.md). The expanded HTTP suite passes 20
tests covering the new shapes, route aliases, ownership checks, and escaped
blob preservation. Further real-client evidence is needed for blob encryption,
Argon2 account fixtures, additional cipher types, and stored passkey use.
Restart, invalid credentials,
refresh expiry, cross-account IDs, stale revisions, oversized input, and
persistence without plaintext vault data remain ongoing regression requirements.

Browser/mobile clients, organizations, remaining attachment/Send variants, two-factor login,
broader auth-request client/device-trust flows, SSO, passkey authentication, key rotation, push notifications,
and recovery need separate implementation and actual-client evidence. A passing personal
CLI test must not be described as complete Bitwarden or Vaultwarden parity.

## Account encryption keys

The [pinned account handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L565-L625)
separate account encryption keys from personal API credentials. Every route here
requires bearer authentication:

| Method and route | Contract |
| --- | --- |
| `GET /api/accounts/keys` | Return the authenticated account’s key pair; 404 unless both fields are present |
| `POST /api/accounts/keys` | Initialize `publicKey` and `encryptedPrivateKey` only when both are absent; reject an existing or partial pair with 400 |
| `GET /api/users/<id>/public-key` | Return that user’s public key to an authenticated caller; 404 for an absent user or public key |

The initialization input requires two JSON strings. They remain opaque, including
empty strings and future formats. The legacy `RegisterRequest` embedding API
retains stricter validation; this key route and the separate modern registration
provider use opaque key strings. Schema failures return 422 and syntax failures return 400.
Successful initialization returns `privateKey`, `publicKey`, and `object: "keys"`.
The provider saves the pair atomically with the account revision and preserves
the symmetric account key, password verifier, sessions, API credentials, and vault.

Reading your pair returns `key`, `publicKey`, `privateKey`, `accountKeys`, and
`object: "keys"`; an empty symmetric key is represented as null. The nested
[`accountKeys` model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs#L270-L289)
contains the wrapped private key and public key, with null signed-key, security,
and signature fields. Public lookup returns only `userId`, `publicKey`, and
`object: "userKey"`. It intentionally permits cross-user public-key access,
without exposing the target’s private key or symmetric key. UUID path parsing
preserves spelling and returns 422 for malformed IDs.

These contracts remain partial until complete upstream behavior, configuration,
error-envelope, and client-path comparisons have been established.

## Account profile and avatar updates

The [pinned metadata handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L510-L563)
accept authenticated owner updates:

| Method and route | Input |
| --- | --- |
| `PUT /api/accounts/profile`, `POST /api/accounts/profile` | Required string `name`, at most 50 UTF-8 bytes |
| `PUT /api/accounts/avatar` | Optional string/null `avatarColor`; present strings require exactly seven UTF-8 bytes |

Names remain exact, including empty values, whitespace, control characters, and
Unicode. The byte limit is not a character count. Avatar validation follows the
source’s length check; it does not require a hex value or a leading hash. Missing
or null avatar values clear the color. Both `{}` and `[null]` clear it; an empty
sequence `[]` fails the required sequence-field shape with 422. Unknown request fields have no authority
over identity, credentials, keys, or the other metadata field.

Successful updates return the existing profile envelope, and the new field also
appears in profile reads and sync. The
[pinned profile model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs#L310-L340)
returns the raw stored name, including an empty name. The provider commits only
the requested metadata field and the account revision. Existing keys, passwords,
API credentials, sessions, vault data, and other accounts stay intact. Repeating a
valid update still advances the revision. JSON schema failures return 422,
syntax failures return 400, and invalid byte lengths return 400.

The borrowed request DTOs and provider-driven mutation rules are allocation-free.
The complete profile response remains an adapter builder, with its broader
account, organization, and authentication variants still tracked as partial.

## Equivalent-domain settings

The [pinned settings handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/mod.rs#L64-L146)
require bearer authentication for `GET`, `PUT`, and `POST /api/settings/domains`.
Both write methods replace the account's settings and return `{}` with status
200. Their optional fields are `excludedGlobalEquivalentDomains`, an array of
signed 32-bit integers, and `equivalentDomains`, an array of string arrays.
An omitted or null field resets that part of the settings to an empty array.
Strings, empty groups, ordering, duplicate domains, and unknown or duplicate
exclusion IDs remain unchanged; there is no domain-name normalization.

The positional JSON form places exclusions first and custom groups second.
`[null,null]` resets both arrays. `[]` and `[null]` fail the sequence shape with
422; a third positional element produces a syntax error with status 400.
Known duplicate fields and incorrect nested types also return 422. The core's
bounded request model uses caller-selected capacities; adapter views can accept
larger collections without allocating in the core.

Reads return exactly `equivalentDomains`, `globalEquivalentDomains`, and
`object: "domains"`. Each global group has `type`, `domains`, and `excluded`.
The catalog is supplied by the adapter. GET returns all groups with their flags;
[sync](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L171-L175)
omits excluded global groups. Sync includes domain settings by default and returns
`domains: null` when `excludeDomains` is true.
The compared query cases include Rocket's case-insensitive boolean aliases,
first-value handling, and dotted/bracketed root names. Authentication runs before
query validation: an invalid query returns 401 without a valid bearer and 422
with one.

Settings writes atomically replace both arrays and advance the account revision,
including repeated writes. They preserve unrelated account and vault data and
other accounts. Upstream also sends a `SyncSettings` notification; notification
transport remains a separate tracked requirement here.

### Account proof and security-stamp endpoints

`POST /api/accounts/verify-password` requires an authenticated device and one
required camelCase `masterPasswordHash` string; `MasterPasswordHash` is not an
alias here. Its personal no-policy response is exactly
`{"Object":"masterPasswordPolicy"}`. Optional typed policy fields use camelCase.
Password verification can upgrade the server's internal verifier without changing
client KDF settings or the security stamp; the standalone adapter currently
creates only current-policy verifiers.

`POST /api/accounts/security-stamp` uses the shared optional
`masterPasswordHash` (including `MasterPasswordHash` alias) and `otp` fields,
requiring exactly one valid proof. Success returns empty 200 and invalidates
existing owner sessions and devices, including the caller. It preserves the API
secret and pending/approved authentication requests. Such an approved request
retains its original deadline, peer-IP check and one-use requirement. The adapter
projects the renewed private stamp into JWT `sstamp`, profile and sync. Any
existing password-change exception retains its original guards and deadline.
Deleted devices block it; recreating the same owned identifier can make a
still-valid old bearer eligible again.

The contracts come from pinned
[account handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1084),
[password verification](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1445),
[proof and policy models](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/mod.rs#L49),
[user stamp reset](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs#L226)
and [direct device deletion](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/device.rs#L174).
The relevant handlers/hooks match Vaultwarden `1.37.4` release commit
`7c188967e7a467b19b2757bc3326f9cf3ccae327`; its protected-action enum refactor
preserves validation behavior. Organization/SSO policies, successful protected
OTP, remembered 2FA, notifications and complete failure semantics remain partial.

### Client KDF changes

`POST /api/accounts/kdf` accepts exactly required `authenticationData`,
`unlockData` and old `masterPasswordHash`. Authentication data is ordered
`salt`, `kdf`, `masterPasswordAuthenticationHash`, with `Salt`, `Kdf` and
`MasterPasswordAuthenticationHash` aliases. Unlock data is ordered `salt`, `kdf`,
`masterKeyWrappedUserKey`, with canonical names only. KDF values reuse the signed
`kdf`/`kdfIterations`/optional memory/parallelism fields and their existing aliases.
Flattened legacy credentials do not replace these required nested objects.

After old-proof verification, both complete KDF values and salts must match.
PBKDF2 requires at least 100,000 iterations; Argon2 requires positive iterations,
15–1024 MiB and parallelism 1–16. Other signed identifiers remain opaque, and
non-Argon memory/parallelism clear to null. Success returns empty 200, changes the
wrapped key/proof/KDF/stamp/revision and invalidates ordinary sessions/refreshes
while preserving devices, API secrets, auth requests and encrypted vaults. An
existing password-change previous-stamp exception retains its original deadline
and device/access/route/stamp guards.

Sources: pinned
[KDF endpoint and nested checks](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L690)
and [password/stamp transition](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs#L201).
The pin normalizes stored email with trim/lowercase; release 1.37.4's nested check
compares stored email exactly. Ordinary tested lowercase accounts agree; other
versioned salt variants remain explicit. Password/auth-request grants omit a
top-level empty `Key`, while API-key grants retain it, as shown in the pinned
[password response](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L592)
and [API-key response](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L726).

### Password changes

`POST /api/accounts/password` requires an authenticated device and old
`masterPasswordHash`. Its six positional fields are old hash, optional hint,
optional authentication data, optional unlock data, optional new hash and
optional key. A complete nested pair wins over legacy credentials; a partial
nested pair can fall back to both legacy fields. Invalid supplied nested JSON
fails before fallback. Nested aliases match the KDF endpoint above.

Old-proof verification precedes semantic selection. Nested KDF values only need
to equal each other; they are neither threshold-validated nor stored. Both salts
must exactly equal stored email, in both the pin and release 1.37.4. Absent/null/
blank hints clear; other hints trim and obey trusted server policy. Hashes and
wrapped keys remain opaque, including empty strings. Success returns empty 200.

The change records the pre-reset stamp for 120 seconds. Only logical handlers
`post_rotatekey`, `get_contacts`, `get_public_keys` and `get_api_webauthn` qualify.
The last is `/api/webauthn` metadata. The adapter supports public-key and WebAuthn credential-metadata admission
from this set; contacts and key rotation remain tracked gaps. Normal JWT/device guards
still apply. Exception expiry is checked before route and stamp mismatch, and
the exact integer deadline remains valid. Current-stamp requests do not trigger
cleanup; expired stale-stamp requests with an existing device attempt lazy
cleanup and advance revision. Historical issued tokens retain their original
access expiry and gain no new refresh or ordinary-route authority.

See the [password subset and primary references](api-parity.md#password-transition-subset)
and [provider boundary](architecture.md#password-changes-and-previous-stamp-authorization)
for cross-transition behavior and verification limits. Event logging,
notifications, remembered 2FA, remaining exception routes and upstream JWT expiry
leeway remain open; local transaction rollback exceeds source failure guarantees.

### WebAuthn credential metadata

`GET /api/webauthn` requires normal authenticated owned-device access and returns
exactly `{"object":"list","data":[],"continuationToken":null}`. It has no
request body schema or query parameters and the handler neither reads credential
storage nor changes account data. The inherited expired-stamp cleanup can still
advance revision before rejecting an old bearer. Logical `get_api_webauthn` is
one of the four password-change exception routes; it never bypasses the original
JWT lifetime, owned-device or previous-stamp checks.

Both [pinned main](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/mod.rs#L198-L207)
and [release 1.37.4](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/mod.rs#L198-L207)
return this fixed envelope. It is distinct from `/api/two-factor/get-webauthn`.
The empty response does not implement passkey creation, login or key rotation.
See the [metadata subset](api-parity.md#webauthn-credential-metadata-subset) for
client-source attribution and remaining comparison limits.

The six selected HTTP cases pass against the actual adapter and Vaultwarden
1.37.4: 129 counted requests, eight identity requests and a real 121-second
exception wait per server. Shared registration bootstrap is excluded. This
establishes the documented metadata subset; it adds no CLI-route trace.

### Personal vault purge

`POST /api/ciphers/purge` uses the existing `PasswordOrOtpRequest`: optional
`masterPasswordHash` (also `MasterPasswordHash`) followed by optional `otp`.
Exactly one non-null string selects a proof; both or neither return 400. The
hash is the opaque client authentication hash, not the plaintext password.
Protected-action OTP validation consumes a valid token; it is distinct from TOTP.
A host without that facility rejects the OTP branch. Unknown body fields cannot
select an owner or organization. Positional input retains both slots, such as
`["<hash>",null]`; a missing slot is a schema error. Schema errors return 422,
while malformed JSON and surplus positional elements return 400.

Normal owned-device authentication precedes JSON decoding. Personal success
returns empty HTTP 200, deletes every owned personal cipher (active, trashed or
archived) and owned folder, and advances account revision even for an empty
vault. Cipher deletion removes its attachment bytes and associations. Account
credentials, client KDF, keys, stamp/exception, devices, sessions, API secrets,
authentication requests and unrelated account settings survive.

The same path has a separate organization handler. Rocket matches the
case-sensitive decoded root `organizationId`, including nested dotted/bracket
names and leading delimiters. A present value is initially a string, including
empty or non-UUID input; it selects organization authorization rather than the
personal purge. For the supported personal account, those organization requests
return 401 without deleting its vault. Missing, unrelated or differently cased
names select the personal handler. Duplicate scalar values use the first value.
Organization-owner purge remains a distinct unimplemented inventory variant.
Other methods do not become purge aliases: GET, PUT and DELETE match upstream
dynamic cipher-ID paths and return 422 after valid authentication, or 401
without it; PATCH returns 404. These failures do not delete vault data.

Both the [pinned handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L1703-L1775)
and [release 1.37.4](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/ciphers.rs#L1703-L1775)
have identical purge declarations and handlers. Query dispatch follows
[`OrgIdGuard`/`OrgHeaders`](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L753-L829),
not the UUID path guard. All six selected Rust cases pass against the actual
adapter and release 1.37.4: 327 counted HTTP requests each, six identity requests,
three auth-request creations, three polls and eight successful purges. Two shared
fixture registrations are excluded. Complete error, transport, notification and
organization variants remain outside this subset.

### Account deletion

`DELETE /api/accounts` and `POST /api/accounts/delete` use the same authenticated
account-deletion operation. Both reuse `PasswordOrOtpRequest`: optional
`masterPasswordHash` (alias `MasterPasswordHash`) followed by optional `otp`.
Exactly one non-null string selects proof verification. Invalid/missing/both
proofs return 400; schema and malformed-JSON distinctions match personal purge.
The proof belongs to the authenticated account, regardless of body or query
owner/organization fields. Success returns empty HTTP 200, including for the
POST alias; it does not return a deleted-user JSON projection.

After verifying the proof, upstream rejects a confirmed organization owner if
its organization has at most one confirmed owner. The guard is after successful
protected-action OTP consumption but before cleanup. Organization-aware providers
must enforce this trusted policy before deleting any account-dependent state.

Pinned cleanup removes Sends, emergency-access relationships/invitations,
memberships and their collection/group links, personal ciphers and attachments,
favorites, folders, auth requests, devices, two-factor records and invitations,
then the user. It does not delete organization vaults. The local adapter removes
all of its supported account-dependent rows, credentials, issued access/refresh
and historical authority, attachments/bytes/capabilities and settings in one
transaction. There is no surviving account revision to advance. Unrelated
accounts and instance-wide registration signing state remain intact.

Sources: [pinned aliases](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1321-L1333),
[pinned model cleanup](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs#L365-L389),
[release 1.37.4 aliases](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/accounts.rs#L1306-L1318)
and [release cleanup](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/db/models/user.rs#L360-L384).
Release cleanup omits the pin's explicit auth-request deletion. Its SQLite
[auth-request foreign key](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/migrations/sqlite/2023-09-01-170620_update_auth_request_table/up.sql#L18)
does not specify cascade. Selected portable fixtures therefore contain no auth
requests; local SQL tests separately establish their deletion. No identical
cross-version cleanup/failure guarantee is inferred. All six selected direct
Rust HTTP cases pass against both actual servers, with 257 counted requests
per target and three excluded fixture registrations. Six identity requests
comprise three successful password logins, two refresh attempts (one success),
and a rejected old API grant. The proof covers both exact aliases, ignored
queries, guarded rejections, live authority revocation, fresh identity after
same-email registration and foreign preservation. Each deletion checks fresh
owned/foreign attachment capabilities within 30 seconds; local SQL tests,
separately, establish physical cleanup and atomic failure rollback.

### Cipher read aliases and guards

The [pinned handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L234-L255)
and [release 1.37.4 handlers](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/ciphers.rs#L234-L255)
are identical: `GET /api/ciphers/{id}`, `/details` and `/admin` use the same
readable-cipher check and return the same user projection. The admin-named
handler explicitly contains an upstream TODO and forwards to the ordinary read;
it does not impose organization-administrator authority or grant a bypass.
Missing ciphers return 400 with `Cipher doesn't exist`; inaccessible ciphers
return 400 with `Cipher is not owned by user`. Ordinary GET previously returned
404 for these cases in the adapter; this source-backed correction leaves write
and lifecycle error policies unchanged.

[Headers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L637-L710)
requires a valid device and user before checking the current security stamp.
None of these three handler names is in the fixed previous-password-stamp
allowlist. [Rocket guard ordering](https://github.com/rwf2/Rocket/blob/v0.5.1/core/codegen/src/attribute/route/mod.rs#L324-L327)
runs request guards before path guards: invalid authority returns 401 before a
malformed cipher UUID can return 422. The
[UUID macro](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/macros/src/lib.rs#L15-L27)
validates syntax but retains exact decoded spelling for lookup, including case.
The GET handlers do not decode a JSON body or select an owner from query fields.

The opt-in `CipherReadStorage` provider can distinguish an absent record from
an existing inaccessible record. Its default checks personal ownership;
organization-aware embeddings can supply trusted readable access independently
of write access. The core returns only a private-constructor borrowed
`AuthorizedCipherRead`, with redacted Debug, rather than a typed cipher payload.
The adapter holds its storage lock through authorization and opaque JSON
projection, preserving active, trashed and archived state without revision
writes. Full organization, transport, notification and response-model parity
remain open. All six selected Rust HTTP cases pass against both actual
servers: 335 counted requests each, including four password logins, with two
fixture registrations excluded. Thirty-four byte-exact attachment checks
accompany normalized alias/snapshot comparisons; normalization changes only
attachment URL tokens. The cases verify current authority, exact error messages,
UUID/body/query/method guards and nonmutation of account/vault snapshots.
These direct comparisons establish no actual notification or CLI alias call.

### Ordinary password-grant validation

The [pinned dispatcher](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L57-L80)
and [release 1.37.4 dispatcher](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/identity.rs#L53-L81)
require present fields in this order: `client_id`, `password`, `scope`, `username`,
`device_identifier`, `device_name`, `device_type`. Missing fields produce 400;
present empty strings pass presence checks. Missing `grant_type` fails Rocket's
form guard with 422, whose response need not be JSON. A present empty grant type
reaches dispatch and fails with 400. The SSO-only configuration policy precedes
ordinary required-field checks and remains outside this personal baseline.

[Password login](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L370-L498)
requires scope exactly `api offline_access` before limiter/account/proof access.
It trims the username using Rust Unicode whitespace semantics before lowercase
email lookup. The password field is an opaque client authentication hash, with
no trimming or case conversion. Unknown accounts and invalid proofs have the
same 400 error. A disabled account is rejected only after proof verification.
The internal verifier upgrade then precedes mail verification, device retrieval,
2FA and issuance; it does not change the client KDF or wrapped user key.

[ConnectData](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L1107-L1167)
uses uncased compact/underscore aliases for `grant_type`, `client_id` and device
fields; `username`, `password` and `scope` have only their uncased canonical
names. Rocket matches the first name root, including dotted/bracketed forms,
and the required grant string keeps its first matching value. Optional fields
have different duplicate semantics: Rocket
[`Option<T>` decoding](https://github.com/rwf2/Rocket/blob/v0.5.1/core/lib/src/form/from_form.rs#L818-L836)
forces strict inner parsing and turns its errors into `None`. Two matching
optional aliases/roots therefore make that field absent, triggering the ordered
400 presence check. The adapter follows this distinction for ordinary forms.
A single recognized present `authRequest`, even empty, selects its separate proof
flow and cannot fall back. Its underscore spelling is not an alias. Duplicate
auth-request selection retains the adapter's stricter rejection policy, an explicit
source gap; other identity grants keep their declared parser/policy limits.

Device IDs and names are opaque strings, including empty values. `deviceType`
is a string form field; nonnumeric, empty or out-of-i32-range input reaches the
[device fallback](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L776-L797)
value 14. Reusing an owned device identifier retains its original metadata.
The supplied client ID is preserved, including an empty string.

Ordinary presence, scope, proof and disabled-account failures use 400 default API
errors, rather than OAuth `invalid_grant`. The
[pinned error serializer](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/error.rs#L230-L273)
and [release serializer](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/error.rs#L209-L238)
provide the message, validation map and lowercase error model, empty OAuth error
strings, null exception fields and `object: "error"`. The adapter has a dedicated
ordinary-login renderer; full global error-envelope parity is not inferred.
All six focused direct Rust cases pass against the adapter and actual
Vaultwarden 1.37.4: 85 counted HTTP requests per target, including 45 token POSTs.
The authored classification is 39 pre-limiter guards and six credential-flow
attempts, including two ordinary successes and one auth-request no-fallback
canary, on one peer under unchanged limits. One fixture registration is excluded.
The checks compare the selected nine-field errors, required-field order, exact
scope, optional-duplicate absence, raw proof, alias/empty-device success, JWT
authority and account/vault invariants. They are not server-side rate telemetry.
A fresh official CLI 2026.10.0 regression also passes all 120 commands against
both actual servers. It is separate lifecycle evidence, without a captured
request trace. Refresh has a separate supported-method contract below;
SMTP/2FA/SSO, optional unrelated guards, universal JWT/time behavior and complete
form transport remain separate contracts.

### Password-method refresh grants

The [pinned dispatcher and refresh response](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L57-L178)
match [release 1.37.4](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/identity.rs#L57-L180)
for this ordinary password-method subset. `grant_type=refresh_token` requires a
present optional `refresh_token`. Missing `grant_type` is a Rocket form 422 whose
body need not be JSON. Missing or repeated matching refresh-proof roots become
absent and return the default nine-field API 400 with
`refresh_token cannot be blank`. Present empty, malformed, revoked or expired
proofs return exactly `{"error":"invalid_grant"}` with 400.

[Form aliases](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L1107-L1167)
are uncased `grant_type`/`granttype`, `refresh_token`/`refreshtoken` and
`client_id`/`clientid`. Rocket root matching includes dotted/bracketed names.
The required grant takes its first match; repeated matching optional roots become
`None`. An absent or repeated client ID yields access claim `undefined`; present
empty is preserved. Refresh ignores submitted scope, username, password and
replacement device metadata. It obtains authority from the verified proof.

[Refresh verification and issuance](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L1276-L1384)
decode the refresh JWT, find its current persistent device secret, touch the
device, resolve its user and enforce the selected method policy. The password
path does not recheck account enabled state, an old security stamp or the
requesting device/IP. A valid proof for another account refreshes that account;
submitted bearer/body owner values cannot change it. Earlier valid proofs remain
usable after new issuance, and their own deadlines do not move. Old access keeps
its original deadline. Upstream refresh JWTs can be byte-identical when issued
within one second; changing token strings is not the replay contract.

The success JSON has exactly `refresh_token`, `access_token`, `expires_in`,
`token_type: "Bearer"` and `scope: "api offline_access"`. Account decryption,
Key/KDF/private-key fields are absent. Access uses the current account stamp,
retained device and request client ID, with a two-hour lifetime. Only Android/iOS
types 0/1 use ninety-day refresh; all other types, including Android Amazon 15,
use thirty days ([device policy](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/device.rs#L93-L105)).

[JWT decoding](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L130-L153)
removes all Unicode whitespace and checks signature, login issuer, `exp` and
`nbf` with thirty-second leeway. The pinned jsonwebtoken 11.1.0
[boundary checks](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/validation.rs#L250-L271)
reject `exp < now - 30` and `nbf > now + 30`; expiry equality is accepted.
Password/KDF changes rotate all owner device secrets; direct stamp reset also
deletes devices. Recreating the same identifier cannot restore an old proof.

`RefreshStorage` keeps proof verification, method/device authority, clocks and
preparation outside the allocation-free service. The conformance host uses
random opaque stored handles with original deadlines and current device joins,
not upstream refresh JWTs; no JWT encoding or `nbf` equivalence is claimed. Its
issuance savepoint provides stronger rollback than upstream's separate activity
writes. Unsupported SSO/API methods, their activity-before-failure ordering,
mobile runtime, thirty-day waits and complete identity policy remain open.

The concrete shipped [CLI sync command](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/vault/sync.command.ts#L13-L20)
calls [full sync](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/platform/sync/default-sync.service.ts#L162-L169),
which reaches [ApiService refresh](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/services/api.service.ts#L1453-L1537).
It forwards the refresh string opaquely and decodes only access tokens for client
ID and account identity. The [bundled SDK renewal request](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-core/src/auth/api/request/renew_token_request.rs#L1-L34)
also posts this form. These are source call paths; they are not captured CLI
request traces or proof that every feature-gated SDK branch executes.
All eight selected Rust HTTP cases pass against the adapter and actual
Vaultwarden 1.37.4: 268 counted requests per target, including six successful
password logins and 42 refresh POSTs. Refreshes comprise 22 successes, 15 minimal
`invalid_grant` failures, four missing/duplicate-proof guards and one missing-grant
422. Two fixture registrations are excluded. Proof reuse across new issuance,
current client/device authority, old access, owner isolation and
password/KDF/stamp revocation/recovery pass with final retained-cipher decryption.
Long expiry, refresh JWT/`nbf`, disabled-account and mobile behavior are not live
runtime claims; applicable provider/clock contracts use separate unit evidence.

## Personal text Sends

The [pinned handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/sends.rs#L69-L215)
and [release 1.37.4 handlers](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/sends.rs#L63-L199)
agree on the personal text subset. Owner routes are `GET`/`POST /api/sends`,
`GET`/`PUT`/`DELETE /api/sends/{id}` and
`PUT /api/sends/{id}/remove-password`. Recipient `POST /api/sends/access` uses
separate Send-token authority. File upload/download contracts are described
below. Owner UUID guards preserve decoded spelling and run after authentication:
malformed paths return 422, valid absent/foreign IDs return 400. Previous-stamp
exceptions do not authorize these owner handlers.

The JSON model declares fifteen fields in this order: `type`, `key`, `password`,
`maxAccessCount`, `expirationDate`, `deletionDate`, `disabled`, `hideEmail`,
`emails`, `name`, `notes`, `text`, `file`, `fileLength`, `id`. Type, key,
deletion date, disabled and name are required. Optional values accept null;
names/keys/notes/passwords are opaque strings, including empty. Only camelCase
field names are declared; unknown outer fields, including `authType`, owner and
access-count claims, do not select persisted state. A supplied body ID is ignored
for ordinary creation/update. The full owned JSON/date decoder remains outside
the core's generic `TextSendRequest<P>` semantic view.

Text type is 0. Owner POST rejects file type 1 and unsupported types with 400.
A non-null `text` value is required. It can contain arbitrary JSON; projection
is not a raw-JSON identity transform. The adapter removes only an exact root
`response` key before storing. [Owner/access projection](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/send.rs#L147-L200)
uses the recursive first-character-lowercase/SSN normalization in
[LowerCase](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/util.rs#L595-L663),
converts a top-level numeric `size` to a string, and projects accepted scalar or
array roots as null when the flattened wrapper cannot decode them. Nested
`response` fields survive. A root `Response` survives removal and then normalizes.

Creation checks disable-Send policy, requested hidden-email policy, type/data,
deletion ceiling, unsupported email verification and late access-limit conversion.
Update checks policy and ownership before email/type/date/data/number checks.
`maxAccessCount` accepts signed `i64` JSON integers or strings that convert to
`i32`; negative values are not rejected. No trimming occurs during conversion.
Deletion dates strictly greater than now plus thirty-one days fail with 400;
past deletion/expiration dates are accepted for owner storage. Date parsing uses
Chrono's Serde grammar; the response formatter emits UTC with six fractional
digits ([formatter](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/util.rs#L472-L476)).
Complete timestamp grammar and clock equivalence require more than selected
portable examples. Omitted/null update password preserves the verifier;
`remove-password` explicitly clears it, even when already absent. Omitted/null
notes, access limit, expiration and hidden-email state replace prior values.

The typed owner envelope has exactly eighteen fields: `id`, `accessId`, `type`,
`name`, `notes`, `text`, `file`, `key`, `maxAccessCount`, `accessCount`, `password`,
`authType`, `disabled`, `hideEmail`, `revisionDate`, `expirationDate`,
`deletionDate`, `object: "send"`. `accessId` is unpadded base64url of UUID bytes;
owner `id` remains its UUID string. `file` is null for text. `password` contains
the server verifier's unpadded base64url marker; `authType` is 1 when protected,
otherwise 2. The list has only `data`, `object: "list"`, `continuationToken: null`.
Sync includes the same owner responses, without filtering disabled/expired/maxed
records until separate purge cleanup. Organizations, collections and policy
placeholders remain separate unimplemented contracts.

Recipient token issuance uses the existing identity form with
`grant_type=send_access`, required `client_id` and `send_id`, and optional
`password_hash_b64`. The latter two names are case-sensitive underscore names;
they have no compact/uncased aliases. Declared grant/client aliases remain
uncased, Rocket root matching applies, and repeated optional fields become
absent. Scope and an ordinary user bearer do not select recipient authority.
The [dispatcher](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L100-L113)
calls its public limiter before required-field checks. The standalone adapter
does not implement matching abuse controls.

[Send-token issuance](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth/send.rs#L16-L109)
decodes the access ID, checks current count/availability, then verifies an exact
opaque password proof when protection exists. Missing proof returns 400 with
`invalid_request`/`password_hash_b64_required`; wrong proof returns 404 with
`invalid_grant`/`password_hash_b64_invalid`; invalid/missing/inaccessible Send
returns 404 with `invalid_grant`/`send_id_invalid`. These errors contain exactly
`kind: "expected_server"`, `error`, `send_access_error_type`. Required form-field
errors instead use the default API envelope. No count is consumed during minting.

Success has four fields: `access_token`, `expires_in`, `token_type: "Bearer"`,
`scope: "api.send.access"`. Upstream signs RS256 with canonical origin plus
`|send`, UUID subject, `nbf` and a 120-second deadline. Decoding strips all Unicode
whitespace and allows thirty-second time leeway. The local persisted signer uses
HS256, so algorithm/key-distribution equivalence and cross-server tokens are not
claimed. The server hashes the raw UTF-8 client proof again with PBKDF2-SHA256,
100000 iterations and a random 64-byte salt. The user's plaintext password and
fragment seed stay client-side.

Recipient access ignores body/query resource claims. It rechecks current
disabled/deletion/expiration state and atomically reserves an access below the
limit. Equality with a deadline is inaccessible. It does not recheck password:
issued capabilities survive password replacement/removal. A failed count
reservation may advance owner revision before 404; no universal denial rollback
is implied. Recipient responses have exactly `id` (access ID), `type`, `name`,
`text`, `file`, `expirationDate`, `creatorIdentifier`, `object: "send-access"`.
Owner key, notes, password, count and deletion date are excluded; hidden creator
email is null. Owner mutations and successful access advance Send/account
revision; read and token-mint operations do not.

All six expanded Rust HTTP cases pass against both actual servers with
129 counted requests, 23 Send-token grants, 15 recipient requests and two ordinary
logins, excluding two fixture registrations. Selected relaxed Chrono timestamp
and leap-second owner create/delete examples also pass. The separate twenty-command
official CLI 2026.10.0 run also passes both actual servers.
The wrong-password and deleted-Send receives require exit 1 and exact public CLI
JSON messages `Invalid password` and `Not found.` respectively; generic failure
output is rejected. These are client-visible checks, separate from raw server
error-envelope parity.
The shipped [create command](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/tools/send/commands/create.command.ts#L168-L179)
delegates encryption and persistence to its selected Send service. Recipient
[receive](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/tools/send/commands/receive.command.ts#L535-L550)
uses a Send token and decrypts the returned encrypted fields. The configured
[SDK token client](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-auth/src/send_access/client.rs#L29-L60)
posts the recipient identity form. Owner
[get](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/tools/send/commands/get.command.ts#L80-L90)
and [list](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/tools/send/commands/list.command.ts#L20-L24)
read local state, so their successful decryption after sync is distinct from
independent owner HTTP read evidence. Mutation implementations remain subject to
the shipped SDK/legacy selector; the focused result does not identify every
feature-flag branch or provide a captured request trace.
Remaining file variants, email verification, enterprise/configuration policies, notifications,
rate controls, scheduled purge and full transport/JWT/time parity remain open.

## Personal file Sends

The [pinned file handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/sends.rs#L218-L463)
and [release 1.37.4 handlers](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/sends.rs#L218-L463)
register four patterns: owner `POST /sends/file/v2`, owner multipart
`POST /sends/{id}/file/{file_id}`, recipient
`POST /sends/access/file/{file_id}`, and public
`GET /sends/{id}/{file_id}?t=…`, mounted under `/api`.
The client upload-renewal GET has no registered handler in either source.

Reservation checks write policy, file type1, requested hidden-email policy,
required integer-or-string `fileLength`, nonnegative length and configured quota
before shared data/date/email/access-limit validation. The absolute declared
ceiling is 550,502,400 bytes (525 MiB), distinct from Rocket's decimal
525,000,000-byte multipart/file limits. Fresh IDs select persisted state; an
object file payload receives authoritative `id`, numeric `size` and `sizeName`.
Projection converts size to a string and applies shared key normalization;
scalar/array payloads project null. The response has exactly `fileUploadType: 0`,
`object: "send-fileUpload"`, relative `url: "/sends/{id}/file/{file_id}"` and
`sendResponse`. Reservation advances Send/account revisions before bytes exist.

Upload parses lenient multipart field `data`: unknown fields are ignored and the
first matching case-sensitive Rocket root wins. Missing data is422. After
owner/current-device and path/data guards, it checks policy, owned file type,
strict raw `id`/`size: u64`/`fileName` metadata, filename, URL file ID and exact
measured bytes, in that order. File IDs preserve case and permit only ASCII
alphanumeric/hyphen path characters; malformed segments return422. Retained
CLI device types23–25 allow `stored_filename.ends_with(received_filename)`;
other devices require equality. Missing/foreign or mismatched uploads return400
and retain the reservation. Default filesystem upload uses create-only writes;
a duplicate returns ordinary400 with public message `OpenDAL`. Success is empty
200, advances account revision, and preserves Send revision/metadata. Type-1
PUT preserves the original raw file metadata and bytes.

File recipient metadata does not consume access count, but touches account
revision. File-URL issuance checks current availability/type/association before
conditional count reservation, without checking byte existence. Its exact
response is `object: "send-fileDownload"`, `id` and absolute `url`. Count and
Send/account revision writes can precede a later URL-generation failure; a
failed count CAS can still advance owner revision. The filesystem
[capability claims](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L556-L563)
use issuer `origin|send`, exact subject `{id}/{file_id}`, 120-second lifetime and
30-second validation leeway. Object-storage presigned URLs use a separate
five-minute path that this adapter does not implement.

Binary GET ignores ordinary bearers and current Send disabled/password/date/count
state; it checks capability and existing bytes only, without incrementing count.
Missing required `t` returns422; present empty/forged/misbound proof or missing
bytes returns404. First `t` query-root matching includes dotted/bracketed names.
Deletion removes stored bytes, invalidating still-fresh URLs. The extensionless
filesystem response has a sized body without a filename-derived Content-Type or
Content-Disposition. Full Range/transport/error behavior is not claimed.

The shipped [direct upload service](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/platform/services/file-upload/bitwarden-file-upload.service.ts#L6-L32)
sends `data` with encrypted filename and binary ciphertext. The file envelope
is byte type2, sixteen-byte IV, thirty-two-byte MAC, then AES-CBC ciphertext;
HMAC authenticates IV and ciphertext before decryption. Name and file encryption
use the client-derived Send key; seed and plaintext stay off the server.
[CLI receive](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/tools/send/commands/receive.command.ts#L540-L577)
obtains metadata and a file URL, downloads/decrypts bytes, then writes the selected
output file. `--obj` returns metadata before binary transfer. Owner get/list
use synced cache rather than proving independent HTTP reads.

All six selected HTTP cases pass on both actual targets with131 requests,
10 Send grants, nine multipart requests, 13 URL requests and19 binary GETs;
two password logins are included and two registrations excluded. A separate
twenty-command official CLI 2026.10.0 file run passes both with byte-exact
reception and exact wrong-password/deleted-resource categories. These results
are separate from text20/baseline120 and provide no captured route trace.
Local units separately prove rollback, reopen, first-field parsing and physical
account-FK cleanup. Configured quota/organization/email policy, notifications,
rate controls, purge cron, live maximum-size/TTL and full JWT/transport behavior
remain open; the host persists HS256 authority instead of upstream RS256.
## Organization owner creation and discovery

The [pinned creation and discovery handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L101-L324)
and [release 1.37.4](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L99-L322)
agree on `POST /api/organizations`, owner `GET /api/organizations/{id}` and
authenticated `GET /api/collections`. Creation requires canonical camelCase
`billingEmail`, `collectionName`, `key`, `name` and `planType`; optional `keys`
contains required `encryptedPrivateKey` then `publicKey`. Positional input keeps
all six slots in that order, with `keys` before `planType`. The plan accepts a
signed 64-bit integer or arbitrary string and is ignored; the response uses 6.
Unknown fields cannot select IDs, role, status or owner. Name, collection name
and key strings remain opaque, including empty strings. Billing email is
Unicode-lowercased without trimming, then validated by the mailbox/domain helper.

Creation checks configured permission first, then applicable SingleOrg policy,
then billing validity. It assigns independent organization, membership and
collection IDs. The creator is confirmed status 2, Owner role 0, with full
collection access and the submitted wrapped organization key. Upstream saves
organization, membership and initial collection sequentially. Membership and
collection saves advance the owner's revision without changing personal vault
payloads, credentials, account keys, device authority or security stamp. The
local provider's atomic creation/revision contract is stronger than those
sequential saves; it does not establish notifications or general administration.

The [owner guard](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L747-L829)
receives the raw nonempty path segment, including dotted or percent-encoded
spellings, before current device/stamp authentication and exact membership and
confirmed-owner checks. A missing or inaccessible organization is 401. A valid
UUID path keeps its exact spelling and takes precedence over query values.
Only malformed paths fall back to the case-sensitive decoded `organizationId`
query root; an owned query can pass the request guard before the malformed path
fails with 422. JSON guards run after authentication: data/schema failures are
422, syntax or invalid whole-body UTF-8 is 400, and these routes do not constrain
JSON by Content-Type. GET bodies and unused queries confer no authority.

The [organization model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/organization.rs#L185-L249)
projects 47 public fields, excluding private/public key contents and member keys.
Its `seats` is null and `limitCollectionCreation` is true. The separate
[profile membership](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/organization.rs#L438-L534)
has 59 fields plus twelve permission flags: Owner permissions are false because
those flags describe custom roles, `seats` is 20, and collection creation is not
limited for this owner. It includes the membership ID, account ID and opaque
RSA-wrapped organization key. Confirmed memberships appear in both profile
`organizations` and `organizationsNew`; the latter also admits accepted members.
JWT organization-role arrays are omitted upstream and are not needed for this
discovery flow.

The [collection model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/collection.rs#L57-L153)
uses seven basic fields, including `type: 0`, null `externalId` and
`defaultUserCollectionEmail`. Sync adds `readOnly: false`, `hidePasswords: false`
and `manage: true` for the confirmed owner. Both model files are identical in
the pinned revision and release 1.37.4. List order is not promised. Event/group
flags depend on configuration and default false; reset-password support depends
on SMTP. Source feature flags do not prove the corresponding APIs are implemented.

The shipped CLI reads organizations and collections from synchronized state
([organization get](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/commands/get.command.ts#L538-L569),
[list](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/commands/list.command.ts#L169-L193),
[crypto/profile sync](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/platform/sync/default-sync.service.ts#L185-L201)).
Owner `list org-collections` instead calls `/organizations/{id}/collections`,
which is outside this three-route slice. Shared API and generated SDK request
constructors do not establish an executed CLI organization-creation call or
captured request trace. General organization CRUD, invitations, member/collection
administration, shared ciphers, enterprise policies, SMTP and notifications
remain separate work. All implementation remains independently authored under
MIT OR Apache-2.0; upstream references describe protocol facts only.

All six selected direct Rust HTTP cases pass against the adapter and actual
Vaultwarden 1.37.4: 137 counted requests, two password logins, two refreshes and
two organization creates per target, excluding two modern registration fixtures.
The cases compare exact public/member/collection projections, decrypt the initial
collection, verify guards and both last-owner deletion rejections, and preserve
personal keys/vault state and foreign authority. The separate focused official
CLI `2026.10.0` comparison passes nineteen commands on both servers, with
collection decryption after login, unlock and fresh-cache login and retained
personal-note decryption. Thirteen direct setup HTTP requests include one
password login; two more logins are CLI commands, and one registration fixture
is excluded. Client internals are not counted or traced. Neither result implies
general organization or captured request-trace parity. A route-classifier
regression verifies dotted-ID authentication/fallback and percent-encoded valid-ID
checks in those same six cases.

## Organization-scoped collection list, create and single details

The [pinned handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L357-L525)
and [release 1.37.4](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L355-L523)
agree on `GET`/`POST /api/organizations/{orgId}/collections`; the registered
[single read](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L736-L799)
is `GET /api/organizations/{orgId}/collections/{collectionId}/details`.
There is no plain single-collection GET. Aggregate `/collections/details`,
bulk access, users and bulk deletion remain separate contracts. Single update
and deletion are described below.

`ManagerHeadersLoose` requires a confirmed Owner, Admin or Manager. List also
requires `access_all` or Owner/Admin role; otherwise it returns 404
`Resource not found.`. Single read uses strict `ManagerHeaders`: after current
device/membership checks it selects the raw collection path, or `collectionId`
query only when path UUID parsing fails, then checks global manageability before
the route's UUID guards. Missing/foreign collections yield 401. A collection
in another organization managed by the same user passes that guard and reaches
400 `Collection is not owned by organization`. An owned query fallback can
reach 422 for a malformed path. Preserve raw dotted/percent-encoded segments
until these guards; URL decoding is not UUID spelling normalization.

The [creation schema](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L120-L164)
requires `name`, `groups` and `users`; `externalId` is optional/null. Positional
order is `[name, groups, users, externalId]`. Each selection requires
`[hidePasswords, id, readOnly, manage]` with three bools and a raw string ID.
User IDs mean organization membership IDs, not account IDs. Unknown fields are
ignored. Names and external IDs are opaque; only exact empty external ID becomes
null at creation, while whitespace remains unchanged. Group validation precedes
membership validation (`Invalid group`, then `Invalid member`, both 400), then
a Manager without `access_all` is denied creation. Valid full-access member
selections are checked but their direct assignment writes are skipped.

Group validation/storage is not disabled by the group feature flag; disabled
projection returns `groups: []`. Effective selection `manage` also derives from
role or unrestricted read/write access, rather than always echoing stored flags.
The selected responses are basic seven-field list entries, ten-field create
`collectionDetails`, and thirteen-field single `collectionAccessDetails` with
assigned/users/groups. Single details do not synthesize full-access owners into
users or include `unmanaged`; aggregate details does both differently. Successful
owner details use readOnly/hidePasswords false and manage/assigned true.

Collection/group/user saves propagate affected account revisions sequentially;
Owner/Admin role alone does not add revision recipients without `access_all`
or a direct grant. Creation has no collection revisionDate field. The local
atomic collection/grant/revision boundary is stronger; event logging,
notifications, general membership/group management and policy matrices remain
outside the selected adapter scope. The shipped CLI has production
[list](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/commands/list.command.ts#L194-L243),
[create](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/vault/create.command.ts#L215-L284)
and [get](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/commands/get.command.ts#L484-L535)
organization-collection calls. All six selected Rust HTTP cases pass both actual
targets with 194 counted requests, two password logins and two refreshes,
excluding two modern fixtures/four registration requests. Five new collections,
exact projections/guards and full membership/foreign/other-owned collection
baselines are checked. The separate official CLI `2026.10.0` comparison passes
nineteen commands on both, exercising production list/create/get and fresh-cache
name decryption. Fourteen direct HTTP requests include one password login; two
further logins are CLI commands, and one registration/two requests is excluded.
Client internals remain uncounted; no captured trace or full-parity claim follows.

## Organization collection replacement and deletion

The [pinned mutation handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L606-L734)
and [release 1.37.4 handlers](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L604-L732)
agree on `PUT` and `DELETE /api/organizations/{orgId}/collections/{collectionId}`.
There are no POST aliases. Bulk DELETE and bulk-access POST are separate,
unimplemented contracts.

Both selected routes use strict `ManagerHeaders`: current device and confirmed
manager membership precede global collection manageability, typed UUID guards
and, for PUT, JSON decoding. Query fallbacks authorize guards without replacing
the final path. Missing, foreign or no-longer-manageable collections return 401;
a collection managed by the actor in another organization reaches handler 400
`Collection not found`. Raw dotted and percent-encoded paths reach these guards.

PUT reuses the creation schema and selection ordering above. It validates every
group before every membership, then checks organization/scoped collection
existence. It replaces the name and complete assignment sets rather than merging
ACLs. Unlike creation, omitted/null or Unicode-whitespace-only `externalId`
clears the value; nonblank strings retain their original bytes. Opaque names,
unknown-field handling and membership-ID selections retain the creation rules.
Validated `access_all` selections are skipped and duplicate writes use the last
selection. A Manager can remove their own last grant and still receive a
successful ten-field `collectionDetails`; without other access its flags are
`readOnly: true`, `hidePasswords: false`, `manage: false`.

DELETE has no JSON guard, ignores its request body and returns empty 200. The
[model cleanup](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/collection.rs#L192-L217)
removes only the selected collection, ACLs and cipher associations. Cipher
records, encrypted bytes, attachment data and cipher revisions survive.
Account revisions advance for previous `access_all`/direct-grant recipients,
removed direct users and new non-full-access selections, without membership
status or Owner/Admin shortcuts. Source persistence is sequential; local
collection/ACL/revision cleanup and response staging are atomic.

The [production CLI edit](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/commands/edit.command.ts#L257-L334)
and [delete](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/vault/delete.command.ts#L143-L155)
call the selected PUT and DELETE directly. Edit encrypts names under the
organization key and supplies empty arrays for omitted selections. Its response
wrapper tolerates the ten-field response without users/groups arrays. All six
HTTP cases pass both actual targets with 229 counted requests, two password
logins and two refreshes, excluding two modern fixtures/four registration
requests. Eight updates and one deletion verify all read views, independent
authenticated name decryption and full membership/foreign/sibling preservation.
The separate official CLI `2026.10.0` comparison passes twenty commands on both
actual targets, with fifteen direct HTTP requests, two CLI logins and one direct
setup login, excluding one registration/two requests. It independently verifies
renamed ciphertext, fresh-cache decryption and live/synced deletion; client
internals are not counted or traced. Public scope remains created
Owner/full-access memberships; imported Manager self-removal and seeded
cipher-association cleanup have separate local provider evidence. No general
member/group administration, sharing, bulk mutation, event/notification,
transport or full-parity claim follows.

## Organization member discovery

The list-only milestone below precedes the expanded [member-detail proof](#organization-member-detail).

The [pinned member-list handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L886-L927)
and [release 1.37.4 handler](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L884-L925)
agree on `GET /api/organizations/{orgId}/users`. It uses current-device
`Headers` and `ManagerHeadersLoose`: the requesting member must be confirmed
Owner, Admin or Manager. Handler admission additionally requires `access_all` or
Owner/Admin role, otherwise 404 `Resource not found.`. Raw organization paths
and owned query fallback retain the existing authentication/UUID ordering.
There is no JSON body guard or member-state mutation.

`includeCollections` and `includeGroups` are case-sensitive optional query
booleans. Rocket's [optional form wrapper](https://github.com/rwf2/Rocket/blob/v0.5.1/core/lib/src/form/from_form.rs#L791-L808)
makes missing, invalid or repeated matching fields absent; the handler defaults
those to false. The [boolean value parser](https://github.com/rwf2/Rocket/blob/v0.5.1/core/lib/src/form/from_form_field.rs#L317-L328)
accepts a single bare/empty or case-insensitive `on`/`yes`/`true` as true, and
`off`/`no`/`false` as false, without whitespace trimming. Derived matching uses
the decoded [first name key](https://github.com/rwf2/Rocket/blob/v0.5.1/core/lib/src/form/name/view.rs#L152-L175),
so dotted/bracketed and leading-dot/bracket roots can match. Unknown or wrongly
cased keys are ignored. The query parser remains adapter-owned; the core takes
semantic booleans.

The [member projection](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/organization.rs#L536-L640)
returns nineteen fields inside a three-field list envelope: membership `id`,
`userId`, name, email, externalId, avatarColor, groups, collections, status,
type, twoFactorEnabled, resetPasswordEnrolled, hasMasterPassword, permissions,
ssoBound, claimedByOrganization, usesKeyConnector, accessSecretsManager and
`object: "organizationUserUserDetails"`. No account or organization keys are
included. All memberships are enumerated, including invited and revoked rows.
The unrevoked status controls nullable name; output status below -1 becomes -1.
Stored Manager role 3 becomes Custom 4. Permissions are null except projected
Custom with `access_all`, which has twelve flags and three collection flags true.

Included collections are direct assignments only, suppressed by stored
`access_all` or an enabled full-access group. They are administrative metadata
and have no membership-status filter. Manager unrestricted read/write grants
acquire effective manage permission. Included groups obey group configuration;
other unsupported SSO/Key Connector/Secrets Manager flags remain false. Providers
resolve enrollment, master-password presence and two-factor state from trusted
records rather than request or registration extras.

The [production CLI list command](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/commands/list.command.ts#L244-L283)
calls the [organization-user API](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts#L55-L79)
for `bw list org-members --organizationid`. This is a direct request, distinct
from cached organization/collection lists. All six selected HTTP cases pass
both actual targets with 190 counted requests, two password logins and two
refreshes, excluding two modern fixtures/four registration requests. Three
organizations demonstrate membership identity/isolation and fresh account
name/avatar projections with preserved vault, revision and session authority.
The separate official CLI `2026.10.0` comparison passes sixteen commands on
both targets, including fresh member names without an intervening sync and
fresh-cache recovery. Seventeen direct HTTP requests include one setup login;
two further logins are CLI commands, excluding one registration/two requests.
Client-internal HTTP remains uncounted and no request trace is captured.
That historical list-only proof used created Owner/full-access memberships;
the invitation extension below adds stored Invited and Accepted recipients.
Other status/role/group variants retain separate provider evidence. Owner/full-access and disabled-group arrays are
empty for every query option, so HTTP acceptance does not independently prove
boolean decoding or non-full-access ACL projection. Source/parser/provider tests
establish those distinctions. Sharing and general organization parity remain
open.

## Organization member detail

The [pinned detail
handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L1452-L1473)
and [release 1.37.4
handler](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L1450-L1471)
agree on `GET /api/organizations/{orgId}/users/{memberId}`. Current-device
`Headers` and confirmed Owner/Admin `AdminHeaders` precede typed UUID guards
and query parsing. A confirmed Manager is denied even with `access_all`.
Organization path/query selection retains the existing guard order; there is
no target-member query fallback. Valid missing and foreign membership IDs both
return 400 with `The specified user isn't a member of the organization`,
because lookup is scoped to both organization and membership. GET bodies are
ignored. The rank-one `users/mini-details` route has a separate
[verified mini projection](api-parity.md#organization-member-mini-details-subset);
other method-only literals do not shadow the rank-two GET member route.

The direct response reuses all nineteen member fields and privacy rules from
[member discovery](#organization-member-discovery), without a list envelope.
The optional query parser is shared, but its defaults differ: absent, invalid
or duplicate `includeGroups` means false; the same states for
`includeCollections` inherit the effective groups value. Explicit false
suppresses collections. Owner/full-access rows and disabled groups keep arrays
empty, so their network acceptance matrix cannot prove non-full-access flag
effects; separate parser and provider tests establish those branches.
Successful current-authority reads preserve revisions, account authority,
vaults and other organizations.

The shipped
[ConfirmCommand](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/admin-console/commands/confirm.command.ts#L46-L120)
loads the organization key, performs this GET and validates status before user
public-key lookup or confirmation POST. A current confirmed Owner triggers a
local Error whose published JSON message is
`Error: User is already confirmed.`. The expanded six-case HTTP comparison
passes both actual targets with 240 counted requests, two password logins and
two refreshes, excluding two modern fixtures/ four registration requests. The
eighteen-command official CLI comparison also passes both targets, with
eighteen direct HTTP requests, two CLI password logins and one direct setup
login, excluding one registration/two requests. Both confirmed-Owner checks
require exact exit-one JSON with no data/private extras; unrelated server,
authorization, transport or malformed failures cannot pass. This
checked-negative branch establishes no successful invitations, acceptance,
confirmation, key delivery or captured route trace.

## Organization invitations and placeholder registration

The [pinned invitation
handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L962-L1141)
and [release 1.37.4
handler](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L960-L1139)
agree on `POST /api/organizations/{orgId}/users/invite`. Current-device
Owner/Admin authorization precedes UUID and JSON guards. It requires emails,
groups and a number-or-string type; collections are optional and permissions
default to an empty map. Collection selections require
id/readOnly/hidePasswords/ manage. All collection references are checked
before groups, then role and inviter authority, before processing recipients.
Request-supplied accessAll is ignored. Names and encrypted membership keys are
not supplied by this operation.

Missing-user policy checks precede mailbox validation. The [default domain
gate](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/config.rs#L1518-L1527)
requires nonempty local and domain parts around the last at-sign even with no
whitelist. Missing-at-sign inputs return
`Email domain not eligible for invitations` first; a valid-domain invalid
mailbox reaches the later Invitation-email error. Existing accounts bypass
these missing-user policy checks.

In the default no-SMTP flow, an existing password account receives an Accepted
membership. An unknown email receives a new enabled, passwordless user, a
pending email invitation and an Invited membership. User and invitation
addresses are lowercased without trimming; their saves enforce email validity.
The placeholder gets a fresh account UUID, creation timestamp, email-based
name, empty verifier and wrapped user key, absent asymmetric keys and default
PBKDF2 settings. Its membership has a separate ID, empty wrapped organization
key and the authenticated inviter's email. This does not confirm membership or
deliver an organization key.

[Registration
completion](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L351-L430)
reuses an eligible empty-verifier account's UUID and creation time. Normal
signed email verification consumes the pending invitation and changes every
Invited membership for that UUID to Accepted, across organizations. Other
statuses, roles, grants, inviter metadata and wrapped organization keys remain
unchanged. The signed optional name replaces the existing name only when
present; omitted asymmetric keys preserve the existing pair. The client proof,
wrapped user key, KDF and cleaned hint initialize the same account, and the
security stamp and device refresh authority rotate. No-SMTP profile
emailVerified remains true even when the registration token's verified claim
is false.

The opt-in allocation-free provider and same-ID adapter completion are
implemented. The corrected six-case HTTP comparison passes both actual targets
with 211 counted requests plus eight modern registration requests, three
password attempts (two successful, one rejected placeholder) and two
refreshes. The separate official CLI 2026.10.0 comparison passes twenty-four
commands on both, with sixteen direct HTTP requests plus four registration
requests and three CLI password attempts plus one direct setup attempt.
Invitation HTTP setup is distinct from CLI commands: the shipped CLI has no
invitation or registration command. That invitation-only milestone did not
confirm members. Invite-JWT acceptance, SMTP, policy matrices, group
administration and cipher sharing remain separate work. Upstream performs inner saves sequentially. The local
provider atomically commits each recipient while retaining earlier successful
recipients. Registration completion atomically covers account/marker/status
updates. These stronger rollback guarantees do not imply batch atomicity.

## Single organization-member confirmation

The [pinned single confirmation handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L1296-L1433)
and [release 1.37.4 handler](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L1294-L1431)
agree on `POST /api/organizations/{orgId}/users/{memberId}/confirm`.
Current-device Owner/Admin authorization precedes typed path and JSON guards.
The canonical optional `id` and `key` fields occur in that order; the body ID
has no selection authority. Missing/null key becomes empty. A nonempty opaque
key is required before the organization-scoped lookup. The server does not
validate an RSA envelope, target asymmetric keypair or ciphertext. Unknown
fields, including the CLI's `defaultUserCollectionName`, are ignored;
confirmation does not create a collection.

A valid missing or foreign membership produces the same scoped 400 error.
An Admin can confirm only a User; a Manager, Admin or Owner requires an Owner,
and hierarchy precedes the target-state check. Only raw Accepted status 1 can
become Confirmed status 2. Proposed-state policy then permits or rejects the
mutation. The default-policy adapter atomically changes that membership's
wrapped key/status and recipient revision, preserving grants, other
memberships, keys, sessions and vault payloads. Upstream saves and
notifications are sequential; local rollback/CAS does not imply equivalent
event, mail or push failure behavior.

[Collection visibility and flags](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/collection.rs#L99-L162)
are separate from administration. Confirmed members enumerate stored
`accessAll` or directly assigned collections; role alone does not select rows.
Basic `GET /api/collections` has seven fields. Sync adds readOnly,
hidePasswords and manage: Users retain restrictions and never get manage;
Managers retain stored restrictions in sync even when manage is true.
Non-sync manager details may clear those restrictions. Profile organizations
contains Confirmed memberships, while organizationsNew contains Accepted and
Confirmed memberships. Existing sessions observe confirmation without a new
login. Shared-cipher ownership and write access remain outside this slice.

The [production CLI confirmation flow](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/admin-console/commands/confirm.command.ts#L47-L102)
loads its organization key, reads Accepted membership, fetches the recipient
public key and wraps the organization key before POST. The [bundled SDK
unsigned encapsulation](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-crypto/src/enc_string/asymmetric.rs#L216-L234)
uses type 4 RSA OAEP-SHA1. Its encrypted default collection name is an ignored
extra at this server. For a regular recipient, the [production org-collection
list](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/commands/list.command.ts#L195-L239)
selects global `GET /collections` when canViewAllCollections is false; it does
not require the Owner/Admin organization list endpoint. `list collections`
reads cache instead. These call paths are not captured request traces.

Both actual targets pass six focused HTTP cases: 213 counted requests plus
eight registration requests, two password logins and two refreshes. The
separate official CLI 2026.10.0 comparison passes 23 commands on both: 32 direct
HTTP requests plus four registration requests, three CLI password logins and
two direct setup logins. It performs actual confirmation and verifies selective
recipient collection decryption after login, unlock and fresh-cache login.
Bulk confirmation, SMTP, policy administration, groups, sharing and complete
transport/error parity remain open.


## Bulk organization-member confirmation

The [pinned bulk handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L1302-L1352)
and [release 1.37.4 handler](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L1300-L1350)
agree on `POST /api/organizations/{orgId}/users/confirm`. Current-device
Owner/Admin authority precedes organization UUID and whole-body JSON guards.
The canonical `keys` field is optional; its entries reuse optional `id` then
`key` fields in source order. Missing/null keys and an empty vector produce
200 with a three-field list envelope and empty data, rather than an empty body.
Unknown names are ignored. Raw string body IDs have no UUID parameter guard.

The complete JSON document must decode before processing starts. A later
schema error therefore causes no writes. Once decoded, entries run in order,
without deduplication, through the single-confirmation validation and mutation.
Each result has exactly id, error and the case-sensitive object value
`OrganizationBulkConfirmResponseModel`. A successful row has an empty error;
a failed item records its error and processing continues. A missing/null item
ID instead aborts the outer request with 400, retaining earlier commits but
returning no partial result list. An empty string ID is present and yields a
per-item validation error. The operation is not batch-atomic.

The row error uses [upstream Debug formatting](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/error.rs#L110-L141),
not the ordinary HTTP error envelope or this core's redacted Debug output.
Supported simple domain errors contain the message without quotes or a type
prefix. Distinct user/log messages and sourced database/SMTP errors have other
formats; complete backend/configuration failure parity remains open. Each
successful recipient mutation retains its single-confirmation revision and
collection/profile effects. Local atomicity for an individual item does not
roll back earlier items.

The [shared client bulk API](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts#L230-L241)
constructs this request, but the shipped CLI confirmation command calls only
the single-member POST. Actual client key/decryption checks after direct HTTP
bulk setup cannot establish a CLI bulk caller or captured request trace.
Both actual targets pass six focused HTTP cases: 211 counted requests plus
ten registration requests for five fixtures, two password logins and two
refreshes. A separate official CLI 2026.10.0 comparison passes 21 commands on
both, with 33 direct HTTP requests plus four registration requests, three CLI
password logins and two direct setup logins. It verifies recipient state and
collection decryption after HTTP bulk setup. No CLI bulk caller, internal
request count or endpoint trace is inferred. SMTP, configured policies,
backend diagnostic variants, remaining member/group administration and
shared-cipher writes remain open.


## Single organization-member removal

The [pinned single DELETE](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L1632-L1694)
and [release 1.37.4 handler](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L1630-L1692)
agree on `DELETE /api/organizations/{orgId}/users/{memberId}`. There is no
request DTO or JSON guard; body bytes, media type and body-supplied owner/ID
have no authority. Current-device confirmed Owner/Admin guards precede typed
organization/member UUID parameters. An organization query fallback can
qualify an invalid organization path before the final UUID rejection, but no
query can replace the target member path. Nonempty raw member segments are
classified before UUID checking, including literals with no DELETE-specific
handler.

Lookup is scoped to organization and membership ID. Missing and foreign IDs
have the same 400 error. Only an Owner may remove any target other than a User;
this includes Managers although the source error names Admins and Owners.
Removing a confirmed Owner requires another confirmed Owner. Self-removal is
allowed when those rules permit it. Success has an empty 200 response.

[Membership deletion](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/organization.rs#L738-L750)
removes all direct grants for that account and organization, group links and
the membership, while advancing recipient revision. The direct-grant helper
has no status filter. The account, passwordless placeholder, keys, devices,
access/refresh authority, personal vault and other memberships remain.
No-SMTP cleanup consumes the global lowercased-email invitation marker only
when no other raw Invited-status-zero membership remains; the target is
excluded from that check. Removing one organization must not consume another
pending organization's marker. Existing initialized users can be invited again
under the same account UUID but a new membership UUID, without restoring old
unselected grants.

Upstream performs notification, marker consumption, two revision updates and
cleanup sequentially. The group-link helper updates revision even with no
group rows, and a failed invitation-marker take is ignored. The local provider
instead atomically commits supported scoped cleanup, conditional marker
removal and one recipient revision update. This preserves revision advancement
while strengthening rollback; identical failure timing, update count or
revision value is not claimed. Group administration and notification delivery
remain unsupported.

The [shared remove transport](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts#L309-L318)
matches this DELETE. The separate deleteOrganizationUser method targets a
different delete-account route. The shipped CLI DeleteCommand has no
org-member branch. Client sync/decryption after HTTP removal is observation of
membership state, not a CLI removal caller or endpoint trace. Removing server
access does not erase previously cached plaintext/organization keys or rotate
the organization key.

Both actual targets pass six focused HTTP cases: 212 counted requests plus
eight registration requests for four fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 25 commands
on both, with 40 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins. Recipient sync/fresh-cache
state loses the removed organization while retained sibling and personal data
decrypts. Private marker cleanup and physical rollback use
local SQL tests, not portable list absence. Bulk removal, configured
group/SMTP/notification variants, shared-cipher writes and complete
failure/transport parity remain open.

## Bulk organization-member removal

The [pinned bulk handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L1596-L1694)
and [release 1.37.4 handler](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L1594-L1692)
are byte-identical for this selected block. The route is
`DELETE /api/organizations/{orgId}/users`. Current-device confirmed Owner/Admin
authority precedes organization UUID and whole-body JSON guards. Existing GET
on the same path remains member discovery, not a removal alias.

The [body](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L178-L182)
requires canonical `ids`, an array of strings. These membership newtypes do
not validate UUIDs during JSON decoding. Empty, malformed, Unicode and NUL
strings therefore reach scoped lookup and become item errors. Unknown fields
are ignored; missing/null/wrong-type IDs or nonstring elements reject the
whole body before writes. Positional `[["id"]]` is accepted. An empty IDs
array returns an empty list. Input order, spelling and duplicates remain.

Every item produces exactly `object`, `id` and `error`; the object value is
`OrganizationBulkConfirmResponseModel`. The wrapper has `data`, `object: list`
and `continuationToken: null`. Successful `error` is empty. Missing targets,
hierarchy and last-owner failures retain the single-member messages in their
row and processing continues. A repeated successfully removed ID becomes a
missing-target row. There is no absent-ID semantic abort as in bulk confirmation.

The source passes the same cached AdminHeaders into every item, even after
self-removal. Target lookup, hierarchy, current confirmed-owner count and
invitation decisions run afresh. The local sealed batch context permits absent
actor membership only after this batch's successful self-removal; unrelated
stale authority remains rejected. This narrows concurrency timing relative to
source request snapshots. Each local item is atomic, unlike sequential source
cleanup, and earlier successes survive subsequent failures. Source Error Debug
can include backend causes; matching private SQL/SMTP diagnostics is not claimed.

The [shared bulk transport](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts#L319-L331)
constructs this DELETE. The shipped CLI DeleteCommand has no member branch.
Both actual targets pass six focused HTTP cases: 251 counted requests plus
eight registration requests for four fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 25 commands
on both, with 40 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins.

CLI sync/decryption after HTTP bulk setup cannot establish a bulk caller or
trace.
Private marker effects remain local SQL evidence. SMTP, groups/notifications,
shared-cipher writes, offline cache erasure and full transport/configuration
parity remain open.

## Single organization-member revoke and restore

The selected [revoke handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L2197-L2205),
[revoke transition](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L2247-L2288)
and [restore aliases/transition](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L2290-L2386)
match the [release 1.37.4 blocks](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/organizations.rs#L2195-L2384).

| Method and member-path suffix | Behavior |
| --- | --- |
| `PUT /revoke` | Hide the scoped membership while retaining key and grants |
| `PUT /restore` | Recover the preceding status |
| `PUT /restore/vnext` | Same transition; requested default collection name ignored |

The prefix is `/api/organizations/{orgId}/users/{memberId}`. No route has a data
argument or JSON/media guard: malformed JSON/UTF8 and body IDs, keys and flags
are ignored within inherited transport limits. Success is empty 200. Current
device, confirmed Owner/Admin and organization guards precede typed path UUIDs.
An organization query fallback can qualify an invalid org path before its final
422, but cannot replace the target member. Scoped missing/foreign targets have
the same 400 message; guard 401/422 bodies are not required to be JSON.

Revoke first requires raw status greater than -1, then rejects self, applies
Owner-only authority for an Owner target, and requires more than one confirmed
Owner for every eligible Owner target, including Invited/Accepted Owners.
Admins may revoke other Admins and Managers. The stored status decreases by
128: 0/1/2 become -128/-127/-126. Member metadata reports -1, while profile
organizations and live collections omit the revoked membership.

Restore first requires raw status below 1, then rejects self and non-Owner
actors restoring Owner targets. Negative status increases by 128. Ordinary
Invited zero stays zero but still saves; repeated Invited restore succeeds.
After transformation, non-Owner/non-Admin roles with positive status require
[ordered restoration policies](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/org_policy.rs#L311-L345):
2FA, another organization's SingleOrg rule, then this organization's SingleOrg
rule. Public Custom input stores Manager; imported unknown raw roles also use
the source's below-Admin policy comparison. The default adapter cannot configure
these policies. Email-2FA enrollment fallback and its possible partial effects
remain outside verified scope.

The same membership UUID, wrapped organization key, direct/group grants,
inviter/registration markers and personal account/session/device authority
remain. Restored confirmed membership regains its prior selective collection
visibility. Neither operation erases cached keys/plaintext or rotates an
organization key. Local atomic status/revision writes and live rechecks are
stronger than source revision-before-save and configured policy failure timing.

Both actual targets pass six focused HTTP cases: 265 counted requests plus
ten registration requests for five fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 31 commands
on both, with 43 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins.

The [shared API](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts#L333-L379)
constructs revoke and restore/vnext. The shipped CLI restore command accepts
items only. Login sessions, sync and fresh-cache decryption after HTTP setup
and one strict revoked-confirmation preflight are state observations, not mutation callers,
successful confirmation or endpoint traces. Invited no-op revision advancement
is source/local SQL evidence; HTTP tests claim only wire status and preserved
grants. Bulk status changes, configured policies/SMTP, events/groups, sharing
and full transport/failure parity remain open.
