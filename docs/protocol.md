# Bitwarden protocol notes

Research date: 2026-10-18. These notes describe upstream wire contracts relevant
to an initial personal vault. They are a research target, **not a claim that
every endpoint below is implemented or verified**. The README and real CLI
integration results define the demonstrated compatibility of no-warden.

## Upstream references

| Project | Reference examined |
| --- | --- |
| Vaultwarden | [`58a980f850464f7d9cdc99a765df36f0a3308b91`](https://github.com/dani-garcia/vaultwarden/tree/58a980f850464f7d9cdc99a765df36f0a3308b91) |
| Bitwarden CLI | [`cli-v2026.10.0`, `b449ac1d255784380d75ef026343198891286be7`](https://github.com/bitwarden/clients/tree/b449ac1d255784380d75ef026343198891286be7) |
| Bitwarden SDK | [`c159ee882654e65dd885014001c7f3253d1a170e`](https://github.com/bitwarden/sdk-internal/tree/c159ee882654e65dd885014001c7f3253d1a170e) |

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

The newer route is used by CLI 2026.10.0. A PBKDF2 response with 600,000 iterations
can expose both generations of response fields:

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

KDF type `0` is PBKDF2-SHA256; `1` is Argon2id. Client password salt for a legacy
personal account is the trimmed, lowercased email. Argon2 memory and parallelism
parameters must agree at registration, prelogin, token issuance, and sync.

Sources: [Vaultwarden prelogin](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs),
[CLI prelogin API](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/auth/password-prelogin/password-prelogin-api.service.ts).

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
SMTP delivery, invitation/emergency enrollment, placeholder completion, domain
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
and auth-request password grants and refresh, retaining refresh capability and
the existing encrypted account-decryption fields. JWT `client_id` is the supplied
value, including empty, or `undefined` when absent. Refresh uses the optional
client ID on the refresh request. Bound tokens project `device` and the retained
registry type label as `devicetype`; repeated login/refresh does not replace the
stored name/type. Personal API-key authority is unchanged, and unbound legacy
sessions remain refreshable without invented device claims.

The strict local refresh replay rule still differs from upstream. Mobile
refresh lifetimes, full JWT/refresh-token equivalence, two-factor/mail/SSO policy,
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

Current clients can backfill a legacy user-key identifier after login using
authenticated `POST /api/accounts/key-management/user-key-id` with
`{"userKeyId":"<client-generated key identifier>"}`. Persist the supplied ID
and return an empty success response. Upstream rejects a second assignment with
422. Subsequent synchronization must return it in `userDecryption.userKeyId`;
the local adapter also includes `UserDecryptionOptions.UserKeyId` in token
responses. This identifies existing key material and does not rotate the key.

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
| `GET /api/ciphers/{id}/details` | Details alias |
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

Browser/mobile clients, organizations, attachments, Send, two-factor login,
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
