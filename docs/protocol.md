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

The token login password is `authentication_hash`; it is not the plaintext
master password. Servers should hash that authentication secret again for
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
An adapter may expose a local fixture endpoint separately; that is not evidence
that upstream public registration is implemented.

Source: [Vaultwarden identity registration](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs).

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
numeric `exp`, `nbf`, and server-side `sstamp`, `device`, `client_id`, `scope`,
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
device approval, SSO, passkey authentication, key rotation, push notifications,
and recovery need separate implementation and actual-client evidence. A passing personal
CLI test must not be described as complete Bitwarden or Vaultwarden parity.
