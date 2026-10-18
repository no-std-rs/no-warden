# Verified compatibility

The baseline personal-vault suite has passed against both the standalone
no-warden adapter and official Vaultwarden 1.37.4 using the official Bitwarden
CLI 2026.10.0. The upstream image digest and examined source revisions are
recorded in [the test tools](../tools/README.md) and [protocol notes](protocol.md).
That client evidence covers the legacy field-level encryption flow described
below, including personal imports; newer model support has separate limits.

The suite registers a disposable, cryptographically valid account through HTTP,
then uses ordinary CLI password login. It checks client-side decryption, folder
create/get/edit/delete, login-item create/get/list/edit, Unicode notes, custom
fields, sync, local lock/unlock, a fresh CLI cache after logout/login, trash,
restore and permanent deletion. A per-run trusted loopback TLS proxy meets the
current CLI's HTTPS requirement without changing the client or disabling
certificate validation.

The expanded suite passes 90 CLI commands against both servers. It imports
Bitwarden JSON containing login, secure-note, card, and identity items (types
1–4), and Bitwarden CSV containing login and secure-note items (types 1–2).
It verifies decrypted imported fields and folder assignments after sync and a
fresh client cache. CSV folder normalization and ancestor folders are generated
by the client. The suite also archives an imported login, decrypts its password
and notes after a fresh cache login, and restores it from the archive.
It then obtains a personal API key through HTTP, logs in with `bw login --apikey`,
checks that the vault is locked, unlocks with the master password, and decrypts
vault data. The flow repeats with a fresh client cache and a rotated key; the
old secret is rejected. API login output alone does not establish vault unlock.
Real-client blob, SSH-key, and other import variants still need their own fixtures.

| API surface | Standalone behavior | Verification |
| --- | --- | --- |
| `GET /api/config` | Endpoint discovery | Real CLI |
| `POST /api/accounts/register` | Registration with encrypted keys | Cryptographic fixture |
| Prelogin legacy and identity aliases | PBKDF2/Argon2 parameters | Latest CLI and HTTP |
| `POST /identity/connect/token` | Password grant, expiring sessions, rotating refresh | CLI and HTTP |
| `POST /api/accounts/api-key`, `POST /api/accounts/rotate-api-key` | Password-reauthenticated personal key retrieval, lazy creation, rotation | Core, HTTP comparison with upstream, rollback and restart tests; keys used by real CLI |
| Personal `client_credentials` at `POST /identity/connect/token` | `user.<id>`, exact `api` scope, access token without refresh token | Real CLI API login, password unlock and decryption; core and HTTP comparison with upstream |
| `POST /api/accounts/key-management/user-key-id` | One-time key-ID migration | SDK login and HTTP |
| Profile, revision date, sync | Personal account and opaque encrypted vault | CLI and HTTP |
| Folder CRUD | Encrypted names, owner isolation, clear references on deletion | CLI, HTTP, storage tests |
| Cipher CRUD | Opaque ciphertext and unknown JSON fields | CLI, HTTP, storage tests |
| `POST /api/ciphers/import` | Personal encrypted batch import, folder-index mapping, fresh item IDs, owned-folder reuse | Real CLI JSON/CSV, HTTP, storage rollback tests |
| Trash, restore, permanent-delete aliases | Owner-checked lifecycle | CLI and HTTP |
| Bulk trash, restore, and permanent deletion, including admin-named aliases | Deduplicated IDs, personal ownership checks, atomic batch persistence | Core, HTTP comparison with upstream, storage rollback and restart tests |
| Single and bulk archive/unarchive | Per-user archive metadata, preserved cipher revision, advancing account revision | Real CLI archive/unarchive, core, HTTP comparison with upstream, rollback and restart tests |
| Conditional cipher update | Stale revision returns 409 | Concurrent HTTP edits |
| Legacy folder update/delete aliases, cipher clone wrapper | Owner isolation, fresh clone IDs, empty collection IDs, PascalCase wrapper aliases | Core and HTTP tests |
| `CipherRequest.data` blob payload | Preserve escaped opaque data through create/get/update/sync | Core and HTTP tests; real-client blob round trip unverified |
| Stored login FIDO2 credentials | Preserve bounded encrypted records and unknown nested fields through create/get/update/sync | Core and HTTP tests; authenticator use unverified |
| CRUD `archivedDate` metadata | Absent/null clears archive state, a valid timestamp sets it, and an invalid timestamp leaves it unchanged | HTTP comparison with upstream |
| Organization ID aliases | Reject non-null `organizationId` and `organizationID` in direct and wrapped personal writes | HTTP authorization tests |
| Type-7 encrypted strings | Validate outer base64 envelope and preserve COSE bytes | Core tests; no COSE cryptography in the core |
| Current user-key ID on creates and imports | Compare a supplied ID with `Storage::user_key_id` when available | Core provider tests for both; HTTP tests for creates |
| Provider conflict errors | `Storage::map_error` can preserve an HTTP 409 conflict | Core provider tests |

The allocation-free core's models include login, secure note, card, identity,
and SSH-key items, plus optional opaque blob data. Its 45 unit tests cover the
typed fields, bounded collections and import decoding, validation, ownership,
lifecycle rules, folder mapping, the atomic import and bulk provider contracts,
and API-key proof selection and authorization. A compile-fail doctest verifies
that `Secret` cannot be serialized through the general Serde interface.
Real-client import evidence covers the types listed above; broader operations
for those types and blob encryption need their own client fixtures. Keeping
encrypted passkey records in a login item does not
implement WebAuthn/passkey account authentication or verify authenticator use.

The fixture uses PBKDF2. Argon2 parameter policy is unit tested; real-client
Argon2 account interoperability is not yet verified. Browsers, extensions,
desktop and mobile are not covered by the CLI result. Full organization,
attachment, Send, notification and account-management compatibility remains on
the [roadmap](../ROADMAP.md).

The expanded HTTP regression suite passes all 52 tests against the rebuilt
standalone server, with 17 Rust host tests covering storage and transport rules.
These establish wire preservation and authorization for the new shapes,
aliases, and personal imports independently of the CLI evidence.
They do not prove that a real client can decrypt a blob or use stored passkey
credentials.
User-key-ID migration is a one-time identifier backfill, not a key-rotation
implementation.

The personal API-key chunk follows the pinned
[key-management handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1476-L1501).
Both endpoints require an authenticated caller and reauthentication. A repeated
key retrieval preserves the secret and account revision; lazy creation and
rotation issue a 30-character alphanumeric secret and advance the revision.
Rotation changes future API-key logins without revoking existing access tokens
or password-grant refresh tokens. The recoverable secret is confidential server
credential data, not encrypted vault content exposed by profile or sync.

The [upstream proof model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/mod.rs#L49-L75)
accepts exactly one of `masterPasswordHash` (`MasterPasswordHash` alias) or `otp`.
The core delegates proof verification to its provider. The host accepts only the
client-derived password authentication hash; protected-action email OTP and
passwordless account flows remain unsupported. An OTP is not a TOTP login code.

The [personal token handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L600-L748)
requires `client_id=user.<account-id>`, a matching `client_secret`, exact
`scope=api`, and device identifier, name, and type. It returns a two-hour access
token and encrypted key/KDF/decryption metadata, with no refresh token. The
[shipped client renews API tokens](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/services/api.service.ts#L1464-L1478)
by repeating that grant. Its TypeScript API-key login strategy preserves the
credentials; the password-account unlock command separately invokes SDK crypto.
All 14 portable API-key HTTP tests pass against the actual Vaultwarden 1.37.4
binary in four isolated processes with unchanged upstream rate-limit settings.
Local rollback tests cover failed key creation and rotation, and keys, rotations,
and issued API bearers survive two graceful restarts. Organization credentials,
KeyConnector, protected-action OTP, upstream rate limiting, two-factor policy,
and device notification behavior are not established by this personal subset.

Personal import follows the pinned
[Vaultwarden folder mapping and creation rules](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L613-L678):
relationships override incoming folder IDs, duplicate cipher indexes use the
last entry, invalid folder indexes clear the mapping, and nonexistent cipher
indexes are ignored. Existing owned folders retain their names; unknown and
foreign IDs create fresh folders. The adapter additionally validates ownership,
current key IDs, and ciphertext before committing the entire batch atomically.
These checks and rollback guarantees are stronger than that source handler,
which prevalidates selected fields and then saves sequentially. The
[pinned client submits JSON and CSV imports](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/importer/src/services/import.service.ts#L468-L481)
to the same authenticated route and expects an empty success response.
Organization import and a full import/export contract remain unimplemented.

The current bulk lifecycle contract follows the pinned
[Vaultwarden delete and restore helpers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L1816-L1972)
and [archive helpers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L2026-L2139).
Requests contain `ids`; duplicates collapse and result order is unspecified.
Delete and trash return an empty success response; bulk restore, archive, and
unarchive return a list of cipher responses. Empty batches succeed. The adapter
requires ownership of every selected personal item before an atomic commit;
missing or inaccessible bulk members return 400, matching the pinned helper's
status. Vaultwarden may already have mutated other members when returning that
error; the adapter rolls back the complete batch. Existing single-item lifecycle
handlers retain their earlier 404 policy. Atomicity and the narrower personal
permissions remain explicit limitations on full parity.

Archive state is independent of trash state. Archive/unarchive updates the
account revision without changing the cipher's revision. Ordinary cipher
create/update follows the
[upstream `archivedDate` handling](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L580-L586):
absent or null unarchives, a valid timestamp sets the supplied date, and an
invalid timestamp leaves the current archive annotation unchanged. The
[pinned CLI archive service](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/vault/services/default-cipher-archive.service.ts#L64-L89)
uses the bulk archive/unarchive routes even for one item. Its archive command
checks premium and item state before sending the request; the pinned server
helpers do not impose those checks. The shared client also constructs bulk
delete/trash/restore requests, but that source evidence does not establish a
dedicated CLI bulk command. Source declarations at Vaultwarden `58a980f` and
runtime behavior of release `1.37.4` are tracked separately. The same 10 portable
HTTP tests pass against the release binary and cover all 12 new route patterns.
The complete standalone suite also checks atomic rollback and persistence across
two graceful restarts; these provider guarantees are separate from the upstream
comparison.

Direct HTTP tests verify that refreshing consumes the supplied refresh token and
issues a new pair while existing access tokens keep their original expiry. The
old-bearer result matches a disposable HTTP probe of Vaultwarden 1.37.4. The CLI
suite verifies its ordinary encrypted lifecycle; it does not force an old-bearer
request to overlap refresh, so that ordering has HTTP-only evidence. This
adapter's single-use refresh policy is stricter: the upstream baseline accepted
immediate refresh-token replay in the disposable HTTP probe, while this adapter
returns `400 invalid_grant` for replay. Concurrent use of one refresh token
allows exactly one successful rotation. Token issuance purges a stored session
only after both its access and refresh authority have expired.

This adapter is a conformance host. It has no deployment hardening, login abuse
controls, two-factor authentication, administrative account recovery, or schema
migration policy yet. Keep real vaults in an established service until those
capabilities and an independent security review are complete.
