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

The prior 90-command baseline passes against both servers. It imports
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

The attachment extension expands the suite to 118 CLI commands, all passing
against the standalone host and official Vaultwarden 1.37.4. The account-key
extension adds two matching fingerprint checks, bringing the verified suite to
120 commands against both servers.

| API surface | Standalone behavior | Verification |
| --- | --- | --- |
| `GET /api/config` | Endpoint discovery | Real CLI |
| `POST /api/accounts/register` | Registration with encrypted keys | Cryptographic fixture |
| Prelogin legacy and identity aliases | PBKDF2/Argon2 parameters | Latest CLI and HTTP |
| `POST /identity/connect/token` | Password grant, expiring sessions, rotating refresh | CLI and HTTP |
| `GET /api/accounts/keys`, `POST /api/accounts/keys`, `GET /api/users/<id>/public-key` | Owner-only private retrieval, initialization of an absent pair, authenticated cross-user public lookup | Borrowed core/provider contracts; Rust HTTP comparison group and SQLite rollback/reopen tests |
| `POST /api/accounts/api-key`, `POST /api/accounts/rotate-api-key` | Password-reauthenticated personal key retrieval, lazy creation, rotation | Core, HTTP comparison with upstream, rollback and restart tests; keys used by real CLI |
| Personal `client_credentials` at `POST /identity/connect/token` | `user.<id>`, exact `api` scope, access token without refresh token | Real CLI API login, password unlock and decryption; core and HTTP comparison with upstream |
| `POST /api/accounts/key-management/user-key-id` | One-time key-ID migration | SDK login and HTTP |
| Profile, revision date, sync | Personal account and opaque encrypted vault | CLI and HTTP |
| `PUT`/`POST /api/accounts/profile`, `PUT /api/accounts/avatar` | Exact profile names and nullable avatar colors with UTF-8 byte limits | Core/provider contracts, host rollback tests, and eight matching Rust HTTP cases on both servers; no CLI mutation claim |
| `GET`/`POST`/`PUT /api/settings/domains`, sync domains | Opaque ordered custom groups, signed exclusions, full flagged catalog for GET and filtered catalog for sync | Reusable borrowed views and typed projections, host rollback/isolation tests, eight matching Rust HTTP cases; no CLI domain mutation or settings request trace claim |
| `GET /api/devices/knowndevice`, `GET /api/devices`, `GET /api/devices/identifier/<id>` | Public exact header lookup, authenticated owner-only device projections, verified-login registry and refresh binding | Eight matching Rust HTTP cases against both servers; core/provider and host rollback/reopen tests; no CLI device-route trace claim |
| Folder CRUD and POST aliases | Opaque names, four-field responses, owner isolation, clear references without changing cipher revisions | CLI baseline; core/host tests and the focused HTTP comparison described below |
| Cipher CRUD | Opaque ciphertext and unknown JSON fields | CLI, HTTP, storage tests |
| Personal v2 attachment reservation and multipart upload | Opaque encrypted metadata and bytes; declared/measured size checks | Core, real CLI on both servers, matching HTTP |
| Legacy attachment upload, replacement, and delete aliases | Same personal write checks; fresh replacement IDs; transactional cleanup | Core, local/upstream HTTP and restart checks |
| Attachment metadata and scoped file download | Personal read checks, authoritative metadata, bearerless short-lived capability | Real CLI on both servers and matching local/upstream HTTP |
| Cipher `attachments2` updates | Associated encrypted filename/key updates preserve stored bytes | Core and local/upstream HTTP |
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
and SSH-key items, plus optional opaque blob data. Its 98 unit tests cover the
typed fields, bounded collections and import decoding, validation, ownership,
lifecycle rules, folder mapping, the atomic import and bulk provider contracts,
API-key proof selection and authorization, and attachment lifecycle and provider
rules, account-key initialization, profile/avatar byte validation, and equivalent-domain
views, serialization, schema and atomic provider boundaries, plus device
discovery, owner checks and explicit projections. A compile-fail
doctest verifies that `Secret` cannot be serialized through the general Serde interface.
Real-client import evidence covers the types listed above; broader operations
for those types and blob encryption need their own client fixtures. Keeping
encrypted passkey records in a login item does not
implement WebAuthn/passkey account authentication or verify authenticator use.

The fixture uses PBKDF2. Argon2 parameter policy is unit tested; real-client
Argon2 account interoperability is not yet verified. Browsers, extensions,
desktop and mobile are not covered by the CLI result. Full organization,
attachment, Send, notification and account-management compatibility remains on
the [roadmap](../ROADMAP.md).

The expanded local HTTP regression suite has passed all 61 tests. After the
missing-download-token status correction, the final nine focused attachment
checks also pass against the rebuilt adapter.
All 63 Rust host tests pass and cover storage and transport rules. The host-only
Rust conformance crate adds 47 unit tests, bringing the workspace count to 208
unit tests plus the core doctest.
These establish wire preservation and authorization for the new shapes,
aliases, and personal imports independently of the CLI evidence.
They do not prove that a real client can decrypt a blob or use stored passkey
credentials.
User-key-ID migration is a one-time identifier backfill, not a key-rotation
implementation.

The account encryption-key group passes all eight Rust HTTP cases against the
adapter and official Vaultwarden `1.37.4`: 242 requests and three password logins
per run. It exercises complete and missing pairs, strict private/public response
projections, opaque initialization, JSON rejection and positional field order,
authenticated cross-user public lookup, UUID guards, and nonmutating repeated
initialization. The folder group still passes its 220 requests against both.

The profile/avatar group passes all eight Rust HTTP cases against the same two
servers: 425 counted requests including two password logins. It preserves exact
empty, whitespace, control and Unicode names, with a maximum of 50 UTF-8 bytes.
Present avatar colors must
contain exactly seven UTF-8 bytes, without hexadecimal or `#` validation.
An omitted/null object field or `[null]` clears the avatar; `[]` rejects with
422, and surplus positional elements reject with 400. Profile GET, mutation
responses, and sync return the stored name directly, including an empty string.
New registrations discard avatar extras. Non-string avatar extras retained in
older account documents project as null, preserving the response field's
string/null type without rewriting those documents.

`AccountProfileStorage` supplies atomic field/revision writes through the
reusable `update_profile` and `update_avatar` services. The provider preserves
keys, credentials, sessions, vault contents, and foreign accounts, including on
failure. Registration validation remains unchanged. Complete profile responses
remain adapter-built; these three new routes add no typed core full-profile
response or CLI mutation claim. The unchanged 120-command CLI baseline also
passes a fresh regression against the updated adapter. Full account lifecycle
and upstream API parity remain open.

The equivalent-domain group passes eight Rust HTTP cases against the adapter
and official Vaultwarden `1.37.4`: 530 counted requests and two password logins.
The selected `--suite personal` run combines folder, account-key, profile/avatar
and domain checks: all 32 cases pass against each server, with 1417 counted
requests and nine password logins, excluding fixture registrations. Its full
91-entry catalog matches the ordered public reference fingerprint. The verified
120-command CLI baseline remains separate client evidence; required CI reruns it
for the device changes. No CLI domain mutation or direct settings request is
attributed to that result.

The selected `--suite devices` run passes all eight cases against the adapter and
official Vaultwarden `1.37.4`: 199 counted HTTP requests per server, including
six identity requests. Those comprise five login attempts (four successful and
one rejected password) and one refresh. The reference `personal` and `devices`
runs use separate fresh processes with unchanged upstream login rate limits;
their combined login attempts would exceed the reference's ten-request login
burst. Default `--suite all` selects all 40 cases for local adapter regression.
It is not a claimed combined 40-case reference run. Fixture registration requests
are outside the counted suite requests.

The device comparison verifies public known-device headers, trailing-padding
removal, strict base64url and UTF-8 handling, email lowercasing without trimming,
exact
opaque identifiers, owner isolation, and authentication/path-guard ordering.
Authenticated lookup uses percent-decoded ASCII alphanumeric/hyphen identifiers
without a UUID requirement. Invalid paths return 422 after authentication;
valid missing/foreign identifiers return 400. Single responses contain exactly
seven fields; list entries contain exactly ten, with null pending and encrypted
key fields. Duplicate successful logins retain original name/type/creation;
password and API-key logins register the verified owner, and refresh retains the
same device identity. Failed login does not register a device. These direct HTTP
results do not establish CLI device-route traces or full device-management parity.

`DeviceStorage` exposes stable borrowed views and explicit allocation-free
boolean/list/single serializers. `KnownDeviceRequest` is borrowed header input,
without JSON serialization/deserialization traits. The two-field pending model
is only a projection contract; the adapter supplies null and implements no
pending-authentication lifecycle. Dedicated registry and per-session binding
tables ignore account-document device extras. Host tests preserve account
revisions, credentials, keys, vault and foreign state; inject provider, session,
binding and deferred-commit failures; and reopen the private database. Refresh
failure also preserves its original authority and device activity. New JWTs
carry the bound `device`; existing unbound sessions remain valid, with legacy
backfill still open. Push-token endpoints, device removal/approval, authentication
requests and notifications remain pending. Required CI reruns the unchanged
120-command real CLI suite for this chunk; the device HTTP proof does not add a
CLI command or broader client claim.

`GET /api/settings/domains` includes every global catalog group with its computed
exclusion flag. Sync includes custom groups and only unexcluded catalog groups,
or `domains:null` when `excludeDomains` is true. Custom strings remain opaque,
including empty strings, NUL and Unicode; group/string order and duplicates are
preserved. Negative, unknown and duplicate signed `i32` exclusion IDs are retained.
`POST` and `PUT` replace both arrays, return exactly `{}`, and advance the account
revision even when the values are unchanged. Omitted/null object fields clear
their arrays. Positional input uses exclusions first and custom groups second:
`[null,null]` clears both; `[]` and `[null]` reject with 422; surplus elements reject
with 400. Schema/syntax errors and unauthenticated writes preserve stored state.

The sync query parser follows the tested Rocket behavior: ASCII-case-insensitive
boolean aliases, empty/bare true, decoded names, leading dotted/bracketed roots
and suffixes, and the first matching value. Tested invalid values return 422;
authentication takes precedence, returning 401 for missing or invalid bearers
even when the query is invalid. The core has no HTTP/query parser dependency.

`DomainSettingsStorage` exposes stable indexed borrowed data and commits both
arrays and the account revision atomically. `DomainSettingsRequest` lets embeddings
choose decoder capacities; the host lends owned vectors without a new count
limit. The host's owner-keyed settings table ignores registration extras and
preserves account authority, keys, sessions and vault data, including on failure.
An adapter-supplied `GlobalDomainCatalog` feeds the allocation-free typed
GET/sync serializers; no catalog or allocation dependency enters the core.
The full sync response remains adapter-built. SyncSettings notifications and
shared content-type, error-envelope and transport-limit gaps remain open;
this focused comparison does not establish complete settings or API parity.

`AccountKeyStorage` provides borrowed state and atomic initialization for embedding
applications. Empty strings count as present keys. A partial pair prevents
initialization but cannot satisfy private retrieval. The adapter preserves the
symmetric account key, key ID, password verifier, API credentials, sessions,
unknown account fields, vault data, and attachments. Tests inject document,
revision, and deferred-commit failures and reopen the private database to verify
rollback and durable empty-key state. Core response serializers redact key
material in Debug and link into the bare-metal consumer without an allocator.

The CLI fingerprint extension compares the cached active user’s fingerprint with
`bw get fingerprint <user-id>`, whose UUID branch performs the authenticated public
lookup. Fingerprints stay private. This flow supplies client evidence for public
lookup only; it does not establish CLI key-pair initialization or captured request
traces. Modern registration, complete key rotation/account lifecycle, exhaustive
errors, content-type handling, and transport-size parity remain open.

The folder chunk corrects the behavior of the seven existing
[pinned folder routes](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/folders.rs#L14-L110).
The upstream request model accepts any string `name`, including empty strings,
Unicode, future encryption formats, and names larger than one MiB. These name
cases already pass the direct Rust HTTP comparison against both the adapter and
Vaultwarden 1.37.4. A supplied body `id` may be a string, null, or absent; it does
not choose the created folder ID or replace the update path ID. Missing or
wrong-typed known fields and duplicate known fields are rejected before mutation.
The owned host decoder handles JSON escapes before borrowing
`FolderWriteRequest`; unknown request fields remain private in local storage.

The core's existing `create_folder` and `update_folder` methods retain the
strict `FolderNamePolicy::Encrypted` default. Embeddings can explicitly choose
`FolderNamePolicy::Opaque` through the corresponding `_with_policy` methods;
this mode does not interpret the name or impose an encrypted-field size limit.
The adapter selects it only for folder CRUD. Personal imports retain their
existing strict validation. HTTP transport limits remain an adapter policy,
outside the `no_std`, allocation-free core.

All folder response surfaces—create, update, get, list, and sync—project exactly
`id`, `name`, `revisionDate`, and `object: "folder"`, following the
[pinned folder model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/folder.rs#L52-L62).
Stored extensions are preserved internally and are not echoed as response fields.
A valid but missing or foreign folder UUID returns 400 with `Invalid folder`;
malformed UUID paths return 422, matching [Rocket’s generated path guard](https://github.com/rwf2/Rocket/blob/v0.5.1/core/codegen/src/attribute/route/mod.rs#L130-L143). The
[upstream UUID path guard](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/macros/src/lib.rs#L15-L27)
validates syntax without normalizing spelling or case. The
[Rocket JSON guard](https://api.rocket.rs/v0.5/src/rocket/serde/json.rs.html#196-210)
distinguishes schema errors classified as data errors (422) from syntax/end-of-input
errors (400); local diagnostics do not include supplied names or response bodies.
Both DELETE and POST-delete aliases return an empty 200 response, matching
upstream's `EmptyResult` and
[Rocket's default empty response](https://api.rocket.rs/v0.5/rocket/struct.Response.html#method.new).

Deleting a folder advances the account revision and clears its associations,
without changing retained cipher revisions, as the
[upstream deletion model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/folder.rs#L101-L110)
shows. A storage regression compares active and trashed cipher documents and
columns before and after deletion, along with opaque fields, archive annotations,
attachment metadata, every encrypted attachment byte, and existing download
grants. Loose items and a foreign account's folder and cipher remain unchanged.
Injected account-revision failures roll the local mutation back atomically;
parser and ownership failures also preserve persisted state.

All eight Rust folder cases pass against the adapter and official Vaultwarden
`1.37.4`: 220 HTTP requests and two password logins per run, covering all seven
folder route patterns. These runs verify projection, opaque names, ignored body
IDs, positional inputs, JSON rejections, ownership, UUID guards, deletion effects,
and unauthenticated access. The 118-command CLI result above is the previously
verified baseline against both servers; the required client job reruns it with
this chunk.
Folder notifications and WebSocket/push behavior, complete error envelopes,
content-type handling, and transport-limit parity remain open. In particular,
the adapter's 16-MiB request cap differs from upstream's
[20-MB JSON limit](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/main.rs#L575-L578).
These folder corrections do not set a full-parity flag or complete the full API
delivery goal.

The attachment chunk follows the pinned
[v2 and legacy handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L1127-L1496).
Reservation accepts `key`, `fileName`, numeric or decimal-string `fileSize`, and
optional `adminRequest`. It returns upload type 0 and a cipher response under
`cipherResponse` or `cipherMiniResponse`. Direct upload is an authenticated
multipart request with a `data` file part; the metadata reservation supplies its
filename and key. Legacy upload instead requires those in the multipart request.
Delete aliases return `{cipher: ...}`. Admin-named aliases do not bypass access
checks. Missing, mismatched, and inaccessible API records produce 400 in the
pinned helpers. The
[required download token query](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/web.rs#L231-L240)
produces 422 when absent, before the upstream handler runs; an invalid supplied
capability or missing file produces 404.

Reservation leaves revisions unchanged. Upload and deletion advance the account
revision while preserving the cipher revision. Actual encrypted size within
one MiB of the declared size is accepted and recorded; an out-of-range upload
deletes its reservation and bytes. The local BLOB transaction and atomic legacy
replacement are stronger than upstream's separate metadata/filesystem writes
and delete-before-replacement sequence. This atomicity covers stored metadata,
bytes, and revision changes; response/capability generation can still fail after
commit, returning an error with the mutation retained. `attachments2` changes only the key and
filename of matching attachments; missing entries are skipped and a foreign
entry stops iteration. Attachment ciphertext validation and decryption remain
client responsibilities.

The [upstream download model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/attachment.rs#L57-L76)
returns encrypted `fileName`, `key`, decimal-string `size`, `sizeName`, and a URL.
The local URL is a 60-second capability scoped to both IDs; its strict expiry
differs from upstream's JWT decoder's 30-second leeway. The local 16-MiB request
cap is below upstream's 525,000,000-byte multipart file limit and the core's
550,502,400-byte declared-size ceiling. See [architecture](architecture.md) for
these distinct transport and provider limits. The same nine portable attachment
HTTP tests pass against Vaultwarden 1.37.4 and cover all eleven route patterns.
All 118 real CLI commands pass against both servers.
Attachment state, encrypted bytes, and cleanup survive two graceful restarts.
Organization access, quotas, remote object storage,
emergency access, and notification transports remain outside this personal proof.

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
