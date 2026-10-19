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
| `POST /api/accounts/register` | Legacy strict registration with encrypted keys | Cryptographic fixture |
| `POST /identity/accounts/register/send-verification-email`, `POST /identity/accounts/register/finish` | No-SMTP new-account verification token and canonical atomic completion; old/current credential shapes | Eight matching corrected Rust HTTP cases on both actual servers; borrowed opt-in core/provider and host parser, token, rollback/reopen and HTTP-dispatch tests; fresh unchanged CLI regression remains separate |
| Prelogin legacy and identity aliases | PBKDF2/Argon2 parameters | Latest CLI and HTTP |
| `POST /identity/connect/token` | Password grant, expiring sessions, rotating refresh | CLI and HTTP |
| Password grant with compact `authRequest` | Approved, unexpired, same-peer one-use access code; different login device allowed | Eight matching Rust HTTP cases on both actual servers; allocation-free service/provider, exact-deadline, rollback, replay and private-reopen host tests; unchanged CLI regression remains separate |
| `GET /api/accounts/keys`, `POST /api/accounts/keys`, `GET /api/users/<id>/public-key` | Owner-only private retrieval, initialization of an absent pair, authenticated cross-user public lookup | Borrowed core/provider contracts; Rust HTTP comparison group and SQLite rollback/reopen tests |
| `POST /api/accounts/api-key`, `POST /api/accounts/rotate-api-key` | Password-reauthenticated personal key retrieval, lazy creation, rotation | Core, HTTP comparison with upstream, rollback and restart tests; keys used by real CLI |
| Personal `client_credentials` at `POST /identity/connect/token` | `user.<id>`, exact `api` scope, access token without refresh token | Real CLI API login, password unlock and decryption; core and HTTP comparison with upstream |
| `POST /api/accounts/key-management/user-key-id` | One-time key-ID migration | SDK login and HTTP |
| Profile, revision date, sync | Personal account and opaque encrypted vault | CLI and HTTP |
| `PUT`/`POST /api/accounts/profile`, `PUT /api/accounts/avatar` | Exact profile names and nullable avatar colors with UTF-8 byte limits | Core/provider contracts, host rollback tests, and eight matching Rust HTTP cases on both servers; no CLI mutation claim |
| `GET`/`POST`/`PUT /api/settings/domains`, sync domains | Opaque ordered custom groups, signed exclusions, full flagged catalog for GET and filtered catalog for sync | Reusable borrowed views and typed projections, host rollback/isolation tests, eight matching Rust HTTP cases; no CLI domain mutation or settings request trace claim |
| `GET /api/devices/knowndevice`, `GET /api/devices`, `GET /api/devices/identifier/<id>` | Public exact header lookup, authenticated owner-only device projections, verified-login registry and refresh binding | Eight matching Rust HTTP cases against both servers; core/provider and host rollback/reopen tests; no CLI device-route trace claim |
| `POST`/`PUT /api/devices/identifier/<id>/token` and `/clear-token` | Bound-session token writes and disabled-relay public no-op clears, with empty 200 responses | Core/provider and host rollback/reopen tests; eight matching Rust HTTP cases and a separate private read-only stored-state probe on both servers; no CLI route attribution |
| `POST /api/auth-requests`, owner GET, base/pending list aliases | Public known-device creation, eleven-field projections, owner-only pending discovery and latest device pending metadata | Eight matching Rust HTTP cases on both servers; core/provider and host rollback/reopen/peer tests; no CLI auth-request route claim |
| `PUT /api/auth-requests/<id>`, public `GET /api/auth-requests/<id>/response` | Verified-session approval/rejection and exact code/type/IP response polling, without login consumption | Core/provider and host tests; eight matching HTTP cases on both actual servers; no new client-route claim |
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
and SSH-key items, plus optional opaque blob data. Its 178 unit tests cover the
typed fields, bounded collections and import decoding, validation, ownership,
lifecycle rules, folder mapping, the atomic import and bulk provider contracts,
API-key proof selection and authorization, and attachment lifecycle and provider
rules, account-key initialization, profile/avatar byte validation, and equivalent-domain
views, serialization, schema and atomic provider boundaries, plus device
discovery, owner checks, explicit projections, push-provider ordering and
auth-request creation/discovery, decisions, code-protected reads and one-use
approved-request login, and separate opaque modern registration. A compile-fail
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
All 398 active workspace unit tests pass: 178 core, 146 host and 74 support,
plus one ignored support test. They include modern registration, deferred email
validation, account proof/stamp transitions and the corrected concurrency fixtures. Clippy with warnings denied
and minimum-Rust-version checks pass. Required CI also checks the core
doctest, formatting, Clippy with warnings denied, minimum Rust versions,
no-allocator, bare-metal and embedded consumers. The verified 61 JavaScript HTTP
checks and restart-persistence regression remain required final-head checks.
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
failure. Legacy registration validation remains unchanged. Complete profile responses
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
120-command CLI baseline remains separate client evidence. No CLI domain mutation
or direct settings request is attributed to that result.

The selected `--suite devices` run passes all eight cases against the adapter and
official Vaultwarden `1.37.4`: 199 counted HTTP requests per server, including
six identity requests. Those comprise five login attempts (four successful and
one rejected password) and one refresh. The reference `personal` and `devices`
runs use separate fresh processes with unchanged upstream login rate limits;
their combined login attempts would exceed the reference's ten-request login
burst. The prior local `--suite all` subtotal passed 56 cases and 2272 counted
HTTP requests. The prior local milestone with login passes 72 cases and 3038
counted requests. Reference comparisons select `personal`, `devices`,
`device-tokens`, `auth-requests`, `auth-responses` and `auth-login` in separate
fresh processes; no combined 72-case reference run is claimed. Fixture
registration requests are outside those counted suite requests.

The device comparison verifies public known-device headers, trailing-padding
removal, strict base64url and UTF-8 handling, email lowercasing without trimming,
exact opaque identifiers, owner isolation, and authentication/path-guard ordering.
Authenticated lookup uses percent-decoded ASCII alphanumeric/hyphen identifiers
without a UUID requirement. Invalid paths return 422 after authentication;
valid missing/foreign identifiers return 400. Single responses contain exactly
seven fields; list entries contain exactly ten. The original discovery fixtures
have null pending and encrypted-key fields; auth-request fixtures now exercise
the two-field pending metadata. Duplicate successful logins retain original name/type/creation;
password and API-key logins register the verified owner, and refresh retains the
same device identity. Failed login does not register a device. These direct HTTP
results do not establish CLI device-route traces or full device-management parity.

`DeviceStorage` exposes stable borrowed views and explicit allocation-free
boolean/list/single serializers. `KnownDeviceRequest` is borrowed header input,
without JSON serialization/deserialization traits. The two-field pending model
now projects the latest pending request from the separate auth-request provider;
approval decisions change that view; login uses the dedicated provider described
below. Registry and per-session binding
tables ignore account-document device extras. Host tests preserve account
revisions, credentials, keys, vault and foreign state; inject provider, session,
binding and deferred-commit failures; and reopen the private database. Refresh
failure also preserves its original authority and device activity. New JWTs
carry the bound `device`; existing unbound sessions remain valid, with legacy
backfill still open. Device removal and notifications remain pending. The device HTTP proof does not add a CLI command or broader client
claim.

The push-token chunk adds authenticated POST/PUT token aliases and public
POST/PUT clear aliases. All eight selected `--suite device-tokens` HTTP cases pass
against the adapter and official Vaultwarden `1.37.4`: 383 counted HTTP requests
per server, including three successful password logins and no refresh. Hidden
token targeting and activity changes cannot be inferred from the public
seven/ten-field device projections, so wire-only success is not treated as proof
of those properties. A separate private Rust/read-only SQLite probe passes
against both actual servers: 16 HTTP requests and 13 read-only checks per server,
using three password logins and one refresh. It verifies the authenticated target
despite a different path, unchanged other/foreign tokens, unchanged activity on
an identical token, retained empty tokens, disabled public clear retaining both
owners, schema-rejection nonmutation, refresh identity, and unchanged profiles
and account revisions. The SQL observations establish unchanged activity;
literal zero SQL writes is the stronger host-test result checked with abort
triggers. Reference runs preserve their default login and public-clear rate
limits.
This focused HTTP proof adds no CLI device-token route claim or full-parity flag.

The write target is the verified session-bound device, regardless of a valid
path identifier or request device/owner fields. The path remains syntax-guarded.
Opaque tokens include empty, control and Unicode strings. An exact repeat skips
all SQL writes, activity and relay registration; a changed token atomically saves
with activity while preserving account revision, original device metadata,
credentials, sessions and vault/foreign state. The core then invokes registration.
A registration error retains the save, and a retry with the same value skips the
callback. This ordering is covered by provider tests; the standalone relay is
disabled and makes no outbound requests.

Clear is public, ignores bearer/body data, and returns an empty 200 with push
disabled while retaining every token. Invalid paths still return 422. No JSON
null success body is emitted. Enabled-provider tests cover clearing all owners
with an identifier before unregistering the first selected record's push ID,
only when that first ID exists; an absent first ID does not select a later owner's
ID. Unregister failure retains cleared state. These tests do not establish actual
enabled relay registration, deletion or delivery.

`DevicePushTokenRequest` is borrowed, allocation-free and redacted in Debug.
The owned host guard preserves escaped strings, duplicate-field schema errors,
and positional input behavior. Host tests verify bound-session targeting,
refresh binding, exact-repeat zero changes, empty responses, provider/write/
activity/commit rollback, relogin retention, private-database reopen and composite
foreign-key cleanup. Legacy unbound sessions return 401 for push writes while
existing routes remain valid. Local unauthenticated abuse limiting is not
implemented; the reference's default rate limits remain unchanged in comparisons.
Real relay configuration, registration/unregistration, push delivery, notification
APIs and wider device management remain open.

The auth-request chunk passes all eight selected `--suite auth-requests` cases
against the actual adapter and official Vaultwarden `1.37.4`: 273 counted HTTP
requests, five successful logins and 33 decoded create attempts per server.
The reference retains its public burst limit of 50. Tests cover public creation,
owner GET, both pending-list aliases, opaque code/key/device identifiers including
a NUL/Unicode/non-UUID device ID, schema/positional inputs, raw optional device-type
handling, owner isolation, UUID guards and pending-device projection. These HTTP
checks add no CLI approval/login or request-trace claim.

`AuthRequestStorage` extends the allocation-free device provider with owned-owner
lookup, atomic creation and stable indexed borrowed reads. The adapter lowercases
email without trimming, verifies the exact registered device and raw `i32` header
type, then generates a fresh ID and timestamp outside the core. Missing or
unparseable `device-type` becomes 14; unknown numeric types retain their value for
matching while using the unknown-browser display label. Internal access codes,
owner IDs and requesting-device IDs stay out of the eleven-field response and
Debug output. Creation returns `requestApproved: false`; the stored pending null
appears as null on GET/list. Pending lists include only null approvals, without
an implicit age filter.

Device lists select the latest pending creation for each exact owner/requesting
device and disclose only `{id, creationDate}`. Single-device responses remain
seven fields. Host tests establish preservation of account revision, vault and
foreign state, credentials, sessions, push tokens and device activity; inject late
insert/deferred-commit failures; prove registration extras have no authority; and
reopen the private database. These hidden storage guarantees are separate from
the HTTP projection evidence. The adapter records the direct socket peer and
ignores forwarding headers. A bounded real-socket test verifies that policy with
peer `127.0.0.2`; it is not an upstream forwarded-IP equivalence test. Vaultwarden
can honor configured `X-Real-IP` from trusted proxies, including default local
peers. Forwarded-IP parity remains open. Canonical configured URL origin,
excluding the path, does match upstream.

Authenticated reads require a verified session binding before path parsing;
legacy unbound sessions keep their older routes but receive 401 here. Public
creation requires no bearer. Notifications/events, expiry jobs, trusted proxy
policy and local rate controls remain open. Complete auth-request lifecycle and upstream API parity
remain delivery goals.

The approval/response chunk passes all eight selected `--suite auth-responses`
cases against the actual adapter and official Vaultwarden `1.37.4`: 322 counted
HTTP requests and four successful logins per server. Its eleven creates and 33
guard-valid polls use 44 admitted public attempts; six additional query/path
guard rejections do not reach the handler's limiter. The reference retains its
public burst limit of 50. This is approval/polling evidence; login has a separate
comparison and adds no notification evidence.
The required client job reruns the unchanged 120-command CLI regression for
the final head. Its verified baseline passes against both servers; it does not
exercise authentication-request login.
No new CLI auth-request route trace or full-parity claim is made.

The PUT service requires the body device to match the verified bound session,
rejects missing/foreign or already-answered requests, then asks the provider to
commit. True decisions store the exact opaque key, optional hash, response device,
`Some(true)` approval and a fresh timestamp. False deletes the pending row and
returns a cached snapshot with its old fields/null approval and fresh response
date. The rejected request's supplied key/hash do not enter that snapshot.
Decisions remove the request from pending lists/device projections. Eleven new
host tests cover schema/guard order, repeated approval rejection, old-state delete
snapshots, wrong owner/device, update/delete late-write and deferred-commit
rollback, private reopen, and preservation of account/device/session/vault state.

Public polling ignores bearer credentials and requires the exact code, original
raw device type and recorded IP. The adapter uses fixed-size HMAC-SHA256
fingerprints and `Mac::verify_slice` for constant-time code comparison; it does
not compare code strings directly or expose tags. Missing records and wrong
code/type/IP return the same 400 error. A missing `code` query field returns 422;
empty values are valid inputs. First matching scalar roots win, form `+` becomes
space and percent decoding occurs once. Pending and approved responses remain
readable without mutation or login consumption; rejection makes them unavailable.

The actual HTTP comparison verifies the focused wire contract; hidden rollback
and durable state guarantees come from host/provider tests. The direct socket
peer policy still ignores forwarding headers and does
not implement upstream trusted-proxy IP behavior. Notifications/events,
expiry cleanup, proxy policy and public abuse controls remain
open, along with the full upstream API parity goal.

The approved-request login chunk implements the password-grant variant from
the [pinned identity handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L370-L498).
Its proof is the original access code; the encrypted response hash is never a
substitute. The compact `authRequest` form root is case-insensitive, including dotted
and bracketed scalar names; `auth_request` stays unknown. A regression uses a
valid ordinary password with nested missing-request selectors to prove that
none can bypass the selected access-code proof. Other form-root behavior and
the inherited duplicate/ambiguous-field rejection policy remain partial gaps. The ID is opaque, with no UUID guard. A present
empty/missing-record ID cannot fall back to an ordinary password. Required
password-grant fields must be present and the scope must be exactly
`api offline_access`. Username is trimmed before lowercase account lookup.
Blank opaque code/client/device values are accepted when the proof matches.

`AuthRequestLoginStorage` extends the no-allocation provider with owner-scoped
constant-time lookup and approved/unused compare-and-set consumption. Its
borrowed request, private record/context and unforgeable account grant redact
Debug output. The service checks approval, unused state, account enablement,
exact peer IP and `now < creation + five minutes` before consumption. It does
not require the login device or type to match the original request; a different
device may register. Approval/key/hash/response fields remain intact. Public
polling stays readable after successful login and has no implicit five-minute
expiry. All eight selected login HTTP cases pass against both the actual
adapter and official Vaultwarden `1.37.4`: 444 counted requests per server,
including 43 identity requests, twelve creations and twelve public polls. The
identity requests include two ordinary logins, seven successful auth-request
logins and two refreshes. The real 301-second fixture verifies expired login
with readable polling. Host unit tests separately check the exact nanosecond
boundary, including dates
beyond a signed 64-bit nanosecond timestamp.

The adapter's private enabled-account policy defaults to enabled when no row
exists. Registration/profile extras do not set it, and no administrative API is
provided. Its outer savepoint covers request consumption, device creation or
activity, expired-session cleanup, session issuance and binding. Six late-failure
phases, including deferred commit, restore all state and leave the proof usable;
standalone provider failure tests cover the consumption step too. This boundary
is stronger than upstream's separately persisted consumption and issuance.
Two-connection compare-and-set and replay tests permit one winner, and private
reopen preserves the used state. Those hidden guarantees come from provider/host
tests rather than response projections.

Shared password/refresh issuance now uses 7200-second access authority. It
preserves the supplied client ID, including empty, and uses `undefined` when
absent. Refresh takes its client ID from the current request. Bound JWTs include
the retained registry type label as `devicetype`, alongside the exact `device`;
changed login/refresh metadata does not overwrite the initial name/type. The
personal API-key policy remains unchanged, and existing unbound sessions remain
refreshable without fabricated device claims. The stricter local refresh replay
rule, upstream mobile refresh lifetime and broader JWT/refresh equivalence remain
separate gaps.

Required CI reruns the focused login HTTP comparison and the verified unchanged
120-command CLI baseline. That CLI regression does
not log in through an auth request or establish new route traces. Two-factor,
mail/SSO and administrative policy, notifications/events, expiry cleanup, local
rate controls and trusted-proxy forwarding remain open. The adapter compares
its direct socket peer and ignores forwarding headers. This chunk does not set
a full-parity flag or complete the authentication lifecycle goal.

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
traces. Modern registration has the separate no-SMTP scope below. SMTP/invited
registration, complete key rotation/account lifecycle, exhaustive errors,
content-type handling, and transport-size parity remain open.

Modern registration has a separate opt-in `RegistrationStorage` contract;
`RegisterRequest` and the historical fixture endpoint retain strict validation.
The new no-SMTP path implements verification-token issuance and ordinary
new-account finish with old/current credential shapes. The host mirrors the
pinned old-first flattened decoder and aliases, preserving opaque string
hash/key/key-pair values and signed KDF metadata. Its programmatic borrowed
finish view, private validated plan and explicit response serializers preserve
the core's no-allocation boundary. Full JSON compatibility parsing, email
normalization, JWTs, hashing, clocks and persistence remain host duties.

The token retains the raw email and optional name, uses the canonical configured
origin plus `|register_verify`, expires in thirty minutes, and has
`verified:false`. The host's separate private HMAC key persists across reopen;
concurrent initialization reads one authoritative key. Signature/purpose/time
checks include 30-second leeway and Unicode whitespace compatibility. Upstream
uses RS256 rather than the adapter's HS256, so cross-server token use and full
JWT equivalence remain outside this claim. JSON versus plain-text token output
follows the preferred `Accept` media type, with Rocket's weighting/specificity
rules. Quoted separators, escaped quotes and UTF-8 parameter values remain
intact; only a first `q` parameter of at most five value bytes supplies a weight.
Long or later quality parameters are unweighted, while malformed short quality
values reject the header. Verification can issue a token for a long name or invalid-looking email;
finish applies the claim-name limit of 50 UTF-8 bytes.

Current-format KDF/salt mismatch returns 422 before missing/bad token or
unsupported invitation proof. Both salts use trimmed/lowercased email; token
subject matching uses exact raw email, and account storage lowercases without
trimming. Only the verified claim name sets the name, with email fallback when
absent; root finish names and verification flags are ignored. Hints trim to null
when blank. PBKDF2 minimum is 100,000 with no new maximum; Argon2 requires at
least one iteration, memory 15–1024 and parallelism 1–16. Other signed KDF IDs
are preserved and non-Argon2 memory/parallelism normalize to null. Finish then
applies upstream account-save mailbox and URL-domain validation; invalid emails
reject with 400 after proof/policy/KDF checks and create no account. Verification
issuance still accepts those inputs. The host-only `email_address` 0.2.9 parser
preserves supported Unicode/display forms; no parser dependency enters the core.

Successful finish returns exactly `{object:"registerFinish"}`. Any existing host
account rejects with 400. Canonical storage excludes raw verification tokens,
client hashes, nested credential documents and unknown extensions. An Argon2
verifier and private verification flag commit atomically with the new account.
No-SMTP profile/JWT output remains verified under upstream policy even though
the stored claim flag is false. Tests inject four account/metadata/write/commit
failures, prove retry without token consumption, and preserve existing accounts,
credentials, sessions, attachments and vault state. Reopen retains both issued
tokens and completed account state. These are host/provider guarantees.

All eight corrected modern HTTP cases pass against both the actual adapter and
official Vaultwarden `1.37.4`: 541 counted requests each, including 69 verification
requests, 64 finish requests, ten prelogins and nine successful password logins.
Public attempts stay at most 44 per peer with the reference limits unchanged.
These HTTP results are independent of provider rollback/reopen guarantees. A
fresh official CLI `2026.10.0` run also passes all 120 commands against both
corrected servers. That unchanged baseline uses legacy fixture registration and
adds no modern-registration command or route-trace claim.
The prior combined local milestone remains 72 cases/3038 requests, including
the selected eight-case login comparison with 444 requests against each server.
The registration milestone expanded the default selection to 80 cases; the
current combined result appears below. SMTP, invitations/emergency access,
placeholder completion, signup/configuration policy, rate controls,
notifications, complete header grammar, error envelopes and transport limits
remain partial. This chunk
does not claim complete registration or upstream API parity.

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
verified baseline against both servers. Current client regression status is
recorded with the approval/polling results above.
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

## Password verification and stamp renewal

The personal password-verification contract accepts a required camelCase-only
`masterPasswordHash` and returns exactly `{"Object":"masterPasswordPolicy"}`
when no policy applies. The allocation-free extension also models an externally
supplied seven-field policy and a server-verifier upgrade callback. The callback
is separate from client KDF metadata; the current adapter uses current-policy
verifiers and does not implement stale-verifier migration or organization/SSO
policy aggregation.

Stamp renewal accepts the shared exclusive password/protected-action OTP proof
and returns empty 200. The adapter uses private stamp authority, projects it in
profile/sync/JWT, advances owner revision and atomically removes all owner
sessions and registered devices. It preserves encrypted vault data, account keys,
password/API credentials, other owners and pending/approved authentication
requests. An unused approved request can still grant a new login within its
original five-minute, same-peer contract. Successful protected-action OTP,
remembered 2FA and logout notification delivery remain unverified/unsupported by
the adapter. Its rollback guarantee is stronger than upstream sequential failure
semantics, which remain partial.

All eight selected Rust HTTP cases pass against the actual adapter and
Vaultwarden `1.37.4`: 292 counted requests per server, including nine identity
requests (eight successful grants and one rejected old refresh), two public
authentication-request creations and three response polls. The selected group
uses a fresh reference with unchanged rate limits. These direct HTTP checks add
no official CLI command or captured CLI-route claim.

The account-security milestone passed all 88 cases with 3871 counted HTTP
requests, including real authentication-request expiry and modern registration.
A fresh official Bitwarden CLI `2026.10.0` regression also passes all 120 commands
against each server. It adds no account-security CLI command or captured route trace.

## Nested KDF transitions

The allocation-free provider verifies the old hash before complete nested KDF
and salt checks, then applies signed upstream policy and passes an opaque
credential-transition plan to storage. The adapter commits verifier, wrapped
key, client KDF, private stamp, revision and session revocation atomically. It
preserves devices/push rows, API credentials, requests and encrypted vaults.
Seven rollback stages, deferred commit, reopen and stale-proof concurrency use
separate SQL tests; they establish stronger rollback than upstream sequential
mutations, rather than proving identical failure behavior.

The exact nested schema has no legacy flattened fallback. The pinned source
normalizes stored email with trim/lowercase while release 1.37.4 compares it
exactly; normal tested lowercase accounts agree. Notification delivery, remembered
2FA, remaining password-exception routes, versioned salt edge cases and
complete account/KDF/identity parity remain open.

All eight selected KDF HTTP cases pass against both actual servers: 343 tracked
requests each, including nine identity requests (eight successful grants and one
rejected old refresh), two authentication-request creations and four public polls.
The separate official CLI `2026.10.0` selection passes nine commands on each
server after a genuine HTTP PBKDF2 600,000-to-700,000 transition: fresh-cache
login, lock/unlock, sync and decryption of the preexisting item. Its direct seven
HTTP requests and one password grant exclude registration bootstrap and all
CLI-internal requests. No CLI-posted KDF endpoint or captured route is inferred.

The KDF milestone passed all 96 cases with 4214 tracked HTTP
requests, including the real authentication-request expiry fixture.
The unchanged official CLI `2026.10.0` baseline also passes all 120 commands
against each server, separately from the nine-command KDF proof.


## Password changes and limited previous-stamp access

The core models exact nested-first/legacy-fallback credentials, unchanged client
KDF metadata, exact stored-email salts and hint cleanup through provider-owned
state. The adapter preserves encrypted data, devices, API credentials and
authentication requests while replacing ordinary session authority. Only the
existing public-key route supports the four-route previous-stamp policy here.
KDF/direct stamp resets preserve that policy; device deletion blocks it and
same-ID recreation can restore eligibility. Local rollback and immutable
historical-bearer regressions establish provider guarantees separately from
upstream sequential failure semantics. Notifications, remembered 2FA, remaining
exception endpoints, upstream JWT expiry leeway and full account parity stay open.


All eight selected password HTTP cases pass against the actual adapter and
Vaultwarden 1.37.4: 285 tracked requests each, including 11 identity requests
(eight password logins, one API-key login and two refresh attempts, one successful), two
authentication-request creations and four response polls. Direct loopback peers
keep at most six identity requests per peer under unchanged reference limits.
The final case waits at least 121 seconds after the latest password change,
then verifies that an older valid bearer clears the expired latest exception
before its stamp mismatch is denied. Repeating it does not advance revision again.
A separate timed account checks expiry and owner isolation. Counts exclude
shared registration bootstrap.

The separate official CLI 2026.10.0 proof passes ten commands against each server:
old-password rejection, fresh-cache new-password login, lock/unlock, sync and
decryption of an item encrypted before the HTTP password change. Seven direct
HTTP requests and one password grant exclude bootstrap and CLI-internal HTTP.
No CLI-posted password endpoint or captured request trace is inferred.


The final local regression passes all 104 HTTP cases with 4499 tracked
requests across thirteen groups, including real authentication-request and
password-exception expiry. The unchanged official CLI 2026.10.0 baseline passes
all 120 commands against each actual server, separately from the focused KDF
and password CLI proofs.
