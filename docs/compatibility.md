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
| `DELETE /api/accounts`, `POST /api/accounts/delete` | Reauthenticated personal-account removal, atomic supported cleanup and authority revocation | Six matching Rust HTTP cases on both actual servers; core/provider and local rollback/reopen tests; no executed account-deletion client or route trace claim |
| `POST /api/ciphers/purge` | Password-reauthenticated personal cipher/folder/attachment cleanup, revision advance and preserved account authority | Six matching Rust HTTP cases on both actual servers; core/provider and local rollback/reopen tests; no CLI purge caller claim |
| `GET /api/webauthn` | Fixed empty credential metadata, authenticated owned-device access and existing previous-stamp guards | Six matching Rust HTTP cases against both actual servers; no passkey or CLI call claim |
| `POST /api/accounts/register` | Legacy strict registration with encrypted keys | Cryptographic fixture |
| `POST /identity/accounts/register/send-verification-email`, `POST /identity/accounts/register/finish` | No-SMTP new-account verification token and canonical atomic completion; old/current credential shapes | Eight matching corrected Rust HTTP cases on both actual servers; borrowed opt-in core/provider and host parser, token, rollback/reopen and HTTP-dispatch tests; fresh unchanged CLI regression remains separate |
| Public identity prelogin aliases; local legacy extension | Complete signed response and stable unknown-account KDF catalog | Six matching identity-route HTTP cases and separate twenty-six-command PBKDF2/Argon2 CLI comparison; local extension uses host tests |
| `POST /identity/connect/token` | Reusable ordinary password grant and password-method refresh; valid refresh proofs can be reused with current device authority | CLI baseline, six matching ordinary-password Rust cases and eight matching refresh cases. Refresh JWT encoding and complete identity policy remain open |
| Personal text Sends, recipient `send_access` grant and sync | Encrypted owner lifecycle, scoped recipient access, password management and atomic access limits | Six matching Rust HTTP cases and twenty matching official CLI commands on both servers. File Sends are verified separately below; full policy/transport parity remains open |
| Personal file Sends: reservation, multipart upload, file-URL issuance and binary GET | Immutable encrypted metadata, exact bytes, scoped capabilities and create-only storage | Six matching HTTP cases and a separate twenty-command official CLI comparison on both servers; configured policies and full transport remain open |
| Organization-owner creation/discovery and initial collection | Confirmed Owner membership, exact public/profile/collection projections and last-owner deletion protection | Six matching HTTP cases and nineteen matching official CLI commands on both actual servers |
| Organization member discovery | Actual member/account metadata, exact nineteen-field projection and current-device/full-access guards | Six matching HTTP cases and sixteen matching official CLI commands on both actual targets; imported-role/query branches have separate provider/parser tests |
| Default no-SMTP organization invitations and placeholder completion | Ordered per-email commits, real Invited/Accepted states and same-ID modern registration | Six matching HTTP cases and twenty-four matching official CLI result checks on both targets; invitation/registration setup is HTTP, not a CLI caller or confirmation claim |
| Organization member detail | Scoped Owner/Admin read and direct nineteen-field response | Expanded six matching HTTP cases and eighteen official CLI commands on both targets, with strict local already-confirmed rejection; no successful confirmation claim |
| Single-member confirmation and recipient reads | Accepted-to-Confirmed key delivery, current-device Owner/Admin guards and selective collection/sync projection | Six matching HTTP cases and 23 matching official CLI commands on both targets, including actual confirmation and recipient decryption; no bulk/SMTP/sharing or trace claim |
| Bulk member confirmation | Ordered item results, continued errors and committed-prefix abort with whole-body schema validation | Six matching HTTP cases and 21 matching official CLI state/decryption commands on both targets after HTTP bulk setup; no CLI bulk caller or trace |
| Single member removal | Scoped membership/grant cleanup and last-owner protection with retained account authority | Six matching HTTP cases and 25 matching official CLI state/decryption commands after HTTP setup on both targets; no removal caller, trace or offline erasure claim |
| Bulk member removal | Ordered independent item commits, exact results and intentional self-removal continuation | Six matching HTTP cases and 25 matching official CLI state/decryption commands after HTTP setup on both targets; no bulk caller or trace claim |
| Single member revoke/restore | Bodyless status transitions preserve keys/grants and recover selective visibility | Six matching HTTP cases and 31 matching CLI observation commands on both actual targets; no mutation caller or trace claim |
| Organization member public-key batches | Ordered scoped public-only rows, null-key retention and unfiltered target states/roles | Six matching HTTP cases (431 requests) and 16 matching official CLI fingerprint/decryption commands on both targets; no bulk CLI caller or browser trace claim |
| Single organization-collection update/delete | Complete grant replacement, opaque names, whitespace external-ID clearing and preserved cipher data | Allocation-free core and local rollback/cascade tests; six matching HTTP cases and twenty matching official CLI commands on both actual targets |
| Organization-scoped collection list/create/single access-details | Confirmed manager authorization, exact projections, opaque names/external IDs and reference validation | Six matching HTTP cases and nineteen matching official CLI commands on both actual servers; atomic local provider tests |
| Password grant with compact `authRequest` | Approved, unexpired, same-peer one-use access code; different login device allowed | Eight matching Rust HTTP cases on both actual servers; allocation-free service/provider, exact-deadline, rollback, replay and private-reopen host tests; unchanged CLI regression remains separate |
| `GET /api/accounts/keys`, `POST /api/accounts/keys`, `GET /api/users/<id>/public-key` | Owner-only private retrieval, initialization of an absent pair, authenticated cross-user public lookup | Borrowed core/provider contracts; Rust HTTP comparison group and SQLite rollback/reopen tests |
| `POST /api/accounts/api-key`, `POST /api/accounts/rotate-api-key` | Password-reauthenticated personal key retrieval, lazy creation, rotation | Core, HTTP comparison with upstream, rollback and restart tests; keys used by real CLI |
| Personal `client_credentials` at `POST /identity/connect/token` | `user.<id>`, exact `api` scope, access token without refresh token | Real CLI API login, password unlock and decryption; core and HTTP comparison with upstream |
| `POST /api/accounts/key-management/user-key-id` | Opaque one-time ID, current-device guards and atomic local persistence | Six matching HTTP cases and fifteen-command actual CLI migration comparison |
| Profile, revision date, sync | Personal account and opaque encrypted vault | CLI and HTTP |
| `PUT`/`POST /api/accounts/profile`, `PUT /api/accounts/avatar` | Exact profile names and nullable avatar colors with UTF-8 byte limits | Core/provider contracts, host rollback tests, and eight matching Rust HTTP cases on both servers; no CLI mutation claim |
| `GET`/`POST`/`PUT /api/settings/domains`, sync domains | Opaque ordered custom groups, signed exclusions, full flagged catalog for GET and filtered catalog for sync | Reusable borrowed views and typed projections, host rollback/isolation tests, eight matching Rust HTTP cases; no CLI domain mutation or settings request trace claim |
| `GET /api/devices/knowndevice`, `GET /api/devices`, `GET /api/devices/identifier/<id>` | Public exact header lookup, authenticated owner-only device projections, verified-login registry and refresh binding | Eight matching Rust HTTP cases against both servers; core/provider and host rollback/reopen tests; no CLI device-route trace claim |
| `POST`/`PUT /api/devices/identifier/<id>/token` and `/clear-token` | Bound-session token writes and disabled-relay public no-op clears, with empty 200 responses | Core/provider and host rollback/reopen tests; eight matching Rust HTTP cases and a separate private read-only stored-state probe on both servers; no CLI route attribution |
| `POST /api/auth-requests`, owner GET, base/pending list aliases | Public known-device creation, eleven-field projections, owner-only pending discovery and latest device pending metadata | Eight matching Rust HTTP cases on both servers; core/provider and host rollback/reopen/peer tests; no CLI auth-request route claim |
| `PUT /api/auth-requests/<id>`, public `GET /api/auth-requests/<id>/response` | Verified-session approval/rejection and exact code/type/IP response polling, without login consumption | Core/provider and host tests; eight matching HTTP cases on both actual servers; no new client-route claim |
| Folder CRUD and POST aliases | Opaque names, four-field responses, owner isolation, clear references without changing cipher revisions | CLI baseline; core/host tests and the focused HTTP comparison described below |
| Cipher CRUD | Opaque ciphertext and unknown JSON fields | CLI, HTTP, storage tests |
| `GET /api/ciphers/{id}`, `/details`, `/admin` | Same readable cipher, current-device/UUID guards and missing/foreign 400; admin name grants no bypass | Six matching Rust HTTP cases on both actual servers; core/provider tests and adapter-owned payload projection; no executed client alias or route trace claim |
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
and SSH-key items, plus optional opaque blob data. Its unit tests cover the
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

The 120-command baseline fixture uses PBKDF2. A separate twenty-six-command
comparison now verifies Argon2id password login, unlock and fresh-cache
decryption with iterations 3, memory 64 MiB and parallelism 4 on both servers.
Broader Argon2 account/configuration variants remain open. Browsers, extensions,
desktop and mobile are not covered by the CLI result. Full organization,
attachment, Send, notification and account-management compatibility remains on
the [roadmap](../ROADMAP.md).

The expanded local HTTP regression suite has passed all 61 tests. After the
missing-download-token status correction, the final nine focused attachment
checks also pass against the rebuilt adapter.
All 831 active workspace unit tests pass: 415 core, 297 host and 119 support,
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
personal API-key policy remains unchanged. Legacy unbound sessions keep existing
access behavior but cannot refresh without a current binding and device.
Password-method refresh now preserves valid earlier proofs and uses the retained
device's thirty/ninety-day lifetime. Refresh JWT encoding/`nbf` and broader
JWT/identity policy equivalence remain separate gaps.

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
current combined result appears below. SMTP, invite-JWT/emergency access,
signup/configuration policy, rate controls,
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

Refresh no longer consumes a valid proof. The password-method provider resolves
the current owner/device binding and permits earlier proofs until their original
deadlines or explicit revocation, while issued access retains its original
expiry. Issuing a new proof never extends an old proof's deadline. Cleanup keeps
the source thirty-second refresh leeway. The host uses private opaque handles,
not upstream refresh JWTs: JWT encoding, `nbf`, cross-server token acceptance and
SSO refresh are outside this supported contract. Mobile thirty/ninety-day policy
and exact leeway use host clock tests, not a real thirty-day expiry wait.
All eight focused direct HTTP cases pass against both actual servers: 268
counted requests each, including six password logins and 42 refresh POSTs
(22 successes, 15 invalid proofs, four missing/duplicate-proof guards and one
missing-grant form guard). Two fixture registrations are excluded. Account/vault
snapshots and real retained ciphertext decryption accompany owner/device
isolation and password/KDF/stamp revocation/recovery checks. The CLI baseline
remains separate lifecycle evidence without captured refresh requests.

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
authentication requests while replacing ordinary session authority. The existing public-key route and WebAuthn credential metadata support the
four-route previous-stamp policy; contacts and key rotation remain open.
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

The preceding password milestone passed all 104 local HTTP cases with 4499 tracked
requests across thirteen groups, including real authentication-request and
password-exception expiry. The unchanged official CLI 2026.10.0 baseline passes
all 120 commands against each actual server, separately from the focused KDF
and password CLI proofs.

## WebAuthn credential metadata

The core's fixed `WebAuthnCredentialsResponse` and provider-free
`get_webauthn_credentials` operation model the authenticated empty list returned
by pinned Vaultwarden main and release 1.37.4. The adapter supports existing
owned-device access and the existing password-change exception for logical
`get_api_webauthn`. Normal reads preserve account/vault state; an expired
historical bearer can trigger the inherited one-time exception cleanup.

All six selected Rust cases pass against the actual adapter and Vaultwarden
1.37.4: 129 counted HTTP requests each, eight identity requests (six successful
grants and two rejected refreshes), at most five per peer, and a real 121-second
exception wait. The two shared fixture registrations are excluded.
They add no CLI call or passkey/rotation claim: the pinned CLI rotation service
throws, while the current bundled SDK rotation uses combined key-rotation data.
Primary references and exclusions are recorded in the
[API parity notes](api-parity.md#webauthn-credential-metadata-subset). Current-bearer
device recreation, generic HEAD/OPTIONS behavior, JWT leeway, complete transport
errors and actual passkey operations remain unverified or unsupported.

## Personal vault purge

`POST /api/ciphers/purge` has an allocation-free proof/provider contract and a
personal-only adapter implementation. Exactly one existing password or
protected-action OTP proof is selected before mutation; the host supports the
password branch. Success removes the owner's active, trashed and archived
personal ciphers, all owned folders and removed-item attachments/capabilities,
then advances revision even for an empty vault. Credentials, keys, sessions,
devices, settings, auth requests and foreign vault state survive.

The local provider commits cleanup and revision atomically, stronger than the
sequential upstream failure behavior. Separate proof consumption does not gain
an automatic rollback guarantee. Recognized organization-query roots select
organization authorization and cannot silently purge the personal vault; that
organization operation remains unimplemented. All six selected Rust HTTP cases
pass against the actual adapter and Vaultwarden 1.37.4: 327 counted requests each,
six identity requests (five successful grants and one refresh), three auth-request
creations, three polls and eight successful purges. Two shared fixture
registrations are excluded; the single peer stays below unchanged reference
limits. The suite verifies empty active/trash/archive lists, foreign bytes and
authority preservation, and direct Rust decryption of a newly created post-purge
item. Fresh capability URLs return exact bytes before purge, then owned URLs
fail while foreign bytes remain available within a 30-second proof window.
Physical BLOB/grant/row deletion remains separate local SQL evidence. Source references and scope limits are recorded in the
[parity notes](api-parity.md#personal-vault-purge-subset); the existing CLI120
baseline adds no purge caller or route trace.

## Personal account deletion

The allocation-free core reuses the exclusive password/protected-action proof
request and exposes an opt-in `AccountDeletionStorage` provider. The adapter adds
both authenticated aliases, `DELETE /api/accounts` and `POST /api/accounts/delete`,
with empty 200 success. It deletes the supported personal account, vault bytes,
attachment capabilities and issued authority atomically; it preserves unrelated
accounts and instance signing state. Last-confirmed-organization-owner policy
belongs to trusted organization-aware providers, not body fields.

All six selected Rust HTTP cases pass against both actual servers: 257 counted
requests per target, six identity requests (three successful password logins,
two refresh attempts with one success, and one rejected old API grant), and
three excluded fixture registrations across two emails. Both aliases and their
guards match; prior authority stays revoked after same-email re-registration
with a fresh account ID and keys. Each deletion also verifies fresh owned
attachment URL revocation and foreign byte preservation within 30 seconds.
Local SQL tests separately prove physical cleanup, rollback and durable reopen.
Release 1.37.4 omits explicit auth-request cleanup present in the pin, so
portable fixtures avoid that versioned case.
A fresh official CLI 2026.10.0 regression passes all 120 commands against both
servers. The generated SDK API shape is documented, but neither that source
attribution nor the regression establishes an actual client account-deletion
flow or CLI-route trace. Account recovery, successful
protected-action OTP, organization/emergency-access and broader Send lifecycle variants, and complete
cross-version failure semantics remain open. See the
[parity notes](api-parity.md#personal-account-deletion-subset).

## Cipher read aliases

The ordinary cipher GET and new `/details` and `/admin` GET aliases share an
opt-in allocation-free read-authorization service. Each requires current bound
account authority before UUID validation, returns 400 for missing or inaccessible
ciphers, and permits owned active, trashed and archived records. The admin-named
path follows Vaultwarden's current ordinary-access TODO; no organization-admin
bypass is implemented. Stored opaque payload projection remains adapter-owned,
with no new typed cipher response and no read-induced revision changes.

All six selected Rust HTTP cases pass against the adapter and actual
Vaultwarden 1.37.4: 335 counted requests each, four successful password logins,
two excluded fixture registrations and 34 byte-exact attachment downloads. They
verify equivalent active/trash/archive projections, current-device and
previous-stamp guards, exact missing/foreign messages, ignored bodies/queries,
UUID spellings/decoding, reserved literal/method guards, and account/vault
snapshot preservation. Only attachment URL tokens are normalized.
The pinned TypeScript details helper has a notification-upsert caller, but neither a live notification
flow nor a real CLI execution of either alias has been established. The generated
SDK methods and baseline CLI regression remain separate evidence. See
[the parity notes](api-parity.md#ordinary-details-and-admin-cipher-reads) for
source/release references and narrower ownership/provider limits.

## Ordinary password identity core

Ordinary password login now has a borrowed request, opt-in provider and sealed
grant in the allocation-free core. The adapter applies the source's required
presence order, exact scope, Unicode username trimming/lowercase lookup and
unmodified proof. Empty client/device strings are accepted; device type parsing
retains fallback 14. Trusted providers check enabled state after a valid proof
and prepare subsequent policy/upgrade work before issuance. The host uses fixed
verifier parameters with no SMTP/2FA/SSO preparation; the generic hook is not
evidence that those policies or dynamic upgrades are implemented. Ordered form
roots follow first-value semantics for the required grant; repeated optional
fields become absent and fail the applicable presence guard. A single recognized
auth-request selector cannot fall back, while ambiguous duplicate selectors retain
the adapter's stricter rejection policy as an explicit gap.

All six focused cases pass against the adapter and actual Vaultwarden 1.37.4:
85 counted HTTP requests per target, 45 token POSTs, 39 authored pre-limiter
guards, six credential-flow attempts and two ordinary successes. One fixture
registration is excluded. The cases verify selected nine-field API errors,
required/scope ordering, raw proof, single aliases and optional-duplicate absence,
empty device/client inputs, token/profile/sync authority and preserved vault
state. Provider/local tests establish hidden enabled/policy/error/rollback
behavior separately; portable HTTP does not claim a disabled-account API.
The fresh official CLI 2026.10.0 regression passes all 120 commands against both
actual servers. It establishes real ordinary password login with client-side
decryption; no captured request trace or broader identity contract is inferred.
Refresh has its separate reusable, replay-preserving provider contract. Full
SMTP/2FA/SSO, optional form guards, transport and JWT/time variants remain open. See
[the parity notes](api-parity.md#ordinary-password-grant-core).

## Personal text Sends

Seven route patterns cover owner create/list/read/update/delete/remove-password
and recipient `POST /api/sends/access`; the existing identity route adds the
`send_access` grant. Personal sync contains owner Send records, including expired
or disabled records until separately purged. The reusable core has generic typed
owner/recipient/list responses and a semantic borrowed write view. It does not
parse arbitrary JSON, dates, HTTP headers or tokens inside `no_std`.

All six focused HTTP cases pass against both actual servers: 129 counted
requests each, with two successful password logins, 23 public Send-token grant
requests and 15 recipient accesses. Two fixture registrations are excluded.
The cases authenticate and decrypt real ciphertext, unwrap the Send seed under
the account key, check eighteen/eight-field projections, owner isolation,
password replacement/removal, issued-capability reuse, disabled/deadline/count
guards, hidden creator email and unchanged vault/keys/devices/foreign state.
The separate twenty-command official CLI comparison passes both actual servers; the unchanged
120-command baseline passes both servers and is separate evidence.
Its two negative receives require exit code 1 and exact public CLI JSON messages:
`Invalid password` for wrong proof and `Not found.` after deletion. Generic
server, rate or transport failures cannot satisfy these checks.

Send names, keys, notes and text remain encrypted opaque values. Upstream does
normalize projected text-object keys and remove an exact root `response` field;
accepted array/scalar roots project as null. Owner responses expose the server's
password verifier marker, not the submitted client proof. Recipient responses
exclude owner key, notes, password, counts and deletion date. Token minting does
not consume an access. Access rechecks availability and atomically increments
below the current limit. Failed count reservation can still advance owner
revision. Existing capabilities survive password changes but cannot bypass
current disabled/deadline/count/deletion state.

Local SQL tests separately cover mutation rollback, persisted signer/rows,
account-deletion cleanup and vault-purge preservation. They do not establish
identical upstream failure timing. The host signs Send JWTs with HS256 while
upstream uses RS256. File Send support is described below; email OTP, organization/configuration policies,
notifications, purge scheduling, rate/abuse controls and full transport/JWT
equivalence remain open. No captured request trace or full endpoint status is
claimed.

## Personal file Sends

Four more route patterns cover `POST /api/sends/file/v2`, multipart
`POST /api/sends/{id}/file/{file_id}`, scoped
`POST /api/sends/access/file/{file_id}` and capability-protected binary
`GET /api/sends/{id}/{file_id}?t=…`. Existing owner CRUD, list/sync, recipient
metadata and `send_access` now retain type-1 files. The static client upload-URL
renewal GET is not a registered Vaultwarden handler and is not implemented.

Both actual targets pass six selected Rust cases: 131 counted HTTP requests,
10 Send-token grants, nine multipart requests, 13 download-URL requests,
19 binary GETs and two password logins, excluding two registrations. They
verify authenticated decryption of arbitrary and empty plaintext files, exact
projections, immutable edits, upload failures/duplicate protection, current
availability/count checks and fresh-URL behavior before/after deletion. Local
unit tests separately prove scalar reservations, multipart first-field/root
semantics, physical BLOB cleanup, rollback and persisted signing authority.

The separate official CLI 2026.10.0 file selection passes all twenty commands on
both targets: create/upload, sync/cache metadata, edit, password removal and two
byte-exact anonymous receives. Fresh recipient stores and strict wrong-password
and deleted-resource messages exclude unrelated failure categories. These are
separate from text-Send20 and baseline120, with no captured request trace.

Declared length allows 525 MiB; multipart transport caps at 525,000,000 bytes.
The host's atomic SQLite cleanup is stronger than the upstream filesystem
sequence. Scoped URLs remain readable after disable/date/count changes while
bytes and token remain valid. No live TTL/maximum upload, configured quota,
organization/email policy, object storage, notification/rate/cron, Range/full
transport or RS256-equivalence claim is made. Full Send/API parity remains open.

## User-key-ID backfill

All six focused Rust HTTP cases pass against both the adapter and Vaultwarden
`1.37.4`: 168 counted requests, three password logins and three refreshes per
target, excluding three registrations. They check opaque empty/long/Unicode/NUL
and positional initialization, current authentication before schema guards,
raw UTF-8 rejection, ignored Content-Type, exact empty 200 and repeated 422
`Unexpected data`, account revision, owner isolation, keys, sessions and vault
preservation. Key-ID observations use `sync.userDecryption.userKeyId`.

The separate fifteen-command official CLI 2026.10.0 migration comparison passes
both targets: absent sync metadata becomes a stable SDK-generated ID, and a
retained note decrypts after login, unlock and fresh-cache login. Sixteen direct
HTTP requests include one fixture login; two additional logins are CLI commands.
It is separate from baseline120 and adds no command-form or captured-route
claim. Local SQL tests separately establish atomic one-time assignment and
rollback/reopen; upstream's separate check/save is weaker. Full key rotation,
all account variants, complete token projections and transport-limit parity
(16,777,216 versus 20,000,000 bytes) remain open.

## Prelogin discovery

The reusable core models public KDF discovery with opaque canonical email input,
signed known settings and bounded deterministic unknown selection. Its complete
six-field response keeps legacy/nested settings identical and salt null. Both
identity routes share it; the legacy `/api` alias remains a local extension.
All six direct HTTP cases pass against both actual targets: 79 counted requests,
27 decoded prelogins and two password logins, excluding two explicit modern
registration fixtures. The separate twenty-six-command official CLI `2026.10.0`
comparison also passes both: three CLI password logins, two direct prelogin HTTP
requests, no direct password login, and two modern fixtures. Both PBKDF2 and
Argon2 notes decrypt after login and unlock; Argon2 also passes fresh-cache
login/sync/decryption. These results add no captured route, unknown-distribution,
registration-command or full-policy claim.

The host uses a private persisted random selection key instead of deriving one
from RSA PEM bytes. It returns backend errors rather than unknown-account
fallback and does not implement the reference public limiter. The 16-MiB versus
decimal 20,000,000-byte JSON limit and complete identity/configuration policies
remain open.

## Organization owner creation and discovery

The bounded slice adds `POST /api/organizations`, owner
`GET /api/organizations/{id}` and authenticated `GET /api/collections`, plus
membership/profile and initial sync-collection projections. The pinned and
release 1.37.4 handlers and model projections agree. Organization private keys
are not returned by public discovery; the authenticated membership retains its
opaque wrapped organization key. Current device/stamp and confirmed-owner
checks remain authoritative, and account deletion must refuse a last confirmed
owner before cleanup.

The local provider makes creation, membership, initial collection and revision
atomic, strengthening upstream's sequential saves. It supports the default
creation policy, not configuration management, arbitrary member roles,
invitations, organization/collection administration or shared ciphers. Event,
group and SMTP-dependent flags describe source configuration; they are not
evidence that those features work here. JSON/body-limit, cross-cutting errors,
notifications and complete failure/transport behavior remain partial. All six
HTTP cases pass both actual targets: 137 counted requests, two password logins,
two refreshes and two organization creates, excluding two modern fixtures. Both
account-deletion aliases reject a last confirmed owner without changing complete
sync/revision state; existing access and refresh authority remain usable. The
separate official CLI `2026.10.0` comparison passes nineteen commands on
both servers, including decrypted collections after login, unlock and fresh-cache
login and retained personal-note decryption. It records two CLI logins, one
direct setup login and thirteen direct HTTP requests, excluding one fixture;
client internals are not counted or traced. Organization creation uses direct
HTTP, and CLI list operations consume synced cache. That owner-discovery runner
does not exercise the organization-scoped endpoints covered separately below. No route
trace or full-parity status is claimed. A route correction now preserves raw
segments before authentication/UUID guards; dotted/percent-path probes pass in
the expanded 137-request comparison.

## Organization-scoped collections

The selected routes are `GET`/`POST /api/organizations/{id}/collections` and
`GET /api/organizations/{id}/collections/{collectionId}/details`. Their confirmed
manager guards preserve raw IDs, query fallback and current device authority;
the single read checks actual collection manageability before handler association.
Creation accepts opaque names and external IDs, validates all group IDs before
membership IDs, and returns ten fields. Empty external IDs become null while
whitespace remains exact. Organization lists use seven-field records; single
access-details uses thirteen, including assigned/users/groups without the
aggregate endpoint's `unmanaged` field.

The host persists supported direct ACLs and affected revisions atomically, a
stronger failure boundary than upstream sequential saves. Its public fixture
scope is owner/full-access membership; imported role/grant behavior uses local
provider tests. There is no group/member lifecycle, bulk/aggregate collection
administration, sharing, notifications or full configured policy support. All six HTTP cases
pass both actual servers: 194 counted requests, two password logins and two
refreshes, excluding two modern fixtures/four registration requests. They create
five collections and preserve full membership arrays and foreign/other-owned
organization collection baselines alongside personal vault/session checks.

The separate official CLI `2026.10.0` comparison passes nineteen commands on both,
including production organization-collection list/create/get, decrypted names
and fresh-cache recovery. It counts fourteen direct HTTP requests, two CLI logins
and one direct setup login, excluding one registration/two requests. Client
internals are uncounted and no trace is captured. Imported role/ACL behavior
remains separately tested provider evidence; these results do not imply a full
membership lifecycle, general sharing or complete organization parity.

## Single organization-collection mutations

The selected `PUT`/`DELETE /api/organizations/{orgId}/collections/{collectionId}`
contracts reuse strict manager and current-device guards. Update replaces name
and all supported grants, preserves the ID, validates groups before membership
IDs, and clears omitted/null/Unicode-whitespace-only external IDs. It returns
ten-field `collectionDetails`. DELETE ignores its body and returns empty 200;
missing, foreign or previously deleted IDs fail the manager guard. There are no
POST aliases. The [protocol references](protocol.md#organization-collection-replacement-and-deletion)
record source ordering and the distinct bulk contracts.

The host transaction preserves personal and foreign vault state and advances old
and new affected account revisions. Local SQL tests separately prove rollback,
removed/new grantee revisions, an imported Manager's successful self-removal,
and deletion of seeded collection/cipher links without changing cipher
revisions or attachment bytes. Public fixture accounts remain confirmed
Owner/full-access memberships. These tests do not establish membership
administration, sharing or imported-role sync parity.

All six authored HTTP cases pass both actual targets: 229 counted requests,
two password logins and two refreshes, excluding two modern fixtures/four
registration requests. Eight updates and one deletion preserve complete
membership, sibling and foreign organization baselines and personal authority.
The separate official CLI `2026.10.0` comparison passes twenty commands on both
actual targets. It calls production edit/delete, checks independently
authenticated ciphertext, fresh-cache decryption and live/synced absence after
deletion. Fifteen direct HTTP requests include one setup password login; two
other logins are CLI commands, excluding one registration/two requests.
Client-internal requests are not counted or traced. Full collection, bulk,
policy, notification and transport parity remain open.

## Organization member discovery

The list-only milestone below precedes the expanded [member-detail proof](protocol.md#organization-member-detail).

`GET /api/organizations/{orgId}/users` lists actual joined account and membership
metadata under current-device, confirmed-manager and full-access guards. The
response has nineteen explicit fields per member, not an empty placeholder or
profile-organization projection. It excludes account/organization keys and
preserves nullable name, status/type mappings, permissions and optional direct
collection/group metadata. Read operations leave revisions and authority intact.
The [source protocol](protocol.md#organization-member-discovery) distinguishes
optional-boolean query behavior from ordinary required Boolean guards.

All six HTTP cases pass both actual targets: 190 counted requests, two password
logins and two refreshes, excluding two modern fixtures/four registration
requests. They check real membership identities, exact projections, empty and
Unicode profile names/avatar freshness, foreign/other-owned organizations and
preserved vault/revision/authority state. The separate official CLI `2026.10.0`
comparison passes sixteen commands on both, including fresh member names without
an intervening sync and fresh-cache recovery. Seventeen direct HTTP requests
include one fixture login; two additional logins are CLI commands, excluding
one modern registration/two requests. Client internals are uncounted and no
route trace is captured. That historical comparison used Owner/full-access memberships; the invitation
extension below adds real Invited and Accepted recipients. Other imported
status/role/ACL projections retain separate local provider evidence. Owner/full-access always suppresses direct
collections and the host has no group rows; the HTTP query matrix cannot by
itself distinguish Boolean decoding. Parser/provider tests establish those
branches. No invitations, arbitrary member changes, group lifecycle, sharing or
full organization/configuration parity is claimed.

## Organization member detail

`GET /api/organizations/{orgId}/users/{memberId}` adds scoped individual
discovery with confirmed Owner/Admin admission. It returns the same nineteen
explicit member fields directly, preserves account/vault/organization state
during successful current-authority reads and distinguishes neither valid
missing nor foreign membership IDs: both return 400 with the source message.
Current-device, raw path, UUID and optional-query guards remain separate from
member state. The source and release agree; see [the protocol
details](protocol.md#organization-member-detail).

The historical member-list milestone passed six cases/190 counted HTTP
requests and a separate sixteen-command official CLI comparison on both actual
targets. The expanded six-case comparison passes both targets with 240 counted
requests, two password logins and two refreshes, excluding two modern
fixtures/four registration requests. The separate eighteen-command official
CLI comparison also passes both, with eighteen direct HTTP requests, two CLI
password logins and one direct setup login, excluding one registration/two
requests. Two strict exit-one JSON checks require
`Error: User is already confirmed.` for the current confirmed Owner after the
production detail GET and before any public-key lookup or confirmation POST.
It does not claim a successful member lifecycle, endpoint trace, general
policy/group support or complete transport/error parity.

## Default no-SMTP organization invitations

`POST /api/organizations/{orgId}/users/invite` creates actual recipient state:
registered accounts become Accepted; unknown accounts receive passwordless
placeholders, pending email markers and Invited memberships. Modern
registration initializes the same UUID and accepts all its pending memberships
across organizations. Ordered batches retain their successful prefix on later
failure. Local per-recipient mutation and registration completion are atomic;
upstream saves their components sequentially. See the [source
contract](protocol.md#organization-invitations-and-placeholder-registration).

Both actual targets pass all six HTTP cases with 211 counted requests plus
eight modern registration requests, three password attempts (two successful,
one rejected placeholder) and two refreshes. The separate twenty-four-command
official CLI 2026.10.0 comparison also passes both targets, with sixteen
direct HTTP requests plus four registration requests, three CLI password
attempts and one direct attempt. Separate fresh reference processes retain
unchanged limits. The client exercises owner listing and completed-invitee
personal-vault login/decryption, not an invitation or registration command,
confirmation, organization-key delivery or request trace. SMTP, invite JWTs,
policy/group administration and sharing remain open.

## Single organization-member confirmation

The supported single POST confirms an Accepted member, preserving their
membership ID and grants while changing the wrapped organization key, status
and recipient revision. Owner/Admin authorization, hierarchy and scoped
missing/foreign errors match the pinned contract; keys remain opaque.
Confirmed recipients read only visible collection projections, including
stored restrictions in sync. Ordinary Users do not gain organization
administration or collection manage authority.

Both actual targets pass all six HTTP cases: 213 counted requests plus eight
registration requests for four fixtures, two password logins and two
refreshes. Both also pass the separate official CLI 2026.10.0 comparison:
23 commands, 32 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins. Actual confirmation delivers
the RSA-wrapped organization key; assigned collection names decrypt after
recipient login, unlock and fresh-cache login, while unassigned collections
remain absent. Direct setup, cached reads and client-internal traffic remain
distinct, without a captured route trace.

The historical already-confirmed CLI rejections and invitation-only results
remain separate milestones. Bulk confirmation, SMTP, policy/group lifecycle,
cipher sharing and complete failure/transport variants remain open.

## Bulk organization-member confirmation

The bulk route has a typed ordered list response and shares the single-member
confirmation guards and transition. Missing/null keys return an empty list.
Per-item failures continue, while a missing ID aborts with committed prefix
retained and no partial response. A schema error anywhere in the body rejects
before writes. Raw string IDs and opaque keys retain their exact values.

Both actual targets pass six HTTP cases with 211 counted requests plus ten
registration requests for five fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 21 commands on
both, with 33 direct HTTP requests plus four registration requests, three CLI
password logins and two direct setup logins. Recipient assigned collection
names decrypt after login, unlock and fresh-cache login; unassigned rows stay
absent. Bulk confirmation is HTTP setup, not a CLI bulk caller. Internal
client traffic remains uncounted and untraced.

Complete error/backend/configuration parity, SMTP, sharing and remaining
member/group administration remain open.

## Single organization-member removal

The single DELETE removes a scoped membership and its direct collection
grants with current-device Owner/Admin authority, hierarchy and last-owner
protection. It accepts no body authority and returns empty 200. The account
and access/refresh/device authority survive, while subsequent profile/sync
reads lose the removed membership. Reinvitation can create a new membership
under the same account without restoring old unselected grants.

Both actual targets pass six focused HTTP cases: 212 counted requests plus
eight registration requests for four fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 25 commands
on both, with 40 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins. Recipient sync and
fresh-cache reads lose primary membership while retained sibling and personal
data decrypts. Private marker state remains local SQL evidence.

The shipped CLI has no member-delete command. Removal does not rotate the
organization key or erase offline cached data. Local atomic
rollback, marker-failure handling and one revision update strengthen/differ
from upstream sequential cleanup and two revision saves. Bulk removal uses
a separate contract; SMTP/groups/notifications, sharing and full
failure/transport parity remain open.

## Bulk organization-member removal

The bulk DELETE shares the single-member hierarchy, last-owner protection,
scoped cleanup and retained account authority. It requires a fully decoded
`ids` array and emits ordered three-field result rows inside a three-field
list. Raw IDs and duplicates are preserved; domain errors remain per-item and
earlier commits survive. Malformed whole bodies reject before all writes.

A sealed request context supports continuation after its own actor's
successful self-removal. A new request must authorize again. Local rejection
of unrelated stale authority, atomic per-item rollback, private marker-error
handling and recipient revision updates differ from upstream's cached role
and sequential cleanup; these are qualified provider guarantees.

Both actual targets pass six focused HTTP cases: 251 counted requests plus
eight registration requests for four fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 25 commands
on both, with 40 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins.

HTTP mutation is setup: the shipped CLI has no member-removal command, and no
endpoint trace or offline-key erasure is claimed. SMTP, groups,
notifications, organization sharing and full configuration/failure/transport
parity remain open.

## Single organization-member revoke and restore

Three bodyless PUT patterns cover revoke plus legacy/vnext restore through an
allocation-free scoped status provider. They preserve account authority,
membership identity and encrypted keys/grants while hiding and recovering
live selective collection access. Admin peer changes and the source's
unconfirmed-Owner count safeguard are distinct from member deletion rules.

Both actual targets pass six focused HTTP cases: 265 counted requests plus
ten registration requests for five fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 31 commands
on both, with 43 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins.

The CLI observes direct HTTP mutations; it has no member revoke/restore command.
One strict revoked-confirmation rejection is a metadata check, not successful
confirmation or a mutation caller. Invited no-op revision advancement is proved
by source/local SQL tests, not inferred from portable HTTP status. No trace,
offline erasure, new command form or combined baseline total is claimed.
Default-policy behavior excludes configured 2FA enrollment/SingleOrg effects,
SMTP, events/groups, bulk status changes and shared-cipher writes. Atomic local
revision/status and live commit checks strengthen source failure/concurrency
timing without claiming complete parity.


## Bulk organization-member revoke and restore

Two PUT routes reuse the allocation-free status rules with caller-owned
ordered inputs and result slots. Revoke permits absent/null IDs; restore
requires the array. Exact opaque IDs and duplicates survive. Each result is
independent: earlier successes persist and later rows run after failures.

Both actual targets pass six focused HTTP cases: 286 counted requests plus
ten registration requests for five fixtures, two password logins and two
refreshes. Shared client code constructs these routes; the CLI has no bulk
status mutation command. The suite verifies exact list/row projections,
whole-body rejection, guard ordering and retained personal/sibling/account
and encrypted membership state.

Local SQL failure injection proves successful-prefix persistence and
per-item status/revision rollback. Live provider checks and atomic writes
strengthen upstream timing, and backend diagnostics are safely mapped.
Configured policies, SMTP/events/groups and full failure/transport parity
remain open.

The separate official CLI 2026.10.0 comparison passes 31 commands on both
actual targets: 43 direct HTTP requests plus four registration requests,
three CLI password logins and two direct setup logins. After HTTP bulk setup,
sync and fresh-cache reads verify primary visibility loss/recovery with
retained personal/sibling decryption. One strict revoked-confirmation
rejection observes metadata. No CLI bulk mutation caller, captured route
trace or successful member confirmation is inferred.

## Pinned web-client smoke

A real Chromium browser now exercises the Vaultwarden-distributed Bitwarden Web
2026.7.0 client against no-warden and Vaultwarden 1.37.4. Both pass password
login, the browser's authenticated initial sync and profile retrieval. Captured
method/path/status counts distinguish actual browser calls from HTTP fixture
registration. The isolated runner emits no tokens, headers, query values,
response bodies, console output or decrypted payloads.

Both also pass vault navigation, Lock now, password unlock with a second
token/sync, and browser reload returning to the lock view. The reference's
extension-onboarding and welcome-tour dialogs are dismissed through their
ordinary Skip controls. Both create a login item through the UI, read its
decrypted username/password, edit it, decrypt the persisted edit after unlock,
and move it to trash. The adapter's single-cipher trash response now matches the
reference's empty200 response; a tightened existing Rust fixture catches the
previous204. Other item types, restore/permanent-delete UI, notification
WebSockets and the wider web interface remain open. This is not evidence for the unmodified official Web
artifact or complete API parity.

The [portable setup](../tools/web-compat/README.md) verifies the immutable image,
all image blobs, official Chromium 149.0.7827.55 archive and executable, and three
web bootstrap bundles. Playwright-core 1.64.1 is locked separately. A dedicated
Linux x64 CI job runs the same disposable HTTPS comparison. Fresh anonymous
image acquisition and the supplied-cache path both pass locally; inherited
browser/HTTP debug modes are suppressed before credentials are created.

## Organization member bulk public-key lookup

The scoped public-key POST requires confirmed Owner/Admin authority and a
canonical required `ids` string list. Its three-field list contains ordered,
duplicate-preserving four-field `organizationUserPublicKeyResponseModel` rows:
membership `id`, account `userId`, nullable `key`, and `object`. Missing scoped
memberships are omitted; an existing null-key account retains its explicit null
row. Empty and synthetic future-format keys remain exact. An actual 1025-item
batch passes. The Linux host separately limits requests to 4,096 IDs while
decoding, before allocating results or running member-key lookups. Its 422
rejection beyond that local work budget is not claimed as upstream behavior;
the allocation-free core itself has no intrinsic batch count cap. A scoped
length-only SQL preflight additionally charges every duplicate and UTF-8
ID/key byte plus 128 bytes per matched row against 8 MiB of unescaped result
material, rejecting 422 before owned key snapshots. Escaping can expand JSON
bytes; this host memory policy is not an upstream byte-limit claim or an exact
encoded-response cap.

The actual matrix includes all four known target statuses and Owner/Admin/
Manager/User roles. Accepted Admin, confirmed Manager/User and revoked Admin
actors remain denied; eligible Owners/Admins can read revoked targets. Portable
registration with `keys: null` establishes nullable-key behavior without SQL
bypasses, while the individual public-key GET returns 404 for that null key.
Whole-body/path/authentication/schema guards and read snapshots preserve account,
vault, key, revision, membership, grant, organization and session state.

Both no-warden and Vaultwarden 1.37.4 pass six focused HTTP cases: 431 counted
requests plus ten registration requests for five fixtures, two password logins
and two refreshes. A separate official CLI 2026.10.0 comparison passes 16 commands
on each, with 32 direct HTTP requests plus four registration requests, two CLI
password logins and two direct setup logins. It checks bulk/individual/registered
key equality, three cached/remote fingerprint equalities and distinct accounts,
then decrypts a personal note and recipient organization collection.

The CLI uses cached or individual public-key lookups; this is observation of
compatible key material, not a CLI bulk caller or an endpoint trace. The web
2026.7.0 bulk-confirm caller is static source-map evidence, not an executed
browser flow for this POST. Pinned server/client revisions and the allocation-
free provider/snapshot boundary are detailed in
[API parity notes](api-parity.md#organization-member-bulk-public-key-lookup-subset).
The source pin and runtime release remain distinct; focused totals are not
combined with the 120-command baseline.

Core and linked no-allocator consumers preserve the missing-account/null-key
distinction without HTTP/SQL/crypto dependencies. Safe provider errors and
association checks have local evidence, not complete upstream backend timing
parity. Configured policies/groups/SMTP, automatic confirmation, dangling-account
HTTP and imported unknown states, full transport/error variants and general
sharing remain open. This handler remains partial.
