# Architecture

On Unix, the standalone host creates its SQLite database with owner-only
permissions before opening it. Startup also restricts existing database, WAL,
shared-memory, and rollback-journal files. Filesystem providers remain outside
the allocation-free core.

The standalone host caps ordinary encoded HTTP bodies at 16 MiB; file-Send
multipart uploads use the upstream decimal 525,000,000-byte cap. Encrypted-field validation normally caps decoded values at 1 MiB; the larger
transport budget accommodates JSON escaping and request metadata. Folder CRUD
uses the explicit opaque-name policy described below. Oversized requests fail
before dispatch.

`no-warden` is the reusable protocol and business-rules crate. It borrows input
strings, models wire data without an allocator, classifies routes, validates
supported payloads, and applies ownership and lifecycle rules through storage
traits. It has no HTTP, database, filesystem, RNG, clock, or crypto implementation.

Adapters authenticate requests and supply identities to the core. A trusted
identity must come from verified session credentials, never from request JSON.
Storage adapters must enforce atomicity where business operations require it.
They retain the typed encrypted payload without decrypting it. Applications that
accept additional wire fields must retain those fields alongside the typed
request; Serde does not preserve unknown fields in the borrowed core models.

Requests retain the wrapped per-cipher `key`, `encryptedFor`, and the opaque
`encryptedByKeyId`. Creates consult `Storage::user_key_id` when the provider
knows an account's current key ID and reject a different supplied ID. The
default provider returns no current ID; embeddings that support key-ID
migration must override it. Ownership comes from the authenticated caller.

Folder CRUD keeps the existing strict `FolderRequest` API and adds borrowed
`FolderWriteRequest` decoding for an optional, untrusted body ID.
`FolderNamePolicy::Encrypted` remains the default for existing service calls and
imports. The standalone adapter uses `create_folder_with_policy` and
`update_folder_with_policy` with `FolderNamePolicy::Opaque` to preserve upstream
names verbatim, including empty strings and future encrypted formats. Transport
and storage limits apply at the adapter boundary. Ownership and generated/route
IDs retain their authority under either policy.

The HTTP adapter decodes folder bodies through an owned Serde guard before
retaining their JSON, preserving escaped strings and duplicate-field errors.
Only `id`, `name`, `revisionDate`, and `object` enter folder responses; unknown
stored extensions stay private. Folder deletion clears owned cipher links and
advances the account revision while retaining cipher revisions, archive state,
encrypted fields, and attachment bytes. The SQLite provider commits these
changes atomically.

Personal import has a configurable allocation-free decoder,
`ImportRequest<'a, F, C, R>`, whose folder, cipher, and relationship capacities
come from the embedding application. These capacities are not protocol batch
limits. Hosts can instead lend their own slices through `ImportView` and the
indexed `ImportData` contract; the entries and counts must stay unchanged
through validation and persistence. The core validates the complete batch before
calling an opt-in `ImportStorage` provider. `ImportPolicy` separately controls
the encrypted-note limit, which defaults to 10,000 bytes.

Import providers resolve supplied folder IDs against an owned-folder snapshot
taken under the operation's lock or transaction. An existing owned folder is
reused without renaming it; missing, unknown, or foreign IDs produce fresh
folders. Every cipher gets a fresh ID. `folderRelationships` maps cipher indexes
to folder indexes and replaces incoming `folderId` values. Duplicate cipher
indexes use the last relationship, an invalid folder index clears the mapping,
and relationships for nonexistent ciphers are ignored. Providers can call
`ValidatedImport::fill_folder_mapping` with caller-owned storage to resolve the
whole batch in O(ciphers + relationships) time without allocation. An undersized
mapping buffer fails before changing it.

`ImportStorage` must commit all folders, ciphers, and the account revision
together, leaving the entire batch unchanged on failure and publishing
notifications only after commit. It preserves ciphertext and key metadata while
discarding imported identities and stale revision preconditions. This atomic
contract and the core's owner/current-key validation are stronger than the
pinned Vaultwarden import handler's sequential writes. Existing `Storage`
implementations do not gain an import operation unless they implement this
additional contract.

Bulk cipher lifecycle requests use `CipherIdsRequest<'a, N>` or a borrowed ID
iterator. `VaultService::bulk_ciphers` takes a `CipherBulkOperation` and
caller-owned ID scratch sized for the raw input, including duplicates. It sorts
and deduplicates exact strings in O(N log N) time without allocation, then returns
the unique count. `CipherBulkStorage::cipher_access` distinguishes read access
for archive/unarchive from write access for trash, restore, and delete. Its
default implementation permits only personal ownership; providers can override
it to model broader permissions.

An opt-in `CipherBulkStorage` provider receives a `ValidatedCipherBulk` plan and
commits it under one lock or transaction, rechecking access before mutation.
A failure must preserve all selected items and the account revision. This
guarantee is stronger than Vaultwarden's sequential bulk helpers, which may
retain writes made before an error. Admin-named aliases apply the same access
rules and grant no additional permission. Existing storage adapters do not
support bulk lifecycle operations until they implement this provider contract.

Trash and restore update each affected cipher's revision; permanent deletion
also accepts an active item. Archive and unarchive change per-user archive
metadata and the account revision while preserving the cipher revision.
Archiving preserves trash state, and restoring from trash preserves archive
state. Repeating an action does not require an opposite starting state; an empty
bulk request succeeds without changing stored revisions. Providers publish
notifications after a successful commit; the standalone adapter does not yet
implement the upstream websocket or push transport.

The host stores archive state as per-owner annotations separate from the cipher
document. Ordinary cipher create/update synchronizes that state from
`archivedDate`, matching the pinned upstream helper: absent or null unarchives,
a valid timestamp sets the supplied date, and an invalid timestamp leaves the
annotation unchanged. Unlike an archive action, ordinary CRUD also updates the
cipher revision.

Legacy field-level ciphers and opaque blob ciphers have separate validation
paths. A blob request stores `data` and can omit the legacy name and type-specific
object. The blob is an escaped JSON string, requiring a decoder scratch buffer
when it cannot be borrowed directly from the incoming JSON. Type-7 EncStrings
are opaque base64 COSE envelopes; validation checks their outer encoding without
interpreting COSE or performing cryptography. Login models also retain bounded
encrypted FIDO2 credential records; this does not implement passkey login.

Collection capacities are explicit: 32 login URIs, 64 custom fields, 32 password
history entries, 16 stored FIDO2 credentials, and 64 clone collection IDs. Excess
elements produce an error, never a truncated vault item. The personal clone
wrapper requires empty collection IDs because organization operations are
outside the service's current scope.

The standalone Rust server provides a local SQLite implementation and the
transport and cryptographic host services required to exercise real clients.
Allocations in this host do not change the core's allocation-free contract.

The opt-in `AttachmentStorage` provider separates metadata and lifecycle
decisions from multipart parsing, encrypted byte transport, storage, randomness,
clocks, and download-token verification. Read access permits attachment metadata retrieval;
uploads, replacement, deletion, and metadata updates require write access.
The default provider scope is personal ownership; embeddings can supply broader
read/write permissions. Admin-named aliases grant no additional access.
Encrypted file names, wrapped keys, and file contents remain opaque.
`VaultService` exposes reservation, upload, legacy creation/replacement, deletion,
read authorization, and metadata-update operations through `ValidatedAttachment`
plans. The host stages the encrypted bytes before the provider commits a plan;
the core neither parses multipart bodies nor owns a byte buffer.

`AttachmentRequest` borrows the reservation's filename and key. Its size decoder
accepts integers or strings and requires Serde's `deserialize_any`; `serde-json-core` 0.6
consumers must use a suitable typed decoding adapter or construct the request
directly. This restriction does not require allocation in the core. The
bare-metal consumer constructs the request and serializes `AttachmentResponse`
and `AttachmentUploadResponse` into caller-owned output buffers; that does not
establish decoder support for the size union.

The v2 flow first reserves metadata, then uploads the encrypted bytes. A pending
reservation appears in cipher responses before the bytes exist. Reservation
does not change account or cipher revisions; successful upload and deletion
advance the account revision while preserving the cipher revision. Uploads accept
an inclusive one-MiB difference from the declared size and record the measured
size. A larger mismatch discards the reservation and any stored bytes. Legacy
multipart uploads require an encrypted filename and key; legacy replacement
creates a fresh attachment ID. The SQLite adapter commits metadata, BLOB contents,
cleanup, and required revision changes together, a stronger guarantee than the
upstream filesystem sequence. This guarantee covers the stored mutation;
subsequent response or download-capability generation can fail after commit and
return an error without reverting it, as in the upstream response path. Hard
cipher deletion also removes attachments; trash and archive retain them.

Cipher responses rebuild attachment lists from authoritative records rather
than trusting an incoming `attachments` array. Ordinary `attachments2` metadata
updates preserve file contents: missing IDs are skipped and an ID belonging to
another cipher stops processing. The host applies these map rules; the core's
`update_attachment_metadata` handles a single strict update. The core does not
choose a map iteration order. Providers retain the surrounding cipher update's
transaction requirements.

Download URLs carry a 60-second capability bound to both cipher and attachment
IDs. The host stores its digest and expiry and serves bytes without requiring a
session bearer. Its expiry is strict; upstream uses a signed JWT with a 60-second
lifetime and a further 30-second validation leeway. A missing token query returns
422; an invalid supplied token or missing file returns 404. Filename metadata
never selects a filesystem path. The core's declared-size ceiling is 525 MiB
(550,502,400 bytes); the host's 16-MiB encoded-request cap also applies to
multipart uploads. These are separate from upstream's 525,000,000-byte multipart
file limit. Quota configuration and remote object-storage policies require
additional adapter work.

The host decodes JSON into owned values, then borrows the decoded strings for
core validation. That accepts ordinary JSON escape sequences without requiring
allocation in the core. It keeps unknown encrypted fields when saving items.
HTTP regressions verify escaped blob strings and complete stored FIDO2 records
through create, update, and sync. These tests check payload preservation;
real-client blob decryption and authenticator use remain unverified.

SQLite transactions commit each mutation and its vault revision together.
The personal import adapter uses one transaction for the complete batch,
including folder resolution and fresh server-owned metadata. Rollback tests
cover import failures after earlier writes and verify that folders, ciphers,
and the account revision remain unchanged.
Revisions advance monotonically even when updates share a millisecond or the
wall clock moves backwards. Conditional cipher updates check the client's last
known revision while holding the same storage lock. Other providers can override
`Storage::map_error` to report a known conflict as `ErrorKind::Conflict` (HTTP
409), while retaining generic errors for unexpected storage failures. They must
check revisions atomically with the write. Access tokens are signed JWTs with a
random token ID, and refresh tokens contain random bytes. The host stores their
SHA-256 digests and checks expiry. Password-method refresh issues another pair
without consuming earlier valid proofs or extending their original deadlines. The
server stores an Argon2 verifier of the client-derived authentication hash,
and never receives the master password or decrypted vault contents.

Personal API-key management has an opt-in `IdentityStorage` provider contract.
`PasswordOrOtpRequest` borrows a master-password authentication hash or a
protected-action OTP; exactly one proof is required. `VaultService::get_api_key`
and `rotate_api_key` select a typed `ReauthenticationProof` and ask the provider
to verify it before retrieving, creating, or rotating a key. The hash is the same
client-derived server authorization value used by password login. The OTP branch
delegates protected-action verification and consumption to the provider; it does
not interpret the value as a two-factor TOTP. The standalone host supports the
password proof and rejects the unsupported OTP branch.

The key provider supplies secure randomness, confidential recoverable storage,
and account revisions. Repeated retrieval must return the existing secret and
revision; first creation and rotation commit a new key and revision together.
The borrowed `Secret` wrapper has redacted `Debug` output and no `Display`,
`Serialize`, `Clone`, or `Copy` implementation. `ApiKeyResponse` serializes the
key explicitly as the intentional disclosure boundary. The embedding application
owns and clears input buffers; the borrowed wrapper cannot erase them. The host
keeps the recoverable key in its private SQLite database and an Argon2 verifier
for credential checks. It excludes that secret from profile and sync data.
The core performs no RNG, hashing, database access, or token signing.

The borrowed `ClientCredentialsRequest` models the personal `user.<account-id>`
identity, secret, exact `api` scope, and required device fields. The provider
authenticates the secret before `VaultService::authenticate_api_key` returns an
`AuthorizedApiKeyGrant`. A transport then issues its two-hour access token. This
grant has no refresh token or offline-access scope: renewal repeats
`client_credentials`.
Rotating an API key changes future credential checks while existing access
tokens and password-grant refresh tokens retain their original authority.

API-key authentication does not decrypt the vault. The shipped CLI uses its
TypeScript API-key login strategy and then, for password accounts, a separate
unlock command that initializes SDK cryptography with the account's encrypted
keys and KDF metadata. Organization credentials, passwordless/KeyConnector
accounts, login rate controls, and device notification policies require further
provider and transport work.

An embedded consumer can provide fixed-capacity storage and serialize responses
into a caller-owned buffer. Feature unification in an embedding application must
not accidentally enable `serde`'s `std` or `alloc` features for the core target.
CI separately compiles the core for a target without an operating system.

Account encryption-key reads and initialization use the opt-in `AccountKeyStorage`
provider. It borrows opaque state from the host; the core checks pair presence and
authenticated identity without interpreting cryptographic material. Public-key
lookup intentionally permits authenticated cross-user access, while private-key
reads always use the authenticated account. Initialization preserves existing key
material, changes only a completely absent pair, and commits with the account
revision. Key response types have explicit serialization boundaries and redacted
Debug output. The standalone adapter holds its storage lock across service checks
and the atomic SQLite write; no persistence or clock enters the core.

Profile metadata has a separate opt-in `AccountProfileStorage` provider with
`update_profile_name` and `update_avatar_color` hooks. The borrowed
`ProfileUpdateRequest` and `AvatarUpdateRequest` retain exact strings without
normalization. `VaultService::update_profile` and `update_avatar` require verified
identity and validate before calling the provider. Names may contain empty,
whitespace, control, or Unicode values up to 50 UTF-8 bytes. A present avatar color
must contain exactly seven UTF-8 bytes; no hexadecimal or `#` check is imposed.
Omitted/null object fields and positional `[null]` clear the avatar, while an
empty positional array is invalid. Registration validation remains separate.

Each successful metadata write changes only its field and the account revision,
including repeated values or clears. The provider must roll back both on failure
and preserve keys, password/API credentials, security stamps, sessions, vault
records, and foreign state. The standalone adapter implements this with its
existing mutex and one SQLite transaction. These core methods return `()`;
complete profile responses stay in the adapter builder. That builder emits the
persisted name directly, including an empty string. The bare-metal JSON consumer
parses and serializes both request models into caller-owned buffers; it does not
link HTTP, persistence, or the full profile builder into the core.

Equivalent-domain settings use the opt-in `DomainSettingsStorage` provider. Its
borrowed read view implements `DomainSettingsData`; updates accept the same
indexed interface and atomically replace custom groups and exclusion IDs with
the account revision. `GlobalDomainCatalog` supplies adapter-owned catalog facts.
The core streams typed GET and sync responses directly from these views, retaining
ordering, duplicates, and opaque strings while filtering excluded global groups
only for sync. HTTP, storage, clocks, and notification transport remain outside
the core.

`DomainSettingsRequest` offers caller-selected decoder capacities. An adapter can
implement the view over its own collections to support larger batches without
adding allocation to the core. The standalone adapter does this over owned
vectors and stores authoritative settings in a dedicated `account_domains`
table. Registration extras do not seed this state. Updates preserve unrelated
account and vault data; transaction failures preserve both settings and revision.
The bare-metal consumer encodes both response projections and `{}` mutation
responses, and decodes settings requests without a global allocator.

Device discovery uses the opt-in `DeviceStorage` provider. Its stable borrowed
`DeviceListData` view and `DeviceRecord` let the core stream exact list and
single-device projections without an allocator. `DeviceRegistration` comes only
from a verified password, auth-request access-code or personal API-key login. The
provider resolves an exact owner/identifier pair, retains its initial name, type and creation time,
and may update activity without advancing the account revision. Headers, email
lowercasing, percent decoding, clocks and token issuance stay in adapters.
`KnownDeviceRequest` is already-decoded borrowed header input, with no JSON
serialization or deserialization traits. Its response serializes as a bare
boolean.

The list projection adds three fields to the seven-field single-device
projection: pending authentication metadata and two null encrypted-key fields.
`PendingDeviceAuthRequest` models only its ID and creation date. The standalone
provider projects the latest pending request for the exact owner and requesting
device, or null when none exists. The two encrypted-key fields remain null.
Approval decisions update this pending view; login uses the separate provider below.

The standalone adapter keeps the registry in its own SQLite table keyed by
`(owner, identifier)`. Account-document extensions and registration extras do not
create devices. The login savepoint covers the core registration hook, activity,
session insertion and device binding. Session, binding and deferred-commit
failures roll back all of them, including cleanup of expired sessions. Successful
login does not change account keys, credentials, revisions or vault contents.
Repeated login retains the original metadata even when a client submits a new
name or type. A separate binding table associates each new access session with
its authenticated owner and device; the JWT includes that exact identifier in
`device`; `devicetype` uses the retained registry type label.

Refresh uses the stored binding and ignores submitted device metadata. It
atomically touches the registered device, issues new refresh authority, and binds
the new session to the same owner and identifier. Existing access tokens retain
their original expiry. Older sessions without binding rows retain their existing
access behavior, but cannot refresh without a current
binding and registered device; no legacy registry backfill is implemented.
Registry and binding records survive private-database reopen. Expiry cleanup,
device removal and notification delivery remain separate tracked work.

`DevicePushStorage` is a separate opt-in provider for push-token ordering.
`DevicePushTokenRequest` borrows its opaque string, decodes/serializes without an
allocator, and redacts Debug output. The service takes the verified owner and
session device identifier; it deliberately takes no request-path target. That
verified identifier remains opaque and may be empty. An exact match with an
already-present token returns before save or registration hooks.
A changed token, including an empty string, saves atomically with device activity
before the registration callback runs. The callback supplies relay policy and
I/O. Its failure leaves the saved token and activity in place; retrying that same
token takes the no-op path rather than retrying the relay.

The core clear service first checks the provider's pure push configuration.
Disabled push returns immediately without storage or relay access. An enabled
provider instead
clears tokens for every owner with the supplied identifier and returns the optional
push ID of its first selected matching record. The core unregisters only that
record's ID when present; a missing ID on the first record does not select a later
owner's ID. Unregister failure retains the cleared state. These ordered callback
contracts have provider-test coverage, not live enabled-relay evidence.

The standalone adapter fixes push configuration to disabled and makes no relay
requests. Its dedicated `device_push_tokens` table has a composite foreign key to
`device_registry`; relogin preserves its opaque values and registry removal
cascades cleanup. Token/activity writes preserve account revisions, initial
device metadata, keys, credentials, sessions, vault contents and foreign state.
An owned JSON guard handles escaped values and known duplicate fields before
borrowing the core request. Writes require a verified session binding before
path or JSON validation; an older unbound session gets 401 for these writes while
its other existing routes remain usable. Clear ignores bearer credentials and
body data, validates the path, and returns an empty 200 with tokens unchanged.
Local abuse limiting, real relay registration/unregistration and push delivery
remain open adapter work.

Auth-request creation and discovery use `AuthRequestStorage`, an opt-in extension
of `DeviceStorage`. Its borrowed four-string request and stable indexed read view
require no allocation in the core. Creation resolves the email through the
provider, then validates the existing device's owner, exact opaque identifier
and raw numeric type before inserting anything. The adapter lowercases email
without trimming; it supplies ID generation, timestamps, peer address and origin.
An absent or unparseable `device-type` header supplies 14; any parsed `i32` is
compared exactly, even when its response label is `Unknown Browser`.

Explicit serializers project eleven auth-request fields. Creation reports
`requestApproved: false` while storing a pending `None`; GET and list report that
state as null. Lists filter only `approved: None`, with no implicit age filter.
Internal owner/device identifiers and access codes have no response field;
request/context/record/response Debug output is redacted, and records have no
general serialization implementation. The caller owns secret input buffers.

The standalone adapter stores requests in a dedicated `auth_requests` table with
nullable future response fields. Account-document and registration extensions do
not seed requests. A savepoint commits only the request; failure preserves account
revision, credentials, sessions, device activity, push tokens, vault data and
foreign state. Tests cover late insert and deferred-commit failure, private
reopen, approval-state filtering and latest-pending ownership. Device lists join
the newest pending row by creation date for each exact owner/device and project
only its ID and creation date; single-device responses keep seven fields.

The Axum adapter records the direct socket peer through `ConnectInfo` and ignores
forwarding headers. A bounded socket regression connects from `127.0.0.2` and
supplies forwarding headers to verify this adapter policy; it is not an upstream
IP-equivalence test. Vaultwarden can honor configured `X-Real-IP` from trusted
proxies, including local peers under its defaults. That forwarded-IP policy is
not implemented here. The canonical origin derived from the configured URL,
without its path, does match upstream. Authenticated auth-request reads require
a verified session-device binding before UUID path validation; existing unbound
sessions keep their older API behavior. Notifications/events, expiry jobs, proxy
policy and public abuse controls remain open.

`AuthRequestResponseStorage` extends `AuthRequestStorage` with decisions and
code-verified reads, without adding crypto or persistence to the core. The
borrowed `AuthRequestUpdateRequest` carries the exact response device identifier,
key, optional hash and boolean decision. The service checks owner/request state,
compares the body device to the verified session device, and rejects any already
answered request before calling the provider. The adapter keeps session, UUID
and owned-JSON guards in that order.

Approval atomically saves the key, exact optional hash, `approved: Some(true)`,
response device ID and fresh response date. Rejection deletes the pending row and
returns an adapter-owned cached snapshot of its prior fields with a fresh
response date; it does not save `Some(false)` or use the rejected body's key/hash.
Both operations preserve account revisions, device activity, credentials,
sessions, vault data and foreign requests. A savepoint covers update/delete and
any triggered writes. No fallible database read is needed after commit. Tests
cover late-write/deferred-commit rollback and durable approval/deletion on reopen.

Public response polling requires an exact access code, original raw device type
and recorded IP, and can read pending or approved requests repeatedly without
consumption. The core accepts a redacted `Secret`; its provider verifies codes.
The host computes fixed-size HMAC-SHA256 fingerprints with a public domain
separator and compares them through `Mac::verify_slice`, avoiding plaintext
prefix or length equality checks. The tags are not stored or exposed. Missing
records and code/type/IP mismatches have the same public 400 error. UUID and
required query guards run first; absent `code` returns 422.

Polling uses the documented direct-peer IP policy and ignores bearer credentials
and forwarding headers. The required query follows Rocket's first matching name
root, including scalar dotted/bracketed suffixes; form decoding converts `+` to
space and `%2B` to plus exactly once. The operation neither grants a session nor
consumes a request for login. Eight focused HTTP cases pass against the adapter
and Vaultwarden `1.37.4`: 322 requests and four successful logins per server.
The prior combined local HTTP milestone passes 72 cases and 3038 requests,
including the separately described login comparison.
Current client and login-comparison results are recorded in
[verified compatibility](compatibility.md). Notifications/events, expiry jobs,
proxy parity and public rate controls remain open.

Approved-request login uses the separate opt-in `AuthRequestLoginStorage`, which
extends `AuthRequestStorage` without adding crypto, clocks, token issuance or
allocation to the core. `AuthRequestLoginRequest` borrows required form inputs;
its proof is a redacted `Secret`. The provider returns private, redacted state
only after owner-scoped constant-time code verification. The service trims the
username before provider email lowercasing, requires exact password scope,
approval, unused state, the same peer IP, an enabled account and a deadline
strictly later than the supplied time. Creation and current timestamps use
full-width `i128` Unix nanoseconds, preserving the exact five-minute boundary.

An owner/ID-scoped approved-and-unused compare-and-set consumes the request
before producing `AuthorizedAuthRequestGrant`. This unforgeable grant owns the
provider's account handle and lends client/device inputs, so storage borrows end
before host issuance. The code is the creation access code, never the encrypted
response `masterPasswordHash`. A new or different login device/type is allowed;
the requesting device's type still governs public polling. No login device/type
comparison is added. The request ID in this form is opaque, with no UUID path
guard. Rocket-style dotted/bracketed scalar names select the compact
case-insensitive `authRequest` root too; a present empty or unknown ID cannot
select ordinary password proof. Other form-field root parsing and the inherited
ambiguity rejection policy remain separate gaps.

The host verifies codes with the existing fixed-size HMAC verifier and reads
enabled state from private `account_auth_policy`, defaulting to enabled for
accounts without a row. Registration/profile document extras cannot supply that
authority; no administration API is implemented. A savepoint encloses consumption,
device registration/activity, expired-session cleanup, session insertion and
binding, including deferred commit checks. Any failure restores the entire
operation. This rollback boundary is stronger than the pinned upstream's
separate consumption and issuance steps. Provider tests also cover standalone
consumption failures, two-connection compare-and-set races and durable used state
after reopen. Successful login preserves approval/key/hash/response fields,
account revisions, credentials and vault state. Polling is neither consumed nor
implicitly expired by login.

Shared password-method issuance now uses the upstream two-hour access lifetime,
the supplied client ID, or `undefined` when absent. Refresh reads its own optional
client ID, retains the verified device binding and projects the stored type label
as `devicetype`; submitted replacement metadata does not overwrite it. Personal
API-key authority retains its existing separate policy. Legacy unbound sessions
cannot refresh without current device authority. Password refresh now preserves
valid earlier proofs and selects the source thirty/ninety-day lifetime from the
retained device type. The host still uses opaque handles rather than upstream
refresh JWTs, so refresh JWT encoding and `nbf` behavior remain unimplemented.
Two-factor/mail/SSO policy,
administrative account management, notification delivery, expiry cleanup,
trusted-proxy IP handling and rate controls remain outside this adapter slice.
The eight focused login HTTP cases pass against both the adapter and actual
Vaultwarden `1.37.4`: 444 counted requests and 43 identity requests per server,
including two ordinary logins, seven successful auth-request logins and two
refreshes. Twelve creations and twelve public polls include a real 301-second
expiry fixture: login expires while polling remains readable. Required CI reruns
the unchanged verified 120-command CLI baseline; this adds no CLI auth-request
route claim.

Modern ordinary registration has its own opt-in `RegistrationStorage` provider.
The existing strict `RegisterRequest`, `VaultService::register` and
`Storage::insert_account` APIs retain their validation and legacy host behavior.
The new provider accepts borrowed opaque hash/key strings and signed `i32` KDF
fields. Verification input, nested authentication/unlock fragments, explicit
token-string serialization and the finish response work without allocating in
the core. `RegistrationFinishRequest` is a programmatic semantic view; the full
flattened/untagged JSON decoder stays in the host.

The owned host guard mirrors the pinned old-first credential selection and
aliases before borrowing that view. The caller supplies separately normalized
storage email (Unicode lowercase without trimming) and salt email (trim then
lowercase). The core checks nested KDF equality and both salts before token
verification, returning 422 for that format mismatch. It then requires verified
token claims with the exact raw email subject, limits the optional claim name to
50 UTF-8 bytes, applies signup/hint/account state, and validates KDF policy.
Name is never taken from the finish document. Hints are trimmed and blank hints
become absent. Opaque client hash/key/key-pair values receive no new base64 or
encrypted-string validation; this is separate from the legacy strict policy.

PBKDF2 requires at least 100,000 iterations with no added maximum. Argon2 requires
at least one iteration, memory 15–1024 and parallelism 1–16. Other signed KDF IDs
remain opaque; non-Argon2 memory/parallelism normalize to null. The host's shared
KDF response builder preserves signed values through prelogin and decryption
metadata instead of silently projecting them as defaults. Before commit, core
state also requires a host-supplied email-validity result. The host uses the
upstream `email_address` 0.2.9 mailbox parser and URL domain/path/query checks on
the storage email, with no extra ASCII-only policy. Invalid addresses return
400 after proof, account-policy and KDF checks; verification still issues tokens
for them. The parser and URL dependencies stay outside the allocation-free core.

The standalone adapter fixes registration to the ordinary no-SMTP, signup-allowed
new-account flow. It returns a verification token directly as JSON or plain text
according to Rocket-style preferred `Accept` selection. Its cursor parser
preserves quoted delimiters/escapes and reads quality only from a first `q`
parameter of at most five bytes; weighting/specificity selection remains ordered.
An invalid-looking email
or long name can receive a token; the name limit belongs to finish. The token
contains the raw email, optional name and `verified:false`, with a 30-minute
lifetime and canonical configured `origin|register_verify` issuer. A separate
32-byte HMAC signing authority persists in private SQLite storage, independent
of the legacy access-token key. Constant-time signature verification checks the
fixed algorithm, issuer, expiry and not-before time with 30-second leeway;
Unicode whitespace removal matches the pinned decoder. A restart retains issued
registration tokens, and concurrent initialization selects one stored key.

Only a canonical account document and Argon2 verifier reach account storage.
IDs/revisions/default avatar and key-ID state are server-owned; the name is the
verified claim or lowercased email fallback. Raw verification tokens, client
hashes, nested proof objects and unknown extensions never enter that document.
A private metadata table retains the actual verification flag. No-SMTP profile
and JWT projections remain verified, matching upstream's policy even when the
token claim is false. Request fields cannot forge either authority.

Account insertion and private verification metadata commit in one savepoint.
Failures after account insertion, metadata writes or deferred commit restore
existing accounts, credentials, sessions, attachments and vault state. The token
is not consumed by a failed finish; repeating a completed finish rejects as a
duplicate without replacement. The host treats every existing account as a
duplicate; invitation/placeholder completion is not exposed. Provider and host
tests cover these boundaries and persistence. All eight corrected modern HTTP
cases pass against the adapter and actual Vaultwarden `1.37.4`: 541 counted
requests per server. A fresh unchanged 120-command CLI regression also passes
against both servers. The HTTP registration proof stays separate from that
client baseline, whose fixture uses legacy registration; no CLI registration
command or route trace is attributed to it.

SMTP delivery/verification, invitation and emergency-access enrollment,
placeholder completion, registration configuration, signup-domain policy,
notifications, rate controls, full JWT interoperability, complete header grammar,
error envelopes and
transport-limit parity remain open. The adapter's encoded-body cap remains
16 MiB, below upstream's 20-MB JSON limit. This provider does not complete the
registration or upstream API parity goal.

## Password verification and security-stamp renewal

`AccountSecurityStorage` adds four opt-in hooks without changing existing
`Storage` or `IdentityStorage` implementations. `VaultService::verify_password`
requires the authenticated owner and a borrowed nonserializable `Secret`, verifies
it, invokes the server-verifier upgrade hook, then obtains the applicable policy.
The server's verifier cost is separate from client KDF parameters. Upgrade writes
need not roll back if later policy lookup fails; the provider owns the upstream
distinction between password-rebuild failure and best-effort user-save failure.
`MasterPasswordPolicyResponse` explicitly serializes the optional seven-field
policy and PascalCase `Object`; no policy yields only that discriminator.

`reset_security_stamp` uses the existing exclusive password/protected-action OTP
proof selection. Successful protected-action verification consumes a purpose-,
account- and expiry-bound OTP; it is not an account TOTP. Consumption precedes
reset, so an adapter must document whether it wraps both operations atomically.
The core supplies no RNG, clock, stamp capacity, password implementation or heap.
The standalone adapter rejects unsupported OTP proofs and uses current Argon2
verifiers, making its upgrade hook a documented no-op. Organization and SSO policy
aggregation and stale-verifier migration remain embedding-provider work.

The adapter stores stamp authority in a private owner-keyed table. Existing
accounts retain their former owner-ID stamp until renewal. Profile, sync and JWT
issuance explicitly read private authority; unknown account-document fields
cannot select it. One SQLite savepoint generates a UUID, advances owner revision,
and removes all owner sessions and registered devices, including push rows and
session bindings. Password/API credentials, client KDF, account keys, encrypted
vaults, authentication requests and other owners survive. This gives stronger
rollback than upstream's sequential refresh rotation, save, notification and
device deletion. Notification delivery and remembered-2FA support remain open.
An unused approved authentication request retains its original lifetime and
peer-IP requirements and can authorize a new login after renewal.

## Client KDF transitions

`AccountKdfStorage` adds two opt-in hooks: verify the old opaque client hash and
return an owned authoritative salt handle, then commit a private validated plan.
`VaultService::change_kdf` checks the owner and old proof before complete nested
KDF equality, exact authentication/unlock salts and signed KDF policy. Only the
shared signed KDF value is reused from registration; this endpoint has a distinct
three-field nested request, not a legacy-first union. Requests and plans have
redacted Debug and no general Serialize implementation. Salt normalization,
verifiers, clocks, randomness and persistence remain external to the no-alloc core.

The adapter rechecks the old proof inside its savepoint, then replaces the server
verifier, wrapped user key and client KDF metadata, creates a private stamp,
advances revision and invalidates ordinary owner sessions. It preserves device/push
registrations, asymmetric keys, API credentials, authentication requests, vault
data and foreign accounts. Rollback covers every local mutation and deferred
commit failure. This is stronger than upstream's sequential refresh rotation and
user save; notification delivery and remembered-2FA behavior remain open.

The pinned source trims and Unicode-lowercases stored email for salt comparison;
Vaultwarden 1.37.4 compares stored email exactly. The provider chooses this policy,
and the adapter targets the pin. Actual comparisons use ordinary valid lowercase
account emails, where both agree. No general equality of those versioned edge
cases is inferred. KDF changes preserve opaque new proof/key strings; client
reencryption belongs to clients. The host-only fixture rewraps the same user key
and encrypts an existing item to establish actual CLI decryption after the change.


## Password changes and previous-stamp authorization

`AccountPasswordStorage` keeps password verification, exact authoritative email,
server hint policy and persistence in adapters. The core checks the old proof
before selecting credentials: a complete nested authentication/unlock pair wins;
a partial nested pair can fall back to complete legacy hash/key fields. Nested
KDF values must equal each other and both salts must equal the exact stored
email. This endpoint neither validates those KDF thresholds nor changes the
stored client KDF. Missing, null or whitespace-only hints clear the hint.

A private validated plan carries the fixed upstream password-change stamp
policy. Its pure helper checks an expired deadline before route membership and
verified previous-stamp equality; equality at the deadline is still valid.
Providers supply clocks, stamp comparisons, JWT verification, device lookup and
lazy cleanup. Only `post_rotatekey`, `get_contacts`, `get_public_keys` and
`get_api_webauthn` qualify, for 120 seconds after the change. The adapter currently
implements public-key and WebAuthn credential-metadata discovery from this set;
contacts and key rotation remain open. The credential-metadata service requires
an authenticated owner and returns the upstream empty list without accessing
storage. It does not implement passkey registration or login.

The SQLite adapter captures the original expiry and bound device of current
owner access tokens before invalidating ordinary sessions and refresh tokens.
Private snapshots survive KDF changes and direct stamp resets, as upstream's
exception does. Direct resets delete devices; recreating the same owned device
identifier can reactivate an unexpired exception. Each password change replaces
the previous generation. An expired mismatched-stamp request with a valid device
lazily clears the exception and advances account revision. A current-stamp request
does not trigger that cleanup.

Credential, hint, key, stamp, revision and session changes use one local
transaction. This is a stronger failure guarantee than upstream's sequential
writes. Upstream event logging before semantic validation, logout notifications,
remembered 2FA and all missing exception routes remain adapter gaps. The inherited
strict access-expiry check does not implement upstream JWT's 30-second leeway;
no exception extends a token's original access lifetime.

## Reauthenticated personal vault purge

The opt-in `purge::VaultPurgeStorage` extends `Storage` with independent proof
verification and personal-vault persistence operations. The allocation-free
`VaultService::purge_personal_vault` first requires an authenticated owner, then
selects exactly one proof from the existing borrowed `PasswordOrOtpRequest`.
It calls `verify_vault_purge_proof` before `purge_personal_vault`; no API-key or
account-security provider trait is required. The core owns no HTTP query parser,
password verifier, clock, token issuer, database or allocator.

The adapter resolves personal versus organization scope before allowing the
personal service. A recognized `organizationId` query root cannot authorize a
personal deletion, even if its string is empty or not a UUID. The provider owns
all cleanup: personal cipher/folder rows, attachment bytes and download grants,
and associated folder/archive state. It advances account revision even for an
empty vault, while preserving credentials, key material, stamp/exception,
sessions, devices, API secrets, auth requests, settings and foreign state.

The provider contract makes the purge mutation and revision atomic. This is
stronger than upstream's sequential cipher/folder deletions and final revision
write, including filesystem failures after earlier database changes. Proof
verification is a separate operation: a protected-action OTP may be consumed
before a later purge failure, and the core does not promise rollback of that
consumption. Providers can supply a stronger combined transaction. The standalone
host supports password proofs; successful protected-action OTP and notification
delivery remain separate capabilities. Six direct Rust cases pass against the
actual adapter and Vaultwarden 1.37.4, including empty server lists, fresh
capability revocation within a 30-second window and preserved authority followed
by authenticated decryption of a newly created item. Local
SQL tests establish physical BLOB/grant/row deletion, rollback and durable reopen;
they establish provider guarantees
without asserting identical upstream failure semantics.

## Reauthenticated account deletion

`account_deletion::AccountDeletionStorage` adds proof verification and account
removal without requiring an API-key or account-security provider. The borrowed
`VaultService::delete_account` accepts the existing `PasswordOrOtpRequest`,
requires an authenticated owner and exactly one proof, then invokes
`verify_account_deletion_proof` before `delete_account`. A request cannot select
another account identifier. HTTP authentication, locks, cryptography, clocks,
policy and persistence remain outside the allocation-free core.

An organization-aware provider enforces last-confirmed-owner policy after proof
verification and before mutation. The personal adapter implements no organization
membership or emergency-access lifecycle; an empty local organization feature
is not a proof of that broader policy. Provider unit tests exercise policy
rejection and error mapping separately from personal HTTP behavior. A consumed
protected-action OTP is not rolled back implicitly when later policy or storage
fails; the host supports password proofs and rejects unsupported OTPs.

Unlike personal vault purge, account deletion leaves no supported owner state or
revision. The adapter commits session/API-secret/item removal and account-FK
cascades together, including ciphertext, attachment BLOBs/grants, devices/push
metadata, auth requests, domain settings, personal text Sends, private stamps/history/exceptions and
registration metadata. It preserves unrelated accounts and the instance's
registration signer. Physical deletion, rollback and durable reopen require local
SQL evidence; portable HTTP demonstrates public authority and capability effects.
This atomic mutation guarantee is stronger than the upstream sequential cleanup,
which can retain prior deletions after a later failure. Release 1.37.4 omits
explicit auth-request deletion present in the pin; the portable comparison avoids
that versioned case. All six selected HTTP cases pass against both actual
servers, covering authority revocation and same-email re-registration with a
fresh account ID, keys and API secret. Fresh owned attachment capabilities
become unavailable while foreign bytes remain intact within 30 seconds.
Local SQL tests establish physical deletion, failure rollback at eighteen
cleanup stages and deferred commit, and durable private-database reopen.

## Cipher read authorization

`cipher_reads::CipherReadStorage` adds an opt-in readable-access hook to the
existing storage boundary. `VaultService::authorize_cipher_read` first requires
an authenticated owner, then distinguishes missing (`None`, 400), inaccessible
(`Some(false)`, 400) and readable (`Some(true)`) provider results. The default
personal implementation compares exact metadata ownership; embeddings may
override it for shared readable access without requiring write permission.
The admin-named alias uses this same policy and supplies no extra authority.

`AuthorizedCipherRead` borrows the exact owner and item ID and has a private
constructor and redacted Debug. It is an operation-local authorization result,
not a serializable cipher response or a durable capability. An adapter must
hold a lock or consistent snapshot across authorization and response projection.
The standalone host keeps its SQLite/store lock across both operations and
returns its existing opaque JSON projection without a new core payload model.
Active, trashed and archived records stay readable without changing account or
cipher revisions, credentials, archive annotations or ciphertext. UUID decoding,
HTTP authentication and trusted organization policy remain adapter concerns.
Projection may issue fresh attachment download capabilities; account/vault
nonmutation does not mean that projection performs no SQL writes. The
no-allocator consumer links the real service against bounded stack-owned storage.
All six focused HTTP cases pass against both actual servers, including active,
trashed and archived alias equivalence, capability-backed exact byte retrieval,
revoked-authority rejection and unchanged owner/foreign snapshots.

## Ordinary password identity grants

`password_login::PasswordLoginStorage` moves ordinary password-grant validation
into the allocation-free core. The borrowed `PasswordLoginRequest` preserves
field presence and an opaque redacted proof. `VaultService::authenticate_password`
requires the password grant, excludes a present auth-request selector, checks
required fields in upstream order, then requires the exact password scope before
provider access. It trims the username by borrowing a subslice and passes the
unmodified proof to the provider. Unicode email lowercase lookup, password
verification, account-enabled state, private verifier upgrade and subsequent
login policy belong to trusted provider hooks. No plaintext vault decryption or
crypto implementation is added to the core.

A sealed `AuthorizedPasswordGrant` returns the verified owner, supplied client ID
and raw `PasswordLoginDevice` metadata, fixed password scope, two-hour access
lifetime and refresh permission. `PasswordLoginAccount<OwnerId>` supplies a
trusted enabled flag and an owned, potentially fixed-capacity account handle,
releasing provider borrows before issuance. The grant is not a token response;
the adapter still issues JWTs, registers/touches the retained device, persists
sessions and builds the existing response metadata. The core does not promise
whole-login rollback: prior verifier upgrades may survive a later policy error,
as in upstream. Embeddings own their transaction boundaries. The local host
keeps device/session issuance atomic, while its fixed-verifier, SMTP/2FA/SSO-free
preparation hook has no additional work; it does not implement dynamic verifier
upgrades or those richer policies.

The host's ordered form parser selects ordinary password login only when the
first matching grant root is `password` and no recognized auth-request root is
present. Matching is uncased for declared aliases and uses Rocket's first name
segment. The required grant string keeps its first matching value. Optional
scalar fields instead become absent when more than one alias/root matches,
because Rocket forces strict inner decoding for `Option<T>` and discards its
error. Other grants and ambiguous auth-request selectors retain their existing
stricter parser policy. The separate refresh contract below now owns supported
password-method authorization; SSO, mail, 2FA and full transport/OAuth response
contracts remain partial. Six focused Rust cases pass against both actual
servers, including duplicate-absent optional fields, exact selected errors, raw
proof semantics, successful authority and unchanged account/vault snapshots.

`RefreshStorage` adds an opt-in password-method contract without new obligations
for existing storage adapters. `RefreshTokenRequest` borrows the decoded grant,
optional redacted proof and optional client ID. `authenticate_refresh` checks
presence, verifies trusted owner/device/method through the provider, then prepares
device activity before returning a sealed `AuthorizedRefreshGrant`. Owned
provider handles avoid retained storage borrows; clocks, cryptography, Unicode
whitespace normalization, persistence and issuance stay outside the core.
There is no consumption, enabled-state check or previous-stamp comparison.

The provider must resolve current device authority, preserve the original proof
deadline and permit repeated use until expiration or revocation. Issuing another
proof does not revoke still-valid earlier proofs. The host joins its stored
SHA-256 proof digest to both the session binding and current registry row, strips
all Unicode whitespace before lookup, and admits expiry equality through thirty
seconds of leeway. It rejects unbound legacy refresh proofs. New opaque handles
expire after ninety days only for retained Android/iOS types 0/1; all other types,
including Android Amazon 15, use thirty days. No JWT refresh representation or
`nbf` equivalence is claimed. Password/KDF/stamp changes invalidate the owner's
old proof rows; recreating a device identifier cannot revive them.

The adapter's outer savepoint includes preparation, activity, new sessions and
binding, with rollback on issuance or deferred commit errors. This is stronger
than upstream's separate activity writes. Refresh returns only the five OAuth
fields and preserves old access deadlines, account keys/KDF/revision, vault
contents and other devices. Missing or repeated optional proof fields use the
default API error; present invalid proofs use only `error: "invalid_grant"`.
Twelve core tests and the actual no-allocator consumer cover the reusable
boundary. All eight selected direct HTTP cases pass against both actual servers:
268 counted requests each, including six password logins and 42 refresh POSTs.
The refresh split is 22 successes, 15 invalid proofs, four presence/duplicate
guards and one missing-grant form guard. Two fixture registrations are excluded.
The cases prove original-proof reuse, exact selected responses, owner/device
isolation, revocation/recovery and retained ciphertext decryption. Clock/provider
tests separately cover hidden deadline/leeway policy. No complete identity or
refresh-JWT parity follows from these comparisons.

## Personal text Sends

`SendStorage` is an opt-in provider for six owner operations and separate
recipient access. `TextSendRequest<P>` is a borrowed semantic view after an
adapter has decoded the full request, dates and signed number-or-string fields;
it is not a complete Serde JSON decoder. Generic caller-owned serializable text
and stable indexed `SendListData` views avoid fixed payload/count capacities and
any core allocator. Typed serializers emit the exact eighteen-field owner,
eight-field recipient and three-field list envelopes. Recipient serialization
itself suppresses `creatorIdentifier` when `hideEmail` is true.

The core orders trusted Send/hidden-email policy checks, ownership, type,
thirty-one-day deletion ceiling and signed `i32` access-limit conversion before
provider writes. Dates use a caller-supplied nanosecond clock. Opaque name, key,
notes, password proof and text receive no invented encrypted-envelope or size
policy. Creation sets fresh IDs/count zero; update keeps identity/count. Omitted
or null update password preserves protection; explicit password removal clears
it. Delete bypasses the disable-Send write policy. Providers own complete local
mutation atomicity, clocks, normalization, cryptography and notifications.

Recipient token issuance validates a decoded access ID, current availability,
count and optional password proof without incrementing access. Its private grant
has 120-second authority and no refresh. An owner bearer cannot satisfy recipient
access. Each actual access rechecks disabled/deadline state and asks the provider
for an atomic count increment below the current limit. Already-issued recipient
capabilities survive password replacement/removal. An exhausted count can advance
the owner revision before returning 404, as upstream does; rejection does not
imply universal rollback. Successful access changes count and Send/owner revision.

The SQLite adapter stores encrypted text and metadata in owner-FK rows, hashes
the exact client-derived proof with PBKDF2-SHA256/100000 and a random 64-byte
salt, and uses a persistent purpose-separated signer for short-lived Send JWTs.
Its HS256 algorithm differs from upstream RS256. Issuer, subject and
`nbf`/`exp` checks use the Send purpose and thirty-second leeway; clock tests do
not establish cross-server JWT acceptance or live long-expiry behavior.
Owner/list/sync projection follows upstream's recursive first-character key
normalization, exact root `response` removal and top-level numeric-size string
conversion. Accepted scalar/array text projects as null. This is not universal
raw-JSON projection preservation.

Local savepoints protect Send rows, password material and revision writes.
Notification or later response construction is a separate boundary. SQL tests
cover rollback, durable reopen, signing authority, account-deletion FK cleanup
and preservation of Sends during personal vault purge. Account deletion removes
Send rows; vault purge continues to remove personal ciphers/folders/attachments
while retaining Sends. Sync now includes real owner Send responses; organization,
collection and policy placeholders do not acquire implementation by that change.

All six selected HTTP cases pass against the adapter and actual Vaultwarden
1.37.4: 129 counted requests each, including two password logins, 23 Send-token
grant requests and 15 recipient access requests. Two fixture registrations are
excluded. Authenticated ciphertext decryption, exact projections, ownership,
password lifecycle, access limits and preserved unrelated state are compared.
The separate official CLI 2026.10.0 text run passes all twenty commands on both servers. File Send support is described below; email verification,
enterprise/configuration policy, notification delivery, rate controls and
scheduled purge remain outside this supported subset; full API parity stays open.

## Personal file Sends

`FileSendStorage` extends the opt-in Send provider without adding operations to
existing `SendStorage` adapters. The core validates reservation length/quota,
immutable file updates, upload ownership/name/identity/exact size, recipient
count reservation and binary-capability authorization. `FileSendRequest<P>` is
a borrowed semantic view after adapter decoding; `SendFileUpload` contains
measured facts, not a multipart decoder or byte buffer. Generic reservation and
download serializers emit four and three fields. Provider-owned URL/string
handles keep allocation outside the library.

Reservation stores a fresh 64-character lowercase-hex file ID and authoritative
metadata. The declared encrypted-length limit is 550,502,400 bytes (525 MiB);
upstream's actual multipart/file cap is decimal 525,000,000 bytes. The host uses
that multipart cap and retains its ordinary 16 MiB body limit. No live maximum
upload is claimed. Type-1 updates preserve raw file metadata and bytes. Upload
requires the exact raw encrypted filename; retained CLI device types 23–25 also
allow the received filename to be a suffix of the stored name. It requires
exact measured length, preserves rejected reservations, and cannot overwrite
existing bytes. Successful upload advances only account revision.

The host commits BLOB insertion and account revision together, stronger than the
upstream filesystem sequence. Tests inject insertion, revision and deferred-FK
commit failures, then prove clean retries. Binary data, reservation and signer
survive reopen; Send/account-FK cleanup preserves foreign state. Later response
or capability generation can fail after a stored mutation, as in the source.
File metadata access does not consume count but touches owner revision; file-URL
issuance reserves count before minting a 120-second capability with 30-second
leeway. Binary GET checks only token/path and existing bytes, so an issued URL
survives policy/date/count changes until expiry or physical deletion.

Six Rust HTTP cases pass against both actual servers. A separate twenty-command
official CLI run passes both and compares received arbitrary bytes exactly.
Object storage, configured quota/policy matrices, email OTP, notifications,
rate controls, purge scheduling, Range/full transport and RS256 equivalence
remain outside this personal subset. No full API or captured-trace claim follows.
