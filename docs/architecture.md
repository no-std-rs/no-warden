# Architecture

On Unix, the standalone host creates its SQLite database with owner-only
permissions before opening it. Startup also restricts existing database, WAL,
shared-memory, and rollback-journal files. Filesystem providers remain outside
the allocation-free core.

The standalone host caps encoded HTTP bodies at 16 MiB. Encrypted-field validation normally caps decoded values at 1 MiB; the larger
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
SHA-256 digests and checks expiry; refresh tokens rotate atomically. The
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
from a verified password or personal API-key login. The provider resolves an
exact owner/identifier pair, retains its initial name, type and creation time,
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
Approval and login workflows remain separate.

The standalone adapter keeps the registry in its own SQLite table keyed by
`(owner, identifier)`. Account-document extensions and registration extras do not
create devices. The login savepoint covers the core registration hook, activity,
session insertion and device binding. Session, binding and deferred-commit
failures roll back all of them, including cleanup of expired sessions. Successful
login does not change account keys, credentials, revisions or vault contents.
Repeated login retains the original metadata even when a client submits a new
name or type. A separate binding table associates each new access session with
its authenticated owner and device; the JWT includes that exact identifier in
`device`.

Refresh uses the stored binding and ignores submitted device metadata. It
atomically touches the registered device, rotates refresh authority, and binds
the new session to the same owner and identifier. Existing access tokens retain
their original expiry. Older sessions without binding rows remain usable and
refresh without inventing a device; no legacy registry backfill is implemented.
Registry and binding records survive private-database reopen. Device approval,
auth-request response/login and expiry cleanup, device removal and notification
delivery remain separate tracked work.

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
a verified session-device binding before UUID path validation; existing unbound sessions keep their older
API behavior. Notifications/events, approval/public response polling, auth-request
login, expiry jobs, proxy policy and public abuse controls remain open.
