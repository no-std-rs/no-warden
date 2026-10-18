# Architecture

On Unix, the standalone host creates its SQLite database with owner-only
permissions before opening it. Startup also restricts existing database, WAL,
shared-memory, and rollback-journal files. Filesystem providers remain outside
the allocation-free core.

The standalone host caps encoded HTTP bodies at 16 MiB. The core caps each
decoded encrypted field at 1 MiB; the larger transport budget accommodates JSON
escaping and request metadata. Oversized fields still fail core validation,
and oversized requests fail before dispatch.

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

An embedded consumer can provide fixed-capacity storage and serialize responses
into a caller-owned buffer. Feature unification in an embedding application must
not accidentally enable `serde`'s `std` or `alloc` features for the core target.
CI separately compiles the core for a target without an operating system.
