# Architecture

On Unix, the standalone host creates its SQLite database with owner-only
permissions before opening it. Startup also restricts existing database, WAL,
shared-memory, and rollback-journal files. Filesystem providers remain outside
the allocation-free core.

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
