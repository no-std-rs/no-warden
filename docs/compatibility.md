# Verified compatibility

The baseline personal-vault suite has passed against both the standalone
no-warden adapter and official Vaultwarden 1.37.4 using the official Bitwarden
CLI 2026.10.0. The upstream image digest and examined source revisions are
recorded in [the test tools](../tools/README.md) and [protocol notes](protocol.md).
That client evidence covers the legacy field-level encryption flow described
below; newer model support has separate limits.

The suite registers a disposable, cryptographically valid account through HTTP,
then uses ordinary CLI password login. It checks client-side decryption, folder
create/get/edit/delete, login-item create/get/list/edit, Unicode notes, custom
fields, sync, local lock/unlock, a fresh CLI cache after logout/login, trash,
restore and permanent deletion. A per-run trusted loopback TLS proxy meets the
current CLI's HTTPS requirement without changing the client or disabling
certificate validation.

| API surface | Standalone behavior | Verification |
| --- | --- | --- |
| `GET /api/config` | Endpoint discovery | Real CLI |
| `POST /api/accounts/register` | Registration with encrypted keys | Cryptographic fixture |
| Prelogin legacy and identity aliases | PBKDF2/Argon2 parameters | Latest CLI and HTTP |
| `POST /identity/connect/token` | Password grant, expiring sessions, rotating refresh | CLI and HTTP |
| `POST /api/accounts/key-management/user-key-id` | One-time key-ID migration | SDK login and HTTP |
| Profile, revision date, sync | Personal account and opaque encrypted vault | CLI and HTTP |
| Folder CRUD | Encrypted names, owner isolation, clear references on deletion | CLI, HTTP, storage tests |
| Cipher CRUD | Opaque ciphertext and unknown JSON fields | CLI, HTTP, storage tests |
| Trash, restore, permanent-delete aliases | Owner-checked lifecycle | CLI and HTTP |
| Conditional cipher update | Stale revision returns 409 | Concurrent HTTP edits |
| Legacy folder update/delete aliases, cipher clone wrapper | Owner isolation, fresh clone IDs, empty collection IDs, PascalCase wrapper aliases | Core and HTTP tests |
| `CipherRequest.data` blob payload | Preserve escaped opaque data through create/get/update/sync | Core and HTTP tests; real-client blob round trip unverified |
| Stored login FIDO2 credentials | Preserve bounded encrypted records and unknown nested fields through create/get/update/sync | Core and HTTP tests; authenticator use unverified |
| `archivedDate` metadata | Preserve client-supplied archive metadata through create/update/sync | HTTP preservation tests; archive action endpoints are unsupported |
| Organization ID aliases | Reject non-null `organizationId` and `organizationID` in direct and wrapped personal writes | HTTP authorization tests |
| Type-7 encrypted strings | Validate outer base64 envelope and preserve COSE bytes | Core tests; no COSE cryptography in the core |
| Current user-key ID on creates | Compare a supplied ID with `Storage::user_key_id` when available | Core provider and HTTP tests |
| Provider conflict errors | `Storage::map_error` can preserve an HTTP 409 conflict | Core provider tests |

The allocation-free core's models include login, secure note, card, identity,
and SSH-key items, plus optional opaque blob data. Its 18 unit tests cover the
new typed fields, bounded collections, validation, ownership, and lifecycle
rules. The initial real-client suite exercises login items; other types and
blob encryption need their own client fixtures before claiming verified
compatibility. Keeping encrypted passkey records in a login item does not
implement WebAuthn/passkey account authentication or verify authenticator use.

The fixture uses PBKDF2. Argon2 parameter policy is unit tested; real-client
Argon2 account interoperability is not yet verified. Browsers, extensions,
desktop and mobile are not covered by the CLI result. Full organization,
attachment, Send, notification and account-management compatibility remains on
the [roadmap](../ROADMAP.md).

The expanded HTTP regression suite passes all 20 tests against the rebuilt
standalone server. These establish wire preservation and authorization for the
new shapes and aliases independently of the CLI evidence. They do not prove
that a real client can decrypt a blob or use stored passkey credentials.
User-key-ID migration is a one-time identifier backfill, not a key-rotation
implementation.

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
