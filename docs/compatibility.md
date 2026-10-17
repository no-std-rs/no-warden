# Verified compatibility

The initial personal-vault suite passes unchanged against both the standalone
no-warden adapter and official Vaultwarden 1.37.4 using the official Bitwarden
CLI 2026.10.0. It executes 37 CLI commands. The upstream image digest and examined
source revisions are recorded in [the test tools](../tools/README.md) and
[protocol notes](protocol.md).

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

The allocation-free core's models include login, secure note, card, identity,
and SSH-key items. The initial real-client suite exercises login items; other
types need their own client fixtures before claiming verified compatibility.

The fixture uses PBKDF2. Argon2 parameter policy is unit tested; real-client
Argon2 account interoperability is not yet verified. Browsers, extensions,
desktop and mobile are not covered by the CLI result. Full organization,
attachment, Send, notification and account-management compatibility remains on
the [roadmap](../ROADMAP.md).

This adapter is a conformance host. It has no deployment hardening, login abuse
controls, two-factor authentication, administrative account recovery, or schema
migration policy yet. Keep real vaults in an established service until those
capabilities and an independent security review are complete.
