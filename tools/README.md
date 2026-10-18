# Real-client compatibility checks

The compatibility harness requires Linux, Rust 1.89 or newer, Node.js 22 or newer,
OpenSSL, util-linux `prlimit`, a `kill` utility, and the pinned official Bitwarden
CLI. This requirement applies to these test tools; the crate and standalone
server have separate platform requirements.

The host-only `no-warden-conformance` Rust crate runs the default CLI suite,
including private subprocess capture, encrypted account fixtures, and disposable
loopback TLS. `tools/e2e.sh` invokes it through Cargo. Rust HTTP groups cover
folder and account-key contracts; the existing HTTP, restart-persistence,
and client-inventory checks still use JavaScript; the broader migration remains
unfinished.

```sh
npm ci --prefix tools
```

Build and start the standalone Rust server, then run the checks:

```sh
cargo test -p no-warden-conformance
tools/e2e.sh
node --test tools/server-tests.mjs
node tools/persistence.mjs
```

The default server is `http://127.0.0.1:8000`. Set `BW_E2E_SERVER` to test a
different address, or `BW_BIN` to select an installed CLI. The runner prefers
`tools/node_modules/.bin/bw` and otherwise looks for `bw` on `PATH`. The checked-in
lockfile pins CLI `2026.10.0` and its transitive dependencies; the runner checks
that exact version. Optional `BW_E2E_EMAIL` and `BW_E2E_PASSWORD` select the fresh
account's credentials; otherwise both are generated for the run. Configuration
uses environment variables, with no positional arguments or verbose-output flag.

Set `BW_E2E_RECEIPT` to a new writable file path to record a JSON run receipt.
The runner refuses an existing file and creates the receipt with mode 0600. It
records only `status`, `commands`, `expectedCommands`, and `cliVersion`, updating
the status from `running` to `passed` or `failed`. It includes no account data,
server URL, credentials, or vault contents. A receipt counts commands completed
or attempted by this run; it does not establish per-route traces or full parity.

Current CLI releases require HTTPS. For a loopback HTTP server, the suite starts
a temporary local HTTPS proxy, generates a one-day certificate with OpenSSL,
and trusts that certificate only in its CLI subprocesses using
`NODE_EXTRA_CA_CERTS`. It never disables TLS certificate validation or changes
the official CLI. Remote test servers must provide HTTPS themselves.

Each run registers fresh accounts with random passwords and cryptographically
valid Bitwarden PBKDF2, AES-CBC/HMAC, and RSA keys. The CLI uses a temporary
`BITWARDENCLI_APPDATA_DIR`, which is deleted even if the test fails. The test
does not access an existing user's CLI account or vault. Account passwords,
session tokens, and vault contents are never printed.

CLI subprocess stdout goes through a regular file descriptor explicitly set to
0600 inside a 0700 directory. Its pathname is unlinked before the child starts,
so terminating the parent during a synchronous CLI call leaves no named stdout
file behind. The helper reads the descriptor at explicit offsets; cleanup guards
close it and remove the empty directory. This avoids the documented Node.js
pipe-write hazard when the unmodified CLI exits immediately after printing.
The Rust capture helper retains a 90-second timeout and a 4 MiB stderr limit.
Stderr is counted and discarded rather than retained. A timeout stops the
process group, reaps the child, and closes its capture resources. A
shell-free [`prlimit` invocation](https://man7.org/linux/man-pages/man1/prlimit.1.html)
caps each child process's regular files at 4 MiB plus one overflow-detection byte
and sets the core-dump size limit to zero. Output above
4 MiB is rejected before reading; output exactly at the limit is accepted.
This kernel limit also applies to CLI cache files and other regular-file writes
in that subprocess. An empty login result still
fails the suite; diagnostics include only the stage or command number, exit
status, and byte counts. The observed intermittent cloud failure has not
been conclusively attributed to stdout flushing. No command is retried.

The CLI suite checks incorrect-password rejection, password login, key
decryption, encrypted folder and login item CRUD, custom fields, Unicode notes,
sync, lock/unlock, trash/restore, permanent deletion, and a fresh local cache
after logout/login. The HTTP suite checks authentication, cross-account
isolation, owner references, malformed input, refresh token rotation, and
preservation of unknown JSON extensions. It also verifies stored key-ID
enforcement, escaped opaque cipher blobs, encrypted FIDO2 records, clone
wrappers, legacy folder aliases, organization alias rejection, and preservation
of valid request-supplied archive dates.

The original 37 CLI lifecycle commands remain intact. The suite then imports
unencrypted Bitwarden JSON and CSV fixtures through the official CLI, which
encrypts their contents before upload. JSON covers logins, secure notes, cards,
and identities; CSV covers logins and secure notes. Escaped Unicode folder names,
multiline notes, custom fields, and item-to-folder links are checked again after
discarding the CLI cache and logging in afresh. Fixture files live in the private
temporary directory and are removed when the run returns. CSV folder checks
include the client's backslash normalization and automatic ancestor-folder creation.

All 51 lifecycle and import commands remain intact. Another 15 commands archive
an imported login, verify its absence from the active vault, discard the client
cache, decrypt its archived password and notes after login, and restore it from
the archive. This baseline executes 66 official CLI commands. The CLI
uses bulk archive and unarchive API requests even for this single-item workflow.

The API-key extension preserves those 66 commands and adds 24 more. It obtains a
personal API key through an ordinary password bearer and master-password-hash
reauthentication, then supplies the client ID and secret only through the CLI
subprocess environment. It checks wrong-secret rejection, API login's locked
state, explicit password unlock, sync and decryption, and repeats the workflow
after discarding the client cache. Finally it rotates the key over HTTP, checks
that the CLI rejects the old secret, and unlocks and decrypts with the new key.
That baseline executes 90 real CLI commands. API login output alone is
never treated as proof that the vault unlocked.

The attachment extension preserves all 90 commands and adds 28. The official CLI
uploads empty, all-byte-value, and 2 MiB plus 37-byte fixtures, including a quoted
Unicode filename. Downloads go to private files and are compared byte for byte;
binary contents never pass through text stdout capture. The test edits the
parent item, trashes/restores it, discards the client cache, syncs and downloads
all attachments again, then deletes them. The complete suite executes 120 real
CLI commands. The Rust runner checks the cumulative 37, 51, 66, 92, and 120-command
milestones. Fixture and downloaded files remain inside private temporary
directories and are removed when the run returns, including on an error.

The personal-import HTTP checks follow the pinned relationship semantics:
existing owned folder IDs are reused, foreign or unknown IDs create fresh owned
folders, duplicate relationship keys use the last value, unknown folder indexes
clear the mapping, and unknown item indexes are ignored. Rejected batches must
leave items, folders, and revision unchanged under the standalone provider's
atomic transaction contract. This rollback requirement is a local guarantee;
the examined Vaultwarden handler saves entries sequentially without an enclosing
import transaction.

The lifecycle HTTP checks cover all eight bulk delete/restore aliases and all
four single/bulk archive/unarchive routes. They check exact response shapes,
empty sets, duplicate IDs, repeated transitions, malformed selections, and
authentication and ownership boundaries. Restore and archive lists are compared
without assuming result order. Archive actions change the account revision and
the owner's archive annotation while preserving the cipher revision, encrypted
fields, and trash state. Ordinary cipher edits retain an explicitly supplied
valid archive date, clear it when omitted or null, and retain the previous
annotation when the supplied date is invalid.

Mixed invalid selections also verify the standalone provider's atomic rollback.
This is a local guarantee: upstream iterates a deduplicated, unordered set and
can retain earlier writes when a later selection fails. These tests do not
assert upstream rollback or which selected item would be processed first.

Personal API-key HTTP checks cover lazy key creation, stable retrieval, key
rotation, password reauthentication and its PascalCase alias, exact `api` scope,
credential ownership, required device fields, and source-supported form aliases.
Present blank device values and nonnumeric device types follow upstream's
permissive parsing. API tokens advertise two-hour access and omit refresh tokens;
clients authenticate again with the API key when needed. Rotation must preserve
already issued API/password access and password refresh authority while blocking
new logins with the replaced secret. Profile and sync must never expose that
secret. Valid protected-email OTP and disabled-account administration are not
exercised by these password-account fixtures.

The portable attachment HTTP group covers all 11 upstream route patterns:
reservation, multipart upload, metadata, both legacy uploads, share replacement,
four deletion aliases, and bearerless capability download. It checks pending
slots, number-or-string sizes, inclusive one-MiB size leeway and mismatch
cleanup, empty and large opaque payloads, metadata key/name updates, ownership
and cipher binding, and missing/forged/misbound download capabilities. A valid
download capability intentionally needs no account bearer. Reservation leaves
revisions unchanged; upload and attachment deletion advance the account revision
while retaining the cipher revision. Trash retains attachment data and permanent
cipher deletion removes it. Organization sharing permissions and external
object storage are outside this personal-vault fixture. Pinned Vaultwarden
exposes no upload-renewal route.

The persistence test starts its own standalone server three times on a free loopback
port, using one temporary SQLite database. It verifies graceful shutdown,
encrypted account and owner data, folders, active and trashed ciphers, revisions,
and authentication sessions across restart. It also imports encrypted login and
secure-note fixtures and verifies their exact stored content and folder links
after restart. Bulk trash, restore, permanent deletion, archive annotations, and
removal of those annotations must survive restarts too. The personal API key,
its replacement after rotation, and previously issued API bearer sessions must
survive both restarts; the replaced key must remain rejected. Attachment metadata
and bytes, an unexpired original download capability, and deletion/cascade
cleanup are checked across restart too. Comparisons omit only regenerated
attachment URL values and retain every stored metadata field. Capabilities and
binary payloads never enter assertion output. Build `no-warden-server` first, or
set `NO_WARDEN_BIN` to its binary path. The test stops its child processes and
removes the temporary database on success or failure.

## Rust folder and account-key HTTP contracts

The portable folder checks use the Rust fixture library and two disposable
accounts. They exercise the existing seven folder routes, JSON decoding and
ownership boundaries, response projections, and cipher preservation on folder
deletion:

```sh
cargo run --locked -p no-warden-conformance --bin no-warden-http-conformance
BW_E2E_SERVER=http://127.0.0.1:8001 cargo run --locked \
  -p no-warden-conformance --bin no-warden-http-conformance
```

`BW_FOLDER_RECEIPT` and `BW_ACCOUNT_KEYS_RECEIPT` optionally name new private
result files for their respective groups. These HTTP
groups make five fixture logins in total; use a fresh disposable reference process before
this group and again before the complete CLI comparison. Its default login
limits remain unchanged. Other HTTP and persistence groups still use their
existing JavaScript tools.

The account-key group uses three fresh accounts and one password login for each.
Two accounts register without a key pair so initialization is exercised directly.
The fixture helper retains a valid generated pair privately for initialization;
it omits that pair from the actual registration request. Public-key lookup is
verified across accounts, while private retrieval always uses the bearer’s owner.
Initialization checks include positional JSON, opaque/empty values, and rejection
of an existing pair without any mutation. Both groups preserve response bodies,
credentials, and encrypted key material inside the process; receipts contain only
authored case names, statuses, and counts. No authentication or mutation is retried.

## Compare against upstream Vaultwarden

The same CLI suite runs unchanged against a disposable upstream Vaultwarden
instance with registration enabled:

```sh
BW_E2E_SERVER=http://127.0.0.1:8001 tools/e2e.sh
```

For a local upstream binary, start it with an isolated data directory:

```sh
DATA_FOLDER="$(mktemp -d)" ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8001 \
  WEB_VAULT_ENABLED=false SIGNUPS_ALLOWED=true vaultwarden
```

The complete HTTP suite includes no-warden-specific validation, token-rotation,
and transaction requirements. Its source-backed lifecycle groups can also run
unchanged against the disposable upstream instance:

```sh
BW_E2E_SERVER=http://127.0.0.1:8001 node --test \
  --test-name-pattern='bulk cipher lifecycle|cipher archive lifecycle' tools/server-tests.mjs
```

These groups use the upstream registration flow when necessary. They cover
personal ownership; organization-specific access and notification behavior
remain outside this test fixture. Run the comparisons in separate disposable
server processes: their test logins share the loopback IP's upstream login-rate
limit. No harness command retries authentication.

The four portable API-key groups can be selected individually using these test
name prefixes: `personal API-key management`, `personal API-key credentials`,
`personal API-key device`, and `personal API-key rotation`. Each group performs
fewer than ten identity requests, including fixture password logins. Start a
fresh disposable reference process for each group, preserving the database if
desired, and another fresh process before the complete CLI comparison. This
keeps upstream's default login rate-limit policy intact.

Select `personal attachments` to run the portable attachment HTTP group against
the upstream instance. Use a fresh disposable process after other login-heavy
groups; the attachment group creates only two password-login fixtures.

The dated results below record the earlier client compatibility milestones. The
Rust runner preserves their command sequence and cumulative checks.

The initial compatibility baseline passed on 2026-10-18: the same 37 official
CLI `2026.10.0` commands passed against both no-warden and upstream Vaultwarden
`1.37.4`. The upstream binary came from the official
`ghcr.io/dani-garcia/vaultwarden` image, pinned by digest
`sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`
(source revision `7c188967e7a467b19b2757bc3326f9cf3ccae327`). The standalone
HTTP suite also passed all 20 tests, and the standalone restart durability check
passed. These checks establish the tested personal
vault lifecycle; they do not establish compatibility with every Bitwarden API.

The personal-import follow-up passed on 2026-10-18: the same 51 official CLI
commands passed against no-warden and the actual Vaultwarden `1.37.4` binary
above, including JSON/CSV imports and decryption after discarding the client
cache. The expanded standalone HTTP suite passed all 27 tests, and imported
encrypted items and folder links survived the standalone restart check.

The bulk/archive follow-up passed on 2026-10-18: all 66 official CLI commands
passed against both no-warden and the same actual Vaultwarden `1.37.4` binary.
The identical portable HTTP groups passed all 10 tests against upstream, covering
the 12 lifecycle route patterns. The complete standalone HTTP suite passed all
38 tests, and its bulk changes and archive annotation removal survived two
graceful restarts.

The personal API-key follow-up passed on 2026-10-18: all 90 official CLI commands
passed against both no-warden and that actual Vaultwarden `1.37.4` binary,
including password unlock, fresh-cache decryption, and rotation. The four
portable API-key HTTP groups passed all 14 tests upstream in isolated processes
with unchanged rate-limit settings. The full standalone HTTP suite passed all
52 tests, and keys, rotation, and API bearer sessions survived both graceful
restarts.

The attachment follow-up passed on 2026-10-18: all 118 official CLI commands
passed against both no-warden and the same actual Vaultwarden `1.37.4` binary,
including empty, all-byte, and 2 MiB + 37-byte fixtures, a Unicode filename,
ordinary item editing, trash/restore, and fresh-cache downloads. The portable
attachment HTTP group passed all nine tests upstream. The local full HTTP suite
passed all 61 tests before the narrow missing-download-token status correction;
the final focused attachment group then passed all nine tests on the corrected
backend. Attachment metadata and bytes, an unexpired download capability, and
deletion/cascade cleanup were verified across two graceful restarts.

The Rust `fixture` module derives the standard server password hash and wrapped
user key locally and registers a fresh account through the ordinary registration
flow. `BW_E2E_EMAIL` and `BW_E2E_PASSWORD` configure that fixture for a complete
CLI run. The retained `tools/seed-account.mjs` helper supports the JavaScript
HTTP/persistence fixtures and standalone account creation until their migration.
For standalone seeding, supply `BW_E2E_EMAIL`, `BW_E2E_PASSWORD`, and optionally
`BW_E2E_SERVER` in the environment, then run `node tools/seed-account.mjs`.

The account-key extension preserves the original 118 commands and adds two
fingerprint commands, for 120 total. `bw get fingerprint me` reads the cached
public key; `bw get fingerprint <user-id>` requests that user’s public key from
the server. The runner requires the two fingerprints to match without printing
either fingerprint or the account ID. This is direct client evidence for the
public-key read flow, with no captured route trace or full-parity claim.
