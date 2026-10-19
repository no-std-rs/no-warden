# Real-client compatibility checks

The compatibility harness requires Linux, Rust 1.89 or newer, Node.js 22 or newer,
OpenSSL, util-linux `prlimit`, a `kill` utility, and the pinned official Bitwarden
CLI. This requirement applies to these test tools; the crate and standalone
server have separate platform requirements.

The host-only `no-warden-conformance` Rust crate runs the default CLI suite,
including private subprocess capture, encrypted account fixtures, and disposable
loopback TLS. `tools/e2e.sh` invokes it through Cargo. Rust HTTP groups cover
folder, account-key, profile/avatar, equivalent-domain, and device contracts; the existing HTTP,
restart-persistence, and client-inventory checks still use JavaScript; the broader migration remains
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
all attachments again, then deletes them. That baseline executes 118 real CLI
commands; the fingerprint extension below brings the current total to 120.
The Rust runner checks the cumulative 37, 51, 66, 92, and 120-command
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

## Rust personal-account and device HTTP contracts

The portable folder checks use the Rust fixture library and two disposable
accounts. They exercise the existing seven folder routes, JSON decoding and
ownership boundaries, response projections, and cipher preservation on folder
deletion:

```sh
cargo run --locked -p no-warden-conformance --bin no-warden-http-conformance
BW_E2E_SERVER=http://127.0.0.1:8001 cargo run --locked \
  -p no-warden-conformance --bin no-warden-http-conformance -- --suite personal
# Restart the disposable reference before running the device group:
BW_E2E_SERVER=http://127.0.0.1:8001 cargo run --locked \
  -p no-warden-conformance --bin no-warden-http-conformance -- --suite devices
```

By default the binary runs folders, account keys, profile/avatar, equivalent
domains, devices, device tokens, authentication requests, responses, login, then
registration, account security, KDF and password changes: 104 cases. The six-case
WebAuthn credential-metadata group is selected separately. `--suite personal` selects the first four groups;
`--suite devices` selects discovery; `--suite device-tokens` selects token routes;
`--suite auth-requests` selects authentication-request creation and reads.
`--suite auth-responses` selects approval, rejection and public response polling.
`--suite auth-login` selects request-based password grants and consumption.
`--suite registration` selects the two-step no-SMTP registration flow.
`--suite account-security` selects password verification and security-stamp renewal.
`--suite account-kdf` selects nested client-KDF changes.
`--suite account-password` selects password changes and previous-stamp authorization.
`--suite webauthn-credentials` selects read-only WebAuthn credential metadata and
its current-device/previous-stamp guards; it is separate from `--suite all`.
`--suite personal-vault-purge` separately selects six destructive disposable-vault
checks; it is also excluded from `--suite all`.
`--suite account-password-cli` separately runs the ten-command fresh-cache password
change proof and is excluded from `--suite all`.
`--suite account-kdf-cli` separately verifies fresh-cache CLI decryption after an
HTTP KDF change; it is excluded from `--suite all` and requires the locked CLI.
Individual selectors are `folders`,
`account-keys`, `profile`, and `domains`; `--suite all` is the default.
Invalid arguments return exit code 2 without echoing supplied values.
`BW_FOLDER_RECEIPT`, `BW_ACCOUNT_KEYS_RECEIPT`, `BW_PROFILE_RECEIPT`,
`BW_DOMAINS_RECEIPT`, `BW_DEVICES_RECEIPT`, `BW_DEVICE_TOKENS_RECEIPT`,
`BW_AUTH_REQUESTS_RECEIPT`, `BW_AUTH_RESPONSES_RECEIPT`, `BW_AUTH_LOGIN_RECEIPT`,
`BW_REGISTRATION_RECEIPT`, `BW_ACCOUNT_SECURITY_RECEIPT`, `BW_ACCOUNT_KDF_RECEIPT`,
`BW_ACCOUNT_PASSWORD_RECEIPT`, `BW_WEBAUTHN_CREDENTIALS_RECEIPT`, and `BW_PURGE_RECEIPT`
optionally name new private result
files for their respective groups. Existing paths are
rejected; files are created with mode 0600 and contain authored case names,
statuses, request counts, and login counts, without request or response values.
The personal groups make nine fixture logins. Devices make six identity
requests: five login attempts (four successful and one deliberately rejected)
and one refresh. Run these selections in separate fresh disposable reference
processes to stay within its unchanged default ten-login limit. Use another
fresh reference process for the complete CLI comparison. The adapter's CI job
runs all 104 HTTP cases together; do not run that combined selection against one
reference process with default limits.
Other HTTP and persistence groups still use their
existing JavaScript tools.

The account-key group uses three fresh accounts and one password login for each.
Two accounts register without a key pair so initialization is exercised directly.
The fixture helper retains a valid generated pair privately for initialization;
it omits that pair from the actual registration request. Public-key lookup is
verified across accounts, while private retrieval always uses the bearer’s owner.
Initialization checks include positional JSON, opaque/empty values, and rejection
of an existing pair without any mutation. All groups preserve response
bodies, credentials, and encrypted key material inside the process. Receipts
contain authored case names, statuses and counts, plus the public catalog
fingerprint for domains. No authentication or mutation is retried.

The profile/avatar group adds two disposable accounts and one password login
per account. It checks both `PUT` and `POST /api/accounts/profile` and
`PUT /api/accounts/avatar`. Names preserve empty strings, whitespace, control
characters, and Unicode without normalization, subject to a 50-byte UTF-8 limit.
Present avatar colors require exactly seven UTF-8 bytes, without hexadecimal or
`#` validation. `{}`, `{"avatarColor":null}`, and `[null]` clear the avatar;
`[]` rejects with 422. The suite also checks schema/syntax errors, ignored fields,
unauthenticated requests, repeated writes, and full account/vault snapshots.
Full profile responses remain adapter-built; the core provides mutation request
models and provider-driven services. That milestone also passed the unchanged
120-command CLI suite; its upstream 120-command baseline was verified in the
preceding account-key chunk.

The domain group uses two fresh accounts and one password login per account.
It exercises `GET`, `POST`, and `PUT /api/settings/domains`, plus the sync domains
projection. It checks the complete ordered 91-group catalog and public
fingerprint, exclusion flags, opaque custom strings, empty groups, order and
duplicates, and negative/unknown/duplicate signed `i32` IDs. Object omission/null
resets each array; positional input places exclusions before custom groups.
`[null,null]` clears both, `[]`/`[null]` return 422, and surplus elements return 400.
Both aliases return exactly `{}` and advance the revision even for identical
updates. Whole-profile/vault/revision snapshots check owner isolation and
nonmutating errors.

Sync query checks include boolean aliases, empty/bare true, decoded names,
leading dotted/bracketed roots and suffixes, first matching value, and invalid
values returning 422. Missing or invalid bearers return 401 before query parsing.
No login or mutation is retried. The optional domain receipt contains the public
catalog count/fingerprint as well as case names, statuses and counts; account
settings and response bodies remain private.

The core supplies indexed `DomainSettingsData` and `GlobalDomainCatalog` views,
configurable `DomainSettingsRequest` capacities, provider-driven atomic writes,
and streaming typed GET/sync serializers. The host uses its own uncapped vectors
and an authoritative owner-keyed settings table, retaining the existing
transport cap. Complete sync responses remain adapter-built. Notifications and
shared transport/error gaps remain unimplemented; the unchanged CLI suite adds
no domain mutation or settings request attribution.
An initial domain-enabled build passed all 120 CLI commands before the final
query/authentication-order corrections; the required client job reruns the same
harness for the final head.

The final HTTP receipts pass against both the adapter and official Vaultwarden
`1.37.4` with the same counts:

| Rust HTTP group | Cases | Counted requests | Password logins |
| --- | --- | --- | --- |
| Folders | 8 | 220 | 2 |
| Account keys | 8 | 242 | 3 |
| Profile/avatar | 8 | 425 | 2 |
| Equivalent domains | 8 | 530 | 2 |
| Personal subtotal | 32 | 1417 | 9 |

The eight device cases also pass against both servers: 199 counted requests,
including the six identity requests described above. They cover public header
decoding and exact identifier matching, owner-only list/single projections,
percent-decoded path guards, metadata retention on repeated login, API-key device
registration, refresh identity, and failed-login/authentication boundaries.
The receipt distinguishes successful logins, attempted logins, identity requests,
and refresh requests. Their combined total with the personal groups is 40 cases
and 1616 requests, measured in separate reference processes. The token group
adds eight cases and 383 requests with three successful password logins, making
the device-enabled subtotal 48 cases and 1999 requests. Select `--suite device-tokens` in
a separate fresh reference process: its 28 valid public clears stay below the
unchanged unauthenticated burst limit of 50; rejected path guards do not enter
that handler. The adapter does not yet implement the reference rate controls.

Device identifiers in headers and login forms remain opaque. Authenticated
lookup paths accept ASCII letters, digits and hyphens after percent-decoding;
they are not UUID paths. List entries have ten fields and single responses
seven. Authentication-request approval and polling now have their own comparison
group. Trust/key setup, enabled push relay and notification lifecycles remain
unimplemented by the adapter; the borrowed pending projection is a narrower
contract than the complete authentication-request lifecycle.

The token group checks POST/PUT update and clear aliases. Update paths have
normal device syntax guards, but the verified session's device is the mutation
target. Required `pushToken` values remain opaque, including empty strings;
unknown fields are ignored, and one-element positional input is accepted.
Authentication precedes path validation, which precedes JSON validation.
Clears are public, ignore bearer/body input, and return empty 200 without
clearing stored tokens when push is disabled. All four success responses have
empty bodies, not JSON null. Hidden token/activity effects are covered separately
by SQLite tests rather than inferred from device projections.

The core exposes `DevicePushStorage` with ordered save/relay and clear/unregister
hooks. A failed relay registration retains the saved token; a repeated identical
token skips both save and relay. Enabled clear semantics are provider-tested,
including clearing every owner with the same identifier and unregistering only
the first device's optional push ID. The adapter uses disabled push and makes no
outbound relay request. Enabled relay interoperability remains open.

Login requests are included in the request counts; fixture registrations are
excluded. These receipts do not establish captured CLI route traces or complete
upstream API parity.

The authentication-request group passes eight cases against both actual servers:
273 requests, five successful logins and 33 decoded creation attempts. Run
`--suite auth-requests` in its own fresh reference process. Its optional private
receipt also records the decoded creation count; schema rejections do not enter
the handler. The prior local baseline passed 72 cases and 3038 requests. Preserve
separate reference processes rather than combining groups across default limits.

This group checks public creation for existing owner/device/type pairs and the
three authenticated read/list routes. It includes opaque non-UUID device IDs,
optional raw device-type headers with fallback 14, eleven-field projections,
created false versus pending null, positional/schema cases, owner/UUID guards,
repeated creation and the latest pending two-field metadata in device lists.
Access codes and internal identities never enter authentication-request responses.
Actual peer IP and canonical advertised origin are adapter inputs; configurable
trusted-proxy forwarding remains unimplemented. Auth-request login, notifications
and expiry/rate controls remain open.

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


The `--suite auth-responses` comparison uses another fresh reference process.
Its eight cases cover approval, rejection, repeated non-consuming polling,
verified response-device and owner boundaries, opaque/nullable/positional input,
JSON and path guards, code query decoding and duplicate selection, raw client
header defaults, ignored bearers, alternate-loopback IP rejection, and pending
projection transitions. The fixture passes against both actual servers with 322 requests and four
password logins per target. Eleven decoded creations plus 33 guard-valid polls
make 44 public handler entries, preserving the reference's unchanged burst
limit of 50; six path/query guard rejects do not enter that handler. Set `BW_AUTH_RESPONSES_RECEIPT` to a new path for a
private receipt containing only authored case names and counters. The selected group passes with exit zero against both servers; no CLI
auth-request login or route trace is inferred from this suite.


`--suite auth-login` uses a fresh reference process and real IPv4 loopback peers
for independent login budgets. It checks approved access-code login, new device
binding, refresh authority, replay/pending/foreign/rejected requests, wrong
proof/IP, opaque and empty values, form aliases/required guards, exact scope and
absence of password fallback. The final case waits at least 301 seconds after a
real request's creation response to verify expiry. No clock override, request
retry or rate-limit configuration change is used. `BW_AUTH_LOGIN_RECEIPT` writes
only authored case names and counters to a new private file. Both servers passed
all eight selected cases with 444 counted HTTP requests each: 43 identity requests
(two ordinary logins, seven request-based logins, two refreshes and 32 rejects),
12 public creations and 12 response polls. The expiry case observed 301 seconds.
These HTTP results
are separate from the unchanged official CLI baseline and establish no CLI
request-login command or captured route trace.


`--suite registration` directly exercises verification and finish without the
fixture helper's legacy-route fallback. It covers token transport and claims,
legacy and nested credential aliases, claim-only names and UTF-8 limits, syntax
and schema guards, proof rejection, KDF failure/retry, duplicate finish and
account isolation. The token and credential values remain private in memory;
`BW_REGISTRATION_RECEIPT` selects a new private file containing authored case
names and counters. A fresh reference process uses direct per-case loopback
peers to preserve its default unauthenticated and login limits. This selected
HTTP comparison establishes no CLI registration command or captured route trace.

Both servers passed the selected registration suite with 541 counted requests:
69 verification, 64 finish, ten prelogin and nine successful password logins.
At most 44 conservative public attempts and nine identity requests reach one
peer's budget. The final official CLI `2026.10.0` baseline separately passed
120 commands against each server.

The registration milestone combined local run passed all 80 cases with 3579 counted HTTP requests.

The `account-security` selection uses a fresh reference process and two disposable
accounts. Its eight cases cover required password verification, exact personal
policy output, JSON/proof/authentication guards, stamp renewal, invalidated
access/refresh tokens, owner-only device cleanup, preserved API-key credentials
and authentication requests, and repeated positional renewal/recovery. It makes
nine identity requests: eight successful grants and one rejected old refresh.
Run it separately from the other reference groups and the CLI regression; no
reference limits are changed. `BW_ACCOUNT_SECURITY_RECEIPT` records only case
status and numeric counts in a new mode-0600 file. No CLI command or route trace
is inferred from this direct HTTP selection.

The account-security milestone passed all 88 cases with 3871 counted HTTP
requests, including real authentication-request expiry and modern registration.
A fresh official Bitwarden CLI `2026.10.0` regression also passes all 120 commands
against each server. It adds no account-security CLI command or captured route trace.

The KDF HTTP selection uses a fresh reference process. It checks nested-only
authentication/unlock data, exact aliases and positional fields, proof/guard
precedence, matching salts/KDF values, signed thresholds, session revocation,
device preservation and opaque future configurations. The separate focused CLI
selection uses another fresh reference: it creates a genuinely encrypted item,
changes PBKDF2 from 600,000 to 700,000 iterations by HTTP while rewrapping the same
user key, then verifies login, lock/unlock, sync and decryption from a fresh CLI
cache. It invokes nine official commands and keeps the original 120-command
regression separate. `BW_ACCOUNT_KDF_CLI_RECEIPT` stores only redacted counts in a
new mode-0600 file. Registration bootstrap and CLI-internal requests are excluded
from its direct HTTP counts; no CLI-posted KDF route or captured trace is claimed.

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


The focused password CLI comparison passes ten commands against both actual
servers with official CLI 2026.10.0. HTTP rewraps the same user key under the new
password before a fresh client cache starts. The CLI rejects the old password,
then logs in, locks/unlocks, syncs and decrypts the preexisting item with the new
password. Seven direct HTTP requests and one direct password grant exclude
registration bootstrap and CLI-internal HTTP. No password POST trace is claimed.
`BW_ACCOUNT_PASSWORD_CLI_RECEIPT` selects a private counts-only receipt.


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

## WebAuthn credential metadata comparison

Run `--suite webauthn-credentials` against a fresh disposable server. It is
separate from the default 104-case selection and the required CI invokes both.
The six authored cases cover exact empty-list projection, authentication,
methods/paths/ignored queries, state preservation, password/API historical
bearers, owner/device isolation, same-ID device recreation and a real 121-second
exception expiry with one revision cleanup. The verified identity budget is eight
requests: six successful grants and two rejected refresh attempts, with three
and five requests on the two direct loopback peers. Shared account registration
bootstrap is not included in the direct HTTP counter. No rate configuration or forwarded-IP override is used.

`BW_WEBAUTHN_CREDENTIALS_RECEIPT` is a new private mode-0600 file containing only
authored case names, status and counters. All six cases pass against the actual
adapter and Vaultwarden 1.37.4: 129 counted HTTP requests per server and a real
121-second wait, excluding two shared fixture registrations. The unchanged
CLI120 baseline regression does not establish a GET `/api/webauthn` call, passkey
login or key rotation; see the [source notes](../docs/api-parity.md#webauthn-credential-metadata-subset).

## Personal vault purge comparison

`--suite personal-vault-purge` selects the Rust proof, cleanup and preservation
checks for `POST /api/ciphers/purge`. Run the selected reference comparison in a
fresh disposable Vaultwarden process without changing its limiter policy. The
suite uses cryptographically valid disposable accounts and records no passwords,
proofs, attachment capabilities or vault contents. Its six authored cases cover authentication/proofs, JSON/method guards,
organization-query isolation, complete personal cleanup, repeated empty/unknown
query operations, and preserved authority/recovery. All six pass against the
actual adapter and Vaultwarden 1.37.4 with 327 counted HTTP requests each. The
verified identity budget is six requests on one direct loopback peer: five
successful grants (including API-key login) and one refresh. Three auth-request
creations, three public polls and eight successful purges are included; two shared
fixture registrations are excluded from the direct HTTP counter. The tests
confirm empty server lists, foreign attachment bytes remain intact and a fresh
post-purge cipher decrypts through the Rust fixture. Fresh URLs for three owned
and one foreign attachment return exact bytes before purge; owned URLs then
return 404 while the foreign URL remains byte-exact 200, all within 30 seconds
of issuance. Physical BLOB/grant deletion has separate local SQL proof. Rate settings
and forwarded-IP overrides are unchanged.
`BW_PURGE_RECEIPT` names a new private mode-0600 counts-only result file.

This is personal purge, preserving account credentials, sessions, devices,
settings and authentication requests. The separate organization-query handler
remains unimplemented. A fresh official CLI 2026.10.0 regression passes all
120 commands against both actual servers; it is independent and supplies no purge
command caller or request trace. See the
[protocol references](../docs/protocol.md#personal-vault-purge).

## Personal account deletion comparison

`--suite account-deletion` selects explicit disposable-account checks for
`DELETE /api/accounts` and `POST /api/accounts/delete`. Run it against a fresh
reference process under unchanged rate limits. It is separate from the default
104-case selection, WebAuthn credential metadata and personal-vault purge.
Auth-request fixtures are excluded because release 1.37.4 and the pin differ in
that cleanup. All six cases pass against the adapter and actual Vaultwarden
1.37.4, each with 257 counted HTTP requests. Six identity requests consist of
three successful password logins, two refresh attempts (one success), and one
rejected old API grant; the maximum is six attempts on one direct peer under
unchanged defaults. Three fixture registrations across two emails are excluded.
The suite deletes two account IDs, checks both empty-200 aliases and rejected
authentication/proof/schema/method inputs, and confirms ignored body/query
overrides cannot select another owner. Each deletion obtains and reads three
fresh owned attachment capabilities and one foreign capability, then checks
owned 404 and byte-exact foreign 200 within 30 seconds. The receipt selected by
`BW_ACCOUNT_DELETION_RECEIPT` records only authored names and counters in a
new private file.

Public HTTP authority/capability outcomes and local physical SQL deletion are
separate evidence. Re-registering the same email must produce a new account ID,
while prior sessions, refresh tokens and the old account's API client identity
grant no access. A fresh official CLI 2026.10.0 regression also passes all
120 commands against both actual servers; it supplies no account-deletion
caller or route trace. The generated SDK request is source attribution only.
