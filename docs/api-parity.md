# Full API parity

Full Bitwarden/Vaultwarden API parity is the delivery goal. The standalone
SQLite vault is a conformance adapter; extending that example is not a substitute
for the reusable allocation-free API and business-logic contracts.

The inventory pins the server source, the shipped CLI, and its bundled SDK.
Upstream method/path declarations, aliases, query shapes, ranked handlers, and
conditional registrations remain separate facts. Alternative configurations are
not counted as routes mounted simultaneously. UI-related and auxiliary routes
remain visible rather than disappearing from the inventory.

Coverage has separate meanings:

- Route recognition identifies an operation; an incidental match as an item ID
  does not implement a reserved action such as `/api/ciphers/import`.
- Typed contracts preserve supported request/response fields without allocation.
- Business behavior applies upstream validation, authorization, and mutation
  semantics through host-provided services.
- HTTP verification exercises the documented contract, including negative cases.
- Client verification names the client version and exercised flow. A CLI cache
  read does not prove the corresponding HTTP read endpoint was called.

An endpoint with one supported request variant remains partial when other
upstream variants are missing. A `404`, stub, disabled feature, or arbitrary JSON
round trip is not full parity. Unresolved dynamic client calls remain explicit
work, and no successful personal-vault suite closes the full parity goal.

Every implementation PR starts from current main, updates coverage evidence,
runs the relevant real client and upstream comparisons, and passes all required
checks plus a clean current-head Codex review through Runnerless. Merge using
squash with an expected-head guard, then continue to the next chunk. The core
must remain `no_std` without `alloc` throughout that cycle.

## Pinned evidence

| Evidence | Revision and scope |
| --- | --- |
| [Server routes](../compatibility/vaultwarden-routes.json) | [Vaultwarden `58a980f`](https://github.com/dani-garcia/vaultwarden/tree/58a980f850464f7d9cdc99a765df36f0a3308b91): 294 declared handlers, 288 method/path templates, seven mounts, three catchers |
| [Shipped client calls](../compatibility/cli-routes.json) | [CLI `2026.10.0`, `b449ac1`](https://github.com/bitwarden/clients/tree/b449ac1d255784380d75ef026343198891286be7): 370 request-construction records, 305 distinct method/path pairs, 41 command registration variants |
| Bundled SDK source | [`c5e53d3`](https://github.com/bitwarden/sdk-internal/tree/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6), resolved from the upstream clients build lock and SDK registry metadata |
| [Current coverage](../compatibility/no-warden-coverage.json) | 76 routed patterns, 41 with typed requests, 64 with reusable core service behavior; each carries its narrower limits |
| Runtime CLI comparison | Official CLI `2026.10.0`: all 120 commands pass against the adapter and official Vaultwarden `1.37.4`, including attachment byte round trips and authenticated public-key fingerprints. This runtime baseline differs from the inventoried Vaultwarden main revision above. |

The coverage ledger joins all 294 declared upstream handlers to an explicit
status: 73 partial and 221 unimplemented. Query/rank/configuration
variants retain separate upstream identities, and path parameter renames have
explicit mappings. Three additional local aliases are tracked as extensions;
they do not replace the corresponding upstream endpoints.

32 local patterns have some typed response representation, including
the domain settings projections and empty mutation response, explicit API-key
responses, and attachment responses. Bulk cipher lists use the generic `ListResponse`
wrapper; a complete borrowed cipher response model is still absent, and single
archive responses remain host-built JSON.

The ledger records positive or restart HTTP evidence for 68 patterns, negative
HTTP evidence for 67, 133 named HTTP cases, and 31 CLI command patterns. These are
distinct coverage dimensions; no route has a captured CLI request trace or a verified
full-parity status.

The client catalog is an overapproximation of shipped code, not a proof that all
those operations are reachable from CLI commands. Its 34 open obligations retain
dynamic destinations, typed call-graph questions, feature flags, and SDK branches.
The 22 routes served by local `bw serve` are a separate catalog; third-party,
Key Connector, provider-RPC, and server-supplied storage calls have explicit roles.
These categories are not added to a backend-completion percentage.

The current supported subset has not established full upstream parity for any
operation's entire contract. Every full-parity status remains false. Tested flows
remain useful evidence, with positive and negative HTTP tests and CLI command
references recorded separately. `POST /api/ciphers/import` now has a dedicated
classifier, typed batch contract, reusable validation and provider boundary,
atomic SQLite implementation, and passing real-client personal import scenarios.
The CLI tests cover JSON types 1–4 and CSV types 1–2; they do not close the whole
import/export family. Additional source-proven gaps remain in every API family;
the inventory is not a plan to stop after import or personal-vault APIs.

The folder compatibility chunk improves seven existing routes, without adding
route patterns or closing the folder family's full-parity status:

| Method and route | Personal folder contract |
| --- | --- |
| `GET /api/folders` | List only the authenticated owner's folders |
| `POST /api/folders` | Create a fresh folder ID; ignore a supplied body ID |
| `GET /api/folders/<id>` | Read the exact owned folder ID |
| `PUT /api/folders/<id>` | Replace the name without changing the path ID |
| `POST /api/folders/<id>` | Same update contract |
| `DELETE /api/folders/<id>` | Clear folder associations and remove the folder; empty 200 |
| `POST /api/folders/<id>/delete` | Same deletion contract |

The [pinned handlers and request model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/folders.rs#L14-L110)
accept arbitrary string names and ignore the optional body ID during CRUD. Empty,
Unicode, future-format, and larger-than-one-MiB names already pass direct Rust
HTTP comparisons against both servers. The separate borrowed
`FolderWriteRequest` models `name` and an optional string `id`. Its owned host
decoding guard preserves escaped strings and duplicate-known-field errors,
then borrows those decoded fields into the allocation-free API. IDs of a type
other than string or null are rejected; omitted, null, empty, and other string
IDs cannot choose storage identity. Unknown fields may remain in the adapter's
private document, while every folder response surface projects the
[upstream four-field model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/folder.rs#L52-L62):
`id`, `revisionDate`, `name`, and `object: "folder"`.

`FolderNamePolicy::Encrypted` remains the default for the existing core methods.
The new `create_folder_with_policy` and `update_folder_with_policy` methods permit
an explicit `FolderNamePolicy::Opaque`, which accepts any borrowed string without
interpreting an encryption envelope or applying the encrypted-field byte ceiling.
The adapter selects that policy for these CRUD routes; import validation is
unchanged. UUID syntax remains a host path guard rather than a restriction on
generic core storage IDs. The
[pinned UUID guard](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/macros/src/lib.rs#L15-L27)
preserves exact spelling and case. Malformed path UUIDs return 422; a valid but
missing or foreign folder returns 400 with `Invalid folder`. Body schema errors
classified as data errors return 422, while syntax/end-of-input errors return
400, following the [Rocket JSON guard](https://api.rocket.rs/v0.5/src/rocket/serde/json.rs.html#196-210).
Successful deletion returns empty 200 through upstream's `EmptyResult` and
[Rocket unit response](https://api.rocket.rs/v0.5/rocket/struct.Response.html#method.new).

The [pinned deletion model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/folder.rs#L101-L110)
advances the owner's account revision and deletes folder associations without
saving linked ciphers. The adapter now preserves active and trashed cipher
revisions and all unrelated stored fields. Its storage regression snapshots
documents and persistence columns, archive annotations, attachment metadata and
all encrypted bytes, existing download grants, loose items, and foreign vault
state. Existing injected revision-write failures and focused HTTP error tests
verify local rollback; these atomic provider guarantees are distinct from a
complete upstream failure-semantics proof.

The eight Rust folder cases pass against both the adapter and official Vaultwarden
`1.37.4`, with 220 requests and two logins per run. The required client job reruns
the 120-command CLI suite against the adapter; the separate reference comparison
is documented in [the test tools](../tools/README.md).
These focused comparisons do not establish a full-parity
status. Notifications, WebSocket/push updates, complete error
envelopes, content-type handling, and transport limits remain open. The host's
16-MiB request cap differs from the
[pinned 20-MB JSON limit](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/main.rs#L575-L578).
Formal comparison and CLI trace receipts remain separate requirements, and the
full API delivery goal remains open.

The
[pinned Vaultwarden personal import handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L613-L678)
and the
[pinned CLI submission](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/importer/src/services/import.service.ts#L468-L481)
use the same route. `ImportRequest` gives embeddings explicit decoder capacities;
`ImportView` lets hosts borrow batches of their own size. `ImportStorage`
requires a stable owned-folder snapshot and an atomic batch commit. The adapter
preserves upstream folder-index tolerance and last-entry-wins relationships,
while enforcing stronger ownership/current-key validation and rollback guarantees.
The upstream source saves sequentially, so local atomicity is recorded as an
adapter guarantee rather than upstream behavioral equivalence. See
[verified compatibility](compatibility.md) for the exercised types and limits.

The cipher lifecycle subset adds the following personal-vault contracts.
All admin-named aliases keep the same ownership checks; organization permissions
remain outside this subset.

| Action | Method and `/api` route | Request and success response |
| --- | --- | --- |
| Permanent bulk deletion | `DELETE /ciphers`, `POST /ciphers/delete`, `DELETE /ciphers/admin`, `POST /ciphers/delete-admin` | `{"ids":[...]}`; empty 200 |
| Bulk trash | `PUT /ciphers/delete`, `PUT /ciphers/delete-admin` | `{"ids":[...]}`; empty 200 |
| Bulk restore | `PUT /ciphers/restore`, `PUT /ciphers/restore-admin` | `{"ids":[...]}`; cipher list |
| Archive/unarchive | `PUT /ciphers/<id>/archive`, `PUT /ciphers/<id>/unarchive` | No body; cipher response |
| Bulk archive/unarchive | `PUT /ciphers/archive`, `PUT /ciphers/unarchive` | `{"ids":[...]}`; cipher list |

The [pinned server helpers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L1876-L1972)
deduplicate IDs without prescribing order. The adapter preserves that success
behavior and the bulk missing/inaccessible-member status of 400 while providing
atomic persistence; upstream errors may occur after partial writes. Existing
single-item lifecycle handlers retain their earlier 404 policy. Archive/unarchive
changes the acting user's archive metadata and account revision while leaving
the cipher revision intact, as the
[pinned archive model](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/archive.rs#L35-L83)
shows. These contracts do not establish full organization, notification,
attachment-cleanup, or error-semantics parity.

The shipped
[archive service](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/vault/services/default-cipher-archive.service.ts#L64-L89)
constructs bulk archive/unarchive requests for individual CLI archive/restore
commands. Shared delete/trash/restore methods choose TypeScript or SDK
construction using `pm-27632-cipher-crud-operations-to-sdk`; their presence is
not proof of a CLI command that selects multiple items. The earlier 66-command
baseline passed against both servers, including archive/unarchive after
discarding the local cache, and remains in the current suite. The same 10 portable
HTTP tests pass against the upstream release and cover all 12 lifecycle route
patterns. Bulk changes and archive state survive two graceful restarts.
Full-parity statuses and the formal comparison/trace receipt requirements remain
unchanged.

The equivalent-domain chunk adds three previously unimplemented pinned handlers:

| Method and route | Reusable settings contract |
| --- | --- |
| `GET /api/settings/domains` | Custom groups plus all global catalog groups with computed exclusion flags |
| `POST /api/settings/domains` | Replace both settings arrays and advance account revision; return `{}` |
| `PUT /api/settings/domains` | Same replacement contract |

The [pinned settings handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/mod.rs#L64-L146)
preserve arbitrary domain strings, including empty strings, controls and Unicode,
without normalization. Group/string order and duplicates survive unchanged.
Exclusion IDs are signed `i32` values; negative, unknown and duplicate IDs are
retained. Missing/null object fields reset their corresponding arrays to empty.
Positional input places exclusions first and custom groups second: `[null,null]`
clears both, `[]` and `[null]` return 422, and surplus sequence elements return
400. Repeated writes still advance the account revision.

`DomainSettingsRequest` has independently configurable exclusion/group/domain
capacities for embeddings. The host instead lends its owned vectors through
`DomainSettingsData`, introducing no array-count or string-size cap beyond its
existing transport limit. `DomainSettingsStorage` returns a borrowed GAT read
view and atomically replaces both arrays and the account revision. Its dedicated
owner-keyed SQLite table is authoritative; registration extras cannot inject
settings. Keys, credentials, sessions, vault records and foreign settings remain
unchanged, including on provider failure.
`VaultService::update_domain_settings` returns an explicit
`DomainSettingsUpdateResponse` that serializes as `{}`.

`VaultService::domain_settings` takes an adapter-supplied `GlobalDomainCatalog`;
the allocation-free core embeds no JSON catalog. `DomainSettingsResponse`
serializes the indexed views directly. `DomainProjection::All` includes all 91
catalog entries with exclusion flags; `DomainProjection::Sync` omits flagged
groups and preserves retained order. The host's copied
[pinned catalog](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/static/global_domains.json)
is source-hashed and its ordered public fingerprint matches the reference.
The entire sync response remains adapter-built, so sync gains no whole-response
typed model or reusable-service coverage flag.

For sync, missing/false `excludeDomains` includes settings and true returns
`domains:null`. Tested Rocket-compatible parsing accepts case-insensitive
`true`/`on`/`yes` and `false`/`off`/`no`, plus empty/bare true, decoded query names,
leading dotted/bracketed root names and suffixes. The first matching root value
wins. Invalid tested values return 422 after authentication; missing or invalid
bearers still return 401. These query edges are HTTP evidence, without a new CLI
domain mutation or captured settings request claim.

All eight domain HTTP cases pass against the adapter and official Vaultwarden
`1.37.4`: 530 counted requests including two password logins. The four-group suite
passes 32 cases with 1417 requests and nine logins, excluding fixture
registrations. An initial domain-enabled build also passed the unchanged
120-command CLI flow; the required client job checks the final query/authentication
corrections with the same harness.
SyncSettings notifications, shared error/content-type/transport limits, and full
settings/API parity remain open. All full-parity flags remain false.

The profile/avatar chunk adds three previously unimplemented pinned handlers:

| Method and route | Reusable metadata contract |
| --- | --- |
| `PUT /api/accounts/profile` | Store the exact name, up to 50 UTF-8 bytes |
| `POST /api/accounts/profile` | Same profile-name update contract |
| `PUT /api/accounts/avatar` | Clear an absent/null color, or store a string of exactly seven UTF-8 bytes |

The [pinned handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L510-L563)
preserve empty, whitespace, control, and Unicode names without trimming or
normalization. Avatar strings need no hexadecimal format or `#` prefix.
`ProfileUpdateRequest` and `AvatarUpdateRequest` borrow their strings;
`VaultService::update_profile` and `update_avatar` validate before invoking
`AccountProfileStorage`. The provider atomically changes only the selected field
and account revision, preserving keys, credentials, sessions, and vault data.
Registration validation remains unchanged.

An omitted/null avatar object field or `[null]` clears the color. Empty positional
`[]` is a schema error returning 422; a surplus sequence element is a syntax
error returning 400. The full response remains an adapter-built profile, so
these three new rows have no typed core response claim. Profile GET and sync use
the [stored name directly](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs#L311-L316),
including an empty string.

All eight profile/avatar Rust HTTP cases pass against the adapter and official
Vaultwarden `1.37.4`: 425 counted requests including two password logins. Together
with folders and account keys, the preceding 24-case milestone passed with 887
requests and seven logins, excluding fixture registrations. That milestone also
passed the unchanged 120-command CLI baseline; no CLI profile/avatar mutation or
captured route trace is claimed.
All 294 upstream entries remain tracked and all full-parity flags remain false.

The account encryption-key chunk adds three previously unimplemented pinned
routes: `GET /api/accounts/keys`, `POST /api/accounts/keys`, and
`GET /api/users/<id>/public-key`. `AccountKeyStorage` keeps persisted key strings
and transactions in the embedding application; `VaultService` applies owner-only
private reads, initialization only when both fields are absent, and authenticated
cross-user public lookup. Explicit borrowed response serializers preserve the
pinned legacy key-pair envelope without linking `alloc`.

The [initialization handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L598-L625)
accepts opaque strings, including empty values. A partially present pair blocks
initialization, while private retrieval requires both fields. This differs from
registration’s stricter cryptographic validation. The
[shipped TypeScript public-key helper](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/services/api.service.ts#L1205)
has a direct CLI method reference; that static fact does not establish a captured
CLI request or command-specific use of this endpoint. Complete account lifecycle,
modern key rotation/registration, and exhaustive error/configuration behavior
remain separate parity work.

The personal API-key chunk adds two account routes and a grant variant on the
existing token route:

| Method and route | Reusable contract and personal-host scope |
| --- | --- |
| `POST /api/accounts/api-key` | Reauthenticated retrieval; create once when absent, otherwise preserve key and revision |
| `POST /api/accounts/rotate-api-key` | Reauthenticated replacement; atomically change the key and account revision |
| `POST /identity/connect/token`, `grant_type=client_credentials` | Authenticate `user.<id>` with exact `api` scope and device fields; issue access authority without refresh authority |

The [pinned account helper](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1476-L1501)
returns `apiKey`, `revisionDate`, and `object: "apiKey"`. Its proof model accepts
one password authentication hash or protected-action OTP. Provider hooks retain
that distinction; the standalone password-account host rejects the unsupported
OTP variant. Secure randomness, confidential recoverable key storage, hash
verification, clocks, and JWT signing stay outside the allocation-free core.
Rotation does not change existing bearer or password-refresh authority.

The [pinned personal token response](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L724-L744)
contains encrypted account key and decryption metadata but no refresh token.
Actual `bw login --apikey` follows the
[TypeScript strategy](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/auth/src/common/login-strategies/user-api-login.strategy.ts#L40-L85);
password-account `bw unlock` separately
[initializes SDK cryptography](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/unlock/src/default-unlock.service.ts#L211-L232).
The bundled SDK's independent API-key login implementation is not proof of that
CLI call path. All 90 real CLI commands pass against both servers; the 24-command
extension checks locked API login, password unlock, fresh-cache decryption,
rotation, and old-secret rejection. All 14 portable API-key HTTP tests pass
against the release binary with its default rate-limit policy. That chunk passed
52 HTTP tests, 45 core unit tests, 17 Rust host tests, and a compile-fail
secret-serialization doctest. Key state and API bearers also survive two graceful
restarts. These runtime results do not supply an exhaustive comparison catalog
or captured CLI request trace.

Organization credentials, passwordless/KeyConnector accounts, OTP delivery and
consumption in the host, login rate controls, device policies, and exhaustive
authentication errors remain further work. All full-parity flags and formal
comparison/trace receipt requirements remain unchanged.

The attachment inventory contains eleven pinned Vaultwarden patterns: ten
authenticated API routes and one capability-based file route. The personal
attachment chunk accounts for each pattern explicitly:

| Method and route | Contract |
| --- | --- |
| `POST /api/ciphers/<cid>/attachment/v2` | Reserve metadata; return upload type 0, attachment ID, upload URL, and `cipherResponse` or `cipherMiniResponse` |
| `POST /api/ciphers/<cid>/attachment/<aid>` | Multipart `data` upload into the existing reservation; empty 200; explicit Rocket rank 1 |
| `GET /api/ciphers/<cid>/attachment/<aid>` | Read-authorized metadata and download URL |
| `POST /api/ciphers/<cid>/attachment`, `POST /api/ciphers/<cid>/attachment-admin` | Legacy multipart filename/key/data upload; cipher response |
| `POST /api/ciphers/<cid>/attachment/<aid>/share` | Legacy replacement with a fresh ID; cipher response |
| `DELETE /api/ciphers/<cid>/attachment/<aid>`, `DELETE /api/ciphers/<cid>/attachment/<aid>/admin` | Write-authorized deletion; `{cipher: ...}` |
| `POST /api/ciphers/<cid>/attachment/<aid>/delete`, `POST /api/ciphers/<cid>/attachment/<aid>/delete-admin` | Same deletion contract |
| `GET /attachments/<cid>/<file_id>?token=...` | Capability-authorized encrypted bytes, without a session bearer |

The [required download query guard](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/web.rs#L231-L240)
returns 422 when `token` is absent. A supplied invalid capability, mismatched ID
binding, or missing file returns 404.

The [pinned handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L1127-L1496)
require read access for metadata and write access for mutation; admin-named
aliases grant no bypass. Reservation ignores the client's extra
`lastKnownRevisionDate`. It leaves revisions unchanged; upload and deletion
advance account revision without changing cipher revision. A measured size
within the inclusive declared-size range of plus or minus one MiB is accepted;
a mismatch discards the reservation and stored bytes. The adapter's atomic BLOB
persistence and replacement are stronger than upstream's separate filesystem
writes and delete-before-replacement flow. This guarantee covers metadata,
BLOBs, and revisions; a later response/capability generation error can leave a
committed mutation, matching the upstream response construction boundary. Ordinary
[`attachments2` updates](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L516-L538)
change only associated key/filename metadata, skipping missing IDs and stopping
at a foreign attachment; their iteration order is unspecified.

The [upstream file capability](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L425-L447)
has a 60-second lifetime and a
[30-second JWT validation leeway](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L130-L139).
The host instead
uses an opaque capability digest with strict expiry. Its 16-MiB encoded-request
limit is separate from the 525-MiB declared-size validation and upstream's
525,000,000-byte multipart file limit: upstream uses
[`525.megabytes()`](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/main.rs#L575-L578),
whose [unit is decimal MB](https://docs.rs/ubyte/0.10.4/ubyte/struct.ByteUnit.html#method.megabytes).

Actual [CLI create](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/vault/create.command.ts#L142-L194)
and [delete attachment commands](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/vault/delete.command.ts#L86-L120)
call the shared cipher service; `pm-28192-cipher-attachment-ops-to-sdk` selects
TypeScript or SDK metadata operations. Both use direct multipart upload for
upload type 0. [CLI get](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/commands/get.command.ts#L395-L425)
performs the authenticated metadata request, downloads the returned URL, and
delegates decryption to SDK attachment cryptography. Its 404 fallback to a cached URL does
not implement a missing server endpoint. The shared client also constructs
admin metadata, upload-renewal, and emergency-access attachment requests absent
from this pinned Vaultwarden inventory; those calls remain explicit gaps rather
than evidence that eleven implemented patterns close the family. The portable
attachment HTTP group passes all nine tests against the release binary and
covers all eleven patterns. All 118 real CLI commands pass against both servers, and the final nine local
HTTP guard checks pass against the rebuilt adapter. The
attachment milestone passed 56 core unit tests, its secret-serialization doctest,
and the Rust 1.85 and allocator-free RISC-V checks, plus 22 Rust host tests with
the Rust 1.89 host check. Current totals are in [CI and review](ci.md).
Local attachment state and bytes survive two graceful
restarts. Organization permissions, quotas, object
storage, notifications, and exhaustive failure behavior remain further work;
all full-parity flags and formal comparison/trace requirements remain unchanged.

## Reproduce and maintain the inventory

The [Rust host utility](../tools/api-inventory/README.md) parses every upstream
Rust source file, resolves route registrations and conditional early returns,
and fails on unregistered attributes or unsupported factory syntax. CI downloads
the pinned source and compares regenerated facts and all 61 source-file hashes.
It never compiles or executes upstream implementation code. The tool has its own
workspace and does not add `std`, `alloc`, or parser dependencies to the core.

After installing the pinned CLI with `npm ci --prefix tools`, fetch its upstream
build lock and verify the client and implementation snapshots:

```sh
export BW_CLIENTS_COMMIT=b449ac1d255784380d75ef026343198891286be7
export BW_SDK_COMMIT=c5e53d3e82ab80fdc9fd79ebd74058399a6444b6
curl --fail --location "https://raw.githubusercontent.com/bitwarden/clients/$BW_CLIENTS_COMMIT/package-lock.json" -o /tmp/clients-build-lock.json
curl --fail --location "https://codeload.github.com/bitwarden/sdk-internal/tar.gz/$BW_SDK_COMMIT" -o /tmp/bw-sdk.tar.gz
mkdir -p /tmp/bw-sdk-source
tar -xzf /tmp/bw-sdk.tar.gz -C /tmp/bw-sdk-source --strip-components=1
BW_CLIENTS_BUILD_LOCK=/tmp/clients-build-lock.json BW_SDK_SOURCE_ROOT=/tmp/bw-sdk-source node --test tools/cli-inventory.test.mjs
node --test tools/api-coverage.test.mjs
node tools/check-api-coverage.mjs
```

The client check binds inventory records to the locked package integrity,
published bundle/source-map hashes, upstream SDK build-lock pins, and actual
shipped source locations. The fetched revision labels must match the recorded
citations. A pinned host-only TypeScript parser independently discovers all 311
literal request-construction variants (including 22 local server routes) and
requires inventory coverage; three generic transports remain explicit obligations.
It also reconciles all 41 command registration variants from 40 construction
sites, resolving the parameterized `move` and deprecated `share` registrations
from their literal caller arguments. Unresolved command declarations fail closed.
Each operation has a reviewed receipt combining its
method/path/role, cited expression span, and pinned SDK/helper source hashes.
Reachability descriptions, conditions, and syntax-checked method references are
also bound. Changing the claim or source bytes invalidates the receipt. These
are audited interpretations, not automatic semantic inference or runtime request
traces. Updating a receipt requires inspecting the source expression and its
SDK/helper trace again; refreshing aggregate counts cannot validate a new claim.

Implementation and test source hashes, including local helpers, protocol JSON
such as the global domain catalog, the tool dependency lock, workspace manifests,
and Rust lockfiles keep coverage claims tied to the audited code. Model and service references must resolve to source
symbols, and handler references must cite the matching classifier arm. A Rust
test checks every local coverage route against the compiled classifier. HTTP coverage
flags must agree with their positive, negative, or restart evidence. An
implementation change must update the affected records and references,
then refresh `source_sha256` using `node tools/check-api-coverage.mjs
--source-hashes`. Review that metadata diff with the code change; refreshing
hashes alone does not establish new behavior. Counts are computed from records.

The upstream comparison catalog is initially empty. A full-parity assertion must
reference an audited comparison case for the same route and upstream revision,
plus a successful runtime receipt matching all current source/dependency hashes.
There are no such receipts in this baseline; case names or an empty list of
remaining variants cannot establish parity. Comparison runners can supply receipts
through `API_COMPARISON_RECEIPTS` as they are implemented and verified.
Full local parity also requires every linked upstream handler status to be
verified. The CLI trace catalog is likewise empty: captured-route claims require
an audited command, the locked client version, and a current-source runtime
receipt supplied through `API_CLI_TRACE_RECEIPTS`. Successful cache commands or
unresolved trace names do not satisfy that requirement.

## Device discovery

The discovery chunk adds three pinned routes through an opt-in `DeviceStorage`
provider and `VaultService` methods:

| Method and route | Verified contract |
| --- | --- |
| `GET /api/devices/knowndevice` | Public base64url email/header lookup; bare JSON boolean |
| `GET /api/devices` | Authenticated owner-only list; ten-field entries |
| `GET /api/devices/identifier/<id>` | Authenticated exact identifier lookup; seven-field response |

The [pinned discovery handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1504-L1580)
use opaque identifiers in headers and login forms. The authenticated lookup path
instead follows the ASCII letter/digit/hyphen guard after percent-decoding,
without UUID normalization. Missing or foreign records return 400; invalid
path syntax returns 422 after authentication. Known-device lookup lowercases
the decoded email without trimming and matches the exact identifier. Invalid or
missing required headers return 400; bearer authentication is not required.

Successful password and personal API-key logins register the owner/device pair.
Repeated login retains the first name, parsed type and creation date, following
[upstream device reuse](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L776-L797).
The adapter binds newly issued sessions to that identity and retains it on
refresh. Its savepoint provides atomic registration/session issuance, with
rollback and database-reopen evidence. Device-only operations preserve account
revision and vault contents. Legacy sessions remain valid without fabricated
bindings; the existing stricter single-use refresh policy remains a separate
compatibility limitation.

Borrowed core records and streamed responses require no allocator. The
known-device request represents decoded headers and has no JSON decoder. The
core list model exposes a two-field pending-auth request when one exists; the
adapter supplies the latest owned pending record and approval/rejection updates
that view. Trust/key setup, enabled push relay, notification policy and legacy
registry backfill remain open.

All eight Rust device cases pass against the adapter and official Vaultwarden
`1.37.4`: 199 requests including six identity requests. Those comprise five login
attempts (four successful and one rejected) and one refresh. The previously verified
32-case personal selection runs separately; fresh reference processes keep
both selections within the unchanged default login limit. The default adapter
entry point runs all 72 cases. No CLI device-route trace or full-parity flag is
claimed, and the full API delivery goal remains open.


## Device push-token contracts

| Method and route | Scoped behavior |
| --- | --- |
| `POST`/`PUT /api/devices/identifier/<id>/token` | Validate the path, then update the verified session's device; empty 200 |
| `POST`/`PUT /api/devices/identifier/<id>/clear-token` | Public guarded path; disabled push returns empty 200 without clearing |

The [pinned handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1576-L1641)
intentionally use the authenticated device rather than the update path's identifier.
A valid missing or foreign path identifier can therefore succeed. Authentication
precedes path validation, which precedes JSON validation. Public clear ignores
authorization and body input. Missing or malformed update fields return the tested
400/422 statuses; all successful responses have empty bodies rather than JSON null.

`DevicePushTokenRequest` contains one required borrowed opaque string. Empty
strings are values; unknown fields are ignored, one-element positional input is
accepted, and duplicate known fields are rejected. `DevicePushStorage` provides
verified owner/device lookup, atomic token/activity writes and ordered relay
callbacks. An exact repeat skips saving and registration. Changed tokens persist
before relay registration, so a callback failure retains the mutation and an
identical retry takes the shortcut, following the pinned source.

Enabled clear providers clear every owner with the exact path identifier and
return the first device's optional push ID for subsequent unregistration. The
owned associated handle can use stack storage without a core allocation. Provider
tests verify that order and failure effects. The standalone adapter uses disabled
push, so clear returns before registry access or relay work. Enabled relay
interoperability, notifications and reference rate controls remain open; adding
these routes does not establish that broader behavior.

Eight selected Rust HTTP cases pass against the adapter and actual Vaultwarden
`1.37.4`: 383 requests and three successful password logins each. The device-enabled
subtotal passes 48 cases with 1999 requests. Separate fresh reference processes
preserve its unchanged login and unauthenticated clear limits. Public projections
do not expose token contents; a separate private Rust/read-only SQLite probe
passes 13 state checks on both servers, covering session targeting, preserved
activity on exact repeats, disabled clears, owner isolation and refresh identity.
Its 16 requests include three logins and one refresh; no secret values are emitted.
The host's stronger zero-write shortcut proof uses abort triggers in unit tests.
No CLI token-route trace, real relay delivery or full-parity status is claimed.


## Authentication-request creation and discovery

| Method and route | Verified slice |
| --- | --- |
| `POST /api/auth-requests` | Public creation for an existing user and matching registered device/type |
| `GET /api/auth-requests/<id>` | Authenticated owner-only eleven-field response |
| `GET /api/auth-requests` and `/api/auth-requests/pending` | Authenticated pending-only list aliases |

The [pinned creation/read handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1650-L1743)
and [pending aliases](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1863-L1900)
preserve required opaque strings in positional order: access code, device
identifier, email and public key. Lookup lowercases email without trimming it.
The optional `device-type` header uses exact `i32` parsing, with absent or
unparseable values defaulting to 14. Device identity and raw numeric type must
match the registered owner/device before creation; neither comes from a claimed
body owner or body type. Fresh requests do not change account revisions, device
activity or vault data.

The allocation-free `AuthRequestStorage` provider composes with `DeviceStorage`.
It supplies an owned account handle, fresh UUID/time and atomic persistence.
Typed responses project exactly eleven fields, excluding access code, internal
owner and request-device identity. Creation returns `requestApproved:false`;
subsequent pending reads return null. Streamed lists include only records with
no approval value, without a core count cap or implicit age filter. UUID paths
are decoded and checked after authentication, preserving spelling for exact
lookup. Device lists expose the latest owned pending request as only its ID and
creation date; single-device projections remain seven fields.

Eight Rust cases pass against both the adapter and actual Vaultwarden `1.37.4`:
273 requests, five successful logins and 33 decoded creation attempts each. The
prior creation/discovery/response subtotal passed 64 cases and 2594 requests. Each reference selection uses
a fresh process within unchanged default limits. Opaque non-UUID device IDs,
header fallback/raw types, ignored fields, schema/positional inputs, owner and
UUID guards, repeated creation and latest-pending metadata have direct HTTP
proof. Rollback, private-code persistence and unchanged device activity have
separate provider/SQLite test evidence.

The adapter records the direct socket peer and canonical configured URL origin.
Vaultwarden can honor configured `X-Real-IP` from trusted proxies, including local
peers by default; that forwarding policy remains unimplemented here. A socket
test verifies adapter behavior, not equivalence for that proxy configuration.
Notifications/events, expiry cleanup and rate controls remain open. No CLI
request trace or complete authentication-request/API parity is claimed.

The authentication-response slice adds authenticated `PUT /api/auth-requests/<id>`
and public `GET /api/auth-requests/<id>/response?code=...`, following the
[pinned approval and polling handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1745-L1861).
`AuthRequestUpdateRequest` borrows the required response-device identifier, opaque
key, optional nullable master-password hash, and approval boolean. Its redacted
formatting keeps all input values private. `AuthRequestResponseStorage` extends
the creation/discovery provider with atomic responses and code-verified lookup;
credential comparison remains an adapter cryptographic duty.

The service requires an owned pending request and an exact match between the
body device and the verified session device. It does not require the responder
to be the requesting device. Approval persists the supplied key/hash, response
device and timestamp, and removes the request from pending lists and device
pending metadata. Rejection deletes the request but returns its prior pending
fields with a fresh response timestamp and null approval. Already answered,
foreign, missing and mismatched-device requests leave state unchanged.

Public polling ignores bearer authority, requires a code query field, and checks
that code plus the exact recorded device type and direct peer IP. Pending and
approved records use the existing explicit eleven-field response model; polling
does not consume them. The adapter verifies fixed-size HMAC tags in constant
time and keeps all credential values out of diagnostics. Notifications, expiry
cleanup, rate controls and trusted forwarding remain open;
these two routes do not complete the authentication-request lifecycle.


All eight authentication-response cases pass against the actual adapter and
Vaultwarden `1.37.4`, with 322 counted HTTP requests and four successful logins
per server. The selected fixture makes eleven decoded creation attempts and
33 guard-valid response polls, below the unchanged public burst limit of 50;
six path/query guard rejects do not enter the polling handler. Comparisons cover
pending/approved/rejected projections, repeated polling, owner/session-device
boundaries, opaque and optional fields, schema/positional guards, query decoding
and first duplicate selection, raw type/default handling, ignored bearers,
alternate-loopback peer rejection, and pending-list/device transitions. Hidden
stored response-device IDs, rollback, account/device invariants and database
reopen remain separately established by host/provider tests. These direct HTTP
results add no CLI auth-request login or captured route trace.


## Authentication-request login

The existing `POST /identity/connect/token` password grant accepts the compact
case-insensitive `authRequest` form field. Its `password` value is then the
request's opaque access code. It never falls back to the account password when
that field is present. The
[pinned login handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L370-L498)
requires an owned approved request, unused authentication state, the same peer
IP and age strictly below five minutes from creation. Login device identifier and
type need not match the requesting device. Required fields distinguish absent
from present empty strings; scope must equal `api offline_access`.

`AuthRequestLoginRequest` borrows decoded fields and a redacted `Secret` proof;
it cannot be serialized implicitly. `AuthRequestLoginStorage` verifies codes in
the adapter, returns private eligibility data and atomically claims unused
requests. Trusted full-width nanosecond time stays in `AuthRequestLoginContext`.
The core validates the strict deadline and returns a private-construction grant
owning the provider's account handle, freeing storage borrows for issuance.

The adapter wraps consumption, login-device registration and session/binding
issuance in one rollback boundary. This is stronger local failure atomicity than
upstream's separate later issuance steps. A private enabled-policy table governs
account authority; registration and profile extras cannot change it. Successful
login preserves approval/key/hash fields, and public polling remains readable.
Shared password/refresh issuance now uses upstream's two-hour access lifetime,
requested client ID (or `undefined` when omitted), and retained registered-device
type. API-key grants keep their access-only scope. Existing stricter refresh
rotation and unimplemented mobile lifetime, 2FA/mail/SSO/admin policy, events,
notifications, purge/rate/proxy variants keep this route partial.

The eight selected login cases passed against the adapter and actual Vaultwarden
`1.37.4`, each with 444 counted HTTP requests and 43 identity requests: two
ordinary logins, seven successful request-based logins, two refreshes and 32
rejects. Twelve creations and twelve public response polls include polling after
consumption and expiry. The expiry check waited 301 real seconds; four nested
`authRequest` roots rejected valid ordinary passwords instead of falling back.
The full local selection passed all 72 cases with 3038 counted requests. These
results establish no CLI request-login command or captured route trace.
