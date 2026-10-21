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
| [Current coverage](../compatibility/no-warden-coverage.json) | 126 routed patterns, 65 with typed requests, 119 with reusable core service behavior; each carries its narrower limits |
| Runtime CLI comparison | Official CLI `2026.10.0`: all 120 commands pass against the adapter and official Vaultwarden `1.37.4`, including attachment byte round trips and authenticated public-key fingerprints. This runtime baseline differs from the inventoried Vaultwarden main revision above. |
| Focused text-Send CLI comparison | A separate official CLI `2026.10.0` run passes all twenty Send commands against both actual servers. Owner get/list use cache after sync; no captured route trace is claimed. |
| Focused file-Send CLI comparison | Another separate official CLI `2026.10.0` run passes twenty commands on both servers, including two byte-exact file receives. Owner cache operations remain distinct from traced HTTP reads. |

The coverage ledger joins all 294 declared upstream handlers to an explicit
status: 123 partial and 171 unimplemented. Query/rank/configuration
variants retain separate upstream identities, and path parameter renames have
explicit mappings. Three additional local aliases are tracked as extensions;
they do not replace the corresponding upstream endpoints.

62 local patterns have some typed response representation, including
the domain settings projections and empty mutation response, explicit API-key
responses, and attachment responses. Bulk cipher lists use the generic `ListResponse`
wrapper; a complete borrowed cipher response model is still absent, and single
archive responses remain host-built JSON.

The ledger records positive or restart HTTP evidence for 120 patterns, negative
HTTP evidence for 119, 325 named HTTP cases, and 54 CLI command patterns. These are
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
the legacy embedding registration API’s stricter cryptographic validation.
Modern ordinary registration preserves opaque values. The
[shipped TypeScript public-key helper](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/services/api.service.ts#L1205)
has a direct CLI method reference; that static fact does not establish a captured
CLI request or command-specific use of this endpoint. Complete account lifecycle,
modern key rotation, remaining registration variants, and exhaustive error/configuration behavior
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
bindings for access. Refresh requires current bound device authority and now
preserves valid earlier proofs through the supported password-method provider.

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
type. API-key grants keep their access-only scope. Refresh JWT representation,
mobile runtime, 2FA/mail/SSO/admin policy, events,
notifications, purge/rate/proxy variants keep this route partial.

The eight selected login cases passed against the adapter and actual Vaultwarden
`1.37.4`, each with 444 counted HTTP requests and 43 identity requests: two
ordinary logins, seven successful request-based logins, two refreshes and 32
rejects. Twelve creations and twelve public response polls include polling after
consumption and expiry. The expiry check waited 301 real seconds; four nested
`authRequest` roots rejected valid ordinary passwords instead of falling back.
The full local selection passed all 72 cases with 3038 counted requests. These
results establish no CLI request-login command or captured route trace.

## Modern registration

The public `POST /identity/accounts/register/send-verification-email` and
`POST /identity/accounts/register/finish` routes implement ordinary registration
with SMTP disabled. The
[pinned verification handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/identity.rs#L1033-L1104)
returns a signed token directly, as a JSON string only when the preferred Accept
media type is `application/json`; otherwise it returns plain text. Its raw email
and optional name become claims with a 30-minute lifetime. Issuance does not
create an account or reject an existing email, an unusual email string, or a name
that will be too long at finish.

`RegistrationStorage` keeps policy, signing, signature/time validation, password
hashing and atomic persistence in adapters. Borrowed verification input, an
explicit token serializer, the finish semantic view and `registerFinish`
response need no core allocation. The semantic view does not decode the full
flattened, untagged JSON union. The host preserves the upstream legacy-first
choice, nested aliases, signed KDF fields, and unknown-field behavior before
calling the service. The existing one-step embedding API remains available.

Finish checks nested KDF/salt agreement before proof, then verifies the token's
exact raw email binding. Account email is Unicode-lowercased without trimming;
nested salts instead use trimmed lowercase email. Completion validates email
syntax and domain URLs through the upstream parser in the adapter; verification
still accepts those strings for token issuance. Only the signed claim name
authorizes a name, with a 50-byte UTF-8 limit. A missing name defaults to the
stored email; a supplied finish-body name has no authority. Client key/hash
values remain opaque. The modern KDF policy matches the source: PBKDF2 needs at
least 100000 iterations, Argon2 needs at least one iteration, 15–1024 MiB and
parallelism 1–16. Other signed KDF identifiers are retained, and non-Argon2
memory/parallelism become null.

The adapter uses a persistent registration signing key separate from access
signing. It validates the registration issuer and JWT times with the upstream
30-second leeway, then atomically stores a canonical account and private verified
metadata. Registration tokens, raw master hashes, nested credentials and arbitrary
finish extensions are excluded from account documents. Duplicate registration or
failure preserves existing accounts and vaults. SMTP delivery, invite-JWT and
emergency-access completion, signup configuration, abuse limits and broader
account lifecycle remain partial.

The eight modern registration cases passed against both the adapter and actual
Vaultwarden `1.37.4`: 541 counted HTTP requests per server, including 69
verification requests, 64 finish requests, ten prelogin requests and nine
successful password logins. The suite checks quoted Accept parameters, invalid
email completion and preserved public account snapshots; hidden-row absence and
rollback use separate host SQL tests. Each direct peer stays within unchanged
reference limits (at most 44 public attempts and nine identity requests).
Official CLI `2026.10.0` separately passed its 120-command baseline against both
servers. These results establish no CLI registration command or captured route
trace and do not complete broader registration parity.

The registration milestone combined local selection passed all 80 cases with 3579 counted HTTP requests,
including the real 301-second authentication-request expiry case.

## Account proof and stamp renewal subset

Two authenticated routes add reusable verification and stamp-renewal services
through `AccountSecurityStorage`. Verification has a required secret and explicit
optional policy projection; the personal default preserves upstream's exact
PascalCase `Object`. Stamp renewal reuses exclusive password/protected-action OTP
proof selection. The adapter binds both routes to a verified device before JSON
guards and uses private stamp state in profile, sync and JWT issuance.

The reset transaction advances owner revision and removes owner access/refresh
sessions and devices while preserving encrypted data, keys, API credentials,
other accounts and pending/approved authentication requests. The latter can
still authorize a fresh login under their original deadline, peer and one-use
checks. SQL tests separately establish rollback, durable reopen and resistance
to forged stamp fields in account documents. The adapter's atomic rollback is
stronger than upstream's sequential failure behavior.

Organization/SSO policy aggregation, stale verifier migration, successful
protected-action OTP, remembered 2FA, notifications, enabled relay behavior and
complete error/configuration variants remain open. The ledger links both new
operations as partial; the full API goal remains unfinished.

All eight selected account-security cases pass against both actual servers:
292 HTTP requests each, including nine identity requests. These comparisons
exercise existing-bearer and old-refresh rejection, private stamp projections,
device cleanup, preserved credentials/requests and owner isolation. They add no
captured CLI-route evidence or full-parity status.

The account-security milestone passed all 88 cases with 3871 counted HTTP
requests, including real authentication-request expiry and modern registration.

## Nested client KDF transition subset

`POST /api/accounts/kdf` adds a distinct nested borrowed request and opt-in
`AccountKdfStorage` contract. Old proof verification precedes full KDF equality,
exact salts and signed policy, then a private validated plan reaches the provider.
The adapter rechecks old proof inside the transaction before changing the server
verifier, wrapped user key, client KDF, private stamp, revision and session
authority. It retains device/push registrations, API credentials, authentication
requests, asymmetric keys, encrypted vault data and foreign state.

Core/provider and host tests cover rejection ordering, error boundaries,
rollback, deferred commit, durable reopen and stale-proof concurrency. The
provider makes atomic rollback stronger than upstream's sequential timing.
Pinned-source and release salt comparison differ; ordinary lowercase comparison
accounts do not close that variant. Notifications, remembered 2FA, remaining
stamp-exception routes and broader account/key contracts remain open.
The source-accepted empty wrapped-key variant also corrects password-grant
omission versus API-key retention of a top-level empty `Key`.

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

## Password transition subset

The [pinned password handler](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L621-L687)
accepts six source-ordered fields. `masterPasswordHash` is required; hint,
nested authentication/unlock and legacy new hash/key fields are optional.
A complete nested pair takes precedence, while a partial nested pair can fall
back to a complete legacy pair. Supplied malformed nested data fails JSON decoding
before that choice. The old proof precedes semantic checks. Unlike registration
and KDF changes, this route only compares the two supplied KDF values; it neither
validates their thresholds nor saves them. Both salts compare the exact stored
email in the pin and release 1.37.4. Hints trim and clear when absent/null/blank.

`AccountPasswordStorage` returns provider-owned trusted state, then accepts a
private validated plan. The core owns no allocator, clock, random generator,
verifier, HTTP or database. The plan carries the fixed previous-stamp policy from
[set_password](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/db/models/user.rs#L190-L250).
The [authentication guard](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/auth.rs#L664-L715)
requires the owned device before checking an exception, then checks expiry before
route and previous-stamp equality. The deadline is inclusive at its integer Unix
second. Expired mismatched-stamp requests lazily clear it and attempt a revision
save; current-stamp requests do not clean it up.

The four logical routes are `post_rotatekey`, `get_contacts`, `get_public_keys`
and `get_api_webauthn`. The last is the authenticated `/api/webauthn` metadata
handler, distinct from the two-factor WebAuthn handler. The public-key route and WebAuthn credential metadata now have adapter
exception behavior; the contacts and rotation routes remain open. A password change
replaces the exception; KDF/direct stamp resets preserve it. Device deletion
blocks it, and recreation of the same owned identifier can restore eligibility
before the deadline. Refresh tokens remain invalidated.

Local rollback covers credentials, hint, wrapped key, private stamp, exception,
revision and session changes. That exceeds upstream sequential failure guarantees.
Pre-validation event logging, logout notifications, remembered 2FA, the other
two exception routes, complete configuration/error variants and broader account
parity remain open. The adapter retains its strict original access deadline;
upstream's 30-second JWT expiry leeway is an inherited difference. Neither a
successful comparison nor CLI decryption establishes full route parity or a
CLI-posted password endpoint trace.

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

## WebAuthn credential metadata subset

`GET /api/webauthn` is the unconditional authenticated metadata route in both
[pinned main](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/mod.rs#L198-L207)
and [Vaultwarden 1.37.4](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/mod.rs#L198-L207).
It returns exactly `{"object":"list","data":[],"continuationToken":null}`.
This route is distinct from two-factor WebAuthn settings and passkey enrollment
or authentication. The source identifies avoiding key-rotation failures as its
purpose; it does not enumerate stored credentials.

`WebAuthnCredentialsResponse` is a fixed serializer with no request DTO or
provider state. `VaultService::get_webauthn_credentials` requires a nonempty
adapter-authenticated owner, uses only the existing `Storage` bound and never
calls storage. The bare-metal consumer serializes it without an allocator.
The adapter first verifies issued access authority and an existing device owned
by that account. Historical password-change bearers use logical route
`get_api_webauthn` under the existing original access deadline, device, exception
expiry and stamp checks. This adds no new token or refresh authority.

The shipped [SDK generated client](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-api-api/src/apis/web_authn_api.rs#L146-L158)
constructs a bearer GET, but no active caller of that method was established in
this pinned client/SDK source. Current SDK rotation instead fetches
[combined key-rotation data](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-user-crypto-management/src/key_rotation/sync.rs#L58-L68).
The [official CLI rotation service](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/key-management/cli-user-key-rotation-service.ts#L8-L34)
explicitly rejects rotation. The unchanged CLI regression therefore supplies no
GET `/api/webauthn` call or end-to-end key-rotation evidence.

Six authored Rust HTTP cases cover exact projection, authentication, routing and
ignored query values, unchanged account/vault state, password/API historical
bearers, device deletion and same-owner identifier recreation, foreign-owner
isolation and real exception expiry with one cleanup. All six cases pass against
the actual adapter and Vaultwarden 1.37.4: 129 counted HTTP requests each,
including eight identity requests (six successful grants and two rejected
refreshes), at most five requests per direct loopback peer. Two shared fixture
registrations are excluded from that HTTP counter. The final case waits 121 real
seconds before proving one-time cleanup. Current-bearer device recreation,
isolated JWT expiry/leeway, generic HEAD/OPTIONS behavior, full transport/error/configuration variants, actual
passkey operations and the contacts/rotation contracts remain separate gaps.
Full-parity and captured-request-trace claims remain false.

## Personal vault purge subset

`POST /api/ciphers/purge` adds a substantive personal-vault operation using the
existing borrowed `PasswordOrOtpRequest` and new `purge::VaultPurgeStorage`.
`VaultService::purge_personal_vault` verifies the authenticated owner and exactly
one proof before invoking the provider. Success is a unit result and empty HTTP
200; there is no new typed JSON response. The core remains allocation-free.

The [pinned handlers](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L1703-L1775)
and [Vaultwarden 1.37.4 release](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/ciphers.rs#L1703-L1775)
match exactly. Personal purge removes all owned personal ciphers and folders and
updates revision even when already empty. The provider also cleans attachments,
download capabilities and association/annotation rows, while preserving account,
credential, session, device, key and authentication-request authority. Local
atomic mutation/revision rollback is stronger than upstream's sequential failure
behavior. OTP consumption is not implicitly included in that rollback promise.

The ranked organization handler remains a separate unimplemented entry among
all 294 inventoried handlers. Query selection is case-sensitive and uses Rocket
form-name roots and string parsing, not path UUID validation. Present empty or
non-UUID `organizationId` values still select organization authorization and fail
401 for a personal account. Missing, unrelated or differently cased fields select
the personal handler. See the [protocol notes](protocol.md#personal-vault-purge)
for the proof schema and guard distinctions. These rejection checks do not
implement organization purge.

The [shared TS API](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/services/api.service.ts#L435-L443)
and [generated bundled SDK](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-api-api/src/apis/ciphers_api.rs#L857-L877)
construct this authenticated request. No actual CLI purge caller has been
established. The existing official CLI regression remains separate evidence,
without a new purge call or captured request trace.

All six selected Rust cases pass against the actual adapter and Vaultwarden
1.37.4: 327 counted HTTP requests per server, six identity requests (five
successful grants and one refresh), three authentication-request creations and
three public polls. Eight successful purge requests cover initial cleanup,
repeated empty operations, alias/positional proofs and unknown/wrong-case query
selection. The two shared fixture registrations are excluded. All six identity
requests use one direct loopback peer under the unchanged ten-attempt limit.
The suite checks all eleven recognized organization-query forms reject without
mutation; empty active/trash/archive server lists; foreign attachment bytes and
account authority; and direct Rust decryption of a fresh post-purge item.
The suite obtains fresh capabilities for three owned attachments and one
foreign attachment, verifies exact bytes with successful pre-purge downloads,
then proves owned URLs return 404 while the foreign URL remains byte-exact 200.
The entire issuance/check/purge sequence must finish within 30 seconds, before
the source's 60-second capability expiry. Physical attachment BLOB/grant/row
deletion is established separately by local SQL tests. Full parity, organization purge, successful protected-action
OTP, notifications and complete transport/error variants remain open.

## Personal account deletion subset

`DELETE /api/accounts` and `POST /api/accounts/delete` add two exact route patterns
for the same `AccountDelete` operation. They reuse the borrowed
`PasswordOrOtpRequest`; success is `Result<()>` and empty HTTP 200, not a new typed
JSON response. The opt-in `account_deletion::AccountDeletionStorage` verifies the
owner's proof before trusted deletion policy and atomic provider cleanup.

The [pinned aliases](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/accounts.rs#L1321-L1333)
and [release 1.37.4 aliases](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/accounts.rs#L1306-L1318)
have the same proof and response behavior. The user model checks confirmed
organization-owner counts after proof verification, then removes account-owned
resources sequentially. Organization vaults are preserved. The personal host
atomically removes its supported dependent state, while preserving unrelated
accounts and shared signer state; this is a stronger failure guarantee.

The pin explicitly deletes auth-request rows, while release 1.37.4 omits that
step and retains a non-cascading SQLite foreign key. Portable fixtures exclude
auth requests so their comparison does not imply cross-version equivalence for
that cleanup. Local provider tests cover complete supported deletion separately.
Organization last-owner policy is a trusted provider obligation. The later
organization-owner slice adds actual membership state and its deletion guard;
the earlier personal deletion proof did not establish organization behavior.
See [protocol details](protocol.md#account-deletion) for primary cleanup references.

The [bundled SDK generated API](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-api-api/src/apis/accounts_api.rs#L237-L252)
constructs bearer `DELETE /accounts` with a JSON proof and expects an empty
response. Its broader `SecretVerificationRequestModel` includes fields that
Vaultwarden's password/OTP DTO does not implement. No production caller or
successful execution of that generated deletion API was established here. The
[pinned CLI delete dispatcher](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/vault/delete.command.ts#L32-L49)
handles items, attachments, folders and organization collections, not accounts.
All six selected Rust HTTP cases pass against the adapter and actual
Vaultwarden 1.37.4: 257 counted requests per target, including six identity
requests (three successful password logins, two refresh attempts with one
success, and one rejected old API grant). Three fixture registrations across
two emails are excluded. The cases verify both aliases, authentication/proof
and JSON/method guards, ignored owner/query overrides, live authority revocation,
same-email re-registration with fresh identity and keys, and foreign preservation.
Each deletion proves three fresh owned attachment capabilities fail while the
foreign capability remains byte-exact, within a 30-second window. Physical
row/BLOB deletion, eighteen-stage rollback and durable reopen are separate local
SQL evidence. The existing CLI120 baseline adds no account-deletion call or
trace. Recovery/email deletion, broader Send variants, emergency-access, organization lifecycle,
successful protected-action OTP and
complete failure/transport variants remain separate gaps. Full parity stays open.

## Ordinary, details and admin cipher reads

`GET /api/ciphers/{id}/details` and `GET /api/ciphers/{id}/admin` add two exact
route patterns. Together with the existing ordinary GET, they use the new
allocation-free `CipherReadStorage`/`VaultService::authorize_cipher_read`
boundary. There is no request body model and no typed cipher response model;
the adapter owns the opaque payload projection. All three retain partial status.

The [pinned source](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L234-L255)
and [release 1.37.4](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/ciphers.rs#L234-L255)
share ordinary readable-access authorization, including the explicit TODO in
`get_cipher_admin`. Missing and inaccessible records return 400, correcting the
adapter's previous ordinary-read 404 expectation. Write/lifecycle errors are
unchanged. Authentication requires a current bound device before the exact
UUID guard; authenticated malformed IDs return 422, while invalid authority
returns 401 first. GET-only reserved malformed-ID spellings also reach that
UUID guard; they do not become create/import/purge operations. Other unimplemented
literal handlers remain unimplemented rather than being counted as read aliases.

The shipped [ApiService helpers](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/services/api.service.ts#L362-L375)
construct all three paths. `getFullCipherDetails` has a concrete
[notification-upsert caller](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/platform/sync/core-sync.service.ts#L142-L205).
Notifications are not implemented by this adapter, and no actual client
execution of the two new aliases is established. No production caller of
`getCipherAdmin` was established in the cached TypeScript sources. The bundled
SDK also generates bearer [admin](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-api-api/src/apis/ciphers_api.rs#L490-L507)
and [details](https://github.com/bitwarden/sdk-internal/blob/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6/crates/bitwarden-api-api/src/apis/ciphers_api.rs#L592-L612)
GETs with different typed response models; their generated existence is not
runtime client evidence or a claim of complete Bitwarden response parity.

All six selected Rust HTTP cases pass against the adapter and actual
Vaultwarden 1.37.4: 337 counted requests per server, four successful password
logins and two excluded fixture registrations. They verify all three GETs,
authentication/UUID order, exact missing/inaccessible messages, active/trash/archive
projection equivalence, ignored bodies/queries, encoded UUIDs, trailing slashes,
eleven malformed reserved GET literals, method guards and revoked-authority
isolation. Thirty-four attachment byte checks per target establish that the
returned capabilities still retrieve the exact encrypted bytes; only attachment
URL tokens are normalized for alias/snapshot comparison. These checks establish
selected direct HTTP behavior, not a client alias execution. Core/provider tests cover
personal ownership, shared readable-but-not-writable overrides, exact IDs,
lifecycle preservation, error mapping and grant redaction. Broad organization
policy, notifications, complete cipher response models and global transport/error
contracts remain open; all full-parity and captured-trace flags remain false.

## Ordinary password-grant core

This chunk deepens the existing partial `POST /identity/connect/token` contract;
it added no route or newly covered upstream handler. The inventory still has
294 handlers; subsequent text-Send coverage is tracked separately below. `PasswordLoginRequest`,
`PasswordLoginStorage` and `VaultService::authenticate_password` add a reusable
allocation-free ordinary password path beside API-key and auth-request login.
OAuth token response projection remains adapter-owned; refresh now has its own
supported-method core contract below. No typed OAuth response model or full
identity-family claim is introduced.

The service preserves upstream required-field order, exact scope, raw proof and
trimmed username semantics before trusted lookup/proof/enabled/preparation hooks.
The adapter corrects previously omitted ordinary scope/client-ID guards and
case-sensitive username/password lookups, and follows root aliases with first
required-grant versus duplicate-absent optional-field semantics for this branch. Existing auth-request selection remains distinct and cannot
fall back to account-password verification. Duplicate policies for other grants
are not broadened by this correction. See
[protocol references](protocol.md#ordinary-password-grant-validation) for precise
pin/release guards and source response behavior.

A concrete shipped client path is
[CLI password credentials](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/auth/commands/login.command.ts#L222-L224),
[password strategy](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/auth/src/common/login-strategies/password-login.strategy.ts#L102-L111),
[base login strategy](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/auth/src/common/login-strategies/login.strategy.ts#L117-L124)
and [ApiService token request](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/common/src/services/api.service.ts#L161-L185).
The request models set the client authentication hash, exact scope, client ID
and device metadata. The existing real CLI baseline exercises ordinary password
login. All six focused Rust cases pass against both actual servers: 85 counted
HTTP requests per target, including 45 token POSTs, with one fixture registration
excluded. The suite classifies 39 pre-limiter guard requests and six
credential-flow attempts, including two ordinary successes and one auth-request
selector canary. It verifies selected complete API errors, required order, exact
scope, raw proof, root aliases, duplicate-absent optional fields, empty client and
device input, token authority and account/vault preservation. Private enabled and
provider failures are separate unit/SQL evidence. A fresh official CLI 2026.10.0
regression also passes all 120 commands against both actual servers. No captured
trace, complete transport/error/2FA/mail/SSO
behavior or refresh-core parity follows from these checks.

## Password-method refresh contract

This deepens the existing token route without adding a routed pattern, typed
OAuth response or newly covered upstream handler. `RefreshTokenRequest`, opt-in
`RefreshStorage` and `authenticate_refresh` return a sealed owner/device grant
without allocating. Provider verification owns proof authenticity/time and
current persistent device authority. The service preserves valid proof reuse
and does not add password, enabled-state or previous-stamp checks. Preparation
and issuance transaction boundaries stay with the embedding application.

The adapter replaces its earlier single-use policy with nonconsuming opaque
handle verification, original deadlines, current device/binding joins and source
Unicode-whitespace normalization. It returns the exact five refresh fields,
uses the current optional client ID, keeps old access deadlines and preserves
account/vault state. Optional repeated proof/client roots become absent; the
required grant keeps its first matching root. Unbound legacy refresh fails even
when its older access behavior remains available. The private issuance savepoint
is stronger failure atomicity than upstream's separate device activity writes.

The [pin and release contract](protocol.md#password-method-refresh-grants) agrees
on this password-method path. Shipped TS CLI sync calls the concrete refresh
service, and the bundled SDK also constructs renewal forms. Both forward refresh
proofs opaquely. The host does not implement upstream's refresh JWT encoding or
`nbf` claims. Unsupported SSO/API methods and their failure-write timing, mobile
runtime, full expiry waits, complete policy/configuration and transport remain
open. All eight focused Rust comparison cases pass against both actual servers:
268 counted HTTP requests each, six successful password logins and 42 refresh
POSTs (22 successes, 15 invalid proofs, four missing/duplicate-proof guards and
one missing-grant form guard). Two fixture registrations are excluded. The
cases include real retained-cipher decryption after password/KDF/stamp recovery.
Source-authored refresh counters are separate from password-login attempts and
are not server-side limiter telemetry. Deadline/leeway/mobile policy uses
separate host clock tests, not long-expiry or mobile runtime proof.
No full-parity or captured request-trace claim is introduced.

## Personal text-Send lifecycle

Seven newly implemented patterns map to seven distinct handlers in the fixed
294-handler inventory: owner `GET`/`POST /api/sends`, owner `GET`/`PUT`/`DELETE
`/api/sends/{id}`, `PUT /api/sends/{id}/remove-password` and recipient
`POST /api/sends/access`. The existing token route adds `grant_type=send_access`;
sync now includes actual owner Send projections. The later file-Send selection
below adds four handlers; email verification and broader enterprise/configuration
variants remain unimplemented or partial. Every full-parity flag remains false.

`SendStorage` supplies trusted policy, stable indexed views, persistence,
password verification and recipient capability verification. `TextSendRequest<P>`
is an allocation-free semantic view, not a full Serde request decoder.
`SendOwnerResponse<P>`, `SendRecipientResponse<P>` and `SendListResponse<L>`
serialize eighteen, eight and three fields without allocating. The HTTP adapter
owns dates, raw JSON, root normalization, cryptography and token signing. No
complete typed sync model is counted; the later file selection adds its own
semantic request and explicit transport-response models.

The [pin/release protocol](protocol.md#personal-text-sends) preserves policy and
ownership ordering, the strict thirty-one-day ceiling, opaque metadata and
late signed-number conversion. Update preserves omitted/null passwords; explicit
remove-password clears them. Token minting does not increment count. Issued
recipient capabilities survive password replacement, but every access checks
current availability and conditionally increments below the limit. A failed
count reservation can advance owner revision. Local transactions provide stronger
row/revision rollback than upstream's sequential writes; that does not promise
universal rollback across notifications or response construction.

All six selected Rust HTTP cases pass against both actual servers: 129 counted
requests, two password logins, 23 Send-token grants and 15 recipient accesses per
target, excluding two fixture registrations. Real authenticated decryption and
account-key seed unwrap accompany projection, ownership, password/count/deadline
and foreign/vault-preservation assertions. Source/unit evidence separately
establishes arbitrary scalar/array projection, exact clock boundaries, rollback,
reopen, account-deletion FK cleanup and preservation during personal vault purge.
The focused twenty-command official CLI 2026.10.0 run passes both actual servers.
Its wrong-password and post-deletion checks require exit 1 plus the exact public
CLI messages `Invalid password` and `Not found.`; an unrelated nonzero exit is
insufficient. New unit fixtures reject generic server/rate/transport errors and
malformed response categories without exposing captured output.
Static client calls and the independently passing CLI120 baseline are not new
Send-route traces.

The host uses a private persisted HS256 Send signer rather than upstream RS256.
Remaining file variants, email OTP, enterprise policies, configuration matrices, notifications,
rate controls, purge cron and full JWT/transport/failure parity remain open. The
delivery goal remains all upstream APIs, beyond the verified personal subset.

## Personal file-Send lifecycle

Four registered handlers become partial: reservation, multipart upload,
recipient file-URL issuance and binary GET. They deepen existing owner CRUD,
recipient metadata, `send_access` and sync; they do not implement the static
client upload-renewal GET or complete the Send family. The ledger retains all
294 handler variants. At the later prelogin milestone, 96 were partial and 198
unimplemented, with zero full and zero traces. That ledger recorded 99 routed
patterns, 53 with typed requests, 44 with any typed response and 92 with reusable
core services. Measured multipart facts are not counted as
a wire request DTO; `FileSendRequest<P>` is a semantic view, and the explicit
reservation/download responses are typed serializers.

The [pin/release protocol](protocol.md#personal-file-sends) preserves generated
identity, immutable file metadata, filename-before-ID-before-size upload guards,
exact encrypted length, count-on-URL issuance and token-only binary reads.
A failed count reservation can still advance account revision. SQLite BLOB and
revision writes are atomic; later response generation is a separate boundary.
Configured quota/policy matrices, object storage and universal failure timing
remain outside the adapter.

Both actual targets pass six Rust cases/131 counted requests, including
10 Send grants, nine multipart requests, 13 URL requests, 19 binary GETs and
two ordinary logins; two registrations are excluded. Real file cryptography
checks authentication before decryption for arbitrary and empty plaintext.
Fresh URL checks separate current policy/limit behavior from physical deletion.
Eight host tests additionally cover rollback/retry, signer/byte reopen,
create-only upload, scalar projection, query/multipart parsing and direct account
FK cleanup. The separate official CLI 2026.10.0 file run passes all twenty
commands on both targets with exact output bytes and strict negative categories;
owner get/list still use synced cache. Text20 and baseline120 remain separate.
No captured trace, live maximum upload/TTL, full transport/Range, email OTP,
enterprise configuration, notification/rate/cron or JWT-algorithm equivalence
claim is introduced. Independent MIT/Apache implementation retains the full
upstream API delivery goal.

## User-key-ID backfill contract

This deepens one existing partial route without adding a route or wire model.
`UserKeyIdRequest` now reaches reusable `VaultService::set_user_key_id` through
`AccountKeyIdStorage` and a sealed plan. At that milestone the ledger recorded 99 routed
patterns, 53 typed requests, 44 with any typed response and 89 reusable core
services; 96 upstream handlers were partial and 198 unimplemented. Full parity
and captured-trace flags remained false; that HTTP catalog had 221 names.

Six matching actual cases pass both servers with 168 counted requests per
target. The separate fifteen-command official CLI 2026.10.0 migration proof also
passes both targets, observing absent sync metadata become a stable SDK-generated
ID and decrypting a retained note after login, unlock and fresh-cache login. Supported
backfill preserves opaque strings and current-device authority, returns empty
200 or exact repeated-assignment 422, and changes only ID/account revision.
The local provider's atomic compare-and-set is stronger than upstream's check
then save. Source/client references and remaining projection/transport limits
are recorded in [the protocol](protocol.md#profile-account-keys-and-synchronization);
key rotation and all remaining account/Send contracts stay on the full roadmap.

## Prelogin discovery contract

This deepens three existing local patterns without adding routes or closing a
full-parity status. Two identity aliases are registered upstream; the legacy
`/api/accounts/prelogin` alias is a local extension. `PreloginStorage` and
`VaultService::prelogin` now return a complete typed six-field response, retaining
the earlier unsigned response API. Known signed values are preserved and unknown
selection uses the exact ordered catalog through a provider-owned secret/index.

Both actual targets pass six HTTP cases with 79 counted requests, 27 decoded
prelogins and two password logins, excluding two modern fixtures. A separate
official CLI `2026.10.0` comparison passes twenty-six commands with real
PBKDF2/Argon2 login, note encryption/sync/unlock/decryption and Argon2 fresh-cache
recovery. It counts three CLI logins and two direct prelogin HTTP requests;
client internals are uncounted and untraced. At this milestone the ledger recorded 99 routes,
53 typed requests, 44 typed responses, 92 reusable services and 227 HTTP names.
The local legacy extension has host-unit evidence only, so positive/negative
network totals rise by two to 93/92. Source/provider and no-allocator proofs
remain distinct from actual-client and captured-request evidence. Independent local secret derivation, backend
errors, absent rate controls and encoded-body limits remain qualified gaps.
All 294 upstream variants and every remaining partial contract stay on the full
API roadmap; no full-parity or captured-trace flag is enabled.

## Organization owner creation and discovery

Three route patterns add a substantive organization boundary: creation, owner
discovery and accessible collection listing. `OrganizationStorage` supplies
trusted policy, membership and stable indexed views; allocation-free services
authorize the owner and serialize public organization, membership and collection
projections. Profile and sync gain these components without implying complete
typed whole-response contracts. Last-confirmed-owner account deletion must
remain guarded before cleanup. The source model files agree between inventory
pin and release 1.37.4, including shared collection `type: 0`.

Creation is atomic in the adapter, while upstream performs sequential saves.
Default creation permission does not implement all enterprise policies or
configuration variants. General organization CRUD, invitations, members,
collection administration, sharing, notification and transport contracts remain
open. The corrected six-case HTTP comparison passes both targets with 137 counted
requests, two password logins, two refreshes and two organization creates,
excluding two modern-registration fixtures. They verify decrypted initial
collection content, exact projections/guards and both last-owner deletion
rejections without changing personal or foreign state. The separate official
CLI `2026.10.0` comparison passes nineteen commands on both servers: two CLI
password logins, one direct setup login and thirteen direct HTTP requests,
excluding one registration. It verifies membership and decrypted initial
collections after login, unlock and fresh-cache login, with preserved personal
note decryption. Cached reads do not prove direct discovery endpoint calls.
At that milestone the ledger bound 119 source hashes and added two CLI command
forms: organization and collection lists. Full-parity and captured-trace
catalogs stay empty. Corrected raw-segment classification passes dotted-ID
401/422 and percent-encoded valid-UUID regression checks in the expanded
137-request comparison.

## Organization-scoped collection subset

Three more registered handlers cover organization collection list, creation and
single access-details. `OrganizationCollectionStorage` and borrowed service
contracts apply confirmed-manager, full-access, reference and association checks
without allocation. The typed responses are a basic collection list,
`collectionDetails` on creation and the distinct thirteen-field
`collectionAccessDetails` on a single read. Existing profile/sync responses
remain adapter-built; their collection components do not complete either route.

Source pin and release 1.37.4 agree on these contracts. List/create use loose
manager guards; single read requires global manageability before path guards
and then enforces organization association. Atomic local collection/grant/revision
persistence strengthens upstream sequential writes. Owner creation does not
implement invitations, arbitrary member/group administration, bulk collection
mutations, aggregate access-details, organization ciphers or full policies.
All six selected HTTP cases pass both actual servers with 194 counted requests,
two password logins and two refreshes, excluding two modern fixtures/four
registration requests. They include five collection creates and preserve full
membership arrays and foreign/same-owner-other-organization collection baselines.
The separate official CLI `2026.10.0` comparison passes nineteen commands on both:
production list/create/get, decrypted collection names and fresh-cache recovery,
with fourteen direct HTTP requests, two CLI logins and one direct login. One
registration/two requests is excluded; client internals are uncounted and untraced.
That creation/discovery milestone bound 124 source hashes. All 294 handler
identities, partial variants and remaining families stay on the delivery
roadmap; no full or captured-trace status is enabled.

## Single collection mutation subset

Two additional registered handlers provide single organization-collection PUT
and DELETE. The opt-in `OrganizationCollectionMutationStorage` and sealed plans
reuse strict manager guards, ordered references, caller-owned request views and
typed ten-field update responses without allocation. DELETE has no response DTO.
The host atomically replaces grants or deletes only collection/ACL/link rows,
advancing old and new revision recipients while preserving cipher and attachment
data. Source and release handlers agree, but upstream writes sequentially.

Both actual targets pass the six-case HTTP comparison: 229 counted requests,
two password logins and two refreshes, excluding two modern fixtures/four
registration requests. It verifies eight updates and one deletion with all
collection read views and complete membership/foreign/sibling baselines. The
separate official CLI `2026.10.0` comparison passes twenty commands on both
targets: production edit/delete, independent authenticated name decryption,
fresh-cache reads and live/synced absence. Fifteen direct HTTP requests include
one setup login; two further logins are CLI commands, and one registration/two
requests is excluded. Client internals remain uncounted and untraced. That
mutation milestone bound 129 source hashes. Public scope is confirmed Owner/full-access
memberships. Imported Manager self-removal, revision recipients and seeded
cipher associations use separate core/local provider evidence; no membership
lifecycle or sharing API is inferred. Bulk access/delete, aggregate details, member/group policy and
notification/transport matrices remain open. All 294 source handlers retain
separate identities and every full-parity and captured-trace flag remains false.

## Organization member discovery subset

The list-only milestone below precedes the expanded [member-detail proof](protocol.md#organization-member-detail).

One further source handler lists organization membership metadata through an
opt-in allocation-free provider. It joins real member/account records, applies
confirmed-manager/full-access admission, and serializes a nineteen-field member
projection inside a list envelope. Optional collection/group views remain
caller-owned and source-scoped. The host exposes actual created Owner members;
no constant empty list substitutes for stored state.

Both actual targets pass all six HTTP cases with 190 counted requests, two
password logins and two refreshes, excluding two modern fixtures/four requests.
The cases verify exact identities/projections, profile/avatar freshness,
foreign/other-owned organization isolation and complete membership/collection
and personal/authority preservation. The separate official CLI `2026.10.0`
comparison passes sixteen commands on both targets, with seventeen direct HTTP
requests, two CLI logins and one direct login, excluding one registration/two
requests. It observes server name changes without an intervening sync and
fresh-cache recovery; client-internal traffic is uncounted and untraced. The
ledger binds 134 source hashes. Query parser and imported status/role/permission
evidence remain distinct from the public Owner/full-access comparison and from
membership administration, invitations, group lifecycle and cipher sharing.
All 294 upstream handler identities remain tracked, with every full-parity and
captured-trace status false.

## Organization member detail subset

One additional source handler reads an organization-scoped member through an
opt-in allocation-free provider and sealed direct nineteen-field response.
Confirmed Owner/Admin admission differs from the list's manager/full-access
gate. A member's valid missing and foreign IDs have the same scoped 400 error;
the separate rank-one mini-details handler is covered by the
[mini-details subset](#organization-member-mini-details-subset). Query
options preserve their absence so collection inclusion can inherit the group
flag.

The historical list milestone remains six matching cases/190 counted HTTP and
a separate sixteen-command CLI comparison. The expanded six-case HTTP
comparison passes both targets with 240 counted requests, two password logins
and two refreshes, excluding four registration requests for two modern
fixtures. The separate eighteen-command official CLI comparison also passes
both, with eighteen direct HTTP requests, two CLI password logins and one
direct setup login, excluding one registration/two requests. The added command
form requires two exact client-local already-confirmed rejections after detail
lookup, without claiming successful confirmation, invitations, user-key
delivery or a captured HTTP trace. All upstream identities and full-parity
requirements remain in scope; imported non-full-access states are provider
evidence only.

## Default no-SMTP invitation subset

One additional handler uses `OrganizationInvitationStorage`, a caller-bounded
or uncapped borrowed request and sealed per-recipient plans. It returns empty
200 without a response DTO. Missing users get real passwordless accounts,
markers and Invited memberships; existing password accounts become Accepted.
The existing registration provider completes eligible placeholders under the
same UUID and accepts all their status-zero memberships. No confirmation/key
delivery follows.

All six HTTP cases and the separate twenty-four-command official CLI 2026.10.0
comparison pass both actual targets. HTTP has 211 counted requests plus eight
modern registration requests, three password attempts (two successful, one
rejected placeholder) and two refreshes. The CLI has sixteen direct HTTP
requests plus four registration requests, three CLI password attempts and one
direct attempt. Existing command forms are reused after HTTP setup; the
invitation route has no production CLI caller or trace claim. Private
marker/verifier, creation-date preservation, rollback and reopen effects use
separate provider/SQL tests. That invitation-only milestone did not confirm
members. SMTP, invite JWTs, general group/policy administration, sharing and
complete failure/rate/transport variants remain open.

## Single-member confirmation subset

The single authenticated confirmation POST deepens the no-SMTP invitation
foundation through an allocation-free opt-in provider and sealed mutation
plan. Accepted members receive an opaque wrapped organization key and become
Confirmed. Current-device Owner/Admin, scoped target, hierarchy and state
checks remain distinct. Empty 200 has no typed response model. Bulk
confirmation is a separate upstream handler and remains unimplemented.

All six focused HTTP cases pass against both actual servers: 213 counted
requests plus eight registration requests for four fixtures, two password
logins and two refreshes. The separate official CLI 2026.10.0 comparison passes
23 commands on both, with 32 direct HTTP requests plus four registration
requests, three CLI password logins and two direct setup logins. It performs
actual confirmation and verifies assigned collection decryption after recipient
login, unlock and fresh-cache login, with unassigned collections absent.
The existing confirmation argv form is reused; the historical eighteen-command
already-confirmed rejection remains a separate milestone.

Recipient reads now include confirmed access-all/direct-grant collection
visibility, profile key delivery and exact supported sync flags. Ordinary Users
do not gain organization administration. Shared-cipher ownership/writes,
group/policy administration, SMTP, bulk confirmation and complete
failure/transport parity remain open. Static call paths and successful client
commands supply no captured endpoint trace or full-parity claim.

## Bulk organization-member confirmation subset

The separate bulk POST uses an allocation-free service with caller-owned input
and result storage. Whole-body JSON validation precedes processing. Results
preserve input order and duplicates; item failures do not stop later items.
A missing item ID instead aborts the outer request while retaining earlier
commits, with no partial result list in the response. Empty requests return a
typed empty list, not an empty body. Individual writes keep the existing
single-confirmation rollback boundary; this is not batch atomicity.

All six focused HTTP cases pass against both actual targets: 211 counted
requests plus ten registration requests for five fixtures, two password logins
and two refreshes. A separate official CLI 2026.10.0 comparison passes 21
commands on both, with 33 direct HTTP requests plus four registration requests,
three CLI password logins and two direct setup logins. It observes recipient
state and collection decryption after HTTP bulk setup; the shipped CLI has no
bulk-confirmation caller. No distinct command form, captured trace or full
parity follows. SMTP, policy/backend diagnostic variants, remaining
member/group administration and shared-cipher writes remain open.

## Single organization-member removal subset

The single DELETE adds a reusable allocation-free removal service with scoped
target authority, role hierarchy and last-confirmed-owner protection. There is
no request DTO or typed response: body bytes are ignored and success is empty
200. The provider removes scoped grants, inviter metadata and membership,
conditionally consumes the pending invitation marker and advances recipient
revision while retaining account, session and personal-vault authority.

Both actual targets pass six focused HTTP cases: 212 counted requests plus
eight registration requests for four fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 25 commands
on both, with 40 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins.

There is no shipped CLI member-removal command; HTTP setup followed by sync is
observation, not a removal caller or endpoint trace. Strong local rollback and
one revision update differ from upstream sequential cleanup and repeated
revision saves. That single-member milestone did not cover bulk deletion.
Group/SMTP/notification variants, shared-cipher writes and complete
failure/transport parity remain open.

## Bulk organization-member removal subset

The selected DELETE adds a separate allocation-free batch contract over
single-member removal rules. Required body IDs remain opaque strings, with
stable input order and duplicates. The complete body decodes before mutation;
each domain failure is a result row and processing continues. Successful
items commit independently, with no batch-wide rollback or semantic missing-ID
abort. The exact list and row projections have three fields each.

`OrganizationBulkMemberRemovalRequest` is a caller-bounded decoder for required
IDs; `OrganizationBulkMemberRemovalData` also accepts an uncapped stable owned
view. `OrganizationBulkMemberRemovalResponse` streams caller-owned result slots.
`VaultService::bulk_remove_org_members` rejects insufficient scratch before
mutation; this embedding limit is not an HTTP batch cap.

A scoped sealed context captures initial Admin/Owner authority. Its special
continuation applies only after this invocation successfully removes its own
actor. The provider still checks each target, live last-owner count and
invitation-cleanup decision. Rejecting unrelated stale actor changes and
rolling back failed individual writes are stronger than upstream's cached
request authority and sequential cleanup. Source backend Debug diagnostics
remain a qualified provider-format difference.

Both actual targets pass six focused HTTP cases: 251 counted requests plus
eight registration requests for four fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 25 commands
on both, with 40 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins.

Shared clients construct this bulk transport, but the shipped CLI has no
member-removal command. HTTP setup followed by sync/decryption is
observation, not an endpoint trace. SMTP, groups/notifications, shared-cipher
writes and complete configuration/failure/transport parity remain open.

## Single organization-member revoke/restore subset

Three PUT patterns add an allocation-free `OrganizationMemberStatusStorage`
provider and sealed `ValidatedOrganizationMemberStatus` plans. There is no
request DTO or typed JSON response: both restore variants and revoke ignore
body fields and return empty 200. The vnext route ignores the requested default
collection name. Current-device Owner/Admin authority precedes UUID guards.

Revoke preserves membership identity, encrypted key, grants and account/session
authority while hiding live collection access. Restore recovers the prior
status and selective reads. Admins may change other Admins and Managers; only
Owner targets require an Owner actor. Every eligible Owner revoke applies the
confirmed-owner count safeguard, even for an Invited/Accepted Owner target.
Invited-status-zero restore succeeds without changing status. Local SQL tests
prove its repeated revision advancement; HTTP evidence covers wire status and
preserved grants, not that hidden revision effect.

Both actual targets pass six focused HTTP cases: 265 counted requests plus
ten registration requests for five fixtures, two password logins and two
refreshes. The separate official CLI 2026.10.0 comparison passes 31 commands
on both, with 43 direct HTTP requests plus four registration requests, three
CLI password logins and two direct setup logins.

The CLI observes HTTP setup through login sessions, sync and fresh-cache
decryption.
One strict revoked-confirmation rejection checks fetched metadata, not a
successful confirmation or revoke/restore caller. No endpoint trace or new
command form is inferred. Configured 2FA fallback/SingleOrg policy effects,
SMTP, events/groups, bulk status changes and shared-cipher writes remain open.
Local atomic status/revision and live commit checks strengthen source failure
and concurrency timing; full parity remains false.


## Bulk organization-member revoke/restore subset

Two PUT routes add ordered bulk status transitions over the existing
allocation-free single-member provider. Revoke accepts absent/null `ids` as
an empty batch; restore requires the string array. IDs remain opaque and
ordered, including duplicates, empty strings and escaped values. The entire
body decodes before mutation. Caller-owned output slots and a stable indexed
input view impose no intrinsic HTTP item cap.

The [pinned shared client service](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts#L343)
constructs both bulk transports. The pinned server inventory records
`bulk_revoke_members` and `bulk_restore_members` separately from the single
routes. Each exact result row has `id`, `error` and
`object: "OrganizationUserBulkResponseModel"`; the enclosing list has
`data`, `object` and `continuationToken`. An item failure does not abort later
rows or undo earlier commits. Duplicate IDs observe earlier transitions.
Self-status changes remain prohibited. Current-device Owner/Admin authority
precedes organization UUID and whole-body guards.

Both actual targets pass six focused HTTP cases: 286 counted requests plus
ten registration requests for five fixtures, two password logins and two
refreshes. The suite checks optional-versus-required schemas, opaque IDs,
ordered domain failures and successes, duplicates, role/self/Owner rules,
retained account/key/grant authority and selective visibility recovery.

The standalone adapter atomically commits each status/revision change and
rechecks live authority and target metadata. A local SQL failure-injection
test proves an earlier success survives, the failing item rolls back and a
later duplicate is still processed. Those guarantees strengthen upstream
sequential revision/save and cached-role timing. Provider diagnostics are
mapped to public errors rather than upstream backend Debug text. Configured
2FA enrollment/SingleOrg effects, SMTP/events/groups and complete
configuration/failure/transport parity remain open.

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
reference's empty 200 response; a tightened existing Rust fixture catches the
previous 204. Both also navigate Trash, decrypt the trashed login, restore it,
verify its persisted edit in All items, retrash it, and permanently delete it
through the ordinary confirmation. Restore and permanent deletion return 200.
The reference's permanent-delete response is empty with no Content-Type; the
adapter now matches that empty 200 instead of 204. The existing final Rust
cipher-read case checks DELETE 200/empty and then a missing-item read, bringing
its unchanged six-case comparison to 337 requests per target. Other item types,
notification WebSockets and the wider web interface remain open. This is not evidence for the
unmodified official Web artifact or complete API parity.

The [portable setup](../tools/web-compat/README.md) verifies the immutable image,
all image blobs, official Chromium 149.0.7827.55 archive and executable, and three
web bootstrap bundles. Playwright-core 1.64.1 is locked separately. A dedicated
Linux x64 CI job runs the same disposable HTTPS comparison. Fresh anonymous
image acquisition and the supplied-cache path both pass locally; inherited
browser/HTTP debug modes are suppressed before credentials are created.

## Organization member bulk public-key lookup subset

`POST /api/organizations/{org_id}/users/public-keys` adds a scoped,
read-only lookup under current-device, confirmed Owner/Admin authority. The
[pinned request/route contract](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs#L1696-L1739)
is separate from the actual Vaultwarden 1.37.4 release used for both comparisons.
This adds one partial upstream handler; full parity remains false.

The required canonical `ids` list contains opaque membership IDs. Whole-body
JSON decoding precedes lookups; missing/null/mistyped IDs reject with 422 and
malformed syntax/UTF-8/trailing input with 400. Empty and positional `[[]]`
requests return an empty JSON list. Unknown fields are ignored. Organization
UUID/path admission remains separate from exact, case-sensitive body IDs.

The response has exactly `data`, `object: "list"`, and `continuationToken: null`.
Each matched row has exactly `id` (membership ID), `userId` (account ID), `key`
(string or explicit null), and `object: "organizationUserPublicKeyResponseModel"`.
Missing scoped memberships are omitted, including foreign memberships in
another owned organization or belonging to the same account. Successful rows
retain input order and duplicates; an actual 1025-item duplicate request passes.
An account ID never substitutes for a membership ID.

The Linux host limits a request to 4,096 IDs. Decoding stops at the first excess
entry with 422 before allocating result slots or performing member-key lookups;
it does not reserve an untrusted sequence size hint. The local boundary/work
regression uses a lazy five-million-entry input without allocating that input.
This is a host resource policy, not a verified upstream count boundary. The
allocation-free core continues to accept caller-provided indexed batches.

Before loading owned public-key snapshots, scoped SQL returns only the lengths
of matched member IDs, account IDs and keys. The host charges every duplicate,
counts UTF-8 bytes rather than characters, and adds 128 fixed bytes per row. More
than 8 MiB of this unescaped result material rejects with 422 before result
allocation. JSON escaping can expand encoded bytes; this is a local memory
budget, not a verified upstream byte limit or an exact encoded-response cap.
The regression enters the same host response path with repeated control/Unicode
keys, checks its byte boundary and scoped omission, and preserves account/vault
state.

An existing account without a public key retains its row with `key: null`.
Portable modern registration with `keys: null` and an invited passwordless
placeholder verify this independently of missing-row omission. The individual
account-public-key GET instead returns 404 for the null key. Empty and synthetic
future-format strings remain exact; client acceptance of invalid key formats is
not implied. Actual targets include Invited 0, Accepted 1, Confirmed 2 and Revoked
-1, and Owner/Admin/Manager/User roles, without target eligibility filtering.
Accepted Admin, confirmed Manager/User and revoked Admin actors are denied;
a confirmed Admin can read and a revoked Admin remains a readable target for
an eligible Owner.

`OrganizationMemberPublicKeysRequest` is a caller-bounded borrowed decoder;
`OrganizationMemberPublicKeysData` also supplies an uncapped stable owned view.
`OrganizationMemberPublicKeyStorage` returns owned scoped public metadata with
`AsRef<str>` handles, without requiring Clone, Debug or Serialize. `None` means
no scoped member/account; `Some(record)` with no public key means an existing
null-key account. The core preflights the entire view and caller-owned output
capacity, validates returned organization/membership associations and compacts
found rows into a contiguous ordered prefix. Its sealed row/list serializers
perform no storage access. The adapter selects only public identifiers/key in a
scoped join and holds its lock through admission and response construction.

The RISC-V link consumer decodes required IDs, calls the real service through
stack-owned storage, and serializes duplicate rows while omitting absent records in caller-owned buffers
without allocator/std/undefined symbols. Firmware is linked, not executed.
HTTP, SQL, clocks and client cryptography remain adapters. Local provider
failures or misassociation clear partial output and return a safe outer error;
this does not reproduce upstream finder APIs that can collapse backend failures
into absence, or establish complete failure/concurrency timing parity.

Both actual targets pass six focused HTTP cases: 431 counted requests plus ten
registration requests for five fixtures, two password logins and two refreshes.
Snapshots preserve accounts, personal ciphertext, keys, revisions, memberships,
roles/grants, organization state and device/session authority. Single-member
confirmation/revoke/restore calls establish fixture states; the new POST does
not mutate them.

A separate official CLI 2026.10.0 comparison passes 16 commands on each target,
with 32 direct HTTP requests plus four registration requests for two fixtures,
two CLI password logins and two direct setup logins. Two direct bulk reads
bracket HTTP confirmation setup. Exact bulk/individual/registered key equality,
three cached/remote CLI fingerprint equalities, one distinct-account fingerprint
check, personal-note decryption and organization-collection decryption pass.
Client-internal requests are uncounted/untraced; totals remain separate from the
120-command baseline and other focused suites.

[Client source b449ac1](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts#L215-L228)
bundles this bulk API, but the shipped CLI
[confirmation branch](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/admin-console/commands/confirm.command.ts#L45-L96)
fetches one account public key. `get fingerprint me` reads its cached key;
UUID-targeted fingerprints use the individual GET. No bulk CLI caller, new
command form or captured route trace follows. Vaultwarden Web 2026.7.0's
BulkConfirmDialogComponent source map has a static Accepted-member caller;
its distribution layer is `d7b6e37be08b53480724fb772207fdfc1d75a2d150580c41348a82e7fa52403b`.
That source evidence does not establish browser execution of this endpoint or
make the UI's Accepted-only selection a server filter.

Configured policy/group/SMTP variants, automatic confirmation and provider-key
APIs, imported unknown statuses, actual dangling-account/backend failure cases,
and complete error/transport/body-limit parity remain open. Synthetic local
provider tests do not establish those actual-server variants. General sharing
and the full upstream API remain unfinished.
## Organization member mini-details subset

`GET /api/organizations/{org_id}/users/mini-details` adds the distinct
rank-one read before the UUID-based member-detail route. Actual Vaultwarden
1.37.4 black-box observations establish the response, admission and state matrix;
the pinned server inventory remains a separate source revision. This one handler
is partial and the full upstream API remains unfinished.

The envelope has exactly `data`, `object: "list"` and `continuationToken: null`.
Every row has exactly `id` (membership identity), `userId` (account identity),
`email`, `name`, `type`, `status` and `object: "organizationUserUserMiniDetails"`.
All native Invited 0, Accepted 1, Confirmed 2 and Revoked -1 target states remain
included. Stored Manager role 3 projects as type 4. Provider order is preserved;
the observed SQLite insertion order is not claimed for other backends.

Mini names come from the account, independently of the full member projection's
status-based name visibility. A native passwordless invitation placeholder has
its email as its stored name, so mini returns that string while the richer member
row exposes null. Actual live Unicode/NUL and empty-name profile updates remain strings.
Revoked target reads retain the existing account name. No key, credential, avatar,
permission, collection/group or other rich account field appears.

Current-device, confirmed Owner/Admin/Manager admission precedes UUID guards.
A confirmed restricted Manager without `access_all` can read mini rows; the
regular nineteen-field member list still returns 404 for that actor. Ordinary
Users and Accepted/Revoked Admin actors are denied. Foreign/uppercase organization
paths fail admission; a malformed path with an authorized organization query
reaches the separate 422 path guard. A valid path wins conflicting query values.

GET bodies are ignored, including invalid JSON/UTF-8 and different media types.
`includeGroups`, `includeCollections` and unknown query values cannot change the
seven-field projection. Trailing slashes and encoded static mini-details letters
or hyphens are matched before the UUID-member route. POST/PATCH unsupported
methods and the existing DELETE UUID fallback are compared. Reference PUT 422 is
an observation of the adjacent still-unimplemented member-edit family and is
excluded from matched GET claims; this slice adds no PUT route or artificial
fallback for that unimplemented service.

`OrganizationMemberMiniStorage` supplies a stable minimal indexed view through
`OrganizationMemberMiniData` and `OrganizationMemberMiniRecord`. The core service
checks confirmed manager authority and validates every row's completeness and
organization before lending the sealed exact serializer. It applies no full-list
`access_all` gate and allocates no member buffer. The adapter owns a minimal SQL
account/membership join, without loading key material or traversing ACLs. Its lock
covers admission/read/projection. The bare-metal link consumer exercises the real
provider/service/serializer with stack-owned data; firmware is linked, not run.

Both actual targets pass six focused HTTP cases: 619 counted
requests, 2 password logins and 2
refreshes, excluding 3 modern registrations and
6 registration requests. Explicit setup confirmations,
status transitions and three profile-name writes establish fixture states; the
mini reads preserve accounts, personal ciphertext, keys, revisions, memberships,
grants, organization and device/session authority.

A separate official CLI 2026.10.0 comparison passes 18 commands on
both targets, with 21 direct HTTP requests, 2
CLI password logins and 1 direct setup login,
excluding 2 registration requests for one fixture.
The existing shared observer adds three explicitly direct mini GETs around
initial, live-name and fresh-cache checks. Production CLI commands continue to
use full member/detail discovery; its two strict already-confirmed controls do
not establish successful confirmation or a mini caller. Existing command forms
are reused, and focused totals are separate from the 120-command baseline.

The [pinned shared client method](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/libs/admin-console/src/common/organization-user/services/default-organization-user-api.service.ts#L81-L92)
and mini response model are bundled source evidence, not proof of CLI reachability
or actual browser execution of this GET. No captured route trace, new command form
or web-vault mini-flow compatibility is inferred. Configured groups/policies,
imported unknown roles/statuses, dangling-account/backend/error behavior,
concurrency/transport limits, cross-backend ordering, member editing and sharing
remain open. Local provider tests and linked firmware do not close those variants.

## Single organization-cipher sharing subset

`PUT /api/ciphers/{cipher_id}/share` adds the single attachment-free
secure-note sharing subset. Existing personal create/update/import remain
organization-rejecting services. The [pinned PUT declaration](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L1001)
and its separate POST/bulk aliases remain distinct from the actual Vaultwarden
1.37.4 runtime used for paired comparisons. This PUT is partial; full API parity
remains false.

The required `collectionIds`/`cipher` wrapper accepts the measured PascalCase and
mixed outer aliases. The host bounds decoding to 4096 selected IDs and rejects
an excess with 422 before any association transaction. This is a local work
budget, not a verified upstream count limit or a total response-byte bound. Native confirmed writable User, readonly/manage, hidden-
password, restricted Manager and full-access fixtures have distinct admission.
Accepted/revoked/nonmember or foreign-source controls fail. Empty selection and
duplicates are measured separately. Missing/null inner `organizationId` follows
the observed personal-payload update branch; the path ID remains authoritative.

Collection association is sequential. `[valid, foreign-or-missing]` returns 400
after retaining its valid prefix and advancing source/recipient account revisions,
while source ownership, ciphertext, key, cipher revision, favorite and folder
remain unchanged. The submitted replacement payload is not applied. Invalid-first
selection has no measured mutation. Only the final sealed phase replaces opaque
payload and canonical ownership; a whole-share atomic rollback is not claimed.

Historical collection links can survive a retry into another organization.
Confirmed membership in the cipher's current organization remains required.
Such a member can gain access through a linked collection grant from the older
organization; paired User and Manager see their older granted collection ID.
A fresh current-organization cipher without a grant remains inaccessible to the
restricted Manager. Eligible full viewers retain every linked ID. Association
scope, actual collection organization and viewer grants stay distinct.
The final paired HTTP suite includes retained full-viewer historical IDs,
confirmed current-organization Manager/User access via an older collection grant,
fresh restricted Manager denial without a grant and retry revision fanout. The separate B-only
selective-recipient result remains native reference-only evidence.

Readonly recipient single GET returns `collectionIds: []`, while list/sync include
the associated visible ID. All three have edit/delete/restore false and password
visibility true. Writable hide-password grants instead preserve edit/delete/
restore and set `viewPassword` false. Folder/favorite/archive annotations belong
to each viewer. The measured default personal/shared `organizationUseTotp` is
true; arbitrary configured capability policies remain unverified. Success uses
thirty known `cipherDetails` fields for these inputs, but response projection is
adapter JSON rather than a complete borrowed typed serializer. Unknown opaque
extensions are preserved independently of measured request-only metadata removal.

`CipherShareRequest` is an optional caller-bounded borrowed wrapper.
`CipherShareIdsData` also accepts uncapped stable views. Owned `AsRef<str>` source,
membership and collection snapshots need no Clone/Debug/Serialize. The core
validates associations, permissions and complete input; sealed association and
payload plans leave persistence, clocks, HTTP and key wrapping in adapters.
`resolve_cipher_access` is a pure allocation-free decision over confirmed current
membership and verified associated grants, including historical collections.
Each trusted association record carries the cipher's canonical organization
separately from the collection's actual organization; viewer and association
scope are still validated. Route-specific ID display remains separate. SQLite migration uses canonical personal
owner XOR organization ownership, preserves opaque documents/child references,
and keeps private annotations separate. Account cleanup preserves organization
ciphers and other viewers while deleting only the departing user's annotations.
Local transaction/reopen/rollback/live-authority checks do not prove upstream
backend, timing, concurrency or durability variants. The RISC-V consumer links
the real decoder/service/prefix/final/access paths with fixed storage; firmware
is not executed and no opaque adapter serializer is implied by that link.

Both actual targets pass seven HTTP cases: 538 counted requests,
2 password logins and 2 refreshes,
excluding 2 registrations/4
registration requests. The separate official CLI 2026.10.0 comparison executes
`bw move` in 21 commands with 25 direct HTTP requests,
3 CLI and 2 direct password
logins, excluding 4 registration requests.
It decrypts the same-ID item immediately and after owner sync/fresh-cache login,
then in a fresh confirmed selective recipient cache, including collection
decryption. These totals are separate from the unchanged 120-command baseline.

A valid older client revision rejects the final payload phase after successful
association/account-revision steps persist. Equal, future, malformed, missing and
null revisions follow the measured accepted controls. Selection errors win before
the final revision guard; null organization runs the same guard without association
steps. Timestamp parsing stays in the provider; the core controls the final phase.
The final SQLite transaction rechecks live destination grants in the target
organization, retaining historical links for independently verified later reads.

Additional paired Vaultwarden 1.37.4 review probes distinguish historical read
admission from response flags. After revoking the older membership, a confirmed
current-organization User still reads the cipher, but all three projections hide
the older collection ID. Single GET retains edit/delete/restore and password
visibility; list/sync clear those flags. Restoring the older membership restores
its collection and flags; removing it denies the historical reader on both
servers. Actual shared writes were not exercised by these probes.

Personal-target sharing synchronizes the archive annotation with the payload in
the final transaction. Missing/null `archivedDate` clears it; the measured valid
older/newer dates replace it and render with six fractional digits. Malformed
date variants remain outside this comparison. A complete positional inner cipher
array now rejects with 422 before association or revision effects, like the native
target; native Rocket's object-valued `error` and the adapter's string-valued
schema error remain distinct. These direct probes do not add CLI or browser claims
or change the seven-case suite totals above.

Organization attachment metadata authorization remains a separate open parity
item: the current attachment metadata provider requires personal ownership.
Native-only attachment probes accept omitted/empty/partial/complete rewrap maps.
Modern attachments sharing the unchanged per-item key remain decryptable in all
four cases, so a complete-map requirement would reject measured valid behavior.
Legacy direct-user-key attachments need the relevant client rewrap to decrypt;
opaque payload acceptance alone does not establish attachment-flow compatibility.

The [pinned CLI command](https://github.com/bitwarden/clients/blob/b449ac1d255784380d75ef026343198891286be7/apps/cli/src/admin-console/commands/share.command.ts#L88)
delegates to the bundled SDK `share_cipher`/`put_share` path. The paired runner
captures no endpoint trace or client-internal request count. A separate Node
reference-only exploratory trace is not promoted into a local trace catalog.
Browser flows, deprecated `share` alias, attachment-bearing moves, other item
types, general shared edits/lifecycle, bulk/import/admin, configured policies/
groups/SMTP, exhaustive errors and full API parity remain open.

## Organization web read subset

Three GETs support organization views used by the actual web client:
`/api/ciphers/organization-details?organizationId=...`,
`/api/organizations/{org_id}/collections/details`, and
`/api/organizations/{org_id}/groups`. The last implements only the explicit
provider-proved default with no created groups. All three handlers remain partial.
Pinned [route declarations](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/organizations.rs)
identify the protocol inventory; actual behavior comes from Vaultwarden 1.37.4.
The image build is `7c188967e7a467b19b2757bc3326f9cf3ccae327`, separate from that
inventory revision. The verified image-derived runtime binary SHA256 is
`a5b13f4da66609b9a0c24fac68e3e1f83fbf23b512b5114a54c6fc4c92cf7a4e`.

All successful envelopes have exactly `data`, `object: "list"`, and
`continuationToken: null`. Organization ciphers require confirmed Owner/Admin
or the measured full-access Custom fixture. Restricted Manager/Custom actors
receive 404; User, accepted/revoked Admin and nonmembers receive 401. Only
canonical organization-owned ciphers appear, even when the actor owns another
organization. The exact 24-field known projection excludes ordinary cipher
`archivedDate`, `edit`, `favorite`, `folderId`, `permissions` and `viewPassword`;
`fields` and `passwordHistory` are arrays in the tested projection: absent and
explicit-null inputs become empty arrays, while nonempty encrypted entries
remain exact. Opaque encrypted
payloads stay in the adapter and never round-trip through a partial core DTO.
Unknown encrypted extensions remain preserved without an upstream parity claim.
Attachments, other cipher types and complete response variants remain open.

Collection-list details admit current confirmed managers. Owners/Admins and
full-access Custom see all collections; the restricted legacy Manager sees only
its assigned readonly collection, and restricted Custom with no grants sees an
empty list. User/accepted or revoked Admin/nonmembers receive 401. Aggregate rows
have exactly 14 known fields, adding only `unmanaged: false` to the separate
13-field individual-detail projection. Individual details still omit that field.
Aggregate `users` includes confirmed implicit full-access memberships plus direct grants,
with exact `id`, `readOnly`, `hidePasswords`, `manage` rows and verified identity/
flag sets. Accepted, invited passwordless and revoked Admin targets without direct grants
are omitted; confirming/restoring Admin adds the implicit entry. Invited and
revoked directly assigned Users retain their grant entries. These target states
remain separate from current confirmed actor admission. Arbitrary
nested ordering and configured groups are not established.

The measured full-access Custom fixture requests role 4 and sets
`createNewCollections`, `editAnyCollection`, and `deleteAnyCollection` true.
Legacy requested Manager 3 serializes as wire role 4. These fixtures do not
establish every custom permission combination or blanket Manager full access.
Groups share the stronger cipher-list guard and return the exact empty envelope
only when `OrganizationGroupPresence::NoCreatedGroups` is explicitly proved.
Configured/unknown provider state fails closed as unsupported 403; this is a
local safety boundary, not an upstream configured-group contract. The default
adapter has no group storage/administration and refuses to fabricate an empty
list if group-storage schema is present. Group CRUD, row models and ACLs remain
separate work.

The cipher query requires `organizationId`. Missing/empty/malformed/unknown/
foreign/uppercase values deny 401; the first duplicate wins. Percent-encoded
names/values and dotted/bracketed root names are accepted, unrelated query
fields ignored. Collection/group path IDs remain exact and case-sensitive;
unknown/foreign/uppercase IDs deny 401. `includeAccessDetails` true/false/invalid
and unrelated queries do not alter the measured collection projection. This is
bounded query evidence, not complete Rocket parsing or method/rank parity.

`OrganizationWebReadsStorage` opts into stable indexed cipher metadata and
borrowed collection access views. The allocation-free service applies current
admission, validates canonical IDs, actor/scope and nested views, then lends
sealed serializers/grants. The adapter holds the lock through projection and
serialization. Cipher documents, HTTP queries, SQL and crypto stay adapters.
The linked RISC-V consumer calls all three real services and serializes typed
aggregate/empty responses into stack buffers without allocator/std/undefined
symbols; firmware is linked rather than executed.

Both actual targets pass six reusable HTTP cases: 156 counted requests,
including two password logins and two refreshes, plus four registration requests
for two accounts. Seven organizations cover positive/negative roles, accepted/
confirmed/revoked/restored Admin states, query guards, two readable organization
cipher scopes, direct/implicit grants and preserved ordinary ciphertext, keys,
revisions and session authority. A separate official CLI 2026.10.0 observer
passes 21 commands and 25 direct HTTP requests per target, including two CLI
password logins and one direct login, plus two registration requests. Nine
new-route reads are explicitly native harness calls. Actual CLI collection
create/list/get/sync/cache/fresh and shared-note authenticated decryption prove
usable state. No new CLI caller, command form, internal request count or captured
route trace follows. The inherited 120-command baseline stays a separate suite.

A separate reference-only owner UI experiment used Vaultwarden Web 2026.7.0,
Chromium 149.0.7827.55 and Playwright 1.64.1. It created a personal note, then an
organization and collection, assigned the note to that collection and reopened
it. Its 32 allowlisted API responses included these three reads and the distinct
bulk `PUT /api/ciphers/share` mutation. That UI experiment ran only against
Vaultwarden; it is not paired browser compatibility for organization creation,
these reads, or bulk sharing. The existing paired personal-web smoke retains its
own narrower evidence. Configured policies/groups/SMTP, attachments, complete
query/error/transport/failure/concurrency variants and full upstream parity
remain unfinished.

## Bulk organization-cipher sharing subset

This partial `PUT /api/ciphers/share` slice accepts the measured native
attachment-free secure-note bulk wrapper. Both actual Vaultwarden 1.37.4 and
no-warden pass seven named direct HTTP cases (1106 counted requests,
3 password logins), excluding 3
registrations/6 registration requests per target.
The [pinned declaration](https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/api/core/ciphers.rs#L1021) remains separate from that runtime executable.
All full-upstream-parity flags remain false.

Required exact `ciphers` and `collectionIds` arrays and the observed positional
`[ciphers, collectionIds]` form are compared. Entire typed structure and every
item ID's presence are checked before mutation. Present missing sources are
looked up only when reached: items run in reverse order, with a fresh lookup for
each duplicate, so the first input payload wins. Collection IDs run forwards.
A later invalid selection retains the current valid association prefix and account
revision fanout; completed suffix items also survive. The current failed item's
payload, canonical ownership, cipher revision and private annotations stay intact.
There is no whole-batch rollback or global source-existence prevalidation claim.

Source update authority and destination permission differ. Confirmed canonical
membership and validated current/historical association facts are required for
shared sources. A readonly existing source with an assigned manage grant can be
updated by bulk while its ordinary GET edit/delete/restore flags remain false.
Readonly NEW selections still fail even with manage. Shared sources require their
same nonnull organization; personal missing/null targets remain personal and skip
selection lookups. Native empty/plain names do not pass through strict
personal/single payload validation. Inner `encryptedFor` is a required nonnull
string whose value does not authorize sharing or require a UUID; the outer field
is ignored. Typed parser categories preserve field-data errors as 422 even when
invalid input includes decoder-message text; positional wrapper overflow is 400.
Missing/null `favorite` preserves the actor's value for measured personal updates,
personal-to-organization moves and same-org updates; explicit false applies.
Missing/null `folderId` clears the actor's folder. Invalid or foreign
folders fail after successful collection associations have already committed.
Final payload/ownership and the actor's folder/favorite update atomically locally,
preserving other viewers' annotations and opaque encrypted fields/extensions.
Personal-target archive metadata joins that final transaction: missing/null clears
it; measured valid older/newer dates replace it and normalize to six fractional
digits. A separate five-case comparison checks subsequent GET/list/sync agreement
and preserved opaque payload/private state. Archive-write failure rolls back the
current item and account locally; malformed dates remain unmeasured for this route.

A dedicated revision-metadata case accepts older, future, malformed, omitted,
null and equal date strings for personal-to-organization updates, plus an older
same-org shared update. Those successes apply opaque payloads and advance cipher
and reader account revisions while retaining each viewer's private annotations.
A numeric date is a whole-request 422 with unchanged state. Bulk therefore does
not inherit the separately measured single-share stale-date guard. Empty selected
collections reject before provider access; every reachable final target plan has
nonempty exact destination checks. This is not a concurrency-parity claim.

Success is exactly empty 200 with no Content-Type. There is no bulk list response
or complete typed cipher serializer. `CipherBulkShareRequest` is a caller-bounded
borrowed wrapper, `CipherBulkShareItemRequest` only its minimal decision view;
adapters retain the original opaque JSON instead of serializing that narrow view.
The host streams at most 4096 ciphers and 4096 selections and rejects a checked
cipher-count times selection-count estimate above 8192 association attempts before
mutation. These are explicit local count/work policies, not upstream limit or
response-byte parity. The reusable indexed `bulk_share_ciphers` service is uncapped.

The separate official CLI 2026.10.0 observer passes 37 commands with
31 direct HTTP requests, including exactly two DIRECT bulk
PUT mutations, 4 CLI and 2
direct password logins, excluding 2 registrations/
4 registration requests per target. It verifies
fresh owner/recipient decryption, assigned collections, per-viewer folders/favorites,
retained account keys/profiles and personal controls. It reuses existing command
forms and does not demonstrate a production CLI bulk caller or captured endpoint
trace; focused totals remain separate from baseline120.

The independently measured combined organization-read plus bulk browser flow is
separate integration evidence reserved for a later browser harness PR. This
standalone API slice claims no actual browser execution or ancillary-read coverage.
General shared Save/edit/lifecycle, attachments, other item types, configured groups,
policies/SMTP, backend/failure/concurrency variants and full parity remain open.
Fourteen core tests, the static-route precedence test, fourteen host regressions
and the real fixed-storage noalloc decoder/prefix/final/source-access link
exercise provide local contracts;
firmware is linked rather than executed, and these are not upstream backend proofs.
