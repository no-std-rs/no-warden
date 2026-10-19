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
| [Current coverage](../compatibility/no-warden-coverage.json) | 102 routed patterns, 54 with typed requests, 95 with reusable core service behavior; each carries its narrower limits |
| Runtime CLI comparison | Official CLI `2026.10.0`: all 120 commands pass against the adapter and official Vaultwarden `1.37.4`, including attachment byte round trips and authenticated public-key fingerprints. This runtime baseline differs from the inventoried Vaultwarden main revision above. |
| Focused text-Send CLI comparison | A separate official CLI `2026.10.0` run passes all twenty Send commands against both actual servers. Owner get/list use cache after sync; no captured route trace is claimed. |
| Focused file-Send CLI comparison | Another separate official CLI `2026.10.0` run passes twenty commands on both servers, including two byte-exact file receives. Owner cache operations remain distinct from traced HTTP reads. |

The coverage ledger joins all 294 declared upstream handlers to an explicit
status: 99 partial and 195 unimplemented. Query/rank/configuration
variants retain separate upstream identities, and path parameter renames have
explicit mappings. Three additional local aliases are tracked as extensions;
they do not replace the corresponding upstream endpoints.

47 local patterns have some typed response representation, including
the domain settings projections and empty mutation response, explicit API-key
responses, and attachment responses. Bulk cipher lists use the generic `ListResponse`
wrapper; a complete borrowed cipher response model is still absent, and single
archive responses remain host-built JSON.

The ledger records positive or restart HTTP evidence for 96 patterns, negative
HTTP evidence for 95, 233 named HTTP cases, and 46 CLI command patterns. These are
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
failure preserves existing accounts and vaults. SMTP delivery, invitation and
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
Vaultwarden 1.37.4: 335 counted requests per server, four successful password
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
The ledger binds 119 source hashes and adds two existing CLI command forms to
its catalog: organization and collection lists. Full-parity and captured-trace
catalogs stay empty. Corrected raw-segment classification passes dotted-ID
401/422 and percent-encoded valid-UUID regression checks in the expanded
137-request comparison.
