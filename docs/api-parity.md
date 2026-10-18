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
| [Shipped client calls](../compatibility/cli-routes.json) | [CLI `2026.10.0`, `b449ac1`](https://github.com/bitwarden/clients/tree/b449ac1d255784380d75ef026343198891286be7): 370 request-construction records, 305 distinct method/path pairs, 40 command declarations |
| Bundled SDK source | [`c5e53d3`](https://github.com/bitwarden/sdk-internal/tree/c5e53d3e82ab80fdc9fd79ebd74058399a6444b6), resolved from the upstream clients build lock and SDK registry metadata |
| [Current coverage](../compatibility/no-warden-coverage.json) | 28 routed patterns, 12 with typed requests, 15 with reusable core service behavior; each carries its narrower limits |

The client catalog is an overapproximation of shipped code, not a proof that all
those operations are reachable from CLI commands. Its 34 open obligations retain
dynamic destinations, typed call-graph questions, feature flags, and SDK branches.
The 22 routes served by local `bw serve` are a separate catalog; third-party,
Key Connector, provider-RPC, and server-supplied storage calls have explicit roles.
These categories are not added to a backend-completion percentage.

The current supported subset has not established full upstream parity for any
operation's entire contract. Its tested flows remain useful evidence, with
positive and negative HTTP tests and CLI command references recorded separately.
Import currently illustrates an explicit gap: `POST /api/ciphers/import` falls
through as an item update, and the actual `bw import` command has no passing
conformance scenario yet. Additional source-proven gaps remain in every API
family; the inventory is not a plan to stop after import or personal-vault APIs.

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
curl --fail --location https://raw.githubusercontent.com/bitwarden/clients/b449ac1d255784380d75ef026343198891286be7/package-lock.json -o /tmp/clients-build-lock.json
BW_CLIENTS_BUILD_LOCK=/tmp/clients-build-lock.json node --test tools/cli-inventory.test.mjs
node --test tools/api-coverage.test.mjs
node tools/check-api-coverage.mjs
```

The client check binds inventory records to the locked package integrity,
published bundle/source-map hashes, upstream SDK build-lock pins, and actual
shipped source locations. It does not promote a symbolic template or source
reference into a runtime request trace.

Implementation and test source hashes keep coverage claims tied to the audited
code. An implementation change must update the affected records and references,
then refresh `source_sha256` using `node tools/check-api-coverage.mjs
--source-hashes`. Review that metadata diff with the code change; refreshing
hashes alone does not establish new behavior. Counts are computed from records.
