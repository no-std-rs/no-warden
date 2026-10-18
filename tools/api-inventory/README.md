# Upstream API inventory tool

This host utility parses pinned Vaultwarden source with `syn`. It resolves the
registered route factories and their configuration branches without executing
upstream code. Unresolved handlers, unregistered attributes, dynamic route
construction, and unsupported factory statements fail the check.

The tool uses `std` in its own Cargo workspace. It is not a dependency of the
allocation-free `no-warden` crate.

```sh
cargo test --manifest-path tools/api-inventory/Cargo.toml --locked
cargo run --manifest-path tools/api-inventory/Cargo.toml --locked -- \
  --source /path/to/pinned/vaultwarden \
  --check compatibility/vaultwarden-routes.json
```

To inspect a new upstream revision, replace `--check` with `--sha COMMIT_SHA
--output /tmp/candidate-routes.json`. Review the source hashes, route facts, and
unsupported constructs before updating the checked inventory and CI source pin.
JSON formatting differences do not affect `--check`.

Counts describe the union of build/configuration variants. Query templates,
explicit ranks, aliases, catcher registrations, and relative mount declarations
are retained. The listed mounted URIs assume an empty configured domain path.
Automatic HEAD fallback and CORS OPTIONS are framework behavior rather than
additional source-declared handlers. Registration facts do not prove schemas,
authorization, response behavior, or client interoperability.
