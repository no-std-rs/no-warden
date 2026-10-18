# no-warden

A reusable Rust foundation for Bitwarden-compatible services, with a `no_std`,
allocation-free API and business-logic core and a standalone local-storage server.

Full Bitwarden/Vaultwarden API parity is the delivery goal. The current verified
slice covers real Bitwarden CLI personal-vault lifecycles, JSON/CSV imports,
archive actions, API-key login followed by password unlock, and encrypted
attachment round trips. The remaining surface
is tracked in the [API parity inventory](docs/api-parity.md). This is an early
implementation, not yet a production password manager or a complete Vaultwarden
replacement. Client-side vault encryption stays with the client.

The core must not depend on HTTP frameworks, databases, operating systems, or a
global allocator. Host applications provide storage, time, randomness, password
verification, and transport. The standalone adapter demonstrates those boundaries.

Development proceeds in reviewable pull requests with Rust checks, real-client
integration tests, and Codex review. See [ROADMAP.md](ROADMAP.md).

```sh
cargo run -p no-warden-server --release
```

The server listens on `127.0.0.1:8000` and persists encrypted vaults in
`no-warden.db`. Set `NO_WARDEN_DB`, `NO_WARDEN_BIND`, and `NO_WARDEN_URL` to change
the database, listener, and externally advertised URL. Current clients require
HTTPS; use a trusted TLS reverse proxy for manual client connections.

In another terminal, run the actual client and authorization checks:

```sh
npm ci --prefix tools
bash tools/e2e.sh
node --test tools/server-tests.mjs
```

The suite runs the pinned official Bitwarden CLI `2026.10.0`, creates disposable
accounts, and provides trusted loopback TLS automatically. It uses its own CLI
cache and never opens your existing vault. See [test tools](tools/README.md).

For the Rust checks and the separate bare-metal consumer:

```sh
cargo test --workspace
cargo build --manifest-path checks/no-alloc/Cargo.toml \
  --target riscv32imac-unknown-none-elf
```

The library lives in [`crates/no-warden`](crates/no-warden). Its `VaultService`
accepts a caller-provided `Storage` implementation; borrowed request models and
bounded collections require no allocator. Opt-in `ImportStorage`,
`CipherBulkStorage`, `IdentityStorage`, and `AttachmentStorage` providers add
batch operations, credential services, and attachment authorization/transitions
without adding an allocator. See [architecture](docs/architecture.md)
and [CI and review](docs/ci.md).

Use the core from another application:

```toml
[dependencies]
no-warden = { git = "https://github.com/no-std-rs/no-warden" }
```

Supported personal-vault operations include registration, PBKDF2/Argon2 KDF
discovery, password and API-key authentication, key retrieval/rotation, password
refresh rotation, profile and sync, folders, encrypted ciphers, JSON/CSV import,
bulk trash/restore/deletion, archive/unarchive, and personal attachments with
legacy/v2 uploads, scoped downloads, metadata updates and deletion cleanup.
Organizations, sharing, remaining attachment variants, Sends, notifications and
the remaining account APIs are tracked in the roadmap.
The local conformance adapter needs further hardening before production use.
See the [verified compatibility matrix](docs/compatibility.md) for exact scope.

Plain `cargo build` and `cargo test` select the allocation-free core. The
[`embedded vault consumer`](checks/embedded-vault/README.md) implements owned,
fixed-capacity storage and exercises the actual business logic without `std`
or an allocator. Host tests and a RISC-V executable link verify that boundary.

Licensed under MIT OR Apache-2.0. This is an independent project and is not
affiliated with Bitwarden or Vaultwarden.
