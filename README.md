# no-warden

A reusable Rust foundation for Bitwarden-compatible services, with a `no_std`,
allocation-free API and business-logic core and a standalone local-storage server.

Full Bitwarden/Vaultwarden API parity is the delivery goal. The current verified
slice covers real Bitwarden CLI personal-vault lifecycles, JSON/CSV imports,
archive actions, API-key login followed by password unlock, and encrypted
attachment round trips. Direct HTTP comparisons also cover personal folder,
account encryption-key, profile/avatar, equivalent-domain, device-discovery,
disabled-relay push-token, auth-request creation/decision/polling, and one-use
access-code login contracts. The remaining
surface is tracked in the [API parity inventory](docs/api-parity.md). This is an early
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
Auth-request IP metadata records the direct socket peer and ignores forwarding
headers. Vaultwarden can honor configured `X-Real-IP` from trusted proxies,
including local peers by default; forwarded-IP parity remains open.

In another terminal, run the actual client and authorization checks:

```sh
npm ci --prefix tools
bash tools/e2e.sh
cargo run -p no-warden-conformance --bin no-warden-http-conformance --locked
node --test tools/server-tests.mjs
```

The suite runs the pinned official Bitwarden CLI `2026.10.0`, creates disposable
accounts, and provides trusted loopback TLS automatically. It uses its own CLI
cache and never opens your existing vault. See [test tools](tools/README.md).

`tools/e2e.sh` runs the host-only `no-warden-conformance` Rust binary. It provides
CLI orchestration, private subprocess capture, encrypted account fixtures, and
disposable loopback TLS. Its separate Rust HTTP binary checks folder, account-key,
profile/avatar, equivalent-domain, device-discovery, disabled-relay push-token,
auth-request creation/decision/polling/login, and modern registration APIs against
a configured adapter or
Vaultwarden release. Its comparisons include
the complete pinned global-domain catalog, settings replacement, sync filtering,
public known-device headers, and owner-scoped device projections. The reference
release is Vaultwarden `1.37.4`.
Existing HTTP, restart-persistence, and client-inventory checks still use
JavaScript; the broader harness migration remains open.

For the Rust checks and the separate bare-metal consumer:

```sh
cargo test --workspace
cargo build --manifest-path checks/no-alloc/Cargo.toml \
  --target riscv32imac-unknown-none-elf
```

The library lives in [`crates/no-warden`](crates/no-warden). Its `VaultService`
accepts a caller-provided `Storage` implementation; borrowed request models and
bounded collections require no allocator. Opt-in `ImportStorage`,
`CipherBulkStorage`, `IdentityStorage`, `AccountKeyStorage`,
`AccountProfileStorage`, `DomainSettingsStorage`, `DeviceStorage`,
`DevicePushStorage`, `AuthRequestStorage`, `AuthRequestResponseStorage`,
`AuthRequestLoginStorage`, `RegistrationStorage`, and
`AttachmentStorage` providers add
batch operations,
credential and account-key services, profile metadata and equivalent-domain updates, device discovery,
registration after verified login, push-token ordering, pending auth-request
creation/discovery, approval/code-protected polling, one-use access-code login,
modern account verification/finish, and attachment transitions
without adding an allocator. See [architecture](docs/architecture.md) and
[CI and review](docs/ci.md).

Use the core from another application:

```toml
[dependencies]
no-warden = { git = "https://github.com/no-std-rs/no-warden" }
```

Supported personal-vault operations include registration, PBKDF2/Argon2 KDF
discovery, password and API-key authentication, personal API-key retrieval/rotation, password
refresh rotation, account-key retrieval/initialization/public lookup, profile
name/avatar updates, equivalent-domain settings and sync, public known-device
checks, authenticated device list/lookup, auth-request creation/discovery, folders,
encrypted ciphers, JSON/CSV import, bulk trash/restore/deletion, archive/unarchive, and personal attachments with
legacy/v2 uploads, scoped downloads, metadata updates and deletion cleanup.
Device push-token write/clear aliases also pass focused HTTP and private
read-only stored-state comparisons with the relay disabled. Enabled relay
interoperability remains unverified. Auth-request comparisons cover public
creation, owner-only lookup/pending lists and device pending metadata. Approval
and code-protected response polling also pass eight focused HTTP cases against
both servers. The prior combined local HTTP milestone passes 72 cases and
3038 requests, including the eight login cases below. The adapter also implements
the approved-auth-request password
grant through an opt-in allocation-free provider: exact access code, same direct
peer, a strict five-minute lifetime and one successful use. The login can register
a different device; polling remains readable after use. Compact `authRequest`
roots include Rocket-style dotted/bracketed names, so those inputs cannot fall
back to an ordinary password. All eight focused login HTTP cases pass against
both servers: 444 counted requests each, including a real 301-second expiry
fixture. Host tests cover atomic consumption/session rollback and a private
enabled-account policy. A fresh 120-command CLI regression passes against both
corrected servers;
see the compatibility matrix for recorded results. Two-factor/mail policies,
trusted proxies, expiry cleanup and local rate controls remain open.

The modern identity registration pair is also implemented for new accounts with
SMTP disabled. An opt-in `RegistrationStorage` provider preserves opaque
credentials while the host verifies a persistent, purpose-bound email token and
commits only canonical account state. Finish also applies upstream mailbox/domain
validation after proof and KDF checks; verification issuance stays permissive.
The strict legacy registration API remains available. All eight modern HTTP
cases pass against the adapter and Vaultwarden `1.37.4`: 541 requests per server.
This HTTP proof adds no CLI registration-command or route-trace claim. SMTP, invitations/emergency
access, placeholder completion, registration configuration and abuse controls
remain open.

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
