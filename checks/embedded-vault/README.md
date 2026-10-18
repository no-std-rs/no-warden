# An embedded vault consumer

This standalone crate imports `no-warden` and implements its `Storage` trait
using owned arrays: two accounts, two folders, two secure-note ciphers,
64-byte identifiers, and 256-byte encrypted text buffers. It uses neither
`std` nor `alloc`, has no allocator, and adds no dependency beyond `no-warden`.
Every replacement is fully prepared before changing storage; capacity errors
leave existing data intact.

The same service exercise runs in host tests and the RISC-V `_start`: register,
create/update a wrapped-key cipher, enforce ownership, trash/restore, clear a
deleted folder's associations, exhaust capacity, and reuse a freed slot.

```sh
cargo test --manifest-path checks/embedded-vault/Cargo.toml --locked
cargo build --manifest-path checks/embedded-vault/Cargo.toml --locked \
  --features firmware --target riscv32imac-unknown-none-elf
```

The binary is a bare-metal link demonstration, not a board support package.
No RISC-V execution is claimed by a successful compilation. Public envelope
placeholders exercise validation and ownership without implementing cryptography.
An embedding application supplies authentication, key generation, clocks,
serialization, transport, and durability. The example deliberately rejects RSA
keypairs, blob-encrypted payloads, missing legacy names, custom fields, password
history, archive dates, conditional revisions, and other cipher types rather than discarding
them. Storage accessors are for trusted
application code; expose authenticated operations through `VaultService`.

Account records retain email, optional name and password hint, KDF settings, and
the wrapped user key in bounded buffers. Authentication remains the embedding
application's responsibility: this example does not retain the client-derived
`masterPasswordHash` or implement password verification.
