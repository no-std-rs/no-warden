# no-warden

A reusable Rust foundation for Bitwarden-compatible services, with a `no_std`,
allocation-free API and business-logic core and a standalone local-storage server.

The first milestone is a real Bitwarden CLI personal-vault round trip. This is an
early implementation, not yet a production password manager or a complete
Vaultwarden replacement. Client-side vault encryption stays with the client.

The core must not depend on HTTP frameworks, databases, operating systems, or a
global allocator. Host applications provide storage, time, randomness, password
verification, and transport. The standalone adapter demonstrates those boundaries.

Development proceeds in reviewable pull requests with Rust checks, real-client
integration tests, and Codex review. See [ROADMAP.md](ROADMAP.md).

Licensed under MIT OR Apache-2.0. This is an independent project and is not
affiliated with Bitwarden or Vaultwarden.
