# Delivery roadmap

Only mark behavior complete after verification. Compatibility is tracked by
endpoint and exercised client, not inferred from matching JSON field names.

- [x] Allocation-free core: borrowed wire types, routing, policy, storage traits.
- [ ] Standalone Rust adapter: persistent SQLite, registration, authentication.
- [ ] Personal vault: encrypted ciphers, folders, sync, trash, restore.
- [ ] Actual Bitwarden CLI end-to-end verification and Vaultwarden comparison.
- [ ] Rust CI, bare-metal compile check, Runnerless configuration, Codex gate.
- [x] Bare-metal consumer links JSON decoding/encoding without a global allocator.
- [ ] Expanded clients: browser extension, desktop, mobile.
- [ ] Device sessions, token rotation, revocation, account lifecycle and recovery.
- [ ] Organizations, collections, sharing and permissions.
- [ ] Attachments, Sends, event notifications and websocket transport.
- [ ] Two-factor authentication, passkeys, SSO and administrative APIs.
- [ ] Import/export compatibility and upstream protocol regression fixtures.
- [ ] Security audit, abuse controls, migration policy and production deployment.
