# Delivery roadmap

Only mark behavior complete after verification. Compatibility is tracked by
endpoint and exercised client, not inferred from matching JSON field names.
Full API parity is the finish line. The completed foundation below is an initial
slice, and the standalone vault is a conformance adapter for the reusable core.
Continue through the remaining API families in small, green, squash-merged PRs.

- [x] Pinned exhaustive Vaultwarden route registrations, including configuration variants.
- [x] Audited current route/model/service/HTTP/client evidence with source drift checks.
- [ ] Resolve the remaining shipped CLI/SDK reachability and dynamic-call obligations.
- [ ] Implement every inventoried API contract and verify its behavior in green PRs.

- [x] Allocation-free core: borrowed wire types, routing, policy, storage traits.
- [x] Standalone Rust adapter: persistent SQLite, registration, authentication.
- [x] Personal vault: encrypted ciphers, folders, sync, trash, restore.
- [x] Actual Bitwarden CLI end-to-end verification and Vaultwarden comparison.
- [x] Personal JSON/CSV import subset: CLI JSON types 1–4, CSV types 1–2, and allocation-free batch/provider contracts with verified atomic persistence.
- [x] Rust CI, bare-metal compile check, Runnerless configuration, Codex gate.
- [x] Bare-metal consumer links JSON decoding/encoding without a global allocator.
- [x] Owned fixed-capacity vault consumer exercises service rules without std/alloc.
- [ ] Expanded clients: browser extension, desktop, mobile.
- [ ] Device sessions, token rotation, revocation, account lifecycle and recovery.
- [ ] Organizations, collections, sharing and permissions.
- [ ] Attachments, Sends, event notifications and websocket transport.
- [ ] Two-factor authentication, passkeys, SSO and administrative APIs.
- [ ] Full import/export compatibility, remaining formats and variants, and upstream protocol regression fixtures.
- [ ] Security audit, abuse controls, migration policy and production deployment.
