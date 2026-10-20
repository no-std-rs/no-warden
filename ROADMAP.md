# Delivery roadmap

Only mark behavior complete after verification. Compatibility is tracked by
endpoint and exercised client, not inferred from matching JSON field names.
Full API parity is the finish line. The completed foundation below is an initial
slice, and the standalone vault is a conformance adapter for the reusable core.
Continue through the remaining API families in small, green, squash-merged PRs.

Prefer Rust for new implementation and conformance tooling. Migrate the existing
JavaScript test orchestration into Rust in reviewed chunks while continuing to
invoke the pinned official Bitwarden CLI as an external process.

- [ ] Rust conformance orchestration and fixtures replacing the growing JavaScript harnesses.
- [x] Rust support library for private subprocess capture, encrypted account fixtures, and disposable loopback TLS.
- [x] Rust folder HTTP conformance cases across the seven pinned folder routes.

- [x] Pinned exhaustive Vaultwarden route registrations, including configuration variants.
- [x] Audited current route/model/service/HTTP/client evidence with source drift checks.
- [ ] Resolve the remaining shipped CLI/SDK reachability and dynamic-call obligations.
- [ ] Implement every inventoried API contract and verify its behavior in green PRs.

- [x] Allocation-free core: borrowed wire types, routing, policy, storage traits.
- [x] Ordinary password identity grant subset: allocation-free presence/scope/proof/policy contract and source-backed HTTP parsing, verified by six matching actual Rust cases. Complete identity policies remain open.
- [x] Password-method refresh subset: allocation-free replay-preserving provider contract, current-device authority, original proof deadlines and exact responses, verified by eight matching actual Rust cases. JWT refresh encoding, SSO and broader identity policies remain open.
- [x] Personal text-Send subset: allocation-free lifecycle/provider and typed projections, six matching actual HTTP cases and twenty matching official CLI commands. Email verification, enterprise policies and full Send parity remain open.
- [x] Personal file-Send subset: allocation-free reservation/upload/download contracts, six matching actual HTTP cases and twenty matching official CLI commands with byte-exact file reception. Object storage, configured policies/quotas, email verification and full Send parity remain open.
- [x] Standalone Rust adapter: persistent SQLite, registration, authentication.
- [x] Personal vault: encrypted ciphers, folders, sync, trash, restore.
- [x] Cipher ordinary/details/admin read subset: allocation-free authorization, exact guards and opaque projections, verified by six matching actual Rust HTTP cases. Full response and organization/notification contracts remain open.
- [x] Prelogin discovery subset: allocation-free known/unknown KDF lookup and complete response, six matching actual HTTP cases and twenty-six matching official CLI commands with PBKDF2/Argon2 decryption. Broader identity and rate/transport policies remain open.
- [x] User-key-ID backfill subset: allocation-free opaque request and atomic one-time provider contract, with six matching actual HTTP cases and fifteen matching official CLI commands. Key rotation and full account/key-management parity remain open.
- [x] Personal account-deletion aliases: allocation-free proof/policy/provider contract and atomic supported cleanup, verified by six matching actual Rust HTTP cases. Broader account recovery and organization lifecycle remain open.
- [x] Reauthenticated personal-vault purge: allocation-free provider contract, atomic cleanup/revision and preserved account authority, verified by six matching actual Rust HTTP cases. Organization purge remains open.
- [x] Actual Bitwarden CLI end-to-end verification and Vaultwarden comparison.
- [x] Personal JSON/CSV import subset: CLI JSON types 1–4, CSV types 1–2, and allocation-free batch/provider contracts with verified atomic persistence.
- [x] Personal cipher bulk lifecycle and archive/unarchive subset: reusable allocation-free contracts, atomic provider behavior, HTTP comparison of all 12 route patterns, and real CLI archive/unarchive verification.
- [x] Personal API-key identity subset: reusable allocation-free proof/provider contracts, confidential key retrieval and rotation, and verified real CLI API-key login, password unlock, fresh-cache decryption, and rotation.
- [x] Personal attachment subset: allocation-free metadata and lifecycle contracts, v2 and legacy uploads, scoped downloads, cleanup, and real CLI create/get/delete verification.
- [x] Authenticated WebAuthn credential-metadata subset: fixed allocation-free empty-list contract and existing previous-stamp guards, with six matching actual HTTP cases. Full passkey and key-rotation APIs remain open.
- [x] Personal KDF/password transition subset: reusable allocation-free validation/provider contracts and previous-stamp policy, with real CLI fresh-cache decryption after client-side rewrap. Full account lifecycle and all exception routes remain open.
- [x] Rust CI, bare-metal compile check, Runnerless configuration, Codex gate.
- [x] Bare-metal consumer links JSON decoding/encoding without a global allocator.
- [x] Owned fixed-capacity vault consumer exercises service rules without std/alloc.
- [ ] Expanded clients: browser extension, desktop, mobile.
- [ ] Device sessions, token rotation, revocation, account lifecycle and recovery.
- [ ] Organizations, collections, sharing and permissions.
- [x] Organization-owner creation/discovery subset: allocation-free policy/provider and typed membership/collection projections, six matching actual HTTP cases and nineteen matching official CLI commands with collection decryption. General administration and sharing remain open.
- [x] Organization collection create/list/single-detail subset: allocation-free opt-in provider and typed 7/10/13-field projections, six matching actual HTTP cases and nineteen matching official CLI commands with encrypted-name decryption and fresh-cache reads. General ACL/group lifecycle and sharing remain open.
- [x] Organization collection single update/delete subset: allocation-free mutation provider and sealed plans, six matching actual HTTP cases and twenty matching official CLI commands with encrypted rename, fresh-cache reads and deletion. Bulk mutations, membership/group lifecycle and sharing remain open.
- [x] Organization member discovery subset: allocation-free real membership/account projections, six matching actual HTTP cases and sixteen matching official CLI commands with fresh server names and fresh-cache recovery. Invitations, member/group administration and sharing remain open.
- [ ] Attachments, Sends, event notifications and websocket transport.
- [ ] Two-factor authentication, passkeys, SSO and administrative APIs.
- [ ] Full import/export compatibility, remaining formats and variants, and upstream protocol regression fixtures.
- [ ] Security audit, abuse controls, migration policy and production deployment.
