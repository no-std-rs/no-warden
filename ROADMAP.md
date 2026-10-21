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
- [x] Original personal cipher bulk lifecycle and archive/unarchive milestone: reusable allocation-free contracts, then-atomic provider behavior, HTTP comparison of all 12 route patterns, and real CLI archive/unarchive verification. Current selected archive/unarchive uses the later READ-first per-step contract below.
- [x] Personal API-key identity subset: reusable allocation-free proof/provider contracts, confidential key retrieval and rotation, and verified real CLI API-key login, password unlock, fresh-cache decryption, and rotation.
- [x] Personal attachment subset: allocation-free metadata and lifecycle contracts, v2 and legacy uploads, scoped downloads, cleanup, and real CLI create/get/delete verification.
- [x] Authenticated WebAuthn credential-metadata subset: fixed allocation-free empty-list contract and existing previous-stamp guards, with six matching actual HTTP cases. Full passkey and key-rotation APIs remain open.
- [x] Personal KDF/password transition subset: reusable allocation-free validation/provider contracts and previous-stamp policy, with real CLI fresh-cache decryption after client-side rewrap. Full account lifecycle and all exception routes remain open.
- [x] Rust CI, bare-metal compile check, Runnerless configuration, Codex gate.
- [x] Bare-metal consumer links JSON decoding/encoding without a global allocator.
- [x] Owned fixed-capacity vault consumer exercises service rules without std/alloc.
- [x] Pinned real Web 2026.7.0 login/initial-sync/profile smoke on both actual
  servers, paired vault lock/unlock/reload after ordinary onboarding controls,
  personal-login UI create/read/edit/read-after-unlock/trash/restore/permanent
  deletion, immutable browser/image inputs and a dedicated CI runner. Other item types,
  notifications and full web parity remain open.
- [ ] Expanded clients: browser extension, desktop, mobile.
- [ ] Device sessions, token rotation, revocation, account lifecycle and recovery.
- [ ] Organizations, collections, sharing and permissions.
- [x] Organization-owner creation/discovery subset: allocation-free policy/provider and typed membership/collection projections, six matching actual HTTP cases and nineteen matching official CLI commands with collection decryption. General administration and sharing remain open.
- [x] Organization collection create/list/single-detail subset: allocation-free opt-in provider and typed 7/10/13-field projections, six matching actual HTTP cases and nineteen matching official CLI commands with encrypted-name decryption and fresh-cache reads. General ACL/group lifecycle and sharing remain open.
- [x] Organization collection single update/delete subset: allocation-free mutation provider and sealed plans, six matching actual HTTP cases and twenty matching official CLI commands with encrypted rename, fresh-cache reads and deletion. Bulk mutations, membership/group lifecycle and sharing remain open.
- [x] Organization member discovery subset: allocation-free real membership/account projections, six matching actual HTTP cases and sixteen matching official CLI commands with fresh server names and fresh-cache recovery. SMTP/invite-JWT variants, confirmation, broader member/group administration and sharing remain open.
- [x] Organization member detail subset: allocation-free scoped Owner/Admin
  lookup and direct nineteen-field response, with six matching expanded HTTP
  cases and eighteen matching official CLI commands, including two strict
  already-confirmed local rejections. That milestone did not exercise
  invitation/confirmation mutations; broader member/group administration and
  sharing remain open.
- [x] Default no-SMTP organization invitations and same-ID passwordless-account
  completion: allocation-free provider and ordered partial writes implemented;
  six matching HTTP cases and twenty-four matching official CLI commands after
  direct HTTP setup.
  That milestone did not confirm members; SMTP, broader policy/member lifecycle
  and sharing remain open.
- [x] Single-member confirmation and confirmed recipient collection reads:
  allocation-free provider, six matching actual HTTP cases and 23 matching
  official CLI commands with selective recipient decryption after login, unlock
  and fresh-cache login. Bulk confirmation is tracked separately; SMTP,
  policy/group lifecycle and shared-cipher writes remain open.
- [x] Bulk organization-member confirmation subset: allocation-free ordered
  service, typed results and committed-prefix behavior, with six matching
  actual HTTP cases and 21 matching official CLI state/decryption commands
  after HTTP bulk setup. No CLI bulk caller, SMTP, sharing or complete
  policy/backend-error parity is claimed.
- [x] Single organization-member removal subset: allocation-free scoped
  removal, last-owner protection and retained account authority, with six
  matching actual HTTP cases and 25 matching official CLI state/decryption
  commands after HTTP setup. Bulk removal is tracked separately; no CLI
  removal command, groups/notifications or offline cache erasure is claimed.
- [x] Bulk organization-member removal subset: allocation-free ordered
  per-item results and scoped self-removal continuation, six matching actual
  HTTP cases and 25 matching official CLI state/decryption commands after HTTP
  setup. No CLI bulk-removal caller, general member/group lifecycle or
  shared-cipher writes are claimed.
- [x] Single organization-member revoke/restore subset: allocation-free status
  provider, both bodyless restore variants and retained encrypted keys/grants,
  with six matching HTTP cases and 31 matching official CLI observation
  commands after HTTP setup. No CLI mutation caller, configured policy/2FA
  fallback, bulk status changes, groups/events or sharing claim.
- [x] Bulk organization-member revoke/restore subset: allocation-free ordered
  services and caller-owned results, six matching actual HTTP cases with
  optional revoke versus required restore IDs and preserved grants. The
  separately verified CLI observer, configured-policy and event/backend
  limitations are recorded in the compatibility documentation.
- [x] Organization member public-key lookup subset: allocation-free scoped
  nullable-key snapshots, ordered duplicates and unfiltered target states/roles,
  six matching actual HTTP cases (431 requests) and 16 matching official CLI
  fingerprint/decryption observation commands on both targets. No CLI bulk
  caller, browser execution of this endpoint, automatic confirmation, configured
  policy/group or full-parity claim.
- [x] Organization member mini-details subset: allocation-free seven-field
  account/membership metadata, unfiltered names and native target states,
  restricted Manager admission, six matching actual HTTP cases
  (619 requests) and 18 matching official CLI observation
  commands on both targets. No production mini CLI caller, browser mini flow,
  configured-group/backend, adjacent member-edit or full-parity claim.
- [x] Single organization-cipher sharing subset: allocation-free sequential
  association plans and verified current/historical grant decisions, private annotations,
  six matching actual HTTP cases (423 requests) and 21
  matching official CLI move/fresh owner/recipient decryption commands per target.
  Attachment-bearing moves, general shared editing/lifecycle, bulk/import/admin,
  configured policy/group/backend and full API parity remain open.
- [x] Organization web read subset: allocation-free scoped canonical cipher
  metadata, aggregate 14-field collection access and provider-proved default
  empty groups; six matching actual HTTP cases (156 requests) and 21 matching
  official CLI observation commands. The organization creation/move browser
  experiment is reference-only; no new CLI route caller, configured groups,
  policy/attachment or full-parity claim.
- [x] Bulk organization-cipher sharing subset: allocation-free global ID preflight,
  reverse items/forward durable prefixes and separate source/manage/destination ACLs;
  six matching direct HTTP cases (1001 requests) and 37 CLI
  observation commands/31 direct HTTP per target, including two
  direct bulk mutations. No CLI bulk caller, captured trace or standalone browser
  claim; configured groups/policies, attachments, shared Save/lifecycle and full
  upstream API parity remain open.
- [ ] Attachments, Sends, event notifications and websocket transport.
- [ ] Two-factor authentication, passkeys, SSO and administrative APIs.
- [ ] Full import/export compatibility, remaining formats and variants, and upstream protocol regression fixtures.
- [ ] Security audit, abuse controls, migration policy and production deployment.

- [x] PUT collections_v2 subset: allocation-free scoped reassignment/unique-order validation, protected old links and lost-read operation response; six actual HTTP cases/522 requests plus separate Owner/recipient item-collections CLI28/25. Native invalid-subset order, aliases/admin/groups/policies/attachments/full parity remain open.

- [x] PUT/POST private cipher annotations subset: allocation-free READ admission/sealed actor-only plan, readonly/historical grants, exact folder scope, unchanged common cipher revision/payload; six paired HTTP cases/605 requests and separate actual CLI observer 31/37. Actual CLI partial caller, broader variants/groups/policies/attachments/native concurrency/full parity remain open.

- [x] Shared cipher archive/unarchive subset: allocation-free READ/sealed per-step decisions, private archive dates, distinct single/current-reader and selected/actor revisions, durable eligible mixed-error subsets; six paired HTTP cases/1115 and actual CLI 39/57 with readonly/fresh decryption. Broader variants, groups/policies, attachments, native concurrency and full parity remain open.

- [x] Shared single-cipher Trash/restore/permanent-delete secure-note subset: allocation-free current-WRITE/sealed live plan, private/archive/opaque preservation, current-reader revisions, exact replies and POSTrestore404; six paired HTTP cases/812 and actual Owner/writable-recipient CLI63/101 with deleted+archived branch and fresh decryption. Selected bulk lifecycle, attachments, broader roles/states, configured groups/policies and full parity remain open.

- [x] Shared selected-cipher Trash/restore/permanent-delete secure-note subset: owned-permutation allocation-free currentWRITE atomicsteps with durable priorresults/currentREADERS fanout;6pairedHTTP/4648, actualCLIobserver47/62, strict writableRecipient two-note pairedWeb4mutations/4freshcontexts. Nativeorder/distribution, selectedCLI mutationcaller, attachments/groups/concurrency/capacity/fullparity remainopen.
