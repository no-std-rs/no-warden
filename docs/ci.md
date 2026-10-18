# CI and review

GitHub Actions runs formatting, Clippy, tests, doctests, the minimum supported
Rust version, and a RISC-V bare-metal compilation of the library. A separate
consumer links JSON decoding and encoding without a global allocator. The
standalone adapter's real Bitwarden CLI, HTTP authorization, and restart
persistence suites run in the same pipeline against disposable SQLite databases.
The workspace has 227 active Rust tests: 107 core, 71 host, and 49 conformance
support tests, plus one ignored subprocess fixture. A compile-fail doctest proves
that `Secret` cannot be serialized implicitly. Host tests on Unix include
attachment byte/revision rollback, capability expiry and deletion cleanup.
The Node HTTP suite has 61 tests,
including imports, bulk lifecycle/archive contracts, and API-key reauthentication,
rotation, scope, device fields, session authority, and all 11 pinned attachment
route patterns. The CLI suite includes
JSON/CSV import, archive/unarchive, API-key login followed by password unlock,
fresh-cache decryption, and encrypted attachment upload/download/deletion.
Restart persistence checks cover vault state, archive annotations, recoverable API
credentials, rotation, access-only sessions, exact attachment bytes and metadata,
unexpired download capabilities, and permanent-deletion cleanup.
The core's minimum Rust version is 1.85; the standalone
server and host-only `no-warden-conformance` support library are checked with
their minimum version, 1.89. The Rust conformance crate's capture, encrypted
account fixtures, and loopback TLS tests run in the workspace suite. The default real-client
entry point, `tools/e2e.sh`, runs the Rust binary and invokes the pinned official
CLI as an external process in the required `bitwarden-cli` job. The separate
`no-warden-http-conformance` Rust binary runs eight folder contract cases in that
job, including response projection, opaque names, JSON guards, ownership, UUID
paths, and deletion revision effects. It also runs eight account-key contract
cases across all three account/private/public-key patterns, followed by eight
profile/avatar cases covering both profile aliases, raw UTF-8 byte limits,
nullable avatar updates, JSON guards, and preservation of unrelated state.
Eight equivalent-domain cases follow, checking both mutation aliases, opaque
ordered groups, signed exclusion IDs, the full 91-group catalog, GET/sync
projections, JSON guards, query parsing, and authentication precedence.
Those 32 cases pass against the adapter and Vaultwarden `1.37.4`, with 1417
counted requests including nine password logins; fixture registrations are
excluded. The domains group accounts for 530 requests and two of those logins.
Eight device discovery cases follow in the default adapter run. They also pass
against Vaultwarden `1.37.4`: 199 requests, including five login attempts (four
successful and one rejected) and one refresh. They verify known-device headers,
exact owner-only projections, path guards, login metadata retention, API-key
registration and refresh identity without changing account/vault state.
The default adapter job runs all 48 cases, totaling 1999 counted requests.
Eight token cases add 383 requests and three password logins, covering both
update/clear aliases, opaque strings, positional input, empty success bodies,
and authentication/path/JSON guard order. The public clears use the reference
configuration with push disabled; actual relay behavior remains open.
Reference comparisons use `--suite personal`, `--suite devices`, and
`--suite device-tokens` in separate
fresh disposable Vaultwarden processes. The separate reference CLI comparison starts another fresh process, preserving the
reference's default ten-login limit.
The required client job reruns the unchanged 120-command CLI flow for the final
head. Its verified baseline covers both servers; it establishes no domain
mutation, settings request trace or device-route trace.
`BW_FOLDER_RECEIPT`, `BW_ACCOUNT_KEYS_RECEIPT`, `BW_PROFILE_RECEIPT`,
`BW_DOMAINS_RECEIPT`, `BW_DEVICES_RECEIPT`, and `BW_DEVICE_TOKENS_RECEIPT`
select optional private per-group
receipts. The domain
receipt also records the public catalog count and fingerprint, without account
settings or response values.
The device receipt separates identity requests, login attempts, successful
logins and refreshes; a refresh is not counted as a login.
The existing HTTP, restart-persistence, and client-inventory orchestration still
uses JavaScript, so the broader migration
remains unfinished.
Bare-metal compilation and the allocator-free consumer link pass independently
of the host suites. Domain settings use caller-selected decoder capacities or
indexed borrowed provider views without fixed core batch limits. Both typed
GET/sync projections and the explicit empty mutation response link without an
allocator; the full sync response remains adapter-built.
The consumer also links the decoded known-device header input, bare boolean
response, and streamed seven-field device and ten-field list projections with
a borrowed pending-auth request. Storage, header decoding, clocks and session
issuance remain in adapters. Host device tests cover failure rollback and
database reopen; legacy sessions remain valid without an invented device binding.

The `embedded` job separately tests the owned fixed-capacity storage consumer,
checks it with Rust 1.85, and links its RISC-V firmware without an allocator.
Its four tests exercise the real service lifecycle, bounded profile metadata,
capacity failures, and rejection of payloads the example cannot preserve.

`.runnerless-ci.ts` is a Runnerless v1 program. It evaluates current-head Codex
review evidence and reports `Runnerless / Codex review`. PRs execute the trusted
base revision, so the configuration starts on `main`. Repository enrollment and
GitHub App access must also be verified; committing this file alone is not
evidence of a live check.

This repository is enrolled in Runnerless. On 2026-10-18, `main` requires these
actual check contexts, pinned to the reporting GitHub App:

| Required context | App ID |
| --- | --- |
| `codex/review-gate` | Runnerless **4602759** |
| `Runnerless / Codex review` | Runnerless **4602759** |
| `rust` | GitHub Actions **15368** |
| `msrv` | GitHub Actions **15368** |
| `bitwarden-cli` | GitHub Actions **15368** |
| `embedded` | GitHub Actions **15368** |

The native review gate and the configured Runnerless check must both succeed
for the current PR head. The native gate has been observed rejecting unresolved
Codex findings, and the core PR passed both review checks before merging.
Strict branch freshness, administrator enforcement, and resolved conversations
are required too. The `bitwarden-cli` context runs the client, HTTP, and host
persistence checks. The `embedded` context protects owned allocation-free
storage and bare-metal linking. Both became required after successful live runs.

Request `@codex review` for the exact PR head. After fixes, request a new review
and verify the new checks. Required checks should be pinned to their actual
reporting GitHub App after that App has produced them. Do not add a nonexistent
required context or substitute a green build for a completed review.

The active [`main: reviewed squash merges` ruleset](https://github.com/no-std-rs/no-warden/rules/25333958) is versioned in
[`.github/main.ruleset.json`](../.github/main.ruleset.json). It requires a PR,
squash merging, resolved review threads, current branches, and all six checks
above. Its bypass-actor list is empty, so administrators follow the same rules.
Deletion, force pushes, and merge commits are forbidden. Repository settings also
disable merge and rebase merges. The existing classic protection remains layered
with this ruleset. Zero required human approvals permits the automated delivery
loop; a clean current-head Codex outcome through Runnerless is still required.

Ruleset changes are applied with owner authentication, without adding privileged
credentials to PR workflows. To create this policy in another repository, run
`gh api repos/OWNER/REPO/rulesets --method POST --input .github/main.ruleset.json`.
For an existing ruleset, use `PUT` on its specific `/rulesets/ID` endpoint after
reviewing the intended diff. To verify this repository, capture fresh metadata, that
ruleset's details, and effective rules for `main` with direct `gh api` calls:

```sh
gh api repos/no-std-rs/no-warden > /tmp/repository.json
gh api repos/no-std-rs/no-warden/rulesets/25333958 > /tmp/ruleset.json
gh api --paginate --slurp repos/no-std-rs/no-warden/rules/branches/main > /tmp/effective.json
node tools/verify-repository-policy.mjs /tmp/repository.json /tmp/ruleset.json /tmp/effective.json
```

The verifier rejects missing bypass information rather than assuming it is
empty: GitHub only exposes that field to callers permitted to write the ruleset.
It also checks that the ruleset actually appears in the effective branch rules.
Ordinary CI tests this verifier with offline fixtures; CI receives no owner
credential. Settings readback verifies policy without attempting a direct push.
See GitHub's [ruleset API](https://docs.github.com/en/rest/repos/rules) and
[PR enforcement rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-a-pull-request-before-merging).

The bare-metal consumer also decodes and encodes `DevicePushTokenRequest` without
an allocator. Core provider tests cover session targeting, exact-repeat no-ops,
save-before-relay failure ordering, and enabled all-owner clear/unregister
semantics. SQLite tests cover token/activity rollback, reopen and foreign-key
cleanup. These provider guarantees are distinct from actual enabled push relay
interoperability, which remains unverified.
