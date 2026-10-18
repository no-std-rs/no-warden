# CI and review

GitHub Actions runs formatting, Clippy, tests, doctests, the minimum supported
Rust version, and a RISC-V bare-metal compilation of the library. A separate
consumer links JSON decoding and encoding without a global allocator. The
standalone adapter's real Bitwarden CLI, HTTP authorization, and restart
persistence suites run in the same pipeline against disposable SQLite databases.
The core has 45 unit tests and a compile-fail doctest proving that `Secret`
cannot be serialized implicitly. The host has thirteen storage tests and four
transport/session/coverage tests on Unix. The expanded HTTP suite passes 52 tests,
including imports, bulk lifecycle/archive contracts, and API-key reauthentication,
rotation, scope, device fields, and session authority. The CLI suite includes
JSON/CSV import, archive/unarchive, API-key login followed by password unlock,
and fresh-cache decryption. Restart persistence checks cover vault state, archive
annotations, recoverable API credentials, rotation, and access-only sessions.
The core's minimum Rust version is 1.85; the standalone
server is also checked with its minimum version, 1.89. Bare-metal compilation
and the allocator-free consumer link pass independently of the host suites.

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
