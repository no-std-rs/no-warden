# CI and review

GitHub Actions runs formatting, Clippy, tests, doctests, the minimum supported
Rust version, and a RISC-V bare-metal compilation of the library. A separate
consumer links JSON decoding and encoding without a global allocator. The
standalone adapter's real Bitwarden CLI, HTTP authorization, and restart
persistence suites run in the same pipeline against disposable SQLite databases.
The core has 18 unit tests and the SQLite host has seven storage tests on Unix. The
expanded HTTP suite passes 20 tests against the rebuilt host, and restart
persistence checks pass. The core's minimum Rust version is 1.85; the standalone
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
