# CI and review

GitHub Actions runs formatting, Clippy, tests, doctests, the minimum supported
Rust version, and a RISC-V bare-metal compilation of the library. A separate
consumer links JSON decoding and encoding without a global allocator. The
standalone adapter's real Bitwarden CLI and HTTP authorization suites run in
the same pipeline against a disposable SQLite database.

`.runnerless-ci.ts` is a Runnerless v1 program. It evaluates current-head Codex
review evidence and reports `Runnerless / Codex review`. PRs execute the trusted
base revision, so the configuration starts on `main`. Repository enrollment and
GitHub App access must also be verified; committing this file alone is not
evidence of a live check.

This repository is enrolled in Runnerless. The live native `codex/review-gate`
check is published by GitHub App **4602759** and is required on `main`, alongside
the `rust` and `msrv` checks from GitHub Actions App **15368**. Administrator
enforcement and resolved conversations are required too. The gate has been
observed failing on unresolved Codex findings; it is not a placeholder status.

Request `@codex review` for the exact PR head. After fixes, request a new review
and verify the new checks. Required checks should be pinned to their actual
reporting GitHub App after that App has produced them. Do not add a nonexistent
required context or substitute a green build for a completed review.
