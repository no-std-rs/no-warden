# CI and review

GitHub Actions runs formatting, Clippy, tests, doctests, the minimum supported
Rust version, and a RISC-V bare-metal compilation of the library. The standalone
adapter's real Bitwarden CLI integration suite belongs in the same pipeline.

`.runnerless-ci.ts` is a Runnerless v1 program. It evaluates current-head Codex
review evidence and reports `Runnerless / Codex review`. PRs execute the trusted
base revision, so the configuration starts on `main`. Repository enrollment and
GitHub App access must also be verified; committing this file alone is not
evidence of a live check.

Request `@codex review` for the exact PR head. After fixes, request a new review
and verify the new checks. Required checks should be pinned to their actual
reporting GitHub App after that App has produced them. Do not add a nonexistent
required context or substitute a green build for a completed review.
