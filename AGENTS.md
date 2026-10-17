# Working on no-warden

- `crates/no-warden` is `no_std` and must not link `alloc`, directly or through
  dependencies. Keep storage, HTTP, crypto providers and clocks in adapters.
- Preserve Bitwarden's opaque encrypted vault payloads. Never log passwords,
  tokens, client keys, or decrypted vault contents.
- Claim compatibility only for behavior verified with actual clients. Record
  tested versions and upstream protocol references.
- Run formatting, Clippy with warnings denied, workspace tests, doctests, and a
  bare-metal core compile check for implementation changes. Run the real CLI
  integration suite for wire or server changes.
- Deliver small PRs. Request `@codex review` for every final head and resolve
  substantiated findings before merging. Do not bypass or weaken review gates.
- Use subagents for independent bounded tasks when parallel work is useful;
  assign disjoint paths and integrate sequentially.
