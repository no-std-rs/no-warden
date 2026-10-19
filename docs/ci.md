# CI and review

GitHub Actions runs formatting, Clippy, tests, doctests, the minimum supported
Rust version, and a RISC-V bare-metal compilation of the library. A separate
consumer links JSON decoding and encoding without a global allocator. The
standalone adapter's real Bitwarden CLI, HTTP authorization, and restart
persistence suites run in the same pipeline against disposable SQLite databases.
The workspace has 489 active Rust tests: 228 core, 177 host, and 84 conformance
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
The default adapter job runs all 104 HTTP cases, including authentication-request
login, real-time expiry, modern registration, account security, KDF and password changes.
The preceding KDF milestone passed 96 cases with 4214 tracked HTTP requests.
The eight authentication-request login cases also passed against Vaultwarden
`1.37.4`: 444 requests per server, including 43 identity requests and a real
301-second expiry check.
Eight token cases add 383 requests and three password logins, covering both
update/clear aliases, opaque strings, positional input, empty success bodies,
and authentication/path/JSON guard order. The public clears use the reference
configuration with push disabled; actual relay behavior remains open.
Reference comparisons use `--suite personal`, `--suite devices`, and
`--suite device-tokens`, `--suite auth-requests`, `--suite auth-responses`,
`--suite auth-login`, `--suite registration`, `--suite account-security`, and
`--suite account-kdf`, `--suite account-password`, and `--suite webauthn-credentials` in separate
fresh disposable Vaultwarden processes. The separate reference CLI comparison starts another fresh process, preserving the
reference's default ten-login limit.
The required client job reruns the unchanged 120-command CLI flow for the final
head. Its verified baseline covers both servers; it establishes no domain
mutation, settings request trace or device-route trace.
`BW_FOLDER_RECEIPT`, `BW_ACCOUNT_KEYS_RECEIPT`, `BW_PROFILE_RECEIPT`,
`BW_DOMAINS_RECEIPT`, `BW_DEVICES_RECEIPT`, `BW_DEVICE_TOKENS_RECEIPT`,
`BW_AUTH_REQUESTS_RECEIPT`, `BW_AUTH_RESPONSES_RECEIPT`,
`BW_AUTH_LOGIN_RECEIPT`, and `BW_REGISTRATION_RECEIPT`
select optional private per-group
receipts. The domain
receipt also records the public catalog count and fingerprint, without account
settings or response values.
The device receipt separates identity requests, login attempts, successful
logins and refreshes; a refresh is not counted as a login.
The selected registration comparison passed eight cases against both the adapter
and Vaultwarden `1.37.4`, with 541 counted requests each: 69 verification, 64
finish, ten prelogin and nine successful password logins. The unchanged official
CLI `2026.10.0` separately passed 120 commands against each server.
The registration selection checks token transport and purpose, exact claim authority,
legacy/nested credentials, signed KDF fields, deferred email validation, guards,
retry and duplicate-account isolation. It uses direct per-case loopback peers
without changing reference limits. SMTP and invitation variants remain open.
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
review evidence. Runnerless deduplicates this policy against its native
`codex/review-gate` when both enforce the same review outcome, so only the
canonical native context is required. PRs execute the trusted base revision, so
the configuration starts on `main`. Repository enrollment and
GitHub App access must also be verified; committing this file alone is not
evidence of a live check.

This repository is enrolled in Runnerless. The policy requires these
actual check contexts, pinned to the reporting GitHub App:

| Required context | App ID |
| --- | --- |
| `codex/review-gate` | Runnerless **4602759** |
| `rust` | GitHub Actions **15368** |
| `msrv` | GitHub Actions **15368** |
| `bitwarden-cli` | GitHub Actions **15368** |
| `embedded` | GitHub Actions **15368** |

The canonical native review gate must succeed for the current PR head. It
rejects unresolved Codex findings; requiring an equivalent configured check
would leave PRs waiting for a duplicate context that Runnerless suppresses.
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
squash merging, resolved review threads, current branches, and all five checks
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

Eight authentication-request cases add 273 requests and five logins per target;
both actual servers pass them with 33 decoded create attempts below the
reference's unchanged public burst limit. They check the four create/read/list
routes, opaque required fields, client-type defaults, exact projections, owner
and UUID guards, pending aliases and latest device metadata. The no-allocator
consumer links request decoding and created/stored/pending-list serializers.
Host tests include rollback, reopen and actual socket-peer capture. Forwarded-IP
configuration, notifications and expiry/rate controls remain
separate parity work.


The authentication-response group adds approval/rejection and public response
polling. Its no-allocator consumer exercises the borrowed update request,
secret code input, approved/rejected-snapshot projections and both route kinds.
The adapter owns constant-time code verification, response timestamps and atomic
persistence. Required CI reruns the default HTTP suite and the unchanged
120-command real-client regression; the selected reference group runs in its
own fresh process. Notification/expiry/proxy/rate behavior
remain separate work.


The eight response cases pass against the adapter and actual Vaultwarden 1.37.4
with 322 requests and four logins per target. Eleven decoded creates and
33 guard-valid polls share a 44-attempt public budget below the unchanged limit
of 50; six rejected query/path guards do not enter the polling handler. The
focused group verifies positive transitions and negative owner/device/code/type/IP
boundaries. All 97 coverage, client-inventory and repository-policy tests pass;
those checks preserve source binding and keep all 294 upstream handlers visible.


The authentication-login group exercises the password-grant `authRequest`
variant, single-use consumption and refresh authority. Its expiry case creates
and approves a real request, runs other cases, then waits until at least 301
monotonic seconds after creation before checking rejection. Exact nanosecond
boundary conditions use core/host tests. Real loopback peers isolate fixture
login budgets under unchanged reference limits; no forwarding headers or clock
overrides are used. This adds roughly five minutes to the HTTP job. The
no-allocator consumer links the borrowed convenience decoder and private
record/context/device types without a secret serializer or clock dependency.

The account-security selection adds eight matching HTTP cases on both actual
servers: 292 requests each, including nine identity requests, two authentication
request creations and three public polls. These cover policy/proof/schema
guards, owner-wide existing-session/device invalidation, preserved API-key and
auth-request recovery, and renewed stamp projection in profile/sync/JWT. Core and
host tests independently verify proof/provider ordering, private authority,
rollback and durable reopen. These HTTP checks add no CLI command or captured
route trace; the official 120-command regression remains a separate final-head
requirement.

The required client job separately runs `--suite account-kdf-cli` after the
default HTTP selection and before the unchanged 120-command CLI suite. Nine
official commands prove that a fresh client cache decrypts preexisting ciphertext
after an HTTP PBKDF2 change and same-user-key rewrap. This does not attribute the
KDF POST to the CLI or count its internal HTTP calls. Reference HTTP, focused CLI
and baseline CLI selections use separate fresh processes with unchanged limits.


The password-change extension adds exact nested/legacy parsing and a pure
four-route, 120-second previous-stamp policy. The no-allocator executable links
both the borrowed request and the inclusive-deadline decision. Host regressions
cover nine transaction failure stages, deferred commit, reopen, preopened races,
API access and immutable bearer history across password/KDF/direct-reset changes.
An independent finding was demonstrated failing before the history fix and
passing afterward: an older valid bearer must trigger latest-exception expiry
cleanup before failing its stamp comparison.

`--suite account-password-cli` runs separately in the required client job. Its
ten official CLI commands reject the old password, then log in with the new
password, lock/unlock, sync and decrypt an item encrypted before the HTTP change.
It passes against both actual servers with CLI 2026.10.0. Seven direct HTTP
requests and one direct password grant exclude registration bootstrap and all
CLI-internal requests. `BW_ACCOUNT_PASSWORD_CLI_RECEIPT` contains redacted counts;
no CLI-posted password route or request trace is inferred. The HTTP group has its
own `BW_ACCOUNT_PASSWORD_RECEIPT` and uses a fresh reference with unchanged limits.

The eight password HTTP cases pass against both actual servers with 285 tracked
requests each, eleven identity requests (eight password logins, one API-key login
and two refresh attempts),
two authentication-request creations and four public polls. The final case waits
at least 121 real seconds after the latest password change; exact equal-second
boundary behavior has separate pure-core/provider tests.


The preceding password milestone passed all 104 local HTTP cases with 4499 tracked
requests across thirteen groups, including real authentication-request and
password-exception expiry. The unchanged official CLI 2026.10.0 baseline passes
all 120 commands against each actual server, separately from the focused KDF
and password CLI proofs.

The required client job separately invokes `--suite webauthn-credentials` after
its default 104-case HTTP selection. Six authored cases target authenticated
empty credential metadata and its previous-stamp guards, including a real wait
of at least 121 seconds for exception expiry. This group uses its own fresh
reference process without changing rate limits. `BW_WEBAUTHN_CREDENTIALS_RECEIPT`
selects an optional private counts-only receipt. All six cases pass against the
actual adapter and Vaultwarden 1.37.4: 129 counted HTTP requests each, eight
identity requests (six successful grants and two rejected refreshes), and a real
121-second exception wait. The two direct peers receive three and five identity
requests, preserving unchanged reference limits. Two shared fixture registrations
are excluded. No CLI call or full WebAuthn authentication claim is inferred.

The personal-vault purge extension adds allocation-free proof-before-mutation
provider tests and a separate Rust `--suite personal-vault-purge` comparison.
The six cases run separately from the default 104-case selection and from the
six WebAuthn metadata cases. Its exact empty response does not count as a typed
JSON response. `BW_PURGE_RECEIPT` names an optional private counts-only receipt.
Seven core module tests plus one route test exercise the borrowed provider
contract. Host tests prove cascade/folder/revision/deferred-commit rollback,
private-database reopen, bound authority, organization-query isolation and old
stamp rejection. The selected
comparison passes all six cases against the actual adapter and unchanged-limit
Vaultwarden 1.37.4: 327 counted HTTP requests each, six identity requests (five
successful grants and one refresh), three auth-request creations, three polls
and eight successful purges. Two shared fixture registrations are excluded; all
six identity requests use one direct peer. The fresh attachment capability
checks prove pre-purge bytes and post-purge revocation within 30 seconds; physical
BLOB/grant/row deletion is separate SQL evidence. A fresh official CLI 2026.10.0
regression also passes all 120 commands against both actual servers. It remains
separate and establishes no purge command or captured route claim.

The account-deletion extension adds two authenticated aliases with one borrowed
proof/provider service. Seven core module tests and one route test exercise proof
ordering, trusted policy rejection, atomic failure mapping and redaction. The
bare-metal consumer decodes the borrowed proof and calls the real service against
a fixed stack-owned provider, without an allocator or implicit proof serialization.
The explicit Rust `--suite account-deletion` comparison passes all six cases
against the adapter and actual Vaultwarden 1.37.4: 257 counted HTTP requests per
server, including six identity requests (three successful password logins, two
refresh attempts with one success, and one rejected old API credential). Three
fixture registrations across two emails are excluded. Both deletion aliases
return empty 200; schema, proof, query and method guards, live authority
revocation, same-email re-registration and foreign preservation match. Each
delete has a fresh capability check within 30 seconds. Its portable fixtures
avoid the release/pin auth-request cleanup difference; local SQL tests establish
that cleanup, failure rollback and durable reopen. The unchanged official CLI
2026.10.0 regression also passes all 120 commands against both actual servers.
It establishes no account-deletion caller, generated-SDK execution or route trace.

The cipher-read extension adds two GET aliases and corrects the ordinary GET's
missing/foreign status to the pinned 400 contract. Separate read authorization
has no typed request/response payload and adds no allocator. The no-allocator
consumer links the real service against bounded storage. Six module tests and
one route test cover the reusable boundary. All six selected Rust
`--suite cipher-reads` cases pass against both actual servers, with 335 counted
HTTP requests, four successful password logins, two excluded fixture registrations
and 34 attachment byte checks per target. The default HTTP selection is unchanged;
`BW_CIPHER_READS_RECEIPT` selects a private authored-case/count receipt. The fresh
official CLI 2026.10.0 regression also passes all 120 commands against both actual
servers. It is separate lifecycle evidence and establishes no client alias
execution or captured route trace.

The ordinary password-grant extension moves the supported request validation and
proof/policy ordering into an opt-in allocation-free service. Eleven core tests
cover required/scope order, no auth-request fallback, raw fields, enabled state,
provider preparation/error mapping, borrowed adapters and redaction. No new route or
typed OAuth response is counted. The no-allocator consumer exercises the real
service, leaving crypto, Unicode lowercase lookup, clocks, HTTP forms and token
issuance in adapters. All six selected `--suite password-grants` cases pass
against both actual servers: 85 counted HTTP requests per target, including 45
token requests, with one fixture registration excluded. The authored classification
is 39 pre-limiter guards and six credential-flow attempts, two successful, under
unchanged reference limits. `BW_PASSWORD_GRANTS_RECEIPT` records private authored
case names and counters. A fresh official CLI 2026.10.0 regression passes all
120 commands against both actual servers, separately from the focused HTTP
matrix. The prior default HTTP regression also passes all 104 cases,
including its real authentication-request and password-exception expiry checks.
Complete identity policy remains open; the refresh comparison below is separate.

The opt-in `--suite refresh-grants` extends the existing required real-client job
with eight focused Rust cases for password-method refresh. Twelve core tests and
an actual no-allocator consumer call cover the replay-preserving provider and
private grant boundary. The host returns only five OAuth fields, resolves current
device authority, preserves original proof deadlines and keeps earlier proofs
valid. Clock/provider tests cover thirty-second leeway and retained-device
thirty/ninety-day issuance; upstream refresh JWT encoding/`nbf`, SSO and mobile
runtime remain outside this slice. `BW_REFRESH_GRANTS_RECEIPT` records private
authored names and counters. All eight selected cases pass against both actual
servers: 268 counted HTTP requests each, including six successful password
logins and 42 refresh POSTs, with two fixture registrations excluded. The refresh
split is 22 successes, 15 invalid proofs, four presence/duplicate guards and one
missing-grant form guard. A fresh official CLI 2026.10.0 regression also passes all
120 commands against both actual servers. That lifecycle regression is separate
from captured refresh requests; no route trace or full-identity claim follows.
