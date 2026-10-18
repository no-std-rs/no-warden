# Real-client compatibility checks

Use Node.js 22 or newer, OpenSSL, and the pinned official Bitwarden CLI:

```sh
npm ci --prefix tools
```

Build and start the standalone Rust server, then run the checks:

```sh
node --test tools/cli-process.test.mjs
tools/e2e.sh
node --test tools/server-tests.mjs
node tools/persistence.mjs
```

The default server is `http://127.0.0.1:8000`. Set `BW_E2E_SERVER` to test a
different address, or `BW_BIN` to use an already installed CLI. The checked-in
lockfile pins CLI `2026.10.0` and its transitive dependencies. The script reports
the actual version it runs.
Set `BW_E2E_VERBOSE=1` to print each CLI operation while diagnosing a failure.

Current CLI releases require HTTPS. For a loopback HTTP server, the suite starts
a temporary local HTTPS proxy, generates a one-day certificate with OpenSSL,
and trusts that certificate only in its CLI subprocesses using
`NODE_EXTRA_CA_CERTS`. It never disables TLS certificate validation or changes
the official CLI. Remote test servers must provide HTTPS themselves.

Each run registers fresh accounts with random passwords and cryptographically
valid Bitwarden PBKDF2, AES-CBC/HMAC, and RSA keys. The CLI uses a temporary
`BITWARDENCLI_APPDATA_DIR`, which is deleted even if the test fails. The test
does not access an existing user's CLI account or vault. Account passwords,
session tokens, and vault contents are never printed.

CLI subprocess stdout goes through a regular file descriptor explicitly set to
0600 inside a 0700 directory. Its pathname is unlinked before the child starts,
so terminating the parent during a synchronous CLI call leaves no named stdout
file behind. The helper reads the descriptor at explicit offsets, then closes it
and removes the empty directory in `finally`. This avoids the documented Node.js
pipe-write hazard when the unmodified CLI exits immediately after printing.
The helper retains a 90-second timeout, the 4 MiB stderr buffer limit, and a 4 MiB
stdout size check before reading the captured file. An empty login result still
fails the suite; its diagnostic includes only byte counts, process metadata, and
the CLI authentication status. The observed intermittent cloud failure has not
been conclusively attributed to stdout flushing. No command is retried.

The CLI suite checks incorrect-password rejection, password login, key
decryption, encrypted folder and login item CRUD, custom fields, Unicode notes,
sync, lock/unlock, trash/restore, permanent deletion, and a fresh local cache
after logout/login. The HTTP suite checks authentication, cross-account
isolation, owner references, malformed input, refresh token rotation, and
preservation of unknown JSON extensions. It also verifies stored key-ID
enforcement, escaped opaque cipher blobs, encrypted FIDO2 records, clone
wrappers, legacy folder aliases, organization alias rejection, and preservation
of archived dates.

The persistence test starts its own standalone server twice on a free loopback
port, using one temporary SQLite database. It verifies graceful shutdown,
encrypted account and owner data, folders, active and trashed ciphers, revisions,
and authentication sessions across restart. Build `no-warden-server` first, or
set `NO_WARDEN_BIN` to its binary path. The test stops its child processes and
removes the temporary database on success or failure.

## Compare against upstream Vaultwarden

The same CLI suite runs unchanged against a disposable upstream Vaultwarden
instance with registration enabled:

```sh
BW_E2E_SERVER=http://127.0.0.1:8001 tools/e2e.sh
```

For a local upstream binary, start it with an isolated data directory:

```sh
DATA_FOLDER="$(mktemp -d)" ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8001 \
  WEB_VAULT_ENABLED=false SIGNUPS_ALLOWED=true vaultwarden
```

The HTTP suite includes no-warden-specific validation and token-rotation
requirements; it is intended for the standalone adapter. The CLI lifecycle is
the portable upstream comparison.

The initial compatibility baseline passed on 2026-10-18: the same 37 official
CLI `2026.10.0` commands passed against both no-warden and upstream Vaultwarden
`1.37.4`. The upstream binary came from the official
`ghcr.io/dani-garcia/vaultwarden` image, pinned by digest
`sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`
(source revision `7c188967e7a467b19b2757bc3326f9cf3ccae327`). The standalone
HTTP suite also passed all 20 tests, and the standalone restart durability check
passed. These checks establish the tested personal
vault lifecycle; they do not establish compatibility with every Bitwarden API.

`seed-account.mjs` can also register a single explicit test account. Supply
`BW_E2E_EMAIL`, `BW_E2E_PASSWORD`, and optionally `BW_E2E_SERVER` in the environment.
It derives the standard server password hash and wrapped user key locally and
uses the ordinary registration endpoint.
