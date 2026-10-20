# Actual web-client smoke

Run `node tools/web-compat.mjs` against disposable loopback instances. This is a
real Chromium test of the Vaultwarden-distributed Bitwarden Web client. It does
not establish compatibility with the unmodified official Bitwarden Web build.
The client assets remain outside this MIT/Apache-2.0 repository; the harness was
independently authored and does not copy client or server implementation code.

The default `BW_WEB_VAULT_MODE=both` scope tests password login, the client's
authenticated initial sync and profile retrieval, vault navigation, Lock now,
password unlock, a second authenticated sync, and browser reload returning to
the lock screen against both servers. It also creates/reads/edits a personal
login through the rendered UI, decrypts its saved values after unlock and
moves it to Trash, restores it, verifies the saved edit in All items, then
retrashes and permanently deletes it through the normal confirmation. The
reference's ordinary onboarding
dialogs are dismissed through Add it later, Skip to web app, and the welcome
tour's Skip button. `BW_WEB_VAULT_MODE=login` limits both servers to login/sync;
`target` runs the extra vault steps only against no-warden. The harness does
not count HTTP fixture registration as browser evidence.

## Pinned inputs

The executable runner and setup consume the shared [pins](pins.json). Coverage
validation binds every recorded version/digest to those inputs, hashes this CI
workflow, and rejects disabled or missing comparison steps. The setup verifies
the reference binary version and the web layer's presence in the manifest.

- Vaultwarden `1.37.4`, source revision
  `7c188967e7a467b19b2757bc3326f9cf3ccae327`, from the official image
  `sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`
  already recorded in [the CLI reference instructions](../README.md).
- Its Vaultwarden Web `2026.7.0` static OCI layer:
  `sha256:d7b6e37be08b53480724fb772207fdfc1d75a2d150580c41348a82e7fa52403b`.
  Verify that layer digest before extracting `web-vault/`. The harness checks
  `/vw-version.json` and SHA-256 of all three application bootstrap bundles.
- `playwright-core` `1.64.1`, locked separately in this directory. Install with
  `npm ci --prefix tools/web-compat`; the normal CLI tools remain independent.
  The package came from the npm registry tarball
  `https://registry.npmjs.org/playwright-core/-/playwright-core-1.64.1.tgz`; its
  SHA-512 was verified against the integrity recorded in `package-lock.json`.
- Chromium `149.0.7827.55`, Playwright browser revision `1228`, Linux x64
  executable SHA-256:
  `2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801`.
  Supply its path with `BW_WEB_CHROMIUM`; the harness checks digest and version.
  Official [Chrome-for-Testing archive](https://cdn.playwright.dev/builds/cft/149.0.7827.55/linux64/chrome-linux64.zip)
  SHA-256: `13113b963ac22fffdad898a677591028e4397c46c1daa9e61811258eed6e35b5`.
  Fresh extraction was byte-identical to the entire browser distribution used
  in the checks, and its rendering/input readiness check passed.

Artifact references: [Vaultwarden release](https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.4),
[web distribution releases](https://github.com/dani-garcia/bw_web_builds/releases),
and [Bitwarden clients web release](https://github.com/bitwarden/clients/releases/tag/web-v2026.7.0).
The executable application bundles are the pinned client reference for the
observed browser operations; no Vaultwarden implementation source is used.

## Portable comparison

On Linux x64, install Docker (or a compatible Podman wrapper), Skopeo,
OpenSSL, unzip, Node 22 or newer, Rust, fontconfig and DejaVu Sans. Then run:

```sh
bash tools/web-compat.sh
```

The script installs the locked browser driver, fetches the pinned public image
and browser archive, verifies their digests, starts disposable servers and runs
both browser scopes above. It checks every image blob before execution. The
reference database lives in container tmpfs; the no-warden database and fonts
live in a private temporary directory. Its exit trap removes those fixtures.
Only sanitized browser receipts reach stdout; server logs are never printed.

The dedicated Ubuntu 24.04 CI job installs the prerequisites and sets
`BW_WEB_INSTALL_DEPS=1` to install Playwright's required shared libraries. It
uses the explicit Chromium archive above, since installing Playwright's default
browser would select a different version. `BW_WEB_FONT` can override the
DejaVu Sans file path on other distributions. Already downloaded inputs may be
provided with `BW_WEB_IMAGE_DIRECTORY` (Skopeo dir transport) and
`BW_WEB_CHROMIUM_ARCHIVE`; every supplied artifact is still verified.

A local end-to-end run using the verified image and official browser archive
passed the paired login/sync/lock/unlock/reload scope. A second
check supplied inherited Node/Playwright debug settings; no verbose HTTP/API
logs or debug file appeared. Those diagnostics can otherwise expose typed
passwords or authorization headers.

## Disposable setup

Build the current no-warden adapter with `cargo build --locked -p
no-warden-server`. Start a fresh reference process with an empty data directory
and the pinned extracted web folder; start no-warden with an empty database.
Keep their output in private disposable logs. For the default ports, the
relevant settings are:

```sh
DATA_FOLDER="$web_test_data/reference" \
ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=18181 \
WEB_VAULT_ENABLED=true WEB_VAULT_FOLDER="$web_test_assets/web-vault" \
SIGNUPS_ALLOWED=true DOMAIN=https://127.0.0.1:18184 vaultwarden
```

```sh
NO_WARDEN_BIND=127.0.0.1:18182 \
NO_WARDEN_DB="$web_test_data/no-warden.db" \
NO_WARDEN_URL=https://127.0.0.1:18185 target/debug/no-warden-server
```

`web_test_data` and `web_test_assets` above must be private temporary directories
created by the caller. If using the extracted reference executable, supply its
required runtime libraries as in the existing reference setup.

Both applications must advertise their HTTPS proxy origin. This actual web
client rejects HTTP API URLs even on loopback. The harness generates a temporary
self-signed certificate with OpenSSL, binds HTTPS proxies only on `127.0.0.1`,
and accepts that certificate only in its isolated browser context. Both proxies
serve the same pinned client assets through the reference server, while API and
identity requests go to the chosen server unchanged. This preserves the
reference server's distribution-specific styles and client bootstrap. External
browser HTTP requests are blocked. Notification WebSocket transport is outside
the smoke scope and the proxy closes upgrade requests.

```sh
BW_WEB_CHROMIUM="$browser_executable" \
BW_WEB_VAULT_MODE=both node tools/web-compat.mjs
```

The four URL overrides are `BW_WEB_REFERENCE_BASE`, `BW_WEB_TARGET_BASE`,
`BW_WEB_REFERENCE_ORIGIN`, and `BW_WEB_TARGET_ORIGIN`; their defaults are the
ports above. All must use `127.0.0.1`, and the two backend origins must differ.
Readiness requires the spawned target process and its private post-bind marker;
an older server occupying the port cannot supply evidence for the checkout.
If Playwright is installed elsewhere,
`BW_WEB_PLAYWRIGHT_MODULE` accepts the absolute `playwright-core/index.mjs` path.

The smoke uses ordinary generated test accounts. Stop both disposable server
processes and remove their entire data directories afterward. Do not point it
at personal or shared vaults. It deliberately logs only pinned versions, fixed
phase names, allowlisted method/path/status/count tuples, and fixed view labels.
It does not collect console output, exceptions, screenshots, HAR, tracing,
request bodies, response bodies, query strings, headers, or decrypted items.
The harness restarts with Node/Playwright debug variables removed before any
network request or credential is created. Those diagnostics can otherwise print
API arguments and authorization headers.

## Host font configuration

The runner checks basic text rendering and input before opening the client.
If Chromium cannot discover host fonts, use a private writable fontconfig:

```sh
web_test_fonts=$(mktemp -d /tmp/no-warden-web-compat-fonts-XXXXXX)
mkdir "$web_test_fonts/fonts" "$web_test_fonts/cache"
cp /usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf "$web_test_fonts/fonts/"
cat > "$web_test_fonts/fonts.conf" <<EOF_FONTS
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
<fontconfig>
  <dir>$web_test_fonts/fonts</dir>
  <cachedir>$web_test_fonts/cache</cachedir>
</fontconfig>
EOF_FONTS
FONTCONFIG_FILE="$web_test_fonts/fonts.conf" \
BW_WEB_CHROMIUM="$browser_executable" \
BW_WEB_VAULT_MODE=both node tools/web-compat.mjs
```

Remove that directory after the browser exits. Adjust the system font path for
your distribution. No fonts or generated certificates are committed.

## Observed on 2026-10-20

With the pinned client and Chromium above, Vaultwarden `1.37.4` and the tested
no-warden adapter both passed actual browser password login, authenticated
initial sync, and profile retrieval:

| Browser operation | Reference | no-warden |
| --- | --- | --- |
| `POST /identity/accounts/prelogin/password` | 200 | 200 |
| `GET /api/devices/knowndevice` | 200 | 200 |
| `POST /identity/connect/token` | 200 | 200 |
| `GET /api/sync` | 200 | 200 |
| `GET /api/accounts/profile` | 200 | 200 |

Both browsers also reached `#/vault`, locked, unlocked with their master
passwords, issued a second token request and sync, and returned to the lock
screen after reload. The reference initially routed its fresh account to
`#/setup-extension`; Add it later, the dialog's Skip to web app link, and the
welcome-tour Skip button reached the ordinary vault. Both browsers also
created/read/edited a personal login, decrypted its persisted edit after unlock
and moved it to trash. Create/update/trash each returned 200. The reference's
trash response was empty with no Content-Type; the adapter now returns the same
empty 200 rather than 204. A tightened existing Rust comparison setup requires
200 with an empty body; this does not add another named HTTP case.

A follow-up on 2026-10-21 passed ordinary Trash navigation, decryption of the
trashed login, Restore, decryption of the restored edit in All items, retrash,
and permanent deletion through the Yes confirmation on both actual servers.
The pinned client issued `PUT /api/ciphers/{id}/restore` once and
`DELETE /api/ciphers/{id}` once, both with 200; the two trash operations each
returned 200. A metadata-only probe confirmed the reference's permanent-delete
response is empty with no Content-Type. The adapter now returns the same
empty 200 rather than 204. The existing final Rust cipher-read case requires
DELETE 200/empty and a subsequent missing-item read after preserving all its
read-only assertions: all six cases pass at 337 requests per target.

Other item types, notification behavior and the broader web interface remain
unverified by this smoke. Cipher identifiers are normalized to `{id}` before
allowlisted operation counts are emitted. These lifecycle checks add browser
phases and tighten an existing HTTP case; they do not add an implemented route,
a named HTTP case or a complete endpoint-parity claim.
