#!/usr/bin/env bash
# Disposable Linux x64 browser comparison. See tools/web-compat/README.md.
set -euo pipefail
web_ci_organization_sharing=false
case "$#:${1:-}" in
  0:) ;;
  1:--organization-sharing) web_ci_organization_sharing=true ;;
  *) printf 'Usage: tools/web-compat.sh [--organization-sharing]\n' >&2; exit 2 ;;
esac
web_ci_root=$(mktemp -d "${RUNNER_TEMP:-/tmp}/no-warden-web-compat-XXXXXX")
web_ci_container="no-warden-web-${GITHUB_RUN_ID:-local}-$$"
web_ci_server_pid=""
cleanup() {
  if [[ -n "$web_ci_server_pid" ]]; then
    kill "$web_ci_server_pid" 2>/dev/null || true
    wait "$web_ci_server_pid" 2>/dev/null || true
  fi
  docker rm --force "$web_ci_container" >/dev/null 2>&1 || true
  docker image rm "$web_ci_container:verified" >/dev/null 2>&1 || true
  rm -rf "$web_ci_root"
}
trap cleanup EXIT

web_ci_pin_output=$(node --input-type=module -e '
import { readFileSync } from "node:fs";
const pins = JSON.parse(readFileSync("tools/web-compat/pins.json", "utf8"));
console.log([pins.reference.imageIndex, pins.reference.manifestSha256,
  pins.chromium.archiveUrl, pins.chromium.archiveSha256,
  pins.chromium.executableSha256, pins.reference.version].join("\n"));
')
mapfile -t web_ci_pins <<< "$web_ci_pin_output"
npm ci --prefix tools/web-compat
if [[ "${BW_WEB_INSTALL_DEPS:-0}" == 1 ]]; then
  node tools/web-compat/node_modules/playwright-core/cli.js install-deps chromium
fi
# Use an explicitly anonymous public registry context.
printf '{"auths":{}}\n' > "$web_ci_root/empty-auth.json"
web_ci_image=${BW_WEB_IMAGE_DIRECTORY:-"$web_ci_root/image"}
if [[ -z "${BW_WEB_IMAGE_DIRECTORY:-}" ]]; then
  skopeo --override-os linux --override-arch amd64 copy \
    --authfile "$web_ci_root/empty-auth.json" \
    "docker://ghcr.io/dani-garcia/vaultwarden@${web_ci_pins[0]}" \
    "dir:$web_ci_image"
fi
printf '%s  %s\n' \
  "${web_ci_pins[1]}" \
  "$web_ci_image/manifest.json" | sha256sum --check
# Check every manifest-referenced blob before running the image, including when
# the caller supplies a cached image directory. No registry credentials are used.
node --input-type=module - "$web_ci_image" <<'VERIFY_IMAGE'
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createReadStream, readFileSync } from "node:fs";
import { join } from "node:path";
const directory = process.argv[2];
const manifest = JSON.parse(readFileSync(join(directory, "manifest.json"), "utf8"));
const pins = JSON.parse(readFileSync("tools/web-compat/pins.json", "utf8"));
assert(manifest.layers.some(blob => blob.digest === `sha256:${pins.client.layerSha256}`));
for (const blob of [manifest.config, ...manifest.layers]) {
  assert.match(blob.digest, /^sha256:[a-f0-9]{64}$/);
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(join(directory, blob.digest.slice(7)))) digest.update(chunk);
  assert.equal(digest.digest("hex"), blob.digest.slice(7));
}
VERIFY_IMAGE

# Do not install Playwright's default browser: it differs from this tested pin.
web_ci_chrome=${BW_WEB_CHROMIUM_ARCHIVE:-"$web_ci_root/chrome.zip"}
if [[ -z "${BW_WEB_CHROMIUM_ARCHIVE:-}" ]]; then
  curl --fail --silent --show-error --location --retry 3 \
    --output "$web_ci_chrome" \
    "${web_ci_pins[2]}"
fi
printf '%s  %s\n' \
  "${web_ci_pins[3]}" \
  "$web_ci_chrome" | sha256sum --check
unzip -q "$web_ci_chrome" -d "$web_ci_root/browser"
printf '%s  %s\n' \
  "${web_ci_pins[4]}" \
  "$web_ci_root/browser/chrome-linux64/chrome" | sha256sum --check

mkdir "$web_ci_root/fonts" "$web_ci_root/fontcache"
web_ci_font=${BW_WEB_FONT:-/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf}
cp "$web_ci_font" "$web_ci_root/fonts/"
cat > "$web_ci_root/fonts.conf" <<FONTCONF
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
<fontconfig>
  <dir>$web_ci_root/fonts</dir>
  <cachedir>$web_ci_root/fontcache</cachedir>
</fontconfig>
FONTCONF

# An archive import works with Docker and Docker-compatible Podman wrappers.
skopeo copy --authfile "$web_ci_root/empty-auth.json" "dir:$web_ci_image" \
  "docker-archive:$web_ci_root/reference.tar:$web_ci_container:verified"
docker load --input "$web_ci_root/reference.tar" >/dev/null
docker run --detach --rm --pull=never --name "$web_ci_container" \
  --publish 127.0.0.1:18181:80 \
  --env DOMAIN=https://127.0.0.1:18184 \
  --env SIGNUPS_ALLOWED=true --env WEB_VAULT_ENABLED=true \
  --env PUSH_ENABLED=false --env LOG_LEVEL=off \
  --tmpfs /data "$web_ci_container:verified" >/dev/null
web_ci_reference_version=$(docker exec "$web_ci_container" /vaultwarden --version)
if [[ "${web_ci_reference_version%%$'\n'*}" != "Vaultwarden ${web_ci_pins[5]}" ]]; then
  printf 'Pinned reference version differs.\n' >&2
  exit 1
fi
cargo build --locked -p no-warden-server
web_ci_binary="${CARGO_TARGET_DIR:-target}/debug/no-warden-server"
NO_WARDEN_BIND=127.0.0.1:18182 \
NO_WARDEN_DB="$web_ci_root/no-warden.db" \
NO_WARDEN_URL=https://127.0.0.1:18185 \
  "$web_ci_binary" > "$web_ci_root/no-warden.log" 2>&1 &
web_ci_server_pid=$!
web_ci_assert_server_alive() {
  if ! kill -0 "$web_ci_server_pid" 2>/dev/null; then
    printf 'Disposable no-warden process exited during readiness.\n' >&2
    exit 1
  fi
}
for web_ci_port in 18181 18182; do
  web_ci_ready=false
  for web_ci_attempt in {1..60}; do
    web_ci_assert_server_alive
    if curl --fail --silent --output /dev/null "http://127.0.0.1:$web_ci_port/api/config"; then
      if [[ "$web_ci_port" == 18182 ]] && ! grep -Fq \
        'no-warden conformance server listening on 127.0.0.1:18182;' "$web_ci_root/no-warden.log"; then
        sleep 1
        continue
      fi
      web_ci_assert_server_alive
      web_ci_ready=true
      break
    fi
    sleep 1
  done
  if [[ "$web_ci_ready" != true ]]; then
    printf 'Disposable server readiness failed.\n' >&2
    exit 1
  fi
done
FONTCONFIG_FILE="$web_ci_root/fonts.conf" \
BW_WEB_CHROMIUM="$web_ci_root/browser/chrome-linux64/chrome" \
BW_WEB_VAULT_MODE=both node tools/web-compat.mjs
# Server logs, browser traces, screenshots and raw network artifacts stay private.

# This explicit extension always follows the existing mandatory personal-vault
# checks. Both servers use the same strict organization-sharing browser flow.
if [[ "$web_ci_organization_sharing" == true ]]; then
  FONTCONFIG_FILE="$web_ci_root/fonts.conf" \
  BW_WEB_CHROMIUM="$web_ci_root/browser/chrome-linux64/chrome" \
  BW_WEB_ORG_MODE=paired node tools/web-org-sharing.mjs
fi
