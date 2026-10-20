#!/usr/bin/env bash
# Disposable Linux x64 browser comparison. See tools/web-compat/README.md.
set -euo pipefail
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
    docker://ghcr.io/dani-garcia/vaultwarden@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055 \
    "dir:$web_ci_image"
fi
printf '%s  %s\n' \
  2bb2e0344616c62a6d76ea10558497499f8ed3f731400e143dc7bf17b757b5b9 \
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
    https://cdn.playwright.dev/builds/cft/149.0.7827.55/linux64/chrome-linux64.zip
fi
printf '%s  %s\n' \
  13113b963ac22fffdad898a677591028e4397c46c1daa9e61811258eed6e35b5 \
  "$web_ci_chrome" | sha256sum --check
unzip -q "$web_ci_chrome" -d "$web_ci_root/browser"
printf '%s  %s\n' \
  2d18db9d8608b052b6a552ee00ec1e830f93692e928b65ecc67d693bd33fe801 \
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
cargo build --locked -p no-warden-server
web_ci_binary="${CARGO_TARGET_DIR:-target}/debug/no-warden-server"
NO_WARDEN_BIND=127.0.0.1:18182 \
NO_WARDEN_DB="$web_ci_root/no-warden.db" \
NO_WARDEN_URL=https://127.0.0.1:18185 \
  "$web_ci_binary" > "$web_ci_root/no-warden.log" 2>&1 &
web_ci_server_pid=$!
for web_ci_port in 18181 18182; do
  web_ci_ready=false
  for web_ci_attempt in {1..60}; do
    if curl --fail --silent --output /dev/null "http://127.0.0.1:$web_ci_port/api/config"; then
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
