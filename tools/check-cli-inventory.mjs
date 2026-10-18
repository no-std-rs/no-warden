import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const cliInventoryPath = join(root, "compatibility/cli-routes.json");
const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");

export function cliEvidence() {
  const packageRoot = process.env.BW_CLI_PACKAGE_ROOT ?? join(root, "tools/node_modules/@bitwarden/cli");
  const bundle = readFileSync(join(packageRoot, "build/bw.js"));
  const mapBytes = readFileSync(join(packageRoot, "build/bw.js.map"));
  const map = JSON.parse(mapBytes);
  const sources = new Map();
  for (let index = 0; index < map.sources.length; index++) {
    const prefix = "webpack://@bitwarden/cli/";
    const source = map.sources[index];
    if (!source.startsWith(prefix) || typeof map.sourcesContent[index] !== "string") continue;
    const relative = source.slice(prefix.length);
    const path = relative.startsWith("./src/") ? `apps/cli/${relative.slice(2)}` : relative.replace(/^(\.\.\/)+/, "");
    sources.set(path, map.sourcesContent[index]);
  }
  const lock = JSON.parse(readFileSync(join(root, "tools/package-lock.json"), "utf8"));
  assert(process.env.BW_CLIENTS_BUILD_LOCK, "Set BW_CLIENTS_BUILD_LOCK to the pinned upstream clients package-lock.json");
  const buildLockBytes = readFileSync(process.env.BW_CLIENTS_BUILD_LOCK);
  return { bundleSha256: sha256(bundle), sourceMapSha256: sha256(mapBytes), sources, lock, buildLock: JSON.parse(buildLockBytes), buildLockSha256: sha256(buildLockBytes), embeddedSourceCount: map.sources.length };
}

export function validateCliInventory(inventory, evidence) {
  assert.equal(inventory.schemaVersion, 1);
  const pin = inventory.provenance;
  assert.equal(pin.repository, "https://github.com/bitwarden/clients");
  assert.match(pin.commit, /^[a-f0-9]{40}$/);
  const locked = evidence.lock.packages["node_modules/@bitwarden/cli"];
  assert.equal(pin.version, locked.version);
  assert.equal(pin.npmIntegrity, locked.integrity);
  assert.equal(pin.bundleSha256, evidence.bundleSha256, "CLI bundle changed");
  assert.equal(pin.sourceMapSha256, evidence.sourceMapSha256, "CLI source map changed");
  assert.equal(pin.embeddedSourceCount, evidence.embeddedSourceCount);
  assert.match(pin.sdk.commit, /^[a-f0-9]{40}$/);
  assert.equal(pin.clientBuildLockSha256, evidence.buildLockSha256);
  const sdk = evidence.buildLock.packages[`node_modules/${pin.sdk.name}`];
  assert.equal(pin.sdk.version, sdk.version);
  assert.equal(pin.sdk.integrity, sdk.integrity);
  assert.equal(typeof inventory.completeness.exhaustiveCliReachabilityProven, "boolean");
  assert(Array.isArray(inventory.openObligations));
  if (inventory.completeness.exhaustiveCliReachabilityProven) {
    assert.equal(inventory.openObligations.length, 0, "Open obligations prevent exhaustive reachability");
    assert(inventory.completeness.reachabilityProof, "Exhaustive reachability requires a proof record");
  }
  const ids = new Set();
  const roles = new Set(["bitwarden_server", "external_key_connector", "server_supplied_storage_url", "third_party_service", "third_party_provider_rpc"]);
  function sourceExists(source) {
    assert.equal(typeof source.path, "string");
    const content = evidence.sources.get(source.path);
    assert.equal(typeof content, "string", `Source absent from shipped CLI: ${source.path}`);
    assert(Number.isSafeInteger(source.line) && source.line > 0 && source.line <= content.split("\n").length, `Invalid source line: ${source.path}`);
    assert.equal(source.url, `${pin.repository}/blob/${pin.commit}/${source.path}#L${source.line}`);
  }
  for (const row of inventory.operations) {
    assert(!ids.has(row.id), `Duplicate client operation ID ${row.id}`);
    ids.add(row.id);
    assert(roles.has(row.trafficRole), `Unknown traffic role ${row.trafficRole}`);
    assert(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(row.method));
    assert.equal(typeof row.path, "string");
    sourceExists(row.source);
    if (row.sdkSource) {
      assert.equal(row.sdkSource.url, `https://github.com/bitwarden/sdk-internal/blob/${pin.sdk.commit}/${row.sdkSource.path}#L${row.sdkSource.line}`);
    }
  }
  for (const row of inventory.cliLocalServeRoutes) {
    assert.equal(row.trafficRole, "cli_local_server");
    sourceExists(row.source);
  }
  for (const command of inventory.commands) sourceExists(command.source);
  const counts = {
    operationRecords: inventory.operations.length,
    uniqueMethodPathPairs: new Set(inventory.operations.map(row => `${row.method} ${row.path}`)).size,
    serverOperationRecords: inventory.operations.filter(row => row.trafficRole === "bitwarden_server").length,
    sdkWrapperRecords: inventory.operations.filter(row => row.sdkSource).length,
    cliLocalServeRoutes: inventory.cliLocalServeRoutes.length,
    commandDeclarations: inventory.commands.length,
    openObligations: inventory.openObligations.length,
  };
  assert.deepEqual(inventory.summary, counts, "Client inventory counts differ");
  return counts;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  console.log(JSON.stringify(validateCliInventory(JSON.parse(readFileSync(cliInventoryPath, "utf8")), cliEvidence()), null, 2));
}
