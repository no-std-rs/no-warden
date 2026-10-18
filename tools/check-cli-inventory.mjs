import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { commandKey, discoverRequests, genericKey, referenceKey, requestKey } from "./discover-cli-requests.mjs";

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
  assert(process.env.BW_SDK_SOURCE_ROOT, "Set BW_SDK_SOURCE_ROOT to the pinned bundled SDK source");
  for (const name of ["BW_CLIENTS_COMMIT", "BW_SDK_COMMIT"]) assert.match(process.env[name] ?? "", /^[a-f0-9]{40}$/, `Set ${name} to the fetched revision`);
  const sdkSources = new Map();
  for (const row of JSON.parse(readFileSync(cliInventoryPath, "utf8")).operations) {
    if (!row.sdkSource) continue;
    const path = row.sdkSource.path;
    assert(/^crates\/[a-zA-Z0-9_/-]+\.rs$/.test(path) && !path.includes(".."), "Invalid SDK source path");
    if (!sdkSources.has(path)) sdkSources.set(path, readFileSync(join(process.env.BW_SDK_SOURCE_ROOT, path), "utf8"));
  }
  return { bundleSha256: sha256(bundle), sourceMapSha256: sha256(mapBytes), sources, sdkSources, lock, buildLock: JSON.parse(buildLockBytes), buildLockSha256: sha256(buildLockBytes), embeddedSourceCount: map.sources.length, clientsCommit: process.env.BW_CLIENTS_COMMIT, sdkCommit: process.env.BW_SDK_COMMIT, discovered: discoverRequests(sources) };
}

// A reviewed receipt binds the interpreted operation to the actual cited expression.
// Regenerating it is an audit action, not a claim of automatic semantic inference.
export function operationBinding(row, evidence) {
  const text = evidence.sources.get(row.source.path);
  assert.equal(typeof text, "string", "Missing request source");
  const span = row.requestEvidence?.sourceSpan;
  assert(span && Number.isSafeInteger(span.start) && Number.isSafeInteger(span.end) && span.start >= 0 && span.end > span.start && span.end <= text.length, "Invalid request expression span");
  assert.equal(text.slice(0, span.start).split("\n").length, row.source.line, "Request expression must start on its cited line");
  const expressionSha256 = sha256(text.slice(span.start, span.end));
  let sdkSourceSha256 = null;
  if (row.sdkSource) {
    const sdkText = evidence.sdkSources.get(row.sdkSource.path);
    assert.equal(typeof sdkText, "string", "Missing pinned SDK request source");
    assert(Number.isSafeInteger(row.sdkSource.line) && row.sdkSource.line > 0 && row.sdkSource.line <= sdkText.split("\n").length, "Invalid SDK source line");
    sdkSourceSha256 = sha256(sdkText);
  }
  const helperSourceSha256 = row.helperSource ? sha256(evidence.sources.get(row.helperSource.path)) : null;
  const { requestEvidence, ...record } = row;
  const referenceSha256 = (row.directCliMethodReferences ?? []).map(reference => sha256(evidence.sources.get(reference.path)));
  const claim = { record, expressionSha256, sdkSourceSha256, helperSourceSha256, referenceSha256 };
  return { sourceSpan: { start: span.start, end: span.end }, expressionSha256, sdkSourceSha256, helperSourceSha256, claimSha256: sha256(JSON.stringify(claim)) };
}

export function validateCliInventory(inventory, evidence) {
  assert.equal(inventory.schemaVersion, 1);
  const pin = inventory.provenance;
  assert.equal(pin.repository, "https://github.com/bitwarden/clients");
  assert.match(pin.commit, /^[a-f0-9]{40}$/);
  assert.equal(pin.commit, evidence.clientsCommit, "Client citation revision differs from the fetched source revision");
  const locked = evidence.lock.packages["node_modules/@bitwarden/cli"];
  assert.equal(pin.version, locked.version);
  assert.equal(pin.npmIntegrity, locked.integrity);
  assert.equal(pin.bundleSha256, evidence.bundleSha256, "CLI bundle changed");
  assert.equal(pin.sourceMapSha256, evidence.sourceMapSha256, "CLI source map changed");
  assert.equal(pin.embeddedSourceCount, evidence.embeddedSourceCount);
  assert.match(pin.sdk.commit, /^[a-f0-9]{40}$/);
  assert.equal(pin.sdk.commit, evidence.sdkCommit, "SDK citation revision differs from the fetched source revision");
  assert.equal(pin.clientBuildLockSha256, evidence.buildLockSha256);
  assert.equal(pin.clientBuildLockUrl, `https://raw.githubusercontent.com/bitwarden/clients/${pin.commit}/package-lock.json`);
  assert.equal(pin.sdk.source, `https://github.com/bitwarden/sdk-internal/tree/${pin.sdk.commit}`);
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
  const references = new Set(evidence.discovered.references.map(referenceKey));
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
    if (row.helperSource) sourceExists(row.helperSource);
    for (const reference of row.directCliMethodReferences ?? []) {
      assert(references.has(referenceKey({ ...reference, name: row.source.function })), `Invalid shipped method reference for ${row.id}`);
    }
    assert.deepEqual(row.requestEvidence, operationBinding(row, evidence), `Operation differs from its reviewed source expression: ${row.id}`);
  }
  for (const row of inventory.cliLocalServeRoutes) {
    assert.equal(row.trafficRole, "cli_local_server");
    sourceExists(row.source);
    assert.equal(row.template, row.construction?.template, "Local serve template must match discovered syntax");
    assert.equal(row.path, row.construction?.template.split("?")[0], "Local serve path must match discovered syntax");
  }
  const commands = inventory.commands.map(command => {
    sourceExists(command.source);
    assert(command.construction, "Command needs a discovered registration");
    assert.equal(command.declaration, command.construction.declaration, "Command declaration differs from shipped syntax");
    assert.equal(command.source.path, command.construction.source.path);
    assert.equal(command.source.line, command.construction.source.line);
    return commandKey(command.construction);
  });
  assert.deepEqual(commands.sort(), evidence.discovered.commands.map(commandKey).sort(), "Inventory must cover every discovered command registration variant");
  const constructions = [...inventory.operations, ...inventory.cliLocalServeRoutes].filter(row => !row.sdkSource).map(row => {
    assert(row.construction, `Missing discovered request construction: ${row.id}`);
    assert.equal(row.construction.source.path, row.source.path);
    assert.equal(row.construction.source.line, row.source.line);
    assert.equal(row.construction.method, row.method);
    assert.equal(row.construction.transport, row.transport);
    if (row.requestEvidence) assert.deepEqual(row.requestEvidence.sourceSpan, { start: row.construction.source.start, end: row.construction.source.end });
    return requestKey(row.construction);
  });
  assert.deepEqual(constructions.sort(), evidence.discovered.requests.map(requestKey).sort(), "Inventory must cover every discovered request construction and symbolic variant");
  const generic = inventory.openObligations.filter(row => ["generic_transport", "generic_request"].includes(row.kind));
  assert.deepEqual(generic.map(genericKey).sort(), evidence.discovered.generic.map(genericKey).sort(), "Every generic transport must remain an explicit obligation");
  const obligationIds = inventory.openObligations.map(row => row.id);
  assert.equal(new Set(obligationIds).size, obligationIds.length, "Obligation IDs must be unique");
  const dynamic = inventory.openObligations.filter(row => row.kind === "dynamic_http_operation");
  const expectedDynamic = inventory.operations.filter(row => row.resolution === "dynamic_destination_or_expression").map(row => ({ id: `dynamic-${row.id}`, kind: "dynamic_http_operation", record: row.id, method: row.method, template: row.template, source: row.source }));
  assert.deepEqual(dynamic.toSorted((a, b) => a.id.localeCompare(b.id)), expectedDynamic.toSorted((a, b) => a.id.localeCompare(b.id)), "Every dynamic operation must retain its matching obligation");
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
