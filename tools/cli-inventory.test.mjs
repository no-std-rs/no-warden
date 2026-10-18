import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { cliEvidence, cliInventoryPath, validateCliInventory } from "./check-cli-inventory.mjs";

const inventory = JSON.parse(readFileSync(cliInventoryPath, "utf8"));
const evidence = cliEvidence();
test("client facts bind to the actual locked CLI bytes and shipped source locations", () => {
  validateCliInventory(inventory, evidence);
});
for (const [name, mutate] of [
  ["changed CLI bundle", data => { data.provenance.bundleSha256 = "0".repeat(64); }],
  ["changed source map", data => { data.provenance.sourceMapSha256 = "0".repeat(64); }],
  ["a different package version", data => { data.provenance.version = "0.0.0"; }],
  ["a nonexistent shipped source", data => { data.operations[0].source.path = "invented.ts"; }],
  ["an out-of-range line", data => { data.operations[0].source.line = Number.MAX_SAFE_INTEGER; }],
  ["duplicate operation IDs", data => { data.operations[1].id = data.operations[0].id; }],
  ["an SDK source from another revision", data => { data.operations.find(row => row.sdkSource).sdkSource.url = "https://example.invalid/source"; }],
  ["unqualified exhaustive reachability", data => { data.completeness.exhaustiveCliReachabilityProven = true; }],
  ["inflated inventory counts", data => { data.summary.serverOperationRecords += 1; }],
]) {
  test(`rejects ${name}`, () => {
    const data = structuredClone(inventory);
    mutate(data);
    assert.throws(() => validateCliInventory(data, evidence));
  });
}

for (const [field, value] of [["method", "DELETE"], ["path", "/api/invented"], ["trafficRole", "third_party_service"]]) {
  test(`rejects a changed ${field} with refreshed counts but an unchanged source receipt`, () => {
    const data = structuredClone(inventory);
    data.operations[0][field] = value;
    data.summary.uniqueMethodPathPairs = new Set(data.operations.map(row => `${row.method} ${row.path}`)).size;
    data.summary.serverOperationRecords = data.operations.filter(row => row.trafficRole === "bitwarden_server").length;
    assert.throws(() => validateCliInventory(data, evidence), /reviewed source expression/);
  });
}

test("rejects a changed cited request expression", () => {
  const changed = { ...evidence, sources: new Map(evidence.sources) };
  const path = inventory.operations[0].source.path;
  changed.sources.set(path, changed.sources.get(path).replace('"GET"', '"PUT"'));
  assert.throws(() => validateCliInventory(inventory, changed), /reviewed source expression/);
});

test("rejects a changed SDK request source", () => {
  const changed = { ...evidence, sdkSources: new Map(evidence.sdkSources) };
  const path = inventory.operations.find(row => row.sdkSource).sdkSource.path;
  changed.sdkSources.set(path, `${changed.sdkSources.get(path)}\n// modified request\n`);
  assert.throws(() => validateCliInventory(inventory, changed), /reviewed source expression/);
});
