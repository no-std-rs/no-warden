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
