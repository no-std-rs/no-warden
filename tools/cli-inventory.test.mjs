import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { cliEvidence, cliInventoryPath, operationBinding, validateCliInventory } from "./check-cli-inventory.mjs";

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

test("rejects omission of a request construction even with refreshed counts", () => {
  const data = structuredClone(inventory);
  data.operations.shift();
  data.summary.operationRecords--;
  data.summary.serverOperationRecords--;
  data.summary.uniqueMethodPathPairs = new Set(data.operations.map(row => `${row.method} ${row.path}`)).size;
  assert.throws(() => validateCliInventory(data, evidence), /every discovered request construction/);
});

test("rejects omission of an unresolved generic transport", () => {
  const data = structuredClone(inventory);
  data.openObligations.splice(data.openObligations.findIndex(row => row.kind === "generic_transport"), 1);
  data.summary.openObligations--;
  assert.throws(() => validateCliInventory(data, evidence), /Every generic transport/);
});

test("rejects relabeling pinned revisions despite refreshed URLs and receipts", () => {
  for (const field of ["commit", "sdk"]) {
    const data = structuredClone(inventory);
    if (field === "commit") data.provenance.commit = "a".repeat(40);
    else data.provenance.sdk.commit = "b".repeat(40);
    for (const row of data.operations) {
      row.source.url = `${data.provenance.repository}/blob/${data.provenance.commit}/${row.source.path}#L${row.source.line}`;
      if (row.sdkSource) row.sdkSource.url = `https://github.com/bitwarden/sdk-internal/blob/${data.provenance.sdk.commit}/${row.sdkSource.path}#L${row.sdkSource.line}`;
      row.requestEvidence = operationBinding(row, evidence);
    }
    assert.throws(() => validateCliInventory(data, evidence), /citation revision differs/);
  }
});

for (const [name, mutate] of [
  ["reachability", row => { row.reachability = "direct_cli_implementation"; }],
  ["a condition", row => { delete row.condition; }],
  ["an invented direct CLI reference", row => { row.directCliMethodReferences = [{ path: "invented.ts", line: 999999999, function: "missing", receiver: "this.api" }]; }],
]) {
  test(`rejects changing ${name} without a new reviewed evidence binding`, () => {
    const data = structuredClone(inventory);
    mutate(data.operations.find(row => row.condition));
    assert.throws(() => validateCliInventory(data, evidence), /reviewed source expression|Invalid shipped method reference/);
  });
}
