import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { coveragePath, sourceHashes, validateCoverage } from "./check-api-coverage.mjs";

const snapshot = JSON.parse(readFileSync(coveragePath, "utf8"));

test("coverage evidence and counts match the actual implementation and tests", () => {
  validateCoverage(snapshot);
});

for (const [name, mutate] of [
  ["stale implementation source hash", data => { data.source_sha256[Object.keys(data.source_sha256)[0]] = "0".repeat(64); }],
  ["an omitted implementation file", data => { delete data.source_sha256[Object.keys(data.source_sha256)[0]]; }],
  ["inflated counts", data => { data.counts.routed_method_path_patterns += 1; }],
  ["a duplicate method/path", data => { data.routes.push(structuredClone(data.routes[0])); }],
  ["an unknown HTTP test", data => { data.routes[0].http_test_names.positive.push("unverified HTTP behavior"); }],
  ["an unknown CLI command", data => { data.routes[0].cli_command_coverage.push("unverified-command"); }],
  ["a cache command presented as a request trace", data => { data.routes[0].cli_route_trace_tested = true; }],
  ["a bare full-parity assertion", data => { data.routes[0].full_upstream_parity_verified = true; }],
]) {
  test(`rejects ${name}`, () => {
    const data = structuredClone(snapshot);
    mutate(data);
    assert.throws(() => validateCoverage(data));
  });
}

test("source enumeration includes the runtime and real-client checks", () => {
  const hashes = sourceHashes();
  assert(Object.hasOwn(hashes, "crates/no-warden/src/lib.rs"));
  assert(Object.hasOwn(hashes, "tools/e2e.mjs"));
  assert(Object.values(hashes).every(hash => /^[a-f0-9]{64}$/.test(hash)));
});

test("an implemented HTTP route still needs upstream comparison evidence", () => {
  const data = structuredClone(snapshot);
  const route = data.routes.find(entry => entry.server_implemented && entry.http_positive_tested);
  route.full_upstream_parity_verified = true;
  assert.throws(() => validateCoverage(data), /upstream comparison cases/);
});
