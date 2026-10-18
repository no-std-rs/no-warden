import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { coveragePath, sourceHashes, validateCoverage } from "./check-api-coverage.mjs";

const snapshot = JSON.parse(readFileSync(coveragePath, "utf8"));

test("coverage evidence and counts match the actual implementation and tests", () => {
  const knownDevice = snapshot.routes.find(route => route.path === "/api/devices/knowndevice");
  assert.deepEqual(knownDevice.core_models.responses, ["KnownDeviceResponse"]);
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
  assert(Object.hasOwn(hashes, "crates/no-warden/src/account_keys.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden/src/account_profile.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden/src/domains.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden/src/devices.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden/src/device_push.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden/src/auth_requests.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden/src/auth_login.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden/src/registration.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden/src/auth_responses.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden-server/src/global_domains.json"));
  assert(Object.hasOwn(hashes, "checks/no-alloc/src/main.rs"));
  assert(Object.hasOwn(hashes, "crates/no-warden-conformance/src/cli.rs"));
  for (const file of ["fixture.rs", "capture.rs", "transport.rs", "registration.rs", "folders.rs", "account_keys.rs", "account_profile.rs", "auth_login.rs", "auth_requests.rs", "auth_responses.rs", "domains.rs", "devices.rs", "device_tokens.rs", "bin/no-warden-http-conformance.rs"]) assert(Object.hasOwn(hashes, `crates/no-warden-conformance/src/${file}`));
  assert(Object.hasOwn(hashes, "crates/no-warden-conformance/Cargo.toml"));
  assert(Object.hasOwn(hashes, "tools/e2e.sh"));
  assert(Object.hasOwn(hashes, "tools/seed-account.mjs"));
  assert(Object.hasOwn(hashes, "tools/package-lock.json"));
  for (const file of ["Cargo.toml", "Cargo.lock", "checks/no-alloc/Cargo.lock", "checks/embedded-vault/Cargo.lock"]) assert(Object.hasOwn(hashes, file));
  assert(Object.values(hashes).every(hash => /^[a-f0-9]{64}$/.test(hash)));
});

for (const field of ["http_positive_tested", "http_negative_tested", "http_tested"]) {
  test(`rejects ${field} without matching HTTP evidence even after count refresh`, () => {
    const data = structuredClone(snapshot);
    data.routes[0][field] = true;
    if (field === "http_positive_tested") data.counts.routes_with_direct_positive_or_restart_http_evidence++;
    if (field === "http_negative_tested") data.counts.routes_with_negative_http_evidence++;
    assert.throws(() => validateCoverage(data), /HTTP coverage/);
  });
}

test("changing a transitive CLI helper invalidates the coverage snapshot", () => {
  for (const file of ["tools/e2e.sh", "tools/seed-account.mjs", "crates/no-warden-conformance/src/fixture.rs", "crates/no-warden-conformance/src/capture.rs", "crates/no-warden-conformance/src/transport.rs"]) {
    const hashes = sourceHashes();
    hashes[file] = "0".repeat(64);
    assert.throws(() => validateCoverage(snapshot, hashes), /sources changed/);
  }
});

test("changing the Rust folder cases or HTTP entry point invalidates coverage evidence", () => {
  for (const file of ["crates/no-warden-conformance/src/folders.rs", "crates/no-warden-conformance/src/bin/no-warden-http-conformance.rs"]) {
    const hashes = sourceHashes();
    assert(Object.hasOwn(hashes, file), "Folder HTTP evidence must be enumerated recursively");
    hashes[file] = "0".repeat(64);
    assert.throws(() => validateCoverage(snapshot, hashes), /sources changed/);
  }
});

test("account and device core, HTTP cases, and no-allocator consumer are bound to audited evidence", () => {
  for (const file of ["crates/no-warden/src/registration.rs", "crates/no-warden-conformance/src/registration.rs", "crates/no-warden-server/src/registration.rs", "crates/no-warden/src/account_keys.rs", "crates/no-warden-conformance/src/account_keys.rs", "crates/no-warden/src/account_profile.rs", "crates/no-warden-conformance/src/account_profile.rs", "crates/no-warden/src/auth_login.rs", "crates/no-warden/src/auth_requests.rs", "crates/no-warden/src/auth_responses.rs", "crates/no-warden/src/devices.rs", "crates/no-warden/src/device_push.rs", "crates/no-warden-conformance/src/auth_login.rs", "crates/no-warden-conformance/src/auth_requests.rs", "crates/no-warden-conformance/src/auth_responses.rs", "crates/no-warden-conformance/src/devices.rs", "crates/no-warden-conformance/src/device_tokens.rs", "crates/no-warden-server/src/auth_requests.rs", "crates/no-warden-server/src/devices.rs", "crates/no-warden-server/src/main.rs", "crates/no-warden-server/src/store.rs", "checks/no-alloc/src/main.rs"]) {
    const hashes = sourceHashes();
    assert(Object.hasOwn(hashes, file), "Account behavior and no-allocator link evidence must be enumerated");
    hashes[file] = "0".repeat(64);
    assert.throws(() => validateCoverage(snapshot, hashes), /sources changed/);
  }
});

test("domain contracts and the global catalog are bound to audited evidence", () => {
  for (const file of ["crates/no-warden/src/domains.rs", "crates/no-warden-server/src/domains.rs", "crates/no-warden-server/src/global_domains.json", "crates/no-warden-conformance/src/domains.rs"]) {
    const hashes = sourceHashes();
    assert(Object.hasOwn(hashes, file), "Domain models, behavior, and protocol data must be enumerated");
    hashes[file] = "0".repeat(64);
    assert.throws(() => validateCoverage(snapshot, hashes), /sources changed/);
  }
});

test("an implemented HTTP route still needs upstream comparison evidence", () => {
  const data = structuredClone(snapshot);
  const route = data.routes.find(entry => entry.server_implemented && entry.http_positive_tested);
  route.full_upstream_parity_verified = true;
  assert.throws(() => validateCoverage(data), /upstream comparison cases/);
});

test("rejects a missing upstream status", () => {
  const data = structuredClone(snapshot);
  data.upstream_routes.pop();
  assert.throws(() => validateCoverage(data), /Every pinned upstream handler/);
});

test("rejects deletion of a local row despite refreshed aggregate counts", () => {
  const data = structuredClone(snapshot);
  const row = data.routes.shift();
  data.counts.routed_method_path_patterns -= Number(row.routed);
  assert.throws(() => validateCoverage(data), /Missing linked coverage record|Missing local extension coverage/);
});

test("rejects an unexplained parameter-name mapping", () => {
  const data = structuredClone(snapshot);
  data.upstream_routes.find(row => Object.keys(row.parameter_mapping).length > 0).parameter_mapping = {};
  assert.throws(() => validateCoverage(data), /parameter mapping/);
});

for (const [dimension, mutate] of [
  ["request model", route => { route.typed_request = true; route.core_models.requests = ["InventedRequest"]; }],
  ["response model", route => { route.typed_response = true; route.core_models.responses = ["InventedResponse"]; }],
  ["service", route => { route.core_service_implemented = true; route.core_service = { file: "missing.rs", line: 999, owner: "InventedService", symbol: "run" }; }],
  ["handler", route => { route.server_implemented = true; route.server_handler = "missing.rs:999"; }],
  ["classifier", route => { route.classifier_enum = "InventedRoute"; }],
]) {
  test(`rejects an invented ${dimension} without source changes`, () => {
    const data = structuredClone(snapshot);
    mutate(data.routes[0]);
    assert.throws(() => validateCoverage(data), /missing wire model|Unaudited source reference|missing classifier symbol/);
  });
}

test("workspace dependency drift invalidates audited coverage", () => {
  const hashes = sourceHashes();
  hashes["Cargo.lock"] = "0".repeat(64);
  assert.throws(() => validateCoverage(snapshot, hashes), /sources changed/);
});

function fullParityAttempt() {
  const data = structuredClone(snapshot);
  const route = data.routes.find(row => row.http_test_names.positive.length > 0 && row.server_implemented);
  const key = `${route.method} ${route.path}`;
  route.full_upstream_parity_verified = true;
  route.parity_evidence = { upstream_comparison_cases: ["invented comparison"], remaining_variants: [] };
  return { data, route, key };
}

test("rejects invented upstream comparison case names", () => {
  const { data } = fullParityAttempt();
  assert.throws(() => validateCoverage(data), /unknown upstream comparison case/);
});

test("an audited comparison case still requires a successful runtime receipt", () => {
  const { data, route, key } = fullParityAttempt();
  data.upstream_comparison_catalog["invented comparison"] = { route: key, upstream_commit: data.upstream_pin, test_name: route.http_test_names.positive[0] };
  assert.throws(() => validateCoverage(data, undefined, undefined, {}), /missing successful current upstream comparison receipt/);
});

test("comparison receipts must match the current audited dependency and source hashes", () => {
  const { data, route, key } = fullParityAttempt();
  data.upstream_comparison_catalog["invented comparison"] = { route: key, upstream_commit: data.upstream_pin, test_name: route.http_test_names.positive[0] };
  const receipts = { "invented comparison": { passed: true, route: key, upstream_commit: data.upstream_pin, source_sha256: {} } };
  assert.throws(() => validateCoverage(data, undefined, undefined, receipts), /comparison receipt must match current audited sources/);
});

test("full parity and every linked upstream status must agree", () => {
  const { data, route, key } = fullParityAttempt();
  data.upstream_comparison_catalog["invented comparison"] = { route: key, upstream_commit: data.upstream_pin, test_name: route.http_test_names.positive[0] };
  const receipts = { "invented comparison": { passed: true, route: key, upstream_commit: data.upstream_pin, source_sha256: sourceHashes() } };
  assert.throws(() => validateCoverage(data, undefined, undefined, receipts), /every linked upstream handler to be verified/);
});

function traceAttempt() {
  const data = structuredClone(snapshot), route = data.routes[0];
  const key = `${route.method} ${route.path}`;
  route.cli_route_trace_tested = true;
  route.cli_trace_evidence = ["invented trace"];
  data.counts.routes_with_captured_cli_request_traces++;
  const version = JSON.parse(readFileSync(new URL("./package-lock.json", import.meta.url))).packages["node_modules/@bitwarden/cli"].version;
  return { data, key, version };
}

test("invented CLI trace IDs cannot establish client route coverage", () => {
  const { data } = traceAttempt();
  assert.throws(() => validateCoverage(data), /unknown CLI trace case/);
});

test("a trace catalog entry still needs a successful actual-client receipt", () => {
  const { data, key, version } = traceAttempt();
  data.cli_trace_catalog["invented trace"] = { route: key, command: "config", test_source: data.cli_command_catalog.config.proof, client_version: version };
  assert.throws(() => validateCoverage(data, undefined, undefined, {}, {}), /missing successful current CLI trace receipt/);
});

for (const field of ["client_version", "source_sha256"]) {
  test(`CLI trace receipts must bind the actual ${field}`, () => {
    const { data, key, version } = traceAttempt();
    data.cli_trace_catalog["invented trace"] = { route: key, command: "config", test_source: data.cli_command_catalog.config.proof, client_version: version };
    const receipt = { passed: true, route: key, client_version: version, source_sha256: sourceHashes() };
    receipt[field] = field === "client_version" ? "0.0.0" : {};
    assert.throws(() => validateCoverage(data, undefined, undefined, {}, { "invented trace": receipt }), /CLI trace receipt/);
  });
}
