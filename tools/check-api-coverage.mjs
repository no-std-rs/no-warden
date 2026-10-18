import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const coveragePath = join(repositoryRoot, "compatibility/no-warden-coverage.json");
export const upstreamKey = route => `${route.method} ${route.uri} @ ${route.source}:${route.line}#${route.handler}`;
export const routeShape = path => path.split("?")[0].replace(/<\w+(?:\.\.)?>|\{\w+\}/g, "{}");
export const routeParameters = path => [...path.split("?")[0].matchAll(/<(\w+)(?:\.\.)?>|\{(\w+)\}/g)].map(match => match[1] ?? match[2]);

export function sourceHashes(root = repositoryRoot) {
  const paths = [];
  function walk(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === "target") continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile() && (entry.name.endsWith(".rs") || entry.name === "Cargo.toml")) paths.push(path);
    }
  }
  for (const directory of ["crates", "checks"]) walk(join(root, directory));
  // Include helpers and subprocess entry points as well as the test entry points.
  for (const entry of readdirSync(join(root, "tools"), { withFileTypes: true })) {
    if (entry.isFile() && (entry.name.endsWith(".mjs") || ["package.json", "package-lock.json"].includes(entry.name))) {
      paths.push(join(root, "tools", entry.name));
    }
  }
  return Object.fromEntries(paths.sort().map(path => [
    relative(root, path).split("\\").join("/"), createHash("sha256").update(readFileSync(path)).digest("hex"),
  ]));
}

export function validateCoverage(coverage, hashes = sourceHashes(), readSource = path => readFileSync(join(repositoryRoot, path), "utf8")) {
  assert.equal(coverage.schema_version, 1);
  assert.match(coverage.snapshot_commit, /^[a-f0-9]{40}$/);
  assert.deepEqual(coverage.source_sha256, hashes, "Implementation or test sources changed: audit and update the coverage snapshot");
  assert(Array.isArray(coverage.routes));
  const unique = new Set();
  const rows = new Map(coverage.routes.map(route => [`${route.method} ${route.path}`, route]));
  const tests = new Set();
  for (const test of coverage.http_test_catalog) {
    assert(readSource(test.file).includes(test.name), `Missing HTTP test: ${test.name}`);
    assert(!tests.has(test.name), `Duplicate HTTP test: ${test.name}`);
    tests.add(test.name);
  }
  for (const [file, names] of Object.entries(coverage.core_unit_test_catalog)) {
    const source = readSource(file);
    for (const name of names) assert(source.includes(`fn ${name}(`), `Missing core test: ${name}`);
  }
  for (const route of coverage.routes) {
    assert(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"].includes(route.method));
    assert.equal(typeof route.path, "string");
    assert(route.path.startsWith("/"));
    const key = `${route.method} ${route.path}`;
    assert(!unique.has(key), `Duplicate coverage record: ${key}`);
    unique.add(key);
    for (const field of ["routed", "typed_request", "typed_response", "core_service_implemented", "server_implemented", "http_tested", "http_positive_tested", "http_negative_tested", "cli_route_trace_tested", "full_upstream_parity_verified"]) {
      assert.equal(typeof route[field], "boolean", `${key}: ${field} must be explicit`);
    }
    for (const name of [...route.http_test_names.positive, ...route.http_test_names.negative]) {
      assert(tests.has(name), `${key}: unknown HTTP test ${name}`);
    }
    if (route.restart_http_test !== null) {
      assert(Object.hasOwn(hashes, route.restart_http_test), `${key}: restart evidence must name an audited source`);
    }
    assert.equal(route.http_positive_tested, route.http_test_names.positive.length > 0 || route.restart_http_test !== null, `${key}: positive HTTP coverage requires test evidence`);
    assert.equal(route.http_negative_tested, route.http_test_names.negative.length > 0, `${key}: negative HTTP coverage requires test evidence`);
    assert.equal(route.http_tested, route.http_positive_tested || route.http_negative_tested, `${key}: HTTP coverage must agree with its evidence`);
    for (const command of route.cli_command_coverage) assert(Object.hasOwn(coverage.cli_command_catalog, command), `${key}: unknown CLI command ${command}`);
    if (route.cli_route_trace_tested) {
      assert(Array.isArray(route.cli_trace_evidence) && route.cli_trace_evidence.length > 0, `${key}: CLI commands alone do not prove a captured route trace`);
    }
    if (route.full_upstream_parity_verified) {
      assert(route.routed && route.server_implemented && route.http_positive_tested, `${key}: parity requires behavior and HTTP evidence`);
      assert(Array.isArray(route.parity_evidence?.upstream_comparison_cases) && route.parity_evidence.upstream_comparison_cases.length > 0, `${key}: parity requires upstream comparison cases`);
      assert.deepEqual(route.parity_evidence.remaining_variants, [], `${key}: unresolved variants prevent full parity`);
    }
  }
  const upstream = JSON.parse(readSource("compatibility/vaultwarden-routes.json"));
  assert.equal(coverage.upstream_pin, upstream.upstream.sha, "Coverage must use the pinned upstream revision");
  const handlers = new Map(upstream.routes.map(route => [upstreamKey(route), route]));
  assert.equal(handlers.size, upstream.routes.length, "Upstream handler keys must be unique");
  const recorded = new Set(), linked = new Set();
  for (const entry of coverage.upstream_routes) {
    assert(handlers.has(entry.upstream_key), `Unknown upstream handler: ${entry.upstream_key}`);
    assert(!recorded.has(entry.upstream_key), "Duplicate upstream coverage record");
    recorded.add(entry.upstream_key);
    assert(["unimplemented", "partial", "verified"].includes(entry.status), "Upstream status must be explicit");
    if (entry.status === "unimplemented") {
      assert.equal(entry.coverage_record, null);
      assert.deepEqual(entry.parameter_mapping, {});
      continue;
    }
    const local = rows.get(entry.coverage_record), remote = handlers.get(entry.upstream_key);
    assert(local, `Missing linked coverage record: ${entry.coverage_record}`);
    linked.add(entry.coverage_record);
    assert.equal(local.method, remote.method);
    assert.equal(routeShape(local.path), routeShape(remote.uri), "Linked path shapes must agree");
    assert.deepEqual(entry.parameter_mapping, Object.fromEntries(routeParameters(remote.uri).map((name, index) => [name, routeParameters(local.path)[index]])), "Path parameter mapping must be explicit");
    if (entry.status === "verified") assert(local.full_upstream_parity_verified, "Verified handler requires full-parity evidence");
  }
  assert.deepEqual([...recorded].sort(), [...handlers.keys()].sort(), "Every pinned upstream handler needs a coverage record");
  for (const key of coverage.local_extensions) {
    assert(rows.has(key), `Missing local extension coverage: ${key}`);
    assert(!linked.has(key), `Upstream-linked route is not a local extension: ${key}`);
    linked.add(key);
  }
  assert.deepEqual([...linked].sort(), [...rows.keys()].sort(), "Every local coverage row needs an upstream link or explicit extension record");
  const counts = {
    routed_method_path_patterns: coverage.routes.filter(r => r.routed).length,
    routes_with_typed_requests: coverage.routes.filter(r => r.typed_request).length,
    routes_with_any_typed_response_model: coverage.routes.filter(r => r.typed_response).length,
    routes_with_reusable_core_service: coverage.routes.filter(r => r.core_service_implemented).length,
    routes_with_direct_positive_or_restart_http_evidence: coverage.routes.filter(r => r.http_positive_tested || r.restart_http_test).length,
    routes_with_negative_http_evidence: coverage.routes.filter(r => r.http_negative_tested).length,
    routes_with_captured_cli_request_traces: coverage.routes.filter(r => r.cli_route_trace_tested).length,
    cli_distinct_command_patterns_in_harness: Object.keys(coverage.cli_command_catalog).length,
    named_http_tests_including_parent: coverage.http_test_catalog.length,
  };
  assert.deepEqual(coverage.counts, counts, "Coverage counts must describe the records");
  return { ...counts, fully_verified_upstream_operations: coverage.routes.filter(r => r.full_upstream_parity_verified).length };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  if (process.argv.length === 3 && process.argv[2] === "--source-hashes") {
    console.log(JSON.stringify(sourceHashes(), null, 2));
  } else {
    assert.equal(process.argv.length, 2, "Usage: node tools/check-api-coverage.mjs [--source-hashes]");
    console.log(JSON.stringify(validateCoverage(JSON.parse(readFileSync(coveragePath, "utf8"))), null, 2));
  }
}
