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
      else if (entry.isFile() && (entry.name.endsWith(".rs") || entry.name.endsWith(".json") || ["Cargo.toml", "Cargo.lock"].includes(entry.name))) paths.push(path);
    }
  }
  for (const directory of ["crates", "checks"]) walk(join(root, directory));
  for (const file of ["Cargo.toml", "Cargo.lock"]) paths.push(join(root, file));
  // Include helpers and subprocess entry points as well as the test entry points.
  for (const entry of readdirSync(join(root, "tools"), { withFileTypes: true })) {
    if (entry.isFile() && (entry.name.endsWith(".mjs") || entry.name.endsWith(".sh") || ["package.json", "package-lock.json"].includes(entry.name))) {
      paths.push(join(root, "tools", entry.name));
    }
  }
  return Object.fromEntries(paths.sort().map(path => [
    relative(root, path).split("\\").join("/"), createHash("sha256").update(readFileSync(path)).digest("hex"),
  ]));
}

export function validateCoverage(coverage, hashes = sourceHashes(), readSource = path => readFileSync(join(repositoryRoot, path), "utf8"), comparisonReceipts = process.env.API_COMPARISON_RECEIPTS ? JSON.parse(readFileSync(process.env.API_COMPARISON_RECEIPTS, "utf8")) : {}, cliTraceReceipts = process.env.API_CLI_TRACE_RECEIPTS ? JSON.parse(readFileSync(process.env.API_CLI_TRACE_RECEIPTS, "utf8")) : {}) {
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
  function auditedLine(reference) {
    assert(reference && typeof reference === "string", "Source reference must name a file and line");
    const match = /^(.*):(\d+)$/.exec(reference);
    assert(match && Object.hasOwn(hashes, match[1]), `Unaudited source reference: ${reference}`);
    const line = readSource(match[1]).split("\n")[Number(match[2]) - 1];
    assert.equal(typeof line, "string", `Invalid source line: ${reference}`);
    return line;
  }
  const wire = readSource("crates/no-warden/src/wire.rs");
  const routing = readSource("crates/no-warden/src/route.rs");
  const variants = /pub enum Route[^\{]*\{([\s\S]*?)^\}/m.exec(routing)?.[1];
  assert(variants, "Missing Route enum source");
  const comparisons = coverage.upstream_comparison_catalog;
  assert(comparisons && typeof comparisons === "object" && !Array.isArray(comparisons), "Comparison catalog must be explicit");
  for (const [id, entry] of Object.entries(comparisons)) {
    assert(rows.has(entry.route), `Unknown comparison route: ${id}`);
    assert.equal(entry.upstream_commit, coverage.upstream_pin, `Wrong comparison upstream: ${id}`);
    assert(tests.has(entry.test_name), `Unknown audited comparison test: ${id}`);
  }
  const traces = coverage.cli_trace_catalog;
  assert(traces && typeof traces === "object" && !Array.isArray(traces), "CLI trace catalog must be explicit");
  const clientVersion = JSON.parse(readSource("tools/package-lock.json")).packages["node_modules/@bitwarden/cli"].version;
  for (const [id, entry] of Object.entries(traces)) {
    assert(rows.has(entry.route), `Unknown CLI trace route: ${id}`);
    assert(Object.hasOwn(coverage.cli_command_catalog, entry.command), `Unknown CLI trace command: ${id}`);
    assert.equal(entry.client_version, clientVersion, `Wrong CLI trace version: ${id}`);
    assert.equal(entry.test_source, coverage.cli_command_catalog[entry.command].proof, `Wrong CLI trace source: ${id}`);
    assert(Object.hasOwn(hashes, entry.test_source), `Unaudited CLI trace source: ${id}`);
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
    const classifier = route.classifier_enum.split("(")[0];
    assert(/^[A-Za-z_]\w*$/.test(classifier), `${key}: invalid classifier symbol`);
    if (route.routed) assert(new RegExp(`^\\s*${classifier}(?:\\(|,)`, "m").test(variants), `${key}: missing classifier symbol`);
    for (const [dimension, flag] of [["requests", "typed_request"], ["responses", "typed_response"]]) {
      const models = route.core_models[dimension];
      assert.equal(route[flag], models.length > 0, `${key}: typed dimension requires model references`);
      for (const model of models) {
        const name = model.split("<")[0];
        assert(/^[A-Za-z_]\w*$/.test(name) && new RegExp(`^pub (?:struct|enum|type) ${name}(?:[<( {=])`, "m").test(wire), `${key}: missing wire model ${model}`);
      }
    }
    assert.equal(route.core_service_implemented, route.core_service !== null, `${key}: service dimension requires a source reference`);
    if (route.core_service_implemented) {
      const service = route.core_service;
      assert(service && typeof service === "object" && /^[A-Za-z_]\w*$/.test(service.symbol) && /^[A-Za-z_]\w*$/.test(service.owner), `${key}: invalid service symbol reference`);
      const line = auditedLine(`${service.file}:${service.line}`);
      assert(new RegExp(`^\\s*pub (?:async )?fn ${service.symbol}\\s*[<(]`).test(line), `${key}: missing service method`);
      assert(new RegExp(`impl[^\\n]*\\b${service.owner}\\b`).test(readSource(service.file).split("\n").slice(0, service.line - 1).join("\n")), `${key}: missing service owner`);
    }
    assert.equal(route.server_implemented, route.server_handler !== null, `${key}: server dimension requires a handler reference`);
    if (route.server_implemented) {
      const line = auditedLine(route.server_handler);
      assert(new RegExp(`\\bRoute::${classifier}\\b`).test(line) && (/=>/.test(line) || /^\s*if route == Route::/.test(line) || /^\s*if let Route::\w+\([^)]*\) = route \{\s*$/.test(line)), `${key}: handler must cite its classifier arm or condition`);
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
      for (const id of route.cli_trace_evidence) {
        assert(Object.hasOwn(traces, id), `${key}: unknown CLI trace case ${id}`);
        assert.equal(traces[id].route, key, `${key}: CLI trace must target this route`);
        const receipt = cliTraceReceipts[id];
        assert(receipt?.passed === true && receipt.route === key && receipt.client_version === clientVersion, `${key}: missing successful current CLI trace receipt`);
        assert.deepEqual(receipt.source_sha256, hashes, `${key}: CLI trace receipt must match current audited sources`);
      }
    }
    if (route.full_upstream_parity_verified) {
      assert(route.routed && route.server_implemented && route.http_positive_tested, `${key}: parity requires behavior and HTTP evidence`);
      assert(Array.isArray(route.parity_evidence?.upstream_comparison_cases) && route.parity_evidence.upstream_comparison_cases.length > 0, `${key}: parity requires upstream comparison cases`);
      for (const id of route.parity_evidence.upstream_comparison_cases) {
        assert(Object.hasOwn(comparisons, id), `${key}: unknown upstream comparison case ${id}`);
        assert.equal(comparisons[id].route, key, `${key}: comparison must target this route`);
        const receipt = comparisonReceipts[id];
        assert(receipt?.passed === true && receipt.route === key && receipt.upstream_commit === coverage.upstream_pin, `${key}: missing successful current upstream comparison receipt`);
        assert.deepEqual(receipt.source_sha256, hashes, `${key}: comparison receipt must match current audited sources`);
      }
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
  for (const [key, row] of rows) {
    if (!row.full_upstream_parity_verified) continue;
    const entries = coverage.upstream_routes.filter(entry => entry.coverage_record === key);
    assert(entries.length > 0 && entries.every(entry => entry.status === "verified"), `${key}: full parity requires every linked upstream handler to be verified`);
  }
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
