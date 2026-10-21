import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { aggregate, commandsForShard, explicitSelectors, runShard, shardJobs, shards, validatePlan, validateWorkflow } from "./client-ci.mjs";

const selector = readFileSync(new URL("../crates/no-warden-conformance/src/bin/no-warden-http-conformance.rs", import.meta.url), "utf8");
const workflow = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const worker = readFileSync(new URL("../.github/workflows/client-shard.yml", import.meta.url), "utf8");
const success = () => Object.fromEntries(shardJobs.map((job) => [job, { result: "success", outputs: { completed: "true" } }]));

// The coverage assertion follows the actual dispatch, so a newly implemented
// opt-in HTTP or CLI suite fails CI until it is assigned to a shard.
test("every explicit HTTP/CLI selector and existing default/Node/CLI check runs exactly once", () => {
  validatePlan(shards, selector);
  validateWorkflow(workflow, worker);
  const commands = Object.keys(shards).flatMap((name) => commandsForShard(name));
  for (const command of [
    ["node", "--test", "tools/repository-policy.test.mjs"],
    ["node", "--test", "tools/api-coverage.test.mjs"],
    ["node", "--test", "tools/cli-inventory.test.mjs"],
    ["node", "--test", "tools/server-tests.mjs"],
    ["node", "tools/persistence.mjs"],
    ["target/conformance/no-warden-http-conformance"],
    ["bash", "tools/e2e.sh"],
  ]) assert.equal(commands.filter((actual) => JSON.stringify(actual) === JSON.stringify(command)).length, 1, `Missing or repeated inherited check: ${command}`);
});

test("rejects any missing or duplicated suite, including newly added dispatch", () => {
  for (const name of explicitSelectors(selector)) {
    const missing = structuredClone(shards);
    for (const tasks of Object.values(missing)) {
      const index = tasks.indexOf(name);
      if (index !== -1) tasks.splice(index, 1);
    }
    assert.throws(() => validatePlan(missing, selector), /Missing, duplicate, or unknown/);
  }
  const extra = structuredClone(shards);
  extra.http.push("organization-owner-cli");
  assert.throws(() => validatePlan(extra, selector));
  const future = `${selector}\n"future-suite" => Self::FutureSuite,\nif suite == Suite::FutureSuite {\n`;
  assert.throws(() => validatePlan(shards, future), /Missing, duplicate, or unknown/);
});

test("rejects missing Node/default/baseline checks and malformed shard plans", () => {
  for (const name of ["repository-policy", "api-coverage", "cli-inventory", "client-ci-tests", "server-tests", "persistence", "default-http", "baseline-cli"]) {
    const plan = Object.fromEntries(Object.entries(shards).map(([key, tasks]) => [key, tasks.filter((task) => task !== name)]));
    assert.throws(() => validatePlan(plan, selector));
  }
  for (const plan of [null, [], {}, { ...shards, http: [] }, { ...shards, baseline: "baseline-cli" }, { ...shards, unexpected: [] }]) {
    assert.throws(() => validatePlan(plan, selector));
  }
  assert.throws(() => commandsForShard("unknown"));
});

test("aggregate accepts only all four exact successful results", () => {
  aggregate(success());
  for (const job of shardJobs) {
    for (const result of ["failure", "cancelled", "skipped", "neutral", "pending", "", null, undefined, true]) {
      const results = success();
      results[job].result = result;
      assert.throws(() => aggregate(results), /did not succeed/);
    }
    for (const completed of [undefined, null, "", "false", false, true]) {
      const unconfirmed = success();
      unconfirmed[job].outputs.completed = completed;
      assert.throws(() => aggregate(unconfirmed), /did not complete/);
    }
    const noOutputs = success();
    delete noOutputs[job].outputs;
    assert.throws(() => aggregate(noOutputs), /did not complete/);
    const missing = success();
    delete missing[job];
    assert.throws(() => aggregate(missing), /All four fixed/);
    const malformed = success();
    malformed[job] = null;
    assert.throws(() => aggregate(malformed));
  }
  for (const results of [null, [], {}, { ...success(), unexpected: { result: "success" } }]) assert.throws(() => aggregate(results));
});

test("required context CLI exits unsuccessfully for absent, malformed, skipped or cancelled needs", () => {
  const cli = new URL("./client-ci.mjs", import.meta.url);
  const run = (value, args = ["aggregate"]) => spawnSync(process.execPath, [cli.pathname, ...args], {
    encoding: "utf8", env: { ...process.env, CLIENT_SHARD_RESULTS: value },
  });
  assert.equal(run(JSON.stringify(success())).status, 0);
  for (const value of ["", "not-json", "null", "{}", "[]"]) assert.equal(run(value).status, 1);
  for (const state of ["failure", "skipped", "cancelled"]) {
    const results = success();
    results[shardJobs[0]].result = state;
    assert.equal(run(JSON.stringify(results)).status, 1);
  }
  assert.equal(run(JSON.stringify(success()), []).status, 1);
});

for (const [name, mutate] of [
  ["missing shard dependency", (text) => text.replace("needs: [bitwarden-cli-http, ", "needs: [")],
  ["aggregate skipped with failed dependencies", (text) => text.replace("    if: ${{ always() }}\n", "")],
  ["conditional shard", (text) => text.replace("  bitwarden-cli-http:\n", "  bitwarden-cli-http:\n    if: false\n")],
  ["ignored worker failure", (text) => text.replace("  bitwarden-cli-http:\n", "  bitwarden-cli-http:\n    continue-on-error: true\n")],
  ["wrong shard selection", (text) => text.replace("      shard: http\n", "      shard: baseline\n")],
  ["duplicate job key", (text) => `${text}\n  bitwarden-cli-http:\n    uses: other.yml\n`],
  ["wrong aggregate implementation", (text) => text.replace("node tools/client-ci.mjs aggregate", "true")],
  ["incomplete needs transfer", (text) => text.replace("${{ toJSON(needs) }}", "{}")],
]) test(`rejects workflow ${name}`, () => assert.throws(() => validateWorkflow(mutate(workflow), worker)));

for (const [name, mutate] of [
  ["conditional run", (text) => text.replace("      - name: Real client", "      - if: false\n        name: Real client")],
  ["ignored failure", (text) => `${text}\n    continue-on-error: true\n`],
  ["missing runner", (text) => text.replace('node tools/client-ci.mjs run "$CLIENT_SHARD"', "true")],
  ["suppressed runner failure", (text) => text.replace('node tools/client-ci.mjs run "$CLIENT_SHARD"', 'node tools/client-ci.mjs run "$CLIENT_SHARD" || true')],
  ["non-failing shell", (text) => text.replace("          set -euo pipefail\n          NO_WARDEN_DB=", "          set +e\n          NO_WARDEN_DB=")],
  ["wrong shard input", (text) => text.replace("CLIENT_SHARD: ${{ inputs.shard }}", "CLIENT_SHARD: http")],
  ["missing completion output", (text) => text.replace("        value: ${{ jobs.check.outputs.completed }}", "        value: true")],
  ["premature completion output", (text) => text.replace('node tools/client-ci.mjs run "$CLIENT_SHARD"\n          printf', 'true\n          printf')],
  ["missing build", (text) => text.replace("      - run: cargo build", "      - run: echo cargo build")],
]) test(`rejects worker ${name}`, () => assert.throws(() => validateWorkflow(workflow, mutate(worker))));

test("shard runner stops on command failures and signals", () => {
  for (const outcome of [{ status: 1 }, { status: null, signal: "SIGTERM" }, { status: 0, error: new Error("spawn failed") }]) {
    const observed = [];
    assert.throws(() => runShard("http", (command) => {
      observed.push(command);
      return observed.length === 2 ? outcome : { status: 0 };
    }), /Client check failed|Could not start client check/);
    assert.deepEqual(observed, commandsForShard("http").slice(0, 2));
  }
});
