import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const http = "target/conformance/no-warden-http-conformance";
// Keep selectors here when adding a suite. The test requires every explicit
// selector in the Rust entry point, exactly once, alongside the default suite.
// Measured check time is approximately 700s per shard, excluding runner setup.
export const shards = {
  http: [
    "repository-policy", "api-coverage", "cli-inventory", "client-ci-tests",
    "server-tests", "persistence", "default-http",
    "organization-member-mini-details", "organization-member-mini-details-cli",
    "web-organization-reads",
    "web-organization-reads-cli",
    "organization-cipher-update", "organization-cipher-update-cli",
    "personal-vault-purge",
  ],
  baseline: [
    "baseline-cli", "text-sends", "text-sends-cli",
    "organization-bulk-confirmation", "organization-bulk-confirmation-cli",
    "user-key-id", "user-key-id-cli", "account-password-cli",
  ],
  "organization-a": [
    "webauthn-credentials", "prelogin", "prelogin-cli",
    "organization-bulk-member-removal", "organization-bulk-member-removal-cli",
    "organization-confirmation", "organization-confirmation-cli",
    "organization-owner", "organization-owner-cli",
    "organization-collection-mutations", "organization-collection-mutations-cli",
    "organization-members", "organization-members-cli",
    "organization-cipher-sharing", "organization-cipher-sharing-cli",
    "account-deletion", "refresh-grants", "cipher-reads", "password-grants",
  ],
  "organization-b": [
    "organization-member-status", "organization-member-status-cli",
    "organization-bulk-member-status", "organization-bulk-member-status-cli",
    "organization-invites", "organization-invites-cli",
    "organization-member-removal", "organization-member-removal-cli",
    "organization-collections", "organization-collections-cli",
    "file-sends", "file-sends-cli",
    "organization-member-public-keys", "organization-member-public-keys-cli",
    "organization-cipher-bulk-sharing", "organization-cipher-bulk-sharing-cli",
    "account-kdf-cli",
  ],
};
export const shardJobs = [
  "bitwarden-cli-http", "bitwarden-cli-baseline",
  "bitwarden-cli-organization-a", "bitwarden-cli-organization-b",
];
const checks = {
  "repository-policy": ["node", "--test", "tools/repository-policy.test.mjs"],
  "api-coverage": ["node", "--test", "tools/api-coverage.test.mjs"],
  "cli-inventory": ["node", "--test", "tools/cli-inventory.test.mjs"],
  "client-ci-tests": ["node", "--test", "tools/client-ci.test.mjs"],
  "server-tests": ["node", "--test", "tools/server-tests.mjs"],
  persistence: ["node", "tools/persistence.mjs"],
  "default-http": [http],
  "baseline-cli": ["bash", "tools/e2e.sh"],
};

export function explicitSelectors(source) {
  const names = new Map([...source.matchAll(/"([a-z][a-z0-9-]*)" => Self::(\w+),/g)].map((match) => [match[2], match[1]]));
  const explicit = [...source.matchAll(/if suite == Suite::(\w+) \{/g)].map((match) => {
    assert(names.has(match[1]), `Missing selector mapping for ${match[1]}`);
    return names.get(match[1]);
  });
  assert(explicit.length > 0, "No explicit conformance selectors found");
  assert.equal(new Set(explicit).size, explicit.length, "Duplicate explicit selector dispatch");
  return explicit;
}

export function validatePlan(plan, source) {
  assert(plan && typeof plan === "object" && !Array.isArray(plan), "Missing shard plan");
  assert.deepEqual(Object.keys(plan).sort(), shardJobs.map((job) => job.slice("bitwarden-cli-".length)).sort(), "Exactly four fixed shards are required");
  const expected = [...Object.keys(checks), ...explicitSelectors(source)].sort();
  const actual = Object.values(plan).flatMap((tasks) => {
    assert(Array.isArray(tasks) && tasks.length > 0, "Each shard must run checks");
    assert(tasks.every((task) => typeof task === "string"), "Checks must be named strings");
    return tasks;
  }).sort();
  assert.deepEqual(actual, expected, "Missing, duplicate, or unknown client check; include every explicit Rust suite exactly once");
}

export function commandsForShard(name, plan = shards) {
  assert(Object.hasOwn(plan, name), `Unknown client shard: ${name}`);
  return plan[name].map((task) => checks[task] ?? [http, "--suite", task]);
}

export function aggregate(results) {
  assert(results && typeof results === "object" && !Array.isArray(results), "Missing shard results");
  assert.deepEqual(Object.keys(results).sort(), [...shardJobs].sort(), "All four fixed shard results are required");
  for (const job of shardJobs) {
    assert.equal(results[job]?.result, "success", `Client shard did not succeed: ${job}`);
    assert.equal(results[job]?.outputs?.completed, "true", `Client shard did not complete its checks: ${job}`);
  }
}

// This deliberately validates the small workflow form we use, rather than
// interpreting arbitrary YAML. Unsupported topology changes require review.
export function validateWorkflow(source, worker) {
  const body = source.slice(source.indexOf("\njobs:\n") + "\njobs:\n".length);
  const matches = [...body.matchAll(/^  ([a-z][a-z0-9-]*):\n/gm)];
  const jobs = Object.fromEntries(matches.map((match, index) => [
    match[1], body.slice(match.index + match[0].length, matches[index + 1]?.index ?? body.length).trimEnd(),
  ]));
  assert.equal(matches.length, Object.keys(jobs).length, "Duplicate CI job");
  assert.deepEqual(Object.keys(jobs).sort(), ["rust", "msrv", "bitwarden-cli", ...shardJobs].sort(), "Unexpected or missing CI job");
  assert(!/^\s*(?:continue-on-error|strategy)\s*:/m.test(source), "Client checks cannot ignore failures or use an implicit matrix");
  for (const job of shardJobs) {
    assert.equal(jobs[job], `    uses: ./.github/workflows/client-shard.yml\n    with:\n      shard: ${job.slice("bitwarden-cli-".length)}`, `Invalid fixed shard wiring: ${job}`);
  }
  assert.equal(jobs["bitwarden-cli"], `    if: \u0024{{ always() }}\n    needs: [${shardJobs.join(", ")}]\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n        with:\n          node-version: '24'\n      - name: Require every fixed client shard to succeed\n        env:\n          CLIENT_SHARD_RESULTS: \u0024{{ toJSON(needs) }}\n        run: node tools/client-ci.mjs aggregate`, "The required context must always evaluate every fixed shard without bypassing failures");
  assert(/^  workflow_call:\n    inputs:\n      shard:\n        required: true\n        type: string$/m.test(worker), "Worker must require its shard input");
  assert(!/^\s*(?:-\s*)?(?:if|continue-on-error|strategy)\s*:/m.test(worker), "Worker checks must run unconditionally and fail on error");
  assert.deepEqual([...worker.slice(worker.indexOf("\njobs:\n")).matchAll(/^  ([a-z][a-z0-9-]*):\n/gm)].map((match) => match[1]), ["check"], "Worker must contain exactly one check job");
  assert.equal([...worker.matchAll(/^          node tools\/client-ci\.mjs run "\$CLIENT_SHARD"$/gm)].length, 1, "Worker must execute its complete shard without suppressing failures");
  assert(worker.includes("          set -euo pipefail\n          NO_WARDEN_DB="), "Worker must fail on a failed check or startup");
  for (const marker of [
    "        value: ${{ jobs.check.outputs.completed }}\n",
    "      completed: ${{ steps.client-checks.outputs.completed }}\n",
    "        id: client-checks\n",
    "          node tools/client-ci.mjs run \"$CLIENT_SHARD\"\n          printf 'completed=true\\n' >> \"$GITHUB_OUTPUT\"\n",
  ]) assert(worker.includes(marker), "Worker must emit its completion output only after all checks succeed");
  assert(worker.includes("CLIENT_SHARD: ${{ inputs.shard }}"), "Worker must use the caller's fixed shard input");
  for (const command of [
    "npm ci --prefix tools", "prlimit --version",
    "cargo build --profile conformance -p no-warden-server -p no-warden-conformance --locked",
  ]) assert(worker.includes(`- run: ${command}\n`), `Missing worker setup: ${command}`);
}

export function runShard(name, execute = (command) => spawnSync(command[0], command.slice(1), { cwd: root, stdio: "inherit" })) {
  const source = readFileSync(new URL("../crates/no-warden-conformance/src/bin/no-warden-http-conformance.rs", import.meta.url), "utf8");
  validatePlan(shards, source);
  for (const command of commandsForShard(name)) {
    console.log(`Client check: ${command.join(" ")}`);
    const result = execute(command);
    assert(!result.error, `Could not start client check: ${command.join(" ")}`);
    assert.equal(result.status, 0, `Client check failed${result.signal ? ` (${result.signal})` : ""}: ${command.join(" ")}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length === 3 && process.argv[2] === "aggregate") {
      aggregate(JSON.parse(process.env.CLIENT_SHARD_RESULTS ?? "null"));
      console.log("All four client shards succeeded");
    } else if (process.argv.length === 4 && process.argv[2] === "run") {
      runShard(process.argv[3]);
    } else throw new Error("Usage: node tools/client-ci.mjs aggregate | run SHARD");
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
