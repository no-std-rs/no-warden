import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repositoryName = "no-std-rs/no-warden";
const expected = JSON.parse(readFileSync(new URL("../.github/main.ruleset.json", import.meta.url), "utf8"));

function object(value, label) {
  assert(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
}

function oneRule(rules, type, label) {
  assert(Array.isArray(rules), `${label} rules must be an array`);
  const matches = rules.filter((rule) => rule?.type === type);
  assert.equal(matches.length, 1, `${label} must contain exactly one ${type} rule`);
  return matches[0];
}

function sortedChecks(checks, label) {
  assert(Array.isArray(checks), `${label} checks must be an array`);
  for (const check of checks) {
    object(check, `${label} check`);
    assert.equal(typeof check.context, "string", `${label} context must be a string`);
    assert(check.context.length > 0, `${label} context must not be empty`);
    assert(Number.isSafeInteger(check.integration_id) && check.integration_id > 0, `${label} check must pin a GitHub App`);
  }
  assert.equal(new Set(checks.map((check) => check.context)).size, checks.length, `${label} contexts must be unique`);
  return checks.map(({ context, integration_id }) => ({ context, integration_id }))
    .sort((left, right) => left.context.localeCompare(right.context));
}

function matchRule(rule, policy, label) {
  for (const [key, value] of Object.entries(policy.parameters ?? {})) {
    const actual = rule.parameters?.[key];
    if (key === "required_status_checks") {
      assert.deepEqual(sortedChecks(actual, label), sortedChecks(value, "expected"), `${label} App-pinned contexts differ`);
    } else {
      assert.deepEqual(actual, value, `${label} ${key} differs`);
    }
  }
}

// These are snapshots from explicit GET requests, not a mutation or push probe.
export function validateRepositoryPolicy(repository, ruleset, effectiveInput) {
  object(repository, "repository");
  object(ruleset, "ruleset");
  assert.equal(repository.full_name, repositoryName, "repository identity differs");
  assert.equal(repository.visibility, "public", "repository must be public");
  assert.equal(repository.private, false, "repository must not be private");
  assert.equal(repository.default_branch, "main", "default branch must be main");
  assert.equal(repository.allow_squash_merge, true, "squash merges must be enabled");
  assert.equal(repository.allow_merge_commit, false, "merge commits must be disabled");
  assert.equal(repository.allow_rebase_merge, false, "rebase merges must be disabled");

  assert(Number.isSafeInteger(ruleset.id) && ruleset.id > 0, "ruleset must have a positive ID");
  assert.equal(ruleset.source_type, "Repository", "ruleset source must be the repository");
  assert.equal(ruleset.source, repositoryName, "ruleset repository identity differs");
  for (const key of ["name", "target", "enforcement", "conditions"]) {
    assert.deepEqual(ruleset[key], expected[key], `ruleset ${key} differs`);
  }
  assert(Array.isArray(ruleset.bypass_actors), "ruleset bypass_actors must be visible as an array");
  assert.equal(ruleset.bypass_actors.length, 0, "ruleset must have no bypass actors");
  assert(Array.isArray(ruleset.rules), "ruleset rules must be an array");
  assert.equal(ruleset.rules.length, expected.rules.length, "ruleset rule count differs");

  assert(Array.isArray(effectiveInput), "effective rules must be an array or array of pages");
  const pages = effectiveInput.some(Array.isArray);
  assert(!pages || effectiveInput.every(Array.isArray), "effective pages must all be arrays");
  const effective = pages ? effectiveInput.flat() : effectiveInput;
  for (const rule of effective) object(rule, "effective rule");
  const applicable = effective.filter((rule) => rule.ruleset_id === ruleset.id);
  assert.equal(applicable.length, expected.rules.length, "effective ruleset ID or rule count differs");
  for (const rule of applicable) {
    assert.equal(rule.ruleset_source_type, "Repository", "effective rule source type differs");
    assert.equal(rule.ruleset_source, repositoryName, "effective rule repository differs");
  }
  for (const policy of expected.rules) {
    matchRule(oneRule(ruleset.rules, policy.type, "ruleset"), policy, `ruleset ${policy.type}`);
    matchRule(oneRule(applicable, policy.type, "effective"), policy, `effective ${policy.type}`);
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    assert.equal(process.argv.length, 5, "Usage: node tools/verify-repository-policy.mjs repository.json ruleset.json effective-rules.json");
    const snapshots = process.argv.slice(2).map((path) => JSON.parse(readFileSync(path, "utf8")));
    validateRepositoryPolicy(...snapshots);
    console.log("PASS: repository snapshots enforce reviewed squash merges on main.");
  } catch (error) {
    console.error(`Repository policy verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}
