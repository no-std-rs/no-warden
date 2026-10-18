import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { validateRepositoryPolicy } from "./verify-repository-policy.mjs";

const policy = JSON.parse(readFileSync(new URL("../.github/main.ruleset.json", import.meta.url), "utf8"));
function fixture() {
  const repository = {
    full_name: "no-std-rs/no-warden", visibility: "public", private: false,
    default_branch: "main", allow_squash_merge: true,
    allow_merge_commit: false, allow_rebase_merge: false,
  };
  const ruleset = { ...structuredClone(policy), id: 42, source_type: "Repository", source: repository.full_name };
  const effective = ruleset.rules.map((rule) => ({
    ...structuredClone(rule), ruleset_id: 42,
    ruleset_source_type: "Repository", ruleset_source: repository.full_name,
  }));
  return [repository, ruleset, effective];
}
const rule = (snapshot, type) => snapshot.rules.find((entry) => entry.type === type);

test("accepts matching flat or fully paginated live snapshots", () => {
  const snapshots = fixture();
  assert.doesNotThrow(() => validateRepositoryPolicy(...snapshots));
  assert.doesNotThrow(() => validateRepositoryPolicy(snapshots[0], snapshots[1], [snapshots[2].slice(0, 2), snapshots[2].slice(2)]));
  snapshots[1].rules.reverse();
  rule(snapshots[1], "required_status_checks").parameters.required_status_checks.reverse();
  assert.doesNotThrow(() => validateRepositoryPolicy(...snapshots));
});

const regressions = [
  ["wrong repository", ([repo]) => { repo.full_name = "other/repository"; }],
  ["private repository", ([repo]) => { repo.private = true; }],
  ["nonpublic visibility", ([repo]) => { repo.visibility = "internal"; }],
  ["different default branch", ([repo]) => { repo.default_branch = "develop"; }],
  ["squash disabled", ([repo]) => { repo.allow_squash_merge = false; }],
  ["merge commits enabled", ([repo]) => { repo.allow_merge_commit = true; }],
  ["rebase enabled", ([repo]) => { repo.allow_rebase_merge = true; }],
  ["hidden bypass actors", ([, set]) => { delete set.bypass_actors; }],
  ["null bypass actors", ([, set]) => { set.bypass_actors = null; }],
  ["configured bypass actor", ([, set]) => { set.bypass_actors = [{ actor_type: "RepositoryRole", actor_id: 5, bypass_mode: "always" }]; }],
  ["missing PR requirement", ([, set]) => { set.rules = set.rules.filter((entry) => entry.type !== "pull_request"); }],
  ["merge method allowed in PR rule", ([, set]) => { rule(set, "pull_request").parameters.allowed_merge_methods.push("merge"); }],
  ["unresolved conversations allowed", ([, set]) => { rule(set, "pull_request").parameters.required_review_thread_resolution = false; }],
  ["missing required context", ([, set]) => { rule(set, "required_status_checks").parameters.required_status_checks.pop(); }],
  ["wrong context App", ([, set]) => { rule(set, "required_status_checks").parameters.required_status_checks[0].integration_id = 4602759; }],
  ["unpinned context", ([, set]) => { delete rule(set, "required_status_checks").parameters.required_status_checks[0].integration_id; }],
  ["non-strict checks", ([, set]) => { rule(set, "required_status_checks").parameters.strict_required_status_checks_policy = false; }],
  ["checks waived on creation", ([, set]) => { rule(set, "required_status_checks").parameters.do_not_enforce_on_create = true; }],
  ["disabled ruleset", ([, set]) => { set.enforcement = "disabled"; }],
  ["evaluation-only ruleset", ([, set]) => { set.enforcement = "evaluate"; }],
  ["tag ruleset", ([, set]) => { set.target = "tag"; }],
  ["unmatched main", ([, set]) => { set.conditions.ref_name.include = ["refs/heads/develop"]; }],
  ["excluded main", ([, set]) => { set.conditions.ref_name.exclude = ["refs/heads/main"]; }],
  ["absent effective ID", ([, , effective]) => { effective.forEach((entry) => { entry.ruleset_id = 99; }); }],
  ["wrong effective source", ([, , effective]) => { effective[0].ruleset_source = "other/repository"; }],
  ["weak effective PR rule", ([, , effective]) => { effective[0].parameters.allowed_merge_methods = ["merge"]; }],
  ["incomplete effective rules", ([, , effective]) => { effective.pop(); }],
  ["duplicate effective rule", ([, , effective]) => { effective[1] = structuredClone(effective[0]); }],
  ["missing deletion restriction", ([, set]) => { set.rules = set.rules.filter((entry) => entry.type !== "deletion"); }],
  ["missing force-push restriction", ([, set]) => { set.rules = set.rules.filter((entry) => entry.type !== "non_fast_forward"); }],
  ["missing linear history", ([, set]) => { set.rules = set.rules.filter((entry) => entry.type !== "required_linear_history"); }],
];
for (const [name, mutate] of regressions) {
  test(`rejects ${name}`, () => {
    const snapshots = fixture();
    mutate(snapshots);
    assert.throws(() => validateRepositoryPolicy(...snapshots));
  });
}

test("rejects malformed or partially paginated effective snapshots", () => {
  const [repo, set, effective] = fixture();
  for (const malformed of [null, {}, [effective, effective[0]], [[effective]], [null], []]) {
    assert.throws(() => validateRepositoryPolicy(repo, set, malformed));
  }
});

test("CLI reads three snapshots and fails closed for malformed input or wrong arguments", () => {
  const directory = mkdtempSync(join(tmpdir(), "no-warden-policy-"));
  const script = new URL("./verify-repository-policy.mjs", import.meta.url);
  try {
    const paths = fixture().map((value, index) => {
      const path = join(directory, `${index}.json`);
      writeFileSync(path, JSON.stringify(value));
      return path;
    });
    const run = (args) => spawnSync(process.execPath, [fileURLToPath(script), ...args], { encoding: "utf8" });
    assert.equal(run(paths).status, 0);
    writeFileSync(paths[2], "{invalid");
    assert.equal(run(paths).status, 1);
    assert.equal(run(paths.slice(0, 2)).status, 1);
    rmSync(paths[0]);
    assert.equal(run(paths).status, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
