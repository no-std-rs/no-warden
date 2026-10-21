import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import http from "node:http";
import test from "node:test";
import { fileURLToPath } from "node:url";

async function childResult(command, args, env) {
  const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", chunk => { output += chunk; });
  child.stderr.on("data", chunk => { output += chunk; });
  const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
  try {
    const code = await new Promise((resolve, reject) => {
      child.once("error", reject); child.once("close", resolve);
    });
    return { code, output };
  } finally { clearTimeout(timer); if (child.exitCode === null) child.kill("SIGKILL"); }
}
for (const spelling of ["identical", "equivalent port"]) {
  test(`organization sharing rejects ${spelling} backends before artifact or fixture HTTP`, async () => {
    let requests = 0;
    const server = http.createServer((request, response) => {
      requests++; request.resume(); response.end("unexpected fixture contact");
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    const reference = `http://127.0.0.1:${port}`;
    const target = spelling === "identical" ? reference : `http://127.0.0.1:0${port}`;
    assert.equal(new URL(reference).origin, new URL(target).origin);
    const directory = await mkdtemp("/tmp/no-warden-web-org-guard-test-");
    const env = { ...process.env, BW_WEB_OUTPUT: directory, BW_WEB_ORG_MODE: "paired",
      BW_WEB_REFERENCE_BASE: reference, BW_WEB_TARGET_BASE: target };
    for (const key of ["DEBUG", "DEBUG_FILE", "PWDEBUG", "NODE_DEBUG", "NODE_DEBUG_NATIVE"]) delete env[key];
    try {
      const result = await childResult(process.execPath,
        [fileURLToPath(new URL("./web-org-sharing.mjs", import.meta.url))], env);
      assert.equal(result.code, 1); assert.equal(requests, 0);
      assert.equal(result.output.trim(), JSON.stringify({ status: "failed", stage: "configuration" }));
    } finally {
      await new Promise(resolve => { server.closeAllConnections(); server.close(resolve); });
      await rm(directory, { recursive: true, force: true });
    }
  });
}
test("unknown browser extension selectors fail before disposable infrastructure starts", async () => {
  const script = fileURLToPath(new URL("./web-compat.sh", import.meta.url));
  const result = await childResult("bash", [script, "--unknown-selector"], process.env);
  assert.equal(result.code, 2);
  assert.equal(result.output.trim(), "Usage: tools/web-compat.sh [--organization-sharing]");
});

test("whole portable CI preserves both strict browser scopes and shell failure propagation", async () => {
  const { validateWebComparisonExecution } = await import("./check-api-coverage.mjs");
  const workflow = await readFile(new URL("../.github/workflows/web-client.yml", import.meta.url), "utf8");
  const setup = await readFile(new URL("./web-compat.sh", import.meta.url), "utf8");
  validateWebComparisonExecution(workflow, setup);
  for (const changed of [setup.replace("BW_WEB_VAULT_MODE=both", "BW_WEB_VAULT_MODE=login"), setup.replace("BW_WEB_ORG_MODE=paired", "BW_WEB_ORG_MODE=reference"), setup.replace("node tools/web-compat.mjs", "node tools/web-compat.mjs || true"), setup.replace("node tools/web-org-sharing.mjs", "node tools/web-org-sharing.mjs || true")]) assert.throws(() => validateWebComparisonExecution(workflow, changed));
});
