import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import test from "node:test";
import { fileURLToPath } from "node:url";

for (const spelling of ["identical", "equivalent port"]) {
  test(`rejects ${spelling} comparison backends before contacting them`, async () => {
    let requests = 0;
    const server = http.createServer((request, response) => {
      requests++;
      request.resume();
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ version: "not-a-tested-artifact" }));
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    const reference = `http://127.0.0.1:${port}`;
    const target = spelling === "identical" ? reference : `http://127.0.0.1:0${port}`;
    assert.equal(new URL(reference).origin, new URL(target).origin);
    const environment = { ...process.env, BW_WEB_REFERENCE_BASE: reference, BW_WEB_TARGET_BASE: target,
      BW_WEB_REFERENCE_ORIGIN: "https://127.0.0.1:18184", BW_WEB_TARGET_ORIGIN: "https://127.0.0.1:18185",
      BW_WEB_CHROMIUM: "/fixture-not-executed/chromium" };
    for (const key of ["DEBUG", "DEBUG_FILE", "PWDEBUG", "NODE_DEBUG", "NODE_DEBUG_NATIVE"]) delete environment[key];
    let child;
    let timer;
    try {
      child = spawn(process.execPath, [fileURLToPath(new URL("./web-compat.mjs", import.meta.url))],
        { env: environment, stdio: ["ignore", "pipe", "pipe"] });
      let output = "";
      child.stdout.on("data", chunk => { output += chunk; });
      child.stderr.on("data", chunk => { output += chunk; });
      timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
      const code = await new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
      assert.equal(code, 1);
      assert.equal(requests, 0);
      assert.equal(output.trim(), "FAIL web compatibility at configuration");
    } finally {
      clearTimeout(timer);
      if (child && child.exitCode === null) child.kill("SIGKILL");
      await new Promise(resolve => { server.closeAllConnections(); server.close(resolve); });
    }
  });
}
