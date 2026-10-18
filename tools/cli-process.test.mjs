import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { runCliProcess } from "./cli-process.mjs";

function withCache(run) {
  const directory = mkdtempSync(join(tmpdir(), "no-warden-cli-test-"));
  try {
    run(directory);
    assert.deepEqual(readdirSync(directory), [], "CLI output files must be removed");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("captures a complete large payload despite the child's immediate exit", () => withCache(cacheDirectory => {
  const bytes = 2 * 1024 * 1024;
  const result = runCliProcess(process.execPath, ["-e", `process.stdout.write("x".repeat(${bytes}));process.exit(0)`], { cacheDirectory });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, "x".repeat(bytes));
  assert.equal(result.stdoutBytes, bytes);
  assert.equal(result.stderrBytes, 0);
}));

test("uses an unlinked regular 0600 file inside an empty 0700 directory", { skip: process.platform === "win32" }, () => withCache(cacheDirectory => {
  const script = `
    const fs = require("node:fs"), path = require("node:path");
    const root = process.argv[1];
    const directory = path.join(root, fs.readdirSync(root)[0]);
    const file = fs.fstatSync(1);
    process.stdout.write(JSON.stringify({
      regular: file.isFile(), fileMode: file.mode & 0o777,
      directoryMode: fs.statSync(directory).mode & 0o777,
      links: file.nlink, entries: fs.readdirSync(directory),
    }));
    process.exit(0);
  `;
  const result = runCliProcess(process.execPath, ["-e", script, cacheDirectory], { cacheDirectory });
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout), {
    regular: true, fileMode: 0o600, directoryMode: 0o700, links: 0, entries: [],
  });
}));

test("rejects stdout beyond 4 MiB before reading it and removes the capture", () => withCache(cacheDirectory => {
  const bytes = 4 * 1024 * 1024 + 1;
  assert.throws(() => runCliProcess(process.execPath, [
    "-e", `process.stdout.write("x".repeat(${bytes}));process.exit(0)`,
  ], { cacheDirectory }), error => {
    assert.equal(error.code, "ERR_CLI_STDOUT_LIMIT");
    assert.equal(error.stdoutBytes, bytes);
    return true;
  });
}));

test("retains the 4 MiB stderr buffer limit and removes the capture", () => withCache(cacheDirectory => {
  const result = runCliProcess(process.execPath, [
    "-e", 'require("node:fs").writeSync(2,Buffer.alloc(4*1024*1024+1,120))',
  ], { cacheDirectory });
  assert.equal(result.error?.code, "ENOBUFS");
}));

test("preserves failed exit status and stderr byte counts without leaving files", () => withCache(cacheDirectory => {
  const result = runCliProcess(process.execPath, [
    "-e", 'process.stdout.write("partial");require("node:fs").writeSync(2,"test error");process.exit(7)',
  ], { cacheDirectory });
  assert.equal(result.status, 7);
  assert.equal(result.stdout, "partial");
  assert.equal(result.stdoutBytes, 7);
  assert.equal(result.stderrBytes, 10);
}));

test("cleans up after a missing executable", () => withCache(cacheDirectory => {
  const result = runCliProcess(join(cacheDirectory, "missing-executable"), [], { cacheDirectory });
  assert.equal(result.error?.code, "ENOENT");
  assert.equal(result.stdoutBytes, 0);
  assert.equal(result.stdout, "");
}));

test("enforces its timeout and cleans up the terminated child's capture", () => withCache(cacheDirectory => {
  const result = runCliProcess(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], { cacheDirectory, timeout: 100 });
  assert.equal(result.error?.code, "ETIMEDOUT");
  assert.notEqual(result.status, 0);
}));

test("captures under restrictive umask 0777 in an isolated process", { skip: process.platform === "win32" }, () => withCache(cacheDirectory => {
  const script = `
    import { runCliProcess } from ${JSON.stringify(new URL("./cli-process.mjs", import.meta.url).href)};
    process.umask(0o777);
    try {
      const result = runCliProcess(process.execPath, ["-e",
        'process.stdout.write(JSON.stringify({mode:require("node:fs").fstatSync(1).mode&0o777}));process.exit(0)'
      ], { cacheDirectory: process.argv[1] });
      process.stdout.write(JSON.stringify({status:result.status, capture:JSON.parse(result.stdout)}));
    } catch (error) {
      process.stderr.write(error.code ?? "capture-error");
      process.exitCode = 1;
    }
  `;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", script, cacheDirectory], {
    encoding: "utf8", timeout: 5000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, `Isolated capture failed with ${result.stderr}`);
  assert.deepEqual(JSON.parse(result.stdout), { status: 0, capture: { mode: 0o600 } });
}));

test("leaves no stdout file when its parent is terminated during spawnSync", { skip: process.platform === "win32", timeout: 15000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), "no-warden-cli-signal-"));
  const cacheDirectory = join(directory, "cache");
  const marker = join(directory, "ready.json");
  mkdirSync(cacheDirectory, { mode: 0o700 });
  const childScript = `
    const fs = require("node:fs");
    process.stdout.write("public capture marker");
    fs.writeFileSync(process.argv[1]+".tmp", JSON.stringify({pid:process.pid,ready:true}));
    fs.renameSync(process.argv[1]+".tmp", process.argv[1]);
    setInterval(() => {}, 1000);
  `;
  const parentScript = `
    import { runCliProcess } from ${JSON.stringify(new URL("./cli-process.mjs", import.meta.url).href)};
    runCliProcess(process.execPath, ["-e", ${JSON.stringify(childScript)}, ${JSON.stringify(marker)}], {
      cacheDirectory: ${JSON.stringify(cacheDirectory)},
    });
  `;
  const parent = spawn(process.execPath, ["--input-type=module", "-e", parentScript], { stdio: "ignore" });
  let childPid;
  let startupError;
  parent.on("error", error => { startupError = error; });
  const closed = new Promise(resolve => parent.once("close", (code, signal) => resolve({ code, signal })));
  try {
    const deadline = Date.now() + 5000;
    while (!existsSync(marker) && Date.now() < deadline && !startupError) await delay(20);
    assert.equal(startupError, undefined);
    assert(existsSync(marker), "Public child readiness marker was not created");
    const readiness = JSON.parse(readFileSync(marker, "utf8"));
    assert.equal(readiness.ready, true);
    childPid = readiness.pid;
    assert(Number.isInteger(childPid) && childPid > 1 && childPid !== process.pid);
    parent.kill("SIGTERM");
    const exit = await Promise.race([
      closed,
      delay(5000, null, { ref: false }).then(() => { throw new Error("Capture parent did not terminate"); }),
    ]);
    assert.equal(exit.signal, "SIGTERM");
    const captures = readdirSync(cacheDirectory);
    assert.equal(captures.length, 1, "Expected the active child's empty capture directory");
    assert.deepEqual(readdirSync(join(cacheDirectory, captures[0])), [], "A terminated parent must not leave named stdout behind");
  } finally {
    try {
      parent.kill("SIGKILL");
      await closed;
      if (!childPid && existsSync(marker)) childPid = JSON.parse(readFileSync(marker, "utf8")).pid;
      if (Number.isInteger(childPid) && childPid > 1 && childPid !== process.pid) {
        try { process.kill(childPid, "SIGTERM"); } catch (error) { if (error.code !== "ESRCH") throw error; }
        const deadline = Date.now() + 3000;
        let reaped = false;
        while (Date.now() < deadline) {
          try { process.kill(childPid, 0); } catch (error) {
            if (error.code !== "ESRCH") throw error;
            reaped = true;
            break;
          }
          await delay(20);
        }
        assert(reaped, "Public marker child must terminate and be reaped");
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});
