import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
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

test("uses a regular 0600 output file inside a 0700 directory", { skip: process.platform === "win32" }, () => withCache(cacheDirectory => {
  const script = `
    const fs = require("node:fs"), path = require("node:path");
    const root = process.argv[1];
    const directory = path.join(root, fs.readdirSync(root)[0]);
    const file = fs.fstatSync(1);
    process.stdout.write(JSON.stringify({
      regular: file.isFile(), fileMode: file.mode & 0o777,
      directoryMode: fs.statSync(directory).mode & 0o777,
    }));
    process.exit(0);
  `;
  const result = runCliProcess(process.execPath, ["-e", script, cacheDirectory], { cacheDirectory });
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout), { regular: true, fileMode: 0o600, directoryMode: 0o700 });
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
