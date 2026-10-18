/** Capture unmodified CLI stdout through an unlinked private regular file.
 *
 * The official CLI can call process.exit() immediately after stdout.write().
 * Node writes to regular files synchronously; POSIX pipe writes can be async:
 * https://nodejs.org/docs/latest-v24.x/api/process.html#a-note-on-process-io
 */
import { spawnSync } from "node:child_process";
import {
  chmodSync, closeSync, fchmodSync, fstatSync, mkdtempSync, openSync, readSync,
  rmSync, unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const CLI_OUTPUT_LIMIT = 4 * 1024 * 1024;
export const CLI_TIMEOUT = 90_000;

export function runCliProcess(binary, args, {
  env = process.env,
  cwd,
  cacheDirectory = tmpdir(),
  timeout = CLI_TIMEOUT,
  maxOutputBytes = CLI_OUTPUT_LIMIT,
} = {}) {
  const directory = mkdtempSync(join(cacheDirectory, "cli-output-"));
  let descriptor;
  try {
    chmodSync(directory, 0o700);
    const path = join(directory, "stdout");
    descriptor = openSync(path, "wx+", 0o600);
    fchmodSync(descriptor, 0o600);
    // No stdout pathname survives once the child can write sensitive output.
    unlinkSync(path);
    const result = spawnSync(binary, args, {
      env, cwd, encoding: "utf8", timeout,
      maxBuffer: maxOutputBytes,
      stdio: ["ignore", descriptor, "pipe"],
    });
    const stdoutBytes = fstatSync(descriptor).size;
    if (stdoutBytes > maxOutputBytes) {
      const error = new Error(`CLI stdout exceeds the ${maxOutputBytes}-byte capture limit.`);
      error.code = "ERR_CLI_STDOUT_LIMIT";
      error.stdoutBytes = stdoutBytes;
      throw error;
    }
    const output = Buffer.alloc(stdoutBytes);
    let offset = 0;
    while (offset < stdoutBytes) {
      // The child shares this descriptor's offset, which is now at EOF.
      const count = readSync(descriptor, output, offset, stdoutBytes - offset, offset);
      if (count === 0) {
        const error = new Error("CLI stdout changed while reading its capture.");
        error.code = "ERR_CLI_STDOUT_CHANGED";
        throw error;
      }
      offset += count;
    }
    return {
      ...result,
      stdout: output.toString("utf8"),
      stdoutBytes,
      stderrBytes: Buffer.byteLength(result.stderr ?? "", "utf8"),
    };
  } finally {
    try {
      if (descriptor !== undefined) closeSync(descriptor);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
}
