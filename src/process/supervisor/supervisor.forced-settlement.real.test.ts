// Real-process proof for the supervisor's terminal output fence: a leaked
// descendant keeps the killed root's inherited pipes open, so the child
// adapter's force-kill wait fallback settles the run while stdout/stderr are
// still delivering. Callers finalize their own output state from that terminal
// result — src/agents/cli-runner/execute-process.ts digests its SHA-256 stdout
// and stderr diagnostics right after `managedRun.wait()` — so any late chunk
// reaching a listener crashes the gateway with ERR_CRYPTO_HASH_FINALIZED.
import crypto from "node:crypto";
import { statSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { waitForDead, waitForPidFile } from "../../../test/helpers/process-wait.js";
import { useAutoCleanupTempDirTracker } from "../../../test/helpers/temp-dir.js";
import { killPidIfAlive } from "../../test-utils/process-tree.js";
import { createProcessSupervisor } from "./supervisor.js";

// SIGTERM plus the adapter's kill-wait fallback is a fixed ~9s production
// window; the gateway journal recorded the same 9.3-9.7s settle delay.
const FORCED_SETTLEMENT_TEST_TIMEOUT_MS = 60_000;
const LATE_OUTPUT_OBSERVATION_MS = 500;

const activePids = new Set<number>();
const tempDirs = useAutoCleanupTempDirTracker(afterEach);

afterEach(async () => {
  for (const pid of activePids) {
    killPidIfAlive(pid);
  }
  await Promise.all([...activePids].map((pid) => waitForDead(pid, 5_000).catch(() => {})));
  activePids.clear();
});

async function createLeakedPipeScope() {
  const cwd = tempDirs.make("openclaw-forced-settlement-");
  const leakPath = path.join(cwd, "leak.cjs");
  const leakPidPath = path.join(cwd, "leak.pid");
  const leakTickPath = path.join(cwd, "leak.ticks");
  const rootPath = path.join(cwd, "root.cjs");
  await writeFile(
    leakPath,
    `
      const { appendFileSync, writeFileSync } = require("node:fs");
      let tick = 0;
      setInterval(() => {
        tick += 1;
        process.stdout.write("leaked-stdout-" + tick + "\\n");
        process.stderr.write("leaked-stderr-" + tick + "\\n");
        // Ticks land on disk too, so the test can prove the inherited pipe was
        // still carrying data during the window it asserts nothing arrived on.
        appendFileSync(process.argv[3], ".");
      }, 50);
      writeFileSync(process.argv[2], String(process.pid));
    `,
    "utf8",
  );
  await writeFile(
    rootPath,
    `
      const { spawn } = require("node:child_process");
      process.stdout.write("live-stdout\\n");
      process.stderr.write("live-stderr\\n");
      // Inherit this root's stdout/stderr so the pipes outlive it, and detach so
      // the supervisor's process-group kill cannot reach the descendant. This is
      // the shipped CLI shape that leaves stdio open past forced settlement.
      const leak = spawn(
        process.execPath,
        [${JSON.stringify(leakPath)}, ${JSON.stringify(leakPidPath)}, ${JSON.stringify(leakTickPath)}],
        { stdio: ["ignore", "inherit", "inherit"], detached: true },
      );
      leak.unref();
      setInterval(() => {}, 1_000);
    `,
    "utf8",
  );
  return { cwd, rootPath, leakPidPath, leakTickPath };
}

function readTickCount(tickPath: string): number {
  try {
    return statSync(tickPath).size;
  } catch {
    return 0;
  }
}

describe.skipIf(process.platform === "win32")("supervisor forced settlement output fence", () => {
  it(
    "delivers nothing after a force-kill fallback settles a run with open inherited pipes",
    async () => {
      const { cwd, rootPath, leakPidPath, leakTickPath } = await createLeakedPipeScope();
      const stdoutHash = crypto.createHash("sha256");
      const stderrHash = crypto.createHash("sha256");
      const delivered: string[] = [];
      // Production crashes uncaught inside the stream "data" handler; recording
      // the failure keeps the fence regression assertable instead of killing
      // the worker, and an empty list is the shipped contract.
      const hashFailures: string[] = [];
      const consume = (hash: crypto.Hash, label: string) => (chunk: string) => {
        delivered.push(`${label}:${chunk.trim()}`);
        try {
          hash.update(chunk);
        } catch (error) {
          hashFailures.push(`${label}:${(error as NodeJS.ErrnoException).code ?? String(error)}`);
        }
      };

      const supervisor = createProcessSupervisor();
      const run = await supervisor.spawn({
        mode: "child",
        argv: [process.execPath, rootPath],
        sessionId: "forced-settlement-real",
        backendId: "forced-settlement-real",
        cwd,
        captureOutput: false,
        onStdout: consume(stdoutHash, "stdout"),
        onStderr: consume(stderrHash, "stderr"),
        onStdoutRaw: (raw) => delivered.push(`stdout-raw:${raw.toString("utf8").trim()}`),
        onStderrRaw: (raw) => delivered.push(`stderr-raw:${raw.toString("utf8").trim()}`),
      });

      const leakedPid = await waitForPidFile(leakPidPath, 15_000);
      activePids.add(leakedPid);
      run.cancel("manual-cancel");

      const exit = await run.wait();
      // Exactly what the CLI runner does with the terminal result it just read.
      const digests = [stdoutHash.digest("hex"), stderrHash.digest("hex")];
      const settledDelivered = [...delivered];
      const settledOutputAtMs = supervisor.getRecord(run.runId)?.lastOutputAtMs;
      const settledTicks = readTickCount(leakTickPath);
      await new Promise<void>((resolve) => {
        setTimeout(resolve, LATE_OUTPUT_OBSERVATION_MS);
      });

      expect(exit.reason).toBe("manual-cancel");
      expect(digests.every((digest) => digest.length === 64)).toBe(true);
      expect(settledDelivered).toContain("stdout:live-stdout");
      expect(settledDelivered).toContain("stderr-raw:live-stderr");
      // The descendant kept writing into the still-open pipe across the window,
      // so an unfenced listener would have run against the finalized hashes.
      expect(readTickCount(leakTickPath)).toBeGreaterThan(settledTicks);
      expect(hashFailures).toEqual([]);
      expect(delivered).toEqual(settledDelivered);
      expect(supervisor.getRecord(run.runId)?.lastOutputAtMs).toBe(settledOutputAtMs);
    },
    FORCED_SETTLEMENT_TEST_TIMEOUT_MS,
  );
});
