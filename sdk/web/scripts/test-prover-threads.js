#!/usr/bin/env node
/**
 * Prove in a browser with the built SDK: on the threaded prover worker when the
 * page is cross-origin isolated, on the serial one when it is not.
 */
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { parseArgs, withProverHarness } from "./prover-browser.js";

const args = parseArgs(process.argv.slice(2));
const checks = [];

const result = await withProverHarness(args, async ({ page }) => {
  const isolated = await page("isolated", { isolated: true });
  assert.equal(isolated.crossOriginIsolated, true, "page served with COOP/COEP is not cross-origin isolated");
  // Needs a machine with more than one logical core, as the CI runners have.
  assert(isolated.cores > 1, `the browser reports ${isolated.cores} logical core(s)`);
  const threaded = await isolated.selection();
  assert.deepEqual(threaded, { mode: "threaded", threads: isolated.cores });
  checks.push(`isolated page selects the threaded prover worker with ${threaded.threads} threads`);
  // The worker fails the request unless the proof verifies.
  const threadedProof = await isolated.prove({ worker: "prover-worker-threads.js", threads: threaded.threads });
  assert.deepEqual(threadedProof.warnings, []);
  assert.equal(threadedProof.poolThreads, threaded.threads, "the threaded worker did not start its pool");
  checks.push(`threaded worker proves and verifies on ${threadedProof.poolThreads} threads`);
  await isolated.close();

  const plain = await page("not-isolated", { isolated: false });
  assert.equal(plain.crossOriginIsolated, false);
  assert.deepEqual(await plain.selection(), { mode: "serial", threads: 1 });
  checks.push("page without COOP/COEP falls back to the serial prover worker");
  const serialProof = await plain.prove({ worker: "prover-worker.js" });
  assert.deepEqual(serialProof.warnings, []);
  assert.equal(serialProof.poolThreads, null);
  checks.push("serial worker proves and verifies");
  await plain.close();

  return {
    browser: args.browser, version: isolated.browser.version, cores: isolated.cores,
    proofMs: { threaded: threadedProof.times[0], serial: serialProof.times[0] },
  };
});

const report = { ...result, checks, passed: true };
await writeFile(join(resolve(args.artifacts), "result.json"), `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
