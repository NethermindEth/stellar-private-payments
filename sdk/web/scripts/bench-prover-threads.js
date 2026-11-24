#!/usr/bin/env node
/**
 * Time `policy_tx_2_2` proofs in a browser on the serial prover worker and on
 * the threaded one at several pool sizes, on a cross-origin isolated page. The
 * first proof of each worker also loads the proving key and is reported apart.
 *
 *   node sdk/web/scripts/bench-prover-threads.js --artifacts target/prover-bench [--runs 5] [--threads 2,4,8]
 */
import { parseArgs, withProverHarness } from "./prover-browser.js";

const args = parseArgs(process.argv.slice(2), { runs: "5", threads: "" });
const runs = Number(args.runs);
if (!Number.isInteger(runs) || runs < 1) throw Error("--runs must be a positive integer");
const median = (values) => { const sorted = [...values].sort((a, b) => a - b); return sorted[Math.floor(sorted.length / 2)]; };

await withProverHarness(args, async ({ page }) => {
  const bench = await page("bench", { isolated: true });
  if (!bench.crossOriginIsolated) throw Error("the page is not cross-origin isolated");
  // Default: powers of two below the core count, and the core count.
  const threads = args.threads
    ? args.threads.split(",").map(Number)
    : [...[2, 4, 8, 16, 32, 64].filter(count => count < bench.cores), bench.cores];
  console.log(`${bench.browser.name} ${bench.browser.version}, ${bench.cores} logical cores, ${runs} timed runs after one warm-up proof`);
  console.log("worker    threads  first ms  median ms  min ms");
  const row = (worker, count, times) => console.log(`${worker.padEnd(8)}  ${String(count).padStart(7)}  ${String(times[0]).padStart(8)}  ${String(median(times.slice(1))).padStart(9)}  ${String(Math.min(...times.slice(1))).padStart(6)}`);
  const serial = await bench.prove({ worker: "prover-worker.js", runs: runs + 1 });
  row("serial", 1, serial.times);
  for (const count of threads) {
    const threaded = await bench.prove({ worker: "prover-worker-threads.js", threads: count, runs: runs + 1 });
    if (threaded.poolThreads !== threaded.configured) throw Error(`asked for ${count} threads, the pool started with ${threaded.poolThreads}`);
    row("threaded", threaded.poolThreads, threaded.times);
  }
  await bench.close();
});
