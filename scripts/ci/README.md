# CI experiments

All benchmark jobs use fresh ubuntu-24.04 runners without cache restore/save.
Each configuration runs three times. Compare medians on the same commit and runner
image; reject runs with errors, memory exhaustion, disk exhaustion, or different
test inventories. GNU time reports command max RSS, not aggregate runner memory.
Disk usage is sampled once per second across the runner filesystem.

Adoption gate: at least 10% lower median total job time for build configuration
changes, or 10% lower median affected-suite time for fixture changes, with every
existing assertion and build/link check preserved. Download measurement artifacts
and include comparisons in the PR. After merge, confirm main cache saving and PR
restores before reporting warm performance. Do not compare a warm main baseline
against a cold PR candidate.

The workflows are manual: workflow_dispatch when registered on the default branch,
or the matching PR label to run a new workflow before merge. Labels do not grant
write permissions to workflow code; all benchmark jobs use contents: read.

## Test setup

Test setup benchmarks or the benchmark-test-setup PR label runs 21 jobs: SDK
baseline/shared with 1/4 threads and three repeats, plus browser fresh/shared/
reverse with three repeats. The baseline fixture comes from batch 1 (b906d4d9).
Refresh that explicit baseline when rebasing changes the source under comparison.

SDK compilation is measured separately; suite.json is the acceptance metric.
Compare inventory.txt across variants before comparing suite times. Fixture timers
are opt-in via SPP_TEST_TIMINGS=1 and require --nocapture to display passing tests.
Dedicated constructor/key-ownership tests still build their own engines.

Browser suite.json includes test compilation and execution, so it includes savings
from avoiding repeated deployment-file invalidation. The default suite starts one
localnet/deployment, with a separate browser and OPFS per case. --fresh-localnet
retains the old lifecycle for baselines; --reverse checks shared-chain isolation.
Pass explicit case names to run cases in isolation. The runner owns cleanup and
propagates failing commands. Confirm one deployment and no intervening deployment
rewrites from full job logs. Docker integration must pass before adoption.
