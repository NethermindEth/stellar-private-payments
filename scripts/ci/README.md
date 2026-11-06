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

## Native profiles

Use Native CI benchmarks with experiment ignored, msrv, or workspace; adding the
benchmark-native PR label runs all configurations (27 jobs). No production default
changes until measurements pass the adoption gate.

Ignored tests compare release/release, ci-native/release, and ci-native/ci-native
(test/compiler). The last two comparisons attribute the compiler-profile change.
MSRV compares dependency opt-level 0/3 against build jobs 2/4; only the three
root workspace builds receive the optimization override. All other commands remain.
Workspace compares inherited debug info against CARGO_PROFILE_DEV_DEBUG=0.

Optional ignored-workflow inputs select test/compiler profiles independently;
both default to release. CIRCUIT_COMPILER_PROFILE defaults to release in make.

Once measured, promote only passing settings in a separate commit: update ignored
workflow profile defaults, set MSRV native-only opt/jobs values, and/or set the
workspace debug override. The experiment implementation alone establishes no saving.
