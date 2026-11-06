#!/usr/bin/env bash
# Run on a fresh hosted runner without cache actions. One configuration per job.
set -euo pipefail
measure() { python3 scripts/ci/measure.py "$@"; }
case "${1:?configuration required}" in
  ignored-*)
    case "$1" in
      ignored-baseline) test_profile=release; compiler_profile=release ;;
      ignored-tests) test_profile=ci-native; compiler_profile=release ;;
      ignored-both) test_profile=ci-native; compiler_profile=ci-native ;;
      *) exit 2 ;;
    esac
    measure circuits make circuits TESTS=1 CIRCUIT_COMPILER_PROFILE="$compiler_profile"
    measure build cargo test --locked --profile "$test_profile" --workspace --no-run
    measure tests cargo test --locked --profile "$test_profile" --workspace -- --ignored
    ;;
  msrv-*)
    case "$1" in
      msrv-opt3-jobs2) export MSRV_DEPENDENCY_OPT_LEVEL=3 CARGO_BUILD_JOBS=2 ;;
      msrv-opt3-jobs4) export MSRV_DEPENDENCY_OPT_LEVEL=3 CARGO_BUILD_JOBS=4 ;;
      msrv-opt0-jobs2) export MSRV_DEPENDENCY_OPT_LEVEL=0 CARGO_BUILD_JOBS=2 ;;
      msrv-opt0-jobs4) export MSRV_DEPENDENCY_OPT_LEVEL=0 CARGO_BUILD_JOBS=4 ;;
      *) exit 2 ;;
    esac
    export CARGO_PROFILE_DEV_DEBUG=0
    measure native bash scripts/check-msrv.sh native
    ;;
  workspace-*)
    case "$1" in
      workspace-baseline) ;;
      workspace-debug0) export CARGO_PROFILE_DEV_DEBUG=0 ;;
      *) exit 2 ;;
    esac
    measure circuits make circuits
    measure build cargo test --locked --workspace --no-run
    measure tests cargo test --locked --workspace
    ;;
  *) exit 2 ;;
esac
