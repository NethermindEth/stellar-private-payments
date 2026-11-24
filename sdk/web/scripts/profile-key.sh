#!/usr/bin/env sh
# Print the build marker shared by build.sh, Trunk.toml and the Makefile.
#
# WASM_PROFILE selects the main module and storage worker (release or
# release-with-logs). PROVER_PROFILE selects the prover worker and defaults to
# the matching hot profile, so the compute-bound worker is optimised without
# growing the other wasm modules. SPP_WEB_THREADS=0 builds without the threaded
# prover worker.
set -eu

profile="${WASM_PROFILE:-release}"
case "$profile" in
  release-with-logs) default_prover="prover-hot-with-logs" ;;
  *) default_prover="prover-hot" ;;
esac
prover="${PROVER_PROFILE:-$default_prover}"
threads=1
if [ "${SPP_WEB_THREADS:-1}" = "0" ]; then
  threads=0
fi

printf '%s:%s:%s:threads=%s%s\n' \
  "$profile" "$prover" "${SPP_NETWORK:-testnet}" "$threads" \
  "${SPP_WEB_CARGO_FEATURES:+:$SPP_WEB_CARGO_FEATURES}"
