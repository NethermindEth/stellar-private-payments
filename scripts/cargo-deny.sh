#!/bin/sh
# Runs cargo-deny with the license policy scoped to what we distribute.
#
# - Advisories, bans and sources: every crate in the workspace, including
#   tools, tests and dev-dependencies.
# - Licenses, distributed crates: deny.toml's permissive list. Tools and tests
#   that are never distributed are excluded, along with dev-dependencies.
# - Licenses, whole workspace: deny-tools.toml, which additionally allows
#   copyleft licenses that only bind on distribution.
#
# A new workspace crate is checked as distributed until it is added to the
# exclusions below.
set -e

cd "$(dirname "$0")/.."

cargo deny check advisories bans sources

cargo deny --exclude-dev \
    --exclude ceremony-cli \
    --exclude circuit-compiler \
    --exclude circuits \
    --exclude e2e-tests \
    --exclude gvkey-gen \
    --exclude sdk-tests \
    check licenses

cargo deny --config deny-tools.toml check licenses
