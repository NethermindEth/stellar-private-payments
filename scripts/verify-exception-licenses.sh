#!/bin/sh
# Verify every js-license-policy.json exception's declared "license" against
# the ACTUAL npm registry metadata at the package's LOCKED version (not
# `latest` — several popular packages, e.g. glob/minimatch/rimraf, relicensed
# in newer majors while older locked versions remain on their original
# license; comparing against `latest` produces false-positive mismatches).
#
# Read-only: does not modify the repo.
#
# Manual maintainer tool — NOT run in CI (hits the npm registry per package,
# so it's slow and not deterministic enough to gate a build).
# Run this whenever adding or editing an exception in .github/js-license-policy.json.
#
# Usage: sh scripts/verify-exception-licenses.sh [path-to-repo-root]
#        (defaults to the current directory if omitted, e.g. run from repo root)
#
# Exit codes: 0 = all exceptions verified,
#             1 = real mismatch or registry error found,
#             2 = policy/jq/curl missing.
#
# Requires: jq, curl
set -eu

REPO_ROOT="${1:-$(pwd)}"
POLICY="$REPO_ROOT/.github/js-license-policy.json"

if [ ! -f "$POLICY" ]; then
    echo "Error: policy file not found at $POLICY" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required" >&2
    exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required" >&2
    exit 2
fi

# Derive the REAL npm package name from a lockfile key. For a nested copy
# under a scope directory (node_modules/foo/node_modules/@scope/bar), the true
# published package is "@scope/bar"; for a bare nested copy
# (node_modules/foo/node_modules/bar) it is "bar".
derive_name() {
    jq -Rr '
        sub("node_modules/"; ""; "g") as $s
        | ($s | split("/")) as $segs
        | if ($segs | length) >= 2 and ($segs[-2] | startswith("@"))
            then ($segs[-2:] | join("/"))
          elif ($segs | length) >= 2
            then $segs[-1]
          else $s end
    ' <<EOF
$1
EOF
}

urlencode_slash() { printf '%s' "$1" | sed 's#/#%2F#g'; }

ok=0; mismatch=0; ambiguous=0; skipped=0; errors=0

echo "=== Verifying js-license-policy.json exceptions against npm registry (locked versions) ==="
echo

exception_count="$(jq '.exceptions | length' "$POLICY")"
i=0
while [ "$i" -lt "$exception_count" ]; do
    exc="$(jq ".exceptions[$i]" "$POLICY")"
    target="$(echo "$exc" | jq -r '.target // empty')"
    declared_license="$(echo "$exc" | jq -r '.license // empty')"

    if [ -z "$target" ]; then
        echo "[SKIP] entry $i has no target lockfile — cannot verify"
        skipped=$((skipped + 1))
        i=$((i + 1))
        continue
    fi

    lockfile="$REPO_ROOT/$target"
    if [ ! -f "$lockfile" ]; then
        echo "[ERROR] lockfile not found for target $target ($lockfile)"
        errors=$((errors + 1))
        i=$((i + 1))
        continue
    fi

    # Collect this exception's package path(s) into a temp file (NOT piped
    # into `while read`, which would run the loop in a subshell and silently
    # discard updates to ok/mismatch/etc. counters).
    paths_file="$(mktemp)"
    echo "$exc" | jq -r 'if has("packages") then .packages[] else .package end' > "$paths_file"

    while IFS= read -r pkg_path; do
        [ -z "$pkg_path" ] && continue

        # Special case: local workspace package (file: reference), not a
        # real published npm package — verify its OWN package.json instead of
        # the registry.
        if [ "$pkg_path" = "stellar-private-payments" ]; then
            actual="$(jq -r '.license // "MISSING"' "$REPO_ROOT/sdk/web/package.json" 2>/dev/null || echo MISSING)"
            if [ "$actual" = "$declared_license" ] || [ "$declared_license" = "UNKNOWN" ]; then
                echo "  [OK]  $pkg_path (workspace package.json) -> $actual"
                ok=$((ok + 1))
            else
                echo "  [MISMATCH] $pkg_path (workspace package.json) declared=$declared_license actual=$actual"
                mismatch=$((mismatch + 1))
            fi
            continue
        fi

        # Regular case: a dependency entry. Accept either a bare name (ISC/MIT/
        # etc. groups) or a full node_modules/... path (GPL-3.0 group).
        key="$pkg_path"
        case "$key" in
            node_modules/*) : ;;
            *) key="node_modules/$pkg_path" ;;
        esac
        version="$(jq -r --arg k "$key" '.packages[$k].version // empty' "$lockfile")"
        if [ -z "$version" ]; then
            echo "  [ERROR] $pkg_path: no matching lockfile entry ($key) — cannot verify"
            errors=$((errors + 1))
            continue
        fi

        name="$(derive_name "$key")"
        enc_name="$(urlencode_slash "$name")"

        resp="$(curl -s "https://registry.npmjs.org/$enc_name/$version" 2>/dev/null || echo "")"
        if [ -z "$resp" ]; then
            echo "  [ERROR] $name@$version: registry request failed"
            errors=$((errors + 1))
            continue
        fi

        # Prefer modern `.license` string; fall back to legacy
        # `.licenses[0].type` array format (real example: prelude-ls@1.1.2).
        actual="$(echo "$resp" | jq -r '.license // (.licenses[0].type // "MISSING")' 2>/dev/null || echo MISSING)"

        if [ "$actual" = "$declared_license" ]; then
            echo "  [OK]  $name@$version -> $actual"
            ok=$((ok + 1))
        elif [ "$actual" = "BSD" ] || [ "$actual" = "MISSING" ]; then
            # Legacy/generic registry tags that can't be auto-verified against
            # a specific SPDX identifier (e.g. bare "BSD" doesn't say 2- vs
            # 3-clause) — flag for manual confirmation, don't hard-fail.
            echo "  [AMBIGUOUS] $name@$version declared=$declared_license registry=$actual (generic/legacy tag — check the package's actual bundled license text by hand)"
            ambiguous=$((ambiguous + 1))
        else
            echo "  [MISMATCH] $name@$version declared=$declared_license actual=$actual"
            mismatch=$((mismatch + 1))
        fi
    done < "$paths_file"
    rm -f "$paths_file"

    i=$((i + 1))
done

echo
echo "=== Summary: $ok ok / $mismatch mismatch / $ambiguous ambiguous / $skipped skipped / $errors error ==="
[ "$mismatch" -gt 0 ] && echo "Real mismatches found — review the [MISMATCH] lines above before trusting the policy's justification text."
[ "$errors" -gt 0 ] && echo "Errors found — some exceptions could not be verified against the registry."
[ "$ambiguous" -gt 0 ] && echo "Ambiguous entries found — the registry only has a generic/legacy license tag; confirm manually against the package's bundled license file."

if [ "$mismatch" -gt 0 ] || [ "$errors" -gt 0 ]; then
    exit 1
fi
exit 0
