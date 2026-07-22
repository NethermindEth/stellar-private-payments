#!/bin/sh
# Full-tree JS license scan (sh+jq port of the former check-js-licenses.py).
#
# Scans every package in the npm lockfiles of all footprints against
# .github/js-license-policy.json (allowlist / denylist / exceptions) and writes
# js-license-scan-report.json to the repo root.
#
# Exit codes: 0 = compliant, 1 = violations found, 2 = policy/jq missing or a
# target lockfile is missing (a missing target would otherwise silently drop
# coverage while still reporting SUCCESS).
#
# Matching semantics (must stay in sync with the policy file's exceptions):
#   - package name = lockfile path with all "node_modules/" stripped; if the
#     result still contains "/" and does not start with "@", only the basename
#     is used (covers nested copies like chalk/node_modules/supports-color);
#   - an exception matches on either that derived name or the full lockfile path;
#   - an exception applies only to the lockfile named by its "target" field
#     (an exception without "target" applies repo-wide — avoid unless intended);
#   - a license is matched EXACTLY against the allowlist/denylist as one string
#     — compound SPDX expressions like "(MIT OR Apache-2.0)" are not evaluated,
#     so a dependency reporting one is treated as a single, distinct license
#     value. If a real dependency ever needs this, add the literal compound
#     string to the allowlist (already done for "(MIT AND BSD-3-Clause)",
#     used by app's sha.js) rather than teaching this script to parse boolean
#     SPDX expressions — no dependency has needed OR-expression evaluation so
#     far, so that logic isn't worth the added complexity until one does.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLICY_PATH="$REPO_ROOT/.github/js-license-policy.json"
REPORT_PATH="$REPO_ROOT/js-license-scan-report.json"

if ! command -v jq >/dev/null 2>&1; then
    echo "Error: jq is required but was not found in PATH" >&2
    exit 2
fi

if [ ! -f "$POLICY_PATH" ]; then
    echo "Error: Policy file not found at $POLICY_PATH" >&2
    exit 2
fi

TARGETS="app/package-lock.json
sdk/web/package-lock.json
circuits/src/circomlib/package-lock.json"

PARTS_DIR="$(mktemp -d)"
trap 'rm -rf "$PARTS_DIR"' EXIT

# Iterate in the main shell (no pipe subshell) so `set -e` would abort
# immediately on any unexpected failure inside the loop body. $TARGETS is
# newline-separated and its paths contain no spaces, so default-IFS word
# splitting here is safe.
for target in $TARGETS; do
    full_path="$REPO_ROOT/$target"
    if [ ! -f "$full_path" ]; then
        echo "ERROR: expected target lockfile $target is missing." >&2
        # Still recorded as a file, not a shell variable — no longer strictly
        # necessary now that this loop isn't a subshell, but keeping the same
        # aggregation mechanism as the part_*.json files below is simpler than
        # having two different bookkeeping styles.
        touch "$PARTS_DIR/missing_$(echo "$target" | tr '/.' '__')"
        continue
    fi

    jq -n --arg target "$target" \
          --slurpfile policy "$POLICY_PATH" \
          --slurpfile lock "$full_path" '
        def normlic:
            if type == "object" then (.type // "UNKNOWN")
            elif type == "array" then (map(tostring) | join(" OR "))
            else . end;
        ($policy[0]) as $p
        | ($p.allowlist // []) as $allow
        | ($p.denylist // []) as $deny
        | ([$p.exceptions[]?
             | select((has("target") | not) or .target == $target)]) as $exc_entries
        | (($lock[0].packages // {}) | to_entries
            | map(select(.key != "")
                | .key as $path
                | ($path | sub("node_modules/"; ""; "g")) as $stripped
                | (if ($stripped | contains("/")) and ($stripped | startswith("@") | not)
                   then ($stripped | split("/")[-1])
                   else $stripped end) as $name
                | ((.value.license // "UNKNOWN") | normlic) as $lic
                | {path: $path, name: $name, lic: $lic})) as $pkgs
        | {
            target: $target,
            license_counts: (reduce $pkgs[] as $x ({}; .[$x.lic] += 1)),
            violations: [
                $pkgs[]
                | . as $pkg
                # Find the (first) exception entry that names this package by
                # derived name or full lockfile path, if any.
                | ([$exc_entries[]
                    | select(
                        (.package? == $pkg.name) or (.package? == $pkg.path)
                        or ((.packages? // []) | index($pkg.name)) or ((.packages? // []) | index($pkg.path))
                      )] | .[0]) as $matched_exc
                | if $matched_exc == null then
                    if (($deny | index($pkg.lic)) != null) or $pkg.lic == "UNKNOWN" then
                        {package: $pkg.path, license: $pkg.lic,
                         reason: "Denylisted or UNKNOWN license without documented exception"}
                    elif ($allow | index($pkg.lic)) == null then
                        {package: $pkg.path, license: $pkg.lic,
                         reason: "License not on allowlist and no documented exception"}
                    else empty end
                  # An exception matched — but if the lockfile now reports a
                  # KNOWN license that no longer matches the license the
                  # matched exception documents, the exception has gone stale
                  # (e.g. a version bump changed the real license) and must
                  # not be trusted silently. UNKNOWN stays silent since that
                  # is the ordinary "license field missing" case the
                  # exception exists for.
                  elif ($pkg.lic != "UNKNOWN") and ($matched_exc.license != null) and ($matched_exc.license != $pkg.lic) then
                    {package: $pkg.path, license: $pkg.lic,
                     reason: "Exception documents license \($matched_exc.license) but the resolved license is now \($pkg.lic) — the exception may be stale; update the policy (see scripts/verify-exception-licenses.sh) or investigate why the license changed"}
                  else empty end
            ]
        }' > "$PARTS_DIR/part_$(echo "$target" | tr '/.' '__').json"
done

missing_files="$(find "$PARTS_DIR" -name 'missing_*' | sort)"
if [ -n "$missing_files" ]; then
    missing_count="$(echo "$missing_files" | wc -l | tr -d ' ')"
    echo "FAILED: $missing_count target lockfile(s) are missing (see ERROR lines above)." >&2
    echo "A missing target would otherwise silently drop from license coverage" >&2
    echo "while the scan still reports SUCCESS. Fix the missing path(s), or update" >&2
    echo "the TARGETS list in this script if a footprint was intentionally removed." >&2
    exit 2
fi

part_files="$(find "$PARTS_DIR" -name 'part_*.json' | sort)"
if [ -z "$part_files" ]; then
    printf '{"targets": {}}\n' > "$REPORT_PATH"
else
    # shellcheck disable=SC2086
    jq -s '{targets: (map({key: .target,
                           value: {license_counts: .license_counts,
                                   violations: .violations}}) | from_entries)}' \
        $part_files > "$REPORT_PATH"
fi

echo "Full-tree JS license scan report written to $REPORT_PATH"

total_violations="$(jq '[.targets[].violations | length] | add // 0' "$REPORT_PATH")"
if [ "$total_violations" -gt 0 ]; then
    echo "FAILED: Found $total_violations license policy violation(s):" >&2
    jq -r '.targets | to_entries[] | .key as $t | .value.violations[]
           | "  [\($t)] \(.package) (\(.license)): \(.reason)"' "$REPORT_PATH" >&2
    exit 1
fi

echo "SUCCESS: All JS dependencies comply with the license policy."
exit 0
