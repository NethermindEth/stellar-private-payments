#!/bin/sh
# Full-tree JS license scan (sh+jq port of the former check-js-licenses.py).
#
# Scans every package in the npm lockfiles of all footprints against
# .github/js-license-policy.json (allowlist / denylist / exceptions) and writes
# js-license-scan-report.json to the repo root.
#
# Exit codes: 0 = compliant, 1 = violations found, 2 = policy/jq missing.
#
# Matching semantics (must stay in sync with the policy file's exceptions):
#   - package name = lockfile path with all "node_modules/" stripped; if the
#     result still contains "/" and does not start with "@", only the basename
#     is used (covers nested copies like chalk/node_modules/supports-color);
#   - an exception matches on either that derived name or the full lockfile path;
#   - an exception applies only to the lockfile named by its "target" field
#     (an exception without "target" applies repo-wide — avoid unless intended).
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

echo "$TARGETS" | while IFS= read -r target; do
    full_path="$REPO_ROOT/$target"
    if [ ! -f "$full_path" ]; then
        echo "Warning: Target lockfile $target does not exist, skipping."
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
             | select((has("target") | not) or .target == $target)
             | if has("packages") then .packages[] else .package end]) as $exc
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
                | select(($exc | index($pkg.name)) == null and ($exc | index($pkg.path)) == null)
                | if (($deny | index($pkg.lic)) != null) or $pkg.lic == "UNKNOWN" then
                    {package: $pkg.path, license: $pkg.lic,
                     reason: "Denylisted or UNKNOWN license without documented exception"}
                  elif ($allow | index($pkg.lic)) == null then
                    {package: $pkg.path, license: $pkg.lic,
                     reason: "License not on allowlist and no documented exception"}
                  else empty end
            ]
        }' > "$PARTS_DIR/part_$(echo "$target" | tr '/.' '__').json"
done

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
