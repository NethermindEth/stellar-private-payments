//! Circuit entry-point discovery and include-graph freshness checks.

use anyhow::{Result, bail};
use regex::Regex;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

/// Recursively find every `.circom` file in a directory.
///
/// Which of them are circuit entry points is decided by the parser, not here.
///
/// `skip_test_dirs` skips directories named `test`. Vendored `circomlib` is
/// always skipped: it carries its own `component main` entry points (for
/// example `sha256/main.circom`) that would produce colliding artifacts.
pub fn find_circom_files(dir: &Path, skip_test_dirs: bool) -> Vec<PathBuf> {
    let mut circom_files = Vec::new();

    let Ok(entries) = fs::read_dir(dir) else {
        eprintln!("warning: failed to read directory {}", dir.display());
        return circom_files;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        // `file_type` comes from the directory entry, so it costs no extra stat.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };

        if file_type.is_file() {
            if path.extension().is_some_and(|ext| ext == "circom") {
                circom_files.push(path);
            }
        } else if file_type.is_dir() {
            if skip_test_dirs && path.file_name().is_some_and(|name| name == "test") {
                continue;
            }
            if path.file_name().is_some_and(|name| name == "circomlib") {
                continue;
            }
            circom_files.extend(find_circom_files(&path, skip_test_dirs));
        }
    }

    circom_files
}

/// Recursively extract all `.circom` dependencies by parsing include
/// statements.
pub fn extract_dependencies(main_file: &Path, base_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut dependencies = Vec::new();
    let mut visited = HashSet::new();
    let mut to_process = vec![main_file.to_path_buf()];

    // Search directories for non-relative includes
    let search_dirs = vec![
        base_dir.to_path_buf(),
        base_dir.join("src"),
        base_dir.join("node_modules"),
    ];

    // `(?m)` is load-bearing: without it `^` anchors to the start of the whole
    // file, so only an include on the very first line is ever found.
    let include_pattern = Regex::new(r#"(?m)^\s*include\s+["']([^"']+)["']"#)?;

    while let Some(current_file) = to_process.pop() {
        if !visited.insert(current_file.clone()) {
            continue;
        }

        let content = fs::read_to_string(&current_file)?;

        for cap in include_pattern.captures_iter(&content) {
            let include_path = cap
                .get(1)
                .expect("No string matching the regex was found")
                .as_str();

            let path = resolve_include_path(
                include_path,
                current_file.parent().expect("No parent directory found"),
                &search_dirs,
            )?;

            dependencies.push(path.clone());
            to_process.push(path);
        }
    }

    Ok(dependencies)
}

/// Resolve an include path to an absolute file path.
///
/// Mirrors circom: a bare include resolves against the including file's own
/// directory before the library search path. Missing that rule silently drops
/// dependencies — `poseidon2_compress.circom` includes `poseidon2_perm.circom`
/// as a sibling, so the permutation would never enter the source closure and an
/// edit to it would not rebuild the circuits that use it.
///
/// An unresolvable include is therefore fatal, not a warning: it is a hole in
/// the closure, and a hole means edits to that file rebuild nothing.
fn resolve_include_path(
    include_path: &str,
    current_dir: &Path,
    search_dirs: &[PathBuf],
) -> Result<PathBuf> {
    let relative = include_path.starts_with("./") || include_path.starts_with("../");

    let candidates = std::iter::once(current_dir.join(include_path)).chain(
        search_dirs
            .iter()
            .filter(|_| !relative)
            .map(|dir| dir.join(include_path)),
    );

    for path in candidates {
        if path.exists() {
            return Ok(path.canonicalize()?);
        }
    }

    bail!(
        "could not resolve include {include_path:?} from {}",
        current_dir.display()
    )
}
