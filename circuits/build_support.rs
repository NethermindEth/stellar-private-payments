use anyhow::Result;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

pub(crate) fn circom_include_path(line: &str) -> Option<&str> {
    let before_comment = line.split_once("//").map_or(line, |(prefix, _)| prefix);
    let trimmed = before_comment.trim_start();
    let rest = trimmed.strip_prefix("include")?;
    if !rest.chars().next().is_some_and(char::is_whitespace) {
        return None;
    }

    let rest = rest.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }

    let quoted = &rest[quote.len_utf8()..];
    let end = quoted.find(quote)?;
    Some(&quoted[..end])
}

/// Recursively extract all .circom file dependencies by parsing include
/// statements line-by-line.
///
/// # Arguments
///
/// * `main_file` - Circom file from where include dependencies will be parsed.
/// * `base_dir` - Base directory to look for other Circom dependencies
pub(crate) fn extract_circom_dependencies(
    main_file: &Path,
    base_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let mut dependencies = Vec::new();
    let mut visited = HashSet::new();
    let mut to_process = vec![main_file.to_path_buf()];

    // Precompute search directories for non-relative includes
    let search_dirs = vec![
        base_dir.to_path_buf(),
        base_dir.join("src"),
        base_dir.join("node_modules"),
    ];

    while let Some(current_file) = to_process.pop() {
        if !visited.insert(current_file.clone()) {
            continue;
        }

        let content = fs::read_to_string(&current_file)?;

        for include_path in content.lines().filter_map(circom_include_path) {
            let resolved_path = resolve_include_path(
                include_path,
                current_file.parent().expect("No parent directory found"),
                &search_dirs,
            )?;

            if let Some(path) = resolved_path {
                dependencies.push(path.clone());
                to_process.push(path);
            }
        }
    }

    Ok(dependencies)
}

/// Resolve an include path to an absolute file path
///
/// Handles both relative paths (starting with `./` or `../`) and library paths
/// by searching in the provided search directories.
///
/// # Arguments
///
/// * `include_path` - The include path string from the Circom file
/// * `current_dir` - Directory of the file containing the include statement
/// * `search_dirs` - List of directories to search for non-relative includes
///
/// # Returns
///
/// Returns `Ok(Some(PathBuf))` if the path is found and resolved, `Ok(None)` if
/// not found, or an error if file system operations fail.
fn resolve_include_path(
    include_path: &str,
    current_dir: &Path,
    search_dirs: &[PathBuf],
) -> Result<Option<PathBuf>> {
    // Relative paths
    if include_path.starts_with("./") || include_path.starts_with("../") {
        let path = current_dir.join(include_path);
        if path.exists() {
            return Ok(Some(path.canonicalize()?));
        }
    } else {
        let path = current_dir.join(include_path);
        if path.exists() {
            return Ok(Some(path.canonicalize()?));
        }

        // Search in library directories
        for dir in search_dirs {
            let path = dir.join(include_path);
            if path.exists() {
                return Ok(Some(path.canonicalize()?));
            }
        }
    }

    // Not found
    eprintln!("Warning: Could not resolve include: {include_path}");
    Ok(None)
}
