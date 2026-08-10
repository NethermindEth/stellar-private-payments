//! Repository layout discovery and atomic file placement.

use anyhow::{Context, Result, anyhow, bail};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

/// Walk up from `start` until a `Cargo.toml` declaring `[workspace]` is found.
pub fn workspace_root(start: &Path) -> Result<PathBuf> {
    for dir in start.ancestors() {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file()
            && fs::read_to_string(&manifest)
                .with_context(|| format!("read {}", manifest.display()))?
                .contains("[workspace]")
        {
            return Ok(dir.to_path_buf());
        }
    }
    bail!(
        "no workspace Cargo.toml above {} - pass --circuits-dir explicitly",
        start.display()
    )
}

/// Default `circuits/` location, resolved from the current directory.
pub fn default_circuits_dir() -> Result<PathBuf> {
    let cwd = env::current_dir().context("read current directory")?;
    Ok(workspace_root(&cwd)?.join("circuits"))
}

/// The circom compiler tag this binary links against.
///
/// Read from our own manifest at compile time so it cannot drift from the
/// dependency that is actually built, then checked against
/// `circuits/circom.lock`. Those two are the R1CS toolchain and the graph
/// toolchain respectively: if they disagree, `.r1cs` and `.graph.bin` come
/// from different compilers.
pub fn circom_version(circuits_dir: &Path) -> Result<String> {
    let tag = circom_tag()?;

    let lock_path = circuits_dir.join("circom.lock");
    let lock = fs::read_to_string(&lock_path)
        .with_context(|| format!("read {}", lock_path.display()))?
        .trim()
        .trim_start_matches('v')
        .to_owned();

    if tag != lock {
        bail!(
            "circom version mismatch: circuit-builder links tag v{tag}, but {} pins {lock}. \
             The R1CS and the witness graphs would come from different compilers.",
            lock_path.display()
        );
    }

    Ok(tag)
}

/// The circom tag from this crate's own `Cargo.toml`, without the `v`.
fn circom_tag() -> Result<String> {
    const MANIFEST: &str = include_str!("../Cargo.toml");

    for line in MANIFEST.lines() {
        let line = line.trim();
        if !line.starts_with("compiler ") && !line.starts_with("compiler=") {
            continue;
        }
        let tag = line
            .split_once("tag = \"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(tag, _)| tag);
        if let Some(tag) = tag {
            return Ok(tag.trim_start_matches('v').to_owned());
        }
    }
    Err(anyhow!(
        "no `compiler = {{ ..., tag = \"...\" }}` entry in circuit-builder/Cargo.toml"
    ))
}

/// A staging path beside `dst`, so the later `rename` stays on one filesystem.
///
/// The suffix is appended rather than replacing the extension: `foo.r1cs` and
/// `foo.wasm` would otherwise both stage through `foo.tmp-<pid>` and collide
/// the moment publishing is done concurrently.
fn temp_sibling(dst: &Path) -> PathBuf {
    let mut name = dst.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp-{}", std::process::id()));
    dst.with_file_name(name)
}

/// Replace `dst` with the staged file, removing the staging file on failure.
///
/// `rename` swaps the destination atomically, so a reader sees either the old
/// file or the new one. Removing `dst` first would instead open a window where
/// it sees no file at all.
fn commit(tmp: &Path, dst: &Path) -> Result<()> {
    if let Err(e) = fs::rename(tmp, dst) {
        let _ = fs::remove_file(tmp);
        return Err(e).with_context(|| format!("rename {} to {}", tmp.display(), dst.display()));
    }
    Ok(())
}

fn ensure_parent(dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    Ok(())
}

/// Copy `src` over `dst` through a temporary file in the destination directory.
pub fn copy_atomic(src: &Path, dst: &Path) -> Result<()> {
    ensure_parent(dst)?;

    let tmp = temp_sibling(dst);
    fs::copy(src, &tmp).with_context(|| format!("copy {} to {}", src.display(), tmp.display()))?;
    commit(&tmp, dst)
}

/// Write `contents` to `dst` through a temporary file in the same directory.
pub fn write_atomic(dst: &Path, contents: &[u8]) -> Result<()> {
    ensure_parent(dst)?;

    let tmp = temp_sibling(dst);
    fs::write(&tmp, contents).with_context(|| format!("write {}", tmp.display()))?;
    commit(&tmp, dst)
}
