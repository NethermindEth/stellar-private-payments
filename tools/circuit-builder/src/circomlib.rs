//! Vendoring and patching of the pinned `circomlib` checkout.

use anyhow::{Context, Result, anyhow, bail};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Clone `circomlib` into `<circuits_dir>/src/circomlib` and check out the
/// revision pinned by `<circuits_dir>/circomlib.lock`.
pub fn vendor(circuits_dir: &Path) -> Result<()> {
    let circomlib_path = circuits_dir.join("src/circomlib");
    let lock_path = circuits_dir.join("circomlib.lock");
    let locked_rev =
        fs::read_to_string(&lock_path).with_context(|| format!("read {}", lock_path.display()))?;
    let locked_rev = locked_rev.trim();
    if locked_rev.len() != 40 || !locked_rev.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid circomlib.lock value (expected 40-char hex SHA): {locked_rev:?}");
    }

    if circomlib_path.exists() && !circomlib_path.join(".git").exists() {
        // Remove invalid directory and re-initialize.
        fs::remove_dir_all(&circomlib_path)?;
    }

    if !circomlib_path.join(".git").exists() {
        fs::create_dir_all(&circomlib_path)?;
        git(&circomlib_path, &["init"], "init circomlib repository")?;
        git(
            &circomlib_path,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/iden3/circomlib.git",
            ],
            "add circomlib remote",
        )?;
    }

    // If already checked out at the locked rev, do nothing.
    if let Ok(out) = Command::new("git")
        .arg("-C")
        .arg(&circomlib_path)
        .args(["rev-parse", "HEAD"])
        .output()
        && out.status.success()
        && String::from_utf8_lossy(&out.stdout).trim() == locked_rev
    {
        eprintln!("circomlib already at locked revision {locked_rev}");
        return Ok(());
    }

    eprintln!("Fetching circomlib revision {locked_rev}...");
    git(
        &circomlib_path,
        &["fetch", "--depth", "1", "origin", locked_rev],
        "fetch circomlib",
    )?;
    git(
        &circomlib_path,
        &["checkout", "--detach", "FETCH_HEAD"],
        "check out circomlib",
    )?;
    Ok(())
}

fn git(repo: &Path, args: &[&str], what: &str) -> Result<()> {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .with_context(|| format!("run git to {what}"))?;
    if !status.success() {
        bail!("failed to {what} (git {})", args.join(" "));
    }
    Ok(())
}

/// Scope guard that ensures `circomlib` BBF patches are transient.
///
/// Resets `comparators.circom` and `bitify.circom` to pristine on creation and
/// again on drop, so `circuits/src/circomlib` git status stays clean either
/// way.
pub struct RestoreGuard {
    circomlib_path: PathBuf,
}

impl RestoreGuard {
    pub fn new_and_patch(circomlib_path: &Path) -> Result<Self> {
        patch(circomlib_path)?;
        Ok(Self {
            circomlib_path: circomlib_path.to_path_buf(),
        })
    }
}

/// Apply the patch and leave it in place.
///
/// `circom-witness-rs` shells out to the `circom` CLI from its own build
/// script, so graph regeneration needs the patch applied before cargo runs.
/// A scope guard cannot reach that far; `scripts/witness-graphs.sh` pairs this
/// with [`restore_pristine`].
pub fn patch(circomlib_path: &Path) -> Result<()> {
    restore_pristine(circomlib_path)?;
    apply_patch(circomlib_path)
}

/// Return the two patched files to their committed contents.
///
/// A failure here matters more than it looks: `circuits/src/circomlib/` is
/// gitignored by the outer repository, so patched files it leaves behind are
/// invisible to `git status` there.
pub fn restore_pristine(circomlib_path: &Path) -> Result<()> {
    git(
        circomlib_path,
        &[
            "checkout",
            "--",
            "circuits/comparators.circom",
            "circuits/bitify.circom",
        ],
        "restore circomlib to pristine",
    )
}

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        // Drop cannot report an error, and panicking here would abort during
        // unwinding. Say so loudly instead, with the command that fixes it.
        if let Err(e) = restore_pristine(&self.circomlib_path) {
            eprintln!("warning: circomlib is still patched: {e}");
            eprintln!(
                "  recover with: git -C {} checkout -- \
                 circuits/comparators.circom circuits/bitify.circom",
                self.circomlib_path.display()
            );
        }
    }
}

/// Inject the `bbf_inv` / `bbf_bit` black-box hint functions into
/// circomlib and route the non-quadratic (`<--`) assignments through them.
///
/// circom-witness-rs only hooks unconstrained/dynamic control flow when it
/// lives in a `bbf*`-prefixed circom *function*. Stock circomlib computes
/// `1/in` (`IsZero`) and the bit decomposition (`Num2Bits`) inline inside
/// templates, which the graph runtime cannot evaluate.
fn apply_patch(circomlib_path: &Path) -> Result<()> {
    let circuits_dir = circomlib_path.join("circuits");

    inject_hint(
        &circuits_dir.join("comparators.circom"),
        "function bbf_inv",
        "include \"binsum.circom\";",
        "\n\nfunction bbf_inv(in) {\n    return in!=0 ? 1/in : 0;\n}",
        &[("    inv <-- in!=0 ? 1/in : 0;", "    inv <-- bbf_inv(in);")],
    )?;

    inject_hint(
        &circuits_dir.join("bitify.circom"),
        "function bbf_bit",
        "include \"aliascheck.circom\";",
        "\n\nfunction bbf_bit(in, bit) {\n    return (in >> bit) & 1;\n}",
        &[
            (
                "        out[i] <-- (in >> i) & 1;",
                "        out[i] <-- bbf_bit(in, i);",
            ),
            (
                "        out[i] <-- (neg >> i) & 1;",
                "        out[i] <-- bbf_bit(neg, i);",
            ),
        ],
    )?;

    Ok(())
}

/// Apply a single circomlib black-box hint patch (one `bbf_*` function).
fn inject_hint(
    file: &Path,
    marker: &str,
    anchor: &str,
    fn_def: &str,
    rewrites: &[(&str, &str)],
) -> Result<()> {
    let content = fs::read_to_string(file).with_context(|| format!("read {}", file.display()))?;

    if content.contains(marker) {
        return Ok(());
    }

    let anchor_idx = content
        .find(anchor)
        .ok_or_else(|| anyhow!("anchor {anchor:?} not found in {}", file.display()))?;
    let insert_at = content[anchor_idx..]
        .find('\n')
        .map(|nl| anchor_idx.checked_add(nl).expect("anchor lines overflow"))
        .ok_or_else(|| anyhow!("no newline after anchor {anchor:?} in {}", file.display()))?;

    let mut patched = String::with_capacity(
        content
            .len()
            .checked_add(fn_def.len())
            .expect("circomlib patch size overflow"),
    );
    patched.push_str(&content[..=insert_at]);
    patched.push_str(fn_def);
    patched.push_str(&content[insert_at.checked_add(1).expect("insert_at overflow")..]);

    for (from, to) in rewrites {
        if !patched.contains(from) {
            bail!(
                "rewrite source {from:?} not found in {} (upstream circomlib changed?)",
                file.display()
            );
        }
        patched = patched.replace(from, to);
    }

    fs::write(file, patched).with_context(|| format!("write {}", file.display()))?;
    eprintln!("Injected {marker} into {}", file.display());
    Ok(())
}
