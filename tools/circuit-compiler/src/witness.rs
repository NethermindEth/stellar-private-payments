//! Witness-graph generation (`circom-witness-rs` 0.3).

use anyhow::{Context, Result, anyhow, bail};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(feature = "witness-graph")]
use crate::copy;

const WITNESS_GRAPH_CIRCUITS: &[&str] = &[
    "policy_tx_2_2",
    "policy_tx_2_2_A",
    "policy_tx_2_2_B",
    "policy_tx_2_2_AB",
    "selectiveDisclosure_1",
    "selectiveDisclosure_2",
    "selectiveDisclosure_3",
    "selectiveDisclosure_4",
];

fn check_circom_version(circuits_dir: &Path) -> Result<()> {
    let expected = fs::read_to_string(circuits_dir.join("circom.lock"))
        .context("read circuits/circom.lock")?
        .trim()
        .to_string();
    let version = Command::new("circom")
        .arg("--version")
        .output()
        .context("run `circom --version` (is Circom on PATH?)")?;
    let version_text = format!(
        "{}{}",
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr)
    );
    anyhow::ensure!(
        version.status.success() && version_text.contains(&expected),
        "Circom CLI must be {expected} (circuits/circom.lock); got:\n{version_text}"
    );
    Ok(())
}

/// Rebuild circom-witness-rs once per production circuit and emit its graph.
///
/// Version 0.3 selects the circuit in its build script, so each worker needs a
/// clean dependency build with a different `WITNESS_CPP`.
pub(crate) fn generate_witness_graphs(circuits_dir: &Path, out_dir: &Path) -> Result<()> {
    check_circom_version(circuits_dir)?;

    let circuits_dir = fs::canonicalize(circuits_dir)
        .with_context(|| format!("canonicalize {}", circuits_dir.display()))?;
    fs::create_dir_all(out_dir)
        .with_context(|| format!("Could not create {}", out_dir.display()))?;
    let out_dir =
        fs::canonicalize(out_dir).with_context(|| format!("canonicalize {}", out_dir.display()))?;
    let workspace_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");

    for stem in WITNESS_GRAPH_CIRCUITS {
        eprintln!("Regenerating witness graph for {stem}");

        let clean = Command::new("cargo")
            .args(["clean", "-p", "circom-witness-rs"])
            .current_dir(&workspace_dir)
            .status()
            .context("clean circom-witness-rs before graph generation")?;
        anyhow::ensure!(
            clean.success(),
            "failed to clean circom-witness-rs before generating {stem}"
        );

        let worker = Command::new("cargo")
            .args([
                "run",
                "-p",
                "circuit-compiler",
                "--bin",
                "circuit-witness-graph-generator",
                "--features",
                "witness-graph",
                "--",
                "--circuits",
            ])
            .arg(&circuits_dir)
            .arg("--out")
            .arg(&out_dir)
            .env(
                "WITNESS_CPP",
                circuits_dir.join("src").join(format!("{stem}.circom")),
            )
            .env("CIRCOM_LIBRARY_PATH", circuits_dir.join("src"))
            .current_dir(&workspace_dir)
            .status()
            .with_context(|| format!("start witness graph worker for {stem}"))?;
        anyhow::ensure!(worker.success(), "witness graph worker failed for {stem}");
    }

    eprintln!("Wrote witness graphs to {}", out_dir.display());
    Ok(())
}

/// Generate the one witness graph baked into the graph-generator binary.
pub fn generate_witness_graph(circuits_dir: &Path, out_dir: &Path) -> Result<()> {
    #[cfg(not(feature = "witness-graph"))]
    {
        let _ = (circuits_dir, out_dir);
        bail!("internal graph worker requires the `witness-graph` feature");
    }

    #[cfg(feature = "witness-graph")]
    {
        let hints_were_present = inject_black_box_hints(&circuits_dir.join("src/circomlib"))?;
        anyhow::ensure!(
            hints_were_present,
            "circomlib hints were missing when the graph worker was built; rerun with --graphs"
        );

        let witness_cpp = env::var("WITNESS_CPP")
            .map_err(|_| anyhow!("WITNESS_CPP must be set for graph generation"))?;
        let stem = Path::new(witness_cpp.trim())
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("invalid WITNESS_CPP circuit path: {witness_cpp}"))?;

        let graph = env::current_dir()
            .context("resolve graph worker directory")?
            .join("graph.bin");
        if graph.exists() {
            fs::remove_file(&graph).with_context(|| format!("remove stale {}", graph.display()))?;
        }

        circom_witness_rs::generate::build_witness()
            .map_err(|error| anyhow!("witness graph generation failed: {error}"))?;
        anyhow::ensure!(
            graph.is_file(),
            "expected circom-witness-rs to write {}",
            graph.display()
        );

        let destination = out_dir.join(format!("{stem}.graph.bin"));
        copy(&graph, &destination)?;
        fs::remove_file(&graph)?;
        eprintln!("Wrote witness graph {}", destination.display());
        Ok(())
    }
}

/// Inject the `bbf_inv` / `bbf_bit` black-box hint functions into
/// circomlib and route the non-quadratic (`<--`) assignments through them.
///
/// circom-witness-rs only hooks unconstrained/dynamic control flow when it
/// lives in a `bbf*`-prefixed circom *function*. Stock circomlib computes
/// `1/in` (`IsZero`) and the bit decomposition (`Num2Bits`) inline inside
/// templates, which the graph runtime cannot evaluate.
///
/// Returns `true` when every hint was already present, i.e. this build did not
/// have to touch circomlib.
pub(crate) fn inject_black_box_hints(circomlib_path: &Path) -> Result<bool> {
    let circuits_dir = circomlib_path.join("circuits");

    let comparators_hinted = inject_hint(
        &circuits_dir.join("comparators.circom"),
        "function bbf_inv",
        "include \"binsum.circom\";",
        "\n\nfunction bbf_inv(in) {\n    return in!=0 ? 1/in : 0;\n}",
        &[("    inv <-- in!=0 ? 1/in : 0;", "    inv <-- bbf_inv(in);")],
    )?;

    let bitify_hinted = inject_hint(
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

    Ok(comparators_hinted && bitify_hinted)
}

/// Apply a single circomlib black-box hint patch (one `bbf_*` function).
///
/// Returns `true` if the hint was already present and the file was left alone.
fn inject_hint(
    file: &Path,
    marker: &str,
    anchor: &str,
    fn_def: &str,
    rewrites: &[(&str, &str)],
) -> Result<bool> {
    let content =
        fs::read_to_string(file).with_context(|| format!("Failed to read {}", file.display()))?;

    if content.contains(marker) {
        return Ok(true);
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

    fs::write(file, patched).with_context(|| format!("Failed to write {}", file.display()))?;
    eprintln!("Injected {marker} into {}", file.display());
    Ok(false)
}
